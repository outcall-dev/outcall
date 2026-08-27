use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use outcall_api::RuleAction;
use tracing::{info, warn};

use super::model::{CompiledRule, EgressMode, RuleFile, RuleSet};

const MAX_RULE_FILES: usize = 1024;
const MAX_RULE_FILE_BYTES: usize = 1024 * 1024;
const MAX_RULES_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_RULES: usize = 10_000;
const MAX_DEFINITION_DEPTH: usize = 64;
const MAX_EXPANDED_CONDITION_BYTES: usize = 1024 * 1024;

pub(super) struct LoadedRules {
    pub rule_set: RuleSet,
    pub files_loaded: usize,
    pub warnings: Vec<String>,
}

pub(super) fn load_rules(rules_dir: &str) -> Result<LoadedRules> {
    let path = Path::new(rules_dir);
    let yaml_files = discover_rule_files(path)?;
    if yaml_files.is_empty() {
        warn!(
            rules_dir,
            "no .yaml/.yml files found - starting with empty rule set"
        );
        return Ok(LoadedRules {
            rule_set: RuleSet::default(),
            files_loaded: 0,
            warnings: Vec::new(),
        });
    }

    let mut all_rules = Vec::new();
    let mut seen_ids: HashMap<String, String> = HashMap::new();
    let mut warnings = Vec::new();
    let mut total_bytes = 0usize;

    for file_path in &yaml_files {
        let file_name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("rule file name must be valid UTF-8")?
            .to_string();
        let content = read_rule_file(file_path)?;
        total_bytes = total_bytes
            .checked_add(content.len())
            .context("total rule file size overflow")?;
        if total_bytes > MAX_RULES_TOTAL_BYTES {
            anyhow::bail!("rule files exceed {MAX_RULES_TOTAL_BYTES} bytes in total");
        }

        let rule_file: RuleFile = serde_yaml::from_str(&content)
            .with_context(|| format!("YAML parse error in {file_name}"))?;
        validate_version(&rule_file, &file_name)?;
        collect_file_warnings(&rule_file, &file_name, &mut warnings);

        for spec in &rule_file.rules {
            validate_rule_id(&spec.id, &file_name)?;
            validate_rule_semantics(spec, &file_name)?;
            if let Some(first_file) = seen_ids.get(&spec.id) {
                anyhow::bail!(
                    "duplicate rule ID {:?} in {file_name} (first seen in {first_file})",
                    spec.id
                );
            }
            seen_ids.insert(spec.id.clone(), file_name.clone());
            if seen_ids.len() > MAX_RULES {
                anyhow::bail!("rule set exceeds {MAX_RULES} rules");
            }

            let expanded = expand_definitions(&spec.condition, &rule_file.definitions, &file_name)
                .with_context(|| {
                    format!("expanding definitions in rule {:?} ({file_name})", spec.id)
                })?;
            let program = cel_interpreter::Program::compile(&expanded)
                .with_context(|| format!("CEL parse error in rule {:?} ({file_name})", spec.id))?;

            all_rules.push(CompiledRule {
                id: spec.id.clone(),
                file: file_name.clone(),
                condition_expanded: expanded,
                action: spec.action.clone(),
                log: spec.log,
                description: spec.description.clone(),
                priority: spec.priority.unwrap_or(100),
                egress: spec.egress.clone(),
                program,
            });
        }

        info!(file = %file_name, rules = rule_file.rules.len(), "loaded rule file");
    }

    all_rules.sort_by_key(|rule| rule.priority);
    if all_rules.is_empty() {
        warn!(
            rules_dir,
            files = yaml_files.len(),
            "rule files loaded but no rules were defined - default-deny will block all traffic"
        );
    }
    for warning in &warnings {
        warn!(message = %warning, "rule static-analysis warning");
    }
    info!(
        total_rules = all_rules.len(),
        files = yaml_files.len(),
        "rule engine loaded"
    );

    Ok(LoadedRules {
        rule_set: RuleSet { rules: all_rules },
        files_loaded: yaml_files.len(),
        warnings,
    })
}

pub(super) fn validate_rule_yaml(rule_yaml: &str) -> Result<(), String> {
    if rule_yaml.len() > MAX_RULE_FILE_BYTES {
        return Err(format!("rule file exceeds {MAX_RULE_FILE_BYTES} bytes"));
    }
    let rule_file: RuleFile =
        serde_yaml::from_str(rule_yaml).map_err(|error| format!("YAML parse error: {error}"))?;
    validate_version(&rule_file, "<input>").map_err(|error| error.to_string())?;

    let mut seen_ids = std::collections::HashSet::new();
    for rule in &rule_file.rules {
        validate_rule_id(&rule.id, "<input>").map_err(|error| error.to_string())?;
        validate_rule_semantics(rule, "<input>").map_err(|error| error.to_string())?;
        if !seen_ids.insert(rule.id.as_str()) {
            return Err(format!("duplicate rule ID {:?}", rule.id));
        }
        let expanded = expand_definitions(&rule.condition, &rule_file.definitions, "<input>")
            .map_err(|error| {
                format!("definition expansion error in rule {:?}: {error}", rule.id)
            })?;
        cel_interpreter::Program::compile(&expanded)
            .map_err(|error| format!("CEL compile error in rule {:?}: {error}", rule.id))?;
    }
    Ok(())
}

fn validate_rule_semantics(rule: &super::model::RuleSpec, file_name: &str) -> Result<()> {
    if rule.action == RuleAction::Enrich {
        anyhow::bail!(
            "rule {:?} ({file_name}) uses unsupported action: enrich; host-side execution must be declared through the host resource broker",
            rule.id
        );
    }
    if rule.enrich.is_some() {
        anyhow::bail!(
            "rule {:?} ({file_name}) declares enrich settings without action: enrich",
            rule.id
        );
    }
    if rule.egress.is_some() && rule.action != RuleAction::Allow {
        anyhow::bail!(
            "rule {:?} ({file_name}) declares egress settings but is not an allow rule",
            rule.id
        );
    }
    if rule
        .egress
        .as_ref()
        .is_some_and(|egress| egress.mode == EgressMode::Intercept)
    {
        anyhow::bail!(
            "rule {:?} ({file_name}) uses unsupported egress.mode: intercept; TLS interception is not implemented, so use mode: proxy",
            rule.id
        );
    }
    Ok(())
}

fn validate_rule_id(id: &str, file_name: &str) -> Result<()> {
    if !outcall_api::valid_rule_id(id) {
        anyhow::bail!(
            "rule ID {id:?} in {file_name} must contain 1-{} ASCII letters, numbers, dots, underscores, or hyphens and start with a letter or number",
            outcall_api::MAX_RULE_ID_BYTES
        );
    }
    Ok(())
}

fn discover_rule_files(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect rules directory {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "rules directory {} must be a real directory",
            path.display()
        );
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("failed to read rules directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        let entry_path = entry.path();
        if !is_rule_file(&entry_path) {
            continue;
        }
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry_path.display()))?;
        if !file_type.is_file() {
            anyhow::bail!("rule file {} must be a real file", entry_path.display());
        }
        files.push(entry_path);
        if files.len() > MAX_RULE_FILES {
            anyhow::bail!("rules directory exceeds {MAX_RULE_FILES} rule files");
        }
    }
    files.sort();
    Ok(files)
}

fn read_rule_file(path: &Path) -> Result<String> {
    let bytes = crate::state_file::read_optional(path, MAX_RULE_FILE_BYTES)?
        .with_context(|| format!("rule file {} disappeared while loading", path.display()))?;
    String::from_utf8(bytes).with_context(|| format!("{} must contain valid UTF-8", path.display()))
}

fn validate_version(rule_file: &RuleFile, file_name: &str) -> Result<()> {
    if rule_file.version != "1" {
        anyhow::bail!(
            "unsupported version {:?} in {file_name} (only \"1\" is supported)",
            rule_file.version
        );
    }
    Ok(())
}

fn collect_file_warnings(rule_file: &RuleFile, file_name: &str, warnings: &mut Vec<String>) {
    for definition in rule_file.definitions.keys() {
        if !rule_file
            .rules
            .iter()
            .any(|rule| rule.condition.contains(&format!("${definition}")))
        {
            warnings.push(format!("unused definition \"{definition}\" in {file_name}"));
        }
    }
    if !rule_file.definitions.is_empty() && rule_file.rules.is_empty() {
        warnings.push(format!(
            "definitions section present but no rules in {file_name}"
        ));
    }
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
}

fn expand_definitions(
    expression: &str,
    definitions: &HashMap<String, String>,
    file_name: &str,
) -> Result<String> {
    expand_recursive(expression, definitions, file_name, &mut Vec::new())
}

fn expand_recursive(
    expression: &str,
    definitions: &HashMap<String, String>,
    file_name: &str,
    stack: &mut Vec<String>,
) -> Result<String> {
    if stack.len() >= MAX_DEFINITION_DEPTH {
        anyhow::bail!("definition expansion exceeds depth {MAX_DEFINITION_DEPTH} in {file_name}");
    }
    let mut result = expression.to_string();
    let mut index = 0;
    while index < result.len() {
        if result.as_bytes()[index] != b'$' {
            index += 1;
            continue;
        }

        let name_start = index + 1;
        let name_end = result[name_start..]
            .find(|character: char| !character.is_alphanumeric() && character != '_')
            .map(|offset| name_start + offset)
            .unwrap_or(result.len());
        let name = &result[name_start..name_end];
        if name.is_empty() {
            index += 1;
            continue;
        }
        let definition = definitions.get(name).ok_or_else(|| {
            anyhow::anyhow!("undefined $name reference \"${name}\" in {file_name}")
        })?;
        if stack.iter().any(|entry| entry == name) {
            anyhow::bail!("circular definition reference \"${name}\" in {file_name}");
        }

        stack.push(name.to_string());
        let expanded = expand_recursive(definition, definitions, file_name, stack)?;
        stack.pop();
        let replacement = format!("({expanded})");
        let new_len = result
            .len()
            .checked_sub(name_end - index)
            .and_then(|length| length.checked_add(replacement.len()))
            .context("expanded condition length overflow")?;
        if new_len > MAX_EXPANDED_CONDITION_BYTES {
            anyhow::bail!(
                "expanded condition exceeds {MAX_EXPANDED_CONDITION_BYTES} bytes in {file_name}"
            );
        }
        result.replace_range(index..name_end, &replacement);
        index += replacement.len();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_rule_file_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("large.yaml");
        std::fs::write(&path, vec![b'x'; MAX_RULE_FILE_BYTES + 1]).unwrap();

        let error = load_rules(root.path().to_str().unwrap())
            .err()
            .expect("oversized rule file should fail")
            .to_string();

        assert!(error.contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_rule_file_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, "version: \"1\"\nrules: []\n").unwrap();
        symlink(&outside, root.path().join("linked.yaml")).unwrap();

        let error = load_rules(root.path().to_str().unwrap())
            .err()
            .expect("symlinked rule should fail")
            .to_string();

        assert!(error.contains("real file"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_rules_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let linked = root.path().join("linked");
        symlink(&real, &linked).unwrap();

        let error = load_rules(linked.to_str().unwrap())
            .err()
            .expect("symlinked rules directory should fail")
            .to_string();

        assert!(error.contains("real directory"));
    }

    #[test]
    fn unknown_rule_fields_are_rejected() {
        let error = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: typo\n    condition: \"true\"\n    action: allow\n    logging: true\n",
        )
        .unwrap_err();

        assert!(error.contains("unknown field"));
    }

    #[test]
    fn empty_and_duplicate_rule_ids_are_rejected() {
        let empty = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: \" \"\n    condition: \"true\"\n    action: allow\n",
        )
        .unwrap_err();
        assert!(empty.contains("must contain"));

        let unsafe_id = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: \"allow\\r\\nX-Injected: yes\"\n    condition: \"true\"\n    action: allow\n",
        )
        .unwrap_err();
        assert!(unsafe_id.contains("rule ID"));

        let duplicate = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: same\n    condition: \"true\"\n    action: allow\n  - id: same\n    condition: \"false\"\n    action: block\n",
        )
        .unwrap_err();
        assert!(duplicate.contains("duplicate rule ID"));
    }

    #[test]
    fn unsupported_enrich_and_invalid_egress_fail_closed() {
        let enrich = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: context\n    condition: \"true\"\n    action: enrich\n    enrich:\n      script: inspect.sh\n",
        )
        .unwrap_err();
        assert!(enrich.contains("unsupported action: enrich"));

        let blocked_egress = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: blocked\n    condition: \"true\"\n    action: block\n    egress:\n      mode: proxy\n",
        )
        .unwrap_err();
        assert!(blocked_egress.contains("not an allow rule"));

        let intercept = validate_rule_yaml(
            "version: \"1\"\nrules:\n  - id: inspect\n    condition: \"true\"\n    action: allow\n    egress:\n      mode: intercept\n",
        )
        .unwrap_err();
        assert!(intercept.contains("TLS interception is not implemented"));
    }

    #[test]
    fn recursive_definition_expansion_is_bounded() {
        let mut definitions = HashMap::new();
        for index in 0..MAX_DEFINITION_DEPTH {
            definitions.insert(format!("d{index}"), format!("$d{}", index + 1));
        }
        definitions.insert(format!("d{MAX_DEFINITION_DEPTH}"), "true".to_string());

        let error = expand_definitions("$d0", &definitions, "test.yaml")
            .unwrap_err()
            .to_string();

        assert!(error.contains("exceeds depth"));
    }
}
