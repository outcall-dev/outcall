//! Project-local rule helpers for the first-run CLI.

use anyhow::{Context, Result};
use serde_yaml::{Mapping, Value};
use std::path::{Path, PathBuf};

use crate::recipes::{PolicyTemplate, Recipe};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChange {
    pub path: PathBuf,
    pub rule_id: String,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRuleSummary {
    pub id: String,
    pub description: Option<String>,
}

/// Add a named recipe grant, exact-host HTTPS grant, or declared host resource.
///
/// The project rule file is the source of truth. Existing rule mappings are
/// retained as-is; only the requested managed rule is appended when absent.
pub fn allow(project_dir: &Path, recipe: &Recipe, target: &str) -> Result<PolicyChange> {
    let path = rule_path(project_dir, recipe);
    let mut document = load_rule_document(&path, recipe.rules)?;
    let (rule_id, rule) = policy_rule(project_dir, recipe, target)?;

    let rules = rules_mut(&mut document)?;
    if rules
        .iter()
        .any(|existing| rule_id_of(existing).as_deref() == Some(&rule_id))
    {
        return Ok(PolicyChange {
            path,
            rule_id,
            changed: false,
        });
    }

    rules.push(rule);
    write_rule_document(&path, &document)?;
    Ok(PolicyChange {
        path,
        rule_id,
        changed: true,
    })
}

pub fn explain(project_dir: &Path, recipe: &Recipe) -> Result<Vec<PolicyRuleSummary>> {
    let path = rule_path(project_dir, recipe);
    let document = load_rule_document(&path, recipe.rules)?;
    let rules = rules(&document)?;
    Ok(rules
        .iter()
        .filter_map(|rule| {
            rule_id_of(rule).map(|id| PolicyRuleSummary {
                id,
                description: string_field(rule, "description"),
            })
        })
        .collect())
}

pub fn rule_path(project_dir: &Path, recipe: &Recipe) -> PathBuf {
    project_dir
        .join(".outcall")
        .join("rules")
        .join(format!("{}.yaml", recipe.id))
}

pub fn template_names(recipe: &Recipe) -> impl Iterator<Item = &'static str> {
    recipe.policy_templates.iter().map(|template| template.name)
}

fn policy_rule(project_dir: &Path, recipe: &Recipe, target: &str) -> Result<(String, Value)> {
    if let Some(template) = recipe
        .policy_templates
        .iter()
        .find(|template| template.name == target)
    {
        return Ok((template.id.to_string(), template_rule(template)));
    }

    if let Some((kind, id)) = target.split_once(':')
        && matches!(kind, "tool" | "file")
    {
        return host_resource_rule(project_dir, recipe, kind, id);
    }

    let host = normalize_host(target)?;
    let id = format!("{}-host-{}", recipe.id, host.replace('.', "-"));
    let description = format!("{} may access {host} over HTTPS.", recipe.name);
    let condition = format!("http.host == \"{host}\" || dns.query == \"{host}\"");
    Ok((id.clone(), allow_rule(&id, &description, &condition)))
}

fn host_resource_rule(
    project_dir: &Path,
    recipe: &Recipe,
    kind: &str,
    id: &str,
) -> Result<(String, Value)> {
    validate_resource_id(id)?;
    let registry = crate::host_resources::load_for_project(project_dir)?;
    match kind {
        "tool" => {
            let tool = crate::host_resources::find_tool(&registry, id).with_context(|| {
                format!(
                    "host tool {id:?} is not declared in {}",
                    crate::host_resources::default_config_path(project_dir).display()
                )
            })?;
            crate::host_resources::resolve_tool_path(project_dir, tool)?;
        }
        "file" => {
            if crate::host_resources::find_file(&registry, id).is_none() {
                anyhow::bail!(
                    "host file {id:?} is not declared in {}",
                    crate::host_resources::default_config_path(project_dir).display()
                );
            }
        }
        _ => unreachable!("validated host resource kind"),
    }

    let rule_id = format!("{}-host-{}-{}", recipe.id, kind, id);
    let resource_kind = if kind == "tool" { "tool" } else { "file root" };
    let description = format!(
        "{} may use declared host {resource_kind} {id}.",
        recipe.name
    );
    let condition = format!("run.tool == \"host.{kind}.{id}\"");
    Ok((
        rule_id.clone(),
        basic_allow_rule(&rule_id, &description, &condition),
    ))
}

fn validate_resource_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        anyhow::bail!(
            "host resource IDs must contain only ASCII letters, numbers, dots, underscores, or hyphens"
        );
    }
    Ok(())
}

fn template_rule(template: &PolicyTemplate) -> Value {
    allow_rule(template.id, template.description, template.condition)
}

fn allow_rule(id: &str, description: &str, condition: &str) -> Value {
    let mut rule = basic_allow_rule(id, description, condition);
    let mut egress = Mapping::new();
    egress.insert(
        Value::String("mode".to_string()),
        Value::String("proxy".to_string()),
    );
    rule.as_mapping_mut()
        .expect("allow rule is a mapping")
        .insert(Value::String("egress".to_string()), Value::Mapping(egress));
    rule
}

fn basic_allow_rule(id: &str, description: &str, condition: &str) -> Value {
    let mut rule = Mapping::new();
    rule.insert(
        Value::String("id".to_string()),
        Value::String(id.to_string()),
    );
    rule.insert(
        Value::String("description".to_string()),
        Value::String(description.to_string()),
    );
    rule.insert(
        Value::String("condition".to_string()),
        Value::String(condition.to_string()),
    );
    rule.insert(
        Value::String("action".to_string()),
        Value::String("allow".to_string()),
    );
    Value::Mapping(rule)
}

fn normalize_host(target: &str) -> Result<String> {
    let trimmed = target.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme.split('/').next().unwrap_or_default();
    if host.is_empty()
        || host.contains('@')
        || host.contains(':')
        || !host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
        || !host.contains('.')
    {
        anyhow::bail!(
            "policy target must be a named recipe grant, exact hostname, or declared host resource, for example github, https://api.sentry.io, tool:chrome-mcp, or file:notes"
        );
    }
    Ok(host.to_ascii_lowercase())
}

fn load_rule_document(path: &Path, defaults: &str) -> Result<Value> {
    let contents = if path.exists() {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?
    } else {
        defaults.to_string()
    };
    serde_yaml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn rules(document: &Value) -> Result<&Vec<Value>> {
    document
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String("rules".to_string())))
        .and_then(Value::as_sequence)
        .context("rule document must contain a rules sequence")
}

fn rules_mut(document: &mut Value) -> Result<&mut Vec<Value>> {
    let mapping = document
        .as_mapping_mut()
        .context("rule document must be a YAML mapping")?;
    let rules_key = Value::String("rules".to_string());
    if !mapping.contains_key(&rules_key) {
        mapping.insert(rules_key.clone(), Value::Sequence(Vec::new()));
    }
    mapping
        .get_mut(&rules_key)
        .and_then(Value::as_sequence_mut)
        .context("rule document rules field must be a YAML sequence")
}

fn rule_id_of(rule: &Value) -> Option<String> {
    string_field(rule, "id")
}

fn string_field(rule: &Value, field: &str) -> Option<String> {
    rule.as_mapping()
        .and_then(|mapping| mapping.get(Value::String(field.to_string())))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn write_rule_document(path: &Path, document: &Value) -> Result<()> {
    let parent = path
        .parent()
        .context("rule file must have a parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let contents = serde_yaml::to_string(document).context("failed to serialize project rules")?;
    let temporary = path.with_extension("yaml.tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed to replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipes::{get_recipe, init_recipe};

    fn temp_project(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("outcall-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn adds_exact_host_without_removing_existing_rules() {
        let project = temp_project("allow");
        let recipe = get_recipe("codex").unwrap();
        init_recipe(&project, recipe, false).unwrap();
        let path = rule_path(&project, recipe);
        let original = std::fs::read_to_string(&path).unwrap();
        assert!(original.contains("codex-github"));

        let change = allow(&project, recipe, "https://api.sentry.io").unwrap();
        assert!(change.changed);
        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.contains("codex-github"));
        assert!(updated.contains("codex-host-api-sentry-io"));

        let repeated = allow(&project, recipe, "api.sentry.io").unwrap();
        assert!(!repeated.changed);
        let _ = std::fs::remove_dir_all(project);
    }

    #[test]
    fn rejects_broad_or_ambiguous_hosts() {
        let project = temp_project("reject");
        let recipe = get_recipe("codex").unwrap();
        init_recipe(&project, recipe, false).unwrap();
        assert!(policy_rule(&project, recipe, "*.example.com").is_err());
        assert!(policy_rule(&project, recipe, "https://example.com:443").is_err());
        let _ = std::fs::remove_dir_all(project);
    }

    #[test]
    fn adds_declared_host_resource_rules() {
        let project = temp_project("host-resource");
        let recipe = get_recipe("codex").unwrap();
        init_recipe(&project, recipe, false).unwrap();
        std::fs::write(
            crate::host_resources::default_config_path(&project),
            r#"version: "1"
tools:
  - id: echo-test
    path: /bin/echo
files:
  - id: notes
    path: /tmp/notes
"#,
        )
        .unwrap();

        let tool = allow(&project, recipe, "tool:echo-test").unwrap();
        let file = allow(&project, recipe, "file:notes").unwrap();
        assert_eq!(tool.rule_id, "codex-host-tool-echo-test");
        assert_eq!(file.rule_id, "codex-host-file-notes");

        let rules = std::fs::read_to_string(rule_path(&project, recipe)).unwrap();
        assert!(rules.contains(r#"run.tool == "host.tool.echo-test""#));
        assert!(rules.contains(r#"run.tool == "host.file.notes""#));
        let _ = std::fs::remove_dir_all(project);
    }

    #[test]
    fn rejects_undeclared_or_malformed_host_resources() {
        let project = temp_project("host-resource-reject");
        let recipe = get_recipe("codex").unwrap();
        init_recipe(&project, recipe, false).unwrap();

        let undeclared = allow(&project, recipe, "tool:missing").unwrap_err();
        assert!(undeclared.to_string().contains("is not declared"));
        let malformed = allow(&project, recipe, "file:../secret").unwrap_err();
        assert!(malformed.to_string().contains("host resource IDs"));
        let _ = std::fs::remove_dir_all(project);
    }

    #[test]
    fn keeps_host_resource_rule_ids_unique() {
        let project = temp_project("host-resource-id");
        let recipe = get_recipe("codex").unwrap();
        init_recipe(&project, recipe, false).unwrap();
        std::fs::write(
            crate::host_resources::default_config_path(&project),
            r#"version: "1"
tools:
  - id: echo.test
    path: /bin/echo
  - id: echo_test
    path: /bin/echo
files: []
"#,
        )
        .unwrap();

        let dotted = allow(&project, recipe, "tool:echo.test").unwrap();
        let underscored = allow(&project, recipe, "tool:echo_test").unwrap();
        assert_eq!(dotted.rule_id, "codex-host-tool-echo.test");
        assert_eq!(underscored.rule_id, "codex-host-tool-echo_test");

        let rules = std::fs::read_to_string(rule_path(&project, recipe)).unwrap();
        assert!(rules.contains(r#"run.tool == "host.tool.echo.test""#));
        assert!(rules.contains(r#"run.tool == "host.tool.echo_test""#));
        let _ = std::fs::remove_dir_all(project);
    }
}
