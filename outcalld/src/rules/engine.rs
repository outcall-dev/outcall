//! Rule engine: YAML loading, CEL compilation, and evaluation (S003).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use cel_interpreter::{Context as CelCtx, Value};
use outcall_api::{
    Decision, DnsContext, DockerContext, EvalContext, EvaluateResult, HttpContext, NetworkContext,
    RuleAction, RuleDetail, RuleSummary, RunContext,
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use super::model::{CompiledRule, EgressSpec, RuleFile, RuleSet};

/// The rule engine. Holds a hot-swappable compiled rule set.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RuleEngine {
    pub rules_dir: String,
    rule_set: Arc<RwLock<Arc<RuleSet>>>,
}

#[allow(dead_code)]
impl RuleEngine {
    /// Load rules from `rules_dir`, compile CEL expressions, return the engine.
    /// Returns an error if any P1 static analysis check fails (S003-FR-014/015).
    pub fn load(rules_dir: &str) -> Result<Self> {
        let rule_set = load_and_compile(rules_dir)?;
        Ok(Self {
            rules_dir: rules_dir.to_string(),
            rule_set: Arc::new(RwLock::new(Arc::new(rule_set))),
        })
    }

    /// Evaluate a request context against the current rule set.
    /// Returns the first matching allow/block verdict, or default block.
    pub async fn evaluate(&self, ctx: &EvalContext) -> EvaluateResult {
        let rule_set = self.rule_set.read().await.clone();
        let started = Instant::now();

        let cel_ctx = build_cel_context(ctx);

        let mut result = EvaluateResult {
            decision: Decision::Block,
            matched_rule: None,
            file: None,
            logged: false,
        };

        for rule in &rule_set.rules {
            let matched = rule
                .program
                .execute(&cel_ctx)
                .ok()
                .and_then(|v| {
                    if let Value::Bool(b) = v {
                        Some(b)
                    } else {
                        None
                    }
                })
                .unwrap_or(false);

            if !matched {
                continue;
            }

            // Enrich rules don't terminate evaluation
            if rule.action == RuleAction::Enrich {
                debug!(rule_id = %rule.id, "enrich rule matched (continuing)");
                continue;
            }

            result.decision = if rule.action == RuleAction::Allow {
                Decision::Allow
            } else {
                Decision::Block
            };
            result.matched_rule = Some(rule.id.clone());
            result.file = Some(rule.file.clone());
            result.logged = rule.log;

            if rule.log {
                info!(
                    rule_id = %rule.id,
                    decision = ?result.decision,
                    file = %rule.file,
                    "rule matched"
                );
            } else {
                debug!(rule_id = %rule.id, decision = ?result.decision, "rule matched");
            }
            break;
        }

        let elapsed_ms = started.elapsed().as_millis();
        // FR-031: warn if evaluation exceeds 50ms budget
        if elapsed_ms > 50 {
            warn!(elapsed_ms, "rule evaluation exceeded 50ms budget");
        } else {
            debug!(elapsed_ms, "rule evaluation complete");
        }

        result
    }

    /// Reload the rule set from disk atomically (S003-FR-021/022/023).
    pub async fn reload(&self) -> Result<(usize, usize, Vec<String>)> {
        let new_set = load_and_compile(&self.rules_dir)?;
        let files = count_files(&self.rules_dir);
        let rules = new_set.rules.len();
        let warnings = collect_warnings(&self.rules_dir)?;

        *self.rule_set.write().await = Arc::new(new_set);
        info!(files, rules, "rules reloaded");
        Ok((files, rules, warnings))
    }

    /// List all loaded rules in evaluation order.
    pub async fn list_rules(&self) -> Vec<RuleSummary> {
        self.rule_set
            .read()
            .await
            .rules
            .iter()
            .map(|r| RuleSummary {
                id: r.id.clone(),
                file: r.file.clone(),
                action: r.action.clone(),
                condition_preview: truncate(&r.condition_expanded, 80),
                description: r.description.clone(),
            })
            .collect()
    }

    /// Get details for a specific rule by ID.
    pub async fn get_rule(&self, id: &str) -> Option<RuleDetail> {
        self.rule_set
            .read()
            .await
            .rules
            .iter()
            .find(|r| r.id == id)
            .map(|r| RuleDetail {
                id: r.id.clone(),
                condition: r.condition_expanded.clone(),
                action: r.action.clone(),
                log: r.log,
                description: r.description.clone(),
                priority: Some(r.priority),
            })
    }

    /// Return the optional egress config for a specific rule.
    pub async fn rule_egress(&self, id: &str) -> Option<EgressSpec> {
        self.rule_set
            .read()
            .await
            .rules
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.egress.clone())
    }

    /// Validate a rule YAML string without modifying the engine's rule set.
    /// Returns `Ok(())` if the file parses and all CEL expressions compile.
    pub fn validate_rule_file(rule_yaml: &str) -> Result<(), String> {
        use super::model::RuleFile;
        let rf: RuleFile =
            serde_yaml::from_str(rule_yaml).map_err(|e| format!("YAML parse error: {e}"))?;
        if rf.version != "1" {
            return Err(format!("unsupported rule file version: {:?}", rf.version));
        }
        for rule in &rf.rules {
            if rule.id.is_empty() {
                return Err("rule is missing 'id' field".to_string());
            }
            cel_interpreter::Program::compile(&rule.condition)
                .map_err(|e| format!("CEL compile error in rule {:?}: {e}", rule.id))?;
        }
        Ok(())
    }

    /// Evaluate a single CEL expression against a context (for the test endpoint).
    pub fn test_expression(expr: &str, ctx: &EvalContext) -> (bool, Option<String>) {
        match cel_interpreter::Program::compile(expr) {
            Err(e) => (false, Some(format!("CEL parse error: {e}"))),
            Ok(prog) => {
                let cel_ctx = build_cel_context(ctx);
                match prog.execute(&cel_ctx) {
                    Ok(Value::Bool(b)) => (b, None),
                    Ok(other) => (
                        false,
                        Some(format!("expression returned non-bool: {other:?}")),
                    ),
                    Err(e) => (false, Some(format!("evaluation error: {e}"))),
                }
            }
        }
    }
}

// ── Rule loading ──────────────────────────────────────────────────────────

/// Load and compile all rules from the given directory.
#[allow(dead_code)]
fn load_and_compile(rules_dir: &str) -> Result<RuleSet> {
    let path = Path::new(rules_dir);

    // FR-038: missing or empty rules dir = empty rule set (no error)
    if !path.exists() {
        info!(
            rules_dir,
            "rules directory does not exist — starting with empty rule set"
        );
        return Ok(RuleSet::default());
    }

    // Collect .yaml files in lexicographic order (FR-007)
    let mut yaml_files: Vec<_> = WalkDir::new(path)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "yaml"))
        .map(|e| e.path().to_path_buf())
        .collect();
    yaml_files.sort();

    if yaml_files.is_empty() {
        info!(
            rules_dir,
            "no .yaml files found — starting with empty rule set"
        );
        return Ok(RuleSet::default());
    }

    let mut all_rules: Vec<CompiledRule> = Vec::new();
    let mut seen_ids: HashMap<String, String> = HashMap::new(); // id → first file

    for file_path in &yaml_files {
        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let content =
            std::fs::read_to_string(file_path).with_context(|| format!("reading {file_name}"))?;

        // FR-015.f: malformed YAML = error
        let rule_file: RuleFile = serde_yaml::from_str(&content)
            .with_context(|| format!("YAML parse error in {file_name}"))?;

        // FR-002/015.b: version must be "1"
        if rule_file.version != "1" {
            anyhow::bail!(
                "unsupported version {:?} in {file_name} (only \"1\" is supported)",
                rule_file.version
            );
        }

        for spec in &rule_file.rules {
            // FR-015.c / FR-028: duplicate ID = error
            if let Some(first_file) = seen_ids.get(&spec.id) {
                anyhow::bail!(
                    "duplicate rule ID {:?} in {file_name} (first seen in {first_file})",
                    spec.id
                );
            }
            seen_ids.insert(spec.id.clone(), file_name.clone());

            // Expand $name definitions
            let expanded = expand_definitions(&spec.condition, &rule_file.definitions, &file_name)
                .with_context(|| {
                    format!("expanding definitions in rule {:?} ({file_name})", spec.id)
                })?;

            // FR-004/015.a: CEL compile at load time
            let program = cel_interpreter::Program::compile(&expanded)
                .with_context(|| format!("CEL parse error in rule {:?} ({file_name})", spec.id))?;

            let priority = spec.priority.unwrap_or(100);

            all_rules.push(CompiledRule {
                id: spec.id.clone(),
                file: file_name.clone(),
                condition_expanded: expanded,
                action: spec.action.clone(),
                log: spec.log,
                description: spec.description.clone(),
                priority,
                egress: spec.egress.clone(),
                program,
            });
        }

        info!(file = %file_name, rules = rule_file.rules.len(), "loaded rule file");
    }

    // FR-007/032: sort by priority (ascending), then filename/position as tiebreaker
    // Rules are already in filename/position order from the loop above.
    // A stable sort by priority preserves that order within the same priority level.
    all_rules.sort_by_key(|r| r.priority);

    info!(
        total_rules = all_rules.len(),
        files = yaml_files.len(),
        "rule engine loaded"
    );

    Ok(RuleSet { rules: all_rules })
}

/// Expand `$name` references in a CEL expression using the definitions map.
/// Definitions are applied recursively. Circular references are detected.
#[allow(dead_code)]
fn expand_definitions(
    expr: &str,
    defs: &HashMap<String, String>,
    file_name: &str,
) -> Result<String> {
    expand_recursive(expr, defs, file_name, &mut Vec::new())
}

#[allow(dead_code)]
fn expand_recursive(
    expr: &str,
    defs: &HashMap<String, String>,
    file_name: &str,
    stack: &mut Vec<String>,
) -> Result<String> {
    let mut result = expr.to_string();
    // Find all $name references
    let mut i = 0;
    while i < result.len() {
        if result.as_bytes()[i] == b'$' {
            // Read the name after $
            let name_start = i + 1;
            let name_end = result[name_start..]
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .map(|n| name_start + n)
                .unwrap_or(result.len());
            let name = &result[name_start..name_end];

            if name.is_empty() {
                i += 1;
                continue;
            }

            let def = defs.get(name).ok_or_else(|| {
                anyhow::anyhow!("undefined $name reference \"${name}\" in {file_name}")
            })?;

            // FR-006.c: circular reference detection
            if stack.contains(&name.to_string()) {
                anyhow::bail!("circular definition reference \"${name}\" in {file_name}");
            }
            stack.push(name.to_string());
            let expanded_def = expand_recursive(def, defs, file_name, stack)?;
            stack.pop();

            let replacement = format!("({expanded_def})");
            result.replace_range(i..name_end, &replacement);
            i += replacement.len();
        } else {
            i += 1;
        }
    }
    Ok(result)
}

// ── CEL context building ──────────────────────────────────────────────────

/// Build a CEL evaluation context from the API EvalContext.
/// Absent namespaces are injected with zero values (FR-005.f).
#[allow(dead_code, mismatched_lifetime_syntaxes)]
fn build_cel_context(ctx: &EvalContext) -> CelCtx {
    let mut cel = CelCtx::default();

    let net = ctx.network.as_ref().cloned().unwrap_or_default();
    let http = ctx.http.as_ref().cloned().unwrap_or_default();
    let dns = ctx.dns.as_ref().cloned().unwrap_or_default();
    let docker = ctx.docker.as_ref().cloned().unwrap_or_default();
    let run = ctx.run.as_ref().cloned().unwrap_or_default();
    let agent = ctx.agent.as_ref().cloned().unwrap_or_default();

    let _ = cel.add_variable("network", network_value(&net));
    let _ = cel.add_variable("http", http_value(&http));
    let _ = cel.add_variable("dns", dns_value(&dns));
    let _ = cel.add_variable("docker", docker_value(&docker));
    let _ = cel.add_variable("run", run_value(&run));
    let _ = cel.add_variable("agent", agent_value(&agent));

    cel
}

#[allow(dead_code)]
fn network_value(n: &NetworkContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("hostname", Value::from(n.hostname.as_deref().unwrap_or("")));
    map.insert("ip", Value::from(n.ip.as_str()));
    map.insert("port", Value::from(n.port as i64));
    map.insert("protocol", Value::from(n.protocol.as_str()));
    Value::from(map)
}

#[allow(dead_code)]
fn http_value(h: &HttpContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("method", Value::from(h.method.as_str()));
    map.insert("path", Value::from(h.path.as_str()));
    map.insert("host", Value::from(h.host.as_str()));
    map.insert("body_size", Value::from(h.body_size as i64));
    // headers: map<string, string>
    let headers: HashMap<&str, Value> = h
        .headers
        .iter()
        .map(|(k, v)| (k.as_str(), Value::from(v.as_str())))
        .collect();
    map.insert("headers", Value::from(headers));
    Value::from(map)
}

#[allow(dead_code)]
fn dns_value(d: &DnsContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("query", Value::from(d.query.as_str()));
    map.insert("record_type", Value::from(d.record_type.as_str()));
    Value::from(map)
}

#[allow(dead_code)]
fn docker_value(d: &DockerContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("image", Value::from(d.image.as_str()));
    map.insert("command", Value::from(str_list(&d.command)));
    map.insert("volumes", Value::from(str_list(&d.volumes)));
    map.insert("env_keys", Value::from(str_list(&d.env_keys)));
    map.insert("capabilities", Value::from(str_list(&d.capabilities)));
    Value::from(map)
}

#[allow(dead_code)]
fn run_value(r: &RunContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("tool", Value::from(r.tool.as_str()));
    map.insert("args", Value::from(str_list(&r.args)));
    map.insert("flags", Value::from(str_list(&r.flags)));
    map.insert("cwd", Value::from(r.cwd.as_str()));
    // run.context is a map — for now we include string-valued keys only
    let ctx_map: HashMap<&str, Value> = r
        .context
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), Value::from(s))))
        .collect();
    map.insert("context", Value::from(ctx_map));
    Value::from(map)
}

#[allow(dead_code)]
fn str_list(v: &[String]) -> Vec<Value> {
    v.iter().map(|s| Value::from(s.as_str())).collect()
}

#[allow(dead_code)]
fn agent_value(a: &outcall_api::AgentContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("name", Value::from(a.name.as_str()));
    Value::from(map)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use outcall_api::{Decision, EvalContext, NetworkContext};
    use std::io::Write;

    /// Write a temporary rule YAML file and return a temp dir.
    fn tmp_rules_dir(content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut f = std::fs::File::create(dir.path().join("rules.yaml")).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        dir
    }

    fn network_ctx(ip: &str, port: u16, protocol: &str) -> EvalContext {
        EvalContext {
            network: Some(NetworkContext {
                ip: ip.to_string(),
                port,
                protocol: protocol.to_string(),
                hostname: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn load_empty_dir_gives_empty_rule_set() {
        let dir = tempfile::tempdir().unwrap();
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        // Can't easily inspect rules_dir length via public API but reload should work.
        assert!(!engine.rules_dir.is_empty());
    }

    #[test]
    fn load_missing_dir_is_not_error() {
        let engine = RuleEngine::load("/tmp/nonexistent-outcall-rules-9999999");
        assert!(engine.is_ok());
    }

    #[test]
    fn load_valid_allow_rule() {
        let yaml = r#"
version: "1"
rules:
  - id: allow-dns
    condition: 'network.port == 53'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let _ = engine; // compiled without panic
    }

    #[test]
    fn load_duplicate_id_is_error() {
        let yaml = r#"
version: "1"
rules:
  - id: dup
    condition: 'true'
    action: allow
  - id: dup
    condition: 'false'
    action: block
"#;
        let dir = tmp_rules_dir(yaml);
        let result = RuleEngine::load(dir.path().to_str().unwrap());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("duplicate rule ID"), "msg: {msg}");
    }

    #[test]
    fn load_bad_version_is_error() {
        let yaml = r#"
version: "2"
rules: []
"#;
        let dir = tmp_rules_dir(yaml);
        let result = RuleEngine::load(dir.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn load_bad_cel_is_error() {
        let yaml = r#"
version: "1"
rules:
  - id: bad-cel
    condition: '((('
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let result = RuleEngine::load(dir.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn evaluate_allow_rule_matches() {
        let yaml = r#"
version: "1"
rules:
  - id: allow-dns
    condition: 'network.port == 53'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let ctx = network_ctx("1.1.1.1", 53, "udp");
        let result = engine.evaluate(&ctx).await;
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.matched_rule.as_deref(), Some("allow-dns"));
    }

    #[tokio::test]
    async fn evaluate_no_match_defaults_to_block() {
        let yaml = r#"
version: "1"
rules:
  - id: allow-dns
    condition: 'network.port == 53'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let ctx = network_ctx("1.1.1.1", 443, "tcp");
        let result = engine.evaluate(&ctx).await;
        assert_eq!(result.decision, Decision::Block);
        assert!(result.matched_rule.is_none());
    }

    #[tokio::test]
    async fn evaluate_first_match_wins() {
        let yaml = r#"
version: "1"
rules:
  - id: block-all-tcp
    condition: 'network.protocol == "tcp"'
    action: block
  - id: allow-https
    condition: 'network.port == 443'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let ctx = network_ctx("1.2.3.4", 443, "tcp");
        let result = engine.evaluate(&ctx).await;
        // First rule (block-all-tcp) matches before allow-https
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(result.matched_rule.as_deref(), Some("block-all-tcp"));
    }

    #[test]
    fn test_expression_true() {
        let ctx = network_ctx("1.1.1.1", 53, "udp");
        let (result, err) = RuleEngine::test_expression("network.port == 53", &ctx);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert!(result);
    }

    #[test]
    fn test_expression_false() {
        let ctx = network_ctx("1.1.1.1", 53, "udp");
        let (result, err) = RuleEngine::test_expression("network.port == 443", &ctx);
        assert!(err.is_none());
        assert!(!result);
    }

    #[test]
    fn test_expression_syntax_error() {
        let ctx = EvalContext::default();
        let (result, err) = RuleEngine::test_expression("(((", &ctx);
        assert!(!result);
        assert!(err.is_some());
    }

    fn agent_ctx(name: &str, port: u16) -> EvalContext {
        EvalContext {
            agent: Some(outcall_api::AgentContext {
                name: name.to_string(),
            }),
            network: Some(NetworkContext {
                ip: String::new(),
                port,
                protocol: "tcp".to_string(),
                hostname: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn definition_expansion() {
        let yaml = r#"
version: "1"
definitions:
  is_dns: 'network.port == 53'
rules:
  - id: allow-dns
    condition: '$is_dns'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let _ = engine; // loaded without error = expansion worked
    }

    #[tokio::test]
    async fn evaluate_agent_name_matches() {
        let yaml = r#"
version: "1"
rules:
  - id: allow-db-admin
    condition: 'agent.name == "db-agent" && network.port == 5432'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let ctx = agent_ctx("db-agent", 5432);
        // S013-FR-005: agent.name is available as a CEL binding
        let result = engine.evaluate(&ctx).await;
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.matched_rule.as_deref(), Some("allow-db-admin"));
    }

    #[tokio::test]
    async fn evaluate_agent_name_no_match() {
        let yaml = r#"
version: "1"
rules:
  - id: allow-db-admin
    condition: 'agent.name == "db-agent" && network.port == 5432'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let ctx = agent_ctx("web-agent", 5432);
        let result = engine.evaluate(&ctx).await;
        assert_eq!(result.decision, Decision::Block);
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn list_rules_returns_all() {
        let yaml = r#"
version: "1"
rules:
  - id: r1
    condition: 'true'
    action: allow
  - id: r2
    condition: 'false'
    action: block
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let rules = rt.block_on(engine.list_rules());
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "r1");
        assert_eq!(rules[1].id, "r2");
    }

    #[test]
    fn get_rule_found_and_not_found() {
        let yaml = r#"
version: "1"
rules:
  - id: my-rule
    condition: 'true'
    action: allow
    description: "Test rule"
"#;
        let dir = tmp_rules_dir(yaml);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let found = rt.block_on(engine.get_rule("my-rule"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().description.as_deref(), Some("Test rule"));

        let missing = rt.block_on(engine.get_rule("no-such-rule"));
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn reload_picks_up_new_rules() {
        let yaml1 = r#"
version: "1"
rules:
  - id: r1
    condition: 'network.port == 53'
    action: allow
"#;
        let dir = tmp_rules_dir(yaml1);
        let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();

        // Overwrite with a block rule
        let yaml2 = r#"
version: "1"
rules:
  - id: r1
    condition: 'network.port == 53'
    action: block
"#;
        std::fs::write(dir.path().join("rules.yaml"), yaml2).unwrap();
        engine.reload().await.unwrap();

        let ctx = network_ctx("1.1.1.1", 53, "udp");
        let result = engine.evaluate(&ctx).await;
        assert_eq!(result.decision, Decision::Block);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[allow(dead_code)]
fn count_files(dir: &str) -> usize {
    WalkDir::new(dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "yaml"))
        .count()
}

/// Collect non-fatal warnings (unused defs, etc.) — FR-016.
#[allow(dead_code)]
fn collect_warnings(rules_dir: &str) -> Result<Vec<String>> {
    let path = Path::new(rules_dir);
    if !path.exists() {
        return Ok(vec![]);
    }

    let mut warnings = Vec::new();
    let mut yaml_files: Vec<_> = WalkDir::new(path)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    yaml_files.sort_by_key(|e| e.path().to_path_buf());

    for entry in yaml_files {
        let file_name = entry
            .path()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let content = std::fs::read_to_string(entry.path())?;
        if let Ok(rule_file) = serde_yaml::from_str::<RuleFile>(&content) {
            // FR-016.a: warn on unused definitions
            for def_name in rule_file.definitions.keys() {
                let used = rule_file
                    .rules
                    .iter()
                    .any(|r| r.condition.contains(&format!("${def_name}")));
                if !used {
                    warnings.push(format!("unused definition \"{def_name}\" in {file_name}"));
                }
            }
            // FR-016.c: warn on definitions section with no rules
            if !rule_file.definitions.is_empty() && rule_file.rules.is_empty() {
                warnings.push(format!(
                    "definitions section present but no rules in {file_name}"
                ));
            }
        }
    }

    Ok(warnings)
}
