use super::*;
use outcall_api::{Decision, EvalContext, NetworkContext};
use std::collections::HashMap;
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

#[test]
fn run_context_preserves_json_value_types() {
    let ctx = EvalContext {
        run: Some(RunContext {
            context: HashMap::from([
                ("attempts".to_string(), serde_json::json!(3)),
                ("approved".to_string(), serde_json::json!(true)),
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let (result, error) =
        RuleEngine::test_expression("run.context.attempts == 3 && run.context.approved", &ctx);

    assert!(error.is_none(), "unexpected error: {error:?}");
    assert!(result);
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

#[tokio::test]
async fn snapshot_keeps_verdict_and_egress_privileges_together_across_reload() {
    let yaml1 = r#"
version: "1"
rules:
  - id: allow-private
    condition: 'network.port == 443'
    action: allow
    egress:
      mode: proxy
      allow_private_ips: true
"#;
    let dir = tmp_rules_dir(yaml1);
    let engine = RuleEngine::load(dir.path().to_str().unwrap()).unwrap();
    let snapshot = engine.snapshot().await;

    let yaml2 = r#"
version: "1"
rules:
  - id: allow-private
    condition: 'network.port == 443'
    action: allow
    egress:
      mode: proxy
      allow_private_ips: false
"#;
    std::fs::write(dir.path().join("rules.yaml"), yaml2).unwrap();
    engine.reload().await.unwrap();

    let context = network_ctx("127.0.0.1", 443, "tcp");
    let old = RuleEngine::evaluate_snapshot_with_egress(&snapshot, &context);
    let current = engine.evaluate_with_egress(&context).await;

    assert_eq!(old.result.decision, Decision::Allow);
    assert!(old.egress.is_some_and(|egress| egress.allow_private_ips));
    assert!(current
        .egress
        .is_some_and(|egress| !egress.allow_private_ips));
}

#[test]
fn condition_preview_truncates_at_character_boundaries() {
    assert_eq!(
        truncate("allowed-\u{1f512}-destination", 9),
        "allowed-\u{1f512}…"
    );
}
