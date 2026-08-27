//! Rule engine: YAML loading, CEL compilation, and evaluation (S003).

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use cel_interpreter::{Context as CelCtx, Value};
use outcall_api::{
    Decision, DnsContext, DockerContext, EvalContext, EvaluateResult, HttpContext, NetworkContext,
    RuleAction, RuleDetail, RuleSummary, RunContext,
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::loader::{load_rules, validate_rule_yaml};
use super::model::{EgressMode, EgressSpec, RuleSet};

/// The rule engine. Holds a hot-swappable compiled rule set.
#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct RuleEngine {
    pub rules_dir: String,
    rule_set: Arc<RwLock<Arc<RuleSet>>>,
}

/// A verdict and its egress metadata from one immutable rule-set snapshot.
/// Keeping these together prevents a reload from changing a matched rule's
/// privileges between evaluation and enforcement.
#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct RuleEvaluation {
    pub(crate) result: EvaluateResult,
    pub(crate) egress: Option<EgressSpec>,
}

pub(crate) struct PreparedReload {
    rule_set: RuleSet,
    files_loaded: usize,
    warnings: Vec<String>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct RuleSnapshot(Arc<RuleSet>);

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl RuleEngine {
    /// Load rules from `rules_dir`, compile CEL expressions, return the engine.
    /// Returns an error if any P1 static analysis check fails (S003-FR-014/015).
    /// Rules with `egress.mode: intercept` are rejected until S011 is implemented.
    pub fn load(rules_dir: &str) -> Result<Self> {
        let loaded = load_rules(rules_dir)?;
        Ok(Self {
            rules_dir: rules_dir.to_string(),
            rule_set: Arc::new(RwLock::new(Arc::new(loaded.rule_set))),
        })
    }

    /// Evaluate a request context against the current rule set.
    /// Returns the first matching allow/block verdict, or default block.
    pub async fn evaluate(&self, ctx: &EvalContext) -> EvaluateResult {
        let rule_set = self.snapshot().await;
        Self::evaluate_snapshot(&rule_set, ctx)
    }

    /// Evaluate and return the matched rule's egress metadata from the same
    /// immutable snapshot.
    pub(crate) async fn evaluate_with_egress(&self, ctx: &EvalContext) -> RuleEvaluation {
        let rule_set = self.snapshot().await;
        Self::evaluate_snapshot_with_egress(&rule_set, ctx)
    }

    /// Capture the current immutable rule set for evaluation on another task.
    pub(crate) async fn snapshot(&self) -> Arc<RuleSet> {
        self.rule_set.read().await.clone()
    }

    pub(crate) async fn rollback_snapshot(&self) -> RuleSnapshot {
        RuleSnapshot(self.snapshot().await)
    }

    pub(crate) async fn restore_snapshot(&self, snapshot: RuleSnapshot) {
        *self.rule_set.write().await = snapshot.0;
        info!("previous rule snapshot restored");
    }

    /// Evaluate against a previously captured rule set without awaiting.
    pub(crate) fn evaluate_snapshot(rule_set: &RuleSet, ctx: &EvalContext) -> EvaluateResult {
        let started = Instant::now();

        let mut result = EvaluateResult {
            decision: Decision::Block,
            matched_rule: None,
            file: None,
            logged: false,
        };
        let cel_ctx = match build_cel_context(ctx) {
            Ok(context) => context,
            Err(error) => {
                warn!(%error, "failed to construct CEL context; request blocked");
                return result;
            }
        };

        for rule in &rule_set.rules {
            // Surface CEL runtime errors at warn! so an operator notices a
            // broken rule instead of it silently never matching. Audit H-1.
            let matched = match rule.program.execute(&cel_ctx) {
                Ok(Value::Bool(b)) => b,
                Ok(other) => {
                    warn!(
                        rule_id = %rule.id,
                        file = %rule.file,
                        "rule condition evaluated to non-bool: {other:?}"
                    );
                    false
                }
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        file = %rule.file,
                        error = %e,
                        "rule condition raised at runtime — treated as no-match"
                    );
                    false
                }
            };

            if !matched {
                continue;
            }

            // Loader validation rejects enrich rules. Keep evaluation fail-closed
            // in case an invalid rule set is ever constructed internally.
            if rule.action == RuleAction::Enrich {
                warn!(rule_id = %rule.id, "unsupported enrich rule reached evaluation");
                result.matched_rule = Some(rule.id.clone());
                result.file = Some(rule.file.clone());
                result.logged = true;
                break;
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

    pub(crate) fn evaluate_snapshot_with_egress(
        rule_set: &RuleSet,
        ctx: &EvalContext,
    ) -> RuleEvaluation {
        let result = Self::evaluate_snapshot(rule_set, ctx);
        let egress = result.matched_rule.as_deref().and_then(|id| {
            rule_set
                .rules
                .iter()
                .find(|rule| rule.id == id)
                .and_then(|rule| rule.egress.clone())
        });
        RuleEvaluation { result, egress }
    }

    /// Reload the rule set from disk atomically (S003-FR-021/022/023).
    /// Rules with `egress.mode: intercept` are rejected until S011 is implemented.
    pub async fn reload(&self) -> Result<(usize, usize, Vec<String>)> {
        let prepared = self.prepare_reload().await?;
        Ok(self.commit_reload(prepared).await)
    }

    /// Parse and compile a replacement rule set without changing live policy.
    pub(crate) async fn prepare_reload(&self) -> Result<PreparedReload> {
        let rules_dir = self.rules_dir.clone();
        let loaded = tokio::task::spawn_blocking(move || load_rules(&rules_dir))
            .await
            .map_err(|error| anyhow::anyhow!("rule preparation task failed: {error}"))??;
        Ok(PreparedReload {
            rule_set: loaded.rule_set,
            files_loaded: loaded.files_loaded,
            warnings: loaded.warnings,
        })
    }

    /// Atomically expose a prevalidated rule set.
    pub(crate) async fn commit_reload(
        &self,
        prepared: PreparedReload,
    ) -> (usize, usize, Vec<String>) {
        let files = prepared.files_loaded;
        let rules = prepared.rule_set.rules.len();
        let warnings = prepared.warnings;

        *self.rule_set.write().await = Arc::new(prepared.rule_set);
        info!(files, rules, "rules reloaded");
        (files, rules, warnings)
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

    /// Return true if any loaded rule explicitly requires the L7 proxy.
    pub async fn has_proxy_egress_rules(&self) -> bool {
        self.rule_set.read().await.rules.iter().any(|r| {
            r.action == RuleAction::Allow
                && r.egress
                    .as_ref()
                    .is_some_and(|e| e.mode == EgressMode::Proxy)
        })
    }

    /// Validate a rule YAML string without modifying the engine's rule set.
    /// Returns `Ok(())` if the file parses and all CEL expressions compile.
    ///
    /// Expands `$name` definition references before compiling so a rule that
    /// uses the `definitions` shorthand is validated against its expanded
    /// form, not the raw `$name` placeholder (which would fail CEL parsing).
    pub fn validate_rule_file(rule_yaml: &str) -> Result<(), String> {
        validate_rule_yaml(rule_yaml)
    }

    /// Evaluate a single CEL expression against a context (for the test endpoint).
    pub fn test_expression(expr: &str, ctx: &EvalContext) -> (bool, Option<String>) {
        match cel_interpreter::Program::compile(expr) {
            Err(e) => (false, Some(format!("CEL parse error: {e}"))),
            Ok(prog) => {
                let cel_ctx = match build_cel_context(ctx) {
                    Ok(context) => context,
                    Err(error) => {
                        return (false, Some(format!("CEL context error: {error}")));
                    }
                };
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

// ── CEL context building ──────────────────────────────────────────────────

/// Build a CEL evaluation context from the API EvalContext.
/// Absent namespaces are injected with zero values (FR-005.f).
fn build_cel_context(ctx: &EvalContext) -> std::result::Result<CelCtx<'static>, String> {
    let mut cel = CelCtx::default();

    let net = ctx.network.as_ref().cloned().unwrap_or_default();
    let http = ctx.http.as_ref().cloned().unwrap_or_default();
    let dns = ctx.dns.as_ref().cloned().unwrap_or_default();
    let docker = ctx.docker.as_ref().cloned().unwrap_or_default();
    let run = ctx.run.as_ref().cloned().unwrap_or_default();
    let agent = ctx.agent.as_ref().cloned().unwrap_or_default();

    cel.add_variable("network", network_value(&net))
        .map_err(|error| error.to_string())?;
    cel.add_variable("http", http_value(&http))
        .map_err(|error| error.to_string())?;
    cel.add_variable("dns", dns_value(&dns))
        .map_err(|error| error.to_string())?;
    cel.add_variable("docker", docker_value(&docker))
        .map_err(|error| error.to_string())?;
    cel.add_variable("run", run_value(&run))
        .map_err(|error| error.to_string())?;
    cel.add_variable("agent", agent_value(&agent))
        .map_err(|error| error.to_string())?;

    Ok(cel)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn network_value(n: &NetworkContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("hostname", Value::from(n.hostname.as_deref().unwrap_or("")));
    map.insert("ip", Value::from(n.ip.as_str()));
    map.insert("port", Value::from(n.port as i64));
    map.insert("protocol", Value::from(n.protocol.as_str()));
    Value::from(map)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn dns_value(d: &DnsContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("query", Value::from(d.query.as_str()));
    map.insert("record_type", Value::from(d.record_type.as_str()));
    Value::from(map)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_value(r: &RunContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("tool", Value::from(r.tool.as_str()));
    map.insert("args", Value::from(str_list(&r.args)));
    map.insert("flags", Value::from(str_list(&r.flags)));
    map.insert("cwd", Value::from(r.cwd.as_str()));
    let context = cel_interpreter::to_value(&r.context).unwrap_or_else(|error| {
        warn!(%error, "failed to convert run.context to a CEL value");
        Value::from(HashMap::<&str, Value>::new())
    });
    map.insert("context", context);
    Value::from(map)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn str_list(v: &[String]) -> Vec<Value> {
    v.iter().map(|s| Value::from(s.as_str())).collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn agent_value(a: &outcall_api::AgentContext) -> Value {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("name", Value::from(a.name.as_str()));
    Value::from(map)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}
#[cfg(test)]
mod tests;
