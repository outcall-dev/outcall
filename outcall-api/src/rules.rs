use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const MAX_RULE_ID_BYTES: usize = 128;

pub fn valid_rule_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_RULE_ID_BYTES
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
    Enrich,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub allowed: bool,
    pub matched_rule: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRequest {
    pub description: String,
    pub condition: String,
    pub action: RuleAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleRequestStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRequestResponse {
    pub id: String,
    pub status: RuleRequestStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkContext {
    pub hostname: Option<String>,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HttpContext {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub body_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsContext {
    pub query: String,
    pub record_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DockerContext {
    pub image: String,
    pub command: Vec<String>,
    pub volumes: Vec<String>,
    pub env_keys: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RunContext {
    pub tool: String,
    pub args: Vec<String>,
    pub flags: Vec<String>,
    pub cwd: String,
    pub context: HashMap<String, serde_json::Value>,
}

/// Verified managed-container identity populated by outcalld.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentContext {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EvalContext {
    pub network: Option<NetworkContext>,
    pub http: Option<HttpContext>,
    pub dns: Option<DnsContext>,
    pub docker: Option<DockerContext>,
    pub run: Option<RunContext>,
    pub agent: Option<AgentContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    pub context: EvalContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateResult {
    pub decision: Decision,
    pub matched_rule: Option<String>,
    pub file: Option<String>,
    pub logged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub id: String,
    pub file: String,
    pub action: RuleAction,
    pub condition_preview: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDetail {
    pub id: String,
    pub condition: String,
    pub action: RuleAction,
    pub log: bool,
    pub description: Option<String>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadResult {
    pub files_loaded: usize,
    pub rules_loaded: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestExpressionRequest {
    pub expression: String,
    pub context: EvalContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestExpressionResult {
    pub result: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRuleRequest {
    pub id: String,
    pub container_id: String,
    pub rule_file: String,
    pub status: RuleRequestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveRuleResult {
    pub id: String,
    #[serde(alias = "nft_handle")]
    pub rules_loaded: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectRuleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectRuleResult {
    pub id: String,
}
