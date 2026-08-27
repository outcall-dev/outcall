use serde::{Deserialize, Serialize};

pub const MAX_DYNAMIC_RULE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleRequest {
    pub container: String,
    pub src_ip: String,
    pub destination: String,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveRule {
    pub container: String,
    pub src_ip: String,
    pub destination: String,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub nft_handle: u64,
    pub inserted_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleResult {
    pub nft_handle: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushDynamicResult {
    pub removed: usize,
}
