use serde::{Deserialize, Serialize};

pub const NETWORK_PREFIX: &str = "outcall-";
pub const DEFAULT_NETWORK_NAME: &str = "outcall-default";
pub const SUBNET_BLOCK: &str = "10.200.0.0/16";
pub const DEFAULT_SUBNET: &str = "10.200.0.0/24";
pub const DEFAULT_GATEWAY: &str = "10.200.0.1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCreateRequest {
    pub name: Option<String>,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCreateResult {
    pub network_id: String,
    pub name: String,
    pub created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContainer {
    pub name: String,
    pub ipv4_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub exists: bool,
    pub network_id: Option<String>,
    pub name: String,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub containers: Vec<NetworkContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestroyRequest {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestroyResult {
    pub name: String,
    pub destroyed: bool,
}
