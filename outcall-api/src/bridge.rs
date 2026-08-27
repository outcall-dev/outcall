use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStatus {
    pub name: String,
    pub up: bool,
    pub index: Option<u32>,
    pub nftables_active: bool,
}
