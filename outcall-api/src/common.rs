use serde::{Deserialize, Serialize};

pub const UNREACHABLE_EXIT_CODE: i32 = 5;
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const DEFAULT_HOST_SOCKET: &str = "/tmp/outcall/host.sock";
pub const DEFAULT_AGENT_SOCKET: &str = "/tmp/outcall/agent.sock";
pub const DEFAULT_BRIDGE_NAME: &str = "outcall0";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/outcall";
pub const RULE_REQUESTS_FILE: &str = "rule-requests.json";

/// Standard API response envelope used by the host API.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T = ()> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}
