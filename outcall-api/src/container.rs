use serde::{Deserialize, Serialize};

use crate::common::DEFAULT_HOST_SOCKET;

pub const CONTAINER_PREFIX: &str = "outcall-";
pub const AGENT_SOCKET_CONTAINER_PATH: &str = "/run/outcall/agent.sock";
pub const SHIM_CONTAINER_PATH: &str = "/usr/local/bin/outcall";
pub const DEFAULT_STOP_TIMEOUT_SECS: i64 = 10;
pub const MAX_STOP_TIMEOUT_SECS: i64 = 300;
pub const MAX_CONTAINER_NAME_BYTES: usize = 128;
pub const DEFAULT_MEMORY_LIMIT: i64 = 512 * 1024 * 1024;
pub const MIN_MEMORY_LIMIT: i64 = 6 * 1024 * 1024;
pub const DEFAULT_CPU_SHARES: i64 = 1024;
pub const MIN_CPU_SHARES: i64 = 2;
pub const MAX_CPU_SHARES: i64 = 262_144;
pub const DEFAULT_PID_LIMIT: i64 = 256;
pub const DEFAULT_CONTAINER_USER: &str = "65532:65532";
pub const MANAGED_BY_LABEL: &str = "managed-by";
pub const MANAGED_BY_VALUE: &str = "outcalld";
pub const NETWORK_LABEL: &str = "outcall.network";
pub const CREATED_AT_LABEL: &str = "outcall.created-at";

pub const HOST_SOCKET_DENY_PATHS: &[&str] = &[
    DEFAULT_HOST_SOCKET,
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
];

pub fn valid_memory_limit(value: i64) -> bool {
    value >= MIN_MEMORY_LIMIT
}

pub fn valid_cpu_shares(value: i64) -> bool {
    (MIN_CPU_SHARES..=MAX_CPU_SHARES).contains(&value)
}

pub fn valid_stop_timeout(value: i64) -> bool {
    (0..=MAX_STOP_TIMEOUT_SECS).contains(&value)
}

pub fn valid_container_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_CONTAINER_NAME_BYTES
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

pub fn valid_container_user(value: &str) -> bool {
    let Some((uid, gid)) = value.split_once(':') else {
        return false;
    };
    !uid.is_empty()
        && !gid.is_empty()
        && !gid.contains(':')
        && uid.bytes().all(|byte| byte.is_ascii_digit())
        && gid.bytes().all(|byte| byte.is_ascii_digit())
        && uid.parse::<u32>().is_ok_and(|uid| uid != 0)
        && gid.parse::<u32>().is_ok_and(|gid| gid != 0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerCreateRequest {
    pub image: String,
    pub network: Option<String>,
    pub name: Option<String>,
    /// Numeric non-root Docker process identity (`UID:GID`). The daemon uses
    /// `DEFAULT_CONTAINER_USER` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub memory_limit: Option<i64>,
    pub cpu_shares: Option<i64>,
    pub env: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Docker `source:destination[:options]` mounts. Daemon-owned helper and
    /// resolver destinations cannot be shadowed by this list.
    pub volumes: Option<Vec<String>>,
    /// Opt in to bind-mounting the agent socket and shim from Docker's host
    /// namespace. Omitted values default to false because paths visible inside
    /// a containerized daemon are not necessarily valid Docker bind sources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_outcall_helper_mounts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interactive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerCreateResult {
    pub container_id: String,
    pub name: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerStopRequest {
    pub name: String,
    pub timeout: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerStopResult {
    pub name: String,
    pub stopped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRemoveRequest {
    pub name: String,
    pub force: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRemoveResult {
    pub name: String,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub network: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInspectResult {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub network: String,
    pub ip_address: String,
    pub mounts: Vec<String>,
    pub env: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePullRequest {
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePullResult {
    pub image: String,
    pub pulled: bool,
}
