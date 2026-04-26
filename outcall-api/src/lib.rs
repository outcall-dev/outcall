use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Exit code when the agent shim cannot reach outcalld.
pub const UNREACHABLE_EXIT_CODE: i32 = 5;

/// Default request timeout for the agent shim (seconds).
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default heartbeat interval for the agent shim (seconds).
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 10;

/// Default path for the host API unix socket.
pub const DEFAULT_HOST_SOCKET: &str = "/run/outcall/host.sock";

/// Default path for the agent API unix socket (bind-mounted into containers).
pub const DEFAULT_AGENT_SOCKET: &str = "/run/outcall/agent.sock";

/// Default bridge interface name.
pub const DEFAULT_BRIDGE_NAME: &str = "outcall0";

/// Default directory for persistent daemon state.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/outcall";

/// Default filename for the rule-requests persistence file.
pub const RULE_REQUESTS_FILE: &str = "rule-requests.json";

// ── Agent API types ──

/// Action types the agent shim can request permission for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Invoke a named tool (e.g. `read_file`, `write_file`).
    ToolExec,
    /// Make an outbound network connection.
    NetworkCall,
    /// Access a file path on the filesystem.
    FileAccess,
    /// Execute a shell command.
    ShellExec,
}

/// Data returned by a successful check-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckinData {
    /// Opaque container identifier derived host-side from SO_PEERCRED.
    pub container_id: String,
    /// Session token to include with subsequent permission requests.
    pub session_token: String,
    /// Context keys the agent should include with permission requests.
    pub context_keys: Vec<String>,
}

/// Permission check request sent by the agent shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub action_type: ActionType,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

// ── Rule types ──

/// Action a matched rule can take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
    Enrich,
}

/// Verdict returned to callers after rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub allowed: bool,
    pub matched_rule: Option<String>,
    pub reason: Option<String>,
}

/// A request from an agent to create a new rule (queued for host approval).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRequest {
    pub description: String,
    pub condition: String,
    pub action: RuleAction,
}

/// Status of a pending rule request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleRequestStatus {
    Pending,
    Approved,
    Rejected,
}

/// Response for a rule request query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRequestResponse {
    pub id: String,
    pub status: RuleRequestStatus,
    pub reason: Option<String>,
}

// ── Rule engine types ──

/// One of the five CEL evaluation context namespaces.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkContext {
    pub hostname: Option<String>,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpContext {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub body_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsContext {
    pub query: String,
    pub record_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DockerContext {
    pub image: String,
    pub command: Vec<String>,
    pub volumes: Vec<String>,
    pub env_keys: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunContext {
    pub tool: String,
    pub args: Vec<String>,
    pub flags: Vec<String>,
    pub cwd: String,
    pub context: HashMap<String, serde_json::Value>,
}

/// Full CEL evaluation context sent to the evaluate endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalContext {
    pub network: Option<NetworkContext>,
    pub http: Option<HttpContext>,
    pub dns: Option<DnsContext>,
    pub docker: Option<DockerContext>,
    pub run: Option<RunContext>,
}

/// Request body for POST /api/v1/rule/evaluate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequest {
    pub context: EvalContext,
}

/// Verdict from the rule engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Block,
}

/// Response for the evaluate endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResult {
    pub decision: Decision,
    pub matched_rule: Option<String>,
    pub file: Option<String>,
    pub logged: bool,
}

/// Summary entry for GET /api/v1/rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub id: String,
    pub file: String,
    pub action: RuleAction,
    pub condition_preview: String,
    pub description: Option<String>,
}

/// Full rule detail for GET /api/v1/rule/:id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDetail {
    pub id: String,
    pub condition: String,
    pub action: RuleAction,
    pub log: bool,
    pub description: Option<String>,
    pub priority: Option<i32>,
}

/// Result of a rule reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResult {
    pub files_loaded: usize,
    pub rules_loaded: usize,
    pub warnings: Vec<String>,
}

/// Request body for POST /api/v1/rule/test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExpressionRequest {
    pub expression: String,
    pub context: EvalContext,
}

/// Result of a CEL expression test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExpressionResult {
    pub result: bool,
    pub error: Option<String>,
}

// ── Bridge types ──

/// Status of the network bridge and its nftables rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStatus {
    pub name: String,
    pub up: bool,
    pub index: Option<u32>,
    pub nftables_active: bool,
}

// ── API envelope ──

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

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

// ── DNS filter types (S007) ──

/// Status of the DNS filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterStatus {
    pub running: bool,
    pub listen_address: String,
    pub listen_port: u16,
    pub upstreams: Vec<String>,
    pub cache_entries: usize,
    pub queries_total: u64,
    pub queries_allowed: u64,
    pub queries_blocked: u64,
}

/// DNS cache statistics (without entry list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheStats {
    pub entries: usize,
    pub max_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// One entry in the DNS cache list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub record_type: String,
    pub ttl_remaining_secs: u32,
}

/// DNS cache stats plus optional entry list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheDetail {
    pub stats: DnsCacheStats,
    pub entries: Vec<DnsCacheEntry>,
}

/// Result of flushing the DNS cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheFlushResult {
    pub entries_flushed: usize,
}

// ── HTTP proxy types (S006) ──

/// Status of the HTTP proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub listen_address: String,
    pub proxy_url: String,
    pub active_connections: u64,
    pub total_requests: u64,
    pub total_blocked: u64,
}

// ── Network Management constants (S002) ──

/// Prefix applied to all outcall-managed Docker networks.
pub const NETWORK_PREFIX: &str = "outcall-";

/// Default network name (created on first `outcall network create`).
pub const DEFAULT_NETWORK_NAME: &str = "outcall-default";

/// Subnet block reserved for outcall network auto-allocation.
pub const SUBNET_BLOCK: &str = "10.200.0.0/16";

/// Default subnet for the default network.
pub const DEFAULT_SUBNET: &str = "10.200.0.0/24";

/// Default gateway for the default network.
pub const DEFAULT_GATEWAY: &str = "10.200.0.1";

// ── Network Management API types (S002) ──

/// Request body for POST /api/v1/network/create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCreateRequest {
    /// Name suffix (without `outcall-` prefix). When omitted, the default network is created.
    pub name: Option<String>,
    /// Explicit subnet override in CIDR form. Auto-allocated when omitted.
    pub subnet: Option<String>,
    /// Explicit gateway override. Defaults to the first usable address in the subnet.
    pub gateway: Option<String>,
}

/// Response body for POST /api/v1/network/create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCreateResult {
    pub network_id: String,
    pub name: String,
    /// `false` when the network already existed (idempotent).
    pub created: bool,
    /// Subnet the network is using (echoed for the CLI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
}

/// One container connected to a network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContainer {
    pub name: String,
    pub ipv4_address: String,
}

/// Status of a single network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub exists: bool,
    pub network_id: Option<String>,
    pub name: String,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub containers: Vec<NetworkContainer>,
}

/// Request body for POST /api/v1/network/destroy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDestroyRequest {
    pub name: Option<String>,
}

/// Response body for POST /api/v1/network/destroy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDestroyResult {
    pub name: String,
    pub destroyed: bool,
}

// ── Docker Manager constants (S008) ──

/// Prefix applied to all agent container names.
pub const CONTAINER_PREFIX: &str = "outcall-agent-";

/// Path inside the container where the agent unix socket is mounted.
pub const AGENT_SOCKET_CONTAINER_PATH: &str = "/run/outcall/agent.sock";

/// Path inside the container where the outcall-agent shim is mounted.
pub const SHIM_CONTAINER_PATH: &str = "/usr/local/bin/outcall";

/// Default timeout (seconds) before SIGKILL on container stop.
pub const DEFAULT_STOP_TIMEOUT_SECS: i64 = 10;

/// Default container memory limit: 512 MiB.
pub const DEFAULT_MEMORY_LIMIT: i64 = 512 * 1024 * 1024;

/// Default CPU shares (normal priority).
pub const DEFAULT_CPU_SHARES: i64 = 1024;

/// Default PID limit per container.
pub const DEFAULT_PID_LIMIT: i64 = 256;

/// Paths that must never be bind-mounted into agent containers.
/// Always includes the host socket; the daemon adds runtime overrides.
pub const HOST_SOCKET_DENY_PATHS: &[&str] = &[DEFAULT_HOST_SOCKET];

// ── Docker Manager API types (S008) ──

/// Request body for POST /api/v1/container/create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerCreateRequest {
    /// Docker image to run (required).
    pub image: String,
    /// Network to connect the container to (default: `outcall-default`).
    pub network: Option<String>,
    /// Full container name. If omitted, a random `outcall-<hex>` name is generated.
    pub name: Option<String>,
    /// Memory limit in bytes (default: 512 MiB).
    pub memory_limit: Option<i64>,
    /// CPU shares (default: 1024).
    pub cpu_shares: Option<i64>,
    /// Extra environment variables merged with mandatory proxy/DNS vars.
    pub env: Option<Vec<String>>,
    /// Override default container command.
    pub cmd: Option<Vec<String>>,
    /// Additional bind mounts in Docker format `host-path:container-path[:options]`.
    /// The outcall agent socket and shim are always added automatically.
    pub volumes: Option<Vec<String>>,
}

/// Response for POST /api/v1/container/create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerCreateResult {
    pub container_id: String,
    pub name: String,
    pub created: bool,
}

/// Request body for POST /api/v1/container/stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStopRequest {
    pub name: String,
    /// Seconds to wait after SIGTERM before SIGKILL (default: 10).
    pub timeout: Option<i64>,
}

/// Response for POST /api/v1/container/stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStopResult {
    pub name: String,
    pub stopped: bool,
}

/// Request body for POST /api/v1/container/remove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRemoveRequest {
    pub name: String,
    /// If true, stop a running container before removing.
    pub force: Option<bool>,
}

/// Response for POST /api/v1/container/remove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRemoveResult {
    pub name: String,
    pub removed: bool,
}

/// One entry in the container list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub network: String,
    pub created_at: String,
}

/// Detailed container inspection result.
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

/// Request body for POST /api/v1/container/pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePullRequest {
    pub image: String,
}

/// Response for POST /api/v1/container/pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePullResult {
    pub image: String,
    /// True if the image was actually downloaded; false if already present.
    pub pulled: bool,
}

/// Request body for POST /v1/requests/rules (agent API, S004-IF-003).
/// The body MUST be a complete, valid S003-format YAML rule file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuleSubmitRequest {
    /// Complete S003-format YAML rule file (version + rules array).
    pub rule_file: String,
}

// ── Dynamic Rules types (S009) ──

/// Request to insert a dynamic nftables allow rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowRuleRequest {
    /// Container name (e.g. `outcall-agent-a3f7b201`).
    pub container: String,
    /// Source IP of the container on the outcall network.
    pub src_ip: String,
    /// Destination — IP address, CIDR, or hostname (resolved at insertion time).
    pub destination: String,
    /// Protocol: "tcp" or "udp". Optional — if omitted, all protocols allowed.
    pub protocol: Option<String>,
    /// Destination port. Optional — if omitted, all ports allowed.
    pub port: Option<u16>,
}

/// A single active dynamic nftables allow rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveRule {
    pub container: String,
    pub src_ip: String,
    pub destination: String,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub nft_handle: u64,
    pub inserted_at: String,
}

/// Result of inserting a dynamic rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowRuleResult {
    pub nft_handle: u64,
}

/// Result of flushing all dynamic rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushDynamicResult {
    pub removed: usize,
}
