//! Agent API (S004) — served on the agent Unix socket (`/run/outcall/agent.sock`).
//!
//! Provides check-in, permission checks, and rule request endpoints for the
//! `outcall-agent` shim running inside managed containers. Container identity
//! is derived host-side from `SO_PEERCRED` — agents cannot self-identify.

use std::collections::HashMap;
use std::path::Path as StdPath;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use outcall_api::{
    ActionType, AgentContext, AgentRuleSubmitRequest, ApiResponse, CheckinData, Decision,
    EvalContext, NetworkContext, PermissionRequest, RuleRequestResponse, RuleRequestStatus,
    RunContext, Verdict,
};

use crate::docker::DockerManager;
use crate::rules::RuleEngine;

// ── Peer credentials ──────────────────────────────────────────────────────────

/// Unix socket peer credentials extracted at connection time.
#[derive(Clone, Debug)]
pub struct UnixPeerCred {
    /// Host-namespace PID of the connecting process. `None` if unavailable.
    pub pid: Option<u32>,
}

impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, tokio::net::UnixListener>,
    > for UnixPeerCred
{
    fn connect_info(target: axum::serve::IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        let pid = target
            .io()
            .peer_cred()
            .ok()
            .and_then(|c| c.pid())
            .map(|p| p as u32);
        UnixPeerCred { pid }
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

struct Session {
    container_id: String,
    token: String,
}

struct SlidingWindow {
    timestamps: Vec<Instant>,
    window: Duration,
    limit: usize,
}

impl SlidingWindow {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            timestamps: Vec::new(),
            window,
            limit,
        }
    }

    /// Records a request and returns `true` if it is within the window limit.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.timestamps
            .retain(|t| now.duration_since(*t) < self.window);
        if self.timestamps.len() >= self.limit {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRequestEntry {
    pub container_id: String,
    /// Held verbatim for the host-side approval workflow (S004-FR-011).
    pub rule_file: String,
    pub status: RuleRequestStatus,
    pub reason: Option<String>,
}

// ── Rule Request Manager ──────────────────────────────────────────────────────

/// Shared handle to the in-memory + on-disk rule-request queue.
///
/// Both the agent API (submit/poll) and the host API (list/approve/reject) hold
/// a clone of this struct so they operate on the same underlying data.
#[derive(Clone)]
pub struct RuleRequestManager {
    pub requests: Arc<Mutex<HashMap<String, RuleRequestEntry>>>,
    pub state_path: String,
}

impl RuleRequestManager {
    pub fn new(state_path: String) -> Self {
        let requests = load_rule_requests(&state_path);
        Self { requests, state_path }
    }

    /// Return all entries whose status is `Pending`.
    pub async fn list_pending(&self) -> Vec<(String, RuleRequestEntry)> {
        let guard = self.requests.lock().await;
        guard
            .iter()
            .filter(|(_, e)| e.status == RuleRequestStatus::Pending)
            .map(|(id, e)| (id.clone(), e.clone()))
            .collect()
    }

    /// Return all entries regardless of status.
    pub async fn list_all(&self) -> Vec<(String, RuleRequestEntry)> {
        let guard = self.requests.lock().await;
        guard.iter().map(|(id, e)| (id.clone(), e.clone())).collect()
    }

    /// Mark a request `Approved` and persist.  Returns the entry (caller inserts the nft rule).
    /// Returns `None` if `id` does not exist.
    pub async fn approve(&self, id: &str) -> Option<RuleRequestEntry> {
        let mut guard = self.requests.lock().await;
        let entry = guard.get_mut(id)?;
        entry.status = RuleRequestStatus::Approved;
        let snapshot = entry.clone();
        persist_rule_requests(&self.state_path, &guard).await;
        Some(snapshot)
    }

    /// Mark a request `Rejected` with an optional reason and persist.
    /// Returns the cloned entry, or `None` if `id` does not exist.
    pub async fn reject(&self, id: &str, reason: Option<String>) -> Option<RuleRequestEntry> {
        let mut guard = self.requests.lock().await;
        let entry = guard.get_mut(id)?;
        entry.status = RuleRequestStatus::Rejected;
        entry.reason = reason;
        let snapshot = entry.clone();
        persist_rule_requests(&self.state_path, &guard).await;
        Some(snapshot)
    }

    /// Retrieve a single entry by ID.
    pub async fn get(&self, id: &str) -> Option<RuleRequestEntry> {
        let guard = self.requests.lock().await;
        guard.get(id).cloned()
    }

    /// Insert a new entry and persist immediately.
    pub async fn insert(&self, id: String, entry: RuleRequestEntry) {
        let mut guard = self.requests.lock().await;
        guard.insert(id, entry);
        persist_rule_requests(&self.state_path, &guard).await;
    }
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AgentState {
    docker: Arc<DockerManager>,
    rules: Arc<RuleEngine>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    container_tokens: Arc<Mutex<HashMap<String, String>>>,
    perm_rate: Arc<Mutex<HashMap<String, SlidingWindow>>>,
    rule_rate: Arc<Mutex<HashMap<String, SlidingWindow>>>,
    rule_mgr: RuleRequestManager,
    eval_timeout: Duration,
    perm_limit: usize,
    perm_window: Duration,
    rule_limit: usize,
    rule_window: Duration,
}

// ── Router ─────────────────────────────────────────────────────────────────────

/// Build the agent API router and return it together with the shared
/// `RuleRequestManager` so the host API can list/approve/reject requests.
pub fn router(
    docker: Arc<DockerManager>,
    rules: Arc<RuleEngine>,
    eval_timeout: Duration,
    perm_count: usize,
    perm_window: Duration,
    rule_count: usize,
    rule_window: Duration,
    rule_mgr: RuleRequestManager,
) -> Router {
    let state = AgentState {
        docker,
        rules,
        sessions: Default::default(),
        container_tokens: Default::default(),
        perm_rate: Default::default(),
        rule_rate: Default::default(),
        rule_mgr,
        eval_timeout,
        perm_limit: perm_count,
        perm_window,
        rule_limit: rule_count,
        rule_window,
    };

    Router::new()
        .route("/v1/checkin", post(checkin))
        .route("/v1/permissions/check", post(permissions_check))
        .route("/v1/requests/rules", post(rule_request_submit))
        .route("/v1/requests/rules/{id}", get(rule_request_status))
        .with_state(state)
        .layer(DefaultBodyLimit::max(65_536))
}

// ── Persistence ───────────────────────────────────────────────────────────────

/// Load rule requests from the JSON state file, or return an empty map if the
/// file does not exist or cannot be parsed.
fn load_rule_requests(path: &str) -> Arc<Mutex<HashMap<String, RuleRequestEntry>>> {
    let file_path = StdPath::new(path);
    if file_path.exists() {
        match std::fs::read_to_string(file_path) {
            Ok(contents) => {
                match serde_json::from_str::<HashMap<String, RuleRequestEntry>>(&contents) {
                    Ok(map) => {
                        info!(path = %path, count = map.len(), "loaded rule requests from disk");
                        return Arc::new(Mutex::new(map));
                    }
                    Err(e) => {
                        warn!(path = %path, error = %e, "failed to parse rule requests file, starting fresh");
                    }
                }
            }
            Err(e) => {
                warn!(path = %path, error = %e, "failed to read rule requests file, starting fresh");
            }
        }
    }
    Arc::new(Mutex::new(HashMap::new()))
}

/// Persist the rule requests map to the JSON state file.
async fn persist_rule_requests(state_path: &str, map: &HashMap<String, RuleRequestEntry>) {
    let file_path = StdPath::new(state_path);
    if let Some(parent) = file_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(path = %parent.display(), error = %e, "failed to create state directory");
                return;
            }
        }
    }
    let json = match serde_json::to_string_pretty(map) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "failed to serialize rule requests");
            return;
        }
    };
    if let Err(e) = tokio::fs::write(file_path, json).await {
        warn!(path = %state_path, error = %e, "failed to write rule requests file");
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

async fn resolve_session(state: &AgentState, headers: &HeaderMap) -> Result<String, Response> {
    let token = match bearer_token(headers) {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::err("invalid or missing session token")),
            )
                .into_response());
        }
    };
    let sessions = state.sessions.lock().await;
    match sessions.get(&token) {
        Some(s) => Ok(s.container_id.clone()),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::err("invalid or missing session token")),
        )
            .into_response()),
    }
}

// ── Handler: POST /v1/checkin ─────────────────────────────────────────────────

async fn checkin(
    ConnectInfo(peer): ConnectInfo<UnixPeerCred>,
    State(state): State<AgentState>,
) -> Response {
    let pid = match peer.pid {
        Some(p) => p,
        None => {
            warn!("check-in: peer credentials unavailable");
            return (
                StatusCode::FORBIDDEN,
                Json(ApiResponse::<CheckinData>::err(
                    "check-in rejected: peer credentials unavailable",
                )),
            )
                .into_response();
        }
    };

    let container_id = match state.docker.lookup_container_by_pid(pid).await {
        Some(id) => id,
        None => {
            warn!(
                peer_pid = pid,
                "check-in: peer PID does not belong to a known container"
            );
            return (
                StatusCode::FORBIDDEN,
                Json(ApiResponse::<CheckinData>::err(format!(
                    "check-in rejected: peer PID {pid} does not belong to a known container"
                ))),
            )
                .into_response();
        }
    };

    // Idempotent: return existing session if this container already checked in.
    {
        let container_tokens = state.container_tokens.lock().await;
        if let Some(existing_token) = container_tokens.get(&container_id) {
            let sessions = state.sessions.lock().await;
            if let Some(session) = sessions.get(existing_token) {
                info!(container_id = %container_id, "check-in: returning existing session");
                return (
                    StatusCode::OK,
                    Json(ApiResponse::ok(CheckinData {
                        container_id: session.container_id.clone(),
                        session_token: session.token.clone(),
                        context_keys: default_context_keys(),
                    })),
                )
                    .into_response();
            }
        }
    }

    let token = generate_token();
    let data = CheckinData {
        container_id: container_id.clone(),
        session_token: token.clone(),
        context_keys: default_context_keys(),
    };

    {
        let mut sessions = state.sessions.lock().await;
        let mut container_tokens = state.container_tokens.lock().await;
        sessions.insert(
            token.clone(),
            Session {
                container_id: container_id.clone(),
                token: token.clone(),
            },
        );
        container_tokens.insert(container_id.clone(), token);
    }

    info!(container_id = %container_id, peer_pid = pid, "check-in: new session");
    (StatusCode::OK, Json(ApiResponse::ok(data))).into_response()
}

fn default_context_keys() -> Vec<String> {
    vec![
        "action_type".to_string(),
        "target".to_string(),
        "metadata".to_string(),
    ]
}

// ── Handler: POST /v1/permissions/check ──────────────────────────────────────

async fn permissions_check(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<PermissionRequest>,
) -> Response {
    let container_id = match resolve_session(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // FR-014.a: configurable sliding-window rate limit per container.
    {
        let mut rate = state.perm_rate.lock().await;
        let limiter = rate
            .entry(container_id.clone())
            .or_insert_with(|| SlidingWindow::new(state.perm_limit, state.perm_window));
        if !limiter.allow() {
            warn!(container_id = %container_id, "permission check: rate limited");
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ApiResponse::<Verdict>::err(format!(
                    "rate limit exceeded for container {container_id}"
                ))),
            )
                .into_response();
            resp.headers_mut()
                // PRIVATE_INVARIANT_OK: "2" is a hardcoded literal; HeaderValue::from_str cannot fail.
                .insert("retry-after", "2".parse().unwrap());
            return resp;
        }
    }

    let eval_ctx = build_eval_context(&req, &container_id);

    // FR-015: server-side timeout — fail closed on expiry.
    let verdict =
        match tokio::time::timeout(state.eval_timeout, state.rules.evaluate(&eval_ctx)).await {
            Ok(result) => Verdict {
                allowed: matches!(result.decision, Decision::Allow),
                matched_rule: result.matched_rule.clone(),
                reason: if matches!(result.decision, Decision::Block) {
                    Some("blocked by policy".to_string())
                } else {
                    None
                },
            },
            Err(_) => {
                warn!(container_id = %container_id, "permission check: evaluation timeout");
                Verdict {
                    allowed: false,
                    matched_rule: None,
                    reason: Some("evaluation timeout".to_string()),
                }
            }
        };

    info!(
        container_id = %container_id,
        action_type = ?req.action_type,
        target = %req.target,
        allowed = verdict.allowed,
        "permission check"
    );

    (StatusCode::OK, Json(ApiResponse::ok(verdict))).into_response()
}

// ── Handler: POST /v1/requests/rules ─────────────────────────────────────────

async fn rule_request_submit(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Json(req): Json<AgentRuleSubmitRequest>,
) -> Response {
    let container_id = match resolve_session(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // FR-014.b: configurable sliding-window rate limit per container.
    {
        let mut rate = state.rule_rate.lock().await;
        let limiter = rate
            .entry(container_id.clone())
            .or_insert_with(|| SlidingWindow::new(state.rule_limit, state.rule_window));
        if !limiter.allow() {
            warn!(container_id = %container_id, "rule submit: rate limited");
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ApiResponse::<RuleRequestResponse>::err(format!(
                    "rate limit exceeded for container {container_id}"
                ))),
            )
                .into_response();
            resp.headers_mut()
                // PRIVATE_INVARIANT_OK: "60" is a hardcoded literal; HeaderValue::from_str cannot fail.
                .insert("retry-after", "60".parse().unwrap());
            return resp;
        }
    }

    if let Err(e) = RuleEngine::validate_rule_file(&req.rule_file) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ApiResponse::<RuleRequestResponse>::err(format!(
                "invalid rule file: {e}"
            ))),
        )
            .into_response();
    }

    let request_id = generate_request_id();
    let response = RuleRequestResponse {
        id: request_id.clone(),
        status: RuleRequestStatus::Pending,
        reason: None,
    };

    let entry = RuleRequestEntry {
        container_id: container_id.clone(),
        rule_file: req.rule_file,
        status: RuleRequestStatus::Pending,
        reason: None,
    };
    // FR-010: persist to disk after every write.
    state.rule_mgr.insert(request_id.clone(), entry).await;

    info!(container_id = %container_id, "rule request submitted");
    (StatusCode::CREATED, Json(ApiResponse::ok(response))).into_response()
}

// ── Handler: GET /v1/requests/rules/{id} ─────────────────────────────────────

async fn rule_request_status(
    State(state): State<AgentState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let container_id = match resolve_session(&state, &headers).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state.rule_mgr.get(&id).await {
        Some(entry) if entry.container_id == container_id => {
            let response = RuleRequestResponse {
                id: id.clone(),
                status: entry.status.clone(),
                reason: entry.reason.clone(),
            };
            (StatusCode::OK, Json(ApiResponse::ok(response))).into_response()
        }
        // EC: cross-container access returns 404 (no info leak about other containers).
        _ => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<RuleRequestResponse>::err(format!(
                "rule request {id} not found"
            ))),
        )
            .into_response(),
    }
}

// ── Context builder ───────────────────────────────────────────────────────────

use regex::Regex;

/// Derives the agent name from a container name by stripping the trailing `-N`
/// replica suffix. Falls back to the full name if no numeric suffix is found.
pub(crate) fn derive_agent_name(container_name: &str) -> String {
    static RE: std::sync::LazyLock<Regex> =
        // PRIVATE_INVARIANT_OK: regex literal is valid; LazyLock panics at first call if not,
        // which is equivalent to a startup crash, not a remote-triggered one.
        std::sync::LazyLock::new(|| Regex::new(r"-[0-9]+$").unwrap());
    RE.replace(container_name, "").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_agent_name() {
        assert_eq!(derive_agent_name("foobar-1"), "foobar");
        assert_eq!(derive_agent_name("foobar-12"), "foobar");
        assert_eq!(derive_agent_name("my-agent-12"), "my-agent");
        assert_eq!(derive_agent_name("standalone"), "standalone");
        assert_eq!(derive_agent_name("agent-0"), "agent");
    }
}

fn build_eval_context(req: &PermissionRequest, container_id: &str) -> EvalContext {
    let agent_name = derive_agent_name(container_id);

    let meta: HashMap<String, String> = req.metadata.clone().unwrap_or_default();

    let mut ctx = match req.action_type {
        ActionType::NetworkCall => {
            let (hostname, port) = parse_host_port(&req.target);
            EvalContext {
                network: Some(NetworkContext {
                    hostname: Some(hostname),
                    ip: String::new(),
                    port,
                    protocol: meta
                        .get("protocol")
                        .cloned()
                        .unwrap_or_else(|| "tcp".to_string()),
                }),
                ..Default::default()
            }
        }
        ActionType::ToolExec => EvalContext {
            run: Some(RunContext {
                tool: req.target.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
        ActionType::FileAccess => EvalContext {
            run: Some(RunContext {
                tool: "file".to_string(),
                args: vec![req.target.clone()],
                cwd: req.target.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
        ActionType::ShellExec => EvalContext {
            run: Some(RunContext {
                tool: "sh".to_string(),
                args: vec!["-c".to_string(), req.target.clone()],
                ..Default::default()
            }),
            ..Default::default()
        },
    };

    // S013-FR-002: Add agent identity to EvalContext
    ctx.agent = Some(AgentContext { name: agent_name });

    ctx
}

fn parse_host_port(target: &str) -> (String, u16) {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (target.to_string(), 443)
}

// ── Token / ID generators ─────────────────────────────────────────────────────

fn generate_token() -> String {
    let mut buf = [0u8; 16];
    fill_random(&mut buf);
    format!("tok-{}", hex_encode(&buf))
}

fn generate_request_id() -> String {
    let mut buf = [0u8; 6];
    fill_random(&mut buf);
    format!("rr-{}", hex_encode(&buf))
}

fn fill_random(buf: &mut [u8]) {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(buf);
    } else {
        // Fallback (degraded but never blocks): mix time and pid.
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id() as u128;
        let mut x = nanos ^ pid.rotate_left(33);
        for byte in buf.iter_mut() {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (x >> 56) as u8;
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        // PRIVATE_INVARIANT_OK: write! to a String (which impls fmt::Write) is infallible.
        write!(&mut s, "{:02x}", b).unwrap();
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_with_port() {
        assert_eq!(
            parse_host_port("example.com:8080"),
            ("example.com".to_string(), 8080)
        );
    }

    #[test]
    fn parse_host_port_without_port() {
        assert_eq!(
            parse_host_port("example.com"),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn sliding_window_allows_under_limit() {
        let mut w = SlidingWindow::new(3, Duration::from_secs(10));
        assert!(w.allow());
        assert!(w.allow());
        assert!(w.allow());
        assert!(!w.allow());
    }

    #[test]
    fn token_format() {
        let t = generate_token();
        assert!(t.starts_with("tok-"));
        assert_eq!(t.len(), "tok-".len() + 32);
        assert!(t["tok-".len()..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn request_id_format() {
        let id = generate_request_id();
        assert!(id.starts_with("rr-"));
        assert_eq!(id.len(), "rr-".len() + 12);
    }

    #[test]
    fn build_eval_context_network() {
        let req = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "evil.com:443".to_string(),
            metadata: None,
        };
        let ctx = build_eval_context(&req, "test-agent-1");
        let net = ctx.network.unwrap();
        assert_eq!(net.hostname, Some("evil.com".to_string()));
        assert_eq!(net.port, 443);
    }

    #[test]
    fn build_eval_context_shell() {
        let req = PermissionRequest {
            action_type: ActionType::ShellExec,
            target: "rm -rf /".to_string(),
            metadata: None,
        };
        let ctx = build_eval_context(&req, "test-agent-1");
        let run = ctx.run.unwrap();
        assert_eq!(run.tool, "sh");
        assert_eq!(run.args, vec!["-c".to_string(), "rm -rf /".to_string()]);
    }

    #[test]
    fn build_eval_context_agent_name() {
        // S013-FR-003: agent name is derived from container name
        let req = PermissionRequest {
            action_type: ActionType::NetworkCall,
            target: "example.com:443".to_string(),
            metadata: None,
        };
        let ctx = build_eval_context(&req, "my-agent-12");
        let agent = ctx.agent.unwrap();
        assert_eq!(agent.name, "my-agent");
    }
}
