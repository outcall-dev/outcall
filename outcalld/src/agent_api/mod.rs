//! Container-facing policy API served on `/run/outcall/agent.sock` (S004).
//!
//! Every request is tied to Linux `SO_PEERCRED` and a live daemon-managed
//! Docker container. Agents cannot choose their own identity.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::{Mutex, Semaphore};
use tracing::warn;

use crate::background_task::BackgroundTask;
use crate::docker::{ContainerEvent, ContainerEventKind, DockerManager};
use crate::rules::RuleEngine;

mod context;
mod errors;
mod evaluation;
mod handlers;
mod identity;
mod limiter;
mod rule_requests;
mod sessions;

#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(crate) use context::derive_agent_name;
pub use errors::AgentApiError;
use evaluation::EvaluationExecutor;
use limiter::SlidingWindow;
pub(crate) use rule_requests::valid_request_id;
pub use rule_requests::{RuleRequestEntry, RuleRequestManager};
use sessions::SessionRegistry;

pub use identity::UnixPeerCred;

const AGENT_API_BODY_LIMIT: usize = 65_536;
const IDENTITY_LOOKUP_CONCURRENCY: usize = 64;

#[derive(Clone)]
struct AgentState {
    docker: Arc<DockerManager>,
    rules: Arc<RuleEngine>,
    sessions: Arc<Mutex<SessionRegistry>>,
    permission_rates: Arc<Mutex<HashMap<String, SlidingWindow>>>,
    rule_rates: Arc<Mutex<HashMap<String, SlidingWindow>>>,
    identity_lookups: Arc<Semaphore>,
    rule_requests: RuleRequestManager,
    evaluations: EvaluationExecutor,
    permission_rate: RateLimitConfig,
    rule_rate: RateLimitConfig,
    _cleanup_task: Arc<BackgroundTask>,
}

#[derive(Clone, Copy)]
pub struct RateLimitConfig {
    pub limit: usize,
    pub window: Duration,
}

#[derive(Clone, Copy)]
pub struct AgentApiConfig {
    pub eval_timeout: Duration,
    pub permission_rate: RateLimitConfig,
    pub rule_rate: RateLimitConfig,
}

pub fn router(
    docker: Arc<DockerManager>,
    rules: Arc<RuleEngine>,
    config: AgentApiConfig,
    rule_requests: RuleRequestManager,
) -> Router {
    let cleanup_task = Arc::new(BackgroundTask::new());
    let state = AgentState {
        docker,
        rules,
        sessions: Default::default(),
        permission_rates: Default::default(),
        rule_rates: Default::default(),
        identity_lookups: Arc::new(Semaphore::new(IDENTITY_LOOKUP_CONCURRENCY)),
        rule_requests,
        evaluations: EvaluationExecutor::new(config.eval_timeout),
        permission_rate: config.permission_rate,
        rule_rate: config.rule_rate,
        _cleanup_task: cleanup_task.clone(),
    };
    spawn_session_cleanup(&state, &cleanup_task);

    Router::new()
        .route("/v1/checkin", post(handlers::checkin))
        .route("/v1/permissions/check", post(handlers::permissions_check))
        .route("/v1/requests/rules", post(handlers::rule_request_submit))
        .route(
            "/v1/requests/rules/{id}",
            get(handlers::rule_request_status),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(AGENT_API_BODY_LIMIT))
}

fn spawn_session_cleanup(state: &AgentState, task: &BackgroundTask) {
    let mut events = state.docker.subscribe_events();
    let sessions = state.sessions.clone();
    let permission_rates = state.permission_rates.clone();
    let rule_rates = state.rule_rates.clone();
    let cancellation = task.cancellation_token();
    task.spawn(async move {
        loop {
            let received = tokio::select! {
                biased;
                () = cancellation.cancelled() => return,
                event = events.recv() => event,
            };
            let event = match received {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "agent session cleanup lagged; clearing derived state"
                    );
                    clear_derived_state(&sessions, &permission_rates, &rule_rates).await;
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    warn!("agent session event stream closed; clearing derived state");
                    clear_derived_state(&sessions, &permission_rates, &rule_rates).await;
                    return;
                }
            };
            match event {
                ContainerEvent::Reset => {
                    clear_derived_state(&sessions, &permission_rates, &rule_rates).await;
                }
                ContainerEvent::Lifecycle {
                    kind:
                        ContainerEventKind::Die
                        | ContainerEventKind::Oom
                        | ContainerEventKind::Kill
                        | ContainerEventKind::Destroy,
                    container_id,
                    ..
                } => {
                    sessions.lock().await.remove_container(&container_id);
                    permission_rates.lock().await.remove(&container_id);
                    rule_rates.lock().await.remove(&container_id);
                }
                ContainerEvent::Lifecycle { .. } => {}
            }
        }
    });
}

async fn clear_derived_state(
    sessions: &Mutex<SessionRegistry>,
    permission_rates: &Mutex<HashMap<String, SlidingWindow>>,
    rule_rates: &Mutex<HashMap<String, SlidingWindow>>,
) {
    sessions.lock().await.clear();
    permission_rates.lock().await.clear();
    rule_rates.lock().await.clear();
}
