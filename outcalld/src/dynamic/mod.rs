//! Dynamic Rules Manager (S009) — inserts and removes per-container nftables
//! allow rules in response to rule engine ALLOW verdicts.
//!
//! ## Design
//!
//! - All nftables operations are serialized through a `tokio::sync::Mutex`
//!   (FR-008) so concurrent container events don't race.
//! - Rules are inserted at the head of `inet outcall forward` chain (position 0)
//!   so they precede the base DROP rules (FR-005).
//! - The nftables rule handle is captured from `nft --handle --echo` output
//!   so individual rules can be deleted without flushing the whole chain (FR-007).
//! - A background task subscribes to `DockerManager`'s event channel and
//!   removes all rules for a container when it dies (FR-004).
//! - On daemon restart the daemon applies the base ruleset only; no previously
//!   active dynamic rules survive (FR-010) since they are stored in memory only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{info, warn};

use outcall_api::{
    ActiveRule, AllowRuleRequest, AllowRuleResult, FlushDynamicResult, MAX_DYNAMIC_RULE_TTL_SECS,
};

use crate::background_task::BackgroundTask;
#[cfg(target_os = "linux")]
use crate::bridge::BridgeManager;
use crate::docker::DockerManager;

mod destination;
mod events;
mod expiry;
mod nft;

#[cfg(target_os = "linux")]
use nft::SystemNftController;
use nft::{NftController, TestNftController};

const MAX_DYNAMIC_RULES_PER_CONTAINER: usize = 256;

#[derive(Clone, Copy)]
enum SourcePolicy {
    OperatorMayPrestage,
    RequireManaged,
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// In-memory record of one active dynamic nftables rule.
struct DynamicRuleRecord {
    container: String,
    src_ip: String,
    destination: String,
    protocol: Option<String>,
    port: Option<u16>,
    nft_handle: u64,
    inserted_at: String,
    expires_at: Option<Instant>,
}

/// Serialized state protected by a Mutex.
struct DynState {
    /// container_name → list of active rules for that container.
    rules: HashMap<String, Vec<DynamicRuleRecord>>,
}

// ── DynamicRuleManager ────────────────────────────────────────────────────────

pub struct DynamicRuleManager {
    state: Mutex<DynState>,
    docker: Arc<DockerManager>,
    nft: Arc<dyn NftController>,
    event_task: BackgroundTask,
    expiration_task: BackgroundTask,
}

impl DynamicRuleManager {
    /// Create the manager and spawn the Docker event watcher.
    #[cfg(target_os = "linux")]
    pub fn new(docker: Arc<DockerManager>, bridge: Arc<Mutex<BridgeManager>>) -> Arc<Self> {
        Self::with_nft_controller(docker, Arc::new(SystemNftController { bridge }))
    }

    #[doc(hidden)]
    pub fn new_without_policy_reset_for_tests(docker: Arc<DockerManager>) -> Arc<Self> {
        Self::with_nft_controller(docker, Arc::new(TestNftController))
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn new_with_noop_nft_for_tests(docker: Arc<DockerManager>) -> Arc<Self> {
        Self::with_nft_controller(docker, Arc::new(nft::NoopNftController))
    }

    fn with_nft_controller(docker: Arc<DockerManager>, nft: Arc<dyn NftController>) -> Arc<Self> {
        let event_task = BackgroundTask::new();
        let event_cancellation = event_task.cancellation_token();
        let expiration_task = BackgroundTask::new();
        let expiration_cancellation = expiration_task.cancellation_token();
        let mgr = Arc::new(Self {
            state: Mutex::new(DynState {
                rules: HashMap::new(),
            }),
            docker: docker.clone(),
            nft,
            event_task,
            expiration_task,
        });

        // Background task: watch for container death events → clean up rules.
        let rx = docker.subscribe_events();
        mgr.event_task
            .spawn(events::run(Arc::downgrade(&mgr), rx, event_cancellation));
        mgr.expiration_task
            .spawn(expiry::run(Arc::downgrade(&mgr), expiration_cancellation));

        mgr
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /// Insert a dynamic nftables allow rule for the given container/destination.
    ///
    /// Returns the nftables handle of the newly inserted rule (FR-007).
    pub async fn insert_rule(&self, req: AllowRuleRequest) -> Result<AllowRuleResult> {
        self.insert_rule_with_source_policy(req, SourcePolicy::OperatorMayPrestage)
            .await
    }

    /// Insert a rule only while the source IP belongs to the named container.
    pub async fn insert_managed_rule(&self, req: AllowRuleRequest) -> Result<AllowRuleResult> {
        self.insert_rule_with_source_policy(req, SourcePolicy::RequireManaged)
            .await
    }

    async fn insert_rule_with_source_policy(
        &self,
        req: AllowRuleRequest,
        source_policy: SourcePolicy,
    ) -> Result<AllowRuleResult> {
        // Validate protocol field to prevent malformed nftables expressions (DoS vector).
        // Protocol must be 'tcp' or 'udp' — invalid values cause `nft insert rule` to fail.
        if let Some(ref proto) = req.protocol {
            match proto.as_str() {
                "tcp" | "udp" => {}
                _ => anyhow::bail!("invalid protocol '{proto}': must be 'tcp' or 'udp'"),
            }
        }
        if req.port.is_some() && req.protocol.is_none() {
            anyhow::bail!("a destination port requires protocol 'tcp' or 'udp'");
        }
        let expires_at = expiration_deadline(req.expires_in_secs, Instant::now())?;

        let src_ip: IpAddr = req
            .src_ip
            .parse()
            .with_context(|| format!("invalid source IP address \"{}\"", req.src_ip))?;

        // The operator API may pre-stage a rule for an address that is not yet
        // assigned. Once Docker reports an owner, however, the requested name
        // must match; lookup failures are not treated as an absent owner.
        let initial_owner = self.docker.lookup_container_name_by_ip(&req.src_ip).await?;
        let initially_assigned = validate_source_owner(
            initial_owner.as_deref(),
            &req.container,
            source_policy,
            &req.src_ip,
        )?;

        let dst_ip = destination::resolve(&req.destination).await?;

        // Serialize duplicate checks, per-container caps, nftables mutation, and
        // in-memory recording so a DNS flood cannot race past the cap.
        let mut state = self.state.lock().await;
        let container_rules = state.rules.entry(req.container.clone()).or_default();
        if let Some(existing) = container_rules.iter_mut().find(|r| {
            r.src_ip == req.src_ip
                && r.destination == req.destination
                && r.protocol == req.protocol
                && r.port == req.port
        }) {
            renew_expiration(&mut existing.expires_at, expires_at, source_policy);
            return Ok(AllowRuleResult {
                nft_handle: existing.nft_handle,
            });
        }

        if container_rules.len() >= MAX_DYNAMIC_RULES_PER_CONTAINER {
            anyhow::bail!(
                "dynamic rule cap exceeded for container '{}' (max {})",
                req.container,
                MAX_DYNAMIC_RULES_PER_CONTAINER
            );
        }

        // Prepare all fallible record metadata before mutating nftables so a
        // clock error cannot leave an untracked allow rule behind.
        let inserted_at = crate::timestamp::now_iso8601()?;
        let handle = self
            .nft
            .insert(src_ip, &dst_ip, req.protocol.as_deref(), req.port)
            .await?;
        let record = DynamicRuleRecord {
            container: req.container.clone(),
            src_ip: req.src_ip.clone(),
            destination: req.destination.clone(),
            protocol: req.protocol.clone(),
            port: req.port,
            nft_handle: handle,
            inserted_at,
            expires_at,
        };
        container_rules.push(record);

        let current_owner = self.docker.lookup_container_name_by_ip(&req.src_ip).await;
        let ownership = current_owner.and_then(|owner| {
            let currently_assigned = validate_source_owner(
                owner.as_deref(),
                &req.container,
                source_policy,
                &req.src_ip,
            )?;
            if initially_assigned && !currently_assigned {
                anyhow::bail!(
                    "source IP {} became unassigned while inserting a rule for '{}'",
                    req.src_ip,
                    req.container
                );
            }
            Ok(())
        });
        if let Err(ownership_error) = ownership {
            warn!(
                container = %req.container,
                src_ip = %req.src_ip,
                handle,
                error = %ownership_error,
                "source ownership changed after dynamic rule insertion; rolling back"
            );
            let rollback = self
                .rollback_inserted_rule(&mut state, &req.container, handle)
                .await;
            return match rollback {
                Ok(()) => Err(ownership_error),
                Err(rollback_error) => Err(rollback_error.context(format!(
                    "source ownership changed after nft insertion: {ownership_error}"
                ))),
            };
        }

        Ok(AllowRuleResult { nft_handle: handle })
    }

    async fn rollback_inserted_rule(
        &self,
        state: &mut DynState,
        container: &str,
        handle: u64,
    ) -> Result<()> {
        let delete_error = match self.nft.delete(handle).await {
            Ok(()) => {
                remove_tracked_handle(state, container, handle);
                return Ok(());
            }
            Err(error) => error,
        };

        self.nft.reset_to_base_policy().await.with_context(|| {
            format!(
                "failed to delete unverified dynamic rule {handle} ({delete_error}) and emergency base-policy reset also failed"
            )
        })?;
        state.rules.clear();
        warn!(
            handle,
            "restored base policy after source ownership changed"
        );
        Ok(())
    }

    pub async fn container_name_for_ip(&self, ip: &str) -> Result<Option<String>> {
        self.docker.lookup_container_name_by_ip(ip).await
    }

    /// Remove all dynamic rules for a container (called on container death).
    pub async fn remove_container_rules(&self, container_name: &str) -> Result<usize> {
        let mut state = self.state.lock().await;
        let handles: Vec<u64> = match state.rules.get(container_name) {
            Some(rules) => rules.iter().map(|rule| rule.nft_handle).collect(),
            None => return Ok(0),
        };

        let count = handles.len();
        for handle in handles {
            if let Err(error) = self.nft.delete(handle).await {
                warn!(
                    container = %container_name,
                    handle,
                    %error,
                    "failed to delete nft rule; restoring fail-closed base policy"
                );
                self.nft.reset_to_base_policy().await.with_context(|| {
                    format!(
                        "failed to delete dynamic rule {handle} and emergency base-policy reset also failed"
                    )
                })?;
                state.rules.clear();
                info!("base policy restored; all dynamic rule records cleared");
                return Ok(count);
            }
        }
        state.rules.remove(container_name);
        if count > 0 {
            info!(container = %container_name, removed = count, "dynamic rules removed");
        }
        Ok(count)
    }

    /// List all currently active dynamic rules (FR-006, S009-IF-001).
    pub async fn list_rules(&self) -> Vec<ActiveRule> {
        let state = self.state.lock().await;
        let now = Instant::now();
        state
            .rules
            .values()
            .flat_map(|rules| {
                rules.iter().map(|r| ActiveRule {
                    container: r.container.clone(),
                    src_ip: r.src_ip.clone(),
                    destination: r.destination.clone(),
                    protocol: r.protocol.clone(),
                    port: r.port,
                    nft_handle: r.nft_handle,
                    inserted_at: r.inserted_at.clone(),
                    expires_in_secs: r
                        .expires_at
                        .map(|deadline| remaining_secs(deadline.saturating_duration_since(now))),
                })
            })
            .collect()
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn seed_rule_for_tests(&self, container: &str, handle: u64) {
        self.state
            .lock()
            .await
            .rules
            .entry(container.to_string())
            .or_default()
            .push(DynamicRuleRecord {
                container: container.to_string(),
                src_ip: "10.200.0.2".to_string(),
                destination: "1.1.1.1".to_string(),
                protocol: Some("tcp".to_string()),
                port: Some(443),
                nft_handle: handle,
                inserted_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: None,
            });
    }

    pub(super) async fn prune_expired(&self) -> Result<usize> {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        let expired: Vec<(String, u64)> = state
            .rules
            .iter()
            .flat_map(|(container, rules)| {
                rules.iter().filter_map(|rule| {
                    rule.expires_at
                        .filter(|deadline| *deadline <= now)
                        .map(|_| (container.clone(), rule.nft_handle))
                })
            })
            .collect();
        let total_tracked = state.rules.values().map(Vec::len).sum();

        for (container, handle) in &expired {
            if let Err(error) = self.nft.delete(*handle).await {
                warn!(
                    %container,
                    handle,
                    %error,
                    "failed to delete expired nft rule; restoring fail-closed base policy"
                );
                self.nft.reset_to_base_policy().await.with_context(|| {
                    format!(
                        "failed to delete expired dynamic rule {handle} and emergency base-policy reset also failed"
                    )
                })?;
                state.rules.clear();
                info!(
                    removed = total_tracked,
                    "base policy restored after dynamic rule expiry"
                );
                return Ok(total_tracked);
            }
            remove_tracked_handle(&mut state, container, *handle);
        }

        Ok(expired.len())
    }

    /// Remove all dynamic rules while preserving base drop rules (FR-009, S009-IF-002).
    pub async fn flush_all(&self) -> Result<FlushDynamicResult> {
        let mut state = self.state.lock().await;
        let handles: Vec<u64> = state
            .rules
            .values()
            .flatten()
            .map(|rule| rule.nft_handle)
            .collect();
        let total = handles.len();
        for handle in handles {
            if let Err(error) = self.nft.delete(handle).await {
                warn!(
                    handle,
                    %error,
                    "flush: failed to delete nft rule; restoring fail-closed base policy"
                );
                self.nft.reset_to_base_policy().await.with_context(|| {
                        format!(
                            "failed to delete dynamic rule {handle} and emergency base-policy reset also failed"
                        )
                    })?;
                state.rules.clear();
                info!(
                    removed = total,
                    "base policy restored; dynamic rules flushed"
                );
                return Ok(FlushDynamicResult { removed: total });
            }
        }
        state.rules.clear();
        info!(removed = total, "dynamic rules flushed");
        Ok(FlushDynamicResult { removed: total })
    }

    pub async fn shutdown(&self) -> Result<FlushDynamicResult> {
        self.expiration_task
            .shutdown(Duration::from_secs(10), "dynamic rule expiry watcher")
            .await;
        self.event_task
            .shutdown(Duration::from_secs(10), "dynamic rule watcher")
            .await;
        self.flush_all().await
    }
}

fn expiration_deadline(ttl_secs: Option<u64>, now: Instant) -> Result<Option<Instant>> {
    let Some(ttl_secs) = ttl_secs else {
        return Ok(None);
    };
    if ttl_secs == 0 || ttl_secs > MAX_DYNAMIC_RULE_TTL_SECS {
        anyhow::bail!("expires_in_secs must be between 1 and {MAX_DYNAMIC_RULE_TTL_SECS} seconds");
    }
    now.checked_add(Duration::from_secs(ttl_secs))
        .context("dynamic rule expiration deadline overflowed")
        .map(Some)
}

fn renew_expiration(
    current: &mut Option<Instant>,
    requested: Option<Instant>,
    source_policy: SourcePolicy,
) {
    match source_policy {
        SourcePolicy::OperatorMayPrestage => *current = requested,
        SourcePolicy::RequireManaged => {
            if let (Some(_), Some(deadline)) = (*current, requested) {
                *current = Some(deadline);
            }
        }
    }
}

fn remaining_secs(remaining: Duration) -> u64 {
    remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0))
}

fn validate_source_owner(
    actual: Option<&str>,
    requested: &str,
    policy: SourcePolicy,
    source_ip: &str,
) -> Result<bool> {
    match actual {
        Some(actual) if actual == requested => Ok(true),
        Some(actual) => anyhow::bail!(
            "src_ip {source_ip} does not belong to container '{requested}' (belongs to '{actual}')"
        ),
        None if matches!(policy, SourcePolicy::RequireManaged) => {
            anyhow::bail!("src_ip {source_ip} is not assigned to managed container '{requested}'")
        }
        None => Ok(false),
    }
}

fn remove_tracked_handle(state: &mut DynState, container: &str, handle: u64) {
    let remove_container = state.rules.get_mut(container).is_some_and(|rules| {
        rules.retain(|rule| rule.nft_handle != handle);
        rules.is_empty()
    });
    if remove_container {
        state.rules.remove(container);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;

    struct MockNftController {
        fail_delete: bool,
        fail_reset: bool,
        reset_count: AtomicUsize,
    }

    #[async_trait]
    impl NftController for MockNftController {
        async fn insert(
            &self,
            _src_ip: IpAddr,
            _dst_ip: &str,
            _protocol: Option<&str>,
            _port: Option<u16>,
        ) -> Result<u64> {
            Ok(1)
        }

        async fn delete(&self, _handle: u64) -> Result<()> {
            if self.fail_delete {
                anyhow::bail!("injected delete failure");
            }
            Ok(())
        }

        async fn reset_to_base_policy(&self) -> Result<()> {
            self.reset_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_reset {
                anyhow::bail!("injected reset failure");
            }
            Ok(())
        }
    }

    struct FailSecondDeleteNft {
        delete_count: AtomicUsize,
        reset_count: AtomicUsize,
    }

    #[async_trait]
    impl NftController for FailSecondDeleteNft {
        async fn insert(
            &self,
            _src_ip: IpAddr,
            _dst_ip: &str,
            _protocol: Option<&str>,
            _port: Option<u16>,
        ) -> Result<u64> {
            Ok(1)
        }

        async fn delete(&self, _handle: u64) -> Result<()> {
            if self.delete_count.fetch_add(1, Ordering::SeqCst) == 1 {
                anyhow::bail!("injected second-delete failure");
            }
            Ok(())
        }

        async fn reset_to_base_policy(&self) -> Result<()> {
            self.reset_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn manager_with_mock(nft: Arc<dyn NftController>) -> Arc<DynamicRuleManager> {
        DynamicRuleManager::with_nft_controller(Arc::new(DockerManager::new_unavailable()), nft)
    }

    async fn seed_rule(manager: &DynamicRuleManager, container: &str, handle: u64) {
        seed_rule_with_expiration(manager, container, handle, None).await;
    }

    async fn seed_rule_with_expiration(
        manager: &DynamicRuleManager,
        container: &str,
        handle: u64,
        expires_at: Option<Instant>,
    ) {
        manager
            .state
            .lock()
            .await
            .rules
            .entry(container.to_string())
            .or_default()
            .push(DynamicRuleRecord {
                container: container.to_string(),
                src_ip: "10.200.0.2".to_string(),
                destination: "1.1.1.1".to_string(),
                protocol: Some("tcp".to_string()),
                port: Some(443),
                nft_handle: handle,
                inserted_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at,
            });
    }

    #[test]
    fn expiration_deadlines_are_bounded() {
        let now = Instant::now();

        assert_eq!(expiration_deadline(None, now).unwrap(), None);
        assert!(expiration_deadline(Some(0), now).is_err());
        assert!(expiration_deadline(Some(MAX_DYNAMIC_RULE_TTL_SECS), now).is_ok());
        assert!(expiration_deadline(Some(MAX_DYNAMIC_RULE_TTL_SECS + 1), now).is_err());
    }

    #[test]
    fn duplicate_expiration_respects_rule_source() {
        let now = Instant::now();
        let first = now + Duration::from_secs(10);
        let renewed = now + Duration::from_secs(20);

        let mut expiration = Some(first);
        renew_expiration(&mut expiration, Some(renewed), SourcePolicy::RequireManaged);
        assert_eq!(expiration, Some(renewed));

        renew_expiration(&mut expiration, None, SourcePolicy::RequireManaged);
        assert_eq!(expiration, Some(renewed));

        expiration = None;
        renew_expiration(&mut expiration, Some(first), SourcePolicy::RequireManaged);
        assert_eq!(expiration, None);

        renew_expiration(
            &mut expiration,
            Some(first),
            SourcePolicy::OperatorMayPrestage,
        );
        assert_eq!(expiration, Some(first));
        renew_expiration(&mut expiration, None, SourcePolicy::OperatorMayPrestage);
        assert_eq!(expiration, None);
    }

    #[tokio::test]
    async fn pruning_removes_only_expired_rules() {
        let nft = Arc::new(MockNftController {
            fail_delete: false,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft);
        seed_rule_with_expiration(
            &manager,
            "agent-expired",
            10,
            Some(Instant::now() - Duration::from_secs(1)),
        )
        .await;
        seed_rule_with_expiration(
            &manager,
            "agent-active",
            20,
            Some(Instant::now() + Duration::from_secs(60)),
        )
        .await;
        seed_rule(&manager, "agent-persistent", 30).await;

        assert_eq!(manager.prune_expired().await.unwrap(), 1);
        let active = manager.list_rules().await;
        assert_eq!(active.len(), 2);
        assert!(active.iter().any(|rule| rule.nft_handle == 20));
        assert!(active.iter().any(|rule| rule.nft_handle == 30));
    }

    #[tokio::test]
    async fn expiration_delete_failure_restores_base_policy() {
        let nft = Arc::new(MockNftController {
            fail_delete: true,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft.clone());
        seed_rule_with_expiration(
            &manager,
            "agent-expired",
            10,
            Some(Instant::now() - Duration::from_secs(1)),
        )
        .await;
        seed_rule(&manager, "agent-persistent", 20).await;

        assert_eq!(manager.prune_expired().await.unwrap(), 2);
        assert!(manager.list_rules().await.is_empty());
        assert_eq!(nft.reset_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expiration_reset_reports_prior_deletions_and_remaining_rules() {
        let nft = Arc::new(FailSecondDeleteNft {
            delete_count: AtomicUsize::new(0),
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft.clone());
        for (container, handle) in [("agent-a", 10), ("agent-b", 20)] {
            seed_rule_with_expiration(
                &manager,
                container,
                handle,
                Some(Instant::now() - Duration::from_secs(1)),
            )
            .await;
        }
        seed_rule(&manager, "agent-persistent", 30).await;

        assert_eq!(manager.prune_expired().await.unwrap(), 3);
        assert!(manager.list_rules().await.is_empty());
        assert_eq!(nft.delete_count.load(Ordering::SeqCst), 2);
        assert_eq!(nft.reset_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expiration_watcher_removes_rules_after_deadline() {
        let nft = Arc::new(MockNftController {
            fail_delete: false,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft);
        tokio::task::yield_now().await;
        seed_rule_with_expiration(
            &manager,
            "agent-expiring",
            10,
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .await;

        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;

        assert!(manager.list_rules().await.is_empty());
    }

    #[tokio::test]
    async fn deletion_failure_resets_all_rules_to_fail_closed_policy() {
        let nft = Arc::new(MockNftController {
            fail_delete: true,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft.clone());
        seed_rule(&manager, "agent-a", 10).await;
        seed_rule(&manager, "agent-b", 20).await;

        let removed = manager
            .remove_container_rules("agent-a")
            .await
            .expect("emergency policy reset should recover deletion failure");

        assert_eq!(removed, 1);
        assert!(manager.list_rules().await.is_empty());
        assert_eq!(nft.reset_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_emergency_reset_returns_error_and_retains_tracking_state() {
        let nft = Arc::new(MockNftController {
            fail_delete: true,
            fail_reset: true,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft.clone());
        seed_rule(&manager, "agent-a", 10).await;

        let error = manager
            .remove_container_rules("agent-a")
            .await
            .expect_err("failed emergency reset must be reported");

        assert!(error.to_string().contains("emergency base-policy reset"));
        assert_eq!(manager.list_rules().await.len(), 1);
        assert_eq!(nft.reset_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn flush_uses_emergency_reset_after_deletion_failure() {
        let nft = Arc::new(MockNftController {
            fail_delete: true,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft.clone());
        seed_rule(&manager, "agent-a", 10).await;
        seed_rule(&manager, "agent-b", 20).await;

        let result = manager
            .flush_all()
            .await
            .expect("emergency reset should flush all rules");

        assert_eq!(result.removed, 2);
        assert!(manager.list_rules().await.is_empty());
        assert_eq!(nft.reset_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn event_gap_discards_all_derived_rules() {
        let nft = Arc::new(MockNftController {
            fail_delete: false,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft);
        seed_rule(&manager, "agent-a", 10).await;
        seed_rule(&manager, "agent-b", 20).await;

        events::reset(&manager, "test event gap").await;

        assert!(manager.list_rules().await.is_empty());
    }

    #[tokio::test]
    async fn event_watcher_does_not_retain_manager() {
        let nft = Arc::new(MockNftController {
            fail_delete: false,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft);
        let weak = Arc::downgrade(&manager);

        assert_eq!(Arc::strong_count(&manager), 1);
        drop(manager);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn shutdown_stops_watcher_and_flushes_rules() {
        let nft = Arc::new(MockNftController {
            fail_delete: false,
            fail_reset: false,
            reset_count: AtomicUsize::new(0),
        });
        let manager = manager_with_mock(nft);
        seed_rule(&manager, "agent-a", 10).await;

        let result = manager.shutdown().await.unwrap();

        assert_eq!(result.removed, 1);
        assert!(manager.list_rules().await.is_empty());
    }

    #[test]
    fn managed_source_policy_rejects_unassigned_or_mismatched_owners() {
        assert!(validate_source_owner(
            Some("agent-a"),
            "agent-a",
            SourcePolicy::RequireManaged,
            "10.200.0.2"
        )
        .is_ok());
        assert!(
            validate_source_owner(None, "agent-a", SourcePolicy::RequireManaged, "10.200.0.2")
                .is_err()
        );
        assert!(validate_source_owner(
            Some("agent-b"),
            "agent-a",
            SourcePolicy::OperatorMayPrestage,
            "10.200.0.2"
        )
        .is_err());
        assert!(!validate_source_owner(
            None,
            "agent-a",
            SourcePolicy::OperatorMayPrestage,
            "10.200.0.2"
        )
        .unwrap());
    }
}
