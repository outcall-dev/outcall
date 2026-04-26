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
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use outcall_api::{ActiveRule, AllowRuleRequest, AllowRuleResult, FlushDynamicResult};

use crate::docker::{ContainerEvent, ContainerEventKind, DockerManager};

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
}

impl DynamicRuleManager {
    /// Create the manager and spawn the Docker event watcher.
    pub fn new(docker: Arc<DockerManager>) -> Arc<Self> {
        let mgr = Arc::new(Self {
            state: Mutex::new(DynState {
                rules: HashMap::new(),
            }),
            docker: docker.clone(),
        });

        // Background task: watch for container death events → clean up rules.
        let mgr_clone = mgr.clone();
        let rx = docker.subscribe_events();
        tokio::spawn(container_event_loop(mgr_clone, rx));

        mgr
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /// Insert a dynamic nftables allow rule for the given container/destination.
    ///
    /// Returns the nftables handle of the newly inserted rule (FR-007).
    pub async fn insert_rule(&self, req: AllowRuleRequest) -> Result<AllowRuleResult> {
        let dst_ip = resolve_destination(&req.destination).await?;

        {
            let state = self.state.lock().await;
            if let Some(existing) = state.rules.get(&req.container).and_then(|rules| {
                rules.iter().find(|r| {
                    r.src_ip == req.src_ip
                        && r.destination == req.destination
                        && r.protocol == req.protocol
                        && r.port == req.port
                })
            }) {
                return Ok(AllowRuleResult {
                    nft_handle: existing.nft_handle,
                });
            }
        }

        let handle = {
            // Serialize all nftables operations (FR-008).
            let _lock = self.state.lock().await;
            nft_insert(
                &req.src_ip,
                &dst_ip,
                req.protocol.as_deref(),
                req.port,
            )
            .await?
        };

        // Record the rule in memory (outside the nft-critical lock is fine —
        // the Mutex is still held for the state update below).
        let mut state = self.state.lock().await;
        let record = DynamicRuleRecord {
            container: req.container.clone(),
            src_ip: req.src_ip,
            destination: req.destination,
            protocol: req.protocol,
            port: req.port,
            nft_handle: handle,
            inserted_at: now_iso8601(),
        };
        state
            .rules
            .entry(req.container)
            .or_default()
            .push(record);

        Ok(AllowRuleResult { nft_handle: handle })
    }

    pub async fn container_name_for_ip(&self, ip: &str) -> Option<String> {
        self.docker.lookup_container_name_by_ip(ip).await
    }

    /// Remove all dynamic rules for a container (called on container death).
    pub async fn remove_container_rules(&self, container_name: &str) -> usize {
        let mut state = self.state.lock().await;
        let rules = match state.rules.remove(container_name) {
            Some(r) => r,
            None => return 0,
        };

        let count = rules.len();
        for rule in rules {
            if let Err(e) = nft_delete(rule.nft_handle).await {
                warn!(
                    container = %container_name,
                    handle = rule.nft_handle,
                    "failed to delete nft rule: {e}"
                );
            }
        }
        if count > 0 {
            info!(container = %container_name, removed = count, "dynamic rules removed");
        }
        count
    }

    /// List all currently active dynamic rules (FR-006, S009-IF-001).
    pub async fn list_rules(&self) -> Vec<ActiveRule> {
        let state = self.state.lock().await;
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
                })
            })
            .collect()
    }

    /// Remove all dynamic rules while preserving base drop rules (FR-009, S009-IF-002).
    pub async fn flush_all(&self) -> FlushDynamicResult {
        let mut state = self.state.lock().await;
        let mut removed = 0usize;
        for rules in state.rules.values() {
            for rule in rules {
                if let Err(e) = nft_delete(rule.nft_handle).await {
                    warn!(handle = rule.nft_handle, "flush: failed to delete nft rule: {e}");
                } else {
                    removed += 1;
                }
            }
        }
        state.rules.clear();
        info!(removed, "dynamic rules flushed");
        FlushDynamicResult { removed }
    }
}

// ── Container event watcher ────────────────────────────────────────────────────

async fn container_event_loop(
    mgr: Arc<DynamicRuleManager>,
    mut rx: tokio::sync::broadcast::Receiver<ContainerEvent>,
) {
    loop {
        match rx.recv().await {
            Ok(ev) => {
                match ev.kind {
                    ContainerEventKind::Die
                    | ContainerEventKind::Oom
                    | ContainerEventKind::Kill
                    | ContainerEventKind::Destroy => {
                        let removed = mgr.remove_container_rules(&ev.container_name).await;
                        if removed > 0 {
                            info!(
                                container = %ev.container_name,
                                removed,
                                "cleaned up dynamic rules on container death"
                            );
                        }
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    "dynamic rule event receiver lagged by {n} messages — some container deaths may have been missed"
                );
                // Continue — don't exit on lag.
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                info!("Docker event channel closed — stopping dynamic rule watcher");
                return;
            }
        }
    }
}

// ── nftables helpers ──────────────────────────────────────────────────────────

const NFT_TABLE: &str = "inet";
const NFT_CHAIN_TABLE: &str = "outcall";
const NFT_CHAIN: &str = "forward";

/// Insert a rule at position 0 (before base drop rules) and return its handle.
async fn nft_insert(
    src_ip: &str,
    dst_ip: &str,
    protocol: Option<&str>,
    port: Option<u16>,
) -> Result<u64> {
    let is_ipv6 = is_ipv6_addr(dst_ip);
    let ip_prefix = if is_ipv6 { "ip6" } else { "ip" };

    // When emitting ip6 rules with an IPv4 source address, nftables requires
    // IPv4-mapped IPv6 form (::ffff:x.x.x.x). Without this conversion, nft
    // rejects "ip6 saddr 10.0.0.1" with "Could not resolve hostname".
    let src_ip_str = if is_ipv6 && !is_ipv6_addr(src_ip) {
        format!("::ffff:{src_ip}")
    } else {
        src_ip.to_string()
    };

    // Build the match expression.
    let mut parts: Vec<String> = vec![
        format!("{ip_prefix} saddr {src_ip_str}"),
        format!("{ip_prefix} daddr {dst_ip}"),
    ];

    match (protocol, port) {
        (Some(proto), Some(p)) => {
            parts.push(format!("{proto} dport {p}"));
        }
        (Some(proto), None) => {
            // Match all ports for a specific protocol.
            parts.push(format!("meta l4proto {proto}"));
        }
        _ => {} // all protocols, all ports
    }
    parts.push("accept".to_string());

    let rule_expr: Vec<&str> = parts.iter().map(String::as_str).collect();

    // `nft insert rule` inserts at position 0 (head of chain) by default.
    // `--handle --echo` causes nft to print the inserted rule with its handle.
    let output = Command::new("nft")
        .arg("--handle")
        .arg("--echo")
        .arg("insert")
        .arg("rule")
        .arg(NFT_TABLE)
        .arg(NFT_CHAIN_TABLE)
        .arg(NFT_CHAIN)
        .args(&rule_expr)
        .output()
        .await
        .context("failed to run nft")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft insert failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_nft_handle(&stdout)
        .with_context(|| format!("could not parse nft handle from: {stdout}"))
}

/// Delete a rule by its nftables handle.
async fn nft_delete(handle: u64) -> Result<()> {
    let output = Command::new("nft")
        .arg("delete")
        .arg("rule")
        .arg(NFT_TABLE)
        .arg(NFT_CHAIN_TABLE)
        .arg(NFT_CHAIN)
        .arg("handle")
        .arg(handle.to_string())
        .output()
        .await
        .context("failed to run nft")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft delete handle {handle} failed: {stderr}");
    }
    Ok(())
}

/// Parse the nftables rule handle from `nft --handle --echo` output.
///
/// `nft --handle --echo insert ...` echoes the inserted rule followed by
/// `# handle N` on the same line, e.g.:
/// ```text
/// 	ip saddr 10.0.0.1 ip daddr 1.2.3.4 tcp dport 443 accept # handle 42
/// ```
fn parse_nft_handle(output: &str) -> Option<u64> {
    for line in output.lines() {
        if let Some(pos) = line.find("# handle ") {
            let tail = line[pos + 9..].trim();
            // The handle may be followed by other text; take the first token.
            if let Some(handle_str) = tail.split_whitespace().next() {
                if let Ok(h) = handle_str.parse::<u64>() {
                    return Some(h);
                }
            }
        }
    }
    None
}

// ── Destination resolution ─────────────────────────────────────────────────────

/// Resolve a destination to a string usable in nftables rules.
///
/// - IP address → returned as-is
/// - CIDR → returned as-is
/// - Hostname → resolved via DNS; first IPv4 address used; falls back to IPv6
async fn resolve_destination(destination: &str) -> Result<String> {
    // If it looks like an IP or CIDR, use directly.
    if is_ip_or_cidr(destination) {
        return Ok(destination.to_string());
    }

    // Hostname — resolve to IP.
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{destination}:0"))
        .await
        .with_context(|| format!("DNS resolution failed for \"{destination}\""))?
        .collect();

    for addr in &addrs {
        if addr.is_ipv4() {
            return Ok(addr.ip().to_string());
        }
    }

    // No IPv4 found — try IPv6.
    for addr in &addrs {
        if addr.is_ipv6() {
            return Ok(addr.ip().to_string());
        }
    }

    anyhow::bail!(
        "no IP address found for \"{destination}\" — nftables requires an IP address"
    )
}

fn is_ip_or_cidr(s: &str) -> bool {
    // Check for CIDR notation first.
    let s = match s.split_once('/') {
        Some((ip, mask)) => {
            if mask.parse::<u8>().is_err() {
                return false;
            }
            ip
        }
        None => s,
    };
    // Check if it's a valid IPv4 address (4 octets).
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }
    // IPv6 — starts with ':'
    s.contains(':')
}

fn is_ipv6_addr(s: &str) -> bool {
    s.contains(':')
}

// ── Time helpers ──────────────────────────────────────────────────────────────

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_unix_ts(secs)
}

fn format_unix_ts(secs: u64) -> String {
    let days = secs / 86400;
    let tod = secs % 86400;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn days_to_ymd(z: u64) -> (u64, u64, u64) {
    let z = z + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nft_handle_from_echo_output() {
        let output = "\ttable inet outcall {\n\t\tchain forward {\n\t\t\tip saddr 10.0.0.1 ip daddr 1.2.3.4 tcp dport 443 accept # handle 42\n\t\t}\n\t}\n";
        assert_eq!(parse_nft_handle(output), Some(42));
    }

    #[test]
    fn parse_nft_handle_missing() {
        assert_eq!(parse_nft_handle("no handle here\n"), None);
    }

    #[test]
    fn is_ip_or_cidr_variants() {
        assert!(is_ip_or_cidr("10.0.0.1"));
        assert!(is_ip_or_cidr("192.168.0.0/24"));
        assert!(!is_ip_or_cidr("example.com"));
        assert!(!is_ip_or_cidr("github.com"));
        assert!(is_ip_or_cidr("::1"));
        assert!(is_ip_or_cidr("2001:db8::1"));
        assert!(is_ip_or_cidr("fe80::1%eth0"));
    }

    #[test]
    fn is_ipv6_addr_variants() {
        assert!(is_ipv6_addr("::1"));
        assert!(is_ipv6_addr("2001:db8::1"));
        assert!(is_ipv6_addr("fe80::1%eth0"));
        assert!(is_ipv6_addr("2001:470:0:284::1"));
        assert!(!is_ipv6_addr("10.0.0.1"));
        assert!(!is_ipv6_addr("192.168.0.0/24"));
        assert!(!is_ipv6_addr("example.com"));
    }

    #[test]
    fn format_unix_ts_epoch() {
        assert_eq!(format_unix_ts(0), "1970-01-01T00:00:00Z");
    }
}
