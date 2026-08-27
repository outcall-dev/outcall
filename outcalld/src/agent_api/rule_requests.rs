use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use outcall_api::RuleRequestStatus;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::info;

use crate::rules::RuleEngine;

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUESTS: usize = 10_000;
const MAX_RULE_FILE_BYTES: usize = 65_536;
const MAX_CONTAINER_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRequestEntry {
    pub container_id: String,
    /// Held verbatim for the host-side approval workflow (S004-FR-011).
    pub rule_file: String,
    pub status: RuleRequestStatus,
    pub reason: Option<String>,
}

/// Durable rule-request queue shared by the agent and operator APIs.
#[derive(Clone)]
pub struct RuleRequestManager {
    requests: Arc<Mutex<HashMap<String, RuleRequestEntry>>>,
    transitions: Arc<Mutex<()>>,
    state_path: PathBuf,
}

pub struct RuleRequestTransitionGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl RuleRequestManager {
    pub fn new(state_path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let state_path = state_path.into();
        let requests = load_rule_requests(&state_path)?;
        Ok(Self {
            requests: Arc::new(Mutex::new(requests)),
            transitions: Arc::new(Mutex::new(())),
            state_path,
        })
    }

    pub async fn lock_transition(&self) -> RuleRequestTransitionGuard {
        RuleRequestTransitionGuard {
            _guard: Arc::clone(&self.transitions).lock_owned().await,
        }
    }

    pub async fn list_pending(&self) -> Vec<(String, RuleRequestEntry)> {
        let guard = self.requests.lock().await;
        let mut entries = guard
            .iter()
            .filter(|(_, entry)| entry.status == RuleRequestStatus::Pending)
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    pub async fn approve(&self, id: &str) -> anyhow::Result<Option<RuleRequestEntry>> {
        let mut guard = self.requests.lock().await;
        let Some(current) = guard.get(id) else {
            return Ok(None);
        };
        if current.status != RuleRequestStatus::Pending {
            anyhow::bail!("rule request {id} is not pending");
        }
        let mut next = guard.clone();
        let entry = next
            .get_mut(id)
            .context("rule request disappeared while applying approval")?;
        entry.status = RuleRequestStatus::Approved;
        entry.rule_file.clear();
        let snapshot = entry.clone();
        self.persist(next.clone()).await?;
        *guard = next;
        Ok(Some(snapshot))
    }

    pub async fn reject(
        &self,
        id: &str,
        reason: Option<String>,
    ) -> anyhow::Result<Option<RuleRequestEntry>> {
        validate_reason(reason.as_deref())?;
        let mut guard = self.requests.lock().await;
        let Some(current) = guard.get(id) else {
            return Ok(None);
        };
        if current.status != RuleRequestStatus::Pending {
            anyhow::bail!("rule request {id} is not pending");
        }
        let mut next = guard.clone();
        let entry = next
            .get_mut(id)
            .context("rule request disappeared while applying rejection")?;
        entry.status = RuleRequestStatus::Rejected;
        entry.reason = reason;
        entry.rule_file.clear();
        let snapshot = entry.clone();
        self.persist(next.clone()).await?;
        *guard = next;
        Ok(Some(snapshot))
    }

    pub async fn get(&self, id: &str) -> Option<RuleRequestEntry> {
        let guard = self.requests.lock().await;
        guard.get(id).cloned()
    }

    pub async fn insert(&self, id: String, entry: RuleRequestEntry) -> anyhow::Result<()> {
        if !valid_request_id(&id) {
            anyhow::bail!("invalid generated rule request ID {id:?}");
        }
        validate_entry(&entry, true)?;

        let mut guard = self.requests.lock().await;
        if guard.contains_key(&id) {
            anyhow::bail!("duplicate generated rule request ID {id}");
        }
        let mut next = guard.clone();
        let pruned = make_room_for_insert(&mut next);
        if next.len() >= MAX_REQUESTS {
            anyhow::bail!("rule request state reached its {MAX_REQUESTS}-entry limit");
        }
        next.insert(id, entry);
        self.persist(next.clone()).await?;
        *guard = next;
        if pruned > 0 {
            info!(pruned, "pruned completed rule request history at capacity");
        }
        Ok(())
    }

    async fn persist(&self, requests: HashMap<String, RuleRequestEntry>) -> anyhow::Result<()> {
        let path = self.state_path.clone();
        tokio::task::spawn_blocking(move || persist_rule_requests(&path, &requests))
            .await
            .context("rule request persistence task failed")?
    }
}

fn load_rule_requests(path: &Path) -> anyhow::Result<HashMap<String, RuleRequestEntry>> {
    let Some(contents) = crate::state_file::read_optional(path, MAX_STATE_BYTES)? else {
        return Ok(HashMap::new());
    };
    let map = serde_json::from_slice::<HashMap<String, RuleRequestEntry>>(&contents)
        .with_context(|| format!("failed to parse rule requests file {}", path.display()))?;
    if map.len() > MAX_REQUESTS {
        anyhow::bail!(
            "rule requests file {} exceeds the {MAX_REQUESTS}-entry limit",
            path.display()
        );
    }
    for (id, entry) in &map {
        if !valid_request_id(id) {
            anyhow::bail!(
                "rule requests file {} contains invalid request ID {id:?}",
                path.display()
            );
        }
        validate_entry(entry, entry.status == RuleRequestStatus::Pending).with_context(|| {
            format!(
                "rule requests file {} contains invalid request {id}",
                path.display()
            )
        })?;
    }
    info!(path = %path.display(), count = map.len(), "loaded rule requests from disk");
    Ok(map)
}

fn validate_entry(entry: &RuleRequestEntry, validate_rule: bool) -> anyhow::Result<()> {
    if entry.container_id.is_empty()
        || entry.container_id.len() > MAX_CONTAINER_ID_BYTES
        || !entry
            .container_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("container ID is invalid");
    }
    if (entry.status == RuleRequestStatus::Pending || !entry.rule_file.is_empty())
        && (entry.rule_file.is_empty() || entry.rule_file.len() > MAX_RULE_FILE_BYTES)
    {
        anyhow::bail!("rule file must contain 1 to {MAX_RULE_FILE_BYTES} bytes");
    }
    validate_reason(entry.reason.as_deref())?;
    if validate_rule {
        RuleEngine::validate_rule_file(&entry.rule_file).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn make_room_for_insert(requests: &mut HashMap<String, RuleRequestEntry>) -> usize {
    if requests.len() < MAX_REQUESTS {
        return 0;
    }
    let before = requests.len();
    requests.retain(|_, entry| entry.status == RuleRequestStatus::Pending);
    before - requests.len()
}

fn validate_reason(reason: Option<&str>) -> anyhow::Result<()> {
    let Some(reason) = reason else {
        return Ok(());
    };
    if reason.trim().is_empty() {
        anyhow::bail!("rejection reason must not be empty");
    }
    if reason.len() > MAX_REASON_BYTES {
        anyhow::bail!("rejection reason exceeds {MAX_REASON_BYTES} bytes");
    }
    if reason.chars().any(char::is_control) {
        anyhow::bail!("rejection reason must not contain control characters");
    }
    Ok(())
}

fn persist_rule_requests(
    path: &Path,
    map: &HashMap<String, RuleRequestEntry>,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(map).context("failed to serialize rule requests")?;
    if json.len() > MAX_STATE_BYTES {
        anyhow::bail!("rule request state exceeds {MAX_STATE_BYTES} bytes");
    }
    crate::state_file::write_atomic(path, &json, 0o600)
        .with_context(|| format!("failed to persist rule requests to {}", path.display()))
}

pub(super) fn generate_request_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 6];
    getrandom::getrandom(&mut bytes)?;
    Ok(format!("rr-{}", hex_encode(&bytes)))
}

pub(crate) fn valid_request_id(id: &str) -> bool {
    id.len() == "rr-".len() + 12
        && id.starts_with("rr-")
        && id["rr-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_entry(status: RuleRequestStatus) -> RuleRequestEntry {
        RuleRequestEntry {
            container_id: "0123456789abcdef".to_string(),
            rule_file: r#"version: "1"
rules:
  - id: requested
    condition: 'true'
    action: allow
"#
            .to_string(),
            status,
            reason: None,
        }
    }

    #[test]
    fn generated_request_ids_have_canonical_format() {
        let id = generate_request_id().unwrap();
        assert!(valid_request_id(&id));
        assert!(!valid_request_id("rr-../../escape"));
        assert!(!valid_request_id("rr-ABCDEF123456"));
    }

    #[tokio::test]
    async fn persists_before_mutating_memory() {
        let root = tempfile::tempdir().unwrap();
        let state_path = root.path().join("requests.json");
        let manager = RuleRequestManager::new(&state_path).unwrap();
        let id = "rr-0123456789ab".to_string();

        manager
            .insert(id.clone(), valid_entry(RuleRequestStatus::Pending))
            .await
            .unwrap();
        drop(manager);
        let reloaded = RuleRequestManager::new(&state_path).unwrap();

        assert_eq!(
            reloaded.get(&id).await.unwrap().status,
            RuleRequestStatus::Pending
        );
    }

    #[tokio::test]
    async fn completed_requests_discard_rule_bodies_but_keep_status() {
        let root = tempfile::tempdir().unwrap();
        let manager = RuleRequestManager::new(root.path().join("requests.json")).unwrap();
        let id = "rr-0123456789ab".to_string();
        manager
            .insert(id.clone(), valid_entry(RuleRequestStatus::Pending))
            .await
            .unwrap();

        manager.approve(&id).await.unwrap();

        let completed = manager.get(&id).await.unwrap();
        assert_eq!(completed.status, RuleRequestStatus::Approved);
        assert!(completed.rule_file.is_empty());
    }

    #[test]
    fn capacity_pressure_prunes_only_completed_history() {
        let mut requests = HashMap::new();
        for index in 0..MAX_REQUESTS {
            let status = if index == 0 {
                RuleRequestStatus::Approved
            } else {
                RuleRequestStatus::Pending
            };
            requests.insert(format!("rr-{index:012x}"), valid_entry(status));
        }

        assert_eq!(make_room_for_insert(&mut requests), 1);
        assert_eq!(requests.len(), MAX_REQUESTS - 1);
        assert!(requests
            .values()
            .all(|entry| entry.status == RuleRequestStatus::Pending));

        requests.insert(
            "rr-ffffffffffff".to_string(),
            valid_entry(RuleRequestStatus::Pending),
        );
        assert_eq!(make_room_for_insert(&mut requests), 0);
        assert_eq!(requests.len(), MAX_REQUESTS);
    }

    #[tokio::test]
    async fn transition_lock_serializes_operator_decisions() {
        let root = tempfile::tempdir().unwrap();
        let manager = RuleRequestManager::new(root.path().join("requests.json")).unwrap();
        let first = manager.lock_transition().await;
        let waiting_manager = manager.clone();
        let mut waiting = tokio::spawn(async move { waiting_manager.lock_transition().await });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        drop(first);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
                .await
                .is_ok()
        );
    }

    #[test]
    fn rejects_malformed_persisted_state() {
        let root = tempfile::tempdir().unwrap();
        let state_path = root.path().join("requests.json");
        std::fs::write(&state_path, "not-json").unwrap();

        let error = RuleRequestManager::new(&state_path)
            .err()
            .expect("malformed state must fail")
            .to_string();
        assert!(error.contains("failed to parse"));
    }

    #[test]
    fn validates_pending_but_not_historical_rule_syntax() {
        let root = tempfile::tempdir().unwrap();
        let state_path = root.path().join("requests.json");
        let mut entry = valid_entry(RuleRequestStatus::Rejected);
        entry.rule_file = "historical unsupported rule".to_string();
        let map = HashMap::from([("rr-0123456789ab".to_string(), entry.clone())]);
        persist_rule_requests(&state_path, &map).unwrap();
        assert!(RuleRequestManager::new(&state_path).is_ok());

        entry.status = RuleRequestStatus::Pending;
        let map = HashMap::from([("rr-0123456789ab".to_string(), entry)]);
        persist_rule_requests(&state_path, &map).unwrap();
        assert!(RuleRequestManager::new(&state_path).is_err());
    }
}
