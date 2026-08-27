use anyhow::{Context, Result};

use super::AppState;
use crate::dns::DnsServer;
use crate::dynamic::DynamicRuleManager;
use crate::rules::engine::RuleSnapshot;
use crate::rules::RuleEngine;

pub(super) async fn reload(state: &AppState) -> Result<(usize, usize, Vec<String>)> {
    let _update = state.policy_update.lock().await;
    reload_locked(state).await
}

pub(super) async fn reload_locked(state: &AppState) -> Result<(usize, usize, Vec<String>)> {
    reload_components(
        &state.rules,
        &state.dns,
        &state.dynamic,
        &state.policy_barrier,
    )
    .await
}

pub(super) async fn restore_locked(state: &AppState, snapshot: RuleSnapshot) -> Result<()> {
    restore_components(
        &state.rules,
        &state.dns,
        &state.dynamic,
        &state.policy_barrier,
        snapshot,
    )
    .await
}

async fn reload_components(
    rules: &RuleEngine,
    dns: &DnsServer,
    dynamic: &DynamicRuleManager,
    policy_barrier: &tokio::sync::RwLock<()>,
) -> Result<(usize, usize, Vec<String>)> {
    let prepared = rules.prepare_reload().await?;
    let _policy = policy_barrier.write().await;

    let dynamic_result = dynamic
        .flush_all()
        .await
        .context("failed to revoke dynamic grants before rule reload")?;
    let cache_entries = dns.flush_cache().await;
    let result = rules.commit_reload(prepared).await;
    tracing::info!(
        dynamic_rules = dynamic_result.removed,
        cache_entries,
        "policy reload revoked derived state"
    );
    Ok(result)
}

async fn restore_components(
    rules: &RuleEngine,
    dns: &DnsServer,
    dynamic: &DynamicRuleManager,
    policy_barrier: &tokio::sync::RwLock<()>,
    snapshot: RuleSnapshot,
) -> Result<()> {
    let _policy = policy_barrier.write().await;

    // Restore L7/DNS policy first. If kernel cleanup then fails, new requests
    // still cannot derive grants from the policy whose persistence failed.
    rules.restore_snapshot(snapshot).await;
    let dynamic_result = dynamic
        .flush_all()
        .await
        .context("failed to revoke dynamic grants while restoring previous policy")?;
    let cache_entries = dns.flush_cache().await;
    tracing::info!(
        dynamic_rules = dynamic_result.removed,
        cache_entries,
        "previous policy restored and derived state revoked"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use outcall_api::{Decision, EvalContext};

    use super::*;
    use crate::docker::DockerManager;

    #[tokio::test]
    async fn reload_waits_for_inflight_policy_and_clears_derived_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rules.yaml");
        std::fs::write(
            &path,
            "version: \"1\"\nrules:\n  - id: current\n    condition: 'true'\n    action: allow\n",
        )
        .unwrap();
        let rules = Arc::new(RuleEngine::load(directory.path().to_str().unwrap()).unwrap());
        let original = rules.rollback_snapshot().await;
        let dns = DnsServer::new_for_tests("127.0.0.1:0".parse().unwrap(), vec![]);
        dns.seed_cache_for_tests().await;
        let dynamic = DynamicRuleManager::new_with_noop_nft_for_tests(Arc::new(
            DockerManager::new_unavailable(),
        ));
        dynamic.seed_rule_for_tests("agent", 7).await;
        let barrier = dns.policy_barrier();
        let lease = barrier.read().await;

        std::fs::write(
            &path,
            "version: \"1\"\nrules:\n  - id: replacement\n    condition: 'true'\n    action: block\n",
        )
        .unwrap();
        let task = tokio::spawn({
            let rules = rules.clone();
            let dns = dns.clone();
            let dynamic = dynamic.clone();
            let barrier = barrier.clone();
            async move { reload_components(&rules, &dns, &dynamic, &barrier).await }
        });

        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(dns.cache_stats().await.entries, 1);
        assert_eq!(dynamic.list_rules().await.len(), 1);

        drop(lease);
        task.await.unwrap().unwrap();

        assert_eq!(dns.cache_stats().await.entries, 0);
        assert!(dynamic.list_rules().await.is_empty());
        assert_eq!(
            rules.evaluate(&EvalContext::default()).await.decision,
            Decision::Block
        );

        restore_components(&rules, &dns, &dynamic, &barrier, original)
            .await
            .unwrap();
        assert_eq!(
            rules.evaluate(&EvalContext::default()).await.decision,
            Decision::Allow
        );
    }
}
