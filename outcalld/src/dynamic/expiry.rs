use std::sync::Weak;
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use super::DynamicRuleManager;

const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

pub(super) async fn run(manager: Weak<DynamicRuleManager>, cancellation: CancellationToken) {
    let mut interval = tokio::time::interval_at(Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = interval.tick() => {}
        }
        let Some(manager) = manager.upgrade() else {
            return;
        };
        match manager.prune_expired().await {
            Ok(0) => {}
            Ok(removed) => info!(removed, "expired dynamic rules removed"),
            Err(error) => error!(%error, "failed to remove expired dynamic rules"),
        }
    }
}
