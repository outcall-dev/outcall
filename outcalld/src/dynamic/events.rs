use std::sync::Weak;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::DynamicRuleManager;
use crate::docker::{ContainerEvent, ContainerEventKind};

pub(super) async fn run(
    manager: Weak<DynamicRuleManager>,
    mut events: tokio::sync::broadcast::Receiver<ContainerEvent>,
    cancellation: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            _ = cancellation.cancelled() => return,
            event = events.recv() => event,
        };
        let Some(manager) = manager.upgrade() else {
            return;
        };
        match event {
            Ok(ContainerEvent::Lifecycle {
                kind:
                    ContainerEventKind::Die
                    | ContainerEventKind::Oom
                    | ContainerEventKind::Kill
                    | ContainerEventKind::Destroy,
                container_name,
                ..
            }) => match manager.remove_container_rules(&container_name).await {
                Ok(removed) if removed > 0 => {
                    info!(
                        container = %container_name,
                        removed,
                        "cleaned up dynamic rules on container death"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        container = %container_name,
                        %error,
                        "dynamic-rule cleanup failed closed incompletely; operator action required"
                    );
                }
                _ => {}
            },
            Ok(ContainerEvent::Lifecycle {
                kind: ContainerEventKind::Pause,
                container_name,
                ..
            }) => {
                info!(container = %container_name, "container paused; dynamic rules preserved");
            }
            Ok(ContainerEvent::Lifecycle {
                kind: ContainerEventKind::Unpause,
                container_name,
                ..
            }) => {
                debug!(container = %container_name, "container resumed");
            }
            Ok(ContainerEvent::Reset) => reset(&manager, "Docker event stream reset").await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "dynamic rule event receiver lagged; resetting derived rules"
                );
                reset(&manager, "Docker event receiver lag").await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                reset(&manager, "Docker event channel closed").await;
                info!("Docker event channel closed; stopping dynamic rule watcher");
                return;
            }
        }
    }
}

pub(super) async fn reset(manager: &DynamicRuleManager, reason: &str) {
    match manager.flush_all().await {
        Ok(result) => {
            warn!(removed = result.removed, %reason, "discarded dynamic rules after event gap");
        }
        Err(error) => {
            tracing::error!(
                %error,
                %reason,
                "failed to restore base policy after Docker event gap; operator action required"
            );
        }
    }
}
