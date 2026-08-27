use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bollard::models::EventActor;
use bollard::system::EventsOptions;
use bollard::Docker;
use futures::stream::StreamExt;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::identity::IdentityCache;
use super::metadata::{container_name, required_text};

#[derive(Debug, Clone)]
pub enum ContainerEvent {
    Lifecycle {
        kind: ContainerEventKind,
        container_name: String,
        container_id: String,
    },
    /// The authoritative event stream was interrupted or could have lost data.
    /// Consumers must discard state derived from lifecycle events.
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerEventKind {
    Die,
    Oom,
    Kill,
    Destroy,
    Pause,
    Unpause,
}

/// Keep the managed-container identity cache synchronized and rebroadcast
/// lifecycle events to session and dynamic-rule cleanup consumers.
pub(super) async fn watch(
    docker: Docker,
    tx: broadcast::Sender<ContainerEvent>,
    identities: Arc<IdentityCache>,
    cancellation: CancellationToken,
) {
    loop {
        if cancellation.is_cancelled() {
            return;
        }
        identities.invalidate().await;
        if let Err(error) = identities.refresh(&docker).await {
            warn!(%error, "Docker identity refresh failed; retrying in 5s");
            send_reset(&tx);
            if !retry_delay(&cancellation).await {
                return;
            }
            continue;
        }

        let mut filters = HashMap::new();
        filters.insert("type", vec!["container"]);
        filters.insert("label", vec!["managed-by=outcalld"]);
        let mut stream = docker.events(Some(EventsOptions {
            filters,
            ..Default::default()
        }));

        loop {
            let event = tokio::select! {
                _ = cancellation.cancelled() => return,
                event = stream.next() => event,
            };
            let Some(event) = event else {
                break;
            };
            let message = match event {
                Ok(message) => message,
                Err(error) => {
                    warn!(%error, "Docker event stream failed; reconnecting in 5s");
                    break;
                }
            };
            let action = message.action.as_deref().unwrap_or("");
            let actor = message.actor.as_ref();

            if matches!(action, "start" | "restart") {
                let container_id = match required_text(
                    actor.and_then(|actor| actor.id.as_deref()),
                    "Docker event container ID",
                ) {
                    Ok(id) => id.to_string(),
                    Err(error) => {
                        warn!(%error, %action, "malformed Docker event; resetting event consumers");
                        break;
                    }
                };
                if let Err(error) = identities.record_container(&docker, &container_id).await {
                    warn!(%error, %container_id, "Docker identity update failed; reconnecting");
                    break;
                }
                continue;
            }

            let kind = match action {
                "die" => ContainerEventKind::Die,
                "oom" => ContainerEventKind::Oom,
                "kill" => ContainerEventKind::Kill,
                "destroy" => ContainerEventKind::Destroy,
                "pause" => ContainerEventKind::Pause,
                "unpause" => ContainerEventKind::Unpause,
                _ => continue,
            };

            let (container_id, container_name) = match lifecycle_identity(actor) {
                Ok(identity) => identity,
                Err(error) => {
                    warn!(%error, %action, "malformed Docker event; resetting event consumers");
                    break;
                }
            };

            if matches!(
                kind,
                ContainerEventKind::Die
                    | ContainerEventKind::Oom
                    | ContainerEventKind::Kill
                    | ContainerEventKind::Destroy
            ) {
                identities
                    .remove_container(&container_id, &container_name)
                    .await;
            }

            info!(name = %container_name, id = %container_id, %action, "container event");
            drop(tx.send(ContainerEvent::Lifecycle {
                kind,
                container_name,
                container_id,
            }));
        }

        identities.invalidate().await;
        send_reset(&tx);
        if !retry_delay(&cancellation).await {
            return;
        }
    }
}

async fn retry_delay(cancellation: &CancellationToken) -> bool {
    tokio::select! {
        _ = cancellation.cancelled() => false,
        _ = tokio::time::sleep(Duration::from_secs(5)) => true,
    }
}

fn send_reset(tx: &broadcast::Sender<ContainerEvent>) {
    drop(tx.send(ContainerEvent::Reset));
}

fn lifecycle_identity(actor: Option<&EventActor>) -> anyhow::Result<(String, String)> {
    let container_id = required_text(
        actor.and_then(|actor| actor.id.as_deref()),
        "Docker event container ID",
    )?
    .to_string();
    let container_name = container_name(
        actor
            .and_then(|actor| actor.attributes.as_ref())
            .and_then(|attributes| attributes.get("name"))
            .map(String::as_str),
    )?;
    Ok((container_id, container_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_complete_lifecycle_identity() {
        let actor = EventActor {
            id: Some("container-id".to_string()),
            attributes: Some(HashMap::from([(
                "name".to_string(),
                "project-1".to_string(),
            )])),
        };
        assert_eq!(
            lifecycle_identity(Some(&actor)).unwrap(),
            ("container-id".to_string(), "project-1".to_string())
        );

        assert!(lifecycle_identity(None).is_err());
        assert!(lifecycle_identity(Some(&EventActor::default())).is_err());
    }

    #[tokio::test]
    async fn reset_signal_is_broadcast() {
        let (tx, mut rx) = broadcast::channel(1);
        send_reset(&tx);
        assert!(matches!(rx.recv().await.unwrap(), ContainerEvent::Reset));
    }
}
