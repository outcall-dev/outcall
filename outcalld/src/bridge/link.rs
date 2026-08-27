use std::net::IpAddr;
use std::time::Duration;

use anyhow::Context;
use futures::TryStreamExt;
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::{LinkBridge, LinkUnspec};
use tracing::info;

use super::{BridgeError, BridgeManager};

const NETLINK_TIMEOUT: Duration = Duration::from_secs(10);

impl BridgeManager {
    pub(super) async fn ensure_link(&mut self) -> Result<(), BridgeError> {
        if let Some(index) = self.find_bridge_index().await? {
            info!(bridge = %self.name, index, "attaching to existing bridge");
            self.index = Some(index);
        } else {
            info!(bridge = %self.name, "creating bridge");
            tokio::time::timeout(
                NETLINK_TIMEOUT,
                self.handle
                    .link()
                    .add(LinkBridge::new(&self.name).build())
                    .execute(),
            )
            .await
            .context("create bridge timed out")?
            .context("create bridge")?;
            self.index = Some(
                self.find_bridge_index()
                    .await?
                    .context("bridge not found after creation")?,
            );
        }

        let index = self.index.context("bridge index missing after creation")?;
        tokio::time::timeout(
            NETLINK_TIMEOUT,
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(index).up().build())
                .execute(),
        )
        .await
        .context("bring bridge up timed out")?
        .context("bring bridge up")?;
        info!(bridge = %self.name, index, "bridge is up");
        Ok(())
    }

    pub(super) async fn ensure_gateway_address(&self) -> Result<(), BridgeError> {
        let index = self
            .index
            .context("bridge index missing before gateway assignment")?;
        tokio::time::timeout(
            NETLINK_TIMEOUT,
            self.handle
                .address()
                .add(index, IpAddr::V4(self.gateway_ip), self.gateway_prefix_len)
                .replace()
                .execute(),
        )
        .await
        .context("assign bridge gateway address timed out")?
        .context("assign bridge gateway address")?;
        info!(
            bridge = %self.name,
            gateway = %self.gateway_ip,
            prefix_len = self.gateway_prefix_len,
            "bridge gateway address configured"
        );
        Ok(())
    }

    pub(super) async fn remove_link(&mut self) -> Result<(), BridgeError> {
        let Some(index) = self.find_bridge_index().await? else {
            self.index = None;
            return Ok(());
        };
        tokio::time::timeout(
            NETLINK_TIMEOUT,
            self.handle
                .link()
                .set(LinkUnspec::new_with_index(index).down().build())
                .execute(),
        )
        .await
        .context("bring bridge down timed out")?
        .context("bring bridge down")?;
        tokio::time::timeout(NETLINK_TIMEOUT, self.handle.link().del(index).execute())
            .await
            .context("delete bridge link timed out")?
            .context("delete bridge link")?;
        self.index = None;
        Ok(())
    }

    pub(super) async fn find_bridge_index(&self) -> Result<Option<u32>, BridgeError> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(self.name.clone())
            .execute();
        let message = match tokio::time::timeout(NETLINK_TIMEOUT, links.try_next()).await {
            Ok(Ok(message)) => message,
            Ok(Err(error)) if error.to_string().contains("No such device") => return Ok(None),
            Ok(Err(error)) => {
                return Err(BridgeError::Operation(
                    anyhow::Error::from(error).context("query link by name"),
                ));
            }
            Err(_) => {
                return Err(BridgeError::Operation(anyhow::anyhow!(
                    "query link by name timed out after {NETLINK_TIMEOUT:?}"
                )));
            }
        };
        let Some(message) = message else {
            return Ok(None);
        };
        if !is_bridge(&message) {
            return Err(BridgeError::Operation(anyhow::anyhow!(
                "interface \"{}\" exists but is not a Linux bridge",
                self.name
            )));
        }
        Ok(Some(message.header.index))
    }
}

fn is_bridge(message: &LinkMessage) -> bool {
    message.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::LinkInfo(infos)
                if infos
                    .iter()
                    .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Bridge)))
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_bridge_link_kind() {
        let mut bridge = LinkMessage::default();
        bridge
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Bridge,
            )]));
        assert!(is_bridge(&bridge));

        let mut dummy = LinkMessage::default();
        dummy
            .attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Dummy,
            )]));
        assert!(!is_bridge(&dummy));
        assert!(!is_bridge(&LinkMessage::default()));
    }
}
