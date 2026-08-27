use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use outcall_api::BridgeStatus;
use rtnetlink::Handle;
use thiserror::Error;
use tracing::info;

use crate::background_task::BackgroundTask;

mod config;
mod link;
mod netfilter;
mod nft;

pub use config::{first_gateway_from_subnet_block, HostServiceAccess, HostServiceEndpoint};

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("netlink connection failed: {0}")]
    Connection(#[source] std::io::Error),
    #[error("bridge operation failed: {0:#}")]
    Operation(#[from] anyhow::Error),
    #[error("nftables operation failed: {0}")]
    Nftables(String),
}

/// Owns the managed Linux bridge and its fail-closed nftables policy.
pub struct BridgeManager {
    name: String,
    gateway_ip: Ipv4Addr,
    gateway_prefix_len: u8,
    host_services: HostServiceAccess,
    handle: Handle,
    connection_task: BackgroundTask,
    index: Option<u32>,
}

impl BridgeManager {
    /// Construct a manager without changing kernel state.
    pub async fn new(
        name: Option<&str>,
        gateway_ip: Ipv4Addr,
        gateway_prefix_len: u8,
        host_services: HostServiceAccess,
    ) -> Result<Self, BridgeError> {
        let name = name.unwrap_or(outcall_api::DEFAULT_BRIDGE_NAME);
        config::validate_bridge_name(name)?;
        if !(1..=32).contains(&gateway_prefix_len) {
            return Err(BridgeError::Operation(anyhow::anyhow!(
                "bridge gateway prefix length must be between 1 and 32"
            )));
        }

        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(BridgeError::Connection)?;
        let connection_task = BackgroundTask::new();
        let cancellation = connection_task.cancellation_token();
        connection_task.spawn(async move {
            tokio::select! {
                () = connection => {}
                () = cancellation.cancelled() => {}
            }
        });
        Ok(Self {
            name: name.to_string(),
            gateway_ip,
            gateway_prefix_len,
            host_services,
            handle,
            connection_task,
            index: None,
        })
    }

    /// Create or validate the bridge, configure its gateway, and install policy.
    pub async fn init(&mut self) -> Result<(), BridgeError> {
        self.ensure_link().await?;
        self.ensure_gateway_address().await?;
        netfilter::enable().await;
        nft::apply_base(&self.name, self.host_services).await
    }

    /// Refuse secure workloads unless bridge traffic traverses netfilter.
    pub async fn require_netfilter_enforceable(&self) -> Result<(), BridgeError> {
        netfilter::require_enforceable().await
    }

    /// Remove dynamic grants while preserving bridge connectivity.
    pub async fn reset_policy(&self) -> Result<(), BridgeError> {
        nft::apply_base(&self.name, self.host_services).await
    }

    /// Remove the bridge first, then remove policy that protects that interface.
    pub async fn teardown(&mut self) -> Result<(), BridgeError> {
        info!(bridge = %self.name, "tearing down");
        self.remove_link().await?;
        nft::delete_table().await?;
        info!(bridge = %self.name, "teardown complete");
        Ok(())
    }

    /// Query netlink and nftables afresh on every call.
    pub async fn status(&self) -> Result<BridgeStatus, BridgeError> {
        let index = self.find_bridge_index().await?;
        Ok(BridgeStatus {
            name: self.name.clone(),
            up: index.is_some(),
            index,
            nftables_active: nft::table_active().await?,
        })
    }

    /// Stop and join the netlink connection owned by this manager.
    pub async fn shutdown(&self) {
        self.connection_task
            .shutdown(Duration::from_secs(5), "bridge netlink connection")
            .await;
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_operation_errors_preserve_source_message() {
        let error = BridgeError::Operation(anyhow::anyhow!("security preflight failed"));
        assert_eq!(
            error.to_string(),
            "bridge operation failed: security preflight failed"
        );
    }
}
