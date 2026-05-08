use std::process::Stdio;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use rtnetlink::{Handle, LinkBridge, LinkUnspec};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

use outcall_api::BridgeStatus;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("netlink connection failed")]
    Connection(#[source] std::io::Error),

    #[error("bridge operation failed")]
    Operation(#[source] anyhow::Error),

    #[error("nftables operation failed: {0}")]
    Nftables(String),
}

/// Manages the outcall network bridge and its associated nftables rules.
///
/// Every agent container attaches to this bridge. The base nftables ruleset
/// drops all forwarded traffic by default — rules are dynamically inserted
/// later to allow specific flows.
pub struct BridgeManager {
    name: String,
    handle: Handle,
    index: Option<u32>,
}

impl BridgeManager {
    /// Create a new bridge manager. Does not touch the kernel yet.
    pub async fn new(name: Option<&str>) -> Result<Self, BridgeError> {
        let (conn, handle, _) = rtnetlink::new_connection().map_err(BridgeError::Connection)?;
        tokio::spawn(conn);

        Ok(Self {
            name: name.unwrap_or(outcall_api::DEFAULT_BRIDGE_NAME).to_string(),
            handle,
            index: None,
        })
    }

    /// Create (or attach to) the bridge and apply the base nftables ruleset.
    pub async fn init(&mut self) -> Result<(), BridgeError> {
        self.ensure_bridge().await?;
        self.apply_base_rules().await?;
        Ok(())
    }

    /// Idempotent bridge setup: create if missing, then bring up.
    async fn ensure_bridge(&mut self) -> Result<(), BridgeError> {
        let existing = self
            .find_link_index()
            .await
            .map_err(BridgeError::Operation)?;

        if let Some(idx) = existing {
            info!(bridge = %self.name, index = idx, "attaching to existing bridge");
            self.index = Some(idx);
        } else {
            info!(bridge = %self.name, "creating bridge");
            self.handle
                .link()
                .add(LinkBridge::new(&self.name).build())
                .execute()
                .await
                .context("create bridge")
                .map_err(BridgeError::Operation)?;

            let idx = self
                .find_link_index()
                .await
                .map_err(BridgeError::Operation)?
                .context("bridge not found after creation")
                .map_err(BridgeError::Operation)?;
            self.index = Some(idx);
        }

        // Bring the bridge up (idempotent — safe even if already up)
        let idx = self.index.expect("set above");
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await
            .context("bring bridge up")
            .map_err(BridgeError::Operation)?;

        info!(bridge = %self.name, index = idx, "bridge is up");
        Ok(())
    }

    /// Look up the bridge by name, returning its interface index if it exists.
    async fn find_link_index(&self) -> Result<Option<u32>> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(self.name.clone())
            .execute();

        match links.try_next().await {
            Ok(Some(msg)) => Ok(Some(msg.header.index)),
            Ok(None) => Ok(None),
            Err(e) => {
                // ENODEV (errno 19) means the device doesn't exist
                if e.to_string().contains("No such device") {
                    Ok(None)
                } else {
                    Err(anyhow::Error::from(e).context("query link by name"))
                }
            }
        }
    }

    /// Apply the base nftables ruleset: drop all forwarded traffic on the
    /// bridge except established/related connections.
    async fn apply_base_rules(&self) -> Result<(), BridgeError> {
        // Clean slate — remove table if it already exists (ignore errors)
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "outcall"])
            .output()
            .await;

        let ruleset = self.base_ruleset();
        self.run_nft(&ruleset).await?;

        info!("base nftables rules applied");
        Ok(())
    }

    /// Generate the base nftables ruleset.
    ///
    /// Policy: the chain default is `accept` so we don't break unrelated
    /// forwarded traffic. Rules explicitly match traffic entering or leaving
    /// our bridge and drop everything that isn't established/related.
    fn base_ruleset(&self) -> String {
        format!(
            r#"table inet outcall {{
    chain forward {{
        type filter hook forward priority 0; policy accept;
        iifname "{name}" ct state established,related accept
        iifname "{name}" drop
        oifname "{name}" ct state established,related accept
        oifname "{name}" drop
    }}
}}"#,
            name = self.name
        )
    }

    /// Execute an nftables ruleset via `nft -f -`.
    async fn run_nft(&self, ruleset: &str) -> Result<(), BridgeError> {
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                let detail = if e.kind() == std::io::ErrorKind::NotFound {
                    "nft command not found — is nftables installed?".to_string()
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission denied running nft — are you root or have CAP_NET_ADMIN?"
                        .to_string()
                } else {
                    format!("spawn nft: {e}")
                };
                BridgeError::Nftables(detail)
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .await
                .map_err(|e| BridgeError::Nftables(format!("write stdin: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| BridgeError::Nftables(format!("wait: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BridgeError::Nftables(format!(
                "nft exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Tear down: delete the nftables table, bring the bridge down, remove it.
    pub async fn teardown(&self) -> Result<(), BridgeError> {
        info!(bridge = %self.name, "tearing down");

        // Delete nftables table
        match Command::new("nft")
            .args(["delete", "table", "inet", "outcall"])
            .output()
            .await
        {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("nft table delete (may not exist): {}", stderr.trim());
            }
            Err(e) => warn!("nft command failed: {e}"),
            _ => {}
        }

        // Bring down and delete the bridge
        if let Some(idx) = self.index {
            let _ = self
                .handle
                .link()
                .set(LinkUnspec::new_with_index(idx).down().build())
                .execute()
                .await;
            self.handle
                .link()
                .del(idx)
                .execute()
                .await
                .context("delete bridge link")
                .map_err(BridgeError::Operation)?;
        }

        info!(bridge = %self.name, "teardown complete");
        Ok(())
    }

    /// Query current bridge and nftables state (fresh check every call).
    pub async fn status(&self) -> BridgeStatus {
        let link_up = self.find_link_index().await.ok().flatten().is_some();

        let nft_active = Command::new("nft")
            .args(["list", "table", "inet", "outcall"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        BridgeStatus {
            name: self.name.clone(),
            up: link_up,
            index: self.index,
            nftables_active: nft_active,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
