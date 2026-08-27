use tokio::process::Command;
use tracing::{debug, info, warn};

use super::BridgeError;
use crate::system_command::{output_with_timeout, SYSTEM_COMMAND_TIMEOUT};

const BRIDGE_NF_IPV4: &str = "/proc/sys/net/bridge/bridge-nf-call-iptables";
const BRIDGE_NF_IPV6: &str = "/proc/sys/net/bridge/bridge-nf-call-ip6tables";

pub(super) async fn enable() {
    let mut modprobe = Command::new("modprobe");
    modprobe.arg("br_netfilter");
    if let Err(error) =
        output_with_timeout(&mut modprobe, SYSTEM_COMMAND_TIMEOUT, "load br_netfilter").await
    {
        debug!(%error, "br_netfilter module load was unavailable; checking sysctls directly");
    }

    for path in [BRIDGE_NF_IPV4, BRIDGE_NF_IPV6] {
        if matches!(tokio::fs::read_to_string(path).await, Ok(value) if value.trim() == "1") {
            info!(sysctl = path, "bridge netfilter already enabled");
            continue;
        }
        match tokio::fs::write(path, b"1").await {
            Ok(()) => info!(sysctl = path, "bridge netfilter enabled"),
            Err(error) => warn!(
                sysctl = path,
                %error,
                "could not enable bridge netfilter; managed container creation will be refused"
            ),
        }
    }
}

pub(super) async fn require_enforceable() -> Result<(), BridgeError> {
    let ipv4 = read_setting(BRIDGE_NF_IPV4).await;
    let ipv6 = read_setting(BRIDGE_NF_IPV6).await;
    if settings_enforceable(&ipv4, &ipv6) {
        return Ok(());
    }
    Err(BridgeError::Operation(anyhow::anyhow!(
        "Secure unattended mode requires bridge netfilter enforcement; \
         bridge-nf-call-iptables={ipv4}, bridge-nf-call-ip6tables={ipv6} (expected both to be 1)"
    )))
}

async fn read_setting(path: &str) -> String {
    match tokio::fs::read_to_string(path).await {
        Ok(value) => value.trim().to_string(),
        Err(error) => format!("unavailable ({error})"),
    }
}

fn settings_enforceable(ipv4: &str, ipv6: &str) -> bool {
    ipv4.trim() == "1" && ipv6.trim() == "1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_bridge_netfilter_hooks_are_required() {
        assert!(settings_enforceable("1\n", "1"));
        assert!(!settings_enforceable("0", "1"));
        assert!(!settings_enforceable("1", "0"));
        assert!(!settings_enforceable("missing", "1"));
    }
}
