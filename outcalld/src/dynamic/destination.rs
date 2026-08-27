use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::IpNet;

const DNS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Normalize an IP/CIDR destination or resolve a hostname for an nftables rule.
pub(super) async fn resolve(destination: &str) -> Result<String> {
    if destination.contains('/') {
        let network: IpNet = destination
            .parse()
            .with_context(|| format!("invalid destination CIDR \"{destination}\""))?;
        if network.addr() != network.network() {
            anyhow::bail!(
                "destination CIDR must use its network address (got {destination}, expected {})",
                network.trunc()
            );
        }
        return Ok(network.to_string());
    }
    if let Ok(address) = destination.parse::<IpAddr>() {
        return Ok(address.to_string());
    }

    let hostname = match url::Host::parse(destination)
        .with_context(|| format!("invalid destination hostname \"{destination}\""))?
    {
        url::Host::Domain(hostname) => hostname,
        _ => anyhow::bail!("invalid destination address \"{destination}\""),
    };

    let addresses: Vec<_> = tokio::time::timeout(
        DNS_RESOLUTION_TIMEOUT,
        tokio::net::lookup_host((hostname.as_str(), 0)),
    )
    .await
    .with_context(|| {
        format!(
            "DNS resolution timed out after {}s for \"{destination}\"",
            DNS_RESOLUTION_TIMEOUT.as_secs()
        )
    })?
    .with_context(|| format!("DNS resolution failed for \"{destination}\""))?
    .collect();

    addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.iter().find(|address| address.is_ipv6()))
        .map(|address| address.ip().to_string())
        .with_context(|| format!("no IP address found for \"{destination}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literals_are_validated_and_normalized() {
        assert_eq!(resolve("10.0.0.1").await.unwrap(), "10.0.0.1");
        assert_eq!(resolve("192.168.0.0/24").await.unwrap(), "192.168.0.0/24");
        assert_eq!(resolve("2001:db8::1").await.unwrap(), "2001:db8::1");
        assert!(resolve("192.168.0.1/24").await.is_err());
        assert!(resolve("192.168.0.0/99").await.is_err());
        assert!(resolve("fe80::1%eth0").await.is_err());
        assert!(resolve("bad:host:value").await.is_err());
    }
}
