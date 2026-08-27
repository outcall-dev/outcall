use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostServiceEndpoint {
    pub address: Ipv4Addr,
    pub port: u16,
}

impl HostServiceEndpoint {
    fn from_listener(listener: SocketAddr, gateway_ip: Ipv4Addr, label: &str) -> Result<Self> {
        if listener.port() == 0 {
            anyhow::bail!("{label} listener must use a fixed, non-zero port");
        }
        let address = match listener.ip() {
            IpAddr::V4(address) if address.is_unspecified() => gateway_ip,
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => anyhow::bail!(
                "{label} listener {listener} is IPv6, but the managed bridge only permits IPv4 host services"
            ),
        };
        Ok(Self {
            address,
            port: listener.port(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostServiceAccess {
    pub dns: HostServiceEndpoint,
    pub proxy: Option<HostServiceEndpoint>,
}

impl HostServiceAccess {
    pub fn from_listeners(
        gateway_ip: Ipv4Addr,
        dns_listener: SocketAddr,
        proxy_listener: Option<SocketAddr>,
    ) -> Result<Self> {
        Ok(Self {
            dns: HostServiceEndpoint::from_listener(dns_listener, gateway_ip, "DNS")?,
            proxy: proxy_listener
                .map(|listener| HostServiceEndpoint::from_listener(listener, gateway_ip, "proxy"))
                .transpose()?,
        })
    }

    pub fn default_for_gateway(gateway_ip: Ipv4Addr) -> Self {
        Self {
            dns: HostServiceEndpoint {
                address: gateway_ip,
                port: 53,
            },
            proxy: Some(HostServiceEndpoint {
                address: gateway_ip,
                port: 8080,
            }),
        }
    }
}

pub fn first_gateway_from_subnet_block(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let block = crate::network_cidr::AllocationBlock::parse(cidr)?;
    let (_, gateway) = block.first_subnet();
    Ok((
        gateway
            .parse()
            .context("derived subnet-block gateway is not a valid IPv4 address")?,
        24,
    ))
}

pub(super) fn validate_bridge_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        anyhow::bail!("bridge name must contain 1 to 15 ASCII characters");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("bridge name contains invalid characters (allowed: alphanumeric, -, _, .)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_first_gateway_from_allocation_block() {
        assert_eq!(
            first_gateway_from_subnet_block("10.200.0.0/16").unwrap(),
            (Ipv4Addr::new(10, 200, 0, 1), 24)
        );
        assert_eq!(
            first_gateway_from_subnet_block("172.30.16.0/20").unwrap(),
            (Ipv4Addr::new(172, 30, 16, 1), 24)
        );
    }

    #[test]
    fn maps_unspecified_listeners_to_gateway() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        let access = HostServiceAccess::from_listeners(
            gateway,
            "0.0.0.0:5353".parse().unwrap(),
            Some("0.0.0.0:8181".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(access.dns.address, gateway);
        assert_eq!(access.dns.port, 5353);
        assert_eq!(access.proxy.unwrap().port, 8181);
    }

    #[test]
    fn rejects_ipv6_and_ephemeral_listener_endpoints() {
        let gateway = Ipv4Addr::new(10, 200, 0, 1);
        assert!(
            HostServiceAccess::from_listeners(gateway, "[::1]:53".parse().unwrap(), None).is_err()
        );
        assert!(
            HostServiceAccess::from_listeners(gateway, "10.200.0.1:0".parse().unwrap(), None)
                .is_err()
        );
    }

    #[test]
    fn bridge_names_fit_linux_interface_and_nft_syntax() {
        assert!(validate_bridge_name("outcall0").is_ok());
        assert!(validate_bridge_name("").is_err());
        assert!(validate_bridge_name("a-very-long-bridge-name").is_err());
        assert!(validate_bridge_name("bad\"name").is_err());
        assert!(validate_bridge_name("bad\nname").is_err());
    }
}
