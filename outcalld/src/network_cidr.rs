use std::net::Ipv4Addr;

use anyhow::{anyhow, Context, Result};
use ipnet::{IpNet, Ipv4Net};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateRange {
    Ten,
    OneSeventyTwo,
    OneNinetyTwo,
}

#[derive(Clone, Debug)]
pub(crate) struct AllocationBlock {
    network: Ipv4Net,
}

impl AllocationBlock {
    pub(crate) fn parse(cidr: &str) -> Result<Self> {
        let network = parse_ipv4_network(cidr, "subnet block")?;
        if network.prefix_len() > 24 {
            return Err(anyhow!(
                "subnet block must be /24 or larger (got /{})",
                network.prefix_len()
            ));
        }
        require_private_network(network, "subnet block")?;
        Ok(Self { network })
    }

    pub(crate) fn cidr(&self) -> String {
        self.network.to_string()
    }

    pub(crate) fn iter_24(&self) -> impl Iterator<Item = (Ipv4Addr, Ipv4Addr)> + '_ {
        let count = 1u32 << (24 - self.network.prefix_len());
        let base = u32::from(self.network.network());

        (0..count).map(move |offset| {
            let network = Ipv4Addr::from(base + (offset << 8));
            let gateway = Ipv4Addr::from(u32::from(network) + 1);
            (network, gateway)
        })
    }

    pub(crate) fn first_subnet(&self) -> (String, String) {
        let network = self.network.network();
        let gateway = Ipv4Addr::from(u32::from(network) + 1);
        (format!("{network}/24"), gateway.to_string())
    }

    pub(crate) fn contains_allocated_subnet(&self, subnet: Ipv4Net) -> bool {
        subnet.prefix_len() == 24
            && self.network.contains(&subnet.network())
            && self.network.contains(&subnet.broadcast())
    }
}

pub(crate) fn parse_agent_subnet(cidr: &str) -> Result<Ipv4Net> {
    let network = parse_ipv4_network(cidr, "agent subnet")?;
    if network.prefix_len() > 30 {
        return Err(anyhow!(
            "agent subnet must provide usable gateway and container addresses (got /{})",
            network.prefix_len()
        ));
    }
    require_private_network(network, "agent subnet")?;
    Ok(network)
}

pub(crate) fn parse_docker_subnet(cidr: &str) -> Result<Option<Ipv4Net>> {
    let network: IpNet = cidr
        .parse()
        .with_context(|| format!("Docker returned invalid subnet CIDR \"{cidr}\""))?;
    Ok(match network {
        IpNet::V4(network) => Some(network.trunc()),
        IpNet::V6(_) => None,
    })
}

pub(crate) fn resolve_gateway(subnet: Ipv4Net, gateway: Option<&str>) -> Result<String> {
    let gateway = match gateway {
        Some(value) => value
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 gateway \"{value}\""))?,
        None => Ipv4Addr::from(u32::from(subnet.network()) + 1),
    };

    if !subnet.contains(&gateway) {
        return Err(anyhow!(
            "gateway {gateway} is outside agent subnet {subnet}"
        ));
    }
    if gateway == subnet.network() || gateway == subnet.broadcast() {
        return Err(anyhow!(
            "gateway {gateway} is not a usable host address in agent subnet {subnet}"
        ));
    }

    Ok(gateway.to_string())
}

pub(crate) fn networks_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn parse_ipv4_network(cidr: &str, kind: &str) -> Result<Ipv4Net> {
    let network: Ipv4Net = cidr
        .parse()
        .with_context(|| format!("invalid {kind} CIDR \"{cidr}\""))?;
    if network.addr() != network.network() {
        return Err(anyhow!(
            "{kind} CIDR must use its network address (got {cidr}, expected {})",
            network.trunc()
        ));
    }
    Ok(network)
}

fn require_private_network(network: Ipv4Net, kind: &str) -> Result<()> {
    let start = private_range(network.network());
    let end = private_range(network.broadcast());
    if start.is_none() || start != end {
        return Err(anyhow!(
            "{kind} {network} is not wholly within one RFC 1918 private range"
        ));
    }
    Ok(())
}

fn private_range(address: Ipv4Addr) -> Option<PrivateRange> {
    let octets = address.octets();
    if octets[0] == 10 {
        Some(PrivateRange::Ten)
    } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        Some(PrivateRange::OneSeventyTwo)
    } else if octets[0] == 192 && octets[1] == 168 {
        Some(PrivateRange::OneNinetyTwo)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_block_iterates_each_24() {
        let block = AllocationBlock::parse("10.42.0.0/22").expect("valid allocation block");
        let subnets: Vec<_> = block.iter_24().collect();

        assert_eq!(block.cidr(), "10.42.0.0/22");
        assert_eq!(
            block.first_subnet(),
            ("10.42.0.0/24".to_string(), "10.42.0.1".to_string())
        );
        assert_eq!(subnets.len(), 4);
        assert_eq!(subnets[0].0.to_string(), "10.42.0.0");
        assert_eq!(subnets[3].0.to_string(), "10.42.3.0");
        assert_eq!(subnets[3].1.to_string(), "10.42.3.1");
        assert!(block.contains_allocated_subnet("10.42.2.0/24".parse().unwrap()));
        assert!(!block.contains_allocated_subnet("10.43.0.0/24".parse().unwrap()));
        assert!(!block.contains_allocated_subnet("10.42.0.0/23".parse().unwrap()));
    }

    #[test]
    fn allocation_block_rejects_host_bits_and_partly_public_ranges() {
        assert!(AllocationBlock::parse("10.42.1.0/16").is_err());
        assert!(AllocationBlock::parse("10.0.0.0/7").is_err());
        assert!(AllocationBlock::parse("172.16.0.0/12").is_ok());
        assert!(AllocationBlock::parse("172.16.0.0/10").is_err());
        assert!(AllocationBlock::parse("192.168.0.0/15").is_err());
    }

    #[test]
    fn agent_subnet_requires_private_canonical_usable_range() {
        assert!(parse_agent_subnet("10.200.5.0/24").is_ok());
        assert!(parse_agent_subnet("10.200.5.1/24").is_err());
        assert!(parse_agent_subnet("8.8.8.0/24").is_err());
        assert!(parse_agent_subnet("10.200.5.0/31").is_err());
        assert!(parse_agent_subnet("2001:db8::/64").is_err());
    }

    #[test]
    fn overlap_detects_containment_in_both_directions() {
        let broad = parse_agent_subnet("10.20.0.0/16").expect("valid broad subnet");
        let narrow = parse_agent_subnet("10.20.5.0/24").expect("valid narrow subnet");
        let separate = parse_agent_subnet("10.21.0.0/16").expect("valid separate subnet");

        assert!(networks_overlap(broad, narrow));
        assert!(networks_overlap(narrow, broad));
        assert!(!networks_overlap(broad, separate));
    }

    #[test]
    fn docker_subnet_parser_ignores_valid_ipv6_and_rejects_malformed_input() {
        assert!(parse_docker_subnet("10.20.5.0/24")
            .expect("valid IPv4 subnet")
            .is_some());
        assert!(parse_docker_subnet("2001:db8::/64")
            .expect("valid IPv6 subnet")
            .is_none());
        assert!(parse_docker_subnet("not-a-subnet").is_err());
    }

    #[test]
    fn gateway_must_be_usable_and_inside_subnet() {
        let subnet = parse_agent_subnet("10.200.5.0/24").expect("valid subnet");

        assert_eq!(
            resolve_gateway(subnet, None).expect("derived gateway"),
            "10.200.5.1"
        );
        assert!(resolve_gateway(subnet, Some("10.200.6.1")).is_err());
        assert!(resolve_gateway(subnet, Some("10.200.5.0")).is_err());
        assert!(resolve_gateway(subnet, Some("not-an-ip")).is_err());
    }
}
