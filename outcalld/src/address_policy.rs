use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn is_restricted(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_restricted_v4(address),
        IpAddr::V6(address) => is_restricted_v6(address),
    }
}

fn is_restricted_v4(address: Ipv4Addr) -> bool {
    let [first, second, third, fourth] = address.octets();
    first == 0
        || first == 10
        || first == 127
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 192 && second == 0 && third == 0 && !matches!(fourth, 9 | 10))
        || (first == 192 && second == 0 && third == 2)
        || (first == 192 && second == 88 && third == 99)
        || (first == 198 && (second == 18 || second == 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
        || (224..=239).contains(&first)
        || first >= 240
}

fn is_restricted_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || (segments[0] & 0xffc0) == 0xfe80 // link-local
        || (segments[0] & 0xfe00) == 0xfc00 // unique local
        || (segments[0] & 0xffc0) == 0xfec0 // deprecated site local
        || (segments[0] & 0xff00) == 0xff00 // multicast
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] == 0x2001 && segments[1] == 0) // Teredo
        || is_ipv4_mapped_or_compatible(segments)
        || restricted_nat64_embedded_v4(segments)
        || restricted_6to4_embedded_v4(segments)
}

fn is_ipv4_mapped_or_compatible(segments: [u16; 8]) -> bool {
    segments[..5] == [0, 0, 0, 0, 0]
        && (segments[5] == 0 || segments[5] == 0xffff)
        && (segments[6] != 0 || segments[7] > 1)
}

fn restricted_nat64_embedded_v4(segments: [u16; 8]) -> bool {
    if segments[..6] != [0x0064, 0xff9b, 0, 0, 0, 0] {
        return false;
    }
    is_restricted_v4(embedded_v4(segments[6], segments[7]))
}

fn restricted_6to4_embedded_v4(segments: [u16; 8]) -> bool {
    segments[0] == 0x2002 && is_restricted_v4(embedded_v4(segments[1], segments[2]))
}

fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    let high = high.to_be_bytes();
    let low = low.to_be_bytes();
    Ipv4Addr::new(high[0], high[1], low[0], low[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_public_addresses() {
        for address in [
            "1.1.1.1",
            "93.184.216.34",
            "192.0.0.9",
            "192.0.0.10",
            "2606:4700:4700::1111",
        ] {
            assert!(!is_restricted(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn blocks_non_public_ipv4_ranges() {
        for address in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(is_restricted(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn blocks_non_public_and_embedded_ipv6_ranges() {
        for address in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:0a00:0001::",
            "2001::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(is_restricted(address.parse().unwrap()), "{address}");
        }
    }
}
