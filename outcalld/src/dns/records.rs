use std::net::IpAddr;

use hickory_proto::rr::{RData, Record};

pub(crate) struct FilteredRecords {
    pub(crate) records: Vec<Record>,
    pub(crate) address_count_before: usize,
    pub(crate) address_count_after: usize,
}

pub(crate) enum AddressPolicyOutcome {
    Allowed(Vec<Record>),
    RestrictedOnly,
}

pub(crate) fn apply_address_policy(
    hostname: &str,
    records: Vec<Record>,
    allow_restricted: bool,
) -> AddressPolicyOutcome {
    if allow_restricted {
        return AddressPolicyOutcome::Allowed(records);
    }
    let filtered = filter_restricted_addresses(hostname, records);
    if filtered.address_count_before > 0 && filtered.address_count_after == 0 {
        AddressPolicyOutcome::RestrictedOnly
    } else {
        AddressPolicyOutcome::Allowed(filtered.records)
    }
}

pub(crate) fn filter_restricted_addresses(hostname: &str, records: Vec<Record>) -> FilteredRecords {
    let address_count_before = records.iter().filter_map(record_address).count();
    let records = records
        .into_iter()
        .filter(|record| {
            let Some(address) = record_address(record) else {
                return true;
            };
            if crate::address_policy::is_restricted(address) {
                tracing::info!(
                    host = %hostname,
                    dropped_ip = %address,
                    reason = "restricted_ip",
                    "DNS answer record stripped"
                );
                return false;
            }
            true
        })
        .collect::<Vec<_>>();
    let address_count_after = records.iter().filter_map(record_address).count();
    FilteredRecords {
        records,
        address_count_before,
        address_count_after,
    }
}

pub(crate) fn extract_ipv4_destinations(records: &[Record]) -> Vec<String> {
    let mut destinations = records
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(address.0.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    destinations.sort();
    destinations.dedup();
    destinations
}

pub(crate) fn extract_ipv6_destinations(records: &[Record]) -> Vec<String> {
    let mut destinations = records
        .iter()
        .filter_map(|record| match &record.data {
            RData::AAAA(address) => Some(address.0.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    destinations.sort();
    destinations.dedup();
    destinations
}

fn record_address(record: &Record) -> Option<IpAddr> {
    match &record.data {
        RData::A(address) => Some(IpAddr::V4(address.0)),
        RData::AAAA(address) => Some(IpAddr::V6(address.0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::rr::{Name, RData, Record};

    use super::*;

    fn a(name: &Name, address: Ipv4Addr) -> Record {
        Record::from_rdata(
            name.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A(address)),
        )
    }

    fn aaaa(name: &Name, address: Ipv6Addr) -> Record {
        Record::from_rdata(
            name.clone(),
            60,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(address)),
        )
    }

    #[test]
    fn strips_restricted_and_keeps_public_addresses() {
        let name = Name::from_ascii("mixed.example.com.").unwrap();
        let filtered = filter_restricted_addresses(
            "mixed.example.com",
            vec![
                a(&name, Ipv4Addr::new(192, 168, 1, 10)),
                a(&name, Ipv4Addr::new(93, 184, 216, 34)),
                aaaa(&name, "fe80::1".parse().unwrap()),
                aaaa(&name, "2606:4700:4700::1111".parse().unwrap()),
            ],
        );

        assert_eq!(filtered.address_count_before, 4);
        assert_eq!(filtered.address_count_after, 2);
        assert_eq!(filtered.records.len(), 2);
    }

    #[test]
    fn reports_when_all_address_answers_were_removed() {
        let name = Name::from_ascii("internal.example.com.").unwrap();
        let filtered = filter_restricted_addresses(
            "internal.example.com",
            vec![a(&name, Ipv4Addr::new(10, 0, 0, 2))],
        );

        assert_eq!(filtered.address_count_before, 1);
        assert_eq!(filtered.address_count_after, 0);
        assert!(filtered.records.is_empty());
    }

    #[test]
    fn private_answers_require_explicit_opt_in() {
        let name = Name::from_ascii("internal.example.com.").unwrap();
        let records = vec![a(&name, Ipv4Addr::new(10, 0, 0, 2))];

        assert!(matches!(
            apply_address_policy("internal.example.com", records.clone(), false),
            AddressPolicyOutcome::RestrictedOnly
        ));
        let AddressPolicyOutcome::Allowed(allowed) =
            apply_address_policy("internal.example.com", records, true)
        else {
            panic!("explicit private-address opt-in should allow the answer");
        };
        assert_eq!(allowed.len(), 1);
    }

    #[test]
    fn destination_extraction_is_sorted_and_deduplicated() {
        let name = Name::from_ascii("example.com.").unwrap();
        let records = vec![
            a(&name, Ipv4Addr::new(93, 184, 216, 34)),
            a(&name, Ipv4Addr::new(1, 1, 1, 1)),
            a(&name, Ipv4Addr::new(93, 184, 216, 34)),
            aaaa(&name, "2606:4700:4700::1111".parse().unwrap()),
        ];

        assert_eq!(
            extract_ipv4_destinations(&records),
            vec!["1.1.1.1", "93.184.216.34"]
        );
        assert_eq!(
            extract_ipv6_destinations(&records),
            vec!["2606:4700:4700::1111"]
        );
    }
}
