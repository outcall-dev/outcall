use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use hickory_proto::rr::{Record, RecordType};
use lru::LruCache;
use outcall_api::DnsCacheEntry;

pub(super) const MAX_ENTRIES: usize = 10_000;
pub(super) const MAX_TTL_SECS: u32 = 300;

#[derive(Clone)]
struct CacheEntry {
    records: Vec<Record>,
    effective_ttl: u32,
    inserted_at: Instant,
    record_type: String,
}

pub(super) struct DnsCache {
    entries: LruCache<(String, RecordType), CacheEntry>,
}

impl DnsCache {
    pub(super) fn new() -> Self {
        Self::with_capacity(NonZeroUsize::new(MAX_ENTRIES).unwrap_or(NonZeroUsize::MIN))
    }

    fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self {
            entries: LruCache::new(capacity),
        }
    }

    pub(super) fn get(&mut self, hostname: &str, record_type: RecordType) -> Option<Vec<Record>> {
        let key = (hostname.to_owned(), record_type);
        let expired = self
            .entries
            .peek(&key)
            .is_some_and(|entry| entry.inserted_at.elapsed() >= ttl_duration(entry.effective_ttl));

        if expired {
            self.entries.pop(&key);
            return None;
        }

        let entry = self.entries.get(&key)?;
        let elapsed = elapsed_secs(entry.inserted_at);
        let remaining = entry.effective_ttl.saturating_sub(elapsed);
        let mut records = entry.records.clone();
        for record in &mut records {
            record.ttl = remaining;
        }
        Some(records)
    }

    /// Stores raw upstream records and returns whether an existing entry was evicted.
    pub(super) fn insert(
        &mut self,
        hostname: String,
        record_type: RecordType,
        record_type_name: String,
        records: Vec<Record>,
    ) -> bool {
        let Some(min_ttl) = records.iter().map(|record| record.ttl).min() else {
            return false;
        };
        let effective_ttl = min_ttl.min(MAX_TTL_SECS);
        if effective_ttl == 0 {
            return false;
        }

        let key = (hostname, record_type);
        let is_new = self.entries.peek(&key).is_none();
        let was_full = self.entries.len() >= self.entries.cap().get();
        self.entries.put(
            key,
            CacheEntry {
                records,
                effective_ttl,
                inserted_at: Instant::now(),
                record_type: record_type_name,
            },
        );
        is_new && was_full
    }

    pub(super) fn clear(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }

    pub(super) fn len(&mut self) -> usize {
        self.prune_expired();
        self.entries.len()
    }

    pub(super) fn snapshot(&mut self) -> Vec<DnsCacheEntry> {
        self.prune_expired();
        self.entries
            .iter()
            .map(|((hostname, _), entry)| DnsCacheEntry {
                hostname: hostname.clone(),
                record_type: entry.record_type.clone(),
                ttl_remaining_secs: entry
                    .effective_ttl
                    .saturating_sub(elapsed_secs(entry.inserted_at)),
            })
            .collect()
    }

    fn prune_expired(&mut self) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.inserted_at.elapsed() >= ttl_duration(entry.effective_ttl))
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.entries.pop(&key);
        }
    }
}

fn elapsed_secs(inserted_at: Instant) -> u32 {
    inserted_at.elapsed().as_secs().min(u64::from(u32::MAX)) as u32
}

fn ttl_duration(ttl: u32) -> Duration {
    Duration::from_secs(u64::from(ttl))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData};

    use super::*;

    fn record(ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
        )
    }

    #[test]
    fn lookup_prunes_expired_entries() {
        let mut cache = DnsCache::with_capacity(NonZeroUsize::MIN);
        cache.entries.put(
            ("example.com".to_string(), RecordType::A),
            CacheEntry {
                records: vec![record(1)],
                effective_ttl: 1,
                inserted_at: Instant::now() - Duration::from_secs(2),
                record_type: "A".to_string(),
            },
        );

        assert!(cache.get("example.com", RecordType::A).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn snapshots_prune_expired_entries() {
        let mut cache = DnsCache::with_capacity(NonZeroUsize::MIN);
        cache.entries.put(
            ("example.com".to_string(), RecordType::A),
            CacheEntry {
                records: vec![record(1)],
                effective_ttl: 1,
                inserted_at: Instant::now() - Duration::from_secs(2),
                record_type: "A".to_string(),
            },
        );

        assert!(cache.snapshot().is_empty());
        assert_eq!(cache.entries.len(), 0);
    }

    #[test]
    fn insertion_caps_ttl_and_reports_eviction() {
        let mut cache = DnsCache::with_capacity(NonZeroUsize::MIN);
        assert!(!cache.insert(
            "one.example".to_string(),
            RecordType::A,
            "A".to_string(),
            vec![record(900)],
        ));
        assert_eq!(
            cache
                .entries
                .peek(&("one.example".to_string(), RecordType::A))
                .unwrap()
                .effective_ttl,
            MAX_TTL_SECS
        );

        assert!(cache.insert(
            "two.example".to_string(),
            RecordType::A,
            "A".to_string(),
            vec![record(60)],
        ));
    }

    #[test]
    fn zero_ttl_records_are_not_cached() {
        let mut cache = DnsCache::with_capacity(NonZeroUsize::MIN);
        assert!(!cache.insert(
            "example.com".to_string(),
            RecordType::A,
            "A".to_string(),
            vec![record(0)],
        ));
        assert_eq!(cache.len(), 0);
    }
}
