use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFilterStatus {
    pub running: bool,
    pub listen_address: String,
    pub listen_port: u16,
    pub upstreams: Vec<String>,
    pub cache_entries: usize,
    pub queries_total: u64,
    pub queries_allowed: u64,
    pub queries_blocked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheStats {
    pub entries: usize,
    pub max_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub record_type: String,
    pub ttl_remaining_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheDetail {
    pub stats: DnsCacheStats,
    pub entries: Vec<DnsCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheFlushResult {
    pub entries_flushed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub listen_address: String,
    pub proxy_url: String,
    pub active_connections: u64,
    pub total_requests: u64,
    pub total_blocked: u64,
}
