use anyhow::Result;
use outcall_api::{
    Decision, DnsCacheDetail, DnsCacheFlushResult, DnsContext, DnsFilterStatus, EvalContext,
    EvaluateRequest, EvaluateResult,
};

use super::response_data;
use crate::daemon_client::{http_get, http_post, http_post_json};

pub(crate) fn cmd_dns_status(socket: &str) -> Result<()> {
    let status: DnsFilterStatus = response_data(&http_get(socket, "/api/v1/dns")?)?;
    if !status.running {
        println!("DNS Filter:     inactive (bridge not up)");
        return Ok(());
    }

    println!("DNS Filter:     active");
    println!(
        "Listen:         {}:{}",
        status.listen_address, status.listen_port
    );
    println!("Upstreams:      {}", status.upstreams.join(", "));
    println!("Cache:          {} entries", status.cache_entries);
    println!(
        "Queries:        {} total ({} allowed, {} blocked)",
        status.queries_total, status.queries_allowed, status.queries_blocked
    );
    Ok(())
}

pub(crate) fn cmd_dns_test(socket: &str, hostname: &str, record_type: &str) -> Result<()> {
    let request = EvaluateRequest {
        context: EvalContext {
            dns: Some(DnsContext {
                query: hostname.to_lowercase(),
                record_type: record_type.to_ascii_uppercase(),
            }),
            ..Default::default()
        },
    };
    let result: EvaluateResult =
        response_data(&http_post_json(socket, "/api/v1/rule/evaluate", &request)?)?;

    println!("Hostname:       {hostname}");
    println!("Record type:    {record_type}");
    println!(
        "Decision:       {}",
        if result.decision == Decision::Allow {
            "ALLOW"
        } else {
            "BLOCK"
        }
    );
    if let Some(rule) = result.matched_rule {
        println!(
            "Matched rule:   {rule} ({})",
            result.file.as_deref().unwrap_or("?")
        );
    } else {
        println!("Matched rule:   (default policy)");
    }
    Ok(())
}

pub(crate) fn cmd_dns_cache(socket: &str, show_entries: bool) -> Result<()> {
    let path = if show_entries {
        "/api/v1/dns/cache?entries=true"
    } else {
        "/api/v1/dns/cache"
    };
    let detail: DnsCacheDetail = response_data(&http_get(socket, path)?)?;
    let stats = &detail.stats;
    let hit_rate = if stats.hits + stats.misses > 0 {
        format!(
            "{:.1}%",
            stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0
        )
    } else {
        "N/A".to_string()
    };

    println!("Entries:        {} / {}", stats.entries, stats.max_entries);
    println!("Hits:           {}", stats.hits);
    println!("Misses:         {}", stats.misses);
    println!("Evictions:      {}", stats.evictions);
    println!("Hit rate:       {hit_rate}");

    if show_entries && !detail.entries.is_empty() {
        println!("\n{:<32} {:<6} TTL", "HOSTNAME", "TYPE");
        for entry in detail.entries {
            println!(
                "{:<32} {:<6} {}s",
                entry.hostname, entry.record_type, entry.ttl_remaining_secs
            );
        }
    }
    Ok(())
}

pub(crate) fn cmd_dns_flush(socket: &str) -> Result<()> {
    let result: DnsCacheFlushResult =
        response_data(&http_post(socket, "/api/v1/dns/cache/flush")?)?;
    println!(
        "DNS cache flushed ({} entries cleared).",
        result.entries_flushed
    );
    Ok(())
}
