//! Library for outcall CLI — exposes helpers for use in integration tests (S000, S014).

#![forbid(unsafe_code)]

pub mod agent_boot;
pub mod agent_config;
pub mod host_resources;
pub mod recipes;

use anyhow::Context;

/// Parse a human-friendly memory string (e.g. "256m", "1g") to bytes.
pub fn parse_memory_arg(s: &str) -> anyhow::Result<i64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('g').or_else(|| s.strip_suffix('G')) {
        (n, 1024 * 1024 * 1024i64)
    } else if let Some(n) = s.strip_suffix('m').or_else(|| s.strip_suffix('M')) {
        (n, 1024 * 1024i64)
    } else if let Some(n) = s.strip_suffix('k').or_else(|| s.strip_suffix('K')) {
        (n, 1024i64)
    } else {
        (s, 1i64)
    };
    let bytes: i64 = num
        .parse()
        .with_context(|| format!("invalid memory value: {s}"))?;
    Ok(bytes * mult)
}

/// Percent-encode a string for use in query parameters (minimal — only encodes spaces).
pub fn urlencoded(s: &str) -> String {
    s.replace(' ', "%20")
}
