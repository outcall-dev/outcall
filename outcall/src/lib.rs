//! Library for outcall CLI — exposes helpers for use in integration tests (S000, S014).

#![forbid(unsafe_code)]

pub mod agent_config;
pub mod host_resources;
pub mod policy;
pub mod recipes;
pub mod request_target;
pub mod secure_fs;

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
    let value: i64 = num
        .parse()
        .with_context(|| format!("invalid memory value: {s}"))?;
    let bytes = value
        .checked_mul(mult)
        .with_context(|| format!("memory value is too large: {s}"))?;
    if !outcall_api::valid_memory_limit(bytes) {
        anyhow::bail!(
            "memory limit must be at least {} bytes (6m)",
            outcall_api::MIN_MEMORY_LIMIT
        );
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_parser_enforces_docker_bounds_and_overflow() {
        assert_eq!(parse_memory_arg("6m").unwrap(), 6 * 1024 * 1024);
        assert!(parse_memory_arg("5m").is_err());
        assert!(parse_memory_arg("0").is_err());
        assert!(parse_memory_arg("-1g").is_err());
        assert!(parse_memory_arg("9223372036854775807g").is_err());
    }
}
