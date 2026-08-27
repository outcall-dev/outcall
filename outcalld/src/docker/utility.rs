use std::collections::HashMap;

use anyhow::Result;
use bollard::models::HostConfig;
use outcall_api::DEFAULT_PID_LIMIT;

#[cfg(test)]
use outcall_api::{DEFAULT_CPU_SHARES, DEFAULT_MEMORY_LIMIT};

pub(super) fn managed_host_config(
    binds: Vec<String>,
    memory: i64,
    cpu_shares: i64,
    dns_addr: &str,
    network_name: &str,
) -> HostConfig {
    HostConfig {
        binds: Some(binds),
        memory: Some(memory),
        cpu_shares: Some(cpu_shares),
        pids_limit: Some(DEFAULT_PID_LIMIT),
        readonly_rootfs: Some(true),
        privileged: Some(false),
        cap_drop: Some(vec!["ALL".to_string()]),
        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
        network_mode: Some(network_name.to_string()),
        dns: Some(vec![dns_addr.to_string()]),
        dns_options: Some(vec!["ndots:0".to_string()]),
        init: Some(true),
        tmpfs: Some(HashMap::from([(
            "/tmp".to_string(),
            "rw,nosuid,nodev,mode=1777".to_string(),
        )])),
        ..Default::default()
    }
}

pub(super) fn random_hex_suffix() -> Result<String> {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("secure OS random source unavailable: {error}"))?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_suffix_is_lowercase_hex() {
        let suffix = random_hex_suffix().unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(suffix
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)));
    }

    #[test]
    fn managed_config_is_fail_closed() {
        let config = managed_host_config(
            vec!["/host:/workspace".to_string()],
            DEFAULT_MEMORY_LIMIT,
            DEFAULT_CPU_SHARES,
            "10.200.0.1",
            "outcall-default",
        );

        assert_eq!(config.privileged, Some(false));
        assert_eq!(config.readonly_rootfs, Some(true));
        assert_eq!(config.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(
            config.security_opt,
            Some(vec!["no-new-privileges:true".to_string()])
        );
        assert_eq!(config.pids_limit, Some(DEFAULT_PID_LIMIT));
        assert_eq!(config.memory, Some(DEFAULT_MEMORY_LIMIT));
        assert_eq!(config.cpu_shares, Some(DEFAULT_CPU_SHARES));
        assert_eq!(config.network_mode.as_deref(), Some("outcall-default"));
        assert_eq!(config.dns, Some(vec!["10.200.0.1".to_string()]));
        assert_eq!(config.dns_options, Some(vec!["ndots:0".to_string()]));
        assert_eq!(config.init, Some(true));
        assert_eq!(
            config.tmpfs,
            Some(HashMap::from([(
                "/tmp".to_string(),
                "rw,nosuid,nodev,mode=1777".to_string()
            )]))
        );
    }
}
