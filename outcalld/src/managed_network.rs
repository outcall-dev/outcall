//! Validation for Docker networks accepted by managed agent containers.

use anyhow::{anyhow, Result};

/// Require a Docker bridge network backed by the exact host bridge protected
/// by Outcall's nftables rules.
pub fn validate_managed_network(
    network_name: &str,
    driver: Option<&str>,
    configured_bridge: Option<&str>,
    expected_bridge: &str,
) -> Result<()> {
    if !network_name.starts_with(outcall_api::NETWORK_PREFIX) {
        return Err(anyhow!(
            "network \"{network_name}\" is not Outcall-managed (expected prefix {})",
            outcall_api::NETWORK_PREFIX
        ));
    }
    if driver != Some("bridge") {
        return Err(anyhow!(
            "network \"{network_name}\" is not an Outcall bridge network"
        ));
    }
    if configured_bridge != Some(expected_bridge) {
        return Err(anyhow!(
            "network \"{network_name}\" uses bridge {configured_bridge:?}, expected {expected_bridge:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_expected_name_driver_and_bridge() {
        assert!(validate_managed_network(
            "outcall-default",
            Some("bridge"),
            Some("outcall0"),
            "outcall0"
        )
        .is_ok());
        assert!(
            validate_managed_network("bridge", Some("bridge"), Some("outcall0"), "outcall0")
                .is_err()
        );
        assert!(validate_managed_network(
            "outcall-default",
            Some("host"),
            Some("outcall0"),
            "outcall0"
        )
        .is_err());
        assert!(validate_managed_network(
            "outcall-default",
            Some("bridge"),
            Some("forged0"),
            "outcall0"
        )
        .is_err());
        assert!(
            validate_managed_network("outcall-default", Some("bridge"), None, "outcall0").is_err()
        );
    }
}
