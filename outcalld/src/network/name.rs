use anyhow::{anyhow, Result};
use outcall_api::{DEFAULT_NETWORK_NAME, NETWORK_PREFIX};

/// Normalize a user-facing suffix into a Docker network name.
pub(super) fn full_name(name: Option<&str>) -> Result<String> {
    match name {
        None | Some("") => Ok(DEFAULT_NETWORK_NAME.to_string()),
        Some(name) => {
            if name.len() > 64 {
                return Err(anyhow!(
                    "network name must be 1-64 characters (got {})",
                    name.len()
                ));
            }
            if !name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            }) {
                return Err(anyhow!(
                    "network name \"{name}\" contains invalid characters (allowed: alphanumeric, -, _)"
                ));
            }
            if name.starts_with(NETWORK_PREFIX) {
                Ok(name.to_string())
            } else {
                Ok(format!("{NETWORK_PREFIX}{name}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_prefixes_names() {
        assert_eq!(full_name(None).unwrap(), "outcall-default");
        assert_eq!(full_name(Some("")).unwrap(), "outcall-default");
        assert_eq!(full_name(Some("staging")).unwrap(), "outcall-staging");
        assert_eq!(full_name(Some("outcall-prod")).unwrap(), "outcall-prod");
    }

    #[test]
    fn validates_name_characters_and_length() {
        assert!(full_name(Some("a-b_c")).is_ok());
        assert!(full_name(Some("bad name")).is_err());
        assert!(full_name(Some("bad/name")).is_err());
        assert!(full_name(Some(&"a".repeat(65))).is_err());
    }
}
