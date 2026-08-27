use std::collections::HashMap;

use anyhow::{Context, Result};

pub(super) fn random_broker_token() -> Result<String> {
    crate::random_token::hex::<16>()
}

pub(crate) fn resolve_broker_auth_token(explicit: Option<String>) -> Result<String> {
    let token = explicit
        .or_else(|| std::env::var("OUTCALL_HOST_BROKER_TOKEN").ok())
        .filter(|token| !token.is_empty())
        .context(
            "host broker authentication token is required; pass --auth-token or set OUTCALL_HOST_BROKER_TOKEN",
        )?;
    if token.len() < 32 || token.len() > 256 || token.chars().any(char::is_control) {
        anyhow::bail!("host broker authentication token must be 32-256 non-control characters");
    }
    Ok(token)
}

pub(super) fn request_is_authenticated(
    headers: &HashMap<String, String>,
    expected_token: &str,
) -> bool {
    let Some(value) = headers.get("authorization") else {
        return false;
    };
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("bearer")
        && constant_time_eq(token.as_bytes(), expected_token.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| {
            difference | (*left ^ *right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let headers = HashMap::from([(
            "authorization".to_string(),
            format!("bEaReR {}", "a".repeat(32)),
        )]);
        assert!(request_is_authenticated(&headers, &"a".repeat(32)));
        assert!(!request_is_authenticated(&headers, &"b".repeat(32)));
    }
}
