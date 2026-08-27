use std::time::Duration;

use anyhow::{Context, Result};

const MAX_RATE_LIMIT: usize = 1_000_000;
const MAX_RATE_WINDOW_SECS: u64 = 24 * 60 * 60;
const MAX_EVALUATION_TIMEOUT_SECS: u64 = 5 * 60;

pub fn parse(specification: &str) -> Result<(usize, Duration)> {
    let (limit, seconds) = specification.split_once('/').with_context(|| {
        format!("invalid rate limit {specification:?}; expected <count>/<seconds>")
    })?;
    if seconds.contains('/') {
        anyhow::bail!("invalid rate limit {specification:?}; expected exactly one '/'");
    }
    let limit = limit
        .parse::<usize>()
        .with_context(|| format!("invalid rate-limit count in {specification:?}"))?;
    let seconds = seconds
        .parse::<u64>()
        .with_context(|| format!("invalid rate-limit window in {specification:?}"))?;
    if !(1..=MAX_RATE_LIMIT).contains(&limit) {
        anyhow::bail!("rate-limit count must be between 1 and {MAX_RATE_LIMIT}");
    }
    if !(1..=MAX_RATE_WINDOW_SECS).contains(&seconds) {
        anyhow::bail!("rate-limit window must be between 1 and {MAX_RATE_WINDOW_SECS} seconds");
    }
    Ok((limit, Duration::from_secs(seconds)))
}

pub fn evaluation_timeout(seconds: u64) -> Result<Duration> {
    if !(1..=MAX_EVALUATION_TIMEOUT_SECS).contains(&seconds) {
        anyhow::bail!(
            "agent evaluation timeout must be between 1 and {MAX_EVALUATION_TIMEOUT_SECS} seconds"
        );
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_rate() {
        assert_eq!(parse("100/10").unwrap(), (100, Duration::from_secs(10)));
    }

    #[test]
    fn rejects_malformed_zero_and_excessive_rates() {
        for invalid in ["100", "100/10/2", "x/10", "100/x", "0/10", "10/0"] {
            assert!(parse(invalid).is_err(), "rate {invalid:?} should fail");
        }
        assert!(parse("1000001/10").is_err());
        assert!(parse("10/86401").is_err());
    }

    #[test]
    fn evaluation_timeout_is_nonzero_and_bounded() {
        assert_eq!(evaluation_timeout(5).unwrap(), Duration::from_secs(5));
        assert!(evaluation_timeout(0).is_err());
        assert!(evaluation_timeout(301).is_err());
    }
}
