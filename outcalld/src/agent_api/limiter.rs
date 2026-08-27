use std::collections::HashMap;
use std::time::{Duration, Instant};

pub(super) struct SlidingWindow {
    timestamps: Vec<Instant>,
    window: Duration,
    limit: usize,
    last_seen: Instant,
}

impl SlidingWindow {
    pub(super) fn new(limit: usize, window: Duration) -> Self {
        Self {
            timestamps: Vec::new(),
            window,
            limit,
            last_seen: Instant::now(),
        }
    }

    /// Records a request, or returns how long the caller should wait.
    pub(super) fn check(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        self.last_seen = now;
        self.timestamps
            .retain(|timestamp| now.duration_since(*timestamp) < self.window);
        if self.timestamps.len() >= self.limit {
            let retry_after = self
                .timestamps
                .first()
                .map(|oldest| self.window.saturating_sub(now.duration_since(*oldest)))
                .unwrap_or(self.window);
            return Err(retry_after);
        }
        self.timestamps.push(now);
        Ok(())
    }

    fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.last_seen) > self.window.saturating_mul(2)
    }
}

pub(super) fn reap_stale(rate: &mut HashMap<String, SlidingWindow>) {
    let now = Instant::now();
    rate.retain(|_, limiter| !limiter.is_stale(now));
}

pub(super) fn retry_after_seconds(duration: Duration) -> u64 {
    let seconds = duration.as_secs();
    if duration.subsec_nanos() == 0 {
        seconds.max(1)
    } else {
        seconds.saturating_add(1).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_under_limit_and_returns_remaining_window() {
        let mut window = SlidingWindow::new(2, Duration::from_secs(10));
        assert!(window.check().is_ok());
        assert!(window.check().is_ok());

        let wait = window.check().unwrap_err();
        assert!(wait > Duration::from_secs(9));
        assert!(wait <= Duration::from_secs(10));
    }

    #[test]
    fn stale_limiters_are_reaped() {
        let mut rate = HashMap::new();
        let mut stale = SlidingWindow::new(1, Duration::from_secs(1));
        stale.last_seen = Instant::now() - Duration::from_secs(3);
        rate.insert("stale".to_string(), stale);
        rate.insert(
            "fresh".to_string(),
            SlidingWindow::new(1, Duration::from_secs(1)),
        );

        reap_stale(&mut rate);

        assert!(!rate.contains_key("stale"));
        assert!(rate.contains_key("fresh"));
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
        assert_eq!(retry_after_seconds(Duration::from_secs(2)), 2);
        assert_eq!(retry_after_seconds(Duration::from_millis(2_001)), 3);
    }
}
