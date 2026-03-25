//! Per-domain rate limiter backed by `governor`.

use governor::{
    clock::{Clock, QuantaClock},
    DefaultKeyedRateLimiter, Quota, RateLimiter,
};
use std::num::NonZeroU32;
use tracing::debug;

/// Wraps a keyed (per-domain) governor rate limiter.
pub struct DomainRateLimiter {
    limiter: DefaultKeyedRateLimiter<String>,
    clock: QuantaClock,
}

impl DomainRateLimiter {
    /// Create a new limiter allowing `rpm` requests per minute per domain.
    pub fn new(rpm: u32) -> Self {
        let n = NonZeroU32::new(rpm.max(1)).expect("rpm must be >= 1");
        let quota = Quota::per_minute(n);
        Self {
            limiter: RateLimiter::keyed(quota),
            clock: QuantaClock::default(),
        }
    }

    /// Async-wait until a request to `domain` is permitted.
    pub async fn acquire(&self, domain: &str) {
        let key = domain.to_string();
        loop {
            match self.limiter.check_key(&key) {
                Ok(_) => return,
                Err(not_until) => {
                    let wait = not_until.wait_time_from(self.clock.now());
                    debug!(
                        domain = %domain,
                        wait_ms = %wait.as_millis(),
                        "rate limit: sleeping"
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}
