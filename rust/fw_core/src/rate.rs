//! Message rate tracking and token-bucket rate limiting. Time is always
//! passed in by the caller so behaviour is deterministic under test.

use std::collections::VecDeque;

/// Rolling-window message rate and time since the last message.
#[derive(Debug)]
pub struct RateTracker {
    window_s: f64,
    stamps: VecDeque<f64>,
    pub total: u64,
    pub last_time: Option<f64>,
}

impl RateTracker {
    pub fn new(window_s: f64) -> Self {
        Self { window_s, stamps: VecDeque::new(), total: 0, last_time: None }
    }

    pub fn tick(&mut self, now: f64) {
        self.stamps.push_back(now);
        self.total += 1;
        self.last_time = Some(now);
        self.evict(now);
    }

    fn evict(&mut self, now: f64) {
        while self.stamps.front().is_some_and(|t| now - t > self.window_s) {
            self.stamps.pop_front();
        }
    }

    pub fn rate_hz(&mut self, now: f64) -> f64 {
        self.evict(now);
        self.stamps.len() as f64 / self.window_s
    }

    pub fn age_s(&self, now: f64) -> f64 {
        self.last_time.map_or(f64::INFINITY, |t| now - t)
    }
}

/// Allows `rate` events per second on average with bursts up to `burst`.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Option<f64>,
}

impl TokenBucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        let burst = burst.max(1.0);
        Self { rate, burst, tokens: burst, last: None }
    }

    pub fn reset(&mut self) {
        self.tokens = self.burst;
        self.last = None;
    }

    pub fn allow(&mut self, now: f64) -> bool {
        if let Some(last) = self.last {
            self.tokens = (self.tokens + (now - last) * self.rate).min(self.burst);
        }
        self.last = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_rate() {
        let mut r = RateTracker::new(1.0);
        for i in 0..50 {
            r.tick(i as f64 * 0.1);
        }
        assert!((r.rate_hz(4.9) - 10.0).abs() <= 1.0);
    }

    #[test]
    fn age_and_eviction() {
        let mut r = RateTracker::new(1.0);
        assert!(r.age_s(0.0).is_infinite());
        for i in 0..10 {
            r.tick(i as f64 * 0.1);
        }
        assert!((r.age_s(3.4) - 2.5).abs() < 1e-9);
        assert_eq!(r.rate_hz(5.0), 0.0);
        assert_eq!(r.total, 10);
    }

    #[test]
    fn bucket_burst_then_rate() {
        let mut b = TokenBucket::new(10.0, 5.0);
        assert_eq!((0..20).filter(|_| b.allow(0.0)).count(), 5);
        assert!(!b.allow(0.05));
        assert!(b.allow(0.2));
    }

    #[test]
    fn bucket_passes_legit_rate() {
        let mut b = TokenBucket::new(50.0, 10.0);
        assert!((0..200).all(|i| b.allow(i as f64 * 0.05)));
    }
}
