use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum connections per IP per window
    pub max_connections_per_ip: u32,
    /// Maximum requests per partner per window
    pub max_requests_per_partner: u32,
    /// Maximum bytes per partner per window
    pub max_bytes_per_partner: u64,
    /// Time window duration
    pub window_duration: Duration,
    /// Ban duration after exceeding limits
    pub ban_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 10,
            max_requests_per_partner: 1000,
            max_bytes_per_partner: 1024 * 1024 * 1024, // 1 GB
            window_duration: Duration::from_secs(60),
            ban_duration: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone)]
struct RateBucket {
    count: u32,
    bytes: u64,
    window_start: Instant,
    banned_until: Option<Instant>,
}

impl RateBucket {
    fn new() -> Self {
        Self {
            count: 0,
            bytes: 0,
            window_start: Instant::now(),
            banned_until: None,
        }
    }

    fn reset_if_expired(&mut self, window_duration: Duration) {
        if self.window_start.elapsed() > window_duration {
            self.count = 0;
            self.bytes = 0;
            self.window_start = Instant::now();
        }
    }

    fn is_banned(&self) -> bool {
        self.banned_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    fn ban(&mut self, duration: Duration) {
        self.banned_until = Some(Instant::now() + duration);
    }
}

/// Thread-safe rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    ip_buckets: Arc<RwLock<HashMap<IpAddr, RateBucket>>>,
    partner_buckets: Arc<RwLock<HashMap<String, RateBucket>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_buckets: Arc::new(RwLock::new(HashMap::new())),
            partner_buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an IP is allowed to connect
    pub async fn check_ip(&self, ip: IpAddr) -> RateLimitResult {
        let mut buckets = self.ip_buckets.write().await;
        let bucket = buckets.entry(ip).or_insert_with(RateBucket::new);

        // Check if banned
        if bucket.is_banned() {
            warn!("IP {} is banned", ip);
            return RateLimitResult::Banned;
        }

        // Reset window if expired
        bucket.reset_if_expired(self.config.window_duration);

        // Check limit
        if bucket.count >= self.config.max_connections_per_ip {
            warn!("IP {} exceeded connection limit", ip);
            bucket.ban(self.config.ban_duration);
            return RateLimitResult::Exceeded;
        }

        bucket.count += 1;
        debug!("IP {} connection count: {}", ip, bucket.count);
        RateLimitResult::Allowed
    }

    /// Check if a partner is allowed to make a request
    pub async fn check_partner(&self, partner_id: &str) -> RateLimitResult {
        let mut buckets = self.partner_buckets.write().await;
        let bucket = buckets
            .entry(partner_id.to_string())
            .or_insert_with(RateBucket::new);

        if bucket.is_banned() {
            warn!("Partner {} is banned", partner_id);
            return RateLimitResult::Banned;
        }

        bucket.reset_if_expired(self.config.window_duration);

        if bucket.count >= self.config.max_requests_per_partner {
            warn!("Partner {} exceeded request limit", partner_id);
            bucket.ban(self.config.ban_duration);
            return RateLimitResult::Exceeded;
        }

        bucket.count += 1;
        RateLimitResult::Allowed
    }

    /// Record bytes transferred for a partner
    pub async fn record_bytes(&self, partner_id: &str, bytes: u64) -> RateLimitResult {
        let mut buckets = self.partner_buckets.write().await;
        let bucket = buckets
            .entry(partner_id.to_string())
            .or_insert_with(RateBucket::new);

        bucket.reset_if_expired(self.config.window_duration);

        bucket.bytes += bytes;

        if bucket.bytes > self.config.max_bytes_per_partner {
            warn!(
                "Partner {} exceeded bandwidth limit ({} bytes)",
                partner_id, bucket.bytes
            );
            bucket.ban(self.config.ban_duration);
            return RateLimitResult::Exceeded;
        }

        RateLimitResult::Allowed
    }

    /// Get current stats for an IP
    pub async fn get_ip_stats(&self, ip: IpAddr) -> Option<(u32, bool)> {
        let buckets = self.ip_buckets.read().await;
        buckets.get(&ip).map(|b| (b.count, b.is_banned()))
    }

    /// Get current stats for a partner
    pub async fn get_partner_stats(&self, partner_id: &str) -> Option<(u32, u64, bool)> {
        let buckets = self.partner_buckets.read().await;
        buckets
            .get(partner_id)
            .map(|b| (b.count, b.bytes, b.is_banned()))
    }

    /// Clean up expired entries (call periodically)
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let expiry = self.config.window_duration * 2;

        {
            let mut buckets = self.ip_buckets.write().await;
            buckets.retain(|_, b| {
                b.window_start.elapsed() < expiry
                    && !b.banned_until.map(|u| now > u).unwrap_or(true)
            });
        }

        {
            let mut buckets = self.partner_buckets.write().await;
            buckets.retain(|_, b| {
                b.window_start.elapsed() < expiry
                    && !b.banned_until.map(|u| now > u).unwrap_or(true)
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    Allowed,
    Exceeded,
    Banned,
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_rate_limiting() {
        let config = RateLimitConfig {
            max_connections_per_ip: 3,
            window_duration: Duration::from_secs(60),
            ban_duration: Duration::from_millis(100),
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 3 should be allowed
        assert!(limiter.check_ip(ip).await.is_allowed());
        assert!(limiter.check_ip(ip).await.is_allowed());
        assert!(limiter.check_ip(ip).await.is_allowed());

        // 4th should be exceeded and banned
        assert_eq!(limiter.check_ip(ip).await, RateLimitResult::Exceeded);
        assert_eq!(limiter.check_ip(ip).await, RateLimitResult::Banned);

        // Wait for ban to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be allowed again (window not expired, but ban lifted)
        // Actually count is still at limit, so it will exceed again
        assert_eq!(limiter.check_ip(ip).await, RateLimitResult::Exceeded);
    }

    #[tokio::test]
    async fn test_partner_rate_limiting() {
        let config = RateLimitConfig {
            max_requests_per_partner: 5,
            window_duration: Duration::from_secs(60),
            ban_duration: Duration::from_millis(100),
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let partner = "test-partner";

        for _ in 0..5 {
            assert!(limiter.check_partner(partner).await.is_allowed());
        }

        assert_eq!(
            limiter.check_partner(partner).await,
            RateLimitResult::Exceeded
        );
    }

    #[tokio::test]
    async fn test_bandwidth_limiting() {
        let config = RateLimitConfig {
            max_bytes_per_partner: 1000,
            window_duration: Duration::from_secs(60),
            ban_duration: Duration::from_millis(100),
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let partner = "test-partner";

        assert!(limiter.record_bytes(partner, 500).await.is_allowed());
        assert!(limiter.record_bytes(partner, 400).await.is_allowed());
        assert_eq!(
            limiter.record_bytes(partner, 200).await,
            RateLimitResult::Exceeded
        );
    }
}
