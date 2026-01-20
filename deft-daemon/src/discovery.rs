use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Endpoint health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Endpoint state tracking
#[derive(Debug, Clone)]
pub struct EndpointState {
    pub endpoint: String,
    pub health: EndpointHealth,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub consecutive_failures: u32,
    pub total_successes: u64,
    pub total_failures: u64,
    pub avg_latency_ms: Option<u64>,
}

impl EndpointState {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            health: EndpointHealth::Healthy,
            last_success: None,
            last_failure: None,
            consecutive_failures: 0,
            total_successes: 0,
            total_failures: 0,
            avg_latency_ms: None,
        }
    }

    pub fn record_success(&mut self, latency_ms: u64) {
        self.last_success = Some(Instant::now());
        self.consecutive_failures = 0;
        self.total_successes += 1;
        self.health = EndpointHealth::Healthy;
        
        // Update average latency with exponential moving average
        self.avg_latency_ms = Some(match self.avg_latency_ms {
            Some(avg) => (avg * 7 + latency_ms) / 8,
            None => latency_ms,
        });
    }

    pub fn record_failure(&mut self) {
        self.last_failure = Some(Instant::now());
        self.consecutive_failures += 1;
        self.total_failures += 1;
        
        self.health = match self.consecutive_failures {
            0..=2 => EndpointHealth::Healthy,
            3..=5 => EndpointHealth::Degraded,
            _ => EndpointHealth::Unhealthy,
        };
    }

    pub fn is_available(&self) -> bool {
        match self.health {
            EndpointHealth::Healthy => true,
            EndpointHealth::Degraded => true,
            EndpointHealth::Unhealthy => {
                // Allow retry after cooldown period
                match self.last_failure {
                    Some(t) => t.elapsed() > Duration::from_secs(60),
                    None => true,
                }
            }
        }
    }

    pub fn score(&self) -> i64 {
        let mut score: i64 = 100;
        
        // Penalize by health
        score -= match self.health {
            EndpointHealth::Healthy => 0,
            EndpointHealth::Degraded => 30,
            EndpointHealth::Unhealthy => 80,
        };
        
        // Penalize by consecutive failures
        score -= (self.consecutive_failures as i64) * 10;
        
        // Bonus for recent success
        if let Some(t) = self.last_success {
            if t.elapsed() < Duration::from_secs(60) {
                score += 20;
            }
        }
        
        // Penalize high latency
        if let Some(avg) = self.avg_latency_ms {
            if avg > 1000 {
                score -= 20;
            } else if avg > 500 {
                score -= 10;
            }
        }
        
        score.max(0)
    }
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Maximum retries per endpoint
    pub max_retries: u32,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Failover strategy
    pub strategy: FailoverStrategy,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            connect_timeout: Duration::from_secs(10),
            health_check_interval: Duration::from_secs(30),
            strategy: FailoverStrategy::RoundRobin,
        }
    }
}

/// Failover strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverStrategy {
    /// Try endpoints in order
    Sequential,
    /// Rotate through endpoints
    RoundRobin,
    /// Select based on health score
    BestScore,
    /// Random selection from healthy endpoints
    Random,
}

/// Endpoint discovery and failover manager
pub struct EndpointDiscovery {
    config: DiscoveryConfig,
    /// Partner ID -> list of endpoint states
    endpoints: Arc<RwLock<HashMap<String, Vec<EndpointState>>>>,
    /// Round-robin index per partner
    rr_index: Arc<RwLock<HashMap<String, usize>>>,
}

impl EndpointDiscovery {
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            rr_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register endpoints for a partner
    pub async fn register_partner(&self, partner_id: &str, endpoints: Vec<String>) {
        let mut eps = self.endpoints.write().await;
        let states: Vec<EndpointState> = endpoints
            .into_iter()
            .map(EndpointState::new)
            .collect();
        eps.insert(partner_id.to_string(), states);
        info!("Registered {} endpoints for partner {}", eps.get(partner_id).map(|v| v.len()).unwrap_or(0), partner_id);
    }

    /// Get the next endpoint to try for a partner
    pub async fn get_endpoint(&self, partner_id: &str) -> Option<String> {
        let eps = self.endpoints.read().await;
        let states = eps.get(partner_id)?;
        
        if states.is_empty() {
            return None;
        }

        let available: Vec<&EndpointState> = states.iter()
            .filter(|s| s.is_available())
            .collect();

        if available.is_empty() {
            // All endpoints unhealthy, try the least bad one
            warn!("All endpoints for {} are unhealthy, selecting least bad", partner_id);
            return states.iter()
                .max_by_key(|s| s.score())
                .map(|s| s.endpoint.clone());
        }

        match self.config.strategy {
            FailoverStrategy::Sequential => {
                available.first().map(|s| s.endpoint.clone())
            }
            FailoverStrategy::RoundRobin => {
                let available_endpoints: Vec<String> = available.iter().map(|s| s.endpoint.clone()).collect();
                drop(eps);
                let mut rr = self.rr_index.write().await;
                let idx = rr.entry(partner_id.to_string()).or_insert(0);
                let ep = available_endpoints.get(*idx % available_endpoints.len()).cloned();
                *idx = (*idx + 1) % available_endpoints.len();
                ep
            }
            FailoverStrategy::BestScore => {
                available.iter()
                    .max_by_key(|s| s.score())
                    .map(|s| s.endpoint.clone())
            }
            FailoverStrategy::Random => {
                use rand::Rng;
                let idx = rand::thread_rng().gen_range(0..available.len());
                available.get(idx).map(|s| s.endpoint.clone())
            }
        }
    }

    /// Get all endpoints for a partner in priority order
    pub async fn get_all_endpoints(&self, partner_id: &str) -> Vec<String> {
        let eps = self.endpoints.read().await;
        match eps.get(partner_id) {
            Some(states) => {
                let mut sorted: Vec<&EndpointState> = states.iter().collect();
                sorted.sort_by(|a, b| b.score().cmp(&a.score()));
                sorted.iter().map(|s| s.endpoint.clone()).collect()
            }
            None => Vec::new(),
        }
    }

    /// Record a successful connection
    pub async fn record_success(&self, partner_id: &str, endpoint: &str, latency_ms: u64) {
        let mut eps = self.endpoints.write().await;
        if let Some(states) = eps.get_mut(partner_id) {
            if let Some(state) = states.iter_mut().find(|s| s.endpoint == endpoint) {
                state.record_success(latency_ms);
                debug!("Endpoint {} healthy (latency: {}ms)", endpoint, latency_ms);
            }
        }
    }

    /// Record a failed connection
    pub async fn record_failure(&self, partner_id: &str, endpoint: &str) {
        let mut eps = self.endpoints.write().await;
        if let Some(states) = eps.get_mut(partner_id) {
            if let Some(state) = states.iter_mut().find(|s| s.endpoint == endpoint) {
                state.record_failure();
                warn!("Endpoint {} failed (consecutive: {})", endpoint, state.consecutive_failures);
            }
        }
    }

    /// Get health status for all endpoints of a partner
    pub async fn get_health(&self, partner_id: &str) -> Vec<(String, EndpointHealth, i64)> {
        let eps = self.endpoints.read().await;
        match eps.get(partner_id) {
            Some(states) => states.iter()
                .map(|s| (s.endpoint.clone(), s.health, s.score()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Try to connect to a partner with automatic failover
    pub async fn connect_with_failover<F, T, E>(
        &self,
        partner_id: &str,
        connect_fn: F,
    ) -> Result<(T, String), Vec<(String, E)>>
    where
        F: Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
        E: std::fmt::Debug,
    {
        let endpoints = self.get_all_endpoints(partner_id).await;
        if endpoints.is_empty() {
            return Err(Vec::new());
        }

        let mut errors = Vec::new();

        for endpoint in endpoints {
            let start = Instant::now();
            
            match connect_fn(endpoint.clone()).await {
                Ok(conn) => {
                    let latency = start.elapsed().as_millis() as u64;
                    self.record_success(partner_id, &endpoint, latency).await;
                    info!("Connected to {} via {} ({}ms)", partner_id, endpoint, latency);
                    return Ok((conn, endpoint));
                }
                Err(e) => {
                    self.record_failure(partner_id, &endpoint).await;
                    warn!("Failed to connect to {} via {}: {:?}", partner_id, endpoint, e);
                    errors.push((endpoint, e));
                }
            }
        }

        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_state() {
        let mut state = EndpointState::new("localhost:7741".into());
        
        assert_eq!(state.health, EndpointHealth::Healthy);
        assert!(state.is_available());
        
        // Record success
        state.record_success(100);
        assert_eq!(state.health, EndpointHealth::Healthy);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.avg_latency_ms, Some(100));
        
        // Record failures
        state.record_failure();
        state.record_failure();
        state.record_failure();
        assert_eq!(state.health, EndpointHealth::Degraded);
        assert_eq!(state.consecutive_failures, 3);
        
        // More failures
        state.record_failure();
        state.record_failure();
        state.record_failure();
        assert_eq!(state.health, EndpointHealth::Unhealthy);
    }

    #[test]
    fn test_endpoint_score() {
        let mut healthy = EndpointState::new("a".into());
        healthy.record_success(50);
        
        let mut degraded = EndpointState::new("b".into());
        degraded.record_failure();
        degraded.record_failure();
        degraded.record_failure();
        
        assert!(healthy.score() > degraded.score());
    }

    #[tokio::test]
    async fn test_discovery_register() {
        let disc = EndpointDiscovery::new(DiscoveryConfig::default());
        
        disc.register_partner("partner1", vec![
            "host1:7741".into(),
            "host2:7741".into(),
        ]).await;
        
        let endpoints = disc.get_all_endpoints("partner1").await;
        assert_eq!(endpoints.len(), 2);
    }

    #[tokio::test]
    async fn test_discovery_round_robin() {
        let disc = EndpointDiscovery::new(DiscoveryConfig {
            strategy: FailoverStrategy::RoundRobin,
            ..Default::default()
        });
        
        disc.register_partner("partner1", vec![
            "host1:7741".into(),
            "host2:7741".into(),
            "host3:7741".into(),
        ]).await;
        
        let e1 = disc.get_endpoint("partner1").await;
        let e2 = disc.get_endpoint("partner1").await;
        let e3 = disc.get_endpoint("partner1").await;
        let e4 = disc.get_endpoint("partner1").await;
        
        // Should cycle through
        assert_eq!(e1, e4);
    }

    #[tokio::test]
    async fn test_discovery_failover() {
        let disc = EndpointDiscovery::new(DiscoveryConfig {
            strategy: FailoverStrategy::BestScore,
            ..Default::default()
        });
        
        disc.register_partner("partner1", vec![
            "host1:7741".into(),
            "host2:7741".into(),
        ]).await;
        
        // Mark first as failing
        for _ in 0..6 {
            disc.record_failure("partner1", "host1:7741").await;
        }
        
        // Should prefer host2 now
        disc.record_success("partner1", "host2:7741", 50).await;
        
        let best = disc.get_endpoint("partner1").await;
        assert_eq!(best, Some("host2:7741".into()));
    }
}
