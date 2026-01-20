//! Prometheus metrics for monitoring.
//! 
//! Some functions reserved for advanced monitoring.
#![allow(dead_code)]

use lazy_static::lazy_static;
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry,
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Connection metrics
    pub static ref CONNECTIONS_TOTAL: IntCounter = IntCounter::new(
        "rift_connections_total",
        "Total number of connections accepted"
    ).unwrap();

    pub static ref CONNECTIONS_ACTIVE: IntGauge = IntGauge::new(
        "rift_connections_active",
        "Number of currently active connections"
    ).unwrap();

    pub static ref CONNECTIONS_REJECTED: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_connections_rejected_total", "Connections rejected"),
        &["reason"]
    ).unwrap();

    // Transfer metrics
    pub static ref TRANSFERS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_transfers_total", "Total transfers"),
        &["direction", "status"]
    ).unwrap();

    pub static ref TRANSFERS_ACTIVE: IntGauge = IntGauge::new(
        "rift_transfers_active",
        "Number of currently active transfers"
    ).unwrap();

    pub static ref BYTES_TRANSFERRED: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_bytes_transferred_total", "Total bytes transferred"),
        &["direction"]
    ).unwrap();

    pub static ref BYTES_COMPRESSED_SAVED: IntCounter = IntCounter::new(
        "rift_bytes_compressed_saved_total",
        "Total bytes saved by compression"
    ).unwrap();

    // Chunk metrics
    pub static ref CHUNKS_SENT: IntCounter = IntCounter::new(
        "rift_chunks_sent_total",
        "Total chunks sent"
    ).unwrap();

    pub static ref CHUNKS_RECEIVED: IntCounter = IntCounter::new(
        "rift_chunks_received_total",
        "Total chunks received"
    ).unwrap();

    pub static ref CHUNKS_FAILED: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_chunks_failed_total", "Chunks that failed verification"),
        &["reason"]
    ).unwrap();

    // Latency metrics
    pub static ref TRANSFER_DURATION: HistogramVec = HistogramVec::new(
        HistogramOpts::new("rift_transfer_duration_seconds", "Transfer duration")
            .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]),
        &["direction"]
    ).unwrap();

    pub static ref CHUNK_LATENCY: Histogram = Histogram::with_opts(
        HistogramOpts::new("rift_chunk_latency_seconds", "Chunk transfer latency")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
    ).unwrap();

    // Rate limiting metrics
    pub static ref RATE_LIMITED_REQUESTS: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_rate_limited_total", "Requests rejected by rate limiting"),
        &["type"]
    ).unwrap();

    // Partner metrics
    pub static ref PARTNER_TRANSFERS: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_partner_transfers_total", "Transfers per partner"),
        &["partner_id", "direction"]
    ).unwrap();

    // Endpoint health metrics
    pub static ref ENDPOINT_HEALTH: IntGaugeVec = IntGaugeVec::new(
        Opts::new("rift_endpoint_health", "Endpoint health status (0=unhealthy, 1=degraded, 2=healthy)"),
        &["partner_id", "endpoint"]
    ).unwrap();

    // Error metrics
    pub static ref ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("rift_errors_total", "Total errors by type"),
        &["type"]
    ).unwrap();
}

/// Register all metrics with the registry
pub fn register_metrics() {
    REGISTRY.register(Box::new(CONNECTIONS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(CONNECTIONS_ACTIVE.clone())).ok();
    REGISTRY
        .register(Box::new(CONNECTIONS_REJECTED.clone()))
        .ok();
    REGISTRY.register(Box::new(TRANSFERS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(TRANSFERS_ACTIVE.clone())).ok();
    REGISTRY.register(Box::new(BYTES_TRANSFERRED.clone())).ok();
    REGISTRY
        .register(Box::new(BYTES_COMPRESSED_SAVED.clone()))
        .ok();
    REGISTRY.register(Box::new(CHUNKS_SENT.clone())).ok();
    REGISTRY.register(Box::new(CHUNKS_RECEIVED.clone())).ok();
    REGISTRY.register(Box::new(CHUNKS_FAILED.clone())).ok();
    REGISTRY.register(Box::new(TRANSFER_DURATION.clone())).ok();
    REGISTRY.register(Box::new(CHUNK_LATENCY.clone())).ok();
    REGISTRY
        .register(Box::new(RATE_LIMITED_REQUESTS.clone()))
        .ok();
    REGISTRY.register(Box::new(PARTNER_TRANSFERS.clone())).ok();
    REGISTRY.register(Box::new(ENDPOINT_HEALTH.clone())).ok();
    REGISTRY.register(Box::new(ERRORS_TOTAL.clone())).ok();
}

/// Get metrics as Prometheus text format
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Helper to record transfer completion
pub fn record_transfer_complete(direction: &str, success: bool, bytes: u64, duration_secs: f64) {
    let status = if success { "success" } else { "failed" };
    TRANSFERS_TOTAL
        .with_label_values(&[direction, status])
        .inc();
    BYTES_TRANSFERRED
        .with_label_values(&[direction])
        .inc_by(bytes);
    TRANSFER_DURATION
        .with_label_values(&[direction])
        .observe(duration_secs);
}

/// Helper to record connection
pub fn record_connection_accepted() {
    CONNECTIONS_TOTAL.inc();
    CONNECTIONS_ACTIVE.inc();
}

pub fn record_connection_closed() {
    CONNECTIONS_ACTIVE.dec();
}

pub fn record_connection_rejected(reason: &str) {
    CONNECTIONS_REJECTED.with_label_values(&[reason]).inc();
}

/// Helper to record rate limiting
pub fn record_rate_limited(limit_type: &str) {
    RATE_LIMITED_REQUESTS.with_label_values(&[limit_type]).inc();
}

/// Helper to record chunk operations
pub fn record_chunk_sent(latency_secs: f64) {
    CHUNKS_SENT.inc();
    CHUNK_LATENCY.observe(latency_secs);
}

pub fn record_chunk_received() {
    CHUNKS_RECEIVED.inc();
}

pub fn record_chunk_failed(reason: &str) {
    CHUNKS_FAILED.with_label_values(&[reason]).inc();
}

/// Helper to record compression savings
pub fn record_compression_saved(bytes: u64) {
    BYTES_COMPRESSED_SAVED.inc_by(bytes);
}

/// Helper to record errors
pub fn record_error(error_type: &str) {
    ERRORS_TOTAL.with_label_values(&[error_type]).inc();
}

/// Helper to update endpoint health
pub fn update_endpoint_health(partner_id: &str, endpoint: &str, health: i64) {
    ENDPOINT_HEALTH
        .with_label_values(&[partner_id, endpoint])
        .set(health);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_metrics() {
        register_metrics();
        // Should not panic on re-registration
        register_metrics();
    }

    #[test]
    fn test_record_transfer() {
        register_metrics();
        record_transfer_complete("send", true, 1024, 1.5);

        let metrics = gather_metrics();
        assert!(metrics.contains("rift_transfers_total"));
        assert!(metrics.contains("rift_bytes_transferred_total"));
    }

    #[test]
    fn test_connection_metrics() {
        register_metrics();

        record_connection_accepted();
        record_connection_accepted();
        record_connection_closed();

        let metrics = gather_metrics();
        assert!(metrics.contains("rift_connections_total"));
        assert!(metrics.contains("rift_connections_active"));
    }
}
