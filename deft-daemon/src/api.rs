use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};

use crate::config::Config;
use crate::metrics;

/// API Server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub listen: String,
    pub api_key: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:7742".to_string(),
            api_key: None,
        }
    }
}

/// Transfer status for API
#[derive(Debug, Clone, Serialize)]
pub struct TransferStatus {
    pub id: String,
    pub virtual_file: String,
    pub partner_id: String,
    pub direction: String,
    pub status: String,
    pub progress_percent: u8,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub started_at: String,
    pub updated_at: String,
}

/// Partner status for API
#[derive(Debug, Clone, Serialize)]
pub struct PartnerStatus {
    pub id: String,
    pub endpoints: Vec<String>,
    pub connected: bool,
    pub last_seen: Option<String>,
    pub transfers_today: u64,
    pub bytes_today: u64,
}

/// System status for API
#[derive(Debug, Clone, Serialize)]
pub struct SystemStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub active_connections: u64,
    pub active_transfers: u64,
    pub total_transfers: u64,
    pub total_bytes: u64,
    pub metrics_enabled: bool,
}

/// API state shared across requests
pub struct ApiState {
    pub config: Config,
    pub start_time: std::time::Instant,
    pub transfers: RwLock<HashMap<String, TransferStatus>>,
}

impl ApiState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            start_time: std::time::Instant::now(),
            transfers: RwLock::new(HashMap::new()),
        }
    }
}

/// Run the API server
pub async fn run_api_server(addr: &str, state: Arc<ApiState>, api_key: Option<String>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind API server to {}: {}", addr, e);
            return;
        }
    };

    info!("API server listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = Arc::clone(&state);
                let key = api_key.clone();
                tokio::spawn(async move {
                    handle_request(stream, peer, state, key).await;
                });
            }
            Err(e) => {
                warn!("API accept error: {}", e);
            }
        }
    }
}

async fn handle_request(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ApiState>,
    api_key: Option<String>,
) {
    let mut buf = vec![0u8; 8192];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let lines: Vec<&str> = request.lines().collect();
    
    if lines.is_empty() {
        return;
    }

    // Parse request line
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let path = parts[1];

    debug!("API {} {} from {}", method, path, peer);

    // Check API key if configured
    if let Some(ref key) = api_key {
        let auth_header = lines.iter()
            .find(|l| l.to_lowercase().starts_with("authorization:"))
            .map(|l| l.split(':').nth(1).unwrap_or("").trim());
        
        let valid = auth_header
            .map(|h| h.strip_prefix("Bearer ").unwrap_or(h) == key)
            .unwrap_or(false);
        
        if !valid {
            send_response(&mut stream, 401, "Unauthorized", r#"{"error":"Invalid API key"}"#).await;
            return;
        }
    }

    // Route request
    let (status, body) = match (method, path) {
        ("GET", "/api/status") => handle_status(&state).await,
        ("GET", "/api/partners") => handle_partners(&state).await,
        ("GET", "/api/transfers") => handle_transfers(&state).await,
        ("GET", "/api/metrics") => handle_metrics().await,
        ("GET", "/api/config") => handle_config(&state).await,
        ("GET", "/") | ("GET", "/index.html") => {
            send_html(&mut stream).await;
            return;
        }
        ("GET", path) if path.starts_with("/static/") => {
            send_static(&mut stream, path).await;
            return;
        }
        ("OPTIONS", _) => (200, "{}".to_string()),
        _ => (404, r#"{"error":"Not found"}"#.to_string()),
    };

    send_response(&mut stream, status, "OK", &body).await;
}

async fn send_response(stream: &mut TcpStream, status: u16, status_text: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: Authorization, Content-Type\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status, status_text, body.len(), body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn send_html(stream: &mut TcpStream) {
    let html = include_str!("../static/index.html");
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        html.len(), html
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn send_static(stream: &mut TcpStream, path: &str) {
    let (content, content_type) = match path {
        "/static/app.js" => (include_str!("../static/app.js"), "application/javascript"),
        "/static/style.css" => (include_str!("../static/style.css"), "text/css"),
        _ => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            return;
        }
    };
    
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        content_type, content.len(), content
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn handle_status(state: &ApiState) -> (u16, String) {
    let status = SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        active_connections: 0, // TODO: track from metrics
        active_transfers: state.transfers.read().await.len() as u64,
        total_transfers: 0,
        total_bytes: 0,
        metrics_enabled: state.config.limits.metrics_enabled,
    };
    
    (200, serde_json::to_string(&status).unwrap_or_default())
}

async fn handle_partners(state: &ApiState) -> (u16, String) {
    let partners: Vec<PartnerStatus> = state.config.partners.iter().map(|p| {
        PartnerStatus {
            id: p.id.clone(),
            endpoints: p.endpoints.clone(),
            connected: false,
            last_seen: None,
            transfers_today: 0,
            bytes_today: 0,
        }
    }).collect();
    
    (200, serde_json::to_string(&partners).unwrap_or_default())
}

async fn handle_transfers(state: &ApiState) -> (u16, String) {
    let transfers: Vec<TransferStatus> = state.transfers.read().await
        .values()
        .cloned()
        .collect();
    
    (200, serde_json::to_string(&transfers).unwrap_or_default())
}

async fn handle_metrics() -> (u16, String) {
    let output = metrics::gather_metrics();
    (200, serde_json::json!({ "metrics": output }).to_string())
}

async fn handle_config(state: &ApiState) -> (u16, String) {
    let config_summary = serde_json::json!({
        "server": {
            "enabled": state.config.server.enabled,
            "listen": state.config.server.listen,
        },
        "client": {
            "enabled": state.config.client.enabled,
        },
        "storage": {
            "chunk_size": state.config.storage.chunk_size,
        },
        "limits": {
            "max_connections_per_ip": state.config.limits.max_connections_per_ip,
            "max_requests_per_partner": state.config.limits.max_requests_per_partner,
            "parallel_chunks": state.config.limits.parallel_chunks,
            "metrics_enabled": state.config.limits.metrics_enabled,
        },
        "partners_count": state.config.partners.len(),
    });
    
    (200, config_summary.to_string())
}
