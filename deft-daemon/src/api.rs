use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::{Config, Direction, VirtualFileConfig};
use crate::metrics;

/// API Server configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

/// Virtual file info for API
#[derive(Debug, Clone, Serialize)]
pub struct VirtualFileInfo {
    pub name: String,
    pub path: String,
    pub direction: String,
    pub partner_id: String,
}

/// Transfer history entry
#[derive(Debug, Clone, Serialize)]
pub struct TransferHistoryEntry {
    pub id: String,
    pub virtual_file: String,
    pub partner_id: String,
    pub direction: String,
    pub status: String,
    pub total_bytes: u64,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// Request to create a transfer
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTransferRequest {
    pub partner_id: String,
    pub virtual_file: String,
    pub source_path: Option<String>,
}

/// Request to create a virtual file
#[derive(Debug, Clone, Deserialize)]
pub struct CreateVirtualFileRequest {
    pub name: String,
    pub path: String,
    pub direction: String,
    pub partner_id: String,
}

/// API state shared across requests
pub struct ApiState {
    pub config: RwLock<Config>,
    pub start_time: std::time::Instant,
    pub transfers: RwLock<HashMap<String, TransferStatus>>,
    pub history: RwLock<Vec<TransferHistoryEntry>>,
}

impl ApiState {
    pub fn new(config: Config) -> Self {
        Self {
            config: RwLock::new(config),
            start_time: std::time::Instant::now(),
            transfers: RwLock::new(HashMap::new()),
            history: RwLock::new(Vec::new()),
        }
    }

    pub async fn register_transfer(
        &self,
        id: String,
        virtual_file: String,
        partner_id: String,
        direction: String,
        total_bytes: u64,
    ) {
        let status = TransferStatus {
            id: id.clone(),
            virtual_file,
            partner_id,
            direction,
            status: "active".to_string(),
            progress_percent: 0,
            bytes_transferred: 0,
            total_bytes,
            started_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        self.transfers.write().await.insert(id, status);
    }

    pub async fn update_transfer_progress(&self, id: &str, bytes: u64, total: u64) {
        if let Some(t) = self.transfers.write().await.get_mut(id) {
            t.bytes_transferred = bytes;
            t.progress_percent = if total > 0 {
                ((bytes * 100) / total) as u8
            } else {
                0
            };
            t.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub async fn complete_transfer(&self, id: &str) {
        let mut transfers = self.transfers.write().await;
        if let Some(t) = transfers.get_mut(id) {
            t.status = "complete".to_string();
            t.progress_percent = 100;
            t.updated_at = chrono::Utc::now().to_rfc3339();

            // Add to history
            let entry = TransferHistoryEntry {
                id: t.id.clone(),
                virtual_file: t.virtual_file.clone(),
                partner_id: t.partner_id.clone(),
                direction: t.direction.clone(),
                status: "complete".to_string(),
                total_bytes: t.total_bytes,
                started_at: t.started_at.clone(),
                completed_at: Some(t.updated_at.clone()),
            };
            self.history.write().await.push(entry);
        }
    }

    pub async fn remove_transfer(&self, id: &str) {
        self.transfers.write().await.remove(id);
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
        let auth_header = lines
            .iter()
            .find(|l| l.to_lowercase().starts_with("authorization:"))
            .map(|l| l.split(':').nth(1).unwrap_or("").trim());

        let valid = auth_header
            .map(|h| h.strip_prefix("Bearer ").unwrap_or(h) == key)
            .unwrap_or(false);

        if !valid {
            send_response(
                &mut stream,
                401,
                "Unauthorized",
                r#"{"error":"Invalid API key"}"#,
            )
            .await;
            return;
        }
    }

    // Extract request body for POST/PUT
    let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
    let request_body = if body_start < n {
        &buf[body_start..n]
    } else {
        &[]
    };

    // Route request
    let (status, body) = match (method, path) {
        // System endpoints
        ("GET", "/api/status") => handle_status(&state).await,
        ("GET", "/api/config") => handle_config(&state).await,
        ("GET", "/api/metrics") => handle_metrics().await,

        // Partner endpoints
        ("GET", "/api/partners") => handle_partners(&state).await,
        ("GET", p) if p.starts_with("/api/partners/") && p.ends_with("/virtual-files") => {
            let partner_id = p
                .strip_prefix("/api/partners/")
                .and_then(|s| s.strip_suffix("/virtual-files"))
                .unwrap_or("");
            handle_partner_virtual_files(&state, partner_id).await
        }
        ("POST", p) if p.starts_with("/api/partners/") && p.ends_with("/virtual-files") => {
            let partner_id = p
                .strip_prefix("/api/partners/")
                .and_then(|s| s.strip_suffix("/virtual-files"))
                .unwrap_or("");
            handle_add_partner_virtual_file(&state, partner_id, request_body).await
        }

        // Transfer endpoints
        ("GET", "/api/transfers") => handle_transfers(&state).await,
        ("GET", "/api/history") => handle_history(&state).await,
        ("POST", "/api/transfers") => handle_create_transfer(&state, request_body).await,
        ("GET", p) if p.starts_with("/api/transfers/") && !p.contains("/retry") => {
            let id = p.strip_prefix("/api/transfers/").unwrap_or("");
            handle_get_transfer(&state, id).await
        }
        ("DELETE", p) if p.starts_with("/api/transfers/") => {
            let id = p.strip_prefix("/api/transfers/").unwrap_or("");
            handle_cancel_transfer(&state, id).await
        }
        ("POST", p) if p.ends_with("/retry") => {
            let id = p
                .strip_prefix("/api/transfers/")
                .and_then(|s| s.strip_suffix("/retry"))
                .unwrap_or("");
            handle_retry_transfer(&state, id).await
        }

        // Virtual file endpoints
        ("GET", "/api/virtual-files") => handle_virtual_files(&state).await,
        ("POST", "/api/virtual-files") => handle_create_virtual_file(&state, request_body).await,
        ("GET", p) if p.starts_with("/api/virtual-files/") => {
            let name = p.strip_prefix("/api/virtual-files/").unwrap_or("");
            handle_get_virtual_file(&state, name).await
        }
        ("PUT", p) if p.starts_with("/api/virtual-files/") => {
            let name = p.strip_prefix("/api/virtual-files/").unwrap_or("");
            handle_update_virtual_file(&state, name, request_body).await
        }
        ("DELETE", p) if p.starts_with("/api/virtual-files/") => {
            let name = p.strip_prefix("/api/virtual-files/").unwrap_or("");
            handle_delete_virtual_file(&state, name).await
        }

        // Static files
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
        status,
        status_text,
        body.len(),
        body
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
        html.len(),
        html
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
        content_type,
        content.len(),
        content
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn handle_status(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let status = SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        active_connections: 0,
        active_transfers: state.transfers.read().await.len() as u64,
        total_transfers: state.history.read().await.len() as u64,
        total_bytes: 0,
        metrics_enabled: config.limits.metrics_enabled,
    };
    (200, serde_json::to_string(&status).unwrap_or_default())
}

async fn handle_partners(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let partners: Vec<PartnerStatus> = config
        .partners
        .iter()
        .map(|p| PartnerStatus {
            id: p.id.clone(),
            endpoints: p.endpoints.clone(),
            connected: false,
            last_seen: None,
            transfers_today: 0,
            bytes_today: 0,
        })
        .collect();
    (200, serde_json::to_string(&partners).unwrap_or_default())
}

async fn handle_transfers(state: &ApiState) -> (u16, String) {
    let transfers: Vec<TransferStatus> = state.transfers.read().await.values().cloned().collect();
    (200, serde_json::to_string(&transfers).unwrap_or_default())
}

async fn handle_get_transfer(state: &ApiState, id: &str) -> (u16, String) {
    if let Some(t) = state.transfers.read().await.get(id) {
        (200, serde_json::to_string(t).unwrap_or_default())
    } else {
        (404, r#"{"error":"Transfer not found"}"#.to_string())
    }
}

async fn handle_create_transfer(state: &ApiState, body: &[u8]) -> (u16, String) {
    let req: Result<CreateTransferRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Validate partner exists
            let config = state.config.read().await;
            let partner = config.partners.iter().find(|p| p.id == r.partner_id);
            if partner.is_none() {
                return (404, r#"{"error":"Partner not found"}"#.to_string());
            }

            // Validate virtual file exists for this partner
            let partner = partner.unwrap();
            let vf = partner.virtual_files.iter().find(|v| v.name == r.virtual_file);
            if vf.is_none() {
                return (404, r#"{"error":"Virtual file not found for this partner"}"#.to_string());
            }

            // Generate transfer ID
            let transfer_id = format!("api-{}", chrono::Utc::now().timestamp_millis());

            // Register transfer in state
            let vf = vf.unwrap();
            let source = r.source_path.unwrap_or_else(|| vf.path.clone());
            let direction = format!("{:?}", vf.direction).to_lowercase();
            drop(config); // Release lock before async call
            
            state.register_transfer(
                transfer_id.clone(),
                r.virtual_file.clone(),
                r.partner_id.clone(),
                direction,
                0, // Size will be updated when transfer actually starts
            ).await;

            let response = serde_json::json!({
                "status": "queued",
                "transfer_id": transfer_id,
                "partner_id": r.partner_id,
                "virtual_file": r.virtual_file,
                "source_path": source
            });
            (202, response.to_string())
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_cancel_transfer(state: &ApiState, id: &str) -> (u16, String) {
    let mut transfers = state.transfers.write().await;
    if transfers.remove(id).is_some() {
        (200, r#"{"status":"cancelled"}"#.to_string())
    } else {
        (404, r#"{"error":"Transfer not found"}"#.to_string())
    }
}

async fn handle_retry_transfer(state: &ApiState, id: &str) -> (u16, String) {
    if state.history.read().await.iter().any(|t| t.id == id) {
        // TODO: Actually retry the transfer
        (202, r#"{"status":"retry_queued"}"#.to_string())
    } else {
        (
            404,
            r#"{"error":"Transfer not found in history"}"#.to_string(),
        )
    }
}

async fn handle_history(state: &ApiState) -> (u16, String) {
    let history = state.history.read().await.clone();
    (200, serde_json::to_string(&history).unwrap_or_default())
}

async fn handle_metrics() -> (u16, String) {
    let output = metrics::gather_metrics();
    (200, serde_json::json!({ "metrics": output }).to_string())
}

async fn handle_config(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let config_summary = serde_json::json!({
        "server": {
            "enabled": config.server.enabled,
            "listen": config.server.listen,
        },
        "client": {
            "enabled": config.client.enabled,
        },
        "storage": {
            "chunk_size": config.storage.chunk_size,
        },
        "limits": {
            "max_connections_per_ip": config.limits.max_connections_per_ip,
            "max_requests_per_partner": config.limits.max_requests_per_partner,
            "parallel_chunks": config.limits.parallel_chunks,
            "metrics_enabled": config.limits.metrics_enabled,
        },
        "partners_count": config.partners.len(),
    });
    (200, config_summary.to_string())
}

// Virtual file handlers
async fn handle_virtual_files(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let mut vfs: Vec<VirtualFileInfo> = Vec::new();
    for partner in &config.partners {
        for vf in &partner.virtual_files {
            vfs.push(VirtualFileInfo {
                name: vf.name.clone(),
                path: vf.path.clone(),
                direction: format!("{:?}", vf.direction).to_lowercase(),
                partner_id: partner.id.clone(),
            });
        }
    }
    (200, serde_json::to_string(&vfs).unwrap_or_default())
}

async fn handle_get_virtual_file(state: &ApiState, name: &str) -> (u16, String) {
    let config = state.config.read().await;
    for partner in &config.partners {
        for vf in &partner.virtual_files {
            if vf.name == name {
                let info = VirtualFileInfo {
                    name: vf.name.clone(),
                    path: vf.path.clone(),
                    direction: format!("{:?}", vf.direction).to_lowercase(),
                    partner_id: partner.id.clone(),
                };
                return (200, serde_json::to_string(&info).unwrap_or_default());
            }
        }
    }
    (404, r#"{"error":"Virtual file not found"}"#.to_string())
}

async fn handle_create_virtual_file(state: &ApiState, body: &[u8]) -> (u16, String) {
    let req: Result<CreateVirtualFileRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let direction = match r.direction.as_str() {
                "send" => Direction::Send,
                "receive" => Direction::Receive,
                _ => {
                    return (
                        400,
                        r#"{"error":"Invalid direction, use 'send' or 'receive'"}"#.to_string(),
                    )
                }
            };
            let vf = VirtualFileConfig {
                name: r.name.clone(),
                path: r.path,
                direction,
            };
            let mut config = state.config.write().await;
            if let Some(partner) = config.partners.iter_mut().find(|p| p.id == r.partner_id) {
                partner.virtual_files.push(vf);
                (
                    201,
                    serde_json::json!({"status":"created", "name": r.name}).to_string(),
                )
            } else {
                (404, r#"{"error":"Partner not found"}"#.to_string())
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_update_virtual_file(state: &ApiState, name: &str, body: &[u8]) -> (u16, String) {
    let req: Result<CreateVirtualFileRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let direction = match r.direction.as_str() {
                "send" => Direction::Send,
                "receive" => Direction::Receive,
                _ => return (400, r#"{"error":"Invalid direction"}"#.to_string()),
            };
            let mut config = state.config.write().await;
            for partner in &mut config.partners {
                for vf in &mut partner.virtual_files {
                    if vf.name == name {
                        vf.path = r.path.clone();
                        vf.direction = direction;
                        return (200, r#"{"status":"updated"}"#.to_string());
                    }
                }
            }
            (404, r#"{"error":"Virtual file not found"}"#.to_string())
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_delete_virtual_file(state: &ApiState, name: &str) -> (u16, String) {
    let mut config = state.config.write().await;
    for partner in &mut config.partners {
        let before = partner.virtual_files.len();
        partner.virtual_files.retain(|vf| vf.name != name);
        if partner.virtual_files.len() < before {
            return (200, r#"{"status":"deleted"}"#.to_string());
        }
    }
    (404, r#"{"error":"Virtual file not found"}"#.to_string())
}

// Partner virtual file handlers
async fn handle_partner_virtual_files(state: &ApiState, partner_id: &str) -> (u16, String) {
    let config = state.config.read().await;
    if let Some(partner) = config.partners.iter().find(|p| p.id == partner_id) {
        let vfs: Vec<VirtualFileInfo> = partner
            .virtual_files
            .iter()
            .map(|vf| VirtualFileInfo {
                name: vf.name.clone(),
                path: vf.path.clone(),
                direction: format!("{:?}", vf.direction).to_lowercase(),
                partner_id: partner_id.to_string(),
            })
            .collect();
        (200, serde_json::to_string(&vfs).unwrap_or_default())
    } else {
        (404, r#"{"error":"Partner not found"}"#.to_string())
    }
}

async fn handle_add_partner_virtual_file(
    state: &ApiState,
    partner_id: &str,
    body: &[u8],
) -> (u16, String) {
    #[derive(Deserialize)]
    struct AddVfRequest {
        name: String,
        path: String,
        direction: String,
    }
    let req: Result<AddVfRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let direction = match r.direction.as_str() {
                "send" => Direction::Send,
                "receive" => Direction::Receive,
                _ => return (400, r#"{"error":"Invalid direction"}"#.to_string()),
            };
            let mut config = state.config.write().await;
            if let Some(partner) = config.partners.iter_mut().find(|p| p.id == partner_id) {
                partner.virtual_files.push(VirtualFileConfig {
                    name: r.name.clone(),
                    path: r.path,
                    direction,
                });
                (
                    201,
                    serde_json::json!({"status":"created", "name": r.name}).to_string(),
                )
            } else {
                (404, r#"{"error":"Partner not found"}"#.to_string())
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}
