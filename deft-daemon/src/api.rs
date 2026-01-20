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
    pub virtual_files: Vec<String>,
    pub allowed_certs: Vec<String>,
    pub connected: bool,
    pub last_seen: Option<String>,
    pub transfers_today: u64,
    pub bytes_today: u64,
}

/// Request to create/update a partner
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PartnerRequest {
    pub id: String,
    pub endpoints: Vec<String>,
    pub allowed_certs: Option<Vec<String>>,
    pub virtual_files: Option<Vec<String>>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Client connection parameters (stored after connect)
#[derive(Debug, Clone, Default)]
pub struct ClientConnection {
    pub server: String,
    pub partner_id: String,
    pub cert: String,
    pub key: String,
    pub ca: String,
}

/// API state shared across requests
pub struct ApiState {
    pub config: RwLock<Config>,
    pub start_time: std::time::Instant,
    pub transfers: RwLock<HashMap<String, TransferStatus>>,
    pub history: RwLock<Vec<TransferHistoryEntry>>,
    history_path: std::path::PathBuf,
    pub client_connection: RwLock<Option<ClientConnection>>,
}

impl ApiState {
    pub fn new(config: Config) -> Self {
        let history_path = std::path::PathBuf::from(&config.storage.temp_dir).join("history.json");
        let history = Self::load_history(&history_path).unwrap_or_default();

        Self {
            config: RwLock::new(config),
            start_time: std::time::Instant::now(),
            transfers: RwLock::new(HashMap::new()),
            history: RwLock::new(history),
            history_path,
            client_connection: RwLock::new(None),
        }
    }

    fn load_history(path: &std::path::Path) -> Option<Vec<TransferHistoryEntry>> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    async fn save_history(&self) {
        let history = self.history.read().await;
        if let Ok(json) = serde_json::to_string_pretty(&*history) {
            if let Some(parent) = self.history_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&self.history_path, json);
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
            drop(transfers); // Release lock before acquiring another
            self.history.write().await.push(entry);
            self.save_history().await;
        }
    }

    pub async fn fail_transfer(&self, id: &str, error: &str) {
        let mut transfers = self.transfers.write().await;
        if let Some(t) = transfers.get_mut(id) {
            t.status = "failed".to_string();
            t.updated_at = chrono::Utc::now().to_rfc3339();

            let entry = TransferHistoryEntry {
                id: t.id.clone(),
                virtual_file: t.virtual_file.clone(),
                partner_id: t.partner_id.clone(),
                direction: t.direction.clone(),
                status: format!("failed: {}", error),
                total_bytes: t.total_bytes,
                started_at: t.started_at.clone(),
                completed_at: Some(t.updated_at.clone()),
            };
            drop(transfers);
            self.history.write().await.push(entry);
            self.save_history().await;
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
        ("POST", "/api/partners") => handle_create_partner(&state, request_body).await,
        ("PUT", p) if p.starts_with("/api/partners/") && !p.contains("/virtual-files") => {
            let partner_id = p.strip_prefix("/api/partners/").unwrap_or("");
            handle_update_partner(&state, partner_id, request_body).await
        }
        ("DELETE", p) if p.starts_with("/api/partners/") && !p.contains("/virtual-files") => {
            let partner_id = p.strip_prefix("/api/partners/").unwrap_or("");
            handle_delete_partner(&state, partner_id).await
        }
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

        // Config endpoints
        ("POST", "/api/config/reload") => handle_config_reload(&state).await,

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

        // Client endpoints (outgoing connections)
        ("POST", "/api/client/connect") => handle_client_connect(&state, request_body).await,
        ("POST", "/api/client/pull") => handle_client_pull(&state, request_body).await,
        ("POST", "/api/client/push") => handle_client_push(&state, request_body).await,

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
            virtual_files: p.virtual_files.iter().map(|vf| vf.name.clone()).collect(),
            allowed_certs: p.allowed_certs.clone(),
            connected: false,
            last_seen: None,
            transfers_today: 0,
            bytes_today: 0,
        })
        .collect();
    (200, serde_json::to_string(&partners).unwrap_or_default())
}

async fn handle_create_partner(state: &ApiState, body: &[u8]) -> (u16, String) {
    let req: Result<PartnerRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let mut config = state.config.write().await;
            if config.partners.iter().any(|p| p.id == r.id) {
                return (409, r#"{"error":"Partner already exists"}"#.to_string());
            }
            let partner = crate::config::PartnerConfig {
                id: r.id.clone(),
                endpoints: r.endpoints,
                allowed_certs: r.allowed_certs.unwrap_or_default(),
                virtual_files: Vec::new(),
            };
            config.partners.push(partner);
            (
                201,
                serde_json::json!({"status":"created", "id": r.id}).to_string(),
            )
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_update_partner(state: &ApiState, partner_id: &str, body: &[u8]) -> (u16, String) {
    let req: Result<PartnerRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let mut config = state.config.write().await;
            if let Some(partner) = config.partners.iter_mut().find(|p| p.id == partner_id) {
                partner.endpoints = r.endpoints;
                if let Some(certs) = r.allowed_certs {
                    partner.allowed_certs = certs;
                }
                (200, r#"{"status":"updated"}"#.to_string())
            } else {
                (404, r#"{"error":"Partner not found"}"#.to_string())
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_delete_partner(state: &ApiState, partner_id: &str) -> (u16, String) {
    let mut config = state.config.write().await;
    let before = config.partners.len();
    config.partners.retain(|p| p.id != partner_id);
    if config.partners.len() < before {
        (200, r#"{"status":"deleted"}"#.to_string())
    } else {
        (404, r#"{"error":"Partner not found"}"#.to_string())
    }
}

async fn handle_config_reload(_state: &ApiState) -> (u16, String) {
    // Signal that config should be reloaded via SIGHUP
    #[cfg(unix)]
    {
        use std::process::Command;
        let pid = std::process::id();
        let result = Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
        match result {
            Ok(_) => (200, r#"{"status":"reload_triggered"}"#.to_string()),
            Err(e) => (
                500,
                format!(r#"{{"error":"Failed to send signal: {}"}}"#, e),
            ),
        }
    }
    #[cfg(not(unix))]
    {
        (
            501,
            r#"{"error":"Config reload not supported on this platform"}"#.to_string(),
        )
    }
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
            let vf = partner
                .virtual_files
                .iter()
                .find(|v| v.name == r.virtual_file);
            if vf.is_none() {
                return (
                    404,
                    r#"{"error":"Virtual file not found for this partner"}"#.to_string(),
                );
            }

            // Generate transfer ID
            let transfer_id = format!("api-{}", chrono::Utc::now().timestamp_millis());

            // Register transfer in state
            let vf = vf.unwrap();
            let source = r.source_path.unwrap_or_else(|| vf.path.clone());
            let direction = format!("{:?}", vf.direction).to_lowercase();
            drop(config); // Release lock before async call

            state
                .register_transfer(
                    transfer_id.clone(),
                    r.virtual_file.clone(),
                    r.partner_id.clone(),
                    direction,
                    0, // Size will be updated when transfer actually starts
                )
                .await;

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

// ============ Client handlers (outgoing connections) ============

#[derive(Debug, Deserialize)]
struct ClientConnectRequest {
    server: String,
    partner_id: String,
    cert: Option<String>,
    key: Option<String>,
}

async fn handle_client_connect(state: &ApiState, body: &[u8]) -> (u16, String) {
    let req: Result<ClientConnectRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Get client config from state
            let config = state.config.read().await;
            let client_config = &config.client;

            // Use provided certs or fall back to config
            let cert_path = r.cert.as_deref().unwrap_or(&client_config.cert).to_string();
            let key_path = r.key.as_deref().unwrap_or(&client_config.key).to_string();
            let ca_path = client_config.ca.clone();
            drop(config); // Release read lock

            // Try to establish TLS connection
            match connect_to_server(&r.server, &cert_path, &key_path, &ca_path, &r.partner_id).await
            {
                Ok(virtual_files) => {
                    // Store connection parameters for subsequent pull/push
                    *state.client_connection.write().await = Some(ClientConnection {
                        server: r.server.clone(),
                        partner_id: r.partner_id.clone(),
                        cert: cert_path,
                        key: key_path,
                        ca: ca_path,
                    });

                    (
                        200,
                        serde_json::json!({
                            "success": true,
                            "server": r.server,
                            "partner_id": r.partner_id,
                            "virtual_files": virtual_files
                        })
                        .to_string(),
                    )
                }
                Err(e) => (
                    200,
                    serde_json::json!({
                        "success": false,
                        "error": format!("{}", e)
                    })
                    .to_string(),
                ),
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn connect_to_server(
    server: &str,
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
    partner_id: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::TlsConnector;

    // Load TLS config
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    let ca_pem = std::fs::read(ca_path)?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    let key =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.ok_or("No private key found")?;
    let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = TlsConnector::from(Arc::new(tls_config));

    // Connect
    let tcp = tokio::net::TcpStream::connect(server).await?;
    let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    let stream = connector.connect(domain, tcp).await?;

    // Split into read/write halves
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    // HELLO
    write_half
        .write_all(b"DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME\n")
        .await?;
    reader.read_line(&mut line).await?;

    if !line.contains("WELCOME") {
        return Err(format!("Unexpected response: {}", line).into());
    }

    // AUTH
    line.clear();
    let auth_cmd = format!("DEFT AUTH {}\n", partner_id);
    write_half.write_all(auth_cmd.as_bytes()).await?;
    reader.read_line(&mut line).await?;

    if !line.contains("AUTH_OK") {
        return Err(format!("Auth failed: {}", line).into());
    }

    // DISCOVER to get virtual files
    line.clear();
    write_half.write_all(b"DEFT DISCOVER\n").await?;
    reader.read_line(&mut line).await?;

    let mut virtual_files = Vec::new();

    // Parse: DEFT FILES <count>
    if line.starts_with("DEFT FILES ") {
        let count: usize = line
            .strip_prefix("DEFT FILES ")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // Read each file line: "  <name> <size> <direction> <modified>"
        for _ in 0..count {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let name = parts[0];
                let size: u64 = parts[1].parse().unwrap_or(0);
                let direction = parts[2].to_lowercase();
                virtual_files.push(serde_json::json!({
                    "name": name,
                    "size": size,
                    "direction": direction
                }));
            }
        }
    }

    // BYE
    let _ = write_half.write_all(b"DEFT BYE\n").await;

    Ok(virtual_files)
}

async fn handle_client_pull(state: &ApiState, body: &[u8]) -> (u16, String) {
    #[derive(Deserialize)]
    struct PullRequest {
        virtual_file: String,
        output_path: String,
    }
    let req: Result<PullRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Get stored connection
            let conn = state.client_connection.read().await;
            let Some(conn) = conn.as_ref() else {
                return (
                    400,
                    r#"{"success":false,"error":"Not connected. Use Connect first."}"#.to_string(),
                );
            };
            let conn = conn.clone();
            drop(conn);

            // Generate transfer ID and register
            let transfer_id = format!("pull_{}", chrono::Utc::now().timestamp_millis());
            let partner_id = {
                let conn = state.client_connection.read().await;
                conn.as_ref()
                    .map(|c| c.partner_id.clone())
                    .unwrap_or_default()
            };
            state
                .register_transfer(
                    transfer_id.clone(),
                    r.virtual_file.clone(),
                    partner_id,
                    "pull".to_string(),
                    0, // Size unknown until transfer starts
                )
                .await;

            // Perform pull
            match pull_file(state, &r.virtual_file, &r.output_path, &transfer_id).await {
                Ok(bytes) => {
                    state.complete_transfer(&transfer_id).await;
                    (
                        200,
                        serde_json::json!({
                            "success": true,
                            "virtual_file": r.virtual_file,
                            "output_path": r.output_path,
                            "bytes": bytes
                        })
                        .to_string(),
                    )
                }
                Err(e) => {
                    state.fail_transfer(&transfer_id, &e.to_string()).await;
                    (
                        200,
                        serde_json::json!({
                            "success": false,
                            "error": format!("{}", e)
                        })
                        .to_string(),
                    )
                }
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn pull_file(
    state: &ApiState,
    virtual_file: &str,
    output_path: &str,
    transfer_id: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::TlsConnector;

    // Clone connection data and release lock immediately
    let conn = {
        let guard = state.client_connection.read().await;
        guard.as_ref().ok_or("Not connected")?.clone()
    };

    // Load TLS config
    let cert_pem = std::fs::read(&conn.cert)?;
    let key_pem = std::fs::read(&conn.key)?;
    let ca_pem = std::fs::read(&conn.ca)?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    let key =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.ok_or("No private key found")?;
    let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = tokio::net::TcpStream::connect(&conn.server).await?;
    let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    let stream = connector.connect(domain, tcp).await?;

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    // HELLO
    write_half
        .write_all(b"DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME\n")
        .await?;
    reader.read_line(&mut line).await?;
    if !line.contains("WELCOME") {
        return Err(format!("HELLO failed: {}", line).into());
    }

    // AUTH
    line.clear();
    write_half
        .write_all(format!("DEFT AUTH {}\n", conn.partner_id).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;
    if !line.contains("AUTH_OK") {
        return Err(format!("AUTH failed: {}", line).into());
    }

    // DESCRIBE to get file info
    line.clear();
    write_half
        .write_all(format!("DEFT DESCRIBE {}\n", virtual_file).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;

    // Parse FILE_INFO: DEFT FILE_INFO <name> SIZE:<size> CHUNKS:<chunks> CHUNK_SIZE:<cs> HASH:<hash>
    if !line.contains("FILE_INFO") {
        return Err(format!("DESCRIBE failed: {}", line).into());
    }

    let mut total_chunks = 0u64;
    let mut chunk_size = 262144u64;
    for part in line.split_whitespace() {
        if let Some(c) = part.strip_prefix("CHUNKS:") {
            total_chunks = c.parse().unwrap_or(0);
        }
        if let Some(cs) = part.strip_prefix("CHUNK_SIZE:") {
            chunk_size = cs.parse().unwrap_or(262144);
        }
    }

    // Skip chunk detail lines
    for _ in 0..total_chunks {
        line.clear();
        reader.read_line(&mut line).await?;
    }

    // Create output file
    let mut file = tokio::fs::File::create(output_path).await?;
    let mut total_bytes = 0u64;

    // GET each chunk - need to drop reader and use raw read for binary data
    drop(reader);
    let (read_half, write_half) = {
        // Reconnect for binary transfer (BufReader doesn't work well with mixed line/binary)
        let tcp = tokio::net::TcpStream::connect(&conn.server).await?;
        let domain = rustls::pki_types::ServerName::try_from("localhost")?;
        let stream = connector.connect(domain, tcp).await?;
        tokio::io::split(stream)
    };
    let mut reader = BufReader::new(read_half);
    let mut write_half = write_half;

    // Re-authenticate
    write_half
        .write_all(b"DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME\n")
        .await?;
    line.clear();
    reader.read_line(&mut line).await?;

    line.clear();
    write_half
        .write_all(format!("DEFT AUTH {}\n", conn.partner_id).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;

    for chunk_idx in 0..total_chunks {
        line.clear();
        write_half
            .write_all(
                format!(
                    "DEFT GET {} CHUNKS {}-{}\n",
                    virtual_file,
                    chunk_idx,
                    chunk_idx + 1
                )
                .as_bytes(),
            )
            .await?;
        reader.read_line(&mut line).await?;

        // Parse CHUNK_DATA: DEFT CHUNK_DATA <vf> <idx> SIZE:<size>
        if !line.contains("CHUNK_DATA") {
            return Err(format!("GET failed: {}", line).into());
        }

        let mut size = chunk_size;
        for part in line.split_whitespace() {
            if let Some(s) = part.strip_prefix("SIZE:") {
                size = s.parse().unwrap_or(chunk_size);
            }
        }

        // Read binary chunk data directly from the inner reader
        let mut chunk_data = vec![0u8; size as usize];
        reader.read_exact(&mut chunk_data).await?;
        file.write_all(&chunk_data).await?;
        total_bytes += size;

        // Update progress
        let total_size = total_chunks * chunk_size;
        state
            .update_transfer_progress(transfer_id, total_bytes, total_size)
            .await;
    }

    // Final progress update with actual total
    state
        .update_transfer_progress(transfer_id, total_bytes, total_bytes)
        .await;

    // BYE
    let _ = write_half.write_all(b"DEFT BYE\n").await;

    Ok(total_bytes)
}

async fn handle_client_push(state: &ApiState, body: &[u8]) -> (u16, String) {
    #[derive(Deserialize)]
    struct PushRequest {
        file_path: String,
        virtual_file: String,
    }
    let req: Result<PushRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Get stored connection
            let conn = state.client_connection.read().await;
            let Some(_conn) = conn.as_ref() else {
                return (
                    400,
                    r#"{"success":false,"error":"Not connected. Use Connect first."}"#.to_string(),
                );
            };
            drop(conn);

            // Get file size for registration
            let file_size = std::fs::metadata(&r.file_path)
                .map(|m| m.len())
                .unwrap_or(0);

            // Generate transfer ID and register
            let transfer_id = format!("push_{}", chrono::Utc::now().timestamp_millis());
            let partner_id = {
                let conn = state.client_connection.read().await;
                conn.as_ref()
                    .map(|c| c.partner_id.clone())
                    .unwrap_or_default()
            };
            state
                .register_transfer(
                    transfer_id.clone(),
                    r.virtual_file.clone(),
                    partner_id,
                    "push".to_string(),
                    file_size,
                )
                .await;

            // Perform push
            match push_file(state, &r.file_path, &r.virtual_file, &transfer_id).await {
                Ok(bytes) => {
                    state.complete_transfer(&transfer_id).await;
                    (
                        200,
                        serde_json::json!({
                            "success": true,
                            "file_path": r.file_path,
                            "virtual_file": r.virtual_file,
                            "bytes": bytes
                        })
                        .to_string(),
                    )
                }
                Err(e) => {
                    state.fail_transfer(&transfer_id, &e.to_string()).await;
                    (
                        200,
                        serde_json::json!({
                            "success": false,
                            "error": format!("{}", e)
                        })
                        .to_string(),
                    )
                }
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn push_file(
    state: &ApiState,
    file_path: &str,
    virtual_file: &str,
    transfer_id: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::TlsConnector;

    // Clone connection data and release lock immediately
    let conn = {
        let guard = state.client_connection.read().await;
        guard.as_ref().ok_or("Not connected")?.clone()
    };

    // Read file to push
    let file_data = std::fs::read(file_path)?;
    let file_size = file_data.len() as u64;
    let chunk_size = 262144usize;
    let total_chunks = file_size.div_ceil(chunk_size as u64);

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let hash = format!("{:x}", hasher.finalize());

    // Load TLS config
    let cert_pem = std::fs::read(&conn.cert)?;
    let key_pem = std::fs::read(&conn.key)?;
    let ca_pem = std::fs::read(&conn.ca)?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    let key =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.ok_or("No private key found")?;
    let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = tokio::net::TcpStream::connect(&conn.server).await?;
    let domain = rustls::pki_types::ServerName::try_from("localhost")?;
    let stream = connector.connect(domain, tcp).await?;

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    // HELLO
    write_half
        .write_all(b"DEFT HELLO 1.0 CHUNKED,PARALLEL,RESUME\n")
        .await?;
    reader.read_line(&mut line).await?;
    if !line.contains("WELCOME") {
        return Err(format!("HELLO failed: {}", line).into());
    }

    // AUTH
    line.clear();
    write_half
        .write_all(format!("DEFT AUTH {}\n", conn.partner_id).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;
    if !line.contains("AUTH_OK") {
        return Err(format!("AUTH failed: {}", line).into());
    }

    // BEGIN_TRANSFER: format is <virtual_file> <total_chunks> <total_bytes> <file_hash>
    line.clear();
    write_half
        .write_all(
            format!(
                "DEFT BEGIN_TRANSFER {} {} {} {}\n",
                virtual_file, total_chunks, file_size, hash
            )
            .as_bytes(),
        )
        .await?;
    reader.read_line(&mut line).await?;

    if !line.contains("TRANSFER_ACCEPTED") && !line.contains("TRANSFER_READY") {
        return Err(format!("BEGIN_TRANSFER failed: {}", line).into());
    }

    // Send each chunk
    for chunk_idx in 0..total_chunks {
        let start = (chunk_idx as usize) * chunk_size;
        let end = std::cmp::min(start + chunk_size, file_data.len());
        let chunk_data = &file_data[start..end];

        // Compute chunk hash
        let mut chunk_hasher = Sha256::new();
        chunk_hasher.update(chunk_data);
        let chunk_hash = format!("{:x}", chunk_hasher.finalize());

        // PUT command: DEFT PUT <vf> CHUNK <idx> SIZE:<size> HASH:<hash>
        line.clear();
        write_half
            .write_all(
                format!(
                    "DEFT PUT {} CHUNK {} SIZE:{} HASH:{}\n",
                    virtual_file,
                    chunk_idx,
                    chunk_data.len(),
                    chunk_hash
                )
                .as_bytes(),
            )
            .await?;
        reader.read_line(&mut line).await?;

        if !line.contains("CHUNK_READY") {
            return Err(format!("PUT failed: {}", line).into());
        }

        // Send binary data
        write_half.write_all(chunk_data).await?;

        // Wait for ACK
        line.clear();
        reader.read_line(&mut line).await?;
        if !line.contains("CHUNK_ACK") {
            return Err(format!("CHUNK_ACK failed: {}", line).into());
        }

        // Update progress
        let bytes_sent = (chunk_idx + 1) * chunk_size as u64;
        state
            .update_transfer_progress(transfer_id, bytes_sent.min(file_size), file_size)
            .await;
    }

    // Server sends TRANSFER_COMPLETE automatically after last chunk
    line.clear();
    reader.read_line(&mut line).await?;
    if !line.contains("TRANSFER_COMPLETE") {
        // Not an error if empty - transfer may still complete
        if !line.trim().is_empty() {
            tracing::warn!("Unexpected response after transfer: {}", line.trim());
        }
    }

    // BYE
    let _ = write_half.write_all(b"DEFT BYE\n").await;

    Ok(file_size)
}
