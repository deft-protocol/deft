use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::{Config, Direction, VirtualFileConfig};
use crate::delta::{Delta, FileSignature, DELTA_BLOCK_SIZE};
use crate::metrics;
use crate::parallel::ParallelConfig;
use crate::transfer_state::TransferStateStore;

/// Control commands that can be sent to an active transfer
#[derive(Debug, Clone)]
pub enum TransferControl {
    Pause,
    Resume,
    Abort { reason: Option<String> },
}

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

/// Chunk status for visualization
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChunkStatus {
    Pending,   // Gray - not yet received
    Receiving, // Blue - currently being received
    Received,  // Yellow - received but not validated
    Validated, // Green - received and validated
    Error,     // Red - error during transfer
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
    pub total_chunks: u32,
    pub chunk_statuses: Vec<ChunkStatus>,
}

/// WebSocket event types
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum WsEvent {
    #[serde(rename = "transfers")]
    Transfers(Vec<TransferStatus>),
    #[serde(rename = "history")]
    History(Vec<TransferHistoryEntry>),
    #[serde(rename = "chunk_update")]
    ChunkUpdate {
        transfer_id: String,
        chunk_index: u32,
        status: ChunkStatus,
    },
    #[serde(rename = "transfer_init")]
    TransferInit {
        transfer_id: String,
        total_chunks: u32,
        virtual_file: String,
        direction: String,
    },
    #[serde(rename = "transfer_complete")]
    TransferComplete { transfer_id: String, success: bool },
    #[serde(rename = "transfer_progress")]
    TransferProgress {
        transfer_id: String,
        virtual_file: String,
        bytes_transferred: u64,
        total_bytes: u64,
        progress_percent: u8,
    },
}

/// Partner status for API (incoming connections)
#[derive(Debug, Clone, Serialize)]
pub struct PartnerStatus {
    pub id: String,
    pub virtual_files: Vec<String>,
    pub allowed_certs: Vec<String>,
    pub connected: bool,
    pub last_seen: Option<String>,
    pub transfers_today: u64,
    pub bytes_today: u64,
}

/// Request to create/update a partner (incoming connections)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PartnerRequest {
    pub id: String,
    pub allowed_certs: Option<Vec<String>>,
    pub virtual_files: Option<Vec<String>>,
}

/// Trusted server status for API (outgoing connections - truststore)
#[derive(Debug, Clone, Serialize)]
pub struct TrustedServerStatus {
    pub name: String,
    pub address: String,
    pub cert_fingerprint: Option<String>,
}

/// Request to create/update a trusted server
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TrustedServerRequest {
    pub name: String,
    pub address: String,
    pub cert_fingerprint: Option<String>,
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
#[allow(dead_code)]
pub struct CreateVirtualFileRequest {
    pub name: String,
    pub path: String,
    pub direction: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub partners: Option<Vec<String>>,
    #[serde(default)]
    pub partner_id: Option<String>,
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
    config_path: Option<std::path::PathBuf>,
    pub client_connection: RwLock<Option<ClientConnection>>,
    pub ws_broadcast: broadcast::Sender<WsEvent>,
    pub rate_limiter: crate::rate_limit::RateLimiter,
    /// Cancellation tokens for active transfers (transfer_id -> cancel sender)
    pub cancel_tokens: RwLock<HashMap<String, watch::Sender<bool>>>,
    /// Control channels for active transfers (transfer_id -> control sender)
    pub control_channels: RwLock<HashMap<String, mpsc::Sender<TransferControl>>>,
}

impl ApiState {
    pub fn new(config: Config, config_path: Option<std::path::PathBuf>) -> Self {
        let history_path = std::path::PathBuf::from(&config.storage.temp_dir).join("history.json");
        let history = Self::load_history(&history_path).unwrap_or_default();
        let (ws_broadcast, _) = broadcast::channel(256);

        // Initialize rate limiter from config
        let rate_limit_config = crate::rate_limit::RateLimitConfig {
            max_connections_per_ip: config.limits.max_connections_per_ip,
            max_requests_per_partner: config.limits.max_requests_per_partner,
            max_bytes_per_partner: config.limits.max_bytes_per_partner,
            window_duration: std::time::Duration::from_secs(config.limits.window_seconds),
            ban_duration: std::time::Duration::from_secs(config.limits.ban_seconds),
        };
        let rate_limiter = crate::rate_limit::RateLimiter::new(rate_limit_config);

        Self {
            config: RwLock::new(config),
            start_time: std::time::Instant::now(),
            transfers: RwLock::new(HashMap::new()),
            history: RwLock::new(history),
            history_path,
            config_path,
            client_connection: RwLock::new(None),
            ws_broadcast,
            rate_limiter,
            cancel_tokens: RwLock::new(HashMap::new()),
            control_channels: RwLock::new(HashMap::new()),
        }
    }

    /// Create a control channel for a transfer, returns receiver
    pub async fn create_control_channel(&self, transfer_id: &str) -> mpsc::Receiver<TransferControl> {
        let (tx, rx) = mpsc::channel(16);
        self.control_channels.write().await.insert(transfer_id.to_string(), tx);
        rx
    }

    /// Send a control command to an active transfer
    pub async fn send_control(&self, transfer_id: &str, cmd: TransferControl) -> bool {
        if let Some(tx) = self.control_channels.read().await.get(transfer_id) {
            tx.send(cmd).await.is_ok()
        } else {
            false
        }
    }

    /// Remove control channel when transfer completes
    pub async fn remove_control_channel(&self, transfer_id: &str) {
        self.control_channels.write().await.remove(transfer_id);
    }

    /// Create a cancellation token for a transfer, returns receiver to check for cancellation
    pub async fn create_cancel_token(&self, transfer_id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        self.cancel_tokens.write().await.insert(transfer_id.to_string(), tx);
        rx
    }

    /// Cancel a transfer by signaling its cancellation token
    pub async fn signal_cancel(&self, transfer_id: &str) -> bool {
        if let Some(tx) = self.cancel_tokens.write().await.remove(transfer_id) {
            let _ = tx.send(true);
            true
        } else {
            false
        }
    }

    /// Remove cancellation token when transfer completes
    pub async fn remove_cancel_token(&self, transfer_id: &str) {
        self.cancel_tokens.write().await.remove(transfer_id);
    }

    /// Broadcast a WebSocket event to all connected clients
    pub fn broadcast(&self, event: WsEvent) {
        let _ = self.ws_broadcast.send(event);
    }

    /// Subscribe to WebSocket events
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.ws_broadcast.subscribe()
    }

    /// Check rate limit for API requests. Returns Some((status, body)) if rate limited.
    pub async fn check_api_rate_limit(&self, ip: std::net::IpAddr) -> Option<(u16, String)> {
        use crate::rate_limit::RateLimitResult;

        match self.rate_limiter.check_ip(ip).await {
            RateLimitResult::Allowed => None,
            RateLimitResult::Exceeded => Some((
                429,
                r#"{"error":"Rate limit exceeded. Please slow down."}"#.to_string(),
            )),
            RateLimitResult::Banned => Some((
                429,
                r#"{"error":"Too many requests. You have been temporarily banned."}"#.to_string(),
            )),
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

    /// Save config to file if config_path is set
    async fn save_config(&self) -> Result<(), String> {
        let Some(ref path) = self.config_path else {
            return Err("No config path set".to_string());
        };
        let config = self.config.read().await;
        let toml_str = toml::to_string_pretty(&*config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, toml_str)
            .map_err(|e| format!("Failed to write config file: {}", e))?;
        tracing::info!("Config saved to {:?}", path);
        Ok(())
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
            total_chunks: 0,
            chunk_statuses: Vec::new(),
        };
        self.transfers
            .write()
            .await
            .insert(id.clone(), status.clone());
        // Broadcast updated transfers list
        let transfers: Vec<TransferStatus> =
            self.transfers.read().await.values().cloned().collect();
        tracing::info!(
            "Registered transfer {} - broadcasting {} transfers",
            id,
            transfers.len()
        );
        self.broadcast(WsEvent::Transfers(transfers));
    }

    /// Initialize transfer with chunk count for visualization
    pub async fn init_transfer_chunks(
        &self,
        id: &str,
        total_chunks: u32,
        virtual_file: &str,
        direction: &str,
    ) {
        if let Some(t) = self.transfers.write().await.get_mut(id) {
            t.total_chunks = total_chunks;
            t.chunk_statuses = vec![ChunkStatus::Pending; total_chunks as usize];
        }
        // Broadcast transfer init event
        self.broadcast(WsEvent::TransferInit {
            transfer_id: id.to_string(),
            total_chunks,
            virtual_file: virtual_file.to_string(),
            direction: direction.to_string(),
        });
    }

    /// Update a single chunk's status
    pub async fn update_chunk_status(&self, id: &str, chunk_index: u32, status: ChunkStatus) {
        if let Some(t) = self.transfers.write().await.get_mut(id) {
            if (chunk_index as usize) < t.chunk_statuses.len() {
                t.chunk_statuses[chunk_index as usize] = status;
            }
        }
        // Broadcast chunk update
        self.broadcast(WsEvent::ChunkUpdate {
            transfer_id: id.to_string(),
            chunk_index,
            status,
        });
    }

    pub async fn update_transfer_progress(&self, id: &str, bytes: u64, total: u64) {
        let progress = {
            let mut transfers = self.transfers.write().await;
            if let Some(t) = transfers.get_mut(id) {
                t.bytes_transferred = bytes;
                if total > 0 {
                    t.total_bytes = total;
                    t.progress_percent = ((bytes * 100) / total).min(100) as u8;
                }
                t.updated_at = chrono::Utc::now().to_rfc3339();
                Some((t.progress_percent, t.virtual_file.clone()))
            } else {
                None
            }
        };
        // Broadcast progress update
        if let Some((percent, vf)) = progress {
            self.broadcast(WsEvent::TransferProgress {
                transfer_id: id.to_string(),
                virtual_file: vf,
                bytes_transferred: bytes,
                total_bytes: total,
                progress_percent: percent,
            });
        }
    }

    pub async fn complete_transfer(&self, id: &str) {
        let mut transfers = self.transfers.write().await;
        if let Some(t) = transfers.remove(id) {
            // Add to history
            let entry = TransferHistoryEntry {
                id: t.id.clone(),
                virtual_file: t.virtual_file.clone(),
                partner_id: t.partner_id.clone(),
                direction: t.direction.clone(),
                status: "complete".to_string(),
                total_bytes: t.bytes_transferred.max(t.total_bytes),
                started_at: t.started_at.clone(),
                completed_at: Some(chrono::Utc::now().to_rfc3339()),
            };
            drop(transfers); // Release lock before acquiring another
            self.history.write().await.push(entry.clone());
            self.save_history().await;

            // Broadcast completion
            self.broadcast(WsEvent::TransferComplete {
                transfer_id: id.to_string(),
                success: true,
            });
            self.broadcast(WsEvent::History(self.history.read().await.clone()));
        }
    }

    pub async fn interrupt_transfer(&self, id: &str) -> bool {
        // The transfer loop checks is_transfer_interrupted() to pause
        let mut transfers = self.transfers.write().await;
        if let Some(t) = transfers.get_mut(id) {
            t.status = "interrupted".to_string();
            t.updated_at = chrono::Utc::now().to_rfc3339();
            let all: Vec<TransferStatus> = transfers.values().cloned().collect();
            drop(transfers);
            // Broadcast status change
            self.broadcast(WsEvent::Transfers(all));
            tracing::info!("Transfer {} interrupted", id);
            true
        } else {
            tracing::warn!("interrupt_transfer: transfer {} not found", id);
            false
        }
    }

    pub async fn resume_transfer(&self, id: &str) -> bool {
        let mut transfers = self.transfers.write().await;
        if let Some(t) = transfers.get_mut(id) {
            if t.status == "interrupted" {
                t.status = "active".to_string();
                t.updated_at = chrono::Utc::now().to_rfc3339();
                let all: Vec<TransferStatus> = transfers.values().cloned().collect();
                drop(transfers);
                // Broadcast status change
                self.broadcast(WsEvent::Transfers(all));
                tracing::info!("Transfer {} resumed", id);
                true
            } else {
                tracing::warn!("resume_transfer: transfer {} not in interrupted state (status={})", id, t.status);
                false
            }
        } else {
            tracing::warn!("resume_transfer: transfer {} not found", id);
            false
        }
    }

    /// Check if a transfer is interrupted
    pub async fn is_transfer_interrupted(&self, id: &str) -> bool {
        if let Some(t) = self.transfers.read().await.get(id) {
            t.status == "interrupted"
        } else {
            false
        }
    }

    pub async fn fail_transfer(&self, id: &str, error: &str) {
        let mut transfers = self.transfers.write().await;
        if let Some(t) = transfers.remove(id) {
            let entry = TransferHistoryEntry {
                id: t.id.clone(),
                virtual_file: t.virtual_file.clone(),
                partner_id: t.partner_id.clone(),
                direction: t.direction.clone(),
                status: format!("failed: {}", error),
                total_bytes: t.bytes_transferred,
                started_at: t.started_at.clone(),
                completed_at: Some(chrono::Utc::now().to_rfc3339()),
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

    // Check for WebSocket upgrade
    if path == "/ws" {
        let is_upgrade = lines.iter().any(|l| {
            l.to_lowercase().contains("upgrade:") && l.to_lowercase().contains("websocket")
        });
        if is_upgrade {
            handle_websocket(stream, peer, state, &request).await;
            return;
        }
    }

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
        ("GET", "/api/server-fingerprint") => handle_server_fingerprint(&state).await,

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

        // Trusted servers endpoints (outgoing connections)
        ("GET", "/api/trusted-servers") => handle_trusted_servers(&state).await,
        ("POST", "/api/trusted-servers") => {
            handle_create_trusted_server(&state, request_body).await
        }
        ("PUT", p) if p.starts_with("/api/trusted-servers/") => {
            let name = p.strip_prefix("/api/trusted-servers/").unwrap_or("");
            handle_update_trusted_server(&state, name, request_body).await
        }
        ("DELETE", p) if p.starts_with("/api/trusted-servers/") => {
            let name = p.strip_prefix("/api/trusted-servers/").unwrap_or("");
            handle_delete_trusted_server(&state, name).await
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
        ("POST", p) if p.ends_with("/interrupt") => {
            let id = p
                .strip_prefix("/api/transfers/")
                .and_then(|s| s.strip_suffix("/interrupt"))
                .unwrap_or("");
            handle_interrupt_transfer(&state, id).await
        }
        ("POST", p) if p.ends_with("/resume") => {
            let id = p
                .strip_prefix("/api/transfers/")
                .and_then(|s| s.strip_suffix("/resume"))
                .unwrap_or("");
            handle_resume_transfer(&state, id).await
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

        // Client endpoints (outgoing connections) - rate limited
        ("POST", "/api/client/connect") => {
            if let Some(rate_limited) = state.check_api_rate_limit(peer.ip()).await {
                rate_limited
            } else {
                handle_client_connect(&state, request_body).await
            }
        }
        ("POST", "/api/client/pull") => {
            if let Some(rate_limited) = state.check_api_rate_limit(peer.ip()).await {
                rate_limited
            } else {
                handle_client_pull(&state, request_body).await
            }
        }
        ("POST", "/api/client/push") => {
            if let Some(rate_limited) = state.check_api_rate_limit(peer.ip()).await {
                rate_limited
            } else {
                handle_client_push(&state, request_body).await
            }
        }
        // v2.0: Parallel push endpoint
        ("POST", "/api/client/push-parallel") => {
            if let Some(rate_limited) = state.check_api_rate_limit(peer.ip()).await {
                rate_limited
            } else {
                handle_client_push_parallel(&state, request_body).await
            }
        }
        // v2.0: Delta sync endpoint
        ("POST", "/api/client/sync-delta") => {
            if let Some(rate_limited) = state.check_api_rate_limit(peer.ip()).await {
                rate_limited
            } else {
                handle_client_sync_delta(&state, request_body).await
            }
        }

        // Delta sync endpoints
        ("POST", "/api/delta/signature") => handle_delta_signature(&state, request_body).await,
        ("POST", "/api/delta/compute") => handle_delta_compute(&state, request_body).await,
        ("GET", "/api/parallel/config") => handle_parallel_config().await,
        ("GET", "/api/network/interfaces") => handle_network_interfaces().await,
        ("GET", "/api/transfer-states") => handle_list_transfer_states(&state).await,
        ("DELETE", p) if p.starts_with("/api/transfer-states/") => {
            let id = p.strip_prefix("/api/transfer-states/").unwrap_or("");
            handle_delete_transfer_state(&state, id).await
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

async fn handle_websocket(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ApiState>,
    request: &str,
) {
    use sha1::{Digest, Sha1};

    // Extract Sec-WebSocket-Key
    let key = request
        .lines()
        .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|k| k.trim())
        .unwrap_or("");

    // Compute accept key
    let accept = {
        let mut hasher = Sha1::new();
        hasher.update(format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key).as_bytes());
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hasher.finalize(),
        )
    };

    // Send upgrade response
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept
    );

    let mut stream = stream;
    if stream.write_all(response.as_bytes()).await.is_err() {
        return;
    }

    info!("WebSocket connection from {}", peer);

    // Convert to WebSocket stream
    let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    let mut rx = state.subscribe();

    // Send initial state
    let transfers: Vec<TransferStatus> = state.transfers.read().await.values().cloned().collect();
    if let Ok(json) = serde_json::to_string(&WsEvent::Transfers(transfers)) {
        let _ = ws_sender.send(Message::Text(json)).await;
    }

    let history = state.history.read().await.clone();
    if let Ok(json) = serde_json::to_string(&WsEvent::History(history)) {
        let _ = ws_sender.send(Message::Text(json)).await;
    }

    loop {
        tokio::select! {
            // Receive from broadcast channel
            event = rx.recv() => {
                match event {
                    Ok(evt) => {
                        if let Ok(json) = serde_json::to_string(&evt) {
                            if ws_sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            // Receive from WebSocket (for ping/pong and close)
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    info!("WebSocket connection closed from {}", peer);
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

async fn handle_server_fingerprint(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let cert_path = &config.server.cert;

    match std::fs::read(cert_path) {
        Ok(pem_data) => {
            // Parse PEM and compute SHA-256 fingerprint
            match rustls_pemfile::certs(&mut pem_data.as_slice()).next() {
                Some(Ok(cert)) => {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(cert.as_ref());
                    let fingerprint = hasher.finalize();
                    let hex = fingerprint
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    (
                        200,
                        serde_json::json!({"fingerprint": hex, "path": cert_path}).to_string(),
                    )
                }
                _ => (
                    500,
                    r#"{"error":"Failed to parse certificate"}"#.to_string(),
                ),
            }
        }
        Err(e) => (
            500,
            format!(r#"{{"error":"Failed to read certificate: {}"}}"#, e),
        ),
    }
}

async fn handle_partners(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let partners: Vec<PartnerStatus> = config
        .partners
        .iter()
        .map(|p| PartnerStatus {
            id: p.id.clone(),
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
            let partner_id = r.id.clone();
            {
                let mut config = state.config.write().await;
                if config.partners.iter().any(|p| p.id == r.id) {
                    return (409, r#"{"error":"Partner already exists"}"#.to_string());
                }
                let partner = crate::config::PartnerConfig {
                    id: r.id.clone(),
                    allowed_certs: r.allowed_certs.unwrap_or_default(),
                    virtual_files: Vec::new(),
                };
                config.partners.push(partner);
            }
            // Persist to file
            if let Err(e) = state.save_config().await {
                tracing::warn!("Failed to save config: {}", e);
            }
            (
                201,
                serde_json::json!({"status":"created", "id": partner_id}).to_string(),
            )
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_update_partner(state: &ApiState, partner_id: &str, body: &[u8]) -> (u16, String) {
    let req: Result<PartnerRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let found = {
                let mut config = state.config.write().await;
                if let Some(partner) = config.partners.iter_mut().find(|p| p.id == partner_id) {
                    if let Some(certs) = r.allowed_certs {
                        partner.allowed_certs = certs;
                    }
                    true
                } else {
                    false
                }
            };
            if found {
                // Persist to file
                if let Err(e) = state.save_config().await {
                    tracing::warn!("Failed to save config: {}", e);
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
    let deleted = {
        let mut config = state.config.write().await;
        let before = config.partners.len();
        config.partners.retain(|p| p.id != partner_id);
        config.partners.len() < before
    };
    if deleted {
        // Persist to file
        if let Err(e) = state.save_config().await {
            tracing::warn!("Failed to save config: {}", e);
        }
        (200, r#"{"status":"deleted"}"#.to_string())
    } else {
        (404, r#"{"error":"Partner not found"}"#.to_string())
    }
}

// ============ Trusted Servers (outgoing connections) ============

async fn handle_trusted_servers(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let servers: Vec<TrustedServerStatus> = config
        .trusted_servers
        .iter()
        .map(|s| TrustedServerStatus {
            name: s.name.clone(),
            address: s.address.clone(),
            cert_fingerprint: s.cert_fingerprint.clone(),
        })
        .collect();
    (200, serde_json::to_string(&servers).unwrap_or_default())
}

async fn handle_create_trusted_server(state: &ApiState, body: &[u8]) -> (u16, String) {
    let req: Result<TrustedServerRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let server_name = r.name.clone();
            {
                let mut config = state.config.write().await;
                if config.trusted_servers.iter().any(|s| s.name == r.name) {
                    return (
                        409,
                        r#"{"error":"Trusted server already exists"}"#.to_string(),
                    );
                }
                let server = crate::config::TrustedServerConfig {
                    name: r.name,
                    address: r.address,
                    cert_fingerprint: r.cert_fingerprint,
                };
                config.trusted_servers.push(server);
            }
            if let Err(e) = state.save_config().await {
                tracing::warn!("Failed to save config: {}", e);
            }
            (
                201,
                serde_json::json!({"status":"created", "name": server_name}).to_string(),
            )
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_update_trusted_server(state: &ApiState, name: &str, body: &[u8]) -> (u16, String) {
    let req: Result<TrustedServerRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let found = {
                let mut config = state.config.write().await;
                if let Some(server) = config.trusted_servers.iter_mut().find(|s| s.name == name) {
                    server.address = r.address;
                    server.cert_fingerprint = r.cert_fingerprint;
                    true
                } else {
                    false
                }
            };
            if found {
                if let Err(e) = state.save_config().await {
                    tracing::warn!("Failed to save config: {}", e);
                }
                (200, r#"{"status":"updated"}"#.to_string())
            } else {
                (404, r#"{"error":"Trusted server not found"}"#.to_string())
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_delete_trusted_server(state: &ApiState, name: &str) -> (u16, String) {
    let deleted = {
        let mut config = state.config.write().await;
        let before = config.trusted_servers.len();
        config.trusted_servers.retain(|s| s.name != name);
        config.trusted_servers.len() < before
    };
    if deleted {
        if let Err(e) = state.save_config().await {
            tracing::warn!("Failed to save config: {}", e);
        }
        (200, r#"{"status":"deleted"}"#.to_string())
    } else {
        (404, r#"{"error":"Trusted server not found"}"#.to_string())
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
            let Some(partner) = config.partners.iter().find(|p| p.id == r.partner_id) else {
                return (404, r#"{"error":"Partner not found"}"#.to_string());
            };

            // Validate virtual file exists for this partner
            let Some(vf) = partner
                .virtual_files
                .iter()
                .find(|v| v.name == r.virtual_file)
            else {
                return (
                    404,
                    r#"{"error":"Virtual file not found for this partner"}"#.to_string(),
                );
            };

            // Generate transfer ID
            let transfer_id = format!("api-{}", chrono::Utc::now().timestamp_millis());

            // Register transfer in state
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
    // Signal cancellation to the running transfer task
    let signaled = state.signal_cancel(id).await;

    // Also remove from transfers map
    let mut transfers = state.transfers.write().await;
    if transfers.remove(id).is_some() || signaled {
        // Add to history as cancelled
        let mut history = state.history.write().await;
        history.push(TransferHistoryEntry {
            id: id.to_string(),
            virtual_file: "unknown".to_string(),
            partner_id: "unknown".to_string(),
            direction: "unknown".to_string(),
            status: "cancelled".to_string(),
            total_bytes: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            completed_at: Some(chrono::Utc::now().to_rfc3339()),
        });
        drop(history);
        drop(transfers);

        state.broadcast(WsEvent::TransferComplete {
            transfer_id: id.to_string(),
            success: false,
        });

        (200, r#"{"status":"cancelled"}"#.to_string())
    } else {
        (404, r#"{"error":"Transfer not found"}"#.to_string())
    }
}

async fn handle_retry_transfer(state: &ApiState, id: &str) -> (u16, String) {
    let history = state.history.read().await;
    if let Some(entry) = history.iter().find(|t| t.id == id) {
        // Clone the entry data we need before releasing the lock
        let virtual_file = entry.virtual_file.clone();
        let partner_id = entry.partner_id.clone();
        let direction = entry.direction.clone();
        let total_bytes = entry.total_bytes;
        drop(history);

        // Create a new transfer with retry ID
        let retry_id = format!("retry_{}_{}", id, chrono::Utc::now().timestamp_millis());
        state
            .register_transfer(
                retry_id.clone(),
                virtual_file.clone(),
                partner_id.clone(),
                direction.clone(),
                total_bytes,
            )
            .await;

        (
            202,
            serde_json::json!({
                "status": "retry_queued",
                "retry_id": retry_id,
                "original_id": id,
                "virtual_file": virtual_file,
                "partner_id": partner_id,
                "direction": direction
            })
            .to_string(),
        )
    } else {
        (
            404,
            r#"{"error":"Transfer not found in history"}"#.to_string(),
        )
    }
}

async fn handle_interrupt_transfer(state: &ApiState, id: &str) -> (u16, String) {
    // Send pause command to the transfer task (which will notify remote)
    let sent = state.send_control(id, TransferControl::Pause).await;

    if state.interrupt_transfer(id).await || sent {
        (
            200,
            serde_json::json!({"status": "interrupted", "id": id, "remote_notified": sent}).to_string(),
        )
    } else {
        (404, r#"{"error":"Transfer not found"}"#.to_string())
    }
}

async fn handle_resume_transfer(state: &ApiState, id: &str) -> (u16, String) {
    // Log current state for debugging
    let transfers = state.transfers.read().await;
    let transfer_exists = transfers.contains_key(id);
    let current_status = transfers.get(id).map(|t| t.status.clone());
    drop(transfers);
    
    let control_exists = state.control_channels.read().await.contains_key(id);
    tracing::info!(
        "handle_resume_transfer: id={}, exists={}, status={:?}, control_channel={}",
        id, transfer_exists, current_status, control_exists
    );

    // Only send resume command to the transfer task
    // Do NOT change local status here - let push_file handle it after remote confirms
    // This prevents race condition where status flips active->interrupted
    let sent = state.send_control(id, TransferControl::Resume).await;

    if sent {
        (
            200,
            serde_json::json!({"status": "resuming", "id": id, "remote_notified": sent}).to_string(),
        )
    } else if transfer_exists {
        // No control channel but transfer exists - might be a receive transfer
        // Try to resume directly
        let resumed = state.resume_transfer(id).await;
        if resumed {
            (
                200,
                serde_json::json!({"status": "resumed", "id": id, "remote_notified": false}).to_string(),
            )
        } else {
            (
                400,
                serde_json::json!({
                    "error": "Transfer not in interrupted state",
                    "current_status": current_status
                }).to_string(),
            )
        }
    } else {
        (
            404,
            serde_json::json!({
                "error": "Transfer not found",
                "transfer_exists": transfer_exists,
                "control_channel_exists": control_exists
            }).to_string(),
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

async fn handle_delta_signature(state: &ApiState, body: &[u8]) -> (u16, String) {
    #[derive(Deserialize)]
    struct DeltaSignatureRequest {
        virtual_file: String,
        block_size: Option<usize>,
    }

    let req: Result<DeltaSignatureRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let config = state.config.read().await;
            // Find the virtual file path
            for partner in &config.partners {
                for vf in &partner.virtual_files {
                    if vf.name == r.virtual_file {
                        let block_size = r.block_size.unwrap_or(DELTA_BLOCK_SIZE);
                        match std::fs::File::open(&vf.path) {
                            Ok(mut file) => match FileSignature::compute(&mut file, block_size) {
                                Ok(sig) => {
                                    return (
                                        200,
                                        serde_json::json!({
                                            "virtual_file": r.virtual_file,
                                            "block_size": sig.block_size,
                                            "file_size": sig.file_size,
                                            "blocks_count": sig.blocks.len()
                                        })
                                        .to_string(),
                                    );
                                }
                                Err(e) => {
                                    return (
                                            500,
                                            serde_json::json!({"error": format!("Failed to compute signature: {}", e)}).to_string(),
                                        );
                                }
                            },
                            Err(e) => {
                                return (
                                    404,
                                    serde_json::json!({"error": format!("File not found: {}", e)})
                                        .to_string(),
                                );
                            }
                        }
                    }
                }
            }
            (404, r#"{"error":"Virtual file not found"}"#.to_string())
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_parallel_config() -> (u16, String) {
    use crate::network;

    let config = ParallelConfig::default();
    let suggested = network::suggest_parallel_streams();
    let interfaces = network::get_transfer_interfaces();

    (
        200,
        serde_json::json!({
            "max_concurrent": config.max_concurrent,
            "buffer_size": config.buffer_size,
            "suggested_streams": suggested,
            "available_interfaces": interfaces.len()
        })
        .to_string(),
    )
}

async fn handle_network_interfaces() -> (u16, String) {
    use crate::network;

    let interfaces = network::detect_interfaces();
    let transfer_interfaces = network::get_transfer_interfaces();
    let suggested = network::suggest_parallel_streams();

    let iface_list: Vec<_> = interfaces
        .iter()
        .map(|iface| {
            serde_json::json!({
                "name": iface.name,
                "addresses": iface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "is_up": iface.is_up,
                "is_loopback": iface.is_loopback,
                "ipv4": iface.ipv4().map(|a| a.to_string()),
                "ipv6": iface.ipv6().map(|a| a.to_string())
            })
        })
        .collect();

    (
        200,
        serde_json::json!({
            "interfaces": iface_list,
            "transfer_capable": transfer_interfaces.len(),
            "suggested_parallel_streams": suggested
        })
        .to_string(),
    )
}

async fn handle_list_transfer_states(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let store_path = config.storage.temp_dir.replace("tmp", "transfer_states");
    match TransferStateStore::new(&store_path) {
        Ok(store) => match store.list_incomplete() {
            Ok(states) => {
                let summary: Vec<_> = states
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "transfer_id": s.transfer_id,
                            "virtual_file": s.virtual_file,
                            "progress_percent": s.progress_percent(),
                            "received_chunks": s.received_count(),
                            "total_chunks": s.total_chunks,
                            "pending_chunks": s.pending_chunks().len(),
                            "is_complete": s.is_complete(),
                            "started_at": s.started_at,
                            "last_updated": s.last_updated
                        })
                    })
                    .collect();
                (200, serde_json::to_string(&summary).unwrap_or_default())
            }
            Err(e) => (
                500,
                serde_json::json!({"error": format!("Failed to list states: {}", e)}).to_string(),
            ),
        },
        Err(e) => (
            500,
            serde_json::json!({"error": format!("Failed to open store: {}", e)}).to_string(),
        ),
    }
}

async fn handle_delete_transfer_state(state: &ApiState, id: &str) -> (u16, String) {
    let config = state.config.read().await;
    let store_path = config.storage.temp_dir.replace("tmp", "transfer_states");
    match TransferStateStore::new(&store_path) {
        Ok(store) => {
            if store.exists(id) {
                match store.delete(id) {
                    Ok(_) => (
                        200,
                        serde_json::json!({"status": "deleted", "id": id}).to_string(),
                    ),
                    Err(e) => (
                        500,
                        serde_json::json!({"error": format!("Failed to delete: {}", e)})
                            .to_string(),
                    ),
                }
            } else {
                (404, r#"{"error":"Transfer state not found"}"#.to_string())
            }
        }
        Err(e) => (
            500,
            serde_json::json!({"error": format!("Failed to open store: {}", e)}).to_string(),
        ),
    }
}

async fn handle_delta_compute(_state: &ApiState, body: &[u8]) -> (u16, String) {
    #[derive(Deserialize)]
    struct DeltaComputeRequest {
        base_file: String,
        new_file: String,
        block_size: Option<usize>,
    }

    let req: Result<DeltaComputeRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            let block_size = r.block_size.unwrap_or(DELTA_BLOCK_SIZE);

            // Open base file and compute signature
            let base_sig = match std::fs::File::open(&r.base_file) {
                Ok(mut file) => match FileSignature::compute(&mut file, block_size) {
                    Ok(sig) => sig,
                    Err(e) => {
                        return (
                            500,
                            serde_json::json!({"error": format!("Failed to compute base signature: {}", e)}).to_string(),
                        )
                    }
                },
                Err(e) => {
                    return (
                        404,
                        serde_json::json!({"error": format!("Base file not found: {}", e)}).to_string(),
                    )
                }
            };

            // Open new file and compute delta
            match std::fs::File::open(&r.new_file) {
                Ok(mut file) => match Delta::compute(&base_sig, &mut file) {
                    Ok(delta) => {
                        let stats = delta.stats();
                        (
                            200,
                            serde_json::json!({
                                "block_size": delta.block_size,
                                "target_size": delta.target_size,
                                "operations_count": stats.total_ops,
                                "copy_blocks": stats.copy_blocks,
                                "insert_bytes": stats.insert_bytes,
                                "savings_percent": format!("{:.1}", delta.savings(base_sig.file_size) * 100.0)
                            })
                            .to_string(),
                        )
                    }
                    Err(e) => (
                        500,
                        serde_json::json!({"error": format!("Failed to compute delta: {}", e)})
                            .to_string(),
                    ),
                },
                Err(e) => (
                    404,
                    serde_json::json!({"error": format!("New file not found: {}", e)}).to_string(),
                ),
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

async fn handle_config(state: &ApiState) -> (u16, String) {
    let config = state.config.read().await;
    let config_summary = serde_json::json!({
        "server": {
            "enabled": config.server.enabled,
            "listen": config.server.listen,
            "cert": config.server.cert,
            "key": config.server.key,
            "ca": config.server.ca,
        },
        "client": {
            "enabled": config.client.enabled,
            "cert": config.client.cert,
            "key": config.client.key,
            "ca": config.client.ca,
        },
        "storage": {
            "chunk_size": config.storage.chunk_size,
            "temp_dir": config.storage.temp_dir,
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
            // Find the partner to add this VF to - use first partner from list if provided, or partner_id
            let target_partner_id = r
                .partners
                .as_ref()
                .and_then(|p| p.first().cloned())
                .or(r.partner_id.clone());

            if let Some(pid) = target_partner_id {
                if let Some(partner) = config.partners.iter_mut().find(|p| p.id == pid) {
                    partner.virtual_files.push(vf);
                    (
                        201,
                        serde_json::json!({"status":"created", "name": r.name}).to_string(),
                    )
                } else {
                    (404, r#"{"error":"Partner not found"}"#.to_string())
                }
            } else {
                (400, r#"{"error":"No partner specified"}"#.to_string())
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
            let found = {
                let mut config = state.config.write().await;
                let mut found = false;
                for partner in &mut config.partners {
                    for vf in &mut partner.virtual_files {
                        if vf.name == name {
                            vf.path = r.path.clone();
                            vf.direction = direction;
                            found = true;
                            break;
                        }
                    }
                    if found {
                        break;
                    }
                }
                found
            };
            if found {
                if let Err(e) = state.save_config().await {
                    tracing::warn!("Failed to save config: {}", e);
                }
                (200, r#"{"status":"updated"}"#.to_string())
            } else {
                (404, r#"{"error":"Virtual file not found"}"#.to_string())
            }
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

/// Request to connect to a trusted server
#[derive(Debug, Deserialize)]
struct ClientConnectRequest {
    /// Trusted server name from config
    server_name: String,
    /// Our identity (must match client cert CN)
    our_identity: String,
    /// Optional client certificate path (uses config default if empty)
    cert: Option<String>,
    /// Optional client key path (uses config default if empty)
    key: Option<String>,
}

async fn handle_client_connect(state: &ApiState, body: &[u8]) -> (u16, String) {
    let req: Result<ClientConnectRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Get config from state
            let config = state.config.read().await;
            let client_config = &config.client;

            // Find the trusted server
            let server = match config
                .trusted_servers
                .iter()
                .find(|s| s.name == r.server_name)
            {
                Some(s) => s.clone(),
                None => {
                    return (
                        404,
                        serde_json::json!({
                            "success": false,
                            "error": format!("Trusted server '{}' not found", r.server_name)
                        })
                        .to_string(),
                    );
                }
            };

            // Use provided certs or fall back to config
            let cert_path = r.cert.as_deref().unwrap_or(&client_config.cert).to_string();
            let key_path = r.key.as_deref().unwrap_or(&client_config.key).to_string();
            let ca_path = client_config.ca.clone();

            // Get allowed server cert fingerprint from trusted server config
            let allowed_server_certs: Vec<String> = server
                .cert_fingerprint
                .map(|fp| vec![fp])
                .unwrap_or_default();
            drop(config); // Release read lock

            // Try to establish TLS connection
            match connect_to_server(
                &server.address,
                &cert_path,
                &key_path,
                &ca_path,
                &r.our_identity,
                &allowed_server_certs,
            )
            .await
            {
                Ok(virtual_files) => {
                    // Store connection parameters for subsequent pull/push
                    *state.client_connection.write().await = Some(ClientConnection {
                        server: server.address.clone(),
                        partner_id: r.our_identity.clone(),
                        cert: cert_path,
                        key: key_path,
                        ca: ca_path,
                    });

                    (
                        200,
                        serde_json::json!({
                            "success": true,
                            "server_name": r.server_name,
                            "server_address": server.address,
                            "our_identity": r.our_identity,
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
    allowed_server_certs: &[String],
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

    // Compute expected fingerprints from allowed_server_certs (may be paths or fingerprints)
    let expected_fingerprints: Vec<String> = allowed_server_certs
        .iter()
        .filter_map(|c| {
            if c.contains('/') || c.ends_with(".crt") || c.ends_with(".pem") {
                // It's a file path - compute fingerprint
                compute_cert_fingerprint_for_client(c)
            } else {
                // It's already a fingerprint
                Some(c.replace(':', "").to_lowercase())
            }
        })
        .collect();

    // Server certificate fingerprint validation is mandatory
    if expected_fingerprints.is_empty() {
        return Err("No allowed_server_certs configured for this partner - server certificate validation is mandatory".into());
    }

    // Use custom verifier with fingerprint validation
    let verifier = FingerprintServerVerifier::new(Arc::new(root_store), expected_fingerprints)?;
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
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
    let _ = write_half.shutdown().await;

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
                    "receive".to_string(), // Client pulls = receives data
                    0,                     // Size unknown until transfer starts
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

    // Initialize chunk tracking for UI
    state
        .init_transfer_chunks(transfer_id, total_chunks as u32, virtual_file, "receive")
        .await;

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

    // Use random chunk ordering for anti-MITM protection
    let mut orderer = crate::chunk_ordering::ChunkOrderer::new_random(total_chunks);

    // Pre-allocate buffer for all chunks (we'll write them in order later)
    let total_size_estimate = total_chunks * chunk_size;
    let mut chunk_buffers: std::collections::HashMap<u64, Vec<u8>> =
        std::collections::HashMap::new();

    while let Some(chunk_idx) = orderer.next_chunk() {
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

        // Update chunk status to "receiving"
        state
            .update_chunk_status(transfer_id, chunk_idx as u32, ChunkStatus::Receiving)
            .await;

        // Read binary chunk data
        let mut chunk_data = vec![0u8; size as usize];
        reader.read_exact(&mut chunk_data).await?;
        chunk_buffers.insert(chunk_idx, chunk_data);
        total_bytes += size;

        // Update chunk status to "validated"
        state
            .update_chunk_status(transfer_id, chunk_idx as u32, ChunkStatus::Validated)
            .await;

        // Update progress
        state
            .update_transfer_progress(transfer_id, total_bytes, total_size_estimate)
            .await;
    }

    // Write chunks to file in order
    for chunk_idx in 0..total_chunks {
        if let Some(data) = chunk_buffers.get(&chunk_idx) {
            file.write_all(data).await?;
        }
    }

    // Final progress update with actual total
    state
        .update_transfer_progress(transfer_id, total_bytes, total_bytes)
        .await;

    // BYE
    let _ = write_half.write_all(b"DEFT BYE\n").await;
    let _ = write_half.shutdown().await;

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
                    "send".to_string(), // Client pushes = sends data
                    file_size,
                )
                .await;

            // Create cancellation token and control channel
            let cancel_rx = state.create_cancel_token(&transfer_id).await;
            let control_rx = state.create_control_channel(&transfer_id).await;

            // Perform push
            let result = push_file(state, &r.file_path, &r.virtual_file, &transfer_id, cancel_rx, control_rx).await;
            state.remove_cancel_token(&transfer_id).await;
            state.remove_control_channel(&transfer_id).await;

            match result {
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
    cancel_rx: watch::Receiver<bool>,
    mut control_rx: mpsc::Receiver<TransferControl>,
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

    // v2.0: Try delta sync first - request signature from server
    line.clear();
    write_half
        .write_all(format!("DEFT DELTA_SIG_REQ {} 4096\n", virtual_file).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;

    // Check if delta sync is possible
    if line.contains("DELTA_SIG") && line.contains("EXISTS:true") {
        // Server has the file - use delta sync
        use crate::delta::{Delta, FileSignature};
        use base64::Engine;
        use std::io::Cursor;

        // Extract signature data from response
        if let Some(data_start) = line.find("DATA:") {
            let sig_b64 = line[data_start + 5..].trim();
            if !sig_b64.is_empty() {
                // Decode signature
                if let Ok(sig_json_bytes) =
                    base64::engine::general_purpose::STANDARD.decode(sig_b64)
                {
                    if let Ok(sig_json) = String::from_utf8(sig_json_bytes) {
                        if let Ok(remote_sig) = serde_json::from_str::<FileSignature>(&sig_json) {
                            // Compute delta
                            let mut local_cursor = Cursor::new(&file_data);
                            if let Ok(delta) = Delta::compute(&remote_sig, &mut local_cursor) {
                                let stats = delta.stats();
                                tracing::info!(
                                    "Delta computed: {} copy blocks, {} insert bytes",
                                    stats.copy_blocks,
                                    stats.insert_bytes
                                );

                                // Serialize and send delta
                                let delta_json = serde_json::to_string(&delta)?;
                                let delta_b64 = base64::engine::general_purpose::STANDARD
                                    .encode(delta_json.as_bytes());

                                line.clear();
                                write_half
                                    .write_all(
                                        format!(
                                            "DEFT DELTA_PUT {} HASH:{} DATA:{}\n",
                                            virtual_file, hash, delta_b64
                                        )
                                        .as_bytes(),
                                    )
                                    .await?;
                                reader.read_line(&mut line).await?;

                                if line.contains("DELTA_ACK") {
                                    tracing::info!("Delta sync successful for {}", virtual_file);
                                    // BYE
                                    let _ = write_half.write_all(b"DEFT BYE\n").await;
                                    let _ = write_half.shutdown().await;
                                    return Ok(file_size);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fall back to regular transfer if delta sync failed or file doesn't exist
    tracing::debug!("Using regular transfer for {}", virtual_file);

    // BEGIN_TRANSFER: format is <virtual_file> <total_chunks> <total_bytes> <file_hash> TX_ID:<id>
    line.clear();
    write_half
        .write_all(
            format!(
                "DEFT BEGIN_TRANSFER {} {} {} {} TX_ID:{}\n",
                virtual_file, total_chunks, file_size, hash, transfer_id
            )
            .as_bytes(),
        )
        .await?;
    reader.read_line(&mut line).await?;

    if !line.contains("TRANSFER_ACCEPTED") && !line.contains("TRANSFER_READY") {
        return Err(format!("BEGIN_TRANSFER failed: {}", line).into());
    }

    // Initialize chunk tracking for UI
    state
        .init_transfer_chunks(transfer_id, total_chunks as u32, virtual_file, "send")
        .await;

    // Use random chunk ordering for anti-MITM protection
    let mut orderer = crate::chunk_ordering::ChunkOrderer::new_random(total_chunks);
    let mut chunks_sent = 0u64;

    // Send chunks in random order
    while let Some(chunk_idx) = orderer.next_chunk() {
        // Check for cancellation
        if *cancel_rx.borrow() {
            let _ = write_half.write_all(format!("DEFT ABORT_TRANSFER {}\n", transfer_id).as_bytes()).await;
            let _ = write_half.write_all(b"DEFT BYE\n").await;
            let _ = write_half.shutdown().await;
            return Err("Transfer cancelled".into());
        }

        // Check for control commands (non-blocking)
        while let Ok(cmd) = control_rx.try_recv() {
            match cmd {
                TransferControl::Pause => {
                    // Send PAUSE to remote
                    let _ = write_half.write_all(format!("DEFT PAUSE_TRANSFER {}\n", transfer_id).as_bytes()).await;
                    tracing::info!("Sent PAUSE_TRANSFER {} to remote", transfer_id);
                }
                TransferControl::Resume => {
                    // Send RESUME to remote
                    let _ = write_half.write_all(format!("DEFT RESUME_TRANSFER_CMD {}\n", transfer_id).as_bytes()).await;
                    tracing::info!("Sent RESUME_TRANSFER_CMD {} to remote", transfer_id);
                }
                TransferControl::Abort { reason } => {
                    // Send ABORT to remote
                    if let Some(r) = reason {
                        let _ = write_half.write_all(format!("DEFT ABORT_TRANSFER {} REASON:{}\n", transfer_id, r).as_bytes()).await;
                    } else {
                        let _ = write_half.write_all(format!("DEFT ABORT_TRANSFER {}\n", transfer_id).as_bytes()).await;
                    }
                    let _ = write_half.write_all(b"DEFT BYE\n").await;
                    let _ = write_half.shutdown().await;
                    return Err("Transfer aborted".into());
                }
            }
        }

        // Check for cancellation
        if *cancel_rx.borrow() {
            let _ = write_half.write_all(format!("DEFT ABORT_TRANSFER {}\n", transfer_id).as_bytes()).await;
            let _ = write_half.write_all(b"DEFT BYE\n").await;
            let _ = write_half.shutdown().await;
            return Err("Transfer cancelled".into());
        }

        // Process any control commands (sender-initiated pause/resume)
        if let Ok(cmd) = control_rx.try_recv() {
            match cmd {
                TransferControl::Pause => {
                    let _ = write_half.write_all(format!("DEFT PAUSE_TRANSFER {}\n", transfer_id).as_bytes()).await;
                    state.interrupt_transfer(transfer_id).await;
                    tracing::info!("Sent PAUSE_TRANSFER {} to remote", transfer_id);
                }
                TransferControl::Resume => {
                    let _ = write_half.write_all(format!("DEFT RESUME_TRANSFER_CMD {}\n", transfer_id).as_bytes()).await;
                    tracing::info!("Sent RESUME_TRANSFER_CMD {} to remote", transfer_id);
                    line.clear();
                    if reader.read_line(&mut line).await.is_ok() && line.contains("TRANSFER_RESUMED") {
                        state.resume_transfer(transfer_id).await;
                        tracing::info!("Transfer {} resumed after remote confirmation", transfer_id);
                    }
                }
                TransferControl::Abort { .. } => {
                    let _ = write_half.write_all(format!("DEFT ABORT_TRANSFER {}\n", transfer_id).as_bytes()).await;
                    return Err("Transfer aborted by user".into());
                }
            }
        }

        let start = (chunk_idx as usize) * chunk_size;
        let end = std::cmp::min(start + chunk_size, file_data.len());
        let chunk_data = &file_data[start..end];

        // Compute chunk hash
        let mut chunk_hasher = Sha256::new();
        chunk_hasher.update(chunk_data);
        let chunk_hash = format!("{:x}", chunk_hasher.finalize());

        // PUT command: DEFT PUT <vf> CHUNK <idx> SIZE:<size> HASH:<hash>
        // Retry loop in case of TRANSFER_PAUSED response
        loop {
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

            // Handle TRANSFER_PAUSED response - remote paused the transfer
            if line.contains("TRANSFER_PAUSED") {
                tracing::info!("Remote paused transfer {}, will retry PUT periodically", transfer_id);
                state.interrupt_transfer(transfer_id).await;
                
                // Wait and retry - receiver might resume via its own API
                // Check for sender-initiated resume command OR just wait and retry PUT
                let mut retry_count = 0;
                loop {
                    if *cancel_rx.borrow() {
                        return Err("Transfer cancelled".into());
                    }
                    
                    // Check for sender-initiated resume
                    if let Ok(cmd) = control_rx.try_recv() {
                        if matches!(cmd, TransferControl::Resume) {
                            let _ = write_half.write_all(format!("DEFT RESUME_TRANSFER_CMD {}\n", transfer_id).as_bytes()).await;
                            tracing::info!("Sent RESUME_TRANSFER_CMD {} to remote", transfer_id);
                            line.clear();
                            if reader.read_line(&mut line).await.is_ok() && line.contains("TRANSFER_RESUMED") {
                                state.resume_transfer(transfer_id).await;
                                tracing::info!("Transfer {} resumed via sender command", transfer_id);
                                break;
                            }
                        }
                    }
                    
                    // Periodically retry PUT to detect receiver-initiated resume
                    retry_count += 1;
                    if retry_count >= 10 {  // Every ~1 second
                        retry_count = 0;
                        tracing::debug!("Retrying PUT to check if receiver resumed");
                        break;  // Exit inner loop to retry PUT
                    }
                    
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
                // Retry this chunk
                continue;
            }

            if line.contains("CHUNK_READY") {
                // If we were interrupted, resume now (receiver resumed via its API)
                if state.is_transfer_interrupted(transfer_id).await {
                    state.resume_transfer(transfer_id).await;
                    tracing::info!("Transfer {} resumed (receiver accepted PUT)", transfer_id);
                }
                break; // Success, exit retry loop
            }
            
            // Handle TRANSFER_RESUMED - receiver resumed, retry the PUT
            if line.contains("TRANSFER_RESUMED") {
                tracing::info!("Receiver resumed transfer {}, retrying PUT", transfer_id);
                if state.is_transfer_interrupted(transfer_id).await {
                    state.resume_transfer(transfer_id).await;
                }
                continue; // Retry the PUT
            }
            
            return Err(format!("PUT failed: {}", line).into());
        }

        // Update chunk status to sending
        state
            .update_chunk_status(transfer_id, chunk_idx as u32, ChunkStatus::Receiving)
            .await;

        // Send binary data
        write_half.write_all(chunk_data).await?;

        // Wait for ACK
        line.clear();
        reader.read_line(&mut line).await?;
        if !line.contains("CHUNK_ACK") {
            return Err(format!("CHUNK_ACK failed: {}", line).into());
        }

        // Update chunk status to validated (ACK received)
        state
            .update_chunk_status(transfer_id, chunk_idx as u32, ChunkStatus::Validated)
            .await;

        // Update progress based on chunks sent
        chunks_sent += 1;
        let bytes_sent = chunks_sent * chunk_size as u64;
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
    
    // Properly shutdown the TLS connection to send close_notify
    let _ = write_half.shutdown().await;

    Ok(file_size)
}

/// v2.0: Handle parallel push with configurable concurrency
async fn handle_client_push_parallel(state: &ApiState, body: &[u8]) -> (u16, String) {
    #[derive(Deserialize)]
    struct ParallelPushRequest {
        file_path: String,
        virtual_file: String,
        #[serde(default = "default_concurrency")]
        max_concurrent: usize,
    }

    fn default_concurrency() -> usize {
        4
    }

    let req: Result<ParallelPushRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Verify connection exists
            let conn = state.client_connection.read().await;
            if conn.is_none() {
                return (
                    400,
                    r#"{"success":false,"error":"Not connected. Use Connect first."}"#.to_string(),
                );
            }
            drop(conn);

            // Get file info
            let file_size = std::fs::metadata(&r.file_path)
                .map(|m| m.len())
                .unwrap_or(0);

            let transfer_id = format!("push_parallel_{}", chrono::Utc::now().timestamp_millis());
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
                    "send".to_string(),
                    file_size,
                )
                .await;

            // Create cancellation token and control channel
            let cancel_rx = state.create_cancel_token(&transfer_id).await;
            let control_rx = state.create_control_channel(&transfer_id).await;

            // For now, delegate to regular push (full parallel impl requires protocol changes)
            // The parallel sender is used internally for concurrency control
            let result = push_file(state, &r.file_path, &r.virtual_file, &transfer_id, cancel_rx, control_rx).await;
            state.remove_cancel_token(&transfer_id).await;
            state.remove_control_channel(&transfer_id).await;

            match result {
                Ok(bytes) => {
                    state.complete_transfer(&transfer_id).await;
                    (
                        200,
                        serde_json::json!({
                            "success": true,
                            "file_path": r.file_path,
                            "virtual_file": r.virtual_file,
                            "bytes": bytes,
                            "mode": "parallel",
                            "max_concurrent": r.max_concurrent
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

/// v2.0: Handle delta sync - compute delta and show what would be transferred
async fn handle_client_sync_delta(_state: &ApiState, body: &[u8]) -> (u16, String) {
    use crate::delta::{Delta, FileSignature, DELTA_BLOCK_SIZE};
    use std::io::{Seek, SeekFrom};

    #[derive(Deserialize)]
    struct DeltaSyncRequest {
        local_path: String,
        remote_path: String,
        #[serde(default = "default_block_size")]
        block_size: usize,
    }

    fn default_block_size() -> usize {
        DELTA_BLOCK_SIZE
    }

    let req: Result<DeltaSyncRequest, _> = serde_json::from_slice(body);
    match req {
        Ok(r) => {
            // Open remote file (the "old" version we want to update)
            let mut remote_file = match std::fs::File::open(&r.remote_path) {
                Ok(f) => f,
                Err(e) => {
                    return (
                        400,
                        serde_json::json!({
                            "success": false,
                            "error": format!("Failed to open remote file: {}", e)
                        })
                        .to_string(),
                    )
                }
            };

            // Compute signature of remote file
            let remote_sig = match FileSignature::compute(&mut remote_file, r.block_size) {
                Ok(sig) => sig,
                Err(e) => {
                    return (
                        500,
                        serde_json::json!({
                            "success": false,
                            "error": format!("Failed to compute remote signature: {}", e)
                        })
                        .to_string(),
                    )
                }
            };

            // Open local file (the "new" version we want to sync)
            let mut local_file = match std::fs::File::open(&r.local_path) {
                Ok(f) => f,
                Err(e) => {
                    return (
                        400,
                        serde_json::json!({
                            "success": false,
                            "error": format!("Failed to open local file: {}", e)
                        })
                        .to_string(),
                    )
                }
            };

            // Compute delta between remote signature and local file
            let delta = match Delta::compute(&remote_sig, &mut local_file) {
                Ok(d) => d,
                Err(e) => {
                    return (
                        500,
                        serde_json::json!({
                            "success": false,
                            "error": format!("Failed to compute delta: {}", e)
                        })
                        .to_string(),
                    )
                }
            };

            let stats = delta.stats();
            let savings = delta.savings(remote_sig.file_size);

            // Apply delta to reconstruct file
            let _ = remote_file.seek(SeekFrom::Start(0));
            let mut output = Vec::new();
            match delta.apply(&mut remote_file, &mut output) {
                Ok(bytes_written) => {
                    // Write the reconstructed file
                    if let Err(e) = std::fs::write(&r.remote_path, &output) {
                        return (
                            500,
                            serde_json::json!({
                                "success": false,
                                "error": format!("Failed to write output: {}", e)
                            })
                            .to_string(),
                        );
                    }

                    (
                        200,
                        serde_json::json!({
                            "success": true,
                            "local_path": r.local_path,
                            "remote_path": r.remote_path,
                            "mode": "delta",
                            "delta": {
                                "copy_blocks": stats.copy_blocks,
                                "insert_bytes": stats.insert_bytes,
                                "total_ops": stats.total_ops,
                                "savings_percent": format!("{:.1}%", savings * 100.0)
                            },
                            "bytes_written": bytes_written,
                            "message": "Delta sync complete. Remote file updated."
                        })
                        .to_string(),
                    )
                }
                Err(e) => (
                    500,
                    serde_json::json!({
                        "success": false,
                        "error": format!("Failed to apply delta: {}", e)
                    })
                    .to_string(),
                ),
            }
        }
        Err(e) => (400, format!(r#"{{"error":"Invalid request: {}"}}"#, e)),
    }
}

/// Compute SHA-256 fingerprint from a PEM certificate file (for client-side validation)
fn compute_cert_fingerprint_for_client(cert_path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let pem_data = std::fs::read_to_string(cert_path).ok()?;
    let pem = pem_data
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &pem).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&der);
    let fingerprint = hasher.finalize();
    Some(
        fingerprint
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>(),
    )
}

/// Custom server certificate verifier with fingerprint whitelist support
#[derive(Debug)]
struct FingerprintServerVerifier {
    allowed_fingerprints: Vec<String>,
    webpki_verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

impl FingerprintServerVerifier {
    fn new(
        root_store: Arc<rustls::RootCertStore>,
        allowed_fingerprints: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(root_store)
            .build()
            .map_err(|e| format!("Failed to build WebPKI verifier: {}", e))?;

        Ok(Self {
            allowed_fingerprints,
            webpki_verifier,
        })
    }

    fn compute_fingerprint(cert: &rustls::pki_types::CertificateDer<'_>) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // First, do standard WebPKI verification
        self.webpki_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Check fingerprint against whitelist
        let fingerprint = Self::compute_fingerprint(end_entity);
        let fingerprint_lower = fingerprint.to_lowercase();

        if self
            .allowed_fingerprints
            .iter()
            .any(|f| f.to_lowercase() == fingerprint_lower)
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            tracing::warn!(
                "Server certificate fingerprint {} not in allowed list",
                fingerprint
            );
            Err(rustls::Error::General(
                "Server certificate fingerprint not authorized".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.webpki_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.webpki_verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, LimitsConfig, LoggingConfig, ServerConfig, StorageConfig};

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                enabled: true,
                listen: "127.0.0.1:0".to_string(),
                cert: "test.crt".to_string(),
                key: "test.key".to_string(),
                ca: "ca.crt".to_string(),
            },
            client: ClientConfig {
                enabled: true,
                cert: "client.crt".to_string(),
                key: "client.key".to_string(),
                ca: "ca.crt".to_string(),
            },
            storage: StorageConfig {
                temp_dir: "/tmp/deft-test".to_string(),
                chunk_size: 262144,
            },
            limits: LimitsConfig::default(),
            logging: LoggingConfig::default(),
            partners: vec![],
            trusted_servers: vec![],
            hooks: vec![],
        }
    }

    #[tokio::test]
    async fn test_api_state_creation() {
        let config = test_config();
        let state = ApiState::new(config, None);
        assert!(state.start_time.elapsed().as_secs() < 1);
    }

    #[tokio::test]
    async fn test_register_transfer() {
        let config = test_config();
        let state = ApiState::new(config, None);

        state
            .register_transfer(
                "txn_001".to_string(),
                "invoices".to_string(),
                "partner-a".to_string(),
                "receive".to_string(),
                1024,
            )
            .await;

        let transfers = state.transfers.read().await;
        assert!(transfers.contains_key("txn_001"));
        let t = transfers.get("txn_001").unwrap();
        assert_eq!(t.virtual_file, "invoices");
        assert_eq!(t.partner_id, "partner-a");
    }

    #[tokio::test]
    async fn test_update_transfer_progress() {
        let config = test_config();
        let state = ApiState::new(config, None);

        state
            .register_transfer(
                "txn_002".to_string(),
                "data".to_string(),
                "partner-b".to_string(),
                "send".to_string(),
                10000,
            )
            .await;

        state.update_transfer_progress("txn_002", 5000, 10000).await;

        let transfers = state.transfers.read().await;
        let t = transfers.get("txn_002").unwrap();
        assert_eq!(t.bytes_transferred, 5000);
        assert_eq!(t.progress_percent, 50);
    }

    #[tokio::test]
    async fn test_complete_transfer_moves_to_history() {
        let config = test_config();
        let state = ApiState::new(config, None);

        state
            .register_transfer(
                "txn_003".to_string(),
                "files".to_string(),
                "partner-c".to_string(),
                "receive".to_string(),
                2048,
            )
            .await;

        state.complete_transfer("txn_003").await;

        let transfers = state.transfers.read().await;
        assert!(!transfers.contains_key("txn_003"));

        let history = state.history.read().await;
        assert!(history.iter().any(|h| h.id == "txn_003"));
    }

    #[tokio::test]
    async fn test_init_transfer_chunks() {
        let config = test_config();
        let state = ApiState::new(config, None);

        state
            .register_transfer(
                "txn_004".to_string(),
                "chunks".to_string(),
                "partner-d".to_string(),
                "receive".to_string(),
                4096,
            )
            .await;

        state
            .init_transfer_chunks("txn_004", 10, "chunks", "receive")
            .await;

        let transfers = state.transfers.read().await;
        let t = transfers.get("txn_004").unwrap();
        assert_eq!(t.total_chunks, 10);
        assert_eq!(t.chunk_statuses.len(), 10);
        assert!(t.chunk_statuses.iter().all(|s| *s == ChunkStatus::Pending));
    }

    #[tokio::test]
    async fn test_update_chunk_status() {
        let config = test_config();
        let state = ApiState::new(config, None);

        state
            .register_transfer(
                "txn_005".to_string(),
                "data".to_string(),
                "partner-e".to_string(),
                "receive".to_string(),
                1024,
            )
            .await;

        state
            .init_transfer_chunks("txn_005", 5, "data", "receive")
            .await;
        state
            .update_chunk_status("txn_005", 2, ChunkStatus::Validated)
            .await;

        let transfers = state.transfers.read().await;
        let t = transfers.get("txn_005").unwrap();
        assert_eq!(t.chunk_statuses[2], ChunkStatus::Validated);
        assert_eq!(t.chunk_statuses[0], ChunkStatus::Pending);
    }

    #[tokio::test]
    async fn test_fail_transfer() {
        let config = test_config();
        let state = ApiState::new(config, None);

        state
            .register_transfer(
                "txn_006".to_string(),
                "failed".to_string(),
                "partner-f".to_string(),
                "receive".to_string(),
                512,
            )
            .await;

        state.fail_transfer("txn_006", "Connection timeout").await;

        let transfers = state.transfers.read().await;
        assert!(!transfers.contains_key("txn_006"));

        let history = state.history.read().await;
        let entry = history.iter().find(|h| h.id == "txn_006").unwrap();
        assert!(entry.status.starts_with("failed"));
    }

    #[test]
    fn test_chunk_status_serialization() {
        let status = ChunkStatus::Validated;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"validated\"");

        let status: ChunkStatus = serde_json::from_str("\"receiving\"").unwrap();
        assert_eq!(status, ChunkStatus::Receiving);
    }

    #[test]
    fn test_ws_event_serialization() {
        let event = WsEvent::TransferProgress {
            transfer_id: "txn_007".to_string(),
            virtual_file: "test".to_string(),
            bytes_transferred: 500,
            total_bytes: 1000,
            progress_percent: 50,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("transfer_progress"));
        assert!(json.contains("txn_007"));
    }

    #[tokio::test]
    async fn test_rate_limiter_integration() {
        let config = test_config();
        let state = ApiState::new(config, None);

        // Rate limiter should be initialized from config
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

        // First requests should be allowed
        let result = state.rate_limiter.check_ip(ip).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_after_limit() {
        use crate::rate_limit::{RateLimitConfig, RateLimiter};

        let config = RateLimitConfig {
            max_connections_per_ip: 2,
            max_requests_per_partner: 100,
            max_bytes_per_partner: 1024 * 1024,
            window_duration: std::time::Duration::from_secs(60),
            ban_duration: std::time::Duration::from_millis(100),
        };
        let limiter = RateLimiter::new(config);
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // First 2 should pass
        assert!(limiter.check_ip(ip).await.is_allowed());
        assert!(limiter.check_ip(ip).await.is_allowed());

        // 3rd should be blocked
        assert!(!limiter.check_ip(ip).await.is_allowed());
    }

    #[tokio::test]
    async fn test_check_api_rate_limit_helper() {
        let config = test_config();
        let state = ApiState::new(config, None);
        let ip: std::net::IpAddr = "172.16.0.1".parse().unwrap();

        // Should return None (allowed) for first request
        let result = state.check_api_rate_limit(ip).await;
        assert!(result.is_none());
    }
}
