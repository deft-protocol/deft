//! Command handler for DEFT protocol.
//!
//! Some methods reserved for sender-side completion.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use deft_protocol::{
    AckStatus, Capabilities, Command, DeftErrorCode, Parser, Response, DEFT_VERSION,
};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::api::ApiState;
use crate::chunk_store::ChunkStore;
use crate::compression::decompress;
use crate::config::{Config, Direction};
use crate::hooks::{HookContext, HookEvent, HookManager};
use crate::metrics;
use crate::parallel::ParallelConfig;
use crate::receipt::ReceiptStore;
use crate::session::{Session, SessionState};
use crate::signer::ReceiptSigner;
use crate::transfer::TransferManager;
use crate::transfer_state::TransferStateStore;
use crate::virtual_file::VirtualFileManager;

pub struct CommandHandler {
    config: Config,
    vf_manager: VirtualFileManager,
    transfer_manager: Arc<TransferManager>,
    receipt_store: Arc<ReceiptStore>,
    chunk_store: Arc<ChunkStore>,
    hook_manager: Arc<HookManager>,
    signer: Arc<ReceiptSigner>,
    api_state: Option<Arc<ApiState>>,
    transfer_state_store: Arc<TransferStateStore>,
    parallel_config: ParallelConfig,
}

impl CommandHandler {
    pub fn new(config: Config) -> Self {
        Self::with_api_state(config, None)
    }

    pub fn with_api_state(config: Config, api_state: Option<Arc<ApiState>>) -> Self {
        let vf_manager = VirtualFileManager::new(config.storage.chunk_size);
        let transfer_manager = Arc::new(TransferManager::new());
        let receipt_store = Arc::new(
            ReceiptStore::new(config.storage.temp_dir.replace("tmp", "receipts"))
                .unwrap_or_else(|_| ReceiptStore::default()),
        );
        let chunk_store = Arc::new(
            ChunkStore::new(&config.storage.temp_dir).expect("Failed to initialize chunk store"),
        );

        // Initialize hook manager from config
        let hook_manager = Arc::new(HookManager::from_configs(config.hooks.clone()));

        // Initialize receipt signer (try Ed25519, fallback to SHA256)
        let signer = Arc::new(ReceiptSigner::with_new_ed25519_key().unwrap_or_else(|_| {
            warn!("Failed to generate Ed25519 key, using SHA256 for receipts");
            ReceiptSigner::new()
        }));

        // Initialize transfer state store for resumable transfers
        // Use parent directory of temp_dir + "transfer_states" to avoid replacing /tmp in path
        let transfer_states_dir = std::path::Path::new(&config.storage.temp_dir)
            .parent()
            .map(|p| p.join("transfer_states"))
            .unwrap_or_else(|| std::path::PathBuf::from("./transfer_states"));
        let transfer_state_store = Arc::new(
            TransferStateStore::new(&transfer_states_dir)
                .expect("Failed to initialize transfer state store"),
        );

        // Initialize parallel transfer config
        let parallel_config = ParallelConfig::default();

        // Register virtual files for all partners
        for partner in &config.partners {
            for vf in &partner.virtual_files {
                if let Err(e) = vf_manager.register(vf) {
                    warn!("Failed to register virtual file {}: {}", vf.name, e);
                }
            }
        }

        Self {
            config,
            vf_manager,
            transfer_manager,
            receipt_store,
            chunk_store,
            hook_manager,
            signer,
            api_state,
            transfer_state_store,
            parallel_config,
        }
    }

    pub fn register_transfer_to_api(
        &self,
        id: &str,
        vf: &str,
        partner: &str,
        direction: &str,
        total_bytes: u64,
    ) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            let vf = vf.to_string();
            let partner = partner.to_string();
            let direction = direction.to_string();
            tokio::spawn(async move {
                api.register_transfer(id, vf, partner, direction, total_bytes)
                    .await;
            });
        }
    }

    pub fn init_transfer_chunks_to_api(
        &self,
        id: &str,
        total_chunks: u32,
        vf: &str,
        direction: &str,
    ) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            let vf = vf.to_string();
            let direction = direction.to_string();
            tokio::spawn(async move {
                api.init_transfer_chunks(&id, total_chunks, &vf, &direction)
                    .await;
            });
        }
    }

    pub fn update_chunk_status_to_api(
        &self,
        id: &str,
        chunk_index: u32,
        status: crate::api::ChunkStatus,
    ) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                api.update_chunk_status(&id, chunk_index, status).await;
            });
        }
    }

    pub fn update_transfer_progress_to_api(&self, id: &str, bytes: u64, total: u64) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                api.update_transfer_progress(&id, bytes, total).await;
            });
        }
    }

    pub fn complete_transfer_to_api(&self, id: &str) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                api.complete_transfer(&id).await;
                // Remove after 30 seconds
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                api.remove_transfer(&id).await;
            });
        }
    }

    pub fn fail_transfer_to_api(&self, id: &str, error: &str) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            let error = error.to_string();
            tokio::spawn(async move {
                api.fail_transfer(&id, &error).await;
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                api.remove_transfer(&id).await;
            });
        }
    }

    /// Sync transfer pause state to API (called when remote sends PAUSE_TRANSFER)
    pub fn pause_transfer_to_api(&self, id: &str) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                api.interrupt_transfer(&id).await;
            });
        }
    }

    /// Sync transfer resume state to API (called when remote sends RESUME_TRANSFER_CMD)
    pub fn resume_transfer_to_api(&self, id: &str) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            tokio::spawn(async move {
                api.resume_transfer(&id).await;
            });
        }
    }

    /// Sync transfer abort state to API (called when remote sends ABORT_TRANSFER)
    pub fn abort_transfer_to_api(&self, id: &str, reason: Option<String>) {
        if let Some(ref api) = self.api_state {
            let api = api.clone();
            let id = id.to_string();
            let error = reason.unwrap_or_else(|| "Aborted by remote".to_string());
            tokio::spawn(async move {
                api.fail_transfer(&id, &error).await;
            });
        }
    }

    /// Persist chunk received for resumable transfers
    fn persist_chunk_received(&self, transfer_id: &str, chunk_index: u64) {
        if let Ok(mut state) = self.transfer_state_store.load(transfer_id) {
            state.mark_chunk_received(chunk_index);
            if let Err(e) = self.transfer_state_store.save(&state) {
                warn!("Failed to persist transfer state: {}", e);
            }
        }
    }

    /// Get parallel config for transfer operations
    pub fn parallel_config(&self) -> &ParallelConfig {
        &self.parallel_config
    }

    /// Get transfer state store for resume operations
    pub fn transfer_state_store(&self) -> &Arc<TransferStateStore> {
        &self.transfer_state_store
    }

    /// Execute a hook asynchronously
    fn execute_hook(&self, ctx: HookContext) {
        let hook_manager = self.hook_manager.clone();
        tokio::spawn(async move {
            let results = hook_manager.execute(&ctx).await;
            for result in results {
                if !result.success {
                    warn!("Hook failed: {}", result.stderr);
                }
            }
        });
    }

    pub fn handle_line(&self, session: &mut Session, line: &str) -> Response {
        match Parser::parse_command(line) {
            Ok(command) => self.handle_command(session, command),
            Err(e) => {
                warn!("Parse error: {}", e);
                Response::error(DeftErrorCode::BadRequest, Some(e.to_string()))
            }
        }
    }

    pub fn handle_command(&self, session: &mut Session, command: Command) -> Response {
        debug!(
            "Handling command: {:?} in state {:?}",
            command, session.state
        );

        match command {
            Command::Hello {
                version,
                capabilities,
            } => self.handle_hello(session, version, capabilities),
            Command::Auth { partner_id } => self.handle_auth(session, partner_id),
            Command::Discover => self.handle_discover(session),
            Command::Describe { virtual_file } => self.handle_describe(session, virtual_file),
            Command::Get {
                virtual_file,
                chunks,
            } => self.handle_get(session, virtual_file, chunks),
            Command::BeginTransfer {
                virtual_file,
                total_chunks,
                total_bytes,
                file_hash,
            } => self.handle_begin_transfer(
                session,
                virtual_file,
                total_chunks,
                total_bytes,
                file_hash,
            ),
            Command::ResumeTransfer {
                virtual_file,
                transfer_id,
            } => self.handle_resume_transfer(session, virtual_file, transfer_id),
            Command::GetStatus { virtual_file } => self.handle_get_status(session, virtual_file),
            Command::Put {
                virtual_file,
                chunk_index,
                size,
                hash,
                nonce,
                compressed,
            } => self.handle_put(
                session,
                virtual_file,
                chunk_index,
                size,
                hash,
                nonce,
                compressed,
            ),
            Command::Bye => self.handle_bye(session),
            Command::DeltaSigReq {
                virtual_file,
                block_size,
            } => self.handle_delta_sig_req(session, virtual_file, block_size),
            Command::DeltaPut {
                virtual_file,
                delta_data,
                final_hash,
            } => self.handle_delta_put(session, virtual_file, delta_data, final_hash),
            Command::PauseTransfer { transfer_id } => {
                self.handle_pause_transfer(session, transfer_id)
            }
            Command::ResumeTransferCmd { transfer_id } => {
                self.handle_resume_transfer_cmd(session, transfer_id)
            }
            Command::AbortTransfer { transfer_id, reason } => {
                self.handle_abort_transfer(session, transfer_id, reason)
            }
        }
    }

    fn handle_hello(
        &self,
        session: &mut Session,
        version: String,
        client_caps: Capabilities,
    ) -> Response {
        if session.state != SessionState::Connected {
            return Response::error(
                DeftErrorCode::BadRequest,
                Some("Unexpected HELLO".to_string()),
            );
        }

        // Check version compatibility
        if !version.starts_with("1.") {
            return Response::error(
                DeftErrorCode::UpgradeRequired,
                Some(format!(
                    "Unsupported version: {}. Server supports 1.x",
                    version
                )),
            );
        }

        // Negotiate capabilities
        let server_caps = Capabilities::all();
        let negotiated = server_caps.intersect(&client_caps);

        session.set_welcomed(DEFT_VERSION.to_string(), negotiated.clone());

        Response::welcome(DEFT_VERSION, negotiated, &session.id)
    }

    fn handle_auth(&self, session: &mut Session, partner_id: String) -> Response {
        if session.state != SessionState::Welcomed {
            return Response::error(
                DeftErrorCode::BadRequest,
                Some("Must HELLO before AUTH".to_string()),
            );
        }

        let partner = match self.config.find_partner(&partner_id) {
            Some(p) => p,
            None => {
                return Response::error(
                    DeftErrorCode::Unauthorized,
                    Some(format!("Unknown partner: {}", partner_id)),
                );
            }
        };

        // mTLS validation: verify certificate CN matches partner_id
        if let Some(cert_cn) = session.get_cert_cn() {
            if cert_cn != partner_id {
                warn!(
                    "mTLS CN mismatch: cert CN '{}' != partner_id '{}'",
                    cert_cn, partner_id
                );
                return Response::error(
                    DeftErrorCode::Unauthorized,
                    Some(format!(
                        "Certificate CN '{}' does not match partner ID '{}'",
                        cert_cn, partner_id
                    )),
                );
            }
            info!("mTLS CN validation passed: {}", cert_cn);
        } else {
            warn!("No client certificate CN available for mTLS validation");
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Client certificate must have a CN that matches partner ID".to_string()),
            );
        }

        // mTLS validation: verify certificate fingerprint is in allowed_certs
        if !partner.allowed_certs.is_empty() {
            if let Some(fingerprint) = session.get_cert_fingerprint() {
                let fingerprint_lower = fingerprint.to_lowercase();
                let allowed = partner.allowed_certs.iter().any(|c| {
                    // Support both raw fingerprints and certificate file paths
                    let allowed_fp =
                        if c.contains('/') || c.ends_with(".crt") || c.ends_with(".pem") {
                            // It's a file path - compute fingerprint from cert file
                            compute_cert_fingerprint(c).unwrap_or_default()
                        } else {
                            // It's already a fingerprint (with or without colons)
                            c.replace(':', "").to_lowercase()
                        };
                    allowed_fp == fingerprint_lower
                });

                if !allowed {
                    warn!(
                        "mTLS fingerprint not in allowed_certs for partner {}: {}",
                        partner_id, fingerprint
                    );
                    return Response::error(
                        DeftErrorCode::Unauthorized,
                        Some("Certificate fingerprint not authorized for this partner".to_string()),
                    );
                }
                info!(
                    "mTLS fingerprint validation passed for partner {}: {}",
                    partner_id, fingerprint
                );
            } else {
                warn!("No client certificate fingerprint available for mTLS validation");
                return Response::error(
                    DeftErrorCode::Unauthorized,
                    Some("Client certificate required for this partner".to_string()),
                );
            }
        }

        let virtual_files: Vec<String> = partner
            .virtual_files
            .iter()
            .map(|vf| vf.name.clone())
            .collect();

        let partner_name = partner_id.clone();

        session.set_authenticated(partner_id, partner_name.clone(), virtual_files.clone());

        Response::auth_ok(partner_name, virtual_files)
    }

    fn handle_discover(&self, session: &Session) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        let files = self
            .vf_manager
            .list_for_partner(&session.allowed_virtual_files);

        Response::Files { files }
    }

    fn handle_describe(&self, session: &mut Session, virtual_file: String) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        match self.vf_manager.compute_chunks(&virtual_file) {
            Ok((info, chunks)) => {
                // Register outbound transfer for tracking
                let transfer_id = format!(
                    "pull-{}-{}",
                    session.id,
                    chrono::Utc::now().timestamp_millis()
                );
                let partner_id = session.partner_id.clone().unwrap_or_default();

                // Store transfer info in session for tracking
                session.active_pull_transfer = Some(transfer_id.clone());
                session.active_pull_vf = Some(virtual_file.clone());
                session.pull_total_chunks = info.chunk_count;
                session.pull_chunks_sent = 0;

                // Register in API state
                self.register_transfer_to_api(
                    &transfer_id,
                    &virtual_file,
                    &partner_id,
                    "send",
                    info.size,
                );

                Response::FileInfo { info, chunks }
            }
            Err(e) => Response::error(
                DeftErrorCode::InternalServerError,
                Some(format!("Failed to describe file: {}", e)),
            ),
        }
    }

    fn handle_get(
        &self,
        session: &mut Session,
        virtual_file: String,
        chunks: deft_protocol::ChunkRange,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        match self.vf_manager.read_chunk(&virtual_file, chunks.start) {
            Ok(data) => {
                // Track pull transfer progress
                session.pull_chunks_sent += 1;

                // Update API progress
                if let Some(ref transfer_id) = session.active_pull_transfer {
                    let total = session.pull_total_chunks;
                    let sent = session.pull_chunks_sent;
                    let bytes = sent * 262144; // Approximate
                    let total_bytes = total * 262144;
                    self.update_transfer_progress_to_api(transfer_id, bytes, total_bytes);

                    // Complete transfer when all chunks sent
                    if sent >= total {
                        self.complete_transfer_to_api(transfer_id);
                        session.active_pull_transfer = None;
                    }
                }

                Response::ChunkData {
                    virtual_file,
                    chunk_index: chunks.start,
                    data,
                }
            }
            Err(e) => Response::error(
                DeftErrorCode::InternalServerError,
                Some(format!("Failed to read chunk: {}", e)),
            ),
        }
    }

    fn handle_begin_transfer(
        &self,
        session: &mut Session,
        virtual_file: String,
        total_chunks: u64,
        total_bytes: u64,
        file_hash: String,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Create chunk hashes placeholder - in real impl, client would send these
        // For now, we'll accept chunks without pre-known hashes
        let chunk_hashes: Vec<(u64, String)> =
            (0..total_chunks).map(|i| (i, String::new())).collect();

        let sender = session.partner_id.clone().unwrap_or_default();
        let transfer = crate::transfer::ActiveTransfer::new_receive(
            virtual_file.clone(),
            sender,
            "self".to_string(),
            total_chunks,
            total_bytes,
            self.config.storage.chunk_size,
            file_hash,
            chunk_hashes,
            session.window_size,
        );

        let transfer_id = self.transfer_manager.start_transfer(transfer);
        session.add_transfer(transfer_id.clone());

        // Register transfer to API dashboard
        self.register_transfer_to_api(
            &transfer_id,
            &virtual_file,
            session.partner_id.as_deref().unwrap_or("unknown"),
            "receive",
            total_bytes,
        );

        // Initialize chunk tracking for UI
        self.init_transfer_chunks_to_api(
            &transfer_id,
            total_chunks as u32,
            &virtual_file,
            "receive",
        );

        info!(
            "Transfer started: {} for {} ({} chunks, {} bytes)",
            transfer_id, virtual_file, total_chunks, total_bytes
        );

        // Execute pre-transfer hook
        let ctx = HookContext::new(HookEvent::PreTransfer)
            .with_transfer(&transfer_id)
            .with_partner(session.partner_id.as_deref().unwrap_or("unknown"))
            .with_virtual_file(&virtual_file)
            .with_size(total_bytes);
        self.execute_hook(ctx);

        Response::TransferAccepted {
            transfer_id,
            virtual_file,
            window_size: session.window_size,
        }
    }

    fn handle_resume_transfer(
        &self,
        session: &mut Session,
        virtual_file: String,
        transfer_id: String,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Check if transfer exists in TransferManager
        if let Some(transfer) = self.transfer_manager.get_transfer(&transfer_id) {
            if transfer.virtual_file != virtual_file {
                return Response::error(
                    DeftErrorCode::BadRequest,
                    Some("Transfer ID does not match virtual file".to_string()),
                );
            }

            // Add transfer to session if not already tracked
            if !session.active_transfer_ids.contains(&transfer_id) {
                session.add_transfer(transfer_id.clone());
            }

            info!("Resuming transfer: {} for {}", transfer_id, virtual_file);

            Response::TransferAccepted {
                transfer_id,
                virtual_file,
                window_size: session.window_size,
            }
        } else {
            Response::error(
                DeftErrorCode::NotFound,
                Some(format!("Transfer not found: {}", transfer_id)),
            )
        }
    }

    fn handle_get_status(&self, session: &Session, virtual_file: String) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Find active transfer for this virtual file
        let transfer_id = self.find_transfer_for_file(session, &virtual_file);

        match transfer_id {
            Some(id) => {
                if let Some(transfer) = self.transfer_manager.get_transfer(&id) {
                    let received: Vec<u64> = transfer
                        .chunks
                        .iter()
                        .filter(|(_, c)| c.state == crate::transfer::ChunkState::Validated)
                        .map(|(idx, _)| *idx)
                        .collect();
                    let pending: Vec<u64> = (0..transfer.total_chunks)
                        .filter(|i| !received.contains(i))
                        .collect();

                    Response::TransferStatus {
                        transfer_id: id,
                        virtual_file,
                        total_chunks: transfer.total_chunks,
                        received_chunks: received.len() as u64,
                        pending_chunks: pending,
                    }
                } else {
                    Response::error(
                        DeftErrorCode::NotFound,
                        Some(format!("Transfer not found for: {}", virtual_file)),
                    )
                }
            }
            None => Response::error(
                DeftErrorCode::NotFound,
                Some(format!("No active transfer for: {}", virtual_file)),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_put(
        &self,
        session: &mut Session,
        virtual_file: String,
        chunk_index: u64,
        size: u64,
        expected_hash: String,
        _nonce: Option<u64>,
        compressed: bool,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Track compressed flag for binary data reception
        session.last_chunk_compressed = compressed;

        // Find active transfer for this virtual file
        let transfer_id = self.find_transfer_for_file(session, &virtual_file);

        match transfer_id {
            Some(id) => {
                // Store expected hash for later validation when data arrives
                self.update_chunk_hash(&id, chunk_index, &expected_hash);

                // Return ChunkReady to signal server is ready to receive binary data
                Response::ChunkReady {
                    virtual_file,
                    chunk_index,
                    size,
                }
            }
            None => Response::error(
                DeftErrorCode::BadRequest,
                Some(format!(
                    "No active transfer for: {}. Use BEGIN_TRANSFER first.",
                    virtual_file
                )),
            ),
        }
    }

    fn find_transfer_for_file(&self, session: &Session, virtual_file: &str) -> Option<String> {
        for transfer_id in &session.active_transfer_ids {
            if let Some(transfer) = self.transfer_manager.get_transfer(transfer_id) {
                if transfer.virtual_file == virtual_file {
                    return Some(transfer_id.clone());
                }
            }
        }
        None
    }

    fn update_chunk_hash(&self, transfer_id: &str, chunk_index: u64, hash: &str) {
        self.transfer_manager
            .update_chunk_hash(transfer_id, chunk_index, hash);
    }

    pub fn handle_chunk_received(
        &self,
        session: &mut Session,
        virtual_file: &str,
        chunk_index: u64,
        data: &[u8],
        _expected_hash: &str,
        compressed: bool,
    ) -> Response {
        // Decompress if needed
        let chunk_data: Vec<u8> = if compressed {
            match decompress(data) {
                Ok(decompressed) => decompressed,
                Err(e) => {
                    warn!("Failed to decompress chunk {}: {}", chunk_index, e);
                    metrics::record_chunk_failed("decompress_error");
                    return Response::ChunkAck {
                        virtual_file: virtual_file.to_string(),
                        chunk_index,
                        status: AckStatus::Error(deft_protocol::AckErrorReason::HashMismatch),
                    };
                }
            }
        } else {
            data.to_vec()
        };
        let data = &chunk_data;
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Find active transfer and validate chunk
        let transfer_id = self.find_transfer_for_file(session, virtual_file);

        match transfer_id {
            Some(id) => {
                // Validate chunk using TransferManager
                let status = self
                    .transfer_manager
                    .validate_chunk(&id, chunk_index, data)
                    .unwrap_or(AckStatus::Error(deft_protocol::AckErrorReason::Unknown));

                // If validation succeeded, store chunk to disk
                if status == AckStatus::Ok {
                    if let Err(e) = self.chunk_store.store_chunk(&id, chunk_index, data) {
                        warn!(
                            "Failed to store chunk {} for transfer {}: {}",
                            chunk_index, id, e
                        );
                        metrics::record_chunk_failed("io_error");
                        return Response::ChunkAck {
                            virtual_file: virtual_file.to_string(),
                            chunk_index,
                            status: AckStatus::Error(deft_protocol::AckErrorReason::IoError),
                        };
                    }
                    metrics::record_chunk_received();

                    // Persist transfer state for resumable transfers
                    self.persist_chunk_received(&id, chunk_index);

                    // Update chunk status in UI (Validated = chunk received and hash verified)
                    self.update_chunk_status_to_api(
                        &id,
                        chunk_index as u32,
                        crate::api::ChunkStatus::Validated,
                    );

                    // Update progress in API dashboard
                    if let Some(transfer) = self.transfer_manager.get_transfer(&id) {
                        let validated = transfer
                            .chunks
                            .values()
                            .filter(|c| c.state == crate::transfer::ChunkState::Validated)
                            .count() as u64;
                        let total_bytes = transfer.total_bytes;
                        let total_chunks = transfer.chunks.len() as u64;
                        let bytes_received = validated * transfer.chunk_size as u64;
                        tracing::debug!(
                            "Transfer {} progress: {}/{} chunks validated, {} bytes",
                            id,
                            validated,
                            total_chunks,
                            bytes_received
                        );
                        self.update_transfer_progress_to_api(&id, bytes_received, total_bytes);
                    } else {
                        tracing::warn!("Transfer {} not found in transfer_manager", id);
                    }
                } else {
                    metrics::record_chunk_failed("validation");
                }

                Response::ChunkAck {
                    virtual_file: virtual_file.to_string(),
                    chunk_index,
                    status,
                }
            }
            None => Response::ChunkAck {
                virtual_file: virtual_file.to_string(),
                chunk_index,
                status: AckStatus::Error(deft_protocol::AckErrorReason::Unknown),
            },
        }
    }

    pub fn check_transfer_complete(
        &self,
        session: &mut Session,
        virtual_file: &str,
    ) -> Option<Response> {
        let transfer_id = self.find_transfer_for_file(session, virtual_file)?;

        if self.transfer_manager.is_complete(&transfer_id) {
            // Get transfer info before completing
            let transfer = self.transfer_manager.get_transfer(&transfer_id)?;
            let total_chunks = transfer.total_chunks;
            let total_bytes = transfer.total_bytes;
            let chunk_size = transfer.chunk_size;

            // Find output path from virtual file config
            let output_path = self.get_virtual_file_path(session, virtual_file);

            // Assemble the final file from chunks
            if let Some(ref path) = output_path {
                match self.chunk_store.assemble_file(
                    &transfer_id,
                    path,
                    total_chunks,
                    chunk_size,
                    total_bytes,
                ) {
                    Ok(()) => {
                        info!("Assembled file: {:?}", path);
                        // Cleanup chunk files after successful assembly
                        if let Err(e) = self.chunk_store.cleanup_transfer(&transfer_id) {
                            warn!("Failed to cleanup chunks: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to assemble file: {}", e);
                        // Mark transfer as failed in API
                        self.fail_transfer_to_api(&transfer_id, &e.to_string());
                        // Execute error hook
                        let ctx = HookContext::new(HookEvent::TransferError)
                            .with_transfer(&transfer_id)
                            .with_partner(session.partner_id.as_deref().unwrap_or("unknown"))
                            .with_virtual_file(virtual_file)
                            .with_path(path)
                            .with_error(&e.to_string());
                        self.execute_hook(ctx);
                    }
                }
            }

            // Complete the transfer and get the receipt
            let mut receipt = self.transfer_manager.complete_transfer(&transfer_id)?;

            // Sign the receipt
            let receipt_json = serde_json::to_string(&receipt).unwrap_or_default();
            if let Some(sig) = self.signer.sign_receipt(&receipt_json) {
                receipt.signature = Some(sig);
            }

            // Store the receipt
            if let Err(e) = self.receipt_store.store(&receipt) {
                warn!("Failed to store receipt: {}", e);
            }

            // Record metrics
            metrics::record_transfer_complete("receive", true, receipt.total_bytes, 0.0);

            // Mark transfer complete in API dashboard
            self.complete_transfer_to_api(&transfer_id);

            // Execute post-transfer hook with path if available
            let mut ctx = HookContext::new(HookEvent::PostTransfer)
                .with_transfer(&transfer_id)
                .with_partner(session.partner_id.as_deref().unwrap_or("unknown"))
                .with_virtual_file(&receipt.virtual_file)
                .with_size(receipt.total_bytes);
            if let Some(ref path) = output_path {
                ctx = ctx.with_path(path);
            }
            self.execute_hook(ctx);

            // Execute file_received hook with path if available
            let mut ctx = HookContext::new(HookEvent::FileReceived)
                .with_transfer(&transfer_id)
                .with_partner(session.partner_id.as_deref().unwrap_or("unknown"))
                .with_virtual_file(&receipt.virtual_file)
                .with_size(receipt.total_bytes);
            if let Some(ref path) = output_path {
                ctx = ctx.with_path(path);
            }
            self.execute_hook(ctx);

            // Remove transfer from session
            session.remove_transfer(&transfer_id);

            info!(
                "Transfer complete: {} ({} bytes, {} chunks)",
                receipt.virtual_file, receipt.total_bytes, receipt.chunks_total
            );

            Some(Response::TransferComplete {
                virtual_file: receipt.virtual_file,
                file_hash: receipt.file_hash,
                total_size: receipt.total_bytes,
                chunk_count: receipt.chunks_total,
                signature: receipt.signature,
            })
        } else {
            None
        }
    }

    fn get_virtual_file_path(&self, session: &Session, virtual_file: &str) -> Option<PathBuf> {
        let partner_id = session.partner_id.as_ref()?;
        let partner = self.config.find_partner(partner_id)?;

        for vf in &partner.virtual_files {
            if vf.name == virtual_file && vf.direction == Direction::Receive {
                // Generate unique filename in the configured path
                let base_path = PathBuf::from(&vf.path);
                let filename = format!(
                    "{}_{}.dat",
                    virtual_file,
                    chrono::Utc::now().format("%Y%m%d_%H%M%S")
                );
                return Some(base_path.join(filename));
            }
        }
        None
    }

    pub fn complete_transfer(
        &self,
        session: &mut Session,
        virtual_file: &str,
        file_hash: &str,
        total_size: u64,
        chunk_count: u64,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        let sender = session.partner_id.clone().unwrap_or_default();
        let receiver = "self".to_string(); // This server

        let receipt = deft_protocol::TransferReceipt {
            transfer_id: format!("{}-{}", session.id, virtual_file),
            virtual_file: virtual_file.to_string(),
            sender_partner: sender,
            receiver_partner: receiver,
            timestamp_start: String::new(),
            timestamp_complete: String::new(),
            chunks_total: chunk_count,
            total_bytes: total_size,
            file_hash: file_hash.to_string(),
            signature: None,
        };

        // Store receipt
        if let Err(e) = self.receipt_store.store(&receipt) {
            warn!("Failed to store receipt: {}", e);
        } else {
            info!(
                "Transfer complete: {} ({} bytes, {} chunks)",
                virtual_file, total_size, chunk_count
            );
        }

        // Generate cryptographic signature for non-repudiation
        let signature_data = format!(
            "{}:{}:{}:{}",
            virtual_file, file_hash, total_size, chunk_count
        );
        let signature = self.signer.sign_receipt(&signature_data);

        Response::TransferComplete {
            virtual_file: virtual_file.to_string(),
            file_hash: file_hash.to_string(),
            total_size,
            chunk_count,
            signature,
        }
    }

    fn handle_bye(&self, session: &mut Session) -> Response {
        // Complete any pending pull transfer when session ends
        if let Some(ref transfer_id) = session.active_pull_transfer {
            self.complete_transfer_to_api(transfer_id);
        }
        session.close();
        Response::Goodbye
    }

    /// v2.0: Handle delta signature request - compute and return file signature
    fn handle_delta_sig_req(
        &self,
        session: &Session,
        virtual_file: String,
        block_size: usize,
    ) -> Response {
        use crate::delta::FileSignature;
        use base64::Engine;

        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Find the file path for this virtual file
        let file_path = match self.resolve_virtual_file_path(session, &virtual_file) {
            Some(p) => p,
            None => {
                // File doesn't exist - return empty signature indicating new file
                return Response::DeltaSig {
                    virtual_file,
                    signature_data: String::new(),
                    file_exists: false,
                };
            }
        };

        // Compute file signature
        match std::fs::File::open(&file_path) {
            Ok(mut file) => match FileSignature::compute(&mut file, block_size) {
                Ok(sig) => {
                    // Serialize signature to JSON then base64
                    let json = serde_json::to_string(&sig).unwrap_or_default();
                    let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
                    Response::DeltaSig {
                        virtual_file,
                        signature_data: b64,
                        file_exists: true,
                    }
                }
                Err(e) => Response::error(
                    DeftErrorCode::InternalServerError,
                    Some(format!("Failed to compute signature: {}", e)),
                ),
            },
            Err(_) => Response::DeltaSig {
                virtual_file,
                signature_data: String::new(),
                file_exists: false,
            },
        }
    }

    /// v2.0: Handle delta put - apply delta to update existing file
    fn handle_delta_put(
        &self,
        session: &mut Session,
        virtual_file: String,
        delta_data: String,
        expected_hash: String,
    ) -> Response {
        use crate::delta::Delta;
        use base64::Engine;

        if !session.is_authenticated() {
            return Response::error(
                DeftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                DeftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Decode delta from base64
        let delta_json = match base64::engine::general_purpose::STANDARD.decode(&delta_data) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => {
                    return Response::error(
                        DeftErrorCode::BadRequest,
                        Some(format!("Invalid delta encoding: {}", e)),
                    )
                }
            },
            Err(e) => {
                return Response::error(
                    DeftErrorCode::BadRequest,
                    Some(format!("Invalid base64: {}", e)),
                )
            }
        };

        // Parse delta
        let delta: Delta = match serde_json::from_str(&delta_json) {
            Ok(d) => d,
            Err(e) => {
                return Response::error(
                    DeftErrorCode::BadRequest,
                    Some(format!("Invalid delta JSON: {}", e)),
                )
            }
        };

        // Get file path
        let file_path = match self.resolve_virtual_file_path_for_write(session, &virtual_file) {
            Some(p) => p,
            None => {
                return Response::error(
                    DeftErrorCode::NotFound,
                    Some(format!("Cannot resolve path for: {}", virtual_file)),
                )
            }
        };

        // Open source file and apply delta
        let mut source_file = match std::fs::File::open(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return Response::error(
                    DeftErrorCode::NotFound,
                    Some(format!("Source file not found: {}", e)),
                )
            }
        };

        let mut output = Vec::new();
        match delta.apply(&mut source_file, &mut output) {
            Ok(bytes_written) => {
                // Verify hash
                let mut hasher = Sha256::new();
                hasher.update(&output);
                let computed_hash = format!("{:x}", hasher.finalize());

                if !computed_hash.eq_ignore_ascii_case(&expected_hash) {
                    return Response::error(
                        DeftErrorCode::BadRequest,
                        Some(format!(
                            "Hash mismatch: expected {}, got {}",
                            expected_hash, computed_hash
                        )),
                    );
                }

                // Write output file
                if let Err(e) = std::fs::write(&file_path, &output) {
                    return Response::error(
                        DeftErrorCode::InternalServerError,
                        Some(format!("Failed to write file: {}", e)),
                    );
                }

                Response::DeltaAck {
                    virtual_file,
                    bytes_written,
                    final_hash: computed_hash,
                }
            }
            Err(e) => Response::error(
                DeftErrorCode::InternalServerError,
                Some(format!("Failed to apply delta: {}", e)),
            ),
        }
    }

    /// Resolve virtual file to actual path (for reading)
    fn resolve_virtual_file_path(&self, session: &Session, virtual_file: &str) -> Option<PathBuf> {
        let partner_id = session.partner_id.as_ref()?;
        let partner = self.config.find_partner(partner_id)?;

        for vf in &partner.virtual_files {
            if vf.name == virtual_file {
                let path = PathBuf::from(&vf.path);
                if path.exists() {
                    return Some(path);
                }
            }
        }
        None
    }

    /// Resolve virtual file to actual path (for writing)
    fn resolve_virtual_file_path_for_write(
        &self,
        session: &Session,
        virtual_file: &str,
    ) -> Option<PathBuf> {
        let partner_id = session.partner_id.as_ref()?;
        let partner = self.config.find_partner(partner_id)?;

        for vf in &partner.virtual_files {
            if vf.name == virtual_file {
                return Some(PathBuf::from(&vf.path));
            }
        }
        None
    }
}

/// Compute SHA-256 fingerprint from a PEM certificate file
fn compute_cert_fingerprint(cert_path: &str) -> Option<String> {
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

impl CommandHandler {
    fn handle_pause_transfer(&self, session: &mut Session, transfer_id: String) -> Response {
        if session.state != SessionState::Authenticated {
            return Response::error(
                DeftErrorCode::BadRequest,
                Some("Must be authenticated".to_string()),
            );
        }

        // Mark the transfer as paused in session
        if let Some(ref mut transfer) = session.active_transfer {
            if transfer.id == transfer_id {
                transfer.paused = true;
                tracing::info!("Transfer {} paused by remote", transfer_id);
                // Sync to API state for console visibility
                self.pause_transfer_to_api(&transfer_id);
                return Response::TransferPaused { transfer_id };
            }
        }

        Response::error(
            DeftErrorCode::NotFound,
            Some(format!("Transfer {} not found", transfer_id)),
        )
    }

    fn handle_resume_transfer_cmd(&self, session: &mut Session, transfer_id: String) -> Response {
        if session.state != SessionState::Authenticated {
            return Response::error(
                DeftErrorCode::BadRequest,
                Some("Must be authenticated".to_string()),
            );
        }

        // Mark the transfer as resumed in session
        if let Some(ref mut transfer) = session.active_transfer {
            if transfer.id == transfer_id {
                transfer.paused = false;
                tracing::info!("Transfer {} resumed by remote", transfer_id);
                // Sync to API state for console visibility
                self.resume_transfer_to_api(&transfer_id);
                return Response::TransferResumed { transfer_id };
            }
        }

        Response::error(
            DeftErrorCode::NotFound,
            Some(format!("Transfer {} not found", transfer_id)),
        )
    }

    fn handle_abort_transfer(
        &self,
        session: &mut Session,
        transfer_id: String,
        reason: Option<String>,
    ) -> Response {
        if session.state != SessionState::Authenticated {
            return Response::error(
                DeftErrorCode::BadRequest,
                Some("Must be authenticated".to_string()),
            );
        }

        // Abort the transfer
        if let Some(ref transfer) = session.active_transfer {
            if transfer.id == transfer_id {
                tracing::info!(
                    "Transfer {} aborted by remote: {:?}",
                    transfer_id,
                    reason
                );
                // Sync to API state for console visibility
                self.abort_transfer_to_api(&transfer_id, reason.clone());
                session.active_transfer = None;
                return Response::TransferAborted {
                    transfer_id,
                    reason,
                };
            }
        }

        Response::error(
            DeftErrorCode::NotFound,
            Some(format!("Transfer {} not found", transfer_id)),
        )
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
                temp_dir: "/tmp/deft-test/tmp".to_string(),
                chunk_size: 262144,
            },
            limits: LimitsConfig::default(),
            logging: LoggingConfig::default(),
            partners: vec![],
            trusted_servers: vec![],
            hooks: vec![],
        }
    }

    #[test]
    fn test_command_handler_creation() {
        let config = test_config();
        let handler = CommandHandler::new(config);
        assert!(handler.config.server.enabled);
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = Session::new();
        assert_eq!(session.state, SessionState::Connected);

        session.state = SessionState::Welcomed;
        assert_eq!(session.state, SessionState::Welcomed);

        session.state = SessionState::Authenticated;
        assert_eq!(session.state, SessionState::Authenticated);

        session.state = SessionState::Closed;
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn test_compute_cert_fingerprint_invalid_path() {
        let result = compute_cert_fingerprint("/nonexistent/path.crt");
        assert!(result.is_none());
    }

    #[test]
    fn test_hello_response_format() {
        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();

        let response = handler.handle_command(
            &mut session,
            Command::Hello {
                version: "1.0".to_string(),
                capabilities: Capabilities::new(),
            },
        );

        match response {
            Response::Welcome { version, .. } => {
                assert_eq!(version, DEFT_VERSION);
            }
            _ => panic!("Expected Welcome response"),
        }
    }

    #[test]
    fn test_auth_without_partner_fails() {
        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Welcomed;

        let response = handler.handle_command(
            &mut session,
            Command::Auth {
                partner_id: "unknown-partner".to_string(),
            },
        );

        match response {
            Response::Error { code, .. } => {
                assert_eq!(code, DeftErrorCode::Unauthorized);
            }
            _ => panic!("Expected Error response for unknown partner"),
        }
    }

    #[test]
    fn test_bye_closes_session() {
        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;

        let response = handler.handle_command(&mut session, Command::Bye);

        assert!(matches!(response, Response::Goodbye));
        assert_eq!(session.state, SessionState::Closed);
    }

    // ==================== Transfer Control Handler Tests ====================

    #[test]
    fn test_pause_transfer_not_authenticated() {
        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Welcomed; // Not authenticated

        let response = handler.handle_command(
            &mut session,
            Command::PauseTransfer {
                transfer_id: "tx_123".to_string(),
            },
        );

        match response {
            Response::Error { code, .. } => {
                assert_eq!(code, DeftErrorCode::BadRequest);
            }
            _ => panic!("Expected Error response for unauthenticated session"),
        }
    }

    #[test]
    fn test_pause_transfer_no_active_transfer() {
        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;

        let response = handler.handle_command(
            &mut session,
            Command::PauseTransfer {
                transfer_id: "tx_nonexistent".to_string(),
            },
        );

        match response {
            Response::Error { code, .. } => {
                assert_eq!(code, DeftErrorCode::NotFound);
            }
            _ => panic!("Expected NotFound error for nonexistent transfer"),
        }
    }

    #[test]
    fn test_pause_transfer_success() {
        use crate::session::ActiveTransfer;

        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;
        session.active_transfer = Some(ActiveTransfer {
            id: "tx_pause_test".to_string(),
            virtual_file: "test.dat".to_string(),
            paused: false,
        });

        let response = handler.handle_command(
            &mut session,
            Command::PauseTransfer {
                transfer_id: "tx_pause_test".to_string(),
            },
        );

        match response {
            Response::TransferPaused { transfer_id } => {
                assert_eq!(transfer_id, "tx_pause_test");
            }
            _ => panic!("Expected TransferPaused response"),
        }

        assert!(session.active_transfer.as_ref().unwrap().paused);
    }

    #[test]
    fn test_pause_transfer_wrong_id() {
        use crate::session::ActiveTransfer;

        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;
        session.active_transfer = Some(ActiveTransfer {
            id: "tx_actual".to_string(),
            virtual_file: "test.dat".to_string(),
            paused: false,
        });

        let response = handler.handle_command(
            &mut session,
            Command::PauseTransfer {
                transfer_id: "tx_different".to_string(),
            },
        );

        match response {
            Response::Error { code, .. } => {
                assert_eq!(code, DeftErrorCode::NotFound);
            }
            _ => panic!("Expected NotFound error for wrong transfer ID"),
        }
    }

    #[test]
    fn test_resume_transfer_cmd_success() {
        use crate::session::ActiveTransfer;

        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;
        session.active_transfer = Some(ActiveTransfer {
            id: "tx_resume_test".to_string(),
            virtual_file: "test.dat".to_string(),
            paused: true,
        });

        let response = handler.handle_command(
            &mut session,
            Command::ResumeTransferCmd {
                transfer_id: "tx_resume_test".to_string(),
            },
        );

        match response {
            Response::TransferResumed { transfer_id } => {
                assert_eq!(transfer_id, "tx_resume_test");
            }
            _ => panic!("Expected TransferResumed response"),
        }

        assert!(!session.active_transfer.as_ref().unwrap().paused);
    }

    #[test]
    fn test_abort_transfer_success() {
        use crate::session::ActiveTransfer;

        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;
        session.active_transfer = Some(ActiveTransfer {
            id: "tx_abort_test".to_string(),
            virtual_file: "test.dat".to_string(),
            paused: false,
        });

        let response = handler.handle_command(
            &mut session,
            Command::AbortTransfer {
                transfer_id: "tx_abort_test".to_string(),
                reason: Some("user_cancelled".to_string()),
            },
        );

        match response {
            Response::TransferAborted { transfer_id, reason } => {
                assert_eq!(transfer_id, "tx_abort_test");
                assert_eq!(reason, Some("user_cancelled".to_string()));
            }
            _ => panic!("Expected TransferAborted response"),
        }

        assert!(session.active_transfer.is_none());
    }

    #[test]
    fn test_abort_transfer_without_reason() {
        use crate::session::ActiveTransfer;

        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;
        session.active_transfer = Some(ActiveTransfer {
            id: "tx_abort_no_reason".to_string(),
            virtual_file: "test.dat".to_string(),
            paused: false,
        });

        let response = handler.handle_command(
            &mut session,
            Command::AbortTransfer {
                transfer_id: "tx_abort_no_reason".to_string(),
                reason: None,
            },
        );

        match response {
            Response::TransferAborted { transfer_id, reason } => {
                assert_eq!(transfer_id, "tx_abort_no_reason");
                assert!(reason.is_none());
            }
            _ => panic!("Expected TransferAborted response"),
        }
    }

    #[test]
    fn test_pause_resume_cycle() {
        use crate::session::ActiveTransfer;

        let config = test_config();
        let handler = CommandHandler::new(config);
        let mut session = Session::new();
        session.state = SessionState::Authenticated;
        session.active_transfer = Some(ActiveTransfer {
            id: "tx_cycle".to_string(),
            virtual_file: "test.dat".to_string(),
            paused: false,
        });

        // Pause
        let response = handler.handle_command(
            &mut session,
            Command::PauseTransfer {
                transfer_id: "tx_cycle".to_string(),
            },
        );
        assert!(matches!(response, Response::TransferPaused { .. }));
        assert!(session.active_transfer.as_ref().unwrap().paused);

        // Resume
        let response = handler.handle_command(
            &mut session,
            Command::ResumeTransferCmd {
                transfer_id: "tx_cycle".to_string(),
            },
        );
        assert!(matches!(response, Response::TransferResumed { .. }));
        assert!(!session.active_transfer.as_ref().unwrap().paused);

        // Pause again
        let response = handler.handle_command(
            &mut session,
            Command::PauseTransfer {
                transfer_id: "tx_cycle".to_string(),
            },
        );
        assert!(matches!(response, Response::TransferPaused { .. }));
        assert!(session.active_transfer.as_ref().unwrap().paused);
    }
}
