use std::path::PathBuf;
use std::sync::Arc;

use rift_protocol::{
    AckStatus, Capabilities, Command, Parser, Response, RiftErrorCode, RIFT_VERSION,
};
use tracing::{debug, info, warn};

use crate::chunk_store::ChunkStore;
use crate::config::{Config, Direction};
use crate::receipt::ReceiptStore;
use crate::session::{Session, SessionState};
use crate::transfer::TransferManager;
use crate::virtual_file::VirtualFileManager;

pub struct CommandHandler {
    config: Config,
    vf_manager: VirtualFileManager,
    transfer_manager: Arc<TransferManager>,
    receipt_store: Arc<ReceiptStore>,
    chunk_store: Arc<ChunkStore>,
}

impl CommandHandler {
    pub fn new(config: Config) -> Self {
        let vf_manager = VirtualFileManager::new(config.storage.chunk_size);
        let transfer_manager = Arc::new(TransferManager::new());
        let receipt_store = Arc::new(
            ReceiptStore::new(&config.storage.temp_dir.replace("tmp", "receipts"))
                .unwrap_or_else(|_| ReceiptStore::default())
        );
        let chunk_store = Arc::new(
            ChunkStore::new(&config.storage.temp_dir)
                .expect("Failed to initialize chunk store")
        );

        // Register virtual files for all partners
        for partner in &config.partners {
            for vf in &partner.virtual_files {
                if let Err(e) = vf_manager.register(vf) {
                    warn!("Failed to register virtual file {}: {}", vf.name, e);
                }
            }
        }

        Self { config, vf_manager, transfer_manager, receipt_store, chunk_store }
    }

    pub fn handle_line(&self, session: &mut Session, line: &str) -> Response {
        match Parser::parse_command(line) {
            Ok(command) => self.handle_command(session, command),
            Err(e) => {
                warn!("Parse error: {}", e);
                Response::error(RiftErrorCode::BadRequest, Some(e.to_string()))
            }
        }
    }

    pub fn handle_command(&self, session: &mut Session, command: Command) -> Response {
        debug!("Handling command: {:?} in state {:?}", command, session.state);

        match command {
            Command::Hello { version, capabilities } => {
                self.handle_hello(session, version, capabilities)
            }
            Command::Auth { partner_id } => {
                self.handle_auth(session, partner_id)
            }
            Command::Discover => {
                self.handle_discover(session)
            }
            Command::Describe { virtual_file } => {
                self.handle_describe(session, virtual_file)
            }
            Command::Get { virtual_file, chunks } => {
                self.handle_get(session, virtual_file, chunks)
            }
            Command::BeginTransfer { virtual_file, total_chunks, total_bytes, file_hash } => {
                self.handle_begin_transfer(session, virtual_file, total_chunks, total_bytes, file_hash)
            }
            Command::ResumeTransfer { virtual_file, transfer_id } => {
                self.handle_resume_transfer(session, virtual_file, transfer_id)
            }
            Command::GetStatus { virtual_file } => {
                self.handle_get_status(session, virtual_file)
            }
            Command::Put { virtual_file, chunk_index, size, hash, nonce, compressed } => {
                self.handle_put(session, virtual_file, chunk_index, size, hash, nonce, compressed)
            }
            Command::Bye => {
                self.handle_bye(session)
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
                RiftErrorCode::BadRequest,
                Some("Unexpected HELLO".to_string()),
            );
        }

        // Check version compatibility
        if !version.starts_with("1.") {
            return Response::error(
                RiftErrorCode::UpgradeRequired,
                Some(format!("Unsupported version: {}. Server supports 1.x", version)),
            );
        }

        // Negotiate capabilities
        let server_caps = Capabilities::all();
        let negotiated = server_caps.intersect(&client_caps);

        session.set_welcomed(RIFT_VERSION.to_string(), negotiated.clone());

        Response::welcome(RIFT_VERSION, negotiated, &session.id)
    }

    fn handle_auth(&self, session: &mut Session, partner_id: String) -> Response {
        if session.state != SessionState::Welcomed {
            return Response::error(
                RiftErrorCode::BadRequest,
                Some("Must HELLO before AUTH".to_string()),
            );
        }

        let partner = match self.config.find_partner(&partner_id) {
            Some(p) => p,
            None => {
                return Response::error(
                    RiftErrorCode::Unauthorized,
                    Some(format!("Unknown partner: {}", partner_id)),
                );
            }
        };

        let virtual_files: Vec<String> = partner.virtual_files
            .iter()
            .map(|vf| vf.name.clone())
            .collect();

        let partner_name = partner_id.clone(); // Could be enhanced with display name

        session.set_authenticated(partner_id, partner_name.clone(), virtual_files.clone());

        Response::auth_ok(partner_name, virtual_files)
    }

    fn handle_discover(&self, session: &Session) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        let files = self.vf_manager.list_for_partner(&session.allowed_virtual_files);

        Response::Files { files }
    }

    fn handle_describe(&self, session: &Session, virtual_file: String) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        match self.vf_manager.compute_chunks(&virtual_file) {
            Ok((info, chunks)) => Response::FileInfo { info, chunks },
            Err(e) => Response::error(
                RiftErrorCode::InternalServerError,
                Some(format!("Failed to describe file: {}", e)),
            ),
        }
    }

    fn handle_get(
        &self,
        session: &Session,
        virtual_file: String,
        chunks: rift_protocol::ChunkRange,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // For now, return first chunk of the range
        // Full implementation would stream all chunks
        match self.vf_manager.read_chunk(&virtual_file, chunks.start) {
            Ok(data) => Response::ChunkData {
                virtual_file,
                chunk_index: chunks.start,
                data,
            },
            Err(e) => Response::error(
                RiftErrorCode::InternalServerError,
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
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Create chunk hashes placeholder - in real impl, client would send these
        // For now, we'll accept chunks without pre-known hashes
        let chunk_hashes: Vec<(u64, String)> = (0..total_chunks)
            .map(|i| (i, String::new()))
            .collect();

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

        info!("Transfer started: {} for {} ({} chunks, {} bytes)",
            transfer_id, virtual_file, total_chunks, total_bytes);

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
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Check if transfer exists in TransferManager
        if let Some(transfer) = self.transfer_manager.get_transfer(&transfer_id) {
            if transfer.virtual_file != virtual_file {
                return Response::error(
                    RiftErrorCode::BadRequest,
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
                RiftErrorCode::NotFound,
                Some(format!("Transfer not found: {}", transfer_id)),
            )
        }
    }

    fn handle_get_status(
        &self,
        session: &Session,
        virtual_file: String,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Find active transfer for this virtual file
        let transfer_id = self.find_transfer_for_file(session, &virtual_file);
        
        match transfer_id {
            Some(id) => {
                if let Some(transfer) = self.transfer_manager.get_transfer(&id) {
                    let received: Vec<u64> = transfer.chunks.iter()
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
                        RiftErrorCode::NotFound,
                        Some(format!("Transfer not found for: {}", virtual_file)),
                    )
                }
            }
            None => {
                Response::error(
                    RiftErrorCode::NotFound,
                    Some(format!("No active transfer for: {}", virtual_file)),
                )
            }
        }
    }

    fn handle_put(
        &self,
        session: &mut Session,
        virtual_file: String,
        chunk_index: u64,
        size: u64,
        expected_hash: String,
        _nonce: Option<u64>,
        _compressed: bool,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(&virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

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
            None => {
                Response::error(
                    RiftErrorCode::BadRequest,
                    Some(format!("No active transfer for: {}. Use BEGIN_TRANSFER first.", virtual_file)),
                )
            }
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
        self.transfer_manager.update_chunk_hash(transfer_id, chunk_index, hash);
    }

    pub fn handle_chunk_received(
        &self,
        session: &mut Session,
        virtual_file: &str,
        chunk_index: u64,
        data: &[u8],
        _expected_hash: &str,
    ) -> Response {
        if !session.is_authenticated() {
            return Response::error(
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        if !session.can_access_virtual_file(virtual_file) {
            return Response::error(
                RiftErrorCode::Forbidden,
                Some(format!("Access denied to: {}", virtual_file)),
            );
        }

        // Find active transfer and validate chunk
        let transfer_id = self.find_transfer_for_file(session, virtual_file);
        
        match transfer_id {
            Some(id) => {
                // Validate chunk using TransferManager
                let status = self.transfer_manager.validate_chunk(&id, chunk_index, data)
                    .unwrap_or(AckStatus::Error(rift_protocol::AckErrorReason::Unknown));

                // If validation succeeded, store chunk to disk
                if status == AckStatus::Ok {
                    if let Err(e) = self.chunk_store.store_chunk(&id, chunk_index, data) {
                        warn!("Failed to store chunk {} for transfer {}: {}", chunk_index, id, e);
                        return Response::ChunkAck {
                            virtual_file: virtual_file.to_string(),
                            chunk_index,
                            status: AckStatus::Error(rift_protocol::AckErrorReason::IoError),
                        };
                    }
                }

                Response::ChunkAck {
                    virtual_file: virtual_file.to_string(),
                    chunk_index,
                    status,
                }
            }
            None => {
                Response::ChunkAck {
                    virtual_file: virtual_file.to_string(),
                    chunk_index,
                    status: AckStatus::Error(rift_protocol::AckErrorReason::Unknown),
                }
            }
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
            if let Some(path) = output_path {
                match self.chunk_store.assemble_file(
                    &transfer_id,
                    &path,
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
                    }
                }
            }

            // Complete the transfer and get the receipt
            let receipt = self.transfer_manager.complete_transfer(&transfer_id)?;
            
            // Store the receipt
            if let Err(e) = self.receipt_store.store(&receipt) {
                warn!("Failed to store receipt: {}", e);
            }
            
            // Remove transfer from session
            session.remove_transfer(&transfer_id);
            
            info!("Transfer complete: {} ({} bytes, {} chunks)", 
                receipt.virtual_file, receipt.total_bytes, receipt.chunks_total);

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
                let filename = format!("{}_{}.dat", virtual_file, chrono::Utc::now().format("%Y%m%d_%H%M%S"));
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
                RiftErrorCode::Unauthorized,
                Some("Not authenticated".to_string()),
            );
        }

        let sender = session.partner_id.clone().unwrap_or_default();
        let receiver = "self".to_string(); // This server

        let receipt = rift_protocol::TransferReceipt {
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
            info!("Transfer complete: {} ({} bytes, {} chunks)", 
                virtual_file, total_size, chunk_count);
        }

        Response::TransferComplete {
            virtual_file: virtual_file.to_string(),
            file_hash: file_hash.to_string(),
            total_size,
            chunk_count,
            signature: None, // TODO: Add cryptographic signature
        }
    }

    fn handle_bye(&self, session: &mut Session) -> Response {
        session.close();
        Response::Goodbye
    }
}
