//! DEFT client for outgoing file transfers.
//!
//! Supports sequential, parallel, and delta-based transfers with
//! compression and randomized chunk ordering for security.

// v2.0 methods ready for API integration
#![allow(dead_code)]

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use deft_common::{sha256_hex, Chunker};
use deft_protocol::{AckStatus, Capabilities, ChunkRange, Command, Parser, Response, DEFT_VERSION};

use crate::chunk_ordering::ChunkOrderer;
use crate::compression::{compress, is_compression_beneficial, CompressionLevel};
use crate::config::{ClientConfig, TrustedServerConfig};
use crate::delta::{Delta, FileSignature};
use crate::discovery::{DiscoveryConfig, EndpointDiscovery};
use crate::metrics;
use crate::parallel::{ChunkResult, ParallelConfig, ParallelSender};

/// DEFT client for outgoing connections
pub struct Client {
    config: ClientConfig,
    tls_connector: TlsConnector,
    discovery: EndpointDiscovery,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let tls_config = build_client_tls_config(&config)?;
        let tls_connector = TlsConnector::from(Arc::new(tls_config));
        let discovery = EndpointDiscovery::new(DiscoveryConfig::default());

        Ok(Self {
            config,
            tls_connector,
            discovery,
        })
    }

    /// Connect to a partner endpoint
    pub async fn connect(&self, endpoint: &str) -> Result<ClientConnection> {
        let stream = TcpStream::connect(endpoint)
            .await
            .with_context(|| format!("Failed to connect to {}", endpoint))?;

        // Extract hostname for TLS SNI
        let host = endpoint.split(':').next().unwrap_or("localhost");
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| anyhow::anyhow!("Invalid server name: {}", host))?;

        let tls_stream = self
            .tls_connector
            .connect(server_name, stream)
            .await
            .context("TLS handshake failed")?;

        info!("Connected to {}", endpoint);

        Ok(ClientConnection::new(tls_stream))
    }

    /// Send a file to a trusted server
    /// - server: the trusted server to connect to
    /// - our_identity: our partner ID (must match our client cert CN)
    pub async fn send_file(
        &self,
        server: &TrustedServerConfig,
        our_identity: &str,
        virtual_file: &str,
        file_path: &Path,
        chunk_size: u32,
    ) -> Result<TransferResult> {
        // Connect to the server
        let mut conn = self.connect(&server.address).await?;

        info!("Connected to {} ({})", server.name, server.address);

        // Handshake
        let welcome = conn.hello().await?;
        info!("Handshake complete: {:?}", welcome);

        // Authenticate with our identity
        let auth_ok = conn.auth(our_identity).await?;
        info!("Authenticated as {}: {:?}", our_identity, auth_ok);

        // Prepare file for transfer
        let mut file = File::open(file_path)
            .with_context(|| format!("Failed to open file: {:?}", file_path))?;

        let chunker = Chunker::new(chunk_size);
        let file_chunks = chunker.compute_chunks(&mut file)?;
        let file_hash = &file_chunks.file_hash;

        info!(
            "Sending file: {:?} ({} bytes, {} chunks)",
            file_path,
            file_chunks.total_size,
            file_chunks.chunks.len()
        );

        // Begin transfer
        let transfer_accepted = conn
            .begin_transfer(
                virtual_file,
                file_chunks.chunks.len() as u64,
                file_chunks.total_size,
                file_hash,
            )
            .await?;

        let transfer_id = match &transfer_accepted {
            Response::TransferAccepted { transfer_id, .. } => transfer_id.clone(),
            _ => {
                return Err(anyhow::anyhow!(
                    "Unexpected response: {:?}",
                    transfer_accepted
                ))
            }
        };

        info!("Transfer started: {}", transfer_id);

        // Create random chunk orderer for anti-MITM protection
        let mut orderer = ChunkOrderer::new_random(file_chunks.chunks.len() as u64);
        info!("Sending chunks in randomized order for security");

        // Send chunks in random order with optional compression
        let mut chunks_sent = 0u64;
        let mut bytes_saved = 0i64;

        while let Some(chunk_index) = orderer.next_chunk() {
            let i = chunk_index as usize;
            let chunk_meta = &file_chunks.chunks[i];
            let chunk_data = chunker.read_chunk(&mut file, chunk_index)?;

            // Get nonce for this chunk
            let nonce = orderer.get_nonce(chunk_index);

            // Try compression if beneficial
            let (send_data, compressed) = match compress(&chunk_data, CompressionLevel::Fast) {
                Ok(compressed_data)
                    if is_compression_beneficial(chunk_data.len(), compressed_data.len()) =>
                {
                    bytes_saved += (chunk_data.len() as i64) - (compressed_data.len() as i64);
                    (compressed_data, true)
                }
                _ => (chunk_data.clone(), false),
            };

            // Send PUT command with compression flag
            let ready = conn
                .put_compressed_with_nonce(
                    virtual_file,
                    chunk_index,
                    send_data.len() as u64,
                    &chunk_meta.hash,
                    nonce,
                    compressed,
                )
                .await?;

            if let Response::ChunkReady { .. } = ready {
                // Send binary data (compressed or not)
                conn.send_raw_data(&send_data).await?;

                // Wait for ACK
                let start_time = std::time::Instant::now();
                let ack = conn.read_response().await?;
                let latency = start_time.elapsed().as_secs_f64();

                match &ack {
                    Response::ChunkAck { status, .. } => {
                        if *status == AckStatus::Ok {
                            chunks_sent += 1;
                            metrics::record_chunk_sent(latency);
                            if compressed && bytes_saved > 0 {
                                metrics::record_compression_saved(
                                    (chunk_data.len() - send_data.len()) as u64,
                                );
                            }
                            debug!(
                                "Chunk {} acknowledged (random order position {})",
                                chunk_index, chunks_sent
                            );
                        } else {
                            warn!("Chunk {} rejected: {:?}", chunk_index, status);
                            metrics::record_error("chunk_rejected");
                        }
                    }
                    Response::TransferComplete { .. } => {
                        chunks_sent += 1;
                        metrics::record_chunk_sent(latency);
                        info!("Transfer complete received");
                        break;
                    }
                    _ => warn!("Unexpected response for chunk {}: {:?}", chunk_index, ack),
                }
            }
        }

        // Close connection
        conn.bye().await?;

        if bytes_saved > 0 {
            info!(
                "Compression saved {} bytes ({:.1}%)",
                bytes_saved,
                (bytes_saved as f64 / file_chunks.total_size as f64) * 100.0
            );
        }

        Ok(TransferResult {
            transfer_id,
            chunks_sent,
            total_chunks: file_chunks.chunks.len() as u64,
            total_bytes: file_chunks.total_size,
            file_hash: file_hash.clone(),
            bytes_saved: bytes_saved as u64,
        })
    }

    /// Send a file with parallel chunk transfers (v2.0)
    pub async fn send_file_parallel(
        &self,
        server: &TrustedServerConfig,
        our_identity: &str,
        virtual_file: &str,
        file_path: &Path,
        chunk_size: u32,
        parallel_config: ParallelConfig,
    ) -> Result<TransferResult> {
        let mut conn = self.connect(&server.address).await?;

        info!(
            "Connected to {} ({}) - parallel mode ({} concurrent)",
            server.name, server.address, parallel_config.max_concurrent
        );

        // Handshake
        conn.hello().await?;
        conn.auth(our_identity).await?;

        // Prepare file
        let mut file = File::open(file_path)
            .with_context(|| format!("Failed to open file: {:?}", file_path))?;

        let chunker = Chunker::new(chunk_size);
        let file_chunks = chunker.compute_chunks(&mut file)?;
        let file_hash = &file_chunks.file_hash;

        info!(
            "Sending file parallel: {:?} ({} bytes, {} chunks)",
            file_path,
            file_chunks.total_size,
            file_chunks.chunks.len()
        );

        // Begin transfer
        let transfer_accepted = conn
            .begin_transfer(
                virtual_file,
                file_chunks.chunks.len() as u64,
                file_chunks.total_size,
                file_hash,
            )
            .await?;

        let transfer_id = match &transfer_accepted {
            Response::TransferAccepted { transfer_id, .. } => transfer_id.clone(),
            _ => {
                return Err(anyhow::anyhow!(
                    "Unexpected response: {:?}",
                    transfer_accepted
                ))
            }
        };

        // Create parallel sender and random orderer
        let parallel_sender = ParallelSender::new(parallel_config);
        let mut orderer = ChunkOrderer::new_random(file_chunks.chunks.len() as u64);
        let mut bytes_saved = 0i64;

        // Send chunks with concurrency control
        while let Some(chunk_index) = orderer.next_chunk() {
            // Acquire permit for concurrency control
            let _permit = parallel_sender.acquire().await;

            let i = chunk_index as usize;
            let chunk_meta = &file_chunks.chunks[i];
            let chunk_data = chunker.read_chunk(&mut file, chunk_index)?;
            let nonce = orderer.get_nonce(chunk_index);

            // Compress if beneficial
            let (send_data, compressed) = match compress(&chunk_data, CompressionLevel::Fast) {
                Ok(compressed_data)
                    if is_compression_beneficial(chunk_data.len(), compressed_data.len()) =>
                {
                    bytes_saved += (chunk_data.len() as i64) - (compressed_data.len() as i64);
                    (compressed_data, true)
                }
                _ => (chunk_data.clone(), false),
            };

            // Send PUT command
            let ready = conn
                .put_compressed_with_nonce(
                    virtual_file,
                    chunk_index,
                    send_data.len() as u64,
                    &chunk_meta.hash,
                    nonce,
                    compressed,
                )
                .await?;

            if let Response::ChunkReady { .. } = ready {
                conn.send_raw_data(&send_data).await?;

                let start_time = std::time::Instant::now();
                let ack = conn.read_response().await?;
                let latency = start_time.elapsed().as_secs_f64();

                let (success, error) = match &ack {
                    Response::ChunkAck { status, .. } => {
                        if *status == AckStatus::Ok {
                            metrics::record_chunk_sent(latency);
                            (true, None)
                        } else {
                            metrics::record_error("chunk_rejected");
                            (false, Some(format!("{:?}", status)))
                        }
                    }
                    Response::TransferComplete { .. } => {
                        metrics::record_chunk_sent(latency);
                        (true, None)
                    }
                    _ => (false, Some("unexpected response".to_string())),
                };

                parallel_sender
                    .record_result(ChunkResult {
                        chunk_index,
                        success,
                        bytes_sent: if success { send_data.len() as u64 } else { 0 },
                        error,
                    })
                    .await;
            }
        }

        conn.bye().await?;

        let chunks_sent = parallel_sender.success_count().await as u64;
        let failed = parallel_sender.failed_chunks().await;

        if !failed.is_empty() {
            warn!("Failed chunks: {:?}", failed);
        }

        if bytes_saved > 0 {
            info!(
                "Parallel transfer complete. Compression saved {} bytes ({:.1}%)",
                bytes_saved,
                (bytes_saved as f64 / file_chunks.total_size as f64) * 100.0
            );
        }

        Ok(TransferResult {
            transfer_id,
            chunks_sent,
            total_chunks: file_chunks.chunks.len() as u64,
            total_bytes: file_chunks.total_size,
            file_hash: file_hash.clone(),
            bytes_saved: bytes_saved.max(0) as u64,
        })
    }

    /// Sync a file using delta transfer (v2.0)
    /// Only sends the differences between local and remote versions
    pub fn compute_delta_for_sync(
        local_path: &Path,
        remote_signature: &FileSignature,
    ) -> Result<Delta> {
        let mut local_file = File::open(local_path)
            .with_context(|| format!("Failed to open local file: {:?}", local_path))?;

        let delta = Delta::compute(remote_signature, &mut local_file)
            .with_context(|| "Failed to compute delta")?;

        let stats = delta.stats();
        info!(
            "Delta computed: {} copy ops, {} insert bytes, {} total ops",
            stats.copy_blocks, stats.insert_bytes, stats.total_ops
        );

        Ok(delta)
    }

    /// Compute file signature for delta sync
    pub fn compute_file_signature(file_path: &Path, block_size: usize) -> Result<FileSignature> {
        let mut file = File::open(file_path)
            .with_context(|| format!("Failed to open file: {:?}", file_path))?;

        let sig = FileSignature::compute(&mut file, block_size)
            .with_context(|| "Failed to compute file signature")?;

        info!(
            "Signature computed: {} blocks, {} bytes, block_size={}",
            sig.blocks.len(),
            sig.file_size,
            sig.block_size
        );

        Ok(sig)
    }

    /// Get a file from a trusted server
    /// - server: the trusted server to connect to
    /// - our_identity: our partner ID (must match our client cert CN)
    pub async fn get_file(
        &self,
        server: &TrustedServerConfig,
        our_identity: &str,
        virtual_file: &str,
        output_path: &Path,
    ) -> Result<TransferResult> {
        let mut conn = self.connect(&server.address).await?;

        // Handshake and auth
        conn.hello().await?;
        conn.auth(our_identity).await?;

        // Describe file to get chunk info
        let describe = conn.describe(virtual_file).await?;

        let (total_chunks, total_size, file_hash) = match describe {
            Response::FileInfo { info, .. } => (info.chunk_count, info.size, info.hash),
            _ => return Err(anyhow::anyhow!("Unexpected response: {:?}", describe)),
        };

        info!(
            "Getting file: {} ({} bytes, {} chunks)",
            virtual_file, total_size, total_chunks
        );

        // Get all chunks
        let mut received_data = Vec::with_capacity(total_size as usize);

        for i in 0..total_chunks {
            let chunk_response = conn.get_chunk(virtual_file, i).await?;

            if let Response::ChunkData { data, .. } = chunk_response {
                received_data.extend_from_slice(&data);
            }
        }

        // Verify hash
        let computed_hash = sha256_hex(&received_data);
        if computed_hash != file_hash {
            return Err(anyhow::anyhow!(
                "Hash mismatch: expected {}, got {}",
                file_hash,
                computed_hash
            ));
        }

        // Write to file
        std::fs::write(output_path, &received_data)
            .with_context(|| format!("Failed to write file: {:?}", output_path))?;

        conn.bye().await?;

        Ok(TransferResult {
            transfer_id: "get".to_string(),
            chunks_sent: 0,
            total_chunks,
            total_bytes: total_size,
            file_hash,
            bytes_saved: 0,
        })
    }
}

/// Active client connection
pub struct ClientConnection {
    reader: TokioBufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    writer: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
}

impl ClientConnection {
    fn new(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: TokioBufReader::new(reader),
            writer,
        }
    }

    async fn send_command(&mut self, cmd: &Command) -> Result<()> {
        let line = format!("{}\n", cmd);
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        debug!("Sent: {}", cmd);
        Ok(())
    }

    pub async fn read_response(&mut self) -> Result<Response> {
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        let response = Parser::parse_response(line.trim())?;
        debug!("Received: {:?}", response);
        Ok(response)
    }

    async fn send_and_receive(&mut self, cmd: &Command) -> Result<Response> {
        self.send_command(cmd).await?;
        self.read_response().await
    }

    pub async fn send_raw_data(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn hello(&mut self) -> Result<Response> {
        let cmd = Command::hello(DEFT_VERSION, Capabilities::all());
        self.send_and_receive(&cmd).await
    }

    pub async fn auth(&mut self, partner_id: &str) -> Result<Response> {
        let cmd = Command::auth(partner_id);
        self.send_and_receive(&cmd).await
    }

    pub async fn discover(&mut self) -> Result<Response> {
        let cmd = Command::discover();
        self.send_and_receive(&cmd).await
    }

    pub async fn describe(&mut self, virtual_file: &str) -> Result<Response> {
        let cmd = Command::describe(virtual_file);
        self.send_and_receive(&cmd).await
    }

    pub async fn begin_transfer(
        &mut self,
        virtual_file: &str,
        total_chunks: u64,
        total_bytes: u64,
        file_hash: &str,
    ) -> Result<Response> {
        let cmd = Command::begin_transfer(virtual_file, total_chunks, total_bytes, file_hash);
        self.send_and_receive(&cmd).await
    }

    pub async fn put(
        &mut self,
        virtual_file: &str,
        chunk_index: u64,
        size: u64,
        hash: &str,
    ) -> Result<Response> {
        let cmd = Command::put(virtual_file, chunk_index, size, hash);
        self.send_and_receive(&cmd).await
    }

    pub async fn put_with_nonce(
        &mut self,
        virtual_file: &str,
        chunk_index: u64,
        size: u64,
        hash: &str,
        nonce: Option<u64>,
    ) -> Result<Response> {
        let cmd = Command::put_with_nonce(virtual_file, chunk_index, size, hash, nonce);
        self.send_and_receive(&cmd).await
    }

    pub async fn put_compressed_with_nonce(
        &mut self,
        virtual_file: &str,
        chunk_index: u64,
        size: u64,
        hash: &str,
        nonce: Option<u64>,
        compressed: bool,
    ) -> Result<Response> {
        let cmd = if compressed {
            Command::put_compressed(virtual_file, chunk_index, size, hash, nonce)
        } else {
            Command::put_with_nonce(virtual_file, chunk_index, size, hash, nonce)
        };
        self.send_and_receive(&cmd).await
    }

    pub async fn get_chunk(&mut self, virtual_file: &str, chunk_index: u64) -> Result<Response> {
        let cmd = Command::get(virtual_file, ChunkRange::single(chunk_index));
        self.send_and_receive(&cmd).await
    }

    pub async fn bye(&mut self) -> Result<Response> {
        let cmd = Command::bye();
        self.send_and_receive(&cmd).await
    }
}

#[derive(Debug, Clone)]
pub struct TransferResult {
    pub transfer_id: String,
    pub chunks_sent: u64,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub file_hash: String,
    pub bytes_saved: u64,
}

/// Custom server certificate verifier with fingerprint whitelist support
#[derive(Debug)]
struct FingerprintServerVerifier {
    root_store: Arc<RootCertStore>,
    allowed_fingerprints: Vec<String>,
    webpki_verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

impl FingerprintServerVerifier {
    fn new(root_store: Arc<RootCertStore>, allowed_fingerprints: Vec<String>) -> Result<Self> {
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(root_store.clone())
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build WebPKI verifier: {}", e))?;

        Ok(Self {
            root_store,
            allowed_fingerprints,
            webpki_verifier,
        })
    }

    fn compute_fingerprint(cert: &CertificateDer<'_>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl ServerCertVerifier for FingerprintServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // First, do standard WebPKI verification
        self.webpki_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // If no fingerprint whitelist, accept any CA-signed cert
        if self.allowed_fingerprints.is_empty() {
            return Ok(ServerCertVerified::assertion());
        }

        // Check fingerprint against whitelist
        let fingerprint = Self::compute_fingerprint(end_entity);
        let fingerprint_lower = fingerprint.to_lowercase();

        if self
            .allowed_fingerprints
            .iter()
            .any(|f| f.to_lowercase() == fingerprint_lower)
        {
            info!("Server certificate fingerprint validated: {}", fingerprint);
            Ok(ServerCertVerified::assertion())
        } else {
            warn!(
                "Server certificate fingerprint {} not in allowed list",
                fingerprint
            );
            Err(rustls::Error::General(format!(
                "Server certificate fingerprint not authorized: {}",
                fingerprint
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki_verifier.supported_verify_schemes()
    }
}

fn build_client_tls_config(config: &ClientConfig) -> Result<rustls::ClientConfig> {
    build_client_tls_config_with_fingerprints(config, Vec::new())
}

fn build_client_tls_config_with_fingerprints(
    config: &ClientConfig,
    allowed_server_fingerprints: Vec<String>,
) -> Result<rustls::ClientConfig> {
    // Load client certificate
    let cert_file = File::open(&config.cert)
        .with_context(|| format!("Failed to open client cert: {}", config.cert))?;
    let key_file = File::open(&config.key)
        .with_context(|| format!("Failed to open client key: {}", config.key))?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse client certificates")?;

    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read client private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    // Load CA certificates
    let ca_file =
        File::open(&config.ca).with_context(|| format!("Failed to open CA file: {}", config.ca))?;
    let mut ca_reader = BufReader::new(ca_file);

    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse CA certificates")?;

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    // Build custom verifier with fingerprint support
    let verifier =
        FingerprintServerVerifier::new(Arc::new(root_store), allowed_server_fingerprints)?;

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certs, key)
        .context("Failed to build client TLS config")?;

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parallel::{ChunkResult, ParallelConfig, ParallelSender};

    #[test]
    fn test_transfer_result() {
        let result = TransferResult {
            transfer_id: "test-123".to_string(),
            chunks_sent: 10,
            total_chunks: 10,
            total_bytes: 1024000,
            file_hash: "abc123".to_string(),
            bytes_saved: 512000,
        };

        assert_eq!(result.chunks_sent, result.total_chunks);
        assert_eq!(result.total_bytes, 1024000);
        assert_eq!(result.bytes_saved, 512000);
    }

    #[test]
    fn test_parallel_config_default() {
        let config = ParallelConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.buffer_size, 16);
    }

    #[tokio::test]
    async fn test_parallel_sender_permits() {
        let config = ParallelConfig {
            max_concurrent: 2,
            buffer_size: 8,
        };
        let sender = ParallelSender::new(config);

        // Should be able to acquire 2 permits
        let permit1 = sender.acquire().await;
        let permit2 = sender.acquire().await;
        assert!(permit1.is_some());
        assert!(permit2.is_some());

        // Record results
        sender
            .record_result(ChunkResult {
                chunk_index: 0,
                success: true,
                bytes_sent: 1024,
                error: None,
            })
            .await;

        assert_eq!(sender.success_count().await, 1);
    }

    #[tokio::test]
    async fn test_parallel_sender_failed_chunks() {
        let sender = ParallelSender::new(ParallelConfig::default());

        sender
            .record_result(ChunkResult {
                chunk_index: 0,
                success: true,
                bytes_sent: 1024,
                error: None,
            })
            .await;

        sender
            .record_result(ChunkResult {
                chunk_index: 1,
                success: false,
                bytes_sent: 0,
                error: Some("timeout".to_string()),
            })
            .await;

        sender
            .record_result(ChunkResult {
                chunk_index: 2,
                success: false,
                bytes_sent: 0,
                error: Some("network error".to_string()),
            })
            .await;

        assert_eq!(sender.success_count().await, 1);
        let failed = sender.failed_chunks().await;
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&1));
        assert!(failed.contains(&2));
    }

    #[test]
    fn test_transfer_result_with_parallel_stats() {
        let result = TransferResult {
            transfer_id: "parallel-001".to_string(),
            chunks_sent: 100,
            total_chunks: 100,
            total_bytes: 10_485_760, // 10 MB
            file_hash: "sha256hash".to_string(),
            bytes_saved: 2_097_152, // 2 MB saved
        };

        // Verify compression ratio
        let compression_ratio = result.bytes_saved as f64 / result.total_bytes as f64;
        assert!(compression_ratio > 0.19 && compression_ratio < 0.21); // ~20%
    }

    #[test]
    fn test_delta_file_signature() {
        use std::io::Cursor;

        let data = b"hello world this is test data for delta sync";
        let mut cursor = Cursor::new(data);

        let sig = FileSignature::compute(&mut cursor, 8).unwrap();
        assert_eq!(sig.file_size, data.len() as u64);
        assert!(!sig.blocks.is_empty());
    }

    #[test]
    fn test_delta_identical_files() {
        use std::io::{Cursor, Seek, SeekFrom};

        let data = b"identical content for both files";
        let mut source = Cursor::new(data);
        let mut target = Cursor::new(data);

        let sig = FileSignature::compute(&mut source, 8).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();

        let delta = Delta::compute(&sig, &mut target).unwrap();
        let stats = delta.stats();

        // Most operations should be Copy for identical files
        assert!(stats.copy_blocks > 0);
    }

    #[test]
    fn test_delta_apply_reconstruction() {
        use std::io::{Cursor, Seek, SeekFrom};

        let original = b"AAAAAAAAAAAAAAAA"; // 16 bytes
        let modified = b"AAAABBBBAAAAAAAA"; // Modified middle

        let mut source = Cursor::new(original);
        let mut new_file = Cursor::new(modified);

        let sig = FileSignature::compute(&mut source, 4).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();

        let delta = Delta::compute(&sig, &mut new_file).unwrap();

        // Apply delta to reconstruct
        source.seek(SeekFrom::Start(0)).unwrap();
        let mut output = Vec::new();
        delta.apply(&mut source, &mut output).unwrap();

        assert_eq!(output, modified);
    }

    #[test]
    fn test_delta_stats() {
        use std::io::{Cursor, Seek, SeekFrom};

        let original = b"AAAAAAAAAAAAAAAA"; // 16 bytes, 4 blocks of 4
        let modified = b"AAAABBBBAAAAAAAA"; // Modified second block

        let mut source = Cursor::new(original);
        let mut new_file = Cursor::new(modified);

        let sig = FileSignature::compute(&mut source, 4).unwrap();
        source.seek(SeekFrom::Start(0)).unwrap();

        let delta = Delta::compute(&sig, &mut new_file).unwrap();
        let stats = delta.stats();

        // Should have operations (copy and/or insert)
        assert!(stats.total_ops > 0);
    }
}
