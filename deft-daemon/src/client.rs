use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::RootCertStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use deft_common::{sha256_hex, Chunker};
use deft_protocol::{AckStatus, Capabilities, ChunkRange, Command, Parser, Response, DEFT_VERSION};

use crate::chunk_ordering::ChunkOrderer;
use crate::compression::{compress, is_compression_beneficial, CompressionLevel};
use crate::config::{ClientConfig, PartnerConfig};
use crate::metrics;

/// RIFT client for outgoing connections
pub struct Client {
    config: ClientConfig,
    tls_connector: TlsConnector,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self> {
        let tls_config = build_client_tls_config(&config)?;
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            config,
            tls_connector,
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

    /// Send a file to a partner with endpoint failover
    pub async fn send_file(
        &self,
        partner: &PartnerConfig,
        virtual_file: &str,
        file_path: &Path,
        chunk_size: u32,
    ) -> Result<TransferResult> {
        // Try each endpoint with failover
        let mut last_error = None;
        let mut conn = None;
        let mut connected_endpoint = String::new();

        for endpoint in &partner.endpoints {
            match self.connect(endpoint).await {
                Ok(c) => {
                    conn = Some(c);
                    connected_endpoint = endpoint.clone();
                    break;
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", endpoint, e);
                    metrics::record_error("connection_failed");
                    last_error = Some(e);
                }
            }
        }

        let mut conn = conn.ok_or_else(|| {
            last_error.unwrap_or_else(|| anyhow::anyhow!("No endpoints configured for partner {}", partner.id))
        })?;

        info!("Connected to {} for partner {}", connected_endpoint, partner.id);

        // Handshake
        let welcome = conn.hello().await?;
        info!("Handshake complete: {:?}", welcome);

        // Authenticate
        let auth_ok = conn.auth(&partner.id).await?;
        info!("Authenticated: {:?}", auth_ok);

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
                let ack = conn.read_response().await?;
                match &ack {
                    Response::ChunkAck { status, .. } => {
                        if *status == AckStatus::Ok {
                            chunks_sent += 1;
                            debug!(
                                "Chunk {} acknowledged (random order position {})",
                                chunk_index, chunks_sent
                            );
                        } else {
                            warn!("Chunk {} rejected: {:?}", chunk_index, status);
                        }
                    }
                    Response::TransferComplete { .. } => {
                        chunks_sent += 1;
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

    /// Get a file from a partner
    pub async fn get_file(
        &self,
        partner: &PartnerConfig,
        virtual_file: &str,
        output_path: &Path,
    ) -> Result<TransferResult> {
        let endpoint = partner
            .endpoints
            .first()
            .ok_or_else(|| anyhow::anyhow!("No endpoints configured for partner {}", partner.id))?;

        let mut conn = self.connect(endpoint).await?;

        // Handshake and auth
        conn.hello().await?;
        conn.auth(&partner.id).await?;

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

fn build_client_tls_config(config: &ClientConfig) -> Result<rustls::ClientConfig> {
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

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .context("Failed to build client TLS config")?;

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
