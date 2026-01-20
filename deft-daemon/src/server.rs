use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::handler::CommandHandler;
use crate::metrics;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::session::Session;

pub struct Server {
    config: Config,
    tls_acceptor: TlsAcceptor,
    handler: Arc<CommandHandler>,
    rate_limiter: Arc<RateLimiter>,
}

impl Server {
    pub fn new(config: Config) -> Result<Self> {
        let tls_config = build_tls_config(&config)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let handler = Arc::new(CommandHandler::new(config.clone()));

        let rate_limit_config = RateLimitConfig {
            max_connections_per_ip: config.limits.max_connections_per_ip,
            max_requests_per_partner: config.limits.max_requests_per_partner,
            max_bytes_per_partner: config.limits.max_bytes_per_partner,
            window_duration: Duration::from_secs(config.limits.window_seconds),
            ban_duration: Duration::from_secs(config.limits.ban_seconds),
        };
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));

        Ok(Self {
            config,
            tls_acceptor,
            handler,
            rate_limiter,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.server.listen)
            .await
            .with_context(|| format!("Failed to bind to {}", self.config.server.listen))?;

        info!("DEFT server listening on {}", self.config.server.listen);

        // Spawn cleanup task for rate limiter
        let cleanup_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_limiter.cleanup().await;
            }
        });

        let idle_timeout = Duration::from_secs(self.config.limits.idle_timeout_seconds);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Check rate limit before accepting
                    let ip = addr.ip();
                    if !self.rate_limiter.check_ip(ip).await.is_allowed() {
                        warn!("Connection rejected from {} (rate limited)", addr);
                        metrics::record_connection_rejected("rate_limited");
                        metrics::record_rate_limited("ip");
                        drop(stream);
                        continue;
                    }

                    metrics::record_connection_accepted();
                    info!("New connection from {}", addr);

                    let acceptor = self.tls_acceptor.clone();
                    let handler = self.handler.clone();
                    let rate_limiter = self.rate_limiter.clone();

                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                // Extract client certificate CN for partner identification
                                let cert_cn = extract_client_cn(&tls_stream);
                                if let Some(ref cn) = cert_cn {
                                    info!("Client certificate CN: {}", cn);
                                }

                                if let Err(e) = handle_connection(
                                    tls_stream,
                                    handler,
                                    cert_cn,
                                    rate_limiter,
                                    idle_timeout,
                                )
                                .await
                                {
                                    warn!("Connection error: {}", e);
                                }
                                metrics::record_connection_closed();
                            }
                            Err(e) => {
                                warn!("TLS handshake failed from {}: {}", addr, e);
                                metrics::record_connection_rejected("tls_failed");
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

fn extract_client_cn<S>(tls_stream: &tokio_rustls::server::TlsStream<S>) -> Option<String> {
    let (_, server_conn) = tls_stream.get_ref();

    // Get peer certificates
    let certs = server_conn.peer_certificates()?;
    let first_cert = certs.first()?;

    // Parse the certificate to extract CN
    // Using x509-parser would be ideal, but for simplicity we'll parse the DER manually
    // The CN is typically in the Subject field
    extract_cn_from_der(first_cert.as_ref())
}

fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // Simple DER parsing to find CN in subject
    // This is a simplified implementation - a production system should use x509-parser
    let der_str = String::from_utf8_lossy(der);

    // Look for common patterns in DER-encoded certificates
    // CN values are often readable in the raw bytes
    for window in der.windows(4) {
        // OID for CN is 2.5.4.3, encoded as 55 04 03
        if window.len() >= 3 && window[0] == 0x55 && window[1] == 0x04 && window[2] == 0x03 {
            // Found CN OID, next bytes should be the value
            if let Some(start) = der.iter().position(|&b| b == window[0]) {
                let after_oid = &der[start + 5..];
                // Find printable string (length-prefixed)
                if after_oid.len() > 2 {
                    let len = after_oid[0] as usize;
                    if len > 0 && len < after_oid.len() {
                        if let Ok(cn) = std::str::from_utf8(&after_oid[1..1 + len]) {
                            return Some(cn.to_string());
                        }
                    }
                }
            }
        }
    }

    // Fallback: try to find CN= pattern in the raw data
    if let Some(pos) = der_str.find("CN=") {
        let start = pos + 3;
        let end = der_str[start..]
            .find(|c: char| c == ',' || c == '/' || !c.is_ascii_graphic())
            .map(|e| start + e)
            .unwrap_or(der_str.len().min(start + 64));
        return Some(der_str[start..end].to_string());
    }

    None
}

async fn handle_connection<S>(
    stream: S,
    handler: Arc<CommandHandler>,
    cert_cn: Option<String>,
    rate_limiter: Arc<RateLimiter>,
    idle_timeout: Duration,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = TokioBufReader::new(reader);
    let mut session = Session::new();

    // Store certificate CN in session for mTLS-based authentication
    if let Some(cn) = cert_cn {
        session.set_cert_cn(cn);
    }
    let mut line = String::new();

    info!("Session {} started", session.id);

    loop {
        line.clear();

        // Read with timeout
        let read_result = tokio::time::timeout(idle_timeout, reader.read_line(&mut line)).await;

        match read_result {
            Err(_) => {
                warn!("Session {} idle timeout", session.id);
                break;
            }
            Ok(Err(e)) => {
                error!("Session {} read error: {}", session.id, e);
                break;
            }
            Ok(Ok(0)) => {
                info!("Session {} closed by client", session.id);
                break;
            }
            Ok(Ok(_)) => {}
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Check partner rate limit if authenticated
        if let Some(partner_id) = session.partner_id() {
            if !rate_limiter.check_partner(partner_id).await.is_allowed() {
                warn!(
                    "Session {} rate limited for partner {}",
                    session.id, partner_id
                );
                let error_response = deft_protocol::Response::Error {
                    code: deft_protocol::DeftErrorCode::RateLimited,
                    message: Some("Rate limit exceeded".to_string()),
                };
                writer
                    .write_all(format!("{}\n", error_response).as_bytes())
                    .await?;
                writer.flush().await?;
                break;
            }
        }

        info!("Session {} <- {}", session.id, trimmed);

        let response = handler.handle_line(&mut session, trimmed);
        let response_str = format!("{}\n", response);

        info!("Session {} -> {}", session.id, response_str.trim());

        writer.write_all(response_str.as_bytes()).await?;
        writer.flush().await?;

        // Handle binary data reception after ChunkReady
        if let deft_protocol::Response::ChunkReady {
            ref virtual_file,
            chunk_index,
            size,
        } = response
        {
            // Record bytes for rate limiting
            if let Some(partner_id) = session.partner_id() {
                if !rate_limiter
                    .record_bytes(partner_id, size)
                    .await
                    .is_allowed()
                {
                    warn!("Session {} bandwidth limit exceeded", session.id);
                    let error_response = deft_protocol::Response::Error {
                        code: deft_protocol::DeftErrorCode::RateLimited,
                        message: Some("Bandwidth limit exceeded".to_string()),
                    };
                    writer
                        .write_all(format!("{}\n", error_response).as_bytes())
                        .await?;
                    writer.flush().await?;
                    break;
                }
            }

            // TODO: Track compressed flag from PUT command in session
            let compressed = false; // For now, assume uncompressed
            let ack_response = receive_chunk_data(
                &mut reader,
                &handler,
                &mut session,
                virtual_file,
                chunk_index,
                size,
                compressed,
            )
            .await;

            let ack_str = format!("{}\n", ack_response);
            info!("Session {} -> {}", session.id, ack_str.trim());
            writer.write_all(ack_str.as_bytes()).await?;
            writer.flush().await?;

            // Check if transfer is complete after this chunk
            if let Some(complete_response) =
                handler.check_transfer_complete(&mut session, virtual_file)
            {
                let complete_str = format!("{}\n", complete_response);
                info!("Session {} -> {}", session.id, complete_str.trim());
                writer.write_all(complete_str.as_bytes()).await?;
                writer.flush().await?;
            }
        }

        if matches!(response, deft_protocol::Response::Goodbye) {
            info!("Session {} ended", session.id);
            break;
        }
    }

    Ok(())
}

async fn receive_chunk_data<R>(
    reader: &mut TokioBufReader<R>,
    handler: &CommandHandler,
    session: &mut Session,
    virtual_file: &str,
    chunk_index: u64,
    size: u64,
    compressed: bool,
) -> deft_protocol::Response
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; size as usize];

    match reader.read_exact(&mut buffer).await {
        Ok(_) => {
            info!(
                "Session {} received {} bytes for chunk {} (compressed: {})",
                session.id, size, chunk_index, compressed
            );

            // Validate and process the chunk
            handler.handle_chunk_received(
                session,
                virtual_file,
                chunk_index,
                &buffer,
                "", // Hash already stored via update_chunk_hash
                compressed,
            )
        }
        Err(e) => {
            error!("Session {} failed to read chunk data: {}", session.id, e);
            deft_protocol::Response::ChunkAck {
                virtual_file: virtual_file.to_string(),
                chunk_index,
                status: deft_protocol::AckStatus::Error(deft_protocol::AckErrorReason::IoError),
            }
        }
    }
}

fn build_tls_config(config: &Config) -> Result<rustls::ServerConfig> {
    let cert_file = File::open(&config.server.cert)
        .with_context(|| format!("Failed to open cert file: {}", config.server.cert))?;
    let key_file = File::open(&config.server.key)
        .with_context(|| format!("Failed to open key file: {}", config.server.key))?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;

    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    // Load CA certificates for client verification (mTLS)
    let ca_file = File::open(&config.server.ca)
        .with_context(|| format!("Failed to open CA file: {}", config.server.ca))?;
    let mut ca_reader = BufReader::new(ca_file);

    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse CA certificates")?;

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    // Build client verifier for mTLS
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("Failed to build client verifier")?;

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;

    info!("mTLS enabled: client certificates will be verified against CA");

    Ok(tls_config)
}
