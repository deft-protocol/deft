use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use deft_common::{sha256_hex, Chunker};
use deft_protocol::{Capabilities, Command, Parser as DeftParser, Response, DEFT_VERSION};

mod chunk_tracker;

#[derive(Parser)]
#[command(name = "deft")]
#[command(about = "DEFT Protocol CLI - Reliable Interoperable File Transfer")]
struct Cli {
    #[arg(short, long, default_value = "localhost:7741")]
    server: String,

    #[arg(long)]
    cert: Option<String>,

    #[arg(long)]
    key: Option<String>,

    #[arg(long)]
    ca: Option<String>,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send HELLO and establish session
    Hello {
        #[arg(default_value = "1.0")]
        version: String,
    },
    /// Authenticate with partner ID
    Auth { partner_id: String },
    /// Discover available virtual files
    Discover,
    /// Describe a virtual file (get metadata and chunk info)
    Describe { virtual_file: String },
    /// Get chunks from a virtual file
    Get {
        virtual_file: String,
        #[arg(short, long, default_value = "0-0")]
        chunks: String,
    },
    /// Put a chunk to a virtual file
    Put {
        virtual_file: String,
        #[arg(short, long)]
        chunk: u64,
        #[arg(short = 'H', long)]
        hash: String,
    },
    /// Send a file to a virtual file destination
    Send {
        /// Partner ID to authenticate as
        partner_id: String,
        /// Virtual file name (destination)
        virtual_file: String,
        /// Local file path to send
        file_path: PathBuf,
        /// Chunk size in bytes (default: 256KB)
        #[arg(long, default_value = "262144")]
        chunk_size: u32,
    },
    /// Interactive session with handshake
    Connect { partner_id: String },
    /// Send raw DEFT command
    Raw { command: Vec<String> },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    match cli.command {
        Commands::Hello { ref version } => {
            let mut conn = connect(&cli).await?;
            let cmd = Command::hello(version, Capabilities::all());
            let response = send_command(&mut conn, &cmd).await?;
            println!("{}", response);
        }
        Commands::Auth { ref partner_id } => {
            let mut conn = connect(&cli).await?;
            // Must HELLO first
            let hello = Command::hello(DEFT_VERSION, Capabilities::all());
            let _ = send_command(&mut conn, &hello).await?;

            let cmd = Command::auth(partner_id);
            let response = send_command(&mut conn, &cmd).await?;
            println!("{}", response);
        }
        Commands::Discover => {
            eprintln!("Error: DISCOVER requires an authenticated session. Use 'connect' command.");
        }
        Commands::Describe { virtual_file } => {
            eprintln!("Error: DESCRIBE requires an authenticated session. Use 'connect' command.");
            eprintln!("Virtual file: {}", virtual_file);
        }
        Commands::Get {
            virtual_file,
            chunks,
        } => {
            eprintln!("Error: GET requires an authenticated session. Use 'connect' command.");
            eprintln!("Virtual file: {}, chunks: {}", virtual_file, chunks);
        }
        Commands::Put {
            virtual_file,
            chunk,
            hash,
        } => {
            eprintln!("Error: PUT requires an authenticated session. Use 'connect' command.");
            eprintln!(
                "Virtual file: {}, chunk: {}, hash: {}",
                virtual_file, chunk, hash
            );
        }
        Commands::Send {
            ref partner_id,
            ref virtual_file,
            ref file_path,
            chunk_size,
        } => {
            send_file(&cli, partner_id, virtual_file, file_path, chunk_size).await?;
        }
        Commands::Connect { ref partner_id } => {
            run_interactive_session(&cli, partner_id).await?;
        }
        Commands::Raw { ref command } => {
            let mut conn = connect(&cli).await?;
            let raw_cmd = format!("DEFT {}", command.join(" "));
            let response = send_raw(&mut conn, &raw_cmd).await?;
            println!("{}", response);
        }
    }

    Ok(())
}

struct Connection {
    reader: TokioBufReader<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    writer: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
}

async fn connect(cli: &Cli) -> Result<Connection> {
    let stream = TcpStream::connect(&cli.server)
        .await
        .with_context(|| format!("Failed to connect to {}", cli.server))?;

    let tls_config = build_client_tls_config(cli)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = cli.server.split(':').next().unwrap_or("localhost");
    let server_name = server_name
        .to_string()
        .try_into()
        .context("Invalid server name")?;

    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake failed")?;

    let (reader, writer) = tokio::io::split(tls_stream);
    let reader = TokioBufReader::new(reader);

    info!("Connected to {}", cli.server);

    Ok(Connection { reader, writer })
}

async fn send_command(conn: &mut Connection, command: &Command) -> Result<String> {
    let cmd_str = format!("{}\n", command);
    send_raw(conn, &cmd_str).await
}

async fn send_raw(conn: &mut Connection, command: &str) -> Result<String> {
    let cmd = if command.ends_with('\n') {
        command.to_string()
    } else {
        format!("{}\n", command)
    };

    conn.writer.write_all(cmd.as_bytes()).await?;
    conn.writer.flush().await?;

    let mut response = String::new();
    conn.reader.read_line(&mut response).await?;

    Ok(response.trim().to_string())
}

async fn run_interactive_session(cli: &Cli, partner_id: &str) -> Result<()> {
    let mut conn = connect(cli).await?;

    // Handshake: HELLO
    println!(">>> DEFT HELLO {} CHUNKED,PARALLEL,RESUME", DEFT_VERSION);
    let hello = Command::hello(DEFT_VERSION, Capabilities::all());
    let welcome = send_command(&mut conn, &hello).await?;
    println!("<<< {}", welcome);

    // Check for error
    if welcome.contains("ERROR") {
        return Err(anyhow::anyhow!("Handshake failed: {}", welcome));
    }

    // Authenticate
    println!(">>> DEFT AUTH {}", partner_id);
    let auth = Command::auth(partner_id);
    let auth_response = send_command(&mut conn, &auth).await?;
    println!("<<< {}", auth_response);

    if auth_response.contains("ERROR") {
        return Err(anyhow::anyhow!("Authentication failed: {}", auth_response));
    }

    println!("\n[Session established. Type DEFT commands or 'quit' to exit]\n");

    // Interactive loop
    let stdin = tokio::io::stdin();
    let mut stdin_reader = TokioBufReader::new(stdin);
    let mut line = String::new();

    loop {
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush()?;

        line.clear();
        if stdin_reader.read_line(&mut line).await? == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit") {
            let bye = Command::bye();
            let _ = send_command(&mut conn, &bye).await;
            println!("Goodbye!");
            break;
        }

        let cmd_line = if trimmed.starts_with("DEFT ") {
            trimmed.to_string()
        } else {
            format!("DEFT {}", trimmed)
        };

        let response = send_raw(&mut conn, &cmd_line).await?;
        println!("{}", response);
    }

    Ok(())
}

async fn send_file(
    cli: &Cli,
    partner_id: &str,
    virtual_file: &str,
    file_path: &PathBuf,
    chunk_size: u32,
) -> Result<()> {
    // Open and analyze file
    let mut file = std::fs::File::open(file_path)
        .with_context(|| format!("Failed to open file: {:?}", file_path))?;
    let file_size = file.metadata()?.len();

    println!("Preparing to send: {:?} ({} bytes)", file_path, file_size);

    // Create chunker and compute chunks metadata
    let chunker = Chunker::new(chunk_size);
    let file_chunks = chunker.compute_chunks(&mut file)?;
    let total_chunks = file_chunks.chunk_count();
    let file_hash = file_chunks.file_hash.clone();

    // Read all chunk data
    let mut chunks_data = Vec::new();
    for i in 0..total_chunks {
        let chunk_data = chunker.read_chunk(&mut file, i)?;
        chunks_data.push(chunk_data);
    }

    println!("File hash: {}", file_hash);
    println!(
        "Total chunks: {} (chunk size: {} bytes)",
        total_chunks, chunk_size
    );

    // Connect and authenticate
    let mut conn = connect(cli).await?;

    // HELLO
    println!("\n>>> Handshake...");
    let hello = Command::hello(DEFT_VERSION, Capabilities::all());
    let welcome = send_command(&mut conn, &hello).await?;
    println!("<<< {}", welcome);

    if welcome.contains("ERROR") {
        return Err(anyhow::anyhow!("Handshake failed: {}", welcome));
    }

    // Parse welcome to get window size
    let window_size = if let Ok(Response::Welcome {
        ref capabilities, ..
    }) = DeftParser::parse_response(&welcome)
    {
        capabilities.window_size.unwrap_or(64)
    } else {
        64 // default
    };
    println!("    Window size: {}", window_size);

    // AUTH
    println!("\n>>> Authenticating as {}...", partner_id);
    let auth = Command::auth(partner_id);
    let auth_response = send_command(&mut conn, &auth).await?;
    println!("<<< {}", auth_response);

    if auth_response.contains("ERROR") {
        return Err(anyhow::anyhow!("Authentication failed: {}", auth_response));
    }

    // BEGIN_TRANSFER
    println!("\n>>> Starting transfer...");
    let begin_cmd = Command::begin_transfer(virtual_file, total_chunks, file_size, &file_hash);
    let begin_response = send_command(&mut conn, &begin_cmd).await?;
    println!("<<< {}", begin_response);

    if begin_response.contains("ERROR") {
        return Err(anyhow::anyhow!("Transfer rejected: {}", begin_response));
    }

    // Send chunks with sliding window
    println!("\n>>> Sending {} chunks...", total_chunks);

    let mut acked_chunks = 0u64;
    let mut failed_chunks = Vec::new();

    for (chunk_index, chunk_data) in chunks_data.iter().enumerate() {
        let chunk_index = chunk_index as u64;
        let chunk_hash = sha256_hex(chunk_data);
        let chunk_size = chunk_data.len() as u64;

        // Send PUT command
        let put_cmd = Command::put(virtual_file, chunk_index, chunk_size, &chunk_hash);
        let put_response = send_command(&mut conn, &put_cmd).await?;

        if put_response.contains("CHUNK_READY") {
            // Send binary chunk data
            conn.writer.write_all(chunk_data).await?;
            conn.writer.flush().await?;

            // Read ACK response
            let mut ack_response = String::new();
            conn.reader.read_line(&mut ack_response).await?;
            let ack_response = ack_response.trim();

            if ack_response.contains("OK") {
                acked_chunks += 1;
                print!(
                    "\r    Sent chunk {}/{} ({:.1}%)",
                    chunk_index + 1,
                    total_chunks,
                    (chunk_index + 1) as f64 / total_chunks as f64 * 100.0
                );
                std::io::Write::flush(&mut std::io::stdout())?;
            } else {
                warn!("Chunk {} failed: {}", chunk_index, ack_response);
                failed_chunks.push(chunk_index);
            }

            // Check for TRANSFER_COMPLETE
            if ack_response.contains("TRANSFER_COMPLETE") || acked_chunks == total_chunks {
                // Read the TRANSFER_COMPLETE response
                let mut complete_response = String::new();
                conn.reader.read_line(&mut complete_response).await?;
                println!("\n\n<<< {}", complete_response.trim());
                break;
            }
        } else {
            warn!("Unexpected response to PUT: {}", put_response);
            failed_chunks.push(chunk_index);
        }
    }

    println!();

    // Summary
    if failed_chunks.is_empty() {
        println!(
            "\n✓ Transfer complete: {} chunks sent successfully",
            acked_chunks
        );
    } else {
        println!(
            "\n✗ Transfer incomplete: {} chunks failed: {:?}",
            failed_chunks.len(),
            failed_chunks
        );
    }

    // BYE
    let _ = send_command(&mut conn, &Command::bye()).await;

    Ok(())
}

fn build_client_tls_config(cli: &Cli) -> Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &cli.ca {
        let ca_file =
            File::open(ca_path).with_context(|| format!("Failed to open CA file: {}", ca_path))?;
        let mut ca_reader = BufReader::new(ca_file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse CA certificates")?;

        for cert in certs {
            root_store.add(cert)?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = if let (Some(cert_path), Some(key_path)) = (&cli.cert, &cli.key) {
        let cert_file = File::open(cert_path)
            .with_context(|| format!("Failed to open cert file: {}", cert_path))?;
        let key_file = File::open(key_path)
            .with_context(|| format!("Failed to open key file: {}", key_path))?;

        let mut cert_reader = BufReader::new(cert_file);
        let mut key_reader = BufReader::new(key_file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificates")?;

        let key = rustls_pemfile::private_key(&mut key_reader)
            .context("Failed to read private key")?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)
            .context("Failed to build client TLS config")?
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(config)
}
