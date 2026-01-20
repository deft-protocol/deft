use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;

use config::LogFormat;

mod api;
mod chunk_ordering;
mod chunk_store;
mod client;
mod compression;
mod config;
mod delta;
mod discovery;
mod handler;
mod hooks;
mod metrics;
mod parallel;
mod platform;
mod rate_limit;
mod receipt;
mod server;
mod session;
mod signer;
mod transfer;
mod transfer_state;
mod virtual_file;
mod watcher;

use client::Client;
use config::Config;
use platform::default_config_path;
use server::Server;

#[derive(Parser)]
#[command(name = "deftd")]
#[command(about = "DEFT Protocol Daemon - Reliable Interoperable File Transfer")]
struct Cli {
    #[arg(short, long)]
    config: Option<String>,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as daemon (default if no command specified)
    Daemon,
    /// Send a file to a partner
    Send {
        /// Partner ID to send to
        partner: String,
        /// Virtual file name (destination)
        virtual_file: String,
        /// Local file path to send
        file: PathBuf,
        /// Chunk size in bytes
        #[arg(long, default_value = "262144")]
        chunk_size: u32,
    },
    /// Get a file from a partner
    Get {
        /// Partner ID to get from
        partner: String,
        /// Virtual file name (source)
        virtual_file: String,
        /// Local file path to save
        output: PathBuf,
    },
    /// List virtual files available from a partner
    List {
        /// Partner ID
        partner: String,
    },
    /// Watch a directory and auto-send new files
    Watch {
        /// Directory to watch
        directory: PathBuf,
        /// Partner ID to send to
        partner: String,
        /// Virtual file name prefix
        virtual_file: String,
        /// File pattern (glob)
        #[arg(long, default_value = "*")]
        pattern: String,
        /// Poll interval in seconds
        #[arg(long, default_value = "30")]
        interval: u64,
        /// Delete files after successful send
        #[arg(long)]
        delete_after: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Use platform-specific default config path if not specified
    let config_path = cli.config.unwrap_or_else(|| {
        default_config_path().to_string_lossy().to_string()
    });

    // Load config first to get logging settings
    let config = Config::load(&config_path)?;

    // Initialize logging based on config
    let log_level = if cli.log_level != "info" {
        &cli.log_level
    } else {
        &config.logging.level
    };

    match config.logging.format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(log_level)
                .json()
                .with_span_events(FmtSpan::CLOSE)
                .init();
        }
        LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(log_level).init();
        }
    }

    info!("Starting DEFT daemon v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration loaded from {}", config_path);

    match cli.command {
        Some(Commands::Send {
            partner,
            virtual_file,
            file,
            chunk_size,
        }) => {
            run_send(&config, &partner, &virtual_file, &file, chunk_size).await?;
        }
        Some(Commands::Get {
            partner,
            virtual_file,
            output,
        }) => {
            run_get(&config, &partner, &virtual_file, &output).await?;
        }
        Some(Commands::List { partner }) => {
            run_list(&config, &partner).await?;
        }
        Some(Commands::Watch {
            directory,
            partner,
            virtual_file,
            pattern,
            interval,
            delete_after,
        }) => {
            run_watch(
                &config,
                &directory,
                &partner,
                &virtual_file,
                &pattern,
                interval,
                delete_after,
            )
            .await?;
        }
        Some(Commands::Daemon) | None => {
            run_daemon(config).await?;
        }
    }

    Ok(())
}

async fn run_daemon(config: Config) -> Result<()> {
    // Initialize metrics
    metrics::register_metrics();

    // Start metrics server if enabled
    if config.limits.metrics_enabled {
        let metrics_port = config.limits.metrics_port;
        tokio::spawn(async move {
            run_metrics_server(metrics_port).await;
        });
        info!(
            "Metrics server started on port {}",
            config.limits.metrics_port
        );
    }

    // Start API server if enabled
    if config.limits.api_enabled {
        let api_listen = config.limits.api_listen.clone();
        let api_key = config.limits.api_key.clone();
        let api_state = std::sync::Arc::new(api::ApiState::new(config.clone()));
        tokio::spawn(async move {
            api::run_api_server(&api_listen, api_state, api_key).await;
        });
        info!("API server started on {}", config.limits.api_listen);
    }

    if config.server.enabled {
        let server = Server::new(config)?;

        // Setup graceful shutdown
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Received shutdown signal, stopping server...");
        };

        tokio::select! {
            result = server.run() => {
                result?;
            }
            _ = shutdown => {
                info!("Server shutdown complete");
            }
        }
    } else {
        info!("Server mode disabled, running in client-only mode");
    }
    Ok(())
}

async fn run_metrics_server(port: u16) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind metrics server to {}: {}", addr, e);
            return;
        }
    };

    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            let metrics_body = metrics::gather_metrics();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                metrics_body.len(),
                metrics_body
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    }
}

async fn run_send(
    config: &Config,
    partner_id: &str,
    virtual_file: &str,
    file_path: &PathBuf,
    chunk_size: u32,
) -> Result<()> {
    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let partner = config
        .find_partner(partner_id)
        .ok_or_else(|| anyhow::anyhow!("Partner '{}' not found in configuration", partner_id))?;

    if partner.endpoints.is_empty() {
        anyhow::bail!("No endpoints configured for partner '{}'", partner_id);
    }

    let client = Client::new(config.client.clone())?;

    println!(
        "Sending file {:?} to {}:{}",
        file_path, partner_id, virtual_file
    );

    let result = client
        .send_file(partner, virtual_file, file_path, chunk_size)
        .await?;

    println!("\n✓ Transfer complete!");
    println!("  Transfer ID: {}", result.transfer_id);
    println!(
        "  Chunks sent: {}/{}",
        result.chunks_sent, result.total_chunks
    );
    println!("  Total bytes: {}", result.total_bytes);
    println!("  File hash:   {}", result.file_hash);

    Ok(())
}

async fn run_get(
    config: &Config,
    partner_id: &str,
    virtual_file: &str,
    output_path: &PathBuf,
) -> Result<()> {
    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let partner = config
        .find_partner(partner_id)
        .ok_or_else(|| anyhow::anyhow!("Partner '{}' not found in configuration", partner_id))?;

    if partner.endpoints.is_empty() {
        anyhow::bail!("No endpoints configured for partner '{}'", partner_id);
    }

    let client = Client::new(config.client.clone())?;

    println!(
        "Getting file {}:{} -> {:?}",
        partner_id, virtual_file, output_path
    );

    let result = client.get_file(partner, virtual_file, output_path).await?;

    println!("\n✓ Download complete!");
    println!("  Total chunks: {}", result.total_chunks);
    println!("  Total bytes:  {}", result.total_bytes);
    println!("  File hash:    {}", result.file_hash);
    println!("  Saved to:     {:?}", output_path);

    Ok(())
}

async fn run_list(config: &Config, partner_id: &str) -> Result<()> {
    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let partner = config
        .find_partner(partner_id)
        .ok_or_else(|| anyhow::anyhow!("Partner '{}' not found in configuration", partner_id))?;

    if partner.endpoints.is_empty() {
        anyhow::bail!("No endpoints configured for partner '{}'", partner_id);
    }

    let client = Client::new(config.client.clone())?;
    let endpoint = partner.endpoints.first().unwrap();

    let mut conn = client.connect(endpoint).await?;
    conn.hello().await?;
    conn.auth(partner_id).await?;

    let response = conn.discover().await?;

    println!("Virtual files available from {}:", partner_id);
    if let deft_protocol::Response::Files { files } = response {
        for file in files {
            println!(
                "  - {} ({} bytes, {} chunks)",
                file.name, file.size, file.chunk_count
            );
        }
    } else {
        println!("  {:?}", response);
    }

    conn.bye().await?;

    Ok(())
}

async fn run_watch(
    config: &Config,
    directory: &PathBuf,
    partner_id: &str,
    virtual_file_prefix: &str,
    pattern: &str,
    interval_secs: u64,
    delete_after: bool,
) -> Result<()> {
    use crate::watcher::{DirectoryWatcher, FileEvent, WatchConfig};
    use tokio::sync::mpsc;
    use tracing::warn;

    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let partner = config
        .find_partner(partner_id)
        .ok_or_else(|| anyhow::anyhow!("Partner '{}' not found in configuration", partner_id))?
        .clone();

    if partner.endpoints.is_empty() {
        anyhow::bail!("No endpoints configured for partner '{}'", partner_id);
    }

    let watch_config = WatchConfig {
        path: directory.clone(),
        pattern: Some(pattern.to_string()),
        partner_id: partner_id.to_string(),
        virtual_file: virtual_file_prefix.to_string(),
        poll_interval_secs: interval_secs,
        delete_after_send: delete_after,
        move_to: None,
    };

    let (tx, mut rx) = mpsc::channel(100);
    let mut watcher = DirectoryWatcher::new(watch_config.clone(), tx);

    println!("Watching directory: {:?}", directory);
    println!("  Pattern: {}", pattern);
    println!("  Partner: {}", partner_id);
    println!("  Interval: {}s", interval_secs);
    println!("  Delete after send: {}", delete_after);
    println!("\nPress Ctrl+C to stop\n");

    // Spawn watcher task
    tokio::spawn(async move {
        watcher.watch().await;
    });

    let client = Client::new(config.client.clone())?;
    let chunk_size = config.storage.chunk_size;

    // Process events
    while let Some(event) = rx.recv().await {
        match event {
            FileEvent::Created(path) | FileEvent::Modified(path) => {
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                let vf_name = format!("{}_{}", virtual_file_prefix, filename);

                println!("📤 Sending: {:?} -> {}", path, vf_name);

                match client
                    .send_file(&partner, &vf_name, &path, chunk_size)
                    .await
                {
                    Ok(result) => {
                        println!(
                            "  ✓ Sent {} chunks, {} bytes",
                            result.chunks_sent, result.total_bytes
                        );
                        if result.bytes_saved > 0 {
                            println!("  ✓ Compression saved {} bytes", result.bytes_saved);
                        }

                        // Delete or move if configured
                        if delete_after {
                            if let Err(e) = std::fs::remove_file(&path) {
                                warn!("Failed to delete {:?}: {}", path, e);
                            } else {
                                println!("  ✓ Deleted source file");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("  ✗ Failed to send {:?}: {}", path, e);
                    }
                }
            }
            FileEvent::Deleted(path) => {
                println!("🗑️  File deleted: {:?}", path);
            }
        }
    }

    Ok(())
}
