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
#[command(about = "DEFT Protocol Daemon - Delta-Enabled File Transfer")]
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
    /// Send a file to a trusted server
    Send {
        /// Trusted server name to send to
        #[arg(short, long)]
        server: String,
        /// Our identity (must match client cert CN)
        #[arg(short, long)]
        identity: String,
        /// Virtual file name (destination)
        virtual_file: String,
        /// Local file path to send
        file: PathBuf,
        /// Chunk size in bytes
        #[arg(long, default_value = "262144")]
        chunk_size: u32,
    },
    /// Get a file from a trusted server
    Get {
        /// Trusted server name to get from
        #[arg(short, long)]
        server: String,
        /// Our identity (must match client cert CN)
        #[arg(short, long)]
        identity: String,
        /// Virtual file name (source)
        virtual_file: String,
        /// Local file path to save
        output: PathBuf,
    },
    /// List virtual files available from a trusted server
    List {
        /// Trusted server name
        #[arg(short, long)]
        server: String,
        /// Our identity (must match client cert CN)
        #[arg(short, long)]
        identity: String,
    },
    /// Watch a directory and auto-send new files
    Watch {
        /// Directory to watch
        directory: PathBuf,
        /// Trusted server name to send to
        #[arg(short, long)]
        server: String,
        /// Our identity (must match client cert CN)
        #[arg(short, long)]
        identity: String,
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
    let config_path = cli
        .config
        .unwrap_or_else(|| default_config_path().to_string_lossy().to_string());

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
            server,
            identity,
            virtual_file,
            file,
            chunk_size,
        }) => {
            run_send(
                &config,
                &server,
                &identity,
                &virtual_file,
                &file,
                chunk_size,
            )
            .await?;
        }
        Some(Commands::Get {
            server,
            identity,
            virtual_file,
            output,
        }) => {
            run_get(&config, &server, &identity, &virtual_file, &output).await?;
        }
        Some(Commands::List { server, identity }) => {
            run_list(&config, &server, &identity).await?;
        }
        Some(Commands::Watch {
            directory,
            server,
            identity,
            virtual_file,
            pattern,
            interval,
            delete_after,
        }) => {
            run_watch(
                &config,
                &directory,
                &server,
                &identity,
                &virtual_file,
                &pattern,
                interval,
                delete_after,
            )
            .await?;
        }
        Some(Commands::Daemon) | None => {
            run_daemon(config, config_path).await?;
        }
    }

    Ok(())
}

async fn run_daemon(config: Config, config_path: String) -> Result<()> {
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

    // Create shared API state if enabled
    let api_state = if config.limits.api_enabled {
        Some(std::sync::Arc::new(api::ApiState::new(
            config.clone(),
            Some(std::path::PathBuf::from(&config_path)),
        )))
    } else {
        None
    };

    // Start API server if enabled
    if let Some(ref state) = api_state {
        let api_listen = config.limits.api_listen.clone();
        let api_key = config.limits.api_key.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            api::run_api_server(&api_listen, state_clone, api_key).await;
        });
        info!("API server started on {}", config.limits.api_listen);
    }

    if config.server.enabled {
        let config_path = config_path.clone();
        let server = Server::new(config, api_state.clone())?;

        // Setup SIGHUP handler for config reload
        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("Failed to install SIGHUP handler");

        // Setup graceful shutdown
        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C handler");
            info!("Received shutdown signal, stopping server...");
        };

        // Config reload task
        #[cfg(unix)]
        let reload_task = {
            let api_state = api_state.clone();
            let config_path = config_path.clone();
            async move {
                loop {
                    sighup.recv().await;
                    info!("Received SIGHUP, reloading configuration...");
                    match Config::load(&config_path) {
                        Ok(new_config) => {
                            if let Some(ref state) = api_state {
                                *state.config.write().await = new_config.clone();
                                info!("Configuration reloaded successfully");
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to reload config: {}", e);
                        }
                    }
                }
            }
        };

        #[cfg(unix)]
        tokio::select! {
            result = server.run() => {
                result?;
            }
            _ = shutdown => {
                info!("Server shutdown complete");
            }
            _ = reload_task => {}
        }

        #[cfg(not(unix))]
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
    server_name: &str,
    our_identity: &str,
    virtual_file: &str,
    file_path: &PathBuf,
    chunk_size: u32,
) -> Result<()> {
    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let server = config.find_trusted_server(server_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Trusted server '{}' not found in configuration",
            server_name
        )
    })?;

    let client = Client::new(config.client.clone())?;

    println!(
        "Sending file {:?} to {} ({}) as {}",
        file_path, server.name, server.address, our_identity
    );

    let result = client
        .send_file(server, our_identity, virtual_file, file_path, chunk_size)
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
    server_name: &str,
    our_identity: &str,
    virtual_file: &str,
    output_path: &PathBuf,
) -> Result<()> {
    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let server = config.find_trusted_server(server_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Trusted server '{}' not found in configuration",
            server_name
        )
    })?;

    let client = Client::new(config.client.clone())?;

    println!(
        "Getting file {} from {} ({}) as {}",
        virtual_file, server.name, server.address, our_identity
    );

    let result = client
        .get_file(server, our_identity, virtual_file, output_path)
        .await?;

    println!("\n✓ Download complete!");
    println!("  Total chunks: {}", result.total_chunks);
    println!("  Total bytes:  {}", result.total_bytes);
    println!("  File hash:    {}", result.file_hash);
    println!("  Saved to:     {:?}", output_path);

    Ok(())
}

async fn run_list(config: &Config, server_name: &str, our_identity: &str) -> Result<()> {
    if !config.client.enabled {
        anyhow::bail!("Client mode is disabled in configuration");
    }

    let server = config.find_trusted_server(server_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Trusted server '{}' not found in configuration",
            server_name
        )
    })?;

    let client = Client::new(config.client.clone())?;

    let mut conn = client.connect(&server.address).await?;
    conn.hello().await?;
    conn.auth(our_identity).await?;

    let response = conn.discover().await?;

    println!(
        "Virtual files available from {} ({}):",
        server.name, server.address
    );
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

#[allow(clippy::too_many_arguments)]
async fn run_watch(
    config: &Config,
    directory: &PathBuf,
    server_name: &str,
    our_identity: &str,
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

    let server = config
        .find_trusted_server(server_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Trusted server '{}' not found in configuration",
                server_name
            )
        })?
        .clone();

    let watch_config = WatchConfig {
        path: directory.clone(),
        pattern: Some(pattern.to_string()),
        server_name: server_name.to_string(),
        our_identity: our_identity.to_string(),
        virtual_file: virtual_file_prefix.to_string(),
        poll_interval_secs: interval_secs,
        delete_after_send: delete_after,
        move_to: None,
    };

    let (tx, mut rx) = mpsc::channel(100);
    let mut watcher = DirectoryWatcher::new(watch_config.clone(), tx);

    println!("Watching directory: {:?}", directory);
    println!("  Pattern: {}", pattern);
    println!("  Server: {} ({})", server.name, server.address);
    println!("  Identity: {}", our_identity);
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
                    .send_file(&server, our_identity, &vf_name, &path, chunk_size)
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
