# ⚡ RIFT - Reliable Interoperable File Transfer

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](CHANGELOG.md)

**RIFT** is a modern, secure file transfer protocol designed for B2B (Business-to-Business) exchanges. It provides reliable, resumable transfers with enterprise-grade security and observability.

## ✨ Features

- 🔒 **Security** - mTLS + Ed25519 signatures + rate limiting
- 🚀 **Performance** - Parallel transfers + gzip compression + delta-sync
- 📊 **Observability** - Prometheus metrics + JSON logging + Web dashboard
- 🔄 **Reliability** - Automatic resume + multi-endpoint failover
- 🎯 **Automation** - Directory watching + plugin hooks
- 🌍 **Cross-platform** - Windows, Linux, macOS

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | Get running in 5 minutes |
| [Getting Started](docs/GETTING_STARTED.md) | Complete setup guide |
| [Configuration](docs/CONFIGURATION.md) | All configuration options |
| [API Reference](docs/API.md) | REST API documentation |
| [Hooks & Plugins](docs/HOOKS.md) | Automation with scripts |
| [Protocol Spec](docs/PROTOCOL.md) | Wire protocol details |

## 🚀 Quick Start

```bash
# Build
cargo build --release

# Run daemon
./target/release/riftd --config config.example.toml

# Send a file
./target/release/riftd send partner-id invoices /path/to/file.xml

# Watch a directory
./target/release/riftd watch /data/outbound partner-id orders --pattern "*.xml"
```

## 📦 Installation

### From Source

```bash
git clone https://github.com/yourorg/rift.git
cd rift
cargo build --release

# Install binaries
sudo cp target/release/riftd /usr/local/bin/
```

### Configuration

```bash
# Copy example config
sudo mkdir -p /etc/rift
sudo cp config.example.toml /etc/rift/config.toml

# Generate certificates (see docs/GETTING_STARTED.md)
```

## 🏗️ Architecture

```
rift/
├── rift-protocol/     # Protocol definitions (commands, responses, parser)
├── rift-common/       # Shared utilities (chunking, hashing)
├── rift-daemon/       # Unified daemon (server + client + API)
│   ├── src/
│   │   ├── server.rs      # TLS server
│   │   ├── client.rs      # TLS client
│   │   ├── handler.rs     # Protocol handler
│   │   ├── api.rs         # REST API + Web dashboard
│   │   ├── metrics.rs     # Prometheus metrics
│   │   ├── hooks.rs       # Plugin system
│   │   ├── delta.rs       # Delta-sync algorithm
│   │   └── watcher.rs     # Directory watching
│   └── static/            # Web dashboard assets
└── docs/                  # Documentation
```

## 🔧 CLI Commands

```bash
# Start daemon (server mode)
riftd daemon

# Send a file to a partner
riftd send <partner-id> <virtual-file> <local-file>

# Receive a file from a partner
riftd get <partner-id> <virtual-file> <output-file>

# List available files from a partner
riftd list <partner-id>

# Watch directory and auto-send new files
riftd watch <directory> <partner-id> <virtual-file> [options]
    --pattern "*.xml"    # File pattern (glob)
    --interval 30        # Poll interval in seconds
    --delete-after       # Delete files after successful send
```

## 📊 Monitoring

### Prometheus Metrics

```bash
# Enable in config.toml
[limits]
metrics_enabled = true
metrics_port = 9090

# Scrape endpoint
curl http://localhost:9090/metrics
```

Available metrics:
- `rift_connections_total` / `rift_connections_active`
- `rift_transfers_total{direction,status}`
- `rift_bytes_transferred_total{direction}`
- `rift_transfer_duration_seconds{direction}`
- `rift_chunks_sent_total` / `rift_chunks_received_total`

### Web Dashboard

```bash
# Enable in config.toml
[limits]
api_enabled = true
api_listen = "127.0.0.1:7742"

# Access dashboard
open http://localhost:7742/
```

## 🔌 Plugin Hooks

Execute scripts on transfer events:

```toml
# In config.toml
[[hooks]]
event = "post_transfer"
command = "/scripts/notify.sh"
partners = ["acme-corp"]  # Optional filter
```

Available events: `pre_transfer`, `post_transfer`, `transfer_error`, `file_received`, `file_sent`

Environment variables: `RIFT_EVENT`, `RIFT_PARTNER_ID`, `RIFT_VIRTUAL_FILE`, `RIFT_FILE_SIZE`, `RIFT_CONTEXT_JSON`

## 🔒 Security

| Feature | Implementation |
|---------|----------------|
| Transport | TLS 1.3 (mTLS required) |
| Authentication | X.509 certificates |
| Integrity | SHA-256 per chunk |
| Signatures | Ed25519 for receipts |
| Rate Limiting | Per IP, partner, bandwidth |
| Anti-replay | Nonces per chunk |

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/yourorg/rift/issues)
- 💬 [Discussions](https://github.com/yourorg/rift/discussions)
