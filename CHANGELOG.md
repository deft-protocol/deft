# Changelog

All notable changes to RIFT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-20

### Added

#### Core Features
- **mTLS Authentication** - Mutual TLS for all connections
- **Chunked Transfers** - Resumable file transfers with integrity verification
- **Parallel Transfers** - Concurrent chunk uploads/downloads
- **Compression** - Automatic gzip compression when beneficial
- **Delta Sync** - rsync-like incremental transfers

#### Security
- **Ed25519 Signatures** - Cryptographic signing of transfer receipts
- **Rate Limiting** - Per IP, partner, and bandwidth limits
- **Anti-replay Protection** - Nonces per chunk
- **Random Chunk Ordering** - Anti-MITM measure

#### Monitoring & Management
- **Prometheus Metrics** - Full observability endpoint
- **Web Dashboard** - Real-time monitoring UI
- **REST API** - Programmatic access to status and config
- **JSON Logging** - Structured logs for aggregators

#### Automation
- **Directory Watching** - Auto-send new files
- **Plugin Hooks** - Execute scripts on transfer events
- **Multi-endpoint Failover** - Automatic endpoint switching

#### Platform Support
- Linux (Ubuntu, Debian, RHEL, CentOS)
- macOS (12+)
- Windows (10+)

### Security
- TLS 1.3 minimum required
- SHA-256 integrity verification per chunk
- Certificate-based partner authentication

---

## [0.2.0] - 2026-01-19

### Added
- Rate limiting (IP, partner, bandwidth)
- Configurable timeouts
- Compression support (gzip)
- Graceful shutdown handling
- Parallel transfer coordinator
- Multi-endpoint discovery
- Prometheus metrics foundation

### Changed
- Improved chunk ordering (randomized)
- Enhanced protocol with nonces

---

## [0.1.0] - 2026-01-15

### Added
- Initial protocol implementation
- Basic server and client
- mTLS support
- Chunked file transfers
- Partner configuration
- Virtual file mapping
- Transfer receipts

---

## Roadmap

### v1.1.0 (Planned)
- [ ] Clustering / High Availability
- [ ] End-to-end encryption (at rest)
- [ ] Python SDK
- [ ] JavaScript SDK

### v2.0.0 (Future)
- [ ] WebSocket transport option
- [ ] S3-compatible storage backend
- [ ] Kubernetes operator
- [ ] OpenAPI documentation

---

## Migration Guides

### v0.2.0 → v1.0.0

No breaking changes. New features are opt-in via configuration.

**New config options:**
```toml
[limits]
api_enabled = true
api_listen = "127.0.0.1:7742"
```

### v0.1.0 → v0.2.0

**Config changes:**
- Added `[limits]` section for rate limiting
- Added `parallel_chunks` option

---

[1.0.0]: https://github.com/yourorg/rift/releases/tag/v1.0.0
[0.2.0]: https://github.com/yourorg/rift/releases/tag/v0.2.0
[0.1.0]: https://github.com/yourorg/rift/releases/tag/v0.1.0
