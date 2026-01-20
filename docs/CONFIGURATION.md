# ⚙️ Configuration Reference

Complete reference for all FlowPact configuration options.

## Configuration File

Default location: `/etc/rift/config.toml`

Override with: `flowpactd --config /path/to/config.toml`

---

## Sections

- [server](#server) - Server settings
- [client](#client) - Client settings
- [storage](#storage) - Storage settings
- [limits](#limits) - Rate limiting and timeouts
- [logging](#logging) - Logging configuration
- [partners](#partners) - Partner definitions

---

## [server]

Server mode configuration for accepting incoming connections.

```toml
[server]
enabled = true
listen = "0.0.0.0:7741"
cert = "/etc/rift/certs/server.crt"
key = "/etc/rift/certs/server.key"
ca = "/etc/rift/certs/ca.crt"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable server mode |
| `listen` | string | `"0.0.0.0:7741"` | Address and port to listen on |
| `cert` | string | required | Path to server certificate (PEM) |
| `key` | string | required | Path to server private key (PEM) |
| `ca` | string | required | Path to CA certificate for client validation |

---

## [client]

Client mode configuration for outgoing connections.

```toml
[client]
enabled = true
cert = "/etc/rift/certs/client.crt"
key = "/etc/rift/certs/client.key"
ca = "/etc/rift/certs/ca.crt"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable client mode |
| `cert` | string | required | Path to client certificate (PEM) |
| `key` | string | required | Path to client private key (PEM) |
| `ca` | string | required | Path to CA certificate for server validation |

---

## [storage]

File storage and chunking settings.

```toml
[storage]
chunk_size = 262144
temp_dir = "/var/rift/tmp"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `chunk_size` | integer | `262144` | Chunk size in bytes (256 KB) |
| `temp_dir` | string | `"/var/rift/tmp"` | Temporary directory for transfers |

### Chunk Size Guidelines

| File Size | Recommended Chunk Size |
|-----------|----------------------|
| < 10 MB | 64 KB (`65536`) |
| 10-100 MB | 256 KB (`262144`) |
| 100 MB - 1 GB | 1 MB (`1048576`) |
| > 1 GB | 4 MB (`4194304`) |

---

## [limits]

Rate limiting, timeouts, and performance settings.

```toml
[limits]
# Rate limiting
max_connections_per_ip = 10
max_requests_per_partner = 1000
max_bytes_per_partner = 10737418240
window_seconds = 3600
ban_seconds = 300

# Timeouts
connection_timeout_seconds = 30
transfer_timeout_seconds = 3600
idle_timeout_seconds = 300

# Performance
parallel_chunks = 4

# Prometheus metrics
metrics_enabled = false
metrics_port = 9090

# Web API
api_enabled = false
api_listen = "127.0.0.1:7742"
api_key = "your-secret-key"
```

### Rate Limiting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_connections_per_ip` | integer | `10` | Max concurrent connections per IP |
| `max_requests_per_partner` | integer | `1000` | Max requests per partner per window |
| `max_bytes_per_partner` | integer | `1073741824` | Max bytes per partner per window (1 GB) |
| `window_seconds` | integer | `60` | Rate limit window duration |
| `ban_seconds` | integer | `300` | Ban duration when limit exceeded |

### Timeouts

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `connection_timeout_seconds` | integer | `30` | Connection establishment timeout |
| `transfer_timeout_seconds` | integer | `3600` | Maximum transfer duration (1 hour) |
| `idle_timeout_seconds` | integer | `300` | Idle connection timeout (5 min) |

### Performance

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `parallel_chunks` | integer | `4` | Concurrent chunk transfers |

### Monitoring

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `metrics_enabled` | bool | `false` | Enable Prometheus metrics endpoint |
| `metrics_port` | integer | `9090` | Metrics HTTP port |

### Web API

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_enabled` | bool | `false` | Enable REST API and dashboard |
| `api_listen` | string | `"127.0.0.1:7742"` | API listen address |
| `api_key` | string | none | Optional API authentication key |

---

## [logging]

Logging configuration.

```toml
[logging]
format = "text"
level = "info"
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `format` | string | `"text"` | Log format: `"text"` or `"json"` |
| `level` | string | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |

### JSON Format

When `format = "json"`, logs are structured for log aggregators:

```json
{"timestamp":"2026-01-20T12:00:00Z","level":"INFO","target":"flowpactd::server","message":"Connection accepted","peer":"192.168.1.100:54321"}
```

---

## [[partners]]

Partner definitions. Repeat for each trading partner.

```toml
[[partners]]
id = "acme-corp"
allowed_certs = ["/etc/rift/partners/acme-corp.crt"]
endpoints = ["rift.acme.com:7741", "rift-backup.acme.com:7741"]

[[partners.virtual_files]]
name = "orders-outbound"
path = "/data/orders/*.xml"
direction = "send"

[[partners.virtual_files]]
name = "invoices-inbound"
path = "/data/invoices/"
direction = "receive"
```

### Partner Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `id` | string | yes | Unique partner identifier |
| `allowed_certs` | array | yes | List of allowed certificate paths |
| `endpoints` | array | yes | Partner endpoints (host:port) |

### Virtual File Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | yes | Virtual file name (used in protocol) |
| `path` | string | yes | Local file path (glob patterns supported) |
| `direction` | string | yes | `"send"` or `"receive"` |

### Direction Explained

| Direction | You Can | Partner Can |
|-----------|---------|-------------|
| `send` | Serve files | GET (download) |
| `receive` | Accept files | PUT (upload) |

### Path Patterns

```toml
# Single file
path = "/data/catalog.json"

# Glob pattern
path = "/data/orders/*.xml"

# Directory (for receiving)
path = "/data/incoming/"
```

---

## Complete Example

```toml
#
# FlowPact Configuration - Production Example
#

[server]
enabled = true
listen = "0.0.0.0:7741"
cert = "/etc/rift/certs/server.crt"
key = "/etc/rift/certs/server.key"
ca = "/etc/rift/certs/ca.crt"

[client]
enabled = true
cert = "/etc/rift/certs/server.crt"
key = "/etc/rift/certs/server.key"
ca = "/etc/rift/certs/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "/var/rift/tmp"

[limits]
max_connections_per_ip = 10
max_requests_per_partner = 1000
max_bytes_per_partner = 10737418240
window_seconds = 3600
ban_seconds = 300
connection_timeout_seconds = 30
transfer_timeout_seconds = 3600
idle_timeout_seconds = 300
parallel_chunks = 4
metrics_enabled = true
metrics_port = 9090
api_enabled = true
api_listen = "127.0.0.1:7742"

[logging]
format = "json"
level = "info"

# Partner: ACME Corporation
[[partners]]
id = "acme-corp"
allowed_certs = ["/etc/rift/partners/acme-corp.crt"]
endpoints = ["rift.acme.com:7741", "rift-backup.acme.com:7741"]

[[partners.virtual_files]]
name = "daily-orders"
path = "/data/orders/outbound/*.xml"
direction = "send"

[[partners.virtual_files]]
name = "invoices"
path = "/data/invoices/inbound/"
direction = "receive"

# Partner: Supplier Inc
[[partners]]
id = "supplier-inc"
allowed_certs = ["/etc/rift/partners/supplier.crt"]
endpoints = ["rift.supplier.com:7741"]

[[partners.virtual_files]]
name = "product-catalog"
path = "/data/catalog/"
direction = "receive"

[[partners.virtual_files]]
name = "purchase-orders"
path = "/data/po/outbound/*.json"
direction = "send"
```

---

## Environment Variables

Configuration values can be overridden with environment variables:

```bash
export FlowPact_LOG_LEVEL=debug
export FlowPact_METRICS_PORT=9091
```

---

## Validation

Validate configuration without starting:

```bash
flowpactd --config /etc/rift/config.toml --validate
```

---

## See Also

- [Getting Started](GETTING_STARTED.md) - Initial setup guide
- [API Reference](API.md) - REST API documentation
- [Hooks](HOOKS.md) - Plugin system
