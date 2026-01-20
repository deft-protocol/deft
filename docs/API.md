# 📊 REST API Reference

DEFT provides a REST API for monitoring and management.

## Enabling the API

```toml
[limits]
api_enabled = true
api_listen = "127.0.0.1:7742"
api_key = "your-secret-key"  # Optional
```

## Authentication

If `api_key` is configured, include it in requests:

```bash
curl -H "Authorization: Bearer your-secret-key" http://localhost:7742/api/status
```

---

## Endpoints

### GET /

Returns the web dashboard HTML.

```bash
open http://localhost:7742/
```

---

### GET /api/status

System status and health information.

**Response:**

```json
{
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "active_connections": 5,
  "active_transfers": 2,
  "total_transfers": 150,
  "total_bytes": 1073741824,
  "metrics_enabled": true
}
```

**Example:**

```bash
curl http://localhost:7742/api/status
```

---

### GET /api/partners

List configured partners and their status.

**Response:**

```json
[
  {
    "id": "acme-corp",
    "endpoints": ["deft.acme.com:7741", "deft-backup.acme.com:7741"],
    "connected": true,
    "last_seen": "2026-01-20T12:00:00Z",
    "transfers_today": 25,
    "bytes_today": 104857600
  },
  {
    "id": "supplier-inc",
    "endpoints": ["deft.supplier.com:7741"],
    "connected": false,
    "last_seen": "2026-01-19T18:30:00Z",
    "transfers_today": 0,
    "bytes_today": 0
  }
]
```

**Example:**

```bash
curl http://localhost:7742/api/partners
```

---

### GET /api/transfers

List active transfers.

**Response:**

```json
[
  {
    "id": "tx-abc123",
    "virtual_file": "daily-orders",
    "partner_id": "acme-corp",
    "direction": "send",
    "status": "active",
    "progress_percent": 75,
    "bytes_transferred": 78643200,
    "total_bytes": 104857600,
    "started_at": "2026-01-20T11:55:00Z",
    "updated_at": "2026-01-20T12:00:00Z"
  }
]
```

**Example:**

```bash
curl http://localhost:7742/api/transfers
```

---

### GET /api/transfers/:id

Get details of a specific transfer.

**Response:**

```json
{
  "id": "tx-abc123",
  "virtual_file": "daily-orders",
  "partner_id": "acme-corp",
  "direction": "send",
  "status": "active",
  "progress_percent": 75,
  "bytes_transferred": 78643200,
  "total_bytes": 104857600,
  "started_at": "2026-01-20T11:55:00Z",
  "updated_at": "2026-01-20T12:00:00Z"
}
```

**Example:**

```bash
curl http://localhost:7742/api/transfers/tx-abc123
```

---

### POST /api/transfers

Start a new transfer.

**Request:**

```json
{
  "partner_id": "acme-corp",
  "virtual_file": "daily-orders",
  "source_path": "/data/orders.xml"
}
```

**Response:**

```json
{
  "status": "queued",
  "message": "Transfer to acme-corp queued for daily-orders",
  "transfer_id": "pending-1737392400000"
}
```

**Example:**

```bash
curl -X POST http://localhost:7742/api/transfers \
  -H "Content-Type: application/json" \
  -d '{"partner_id":"acme-corp","virtual_file":"daily-orders"}'
```

---

### DELETE /api/transfers/:id

Cancel an active transfer.

**Response:**

```json
{
  "status": "cancelled"
}
```

**Example:**

```bash
curl -X DELETE http://localhost:7742/api/transfers/tx-abc123
```

---

### POST /api/transfers/:id/retry

Retry a failed transfer from history.

**Response:**

```json
{
  "status": "retry_queued"
}
```

**Example:**

```bash
curl -X POST http://localhost:7742/api/transfers/tx-abc123/retry
```

---

### GET /api/history

List completed transfers history.

**Response:**

```json
[
  {
    "id": "tx-abc123",
    "virtual_file": "daily-orders",
    "partner_id": "acme-corp",
    "direction": "send",
    "status": "complete",
    "total_bytes": 104857600,
    "started_at": "2026-01-20T11:55:00Z",
    "completed_at": "2026-01-20T12:05:00Z"
  }
]
```

**Example:**

```bash
curl http://localhost:7742/api/history
```

---

### GET /api/virtual-files

List all virtual files across all partners.

**Response:**

```json
[
  {
    "name": "daily-orders",
    "path": "/data/orders/",
    "direction": "send",
    "partner_id": "acme-corp"
  },
  {
    "name": "invoices",
    "path": "/data/invoices/",
    "direction": "receive",
    "partner_id": "acme-corp"
  }
]
```

**Example:**

```bash
curl http://localhost:7742/api/virtual-files
```

---

### GET /api/virtual-files/:name

Get details of a specific virtual file.

**Response:**

```json
{
  "name": "daily-orders",
  "path": "/data/orders/",
  "direction": "send",
  "partner_id": "acme-corp"
}
```

**Example:**

```bash
curl http://localhost:7742/api/virtual-files/daily-orders
```

---

### POST /api/virtual-files

Create a new virtual file.

**Request:**

```json
{
  "name": "reports",
  "path": "/data/reports/",
  "direction": "send",
  "partner_id": "acme-corp"
}
```

**Response:**

```json
{
  "status": "created",
  "name": "reports"
}
```

**Example:**

```bash
curl -X POST http://localhost:7742/api/virtual-files \
  -H "Content-Type: application/json" \
  -d '{"name":"reports","path":"/data/reports/","direction":"send","partner_id":"acme-corp"}'
```

---

### PUT /api/virtual-files/:name

Update an existing virtual file.

**Request:**

```json
{
  "name": "reports",
  "path": "/data/new-reports/",
  "direction": "receive",
  "partner_id": "acme-corp"
}
```

**Response:**

```json
{
  "status": "updated"
}
```

**Example:**

```bash
curl -X PUT http://localhost:7742/api/virtual-files/reports \
  -H "Content-Type: application/json" \
  -d '{"name":"reports","path":"/data/new-reports/","direction":"receive","partner_id":"acme-corp"}'
```

---

### DELETE /api/virtual-files/:name

Delete a virtual file.

**Response:**

```json
{
  "status": "deleted"
}
```

**Example:**

```bash
curl -X DELETE http://localhost:7742/api/virtual-files/reports
```

---

### GET /api/partners/:id/virtual-files

List virtual files for a specific partner.

**Response:**

```json
[
  {
    "name": "daily-orders",
    "path": "/data/orders/",
    "direction": "send",
    "partner_id": "acme-corp"
  }
]
```

**Example:**

```bash
curl http://localhost:7742/api/partners/acme-corp/virtual-files
```

---

### POST /api/partners/:id/virtual-files

Add a virtual file to a partner.

**Request:**

```json
{
  "name": "new-feed",
  "path": "/data/feed/",
  "direction": "send"
}
```

**Response:**

```json
{
  "status": "created",
  "name": "new-feed"
}
```

**Example:**

```bash
curl -X POST http://localhost:7742/api/partners/acme-corp/virtual-files \
  -H "Content-Type: application/json" \
  -d '{"name":"new-feed","path":"/data/feed/","direction":"send"}'
```

---

### GET /api/config

Current configuration summary (sensitive values redacted).

**Response:**

```json
{
  "server": {
    "enabled": true,
    "listen": "0.0.0.0:7741"
  },
  "client": {
    "enabled": true
  },
  "storage": {
    "chunk_size": 262144
  },
  "limits": {
    "max_connections_per_ip": 10,
    "max_requests_per_partner": 1000,
    "parallel_chunks": 4,
    "metrics_enabled": true
  },
  "partners_count": 3
}
```

**Example:**

```bash
curl http://localhost:7742/api/config
```

---

### GET /api/metrics

Prometheus metrics in JSON format.

**Response:**

```json
{
  "metrics": "# HELP deft_connections_total Total connections\n# TYPE deft_connections_total counter\ndeft_connections_total 150\n..."
}
```

**Example:**

```bash
curl http://localhost:7742/api/metrics
```

> **Note:** For Prometheus scraping, use the dedicated metrics endpoint on port 9090.

---

## Error Responses

### 401 Unauthorized

```json
{
  "error": "Invalid API key"
}
```

### 404 Not Found

```json
{
  "error": "Not found"
}
```

---

## CORS

The API includes CORS headers for browser access:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Authorization, Content-Type
```

---

## Prometheus Metrics

When `metrics_enabled = true`, a separate endpoint is available:

```bash
curl http://localhost:9090/metrics
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `deft_connections_total` | counter | - | Total connections received |
| `deft_connections_active` | gauge | - | Current active connections |
| `deft_transfers_total` | counter | direction, status | Total transfers |
| `deft_bytes_transferred_total` | counter | direction | Total bytes transferred |
| `deft_bytes_compressed_saved_total` | counter | - | Bytes saved by compression |
| `deft_chunks_sent_total` | counter | - | Total chunks sent |
| `deft_chunks_received_total` | counter | - | Total chunks received |
| `deft_transfer_duration_seconds` | histogram | direction | Transfer duration |
| `deft_rate_limited_total` | counter | type | Rate limit events |
| `deft_endpoint_health` | gauge | partner_id, endpoint | Endpoint health (0/1) |
| `deft_errors_total` | counter | type | Error count by type |

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'deft'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

### Grafana Dashboard

Import the included dashboard from `docs/grafana-dashboard.json` or create panels:

```
# Connections rate
rate(deft_connections_total[5m])

# Transfer throughput
rate(deft_bytes_transferred_total[5m])

# Error rate
rate(deft_errors_total[5m])
```

---

## Web Dashboard

The built-in dashboard at `http://localhost:7742/` provides:

- **System Status** - Uptime, version, active connections
- **Partners** - Partner list with connection status
- **Transfers** - Active transfer progress
- **Configuration** - Current config summary

### Screenshot

```
┌─────────────────────────────────────────────────┐
│ ⚡ DEFT Admin                    [Connected]    │
├─────────────────────────────────────────────────┤
│ [Dashboard] [Partners] [Transfers] [Config]    │
├─────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │  2h 15m  │ │    5     │ │    2     │        │
│  │  Uptime  │ │ Connections│ │ Transfers│        │
│  └──────────┘ └──────────┘ └──────────┘        │
│                                                 │
│  Recent Activity                                │
│  ─────────────────────────────────────          │
│  12:00:05  Transfer completed: daily-orders     │
│  11:58:32  Partner connected: acme-corp         │
│  11:55:00  Transfer started: invoices           │
└─────────────────────────────────────────────────┘
```

---

## Security Recommendations

1. **Bind to localhost** - Use `api_listen = "127.0.0.1:7742"` in production
2. **Use API key** - Set `api_key` for authentication
3. **Reverse proxy** - Put behind nginx/traefik for HTTPS
4. **Firewall** - Block external access to port 7742

### Nginx Proxy Example

```nginx
server {
    listen 443 ssl;
    server_name deft-admin.yourcompany.com;

    ssl_certificate /etc/ssl/certs/admin.crt;
    ssl_certificate_key /etc/ssl/private/admin.key;

    location / {
        proxy_pass http://127.0.0.1:7742;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## See Also

- [Configuration](CONFIGURATION.md) - Enable API in config
- [Getting Started](GETTING_STARTED.md) - Initial setup
- [Hooks](HOOKS.md) - Automation
