# 📖 Getting Started Guide

Complete guide to deploying DEFT in production.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Certificate Setup](#certificate-setup)
4. [Configuration](#configuration)
5. [Partner Setup](#partner-setup)
6. [Running the Daemon](#running-the-daemon)
7. [Systemd Service](#systemd-service)
8. [Verification](#verification)

---

## System Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 512 MB | 2+ GB |
| Disk | 1 GB | 10+ GB (depends on file sizes) |
| Network | 10 Mbps | 100+ Mbps |

### Software

- **OS**: Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+), macOS 12+, Windows 10+
- **Rust**: 1.70+ (for building from source)
- **OpenSSL**: 1.1.1+ (for TLS)

### Network Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 7741 | TCP/TLS | DEFT protocol (configurable) |
| 9090 | TCP/HTTP | Prometheus metrics (optional) |
| 7742 | TCP/HTTP | Web dashboard API (optional) |

---

## Installation

### From Source (Recommended)

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/deft/deft.git
cd deft
cargo build --release

# Install binary
sudo cp target/release/deftd /usr/local/bin/
sudo chmod +x /usr/local/bin/deftd

# Verify installation
deftd --version
```

### Directory Structure

```bash
# Create standard directories
sudo mkdir -p /etc/deft/certs
sudo mkdir -p /etc/deft/partners
sudo mkdir -p /var/deft/data
sudo mkdir -p /var/deft/tmp
sudo mkdir -p /var/deft/receipts
sudo mkdir -p /var/log/deft

# Set permissions
sudo chown -R deft:deft /var/deft
sudo chmod 700 /etc/deft/certs
```

---

## Certificate Setup

DEFT requires mTLS (mutual TLS) for all connections. You need:

1. **CA certificate** - Signs all partner certificates
2. **Server certificate** - Identifies your DEFT instance
3. **Partner certificates** - One per trading partner

### Option 1: Self-Signed CA (Development/Internal)

```bash
cd /etc/deft/certs

# 1. Generate CA private key
openssl genrsa -out ca.key 4096

# 2. Generate CA certificate (valid 10 years)
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=FR/O=YourCompany/CN=DEFT Internal CA"

# 3. Generate server private key
openssl genrsa -out server.key 2048

# 4. Generate server CSR
openssl req -new -key server.key -out server.csr \
    -subj "/C=FR/O=YourCompany/CN=deft.yourcompany.com"

# 5. Sign server certificate
openssl x509 -req -days 365 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt \
    -extfile <(echo "subjectAltName=DNS:deft.yourcompany.com,DNS:localhost,IP:127.0.0.1")

# 6. Set secure permissions
chmod 600 *.key
chmod 644 *.crt
```

### Option 2: Using Let's Encrypt (Public)

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d deft.yourcompany.com

# Certificates will be in /etc/letsencrypt/live/deft.yourcompany.com/
# - fullchain.pem (certificate)
# - privkey.pem (private key)

# Still need a CA for partner authentication (use self-signed)
```

### Generate Partner Certificate

For each trading partner:

```bash
PARTNER_ID="acme-corp"

# Generate partner key
openssl genrsa -out /etc/deft/partners/${PARTNER_ID}.key 2048

# Generate CSR
openssl req -new -key /etc/deft/partners/${PARTNER_ID}.key \
    -out /etc/deft/partners/${PARTNER_ID}.csr \
    -subj "/C=US/O=ACME Corporation/CN=${PARTNER_ID}"

# Sign with your CA
openssl x509 -req -days 365 \
    -in /etc/deft/partners/${PARTNER_ID}.csr \
    -CA /etc/deft/certs/ca.crt \
    -CAkey /etc/deft/certs/ca.key \
    -CAcreateserial \
    -out /etc/deft/partners/${PARTNER_ID}.crt

# Send to partner: ${PARTNER_ID}.crt and ${PARTNER_ID}.key
# Keep: ${PARTNER_ID}.crt (for allowed_certs in config)
```

---

## Configuration

Create `/etc/deft/config.toml`:

```toml
#
# DEFT Configuration
#

[server]
enabled = true
listen = "0.0.0.0:7741"
cert = "/etc/deft/certs/server.crt"
key = "/etc/deft/certs/server.key"
ca = "/etc/deft/certs/ca.crt"

[client]
enabled = true
cert = "/etc/deft/certs/server.crt"
key = "/etc/deft/certs/server.key"
ca = "/etc/deft/certs/ca.crt"

[storage]
chunk_size = 262144          # 256 KB chunks
temp_dir = "/var/deft/tmp"

[limits]
# Rate limiting
max_connections_per_ip = 10
max_requests_per_partner = 1000
max_bytes_per_partner = 10737418240  # 10 GB per window
window_seconds = 3600                 # 1 hour window
ban_seconds = 300

# Timeouts
connection_timeout_seconds = 30
transfer_timeout_seconds = 3600       # 1 hour
idle_timeout_seconds = 300            # 5 minutes

# Performance
parallel_chunks = 4

# Monitoring (optional)
metrics_enabled = true
metrics_port = 9090

# Web Dashboard (optional)
api_enabled = true
api_listen = "127.0.0.1:7742"
# api_key = "your-secret-key"        # Enable for authentication

[logging]
format = "json"                       # "text" or "json"
level = "info"                        # trace, debug, info, warn, error
```

See [Configuration Reference](CONFIGURATION.md) for all options.

---

## Partner Setup

Add partners to your configuration:

```toml
# Partner: ACME Corporation
[[partners]]
id = "acme-corp"
allowed_certs = ["/etc/deft/partners/acme-corp.crt"]
endpoints = ["deft.acme.com:7741", "deft-backup.acme.com:7741"]

# Virtual files we SEND to this partner (they can GET)
[[partners.virtual_files]]
name = "daily-orders"
path = "/data/orders/outbound/*.xml"
direction = "send"

# Virtual files we RECEIVE from this partner (they can PUT)
[[partners.virtual_files]]
name = "invoices"
path = "/data/invoices/inbound/"
direction = "receive"


# Partner: Supplier Inc
[[partners]]
id = "supplier-inc"
allowed_certs = ["/etc/deft/partners/supplier.crt"]
endpoints = ["deft.supplier.com:7741"]

[[partners.virtual_files]]
name = "product-catalog"
path = "/data/catalog/"
direction = "receive"
```

### Virtual File Directions

| Direction | Meaning | Partner Can |
|-----------|---------|-------------|
| `send` | We have files to send | GET (download) |
| `receive` | We accept files | PUT (upload) |

---

## Running the Daemon

### Foreground (Testing)

```bash
deftd --config /etc/deft/config.toml
```

### With Custom Log Level

```bash
deftd --config /etc/deft/config.toml --log-level debug
```

---

## Systemd Service

Create `/etc/systemd/system/deft.service`:

```ini
[Unit]
Description=DEFT Protocol Daemon
After=network.target

[Service]
Type=simple
User=deft
Group=deft
ExecStart=/usr/local/bin/deftd --config /etc/deft/config.toml
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/deft /var/log/deft
PrivateTmp=true

# Resource limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Create deft user
sudo useradd -r -s /bin/false deft

# Set ownership
sudo chown -R deft:deft /var/deft /etc/deft

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable deft
sudo systemctl start deft

# Check status
sudo systemctl status deft
sudo journalctl -u deft -f
```

---

## Verification

### Check Daemon Status

```bash
# Service status
sudo systemctl status deft

# View logs
sudo journalctl -u deft -f

# Check listening port
ss -tlnp | grep 7741
```

### Test Metrics Endpoint

```bash
curl http://localhost:9090/metrics | head -20
```

### Test Web Dashboard

Open http://localhost:7742 in a browser.

### Test Partner Connection

```bash
# From partner's machine
deftd --config /path/to/partner-config.toml \
    list your-partner-id
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/deft-healthcheck.sh

# Check process
if ! pgrep -x deftd > /dev/null; then
    echo "CRITICAL: deftd not running"
    exit 2
fi

# Check port
if ! nc -z localhost 7741; then
    echo "CRITICAL: Port 7741 not responding"
    exit 2
fi

# Check metrics
if curl -sf http://localhost:9090/metrics > /dev/null; then
    echo "OK: DEFT daemon healthy"
    exit 0
else
    echo "WARNING: Metrics endpoint not responding"
    exit 1
fi
```

---

## Next Steps

- [Configuration Reference](CONFIGURATION.md) - All configuration options
- [API Documentation](API.md) - REST API endpoints
- [Hooks & Plugins](HOOKS.md) - Automation with scripts
- [Protocol Specification](PROTOCOL.md) - Wire protocol details

---

## Troubleshooting

### Common Issues

**"Connection refused"**
- Check firewall rules: `sudo ufw allow 7741/tcp`
- Verify daemon is running: `systemctl status deft`

**"Certificate verify failed"**
- Ensure CA certificate matches on both sides
- Check certificate expiration: `openssl x509 -in cert.crt -noout -dates`

**"Partner not found"**
- Verify partner ID matches in config
- Check certificate CN matches partner ID

**"Permission denied"**
- Check file ownership: `ls -la /var/deft/`
- Verify deft user can read certificates

### Debug Mode

```bash
# Run with debug logging
deftd --config /etc/deft/config.toml --log-level debug

# Or set in config.toml
[logging]
level = "debug"
```

### Support

- Check logs: `journalctl -u deft -n 100`
- Open an issue: https://github.com/deft/deft/issues
