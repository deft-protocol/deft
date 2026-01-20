# ⚡ Quick Start

Get RIFT running in 5 minutes.

## Prerequisites

- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- OpenSSL (for certificate generation)

## 1. Build

```bash
git clone https://github.com/yourorg/rift.git
cd rift
cargo build --release
```

## 2. Generate Test Certificates

```bash
# Create certificate directory
mkdir -p test-certs

# Generate CA
openssl genrsa -out test-certs/ca.key 4096
openssl req -new -x509 -days 365 -key test-certs/ca.key \
    -out test-certs/ca.crt -subj "/CN=RIFT Test CA"

# Generate server certificate
openssl genrsa -out test-certs/server.key 2048
openssl req -new -key test-certs/server.key \
    -out test-certs/server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in test-certs/server.csr \
    -CA test-certs/ca.crt -CAkey test-certs/ca.key \
    -CAcreateserial -out test-certs/server.crt

# Generate client certificate
openssl genrsa -out test-certs/client.key 2048
openssl req -new -key test-certs/client.key \
    -out test-certs/client.csr -subj "/CN=test-partner"
openssl x509 -req -days 365 -in test-certs/client.csr \
    -CA test-certs/ca.crt -CAkey test-certs/ca.key \
    -CAcreateserial -out test-certs/client.crt
```

## 3. Create Configuration

Create `test-config.toml`:

```toml
[server]
enabled = true
listen = "127.0.0.1:7741"
cert = "test-certs/server.crt"
key = "test-certs/server.key"
ca = "test-certs/ca.crt"

[client]
enabled = true
cert = "test-certs/client.crt"
key = "test-certs/client.key"
ca = "test-certs/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "/tmp/rift"

[limits]
metrics_enabled = true
metrics_port = 9090
api_enabled = true
api_listen = "127.0.0.1:7742"

[logging]
format = "text"
level = "info"

[[partners]]
id = "test-partner"
allowed_certs = ["test-certs/client.crt"]
endpoints = ["127.0.0.1:7741"]

[[partners.virtual_files]]
name = "test-files"
path = "/tmp/rift-test/"
direction = "receive"
```

## 4. Start the Daemon

```bash
# Create data directory
mkdir -p /tmp/rift-test

# Start daemon
./target/release/riftd --config test-config.toml
```

You should see:
```
INFO riftd: RIFT Daemon starting...
INFO riftd: Metrics server started on port 9090
INFO riftd: API server started on 127.0.0.1:7742
INFO riftd::server: Server listening on 127.0.0.1:7741
```

## 5. Test the Dashboard

Open http://localhost:7742 in your browser to see the web dashboard.

## 6. Send a File (New Terminal)

```bash
# Create a test file
echo "Hello RIFT!" > /tmp/test-file.txt

# Send it
./target/release/riftd --config test-config.toml \
    send test-partner test-files /tmp/test-file.txt
```

## 7. Check Metrics

```bash
curl http://localhost:9090/metrics | grep rift_
```

## Next Steps

- 📖 [Full Getting Started Guide](GETTING_STARTED.md) - Production setup
- ⚙️ [Configuration Reference](CONFIGURATION.md) - All options explained
- 🔌 [Hooks & Automation](HOOKS.md) - Script integration
- 📊 [API Documentation](API.md) - REST endpoints

## Troubleshooting

### Connection refused
- Check the daemon is running
- Verify the port is correct (default: 7741)

### Certificate errors
- Ensure CA matches between client and server
- Check certificate paths in config

### Permission denied
- Create required directories with proper permissions
- Run with appropriate user privileges

---

Need help? Check the [full documentation](GETTING_STARTED.md) or [open an issue](https://github.com/yourorg/rift/issues).
