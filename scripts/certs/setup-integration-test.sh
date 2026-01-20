#!/bin/bash
# Setup certificates for DEFT integration testing with 2 instances
# Usage: ./setup-integration-test.sh <base_dir>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${1:-/tmp/deft-integration}"

echo "=== Setting up DEFT integration test environment ==="
echo "Base directory: $BASE_DIR"

# Create directory structure
mkdir -p "$BASE_DIR"/{instance-a,instance-b}/{data,outbox,received,tmp}

# Generate CA (shared between both instances)
echo ""
echo "=== Generating CA ==="
"$SCRIPT_DIR/generate-ca.sh" "$BASE_DIR" "deft-integration-ca"

# Copy CA to both instances
cp "$BASE_DIR/ca.crt" "$BASE_DIR/instance-a/"
cp "$BASE_DIR/ca.crt" "$BASE_DIR/instance-b/"

# Generate server cert for instance-a
echo ""
echo "=== Generating Instance A server certificate ==="
"$SCRIPT_DIR/generate-server-cert.sh" "$BASE_DIR" "$BASE_DIR/instance-a" "instance-a-server" "localhost" "127.0.0.1"

# Generate client cert for instance-a
echo ""
echo "=== Generating Instance A client certificate ==="
"$SCRIPT_DIR/generate-client-cert.sh" "$BASE_DIR" "$BASE_DIR/instance-a" "instance-a"

# Generate server cert for instance-b
echo ""
echo "=== Generating Instance B server certificate ==="
"$SCRIPT_DIR/generate-server-cert.sh" "$BASE_DIR" "$BASE_DIR/instance-b" "instance-b-server" "localhost" "127.0.0.1"

# Generate client cert for instance-b
echo ""
echo "=== Generating Instance B client certificate ==="
"$SCRIPT_DIR/generate-client-cert.sh" "$BASE_DIR" "$BASE_DIR/instance-b" "instance-b"

# Create test files
echo ""
echo "=== Creating test files ==="
echo "Test file from Instance A - $(date)" > "$BASE_DIR/instance-a/outbox/test-a.txt"
echo "Test file from Instance B - $(date)" > "$BASE_DIR/instance-b/outbox/test-b.txt"
dd if=/dev/urandom of="$BASE_DIR/instance-a/outbox/data-a.bin" bs=1024 count=100 2>/dev/null
dd if=/dev/urandom of="$BASE_DIR/instance-b/outbox/data-b.bin" bs=1024 count=100 2>/dev/null

# Generate config files
echo ""
echo "=== Generating configuration files ==="

cat > "$BASE_DIR/instance-a/config.toml" << 'EOF'
# DEFT Instance A Configuration

[server]
enabled = true
listen = "0.0.0.0:7751"
cert = "/tmp/deft-integration/instance-a/server.crt"
key = "/tmp/deft-integration/instance-a/server.key"
ca = "/tmp/deft-integration/instance-a/ca.crt"

[client]
enabled = true
cert = "/tmp/deft-integration/instance-a/client.crt"
key = "/tmp/deft-integration/instance-a/client.key"
ca = "/tmp/deft-integration/instance-a/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "/tmp/deft-integration/instance-a/tmp"

[limits]
max_connections_per_ip = 100
max_requests_per_partner = 10000
metrics_enabled = true
metrics_listen = "127.0.0.1:9091"
api_enabled = true
api_listen = "127.0.0.1:7752"

[logging]
format = "text"
level = "debug"

# Partner: instance-b can connect to us using their client cert
[[partners]]
id = "instance-b"
allowed_certs = ["/tmp/deft-integration/instance-b/client.crt"]
endpoints = ["localhost:7761"]

[[partners.virtual_files]]
name = "files-from-a"
path = "/tmp/deft-integration/instance-a/outbox/"
direction = "send"

[[partners.virtual_files]]
name = "files-to-a"
path = "/tmp/deft-integration/instance-a/received/"
direction = "receive"
EOF

cat > "$BASE_DIR/instance-b/config.toml" << 'EOF'
# DEFT Instance B Configuration

[server]
enabled = true
listen = "0.0.0.0:7761"
cert = "/tmp/deft-integration/instance-b/server.crt"
key = "/tmp/deft-integration/instance-b/server.key"
ca = "/tmp/deft-integration/instance-b/ca.crt"

[client]
enabled = true
cert = "/tmp/deft-integration/instance-b/client.crt"
key = "/tmp/deft-integration/instance-b/client.key"
ca = "/tmp/deft-integration/instance-b/ca.crt"

[storage]
chunk_size = 262144
temp_dir = "/tmp/deft-integration/instance-b/tmp"

[limits]
max_connections_per_ip = 100
max_requests_per_partner = 10000
metrics_enabled = true
metrics_listen = "127.0.0.1:9092"
api_enabled = true
api_listen = "127.0.0.1:7762"

[logging]
format = "text"
level = "debug"

# Partner: instance-a can connect to us using their client cert
[[partners]]
id = "instance-a"
allowed_certs = ["/tmp/deft-integration/instance-a/client.crt"]
endpoints = ["localhost:7751"]

[[partners.virtual_files]]
name = "files-from-b"
path = "/tmp/deft-integration/instance-b/outbox/"
direction = "send"

[[partners.virtual_files]]
name = "files-to-b"
path = "/tmp/deft-integration/instance-b/received/"
direction = "receive"
EOF

echo ""
echo "=== Setup complete ==="
echo ""
echo "Directory structure:"
find "$BASE_DIR" -type f -name "*.crt" -o -name "*.key" -o -name "*.toml" | sort
echo ""
echo "To start the instances:"
echo "  Instance A: ./target/release/deftd --config $BASE_DIR/instance-a/config.toml"
echo "  Instance B: ./target/release/deftd --config $BASE_DIR/instance-b/config.toml"
echo ""
echo "Consoles:"
echo "  Instance A: http://127.0.0.1:7752"
echo "  Instance B: http://127.0.0.1:7762"
