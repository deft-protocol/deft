#!/bin/bash
# Generate a server certificate signed by the CA
# Usage: ./generate-server-cert.sh <ca_dir> <output_dir> <server_name> [hostnames...]

set -e

CA_DIR="${1:-.}"
OUTPUT_DIR="${2:-.}"
SERVER_NAME="${3:-server}"
shift 3 2>/dev/null || true
HOSTNAMES=("$@")

# Default hostnames if none provided
if [ ${#HOSTNAMES[@]} -eq 0 ]; then
    HOSTNAMES=("localhost" "127.0.0.1")
fi

mkdir -p "$OUTPUT_DIR"

# Create OpenSSL config for SAN
CONFIG_FILE=$(mktemp)
cat > "$CONFIG_FILE" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $SERVER_NAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
EOF

# Add DNS and IP entries
IDX=1
for host in "${HOSTNAMES[@]}"; do
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "IP.$IDX = $host" >> "$CONFIG_FILE"
    else
        echo "DNS.$IDX = $host" >> "$CONFIG_FILE"
    fi
    ((IDX++))
done

# Generate server private key
openssl genrsa -out "$OUTPUT_DIR/server.key" 2048

# Generate CSR
openssl req -new \
    -key "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.csr" \
    -config "$CONFIG_FILE"

# Sign with CA
openssl x509 -req \
    -in "$OUTPUT_DIR/server.csr" \
    -CA "$CA_DIR/ca.crt" \
    -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/server.crt" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "$CONFIG_FILE"

rm -f "$OUTPUT_DIR/server.csr" "$CONFIG_FILE"

echo "Server certificate generated in $OUTPUT_DIR:"
echo "  - server.key (private key)"
echo "  - server.crt (certificate)"
echo "  Hostnames: ${HOSTNAMES[*]}"
