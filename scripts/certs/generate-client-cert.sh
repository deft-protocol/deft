#!/bin/bash
# Generate a client certificate signed by the CA
# Usage: ./generate-client-cert.sh <ca_dir> <output_dir> <client_name>

set -e

CA_DIR="${1:-.}"
OUTPUT_DIR="${2:-.}"
CLIENT_NAME="${3:-client}"

mkdir -p "$OUTPUT_DIR"

# Generate client private key
openssl genrsa -out "$OUTPUT_DIR/client.key" 2048

# Generate CSR
openssl req -new \
    -key "$OUTPUT_DIR/client.key" \
    -out "$OUTPUT_DIR/client.csr" \
    -subj "/CN=$CLIENT_NAME/O=DEFT/OU=Client"

# Sign with CA (with clientAuth extension)
openssl x509 -req \
    -in "$OUTPUT_DIR/client.csr" \
    -CA "$CA_DIR/ca.crt" \
    -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial \
    -out "$OUTPUT_DIR/client.crt" \
    -days 365 \
    -sha256 \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth")

rm -f "$OUTPUT_DIR/client.csr"

echo "Client certificate generated in $OUTPUT_DIR:"
echo "  - client.key (private key)"
echo "  - client.crt (certificate for CN=$CLIENT_NAME)"
