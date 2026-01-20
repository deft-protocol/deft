#!/bin/bash
# Generate a Certificate Authority for DEFT
# Usage: ./generate-ca.sh <output_dir> [ca_name]

set -e

OUTPUT_DIR="${1:-.}"
CA_NAME="${2:-deft-ca}"

mkdir -p "$OUTPUT_DIR"

# Generate CA private key
openssl genrsa -out "$OUTPUT_DIR/ca.key" 4096

# Generate CA certificate
openssl req -x509 -new -nodes \
    -key "$OUTPUT_DIR/ca.key" \
    -sha256 \
    -days 3650 \
    -out "$OUTPUT_DIR/ca.crt" \
    -subj "/CN=$CA_NAME/O=DEFT/OU=Certificate Authority"

echo "CA generated in $OUTPUT_DIR:"
echo "  - ca.key (private key - keep secure!)"
echo "  - ca.crt (certificate - distribute to all nodes)"
