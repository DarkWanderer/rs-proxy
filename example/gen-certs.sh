#!/usr/bin/env bash
# gen-certs.sh — generate a local PKI for Gatekeeper mTLS authentication.
#
# Creates a self-signed CA, a server certificate (used by the proxy), and a
# client certificate (presented by curl / other tools when connecting).
#
# Output: certs/ directory alongside this script.
#
# Usage:
#   bash gen-certs.sh
#
# Requirements: openssl (1.1.1 or later)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "==> Generating CA key and self-signed certificate..."
openssl req -x509 \
    -newkey rsa:4096 \
    -keyout ca.key \
    -out ca.crt \
    -days 3650 \
    -nodes \
    -subj "/CN=Gatekeeper Example CA"

echo "==> Generating server key and certificate signing request..."
openssl req \
    -newkey rsa:4096 \
    -keyout server.key \
    -out server.csr \
    -nodes \
    -subj "/CN=localhost"

echo "==> Signing server certificate with CA (SAN: localhost, 127.0.0.1)..."
openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server_leaf.crt \
    -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")

# Build chain: leaf cert followed by CA cert
cat server_leaf.crt ca.crt > server.crt
rm server_leaf.crt server.csr

echo "==> Generating client key and certificate signing request..."
openssl req \
    -newkey rsa:4096 \
    -keyout client.key \
    -out client.csr \
    -nodes \
    -subj "/CN=example-client"

echo "==> Signing client certificate with CA..."
openssl x509 -req \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days 365 \
    -extfile <(printf "extendedKeyUsage=clientAuth\n")

rm client.csr

echo ""
echo "Done. Files written to $CERTS_DIR:"
ls -1 "$CERTS_DIR"
echo ""
echo "Start the proxy from the example/ directory:"
echo "  ../target/release/gatekeeper --config gatekeeper.toml"
