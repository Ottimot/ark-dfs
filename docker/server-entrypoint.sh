#!/usr/bin/env bash
set -euo pipefail

SHARED_CERT_DIR=/certs
SERVER_CERT=/etc/ssl/certs/cert.pem
SERVER_KEY=/etc/ssl/private/key.pem
CA_CERT=$SHARED_CERT_DIR/root-ca.pem
CA_KEY=/etc/ssl/private/root-ca.key.pem

mkdir -p "$SHARED_CERT_DIR" /etc/ssl/certs /etc/ssl/private

if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
  echo "[server] Generating CA and server certificate..."

  # Root CA private key (server-only)
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$CA_KEY"

  # Root CA public cert (shared with client)
  openssl req -x509 -new -sha256 \
    -key "$CA_KEY" \
    -days 3650 \
    -out "$CA_CERT" \
    -subj "/CN=Rustls Docker Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

  # Server private key
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SERVER_KEY"

  # Server CSR
  openssl req -new -sha256 \
    -key "$SERVER_KEY" \
    -out /tmp/cert.csr.pem \
    -subj "/CN=server" \
    -addext "subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1"

  cat > /tmp/cert.ext <<'EOF'
[v3_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

  # Sign server cert with CA
  openssl x509 -req -sha256 \
    -in /tmp/cert.csr.pem \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$SERVER_CERT" \
    -days 825 \
    -extfile /tmp/cert.ext \
    -extensions v3_server

  chmod 600 "$CA_KEY" "$SERVER_KEY" "$SERVER_CERT"
  openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"

  rm -f /tmp/cert.csr.pem /tmp/cert.ext /certs/root-ca.srl
else
  echo "[server] Certs already present, reusing."
fi

ip route add 172.20.0.3 via 172.20.0.5 dev eth0 src 172.20.0.4
exec nginx -g 'daemon off;'
