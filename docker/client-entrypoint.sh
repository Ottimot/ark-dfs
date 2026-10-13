#!/usr/bin/env bash
set -euo pipefail

echo "[client] Waiting for CA certificate..."
until [ -f /certs/root-ca.pem ]; do
  sleep 1
done

mkdir -p /app/files
mkdir -p /app/measurments

ip route add 172.20.0.4 via 172.20.0.5 dev eth0 src 172.20.0.3
#/app/client server:8443 server /certs/root-ca.pem
source /app/.venv/bin/activate
python3 /app/trackers.py
deactivate
