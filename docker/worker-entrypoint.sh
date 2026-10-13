#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/run/sshd /root/.ssh
chmod 700 /root/.ssh

# Install authorized_keys so coordinator can SSH into this container as root
cp /opt/dev_authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Configure sshd for root key-based login (dev setup)
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Generate SSH host keys (server identity) if missing
ssh-keygen -A

echo "[worker] starting sshd..."
exec /usr/sbin/sshd -D -e
