#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/run/sshd /root/.ssh
chmod 700 /root/.ssh

# Coordinator uses the baked private key to SSH out
cp /opt/dev_ssh_id_rsa /root/.ssh/id_rsa
chmod 600 /root/.ssh/id_rsa

# Also allow inbound SSH (useful later if coordinator hosts MPI ranks too)
cp /opt/dev_authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# SSH client config to avoid prompts in dev
cat > /root/.ssh/config <<'EOF'
Host *
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF
chmod 600 /root/.ssh/config

# Start sshd too (optional now, useful later)
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
ssh-keygen -A
/usr/sbin/sshd -D -e &
SSHD_PID=$!

wait_for_ssh() {
  local host="$1"
  echo "[coordinator] waiting for $host SSH..."
  until ssh root@"$host" "echo ok" >/dev/null 2>&1; do
    sleep 1
  done
  echo "[coordinator] $host ready"
}

for h in worker1 worker2 worker3; do
  wait_for_ssh "$h"
done

#exec mpirun -np 4 --allow-run-as-root --hostfile app/hostfile app/rss_snark work --log-instance-size 12 --log-num-workers-per-party 0 --log-num-public-workers 1 --key-file app/inst_folder/inst_12_0_1/test --worker-id 0 --local 1
#
mkdir -p app/files
mkdir -p files

python app/capture.py eth0 &
mpirun --allow-run-as-root \
  --bind-to none \
  --hostfile app/hostfile \
  -np 4 \
  --tag-output \
  bash -lc 'echo START rank=$OMPI_COMM_WORLD_RANK host=$(hostname); exec app/rss_snark work --log-instance-size 13 --log-num-workers-per-party 0 --log-num-public-workers 1 --key-file app/inst_folder/inst_13_0_1/test --worker-id $OMPI_COMM_WORLD_RANK --local 1'


#exec mpirun --allow-run-as-root \
#  --hostfile app/hostfile \
#  -np 4 \
#  --tag-output \
#  bash -lc 'echo START rank=$OMPI_COMM_WORLD_RANK host=$(hostname); exec app/rss_snark work --log-instance-size 12 --log-num-workers-per-party 0 --log-num-public-workers 1 --key-file app/inst_folder 
#inst_12_0_1/test --worker-id $OMPI_COMM_WORLD_RANK --local 1'
echo "[coordinator] done."

