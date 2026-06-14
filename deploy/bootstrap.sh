#!/usr/bin/env bash
# getarp.net PoC bootstrap. Run once on a fresh Ubuntu 22.04/24.04 VM as root.
set -euo pipefail

echo "[*] getarp bootstrap starting"

# ── 0. CRITICAL: move the real SSH daemon off port 22 (Cowrie needs it) ──
# The honeypot binds host:22. Your real admin SSH MUST move to a mgmt port
# bound to a management interface, BEFORE you start the stack, or you lock
# yourself out / collide with Cowrie.
MGMT_PORT="${MGMT_PORT:-2022}"
if grep -qE '^#?Port 22' /etc/ssh/sshd_config; then
  sed -i "s/^#\?Port .*/Port ${MGMT_PORT}/" /etc/ssh/sshd_config
  echo "[*] sshd moved to port ${MGMT_PORT} — reconnect there after reboot:"
  echo "    ssh -p ${MGMT_PORT} <user>@<vm>"
  systemctl restart ssh || systemctl restart sshd || true
fi

# ── 1. Docker + compose ──
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || apt-get install -y docker-compose-plugin

# ── 2. host firewall: allow honeypot ports + 443 + mgmt; default deny ──
# Cloud security group should mirror this. We keep nftables managed by CrowdSec
# for bans; this base policy just exposes the right surfaces.
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
ufw allow ${MGMT_PORT}/tcp comment 'admin ssh'
ufw allow 443/tcp comment 'dashboard'
for p in 22 23 80 8081 3306 21 6379; do ufw allow ${p}/tcp comment 'honeypot'; done
ufw --force enable

# ── 3. config ──
[ -f .env ] || { cp .env.example .env; echo "[!] edit .env (passwords, JWT, iface) then re-run"; exit 1; }

# ── 4. detect public iface if not set ──
if grep -q 'PUBLIC_IFACE=eth0' .env; then
  IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
  sed -i "s/^PUBLIC_IFACE=.*/PUBLIC_IFACE=${IFACE}/" .env
  echo "[*] public iface set to ${IFACE}"
fi

# ── 5. Suricata rules pull ──
mkdir -p ids/suricata/rules
touch ids/suricata/rules/suricata.rules
echo "[*] after first boot, fetch ET Open rules:"
echo "    docker compose exec suricata suricata-update && docker compose restart suricata"

# ── 6. build + launch ──
docker compose pull || true
docker compose up -d --build
echo "[*] stack up. dashboard -> https://getarp.net  (admin: see .env)"
echo "[*] register CrowdSec console (optional): docker compose exec crowdsec cscli console enroll <token>"
