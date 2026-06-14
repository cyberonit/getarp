#!/usr/bin/env bash
# getarp.net — interactive first-run setup
# Tested on Ubuntu 22.04 / 24.04. Run as root: sudo bash deploy/setup.sh
set -eo pipefail   # NOTE: -u deliberately omitted — empty optional vars must not abort

# ── colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash deploy/setup.sh"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
info "Working directory: $REPO_DIR"

# ── input helpers ───────────────────────────────────────────────────────────
ask() {
    # ask VARNAME "Prompt text" "default"
    local _var="$1" _prompt="$2" _default="${3:-}" _val=""
    while [[ -z "$_val" ]]; do
        if [[ -n "$_default" ]]; then
            read -r -p $'\e[0;36m?\e[0m '"$_prompt [$_default]: " _val
            _val="${_val:-$_default}"
        else
            read -r -p $'\e[0;36m?\e[0m '"$_prompt: " _val
        fi
        [[ -z "$_val" ]] && warn "Value required, try again."
    done
    # Use declare -g so the variable is set in the global scope
    declare -g "$_var"="$_val"
}

ask_secret() {
    # ask_secret VARNAME "Prompt text"  — silent input, confirmed twice
    local _var="$1" _prompt="$2" _a="" _b=""
    while true; do
        read -r -s -p $'\e[0;36m?\e[0m '"$_prompt: " _a; echo
        read -r -s -p $'\e[0;36m?\e[0m '"Confirm $_prompt: " _b; echo
        if [[ -n "$_a" && "$_a" == "$_b" ]]; then
            declare -g "$_var"="$_a"
            break
        fi
        warn "Mismatch or empty — try again."
    done
}

ask_optional() {
    # ask_optional VARNAME "Prompt text"  — blank is fine
    local _var="$1" _prompt="$2" _val=""
    read -r -p $'\e[0;36m?\e[0m '"$_prompt (leave blank to skip): " _val
    declare -g "$_var"="${_val:-}"
}

# ── banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}   getarp.net — Defence Intelligence Setup${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1  Collect all input before touching anything on the system
# ═══════════════════════════════════════════════════════════════════════════
info "--- Network ---"
IFACE_DEFAULT=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
IFACE_DEFAULT="${IFACE_DEFAULT:-eth0}"
ask PUBLIC_IFACE "Public network interface" "$IFACE_DEFAULT"
ask DOMAIN       "Domain name"              "getarp.net"

echo ""
info "--- SSH management ---"
warn "sshd will be moved off port 22 so Cowrie can bind it."
warn "Pick a port, open it in your cloud firewall NOW, then press Enter."
ask MGMT_PORT "Management SSH port" "2022"
# validate it's actually a number
[[ "$MGMT_PORT" =~ ^[0-9]+$ ]] || die "MGMT_PORT must be a number, got: $MGMT_PORT"
[[ "$MGMT_PORT" -gt 1024 && "$MGMT_PORT" -lt 65535 ]] || die "MGMT_PORT must be 1025-65534"

echo ""
info "--- PostgreSQL ---"
ask PG_DB   "Database name"     "getarp"
ask PG_USER "Database username" "getarp"
ask_secret PG_PASSWORD "Database password"

echo ""
info "--- Admin dashboard ---"
ask ADMIN_USER "Admin username" "admin"
ask_secret ADMIN_PASSWORD "Admin password"

echo ""
info "--- Threat intelligence API keys (all optional) ---"
echo "  CrowdSec CTI: https://app.crowdsec.net (free, recommended)"
ask_optional CROWDSEC_CTI_KEY "CrowdSec CTI API key"
ask_optional ABUSEIPDB_KEY    "AbuseIPDB API key"
ask_optional GREYNOISE_KEY    "GreyNoise API key"

ENRICHMENT_PROVIDER="crowdsec"
[[ -z "$CROWDSEC_CTI_KEY" && -n "$ABUSEIPDB_KEY" ]] && ENRICHMENT_PROVIDER="abuseipdb"
[[ -n "$GREYNOISE_KEY" && -z "$CROWDSEC_CTI_KEY" && -z "$ABUSEIPDB_KEY" ]] && ENRICHMENT_PROVIDER="greynoise"

echo ""
ok "All input collected."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2  Generate JWT and write .env (mode 600)
# ═══════════════════════════════════════════════════════════════════════════
JWT_SECRET=$(openssl rand -hex 32)
ok "JWT secret auto-generated."

ENV_FILE="$REPO_DIR/.env"
[[ -f "$ENV_FILE" ]] && cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%s)" \
    && warn "Existing .env backed up."

# Write using individual echo statements — avoids ALL heredoc expansion surprises
{
echo "# getarp.net generated $(date -u +"%Y-%m-%dT%H:%M:%SZ") — DO NOT COMMIT"
echo ""
echo "DOMAIN=$DOMAIN"
echo "PUBLIC_IFACE=$PUBLIC_IFACE"
echo ""
echo "PG_DB=$PG_DB"
echo "PG_USER=$PG_USER"
echo "PG_PASSWORD=$PG_PASSWORD"
echo "PG_HOST=postgres"
echo "PG_PORT=5432"
echo ""
echo "REDIS_URL=redis://redis:6379/0"
echo ""
echo "JWT_SECRET=$JWT_SECRET"
echo "JWT_EXPIRE_MINUTES=60"
echo "ADMIN_USER=$ADMIN_USER"
echo "ADMIN_PASSWORD=$ADMIN_PASSWORD"
echo ""
echo "ENRICHMENT_PROVIDER=$ENRICHMENT_PROVIDER"
echo "CROWDSEC_LAPI_URL=http://crowdsec:8080"
echo "CROWDSEC_CTI_KEY=$CROWDSEC_CTI_KEY"
echo "ABUSEIPDB_KEY=$ABUSEIPDB_KEY"
echo "GREYNOISE_KEY=$GREYNOISE_KEY"
echo ""
echo "SCAN_PORT_THRESHOLD=5"
echo "SCAN_WINDOW_SECONDS=60"
echo "BRUTEFORCE_THRESHOLD=10"
echo "BRUTEFORCE_WINDOW_SECONDS=120"
echo "STATUS_INTERVAL_SECONDS=300"
echo "ENABLED_DETECTORS=scan,attack"
echo "ENABLED_PROFILERS=default"
echo "REPORT_CRON_HOUR=6"
} > "$ENV_FILE"

chmod 600 "$ENV_FILE"
ok ".env written (mode 600)."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3  Move sshd off port 22
# ═══════════════════════════════════════════════════════════════════════════
info "Moving sshd to port $MGMT_PORT"
SSHD_CFG=/etc/ssh/sshd_config

cp "$SSHD_CFG" "${SSHD_CFG}.bak.$(date +%s)"

# Remove ALL existing Port lines (comments and active), then append a clean one.
# This is safer than sed in-place substitution which can match comment lines.
grep -v "^[[:space:]]*#\?[[:space:]]*Port[[:space:]]" "$SSHD_CFG" > /tmp/sshd_config_new || true
echo "Port $MGMT_PORT" >> /tmp/sshd_config_new
cp /tmp/sshd_config_new "$SSHD_CFG"

# Ubuntu 24.04 uses socket-based activation by default — disable the socket
# so sshd_config's Port directive is authoritative.
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    info "Disabling ssh.socket (Ubuntu 24.04 socket activation)"
    systemctl disable --now ssh.socket 2>/dev/null || true
fi

# Ensure /run/sshd exists (systemd normally creates it but not after manual stop)
mkdir -p /run/sshd

# Validate config before restarting
if ! sshd -t 2>/tmp/sshd_test_err; then
    warn "sshd config test failed:"
    cat /tmp/sshd_test_err
    warn "Restoring backup config."
    cp "${SSHD_CFG}.bak."* "$SSHD_CFG" 2>/dev/null | tail -1 || true
    die "Fix sshd_config manually then rerun."
fi

systemctl enable ssh.service 2>/dev/null || true
systemctl restart ssh.service

ok "sshd running on port $MGMT_PORT."
echo ""
warn "════════════════════════════════════════════════════════"
warn "  Reconnect via:  ssh -p $MGMT_PORT <user>@<vm-ip>"
warn "  Open a second terminal and confirm before continuing."
warn "════════════════════════════════════════════════════════"
echo ""
read -r -p $'\e[0;33m?\e[0m Press Enter once you have confirmed SSH on port '"$MGMT_PORT"' works: '

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4  Docker
# ═══════════════════════════════════════════════════════════════════════════
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    ok "Docker installed."
else
    ok "Docker already installed: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'ok')"
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5  Host firewall (UFW)
# ═══════════════════════════════════════════════════════════════════════════
info "Configuring UFW firewall"
if command -v ufw &>/dev/null; then
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming  >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    ufw allow "$MGMT_PORT/tcp"  comment 'admin ssh'
    ufw allow 443/tcp           comment 'dashboard TLS'
    ufw allow 22/tcp            comment 'honeypot SSH'
    ufw allow 23/tcp            comment 'honeypot Telnet'
    ufw allow 80/tcp            comment 'honeypot HTTP'
    ufw allow 21/tcp            comment 'honeypot FTP'
    ufw allow 3306/tcp          comment 'honeypot MySQL'
    ufw allow 6379/tcp          comment 'honeypot Redis'
    ufw allow 8081/tcp          comment 'honeypot HTTP-alt'

    ufw --force enable >/dev/null 2>&1
    ok "UFW configured."
else
    warn "ufw not found — skip firewall config."
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 6  CrowdSec firewall bouncer (host service — no Docker image exists)
# ═══════════════════════════════════════════════════════════════════════════
info "Installing CrowdSec firewall bouncer (host native)"

if ! command -v crowdsec-firewall-bouncer &>/dev/null 2>&1; then
    # Add CrowdSec apt repo if not already present
    if ! grep -rq "packagecloud.io/crowdsec" /etc/apt/sources.list* 2>/dev/null; then
        curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    fi
    apt-get install -y crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
        && ok "crowdsec-firewall-bouncer-nftables installed." \
        || warn "Bouncer package install failed — run 'make bouncer' after stack is up."
else
    ok "CrowdSec firewall bouncer already installed."
fi

# Write the bouncer registration helper (run after stack starts)
cat > /usr/local/bin/getarp-register-bouncer << HOOK
#!/usr/bin/env bash
set -euo pipefail
COMPOSE_FILE="${REPO_DIR}/docker-compose.yml"
echo "Waiting for CrowdSec LAPI to be ready..."
for i in \$(seq 1 20); do
    docker compose -f "\$COMPOSE_FILE" exec -T crowdsec cscli version &>/dev/null && break
    echo "  attempt \$i/20..."; sleep 3
done
# Remove stale key if present, then generate a fresh one
docker compose -f "\$COMPOSE_FILE" exec -T crowdsec \
    cscli bouncers delete firewall-bouncer-host &>/dev/null || true
LAPI_KEY=\$(docker compose -f "\$COMPOSE_FILE" exec -T crowdsec \
    cscli bouncers add firewall-bouncer-host -o raw)
if [[ -z "\$LAPI_KEY" ]]; then
    echo "ERROR: could not get bouncer API key from CrowdSec."
    exit 1
fi
BCFG=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
sed -i "s|^api_key:.*|api_key: \${LAPI_KEY}|"  "\$BCFG"
sed -i "s|^api_url:.*|api_url: http://127.0.0.1:8080/|" "\$BCFG"
systemctl restart crowdsec-firewall-bouncer
echo "Bouncer registered and restarted."
HOOK
chmod +x /usr/local/bin/getarp-register-bouncer
ok "Bouncer registration helper written."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 7  Stub rules file + start the stack
# ═══════════════════════════════════════════════════════════════════════════
mkdir -p "$REPO_DIR/ids/suricata/rules"
touch "$REPO_DIR/ids/suricata/rules/suricata.rules"

info "Starting the stack (pulling images + building — may take a few minutes)..."
cd "$REPO_DIR"
docker compose pull --ignore-buildable 2>&1 | grep -E "Pulled|Error" || true
docker compose up -d --build
ok "Stack started."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 8  Post-start wiring
# ═══════════════════════════════════════════════════════════════════════════
info "Waiting 20s for services to initialise..."
sleep 20

info "Registering firewall bouncer with CrowdSec LAPI..."
bash /usr/local/bin/getarp-register-bouncer \
    && ok "Bouncer registered." \
    || warn "Bouncer registration failed — run 'make bouncer' once stack is healthy."

info "Pulling Suricata ET Open rules..."
docker compose exec -T suricata suricata-update >/dev/null 2>&1 \
    && docker compose restart suricata \
    && ok "Suricata rules updated." \
    || warn "suricata-update failed — run 'make rules' manually."

# ═══════════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   Setup complete.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Dashboard  : https://$DOMAIN"
echo "  Admin login: $ADMIN_USER  (password as entered)"
echo "  SSH (admin): ssh -p $MGMT_PORT <user>@<vm-ip>"
echo ""
echo "  Useful commands:"
echo "    make ps           — service health"
echo "    make logs         — tail all logs"
echo "    make rules        — refresh Suricata ET rules"
echo "    make bouncer      — re-register firewall bouncer"
echo "    make enroll T=... — join CrowdSec community console"
echo ""
warn "Ensure $DOMAIN DNS A record points to this VM's public IP."
warn "Caddy issues TLS via TLS-ALPN-01 on port 443."
echo ""
