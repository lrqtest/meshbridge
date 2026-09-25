#!/usr/bin/env bash
# install-control.sh — Debian 12 / Ubuntu 24.04 LTS, idempotent-ish.
# Usage: sudo bash install-control.sh --headscale-version 0.29.4 --hs-domain hs.example.com --mesh-domain mesh.example.com
set -euo pipefail
HS_VER="0.29.4"
HS_DOMAIN=""; MESH_DOMAIN=""
while [[ $# -gt 0 ]]; do case "$1" in
  --headscale-version) HS_VER="$2"; shift 2;;
  --hs-domain) HS_DOMAIN="$2"; shift 2;;
  --mesh-domain) MESH_DOMAIN="$2"; shift 2;;
  *) echo "unknown $1"; exit 2;;
esac; done
[[ -z "$HS_DOMAIN" || -z "$MESH_DOMAIN" ]] && { echo "domains required"; exit 2; }

apt-get update
apt-get install -y curl ca-certificates gnupg ufw vnstat sqlite3
timedatectl set-ntp true || true
hostnamectl set-hostname control || true

# SSH hardening via drop-in (first-match wins in sshd: appending to the end of
# sshd_config loses to earlier directives; sshd_config.d is Included at the top).
# Validate with sshd -t and only reload if the config parses — never break the
# current session.
SSHD_PORT="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
[[ -z "$SSHD_PORT" ]] && SSHD_PORT=22
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-meshbridge-hardening.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 4
EOF
chmod 644 /etc/ssh/sshd_config.d/00-meshbridge-hardening.conf
if sshd -t 2>/dev/null; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  echo "sshd hardened (port ${SSHD_PORT} detected, keep-alive: current session)"
else
  rm -f /etc/ssh/sshd_config.d/00-meshbridge-hardening.conf
  echo "WARN: sshd drop-in failed validation; removed, nothing reloaded"
fi

# Firewall: detected SSH port + 80/443 only. Never reset before allowing SSH.
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSHD_PORT}"/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Caddy (official repo).
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy

# Headscale official DEB (pinned).
ARCH=$(dpkg --print-architecture)
curl -L -o /tmp/headscale.deb "https://github.com/juanfont/headscale/releases/download/v${HS_VER}/headscale_${HS_VER}_linux_${ARCH}.deb"
dpkg -i /tmp/headscale.deb || apt-get install -f -y
id meshbridge >/dev/null 2>&1 || useradd --system --home-dir /var/lib/meshbridge --create-home --shell /usr/sbin/nologin meshbridge
mkdir -p /etc/meshbridge /var/lib/meshbridge /etc/headscale
chmod 700 /etc/meshbridge /var/lib/meshbridge

echo "Next: copy deploy/caddy/Caddyfile.example (domains), deploy/headscale/config.yaml.example, then:"
echo "  headscale config check && systemctl enable --now headscale caddy"
echo "  install meshbridge-server binary + deploy/systemd/meshbridge-server.service"
