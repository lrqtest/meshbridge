#!/usr/bin/env bash
# install-relay.sh — high-bandwidth relay VPS (NOT control VPS).
# Requirements: public IPv4, UDP 40000 reachable, big traffic plan.
set -euo pipefail
PORT="${PORT:-40000}"
TS_VER="${TS_VER:-1.102.3}"
curl -fsSL "https://tailscale.com/install.sh" | sh
echo "1) tailscale up --login-server https://hs.example.com --hostname relay-xx-01 --authkey <PREAUTH with tag:relay>"
echo "2) tailscale set --relay-server-port=${PORT}"
echo "3) ufw allow ${PORT}/udp (and keep 22/tcp restricted)"
echo "4) MeshBridge: grant tailscale.com/cap/relay from project tags to relay tag; verify tailscale status shows peer-relay"
tailscale set --relay-server-port="${PORT}" || echo "run after tailscale up"
