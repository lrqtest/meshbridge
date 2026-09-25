#!/usr/bin/env bash
# install-agent.sh — Linux agent + tailscale (>=1.86 for peer relay).
set -euo pipefail
TS_VER="${TS_VER:-1.102.3}"
CONTROLLER="${1:-https://mesh.example.com}"
curl -fsSL "https://tailscale.com/install.sh" | sh
tailscale version || true
echo "tailscale >=1.86 required for peer relay; pinned test version $TS_VER"
echo "Then: tailscale up --login-server https://hs.example.com --hostname <name> --authkey <PREAUTH>"
echo "Install meshbridge-agent binary to /usr/local/bin + systemd unit, token 0600 at /etc/meshbridge/agent.token"
echo "Controller: $CONTROLLER"
