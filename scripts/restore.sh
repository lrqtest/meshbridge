#!/usr/bin/env bash
# restore.sh — USE ON STAGING FIRST. Stops services, restores, validates, restarts.
set -euo pipefail
IN="$1"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
if [[ "$IN" == *.age ]]; then age -d -o "$TMP/bundle.tar.gz" "$IN"; else cp "$IN" "$TMP/bundle.tar.gz"; fi
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP"
systemctl stop meshbridge-server headscale || true
cp "$TMP/headscale.sqlite" /var/lib/headscale/db.sqlite
cp "$TMP/meshbridge.sqlite" /var/lib/meshbridge/meshbridge.sqlite
cp "$TMP/config.yaml" /etc/headscale/config.yaml
cp "$TMP/policy.hujson" /etc/headscale/policy.hujson
headscale config check
systemctl start headscale meshbridge-server
systemctl is-active headscale meshbridge-server
curl -sf http://127.0.0.1:8081/api/v1/health
