#!/usr/bin/env bash
# backup.sh — encrypted backup (age or restic). Never uploads secrets to public storage by default.
set -euo pipefail
OUT="${1:-/var/backups/meshbridge-$(date +%F-%H%M).tar.gz}"
AGE_RECIPIENT="${AGE_RECIPIENT:-}"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT
sqlite3 /var/lib/headscale/db.sqlite ".backup '$TMP/headscale.sqlite'" || cp /var/lib/headscale/db.sqlite "$TMP/headscale.sqlite"
sqlite3 /var/lib/meshbridge/meshbridge.sqlite ".backup '$TMP/meshbridge.sqlite'" || cp /var/lib/meshbridge/meshbridge.sqlite "$TMP/meshbridge.sqlite"
cp /etc/headscale/config.yaml "$TMP/" 2>/dev/null || true
cp /etc/headscale/policy.hujson "$TMP/" 2>/dev/null || true
cp /etc/caddy/Caddyfile "$TMP/Caddyfile" 2>/dev/null || true
tar -czf "$TMP/bundle.tar.gz" -C "$TMP" .
if [[ -n "$AGE_RECIPIENT" ]]; then
  age -r "$AGE_RECIPIENT" -o "$OUT.age" "$TMP/bundle.tar.gz"
  echo "encrypted backup: $OUT.age"
else
  cp "$TMP/bundle.tar.gz" "$OUT"
  echo "backup (UNENCRYPTED, chmod 600): $OUT"
  chmod 600 "$OUT"
fi
