#!/usr/bin/env bash
# Two-origin development instance (foreground; Ctrl-C stops it).
#
#   http://localhost:$DEV_PORT   -> the MineAI platform surface
#   http://127.0.0.1:$DEV_PORT   -> the MeshBridge project surface
#
# Same process, two browser origins: each has its own localStorage, exactly as
# mineai.top and meshbridge.mineai.top do in production. The UI is served from
# disk (edit and reload). State lives in $DEV_DIR (default .meshbridge/dev,
# ignored by git); the admin password is generated on first start and kept in
# $DEV_DIR/admin-password.txt (0600) -- it is never printed.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${DEV_PORT:-28081}"
DIR="${DEV_DIR:-$PWD/.meshbridge/dev}"
mkdir -p "$DIR/data" && chmod 700 "$DIR"
go build -o "$DIR/server" ./cmd/meshbridge-server

if [ ! -s "$DIR/admin-password.txt" ]; then
  ( umask 077; head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 24 > "$DIR/admin-password.txt" )
  "$DIR/server" --data-dir "$DIR/data" --migrations migrations --create-admin admin < "$DIR/admin-password.txt" >/dev/null 2>&1
fi

export MESH_ENV=dev MESH_LISTEN="127.0.0.1:$PORT" MESH_GATEWAY_LISTEN="127.0.0.1:$((PORT + 1))"
export MESH_DATA_DIR="$DIR/data" MESH_MASTER_KEY_PATH="$DIR/master.key" MESH_HEADSCALE_URL="http://127.0.0.1:1"
export MESH_BASE_URL="http://localhost:$PORT" MESH_PROJECT_URL="http://127.0.0.1:$PORT"
export MESH_SSO_ENABLED=true MESH_SSO_DEV=true MESH_SSO_ISSUER="http://localhost:$PORT"
export MESH_SSO_CLIENTS="{\"folio\":\"http://localhost:$((PORT + 10))/sso/callback\",\"inkwell\":\"http://localhost:$((PORT + 11))/sso/callback\",\"parley\":\"http://localhost:$((PORT + 12))/sso/callback\",\"codebench\":\"http://localhost:$((PORT + 13))/sso/callback\",\"echo\":\"http://localhost:$((PORT + 14))/sso/callback\",\"hearthvale\":\"http://localhost:$((PORT + 15))/sso/callback\"}"
export MESH_WEB_DIR="$PWD/web" KIT_WEB_DIR="$PWD/../kit/web/assets/kit"
[ -n "${DEV_GOOGLE_CLIENT_ID:-}" ] && export MESH_GOOGLE_CLIENT_ID="$DEV_GOOGLE_CLIENT_ID"
echo "platform http://localhost:$PORT  |  project http://127.0.0.1:$PORT  |  state $DIR"
exec "$DIR/server" --data-dir "$DIR/data" --migrations migrations
