#!/usr/bin/env bash
# smoke-test.sh — production smoke (run AFTER deploy). Uses deterministic pseudo-random (NOT zeros).
set -euo pipefail
BASE="${BASE:-https://mesh.example.com}"
TOKEN="${MESH_TOKEN:-}"
[[ -z "$TOKEN" ]] && { echo "MESH_TOKEN required"; exit 2; }
echo "== health =="
curl -sf "$BASE/api/v1/health" | head -c 500; echo
echo "== projects/devices/transfers =="
curl -sf -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/projects?limit=5" | head -c 500; echo
curl -sf -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/devices?limit=5" | head -c 500; echo
echo "== gen 1GB deterministic file =="
python3 -c "import os;x=0x12345678
with open('/tmp/mb-smoke.bin','wb') as f:
 for _ in range(1024):
  blk=bytearray(1024*1024)
  for i in range(len(blk)):
   x=(x*6364136223846793005+1)&((1<<64)-1); blk[i]=(x>>33)&0xFF
  f.write(blk)"
ls -lh /tmp/mb-smoke.bin
echo "SMOKE OK (full 10GB + resume + DERP-refuse tests: see docs/TEST-PLAN.md)"
