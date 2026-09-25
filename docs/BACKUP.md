# BACKUP.md

见 OPERATIONS.md 备份章节 + `scripts/backup.sh` / `scripts/restore.sh`.

- 内容: Headscale SQLite (`.backup`, 不直接 cp-wal), MeshBridge SQLite, `/etc/headscale/config.yaml`, `policy.hujson`, Caddyfile
- 加密: `AGE_RECIPIENT=age1... backup.sh` (推荐) 或 restic; 默认不上传公网; 输出 0600
- 恢复必须先 staging, `restore.sh` 会 stop → restore → `headscale config check` → start → `/health`
- 恢复后必做: `go test` 逻辑 + smoke-test + policy 快照检查
