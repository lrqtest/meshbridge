# RESTORE.md

见 OPERATIONS.md + `scripts/restore.sh`. 原则: 先恢复可工作版本, 记录失败原因, 再修.

```bash
sudo bash scripts/restore.sh /var/backups/meshbridge-2026-09-25.tgz.age
systemctl is-active headscale meshbridge-server caddy
curl -sf http://127.0.0.1:8081/api/v1/health
headscale nodes list
```

失败回滚: 保留 restore 前的二次备份; policy 自动保留 10 快照 (`/var/lib/meshbridge/policy-snapshots`).
