# OPERATIONS.md / BACKUP.md / TROUBLESHOOTING.md 合并速查

## 日常

- health: `curl -sf http://127.0.0.1:8081/api/v1/health` (headscale/db/disk/bandwidth/agents/relays)
- 流量: `vnstat -d; vnstat -m` (告警 30/40/45GB 可配)
- 日志: `journalctl -u meshbridge-server -f`, JSON 字段 ts/level/component/device/project/job/event/error
- policy 发布: DB 生成 → tmp → `headscale policy check` → 备份 → atomic rename → reload → verify → 失败 rollback (10 快照)

## 升级 (Headscale)

1. backup 2. release notes 3. client compat 4. staging 5. pin 安装 6. health 7. rollback 预案. Agent 上报版本, 不静默全 fleet 升级.

## 备份/恢复

- `sudo bash scripts/backup.sh /var/backups/mb.tgz` (+ AGE_RECIPIENT 加密, 推荐)
- 恢复先 staging: `sudo bash scripts/restore.sh <file>` (stop→restore→config check→start→health)
- 备份内容: headscale sqlite + config + policy, meshbridge sqlite + config; secrets 默认不上传公网

## 排障

- agent offline: 检查 controller HTTPS, token 0600, 时间同步, tailscale login-server
- 无 direct: `tailscale status --json`, `tailscale ping --c 5 peer`, `tailscale netcheck --format=json`; 查 UDP/防火墙/CGNAT
- DERP 大文件被拒: EXPECTED (>100MiB → WAIT/S3/PeerRelay), 查 probe + scheduler 日志
- relay 不生效: Tailscale 版本 >=1.86? `--relay-server-port`? grant `cap/relay`? UDP 可达? Headscale 兼容性 (RELAY.md)
- 磁盘满: 查 `.meshbridge.part` + bitmap, 清理 state dir, 检查 quota
- policy reload 失败: 自动 rollback 到上一快照, `headscale policy check` 看错
