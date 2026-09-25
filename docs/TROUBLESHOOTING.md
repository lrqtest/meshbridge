# TROUBLESHOOTING.md

- 502 from Caddy: `systemctl status headscale/meshbridge-server`, `ss -lnt | grep 808`, Caddyfile 域名拼写
- ACME 失败: DNS 未生效 / 80 被墙 / 时钟偏; `caddy validate`, `journalctl -u caddy`
- `headscale config check` 失败: 对照 `deploy/headscale/config.yaml.example` (v0.29.4 字段), 不套旧版 config
- agent heartbeat 401: token 错/过期, `agent.token` 0600, 时间同步
- `tailscale status` 无 peer: policy grants 缺失 (Alpha✕Beta 默认隔离是 EXPECTED), `headscale policy check`
- 大文件卡 WAITING_FOR_ROUTE: 看 probe class + relay quota + S3 enabled; DERP 大文件被拒是 EXPECTED
- 传输中变慢/暂停: `path_observations` 查 DIRECT→DERP flap, 按 TRANSFER.md 阻尼重调度
- 磁盘满: `.meshbridge.part` 预分配前已检查? `df -h`, 清 state dir, 降 chunk 并发
- Control 流量异常: `vnstat -d`, 查 embedded DERP 是否被误开 (`derp.server.enabled` 必须 false), 查 transfer endpoint 是否误绑 0.0.0.0
