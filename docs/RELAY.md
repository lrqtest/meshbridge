# RELAY.md

Relay 独立于 Control VPS, 无 DB/Web, 只 `tailscaled + Peer Relay`.

## 要求 (部署前按当时官方文档核对, 不假设 CLI 不变)

- Tailscale >= 1.86 (relay 本机 + 使用方都要), 推荐 1.102.3
- 公网 IPv4 + 可达 UDP 端口 (本项目统一 40000/udp), 高流量套餐, 低延迟
- 非 iOS/AppleTV/Android (官方限制)
- `tailscale set --relay-server-port=40000`
- Grant: `{"src":["tag:project-<slug>"],"dst":["tag:relay-jp"],"app":{"tailscale.com/cap/relay":[]}}`, 禁 `src:["*"]`
- 标签: `tag:relay`, 细分 `tag:relay-jp/hk/sg/usw`; 防火墙只开 40000/udp + 受限 22/tcp

见 scripts/install-relay.sh.

## Headscale 兼容性 (必须先验证)

Headscale 0.29.x 已支持 Grants app 字段, 但 Peer Relay 端点发现是否完整透传需集成测试:

1. pin Headscale 0.29.4 + Tailscale 1.102.3
2. 起 2 客户端 + 1 relay, 制造 NAT 使 direct 失败
3. `tailscale status --json` 应出现 `peer-relay` relay, ping 显示 `via peer-relay(name)`
4. 传 10GB: relay vnStat ↑ ~10GB, control VPS ≈ MB 级

若不兼容: 不回退 Control VPS DERP; 启动 custom relay milestone (仍大流量节点, 应用层 E2E 加密), 记录 issue.

## Quota/健康

- `monthly_quota_bytes` (如 1TB), warn 80% / critical 95%; critical 禁新大文件 (现有按配置继续/暂停)
- 上报 region/connectivity/uptime/sessions/in/out/monthly/estimate/health; 默认小 probe, 用户可手动 speedtest (禁持续高频测速)
- 指标: `tailscaled_peer_relay_forwarded_{packets,bytes}_total` (Tailscale 1.94+ client metrics)
