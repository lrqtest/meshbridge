# ARCHITECTURE.md

## 目标

N 用户 / N 项目 / M 设备, CN↔US 等 NAT/CGNAT 后终端的私网互联 + 大文件断点续传, Control VPS (2C/低RAM/50GB月流量) 绝不承担正常大文件中继.

## 分层

```
Internet
  │
  Caddy (:443, auto HTTPS)
  ├── hs.example.com → 127.0.0.1:8080 Headscale (SQLite, DERP embedded DISABLED)
  └── mesh.example.com → 127.0.0.1:8081 MeshBridge Server (SQLite WAL)
        ├── REST /api/v1 + Web UI (轻量, 无框架)
        ├── Auth (Argon2id) / Session (Secure/HttpOnly/SameSite+CSRF) / API token (sha256存hash)
        ├── Projects/memberships/devices/enrollments/agents/sessions
        ├── Headscale API client (timeout/retry/ctx) + policy generator (Grants)
        ├── Scheduler (probe→DIRECT/PEER_RELAY/S3/WAIT; DERP仅<100MiB)
        ├── Relay registry + quota (monthly_quota, 80% warn / 95% critical)
        ├── Storage profiles (S3-compatible, secret用master.key加密, 不下发AK给agent)
        └── Audit log (append-only) + /health (headscale/db/disk/bandwidth/agents/relays)
```

Data Plane (不经 Server):

1. **Direct P2P** (WireGuard, 任意大小, parallel 4 chunks 默认, 1-16 自适应, token-bucket 限速)
2. **Peer Relay** (tailscale >=1.86, `tailscale set --relay-server-port=40000/udp`, grant `tailscale.com/cap/relay`, 仅 quota OK 的 relay, 独立大流量 VPS)
3. **S3 fallback** (rclone multipart, Controller 只调度, 数据 CN→S3→US)
4. **DERP** (最终 connectivity fallback, 默认仅 <=100MiB, 大文件 WAITING_FOR_ROUTE, 不偷传)

## 关键流程

### Enrollment (30min 一次性 token, 256bit, DB只存hash)

UI 创建 → token → agent `enroll` (HTTPS POST) → server 创建/取 Headscale pre-auth key → 返回 {headscaleURL, hostname, tags} → agent `tailscale up` → 上报 node identity → server 建 device↔node 映射. Linux 尽量自动化; Win/macOS 给 GUI 步骤.

### Heartbeat (30s + jitter)

agent→server: deviceID/hostname/OS/arch/agent+tailscale版本/tailscale IP/IPv6/online/transfers/disk/probe摘要. Server 更新 last_seen, 下发 pending jobs/policy version.

### Probe (JSON 优先)

`tailscale status --json` (稳定) + LocalAPI; `tailscale ping --c 5 --timeout 5s --json` 若可用; `tailscale netcheck --format=json`. 解析隔离在 internal/probe, 输出 {class: DIRECT|PEER_RELAY|DERP|UNREACHABLE|UNKNOWN, rtt, loss, relayName, endpoint, ts}. 每个 observation 写 path_observations (带 timestamp).

连接类型判定 (Tailscale 路径 Direct→PeerRelay→DERP, 2026-02 文档确认):
- `tailscale status --json` peer.relay="" 且 direct endpoint 可达 → DIRECT
- relay 字段含 `peer-relay(...)` / ping 显示 peer-relay → PEER_RELAY
- relay 字段为城市名 (如 `ord`, `hkg`) → DERP
- 超时/无路由 → UNREACHABLE

### Transfer (resumable chunked, 不用 scp)

Manifest: {fileID, relPath, size, mtime, mode, chunkSize(默认64MiB, 8MiB-256MiB可配), chunkCount, perChunk BLAKE3, final BLAKE3}.
Receiver: `<name>.meshbridge.part` 预分配(先查磁盘) + bitmap (SQLite/JSON, 不用数万小文件) + WriteAt(offset) + per-chunk BLAKE3 校验 → 全齐 → final BLAKE3 → fsync → atomic rename. 已存在目标默认 error (可选 overwrite/rename/skip-if-identical).
Transport: Receiver 只 bind Tailscale IP (绝不 0.0.0.0), TLS + Controller HMAC 短效 transfer token (job/src/dst/expiry/nonce, 10min, 防replay). 并发 4 默认, 按 throughput/RTT/loss 自适应, token-bucket 限速 (10/50/100Mbps/unlimited).
目录: 流式扫描 manifest, 保留 relPath/size/mtime, 拒绝 socket/device, symlink 默认拒绝 (不 follow, 防逃逸), 小文件 batch.
Route monitor: 传输中每 15s+jitter probe; DIRECT→DERP 需连续 2-3 次 + remaining>derp_limit 才 PAUSE (保留 bitmap) → Controller 重调度 (Direct retry→PeerRelay→S3). 每次变化写 audit.

### Policy (Grants, deny-by-default)

标签: `tag:project-<slug>`, `tag:role-dev/prod`, `tag:relay`, `tag:relay-jp/hk/sg/usw`, `tag:admin-device`.
同一 project 内 dev↔prod 按 grants 放行; 跨 project 默认拒绝, 需显式 grant. Relay 最小授权 (src 精确到项目 tags, dst relay tags, app 仅 `tailscale.com/cap/relay`), 禁 `src:["*"]`.
生成: DB→hujson → tmp → `headscale policy check` → 备份旧版 → atomic rename → `reload` → verify → 失败 rollback. 保留 10 快照, 每次写 audit.

## 为什么不用 …

- PostgreSQL/Redis/Kafka/Prometheus/K8s/Docker-swarm: 2C VPS 无理由堆; SQLite WAL + journal + vnStat 足够.
- 重写 WireGuard/NAT/DERP: 集中做 项目/策略/路由识别/续传/调度/流量保护, overlay 复用 Tailscale.
- Agent 任意 shell: 不做, 用 SSH over Tailscale (OpenSSH), 避免自造 RCE 平台.

## 端口/域名矩阵

公网: 22/tcp SSH(key only), 80/tcp ACME, 443/tcp HTTPS. Headscale 8080/metrics 9090 只 127.0.0.1, 9090 绝不公网. Relay 额外: 40000/udp (Peer Relay) + 22/tcp (管理, 建议跳板/allowlist).

## 流量保护

vnStat daily/monthly; Dashboard 显示 control 月流量; 30/40/45GB 三档 warn (可配); 启动检查 embedded DERP 若 enabled 则 WARN + 大文件调度阻断; transfer endpoint 永不绑公网.
