# MeshBridge — Private Mesh + Transfer Orchestrator

Control Plane != Data Plane. 50GB Control VPS 绝不承担正常大文件中继。

- Control VPS: Caddy + Headscale + MeshBridge Server + SQLite
- Data Plane 优先级: Direct P2P → Peer Relay → S3 Object Storage → DERP(仅小文件/最终fallback)
- Agent: Linux/Windows/macOS, 主动 HTTPS 连接 Controller, heartbeat 30s+jitter
- Transfer: 64MiB chunk, WriteAt resume, BLAKE3 per-chunk + final, atomic rename

Pinned versions (verified 2026-09-25, see STATE.md):

- Headscale **v0.29.4** (latest stable, released 2026-09-23; min Tailscale client v1.80.0)
- Tailscale client **>= v1.86** (Peer Relay 最低要求), 推荐 **v1.102.3** (2026-08-20 verified latest)
- rclone **v1.75.0** (2026-07-31)
- Go **1.27.x** toolchain (go.mod requires >=1.24)
- Debian 12 / Ubuntu 24.04 LTS, Caddy latest stable, SQLite (WAL)

快速开始见 `docs/DEPLOYMENT.md`, `docs/CLIENT-ONBOARDING.md`, `STATE.md`.

```bash
make tidy
make test
make build
```

安全模型见 `docs/SECURITY.md` + `docs/THREAT-MODEL.md`. 默认 deny-by-default Grants, 跨项目隔离.
