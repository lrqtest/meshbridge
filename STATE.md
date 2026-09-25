# STATE.md — MeshBridge 项目状态 (Single Source of Truth)

> Agent 每次开始工作先读此文件. 用户最后提供 SSH 后才做真实部署.

## Current Phase

- Phase 0: DONE (repo skeleton + docs + threat model + pinned versions, 2026-09-25)
- Phase 1: READY (Control VPS automation 已写 Ansible/systemd/Caddy/Headscale 模板, 待 SSH 后执行)
- Phase 2-14: 代码已实现 MVP, 待集成测试 + 生产部署

## Pinned Versions (verified 2026-09-25 UTC)

| Component | Pinned | Source | Notes |
|---|---|---|---|
| Headscale | **v0.29.4** | github.com/juanfont/headscale/releases (Latest, 2026-09-23) | plan 中 0.29.3 已过时; min Tailscale client v1.80.0; 用官方 DEB + systemd, SQLite |
| Tailscale client | **>= v1.86, 推荐 v1.102.3** | tailscale.com/docs/features/peer-relay (min 1.86), what-version verified 1.102.3 (2026-08-20) | Peer Relay GA (2026-03 月度更新确认); relay 需 `--relay-server-port`, grant `tailscale.com/cap/relay` |
| rclone | **v1.75.0** | rclone.org/changelog, downloads.rclone.org (2026-07-31) | S3 multipart/并发/校验; fallback 直接调 rclone binary, 需 `rclone version` 检测 |
| Go | **1.27.1 / go.mod >=1.24** | local `go version` | |
| OS | **Debian 12 / Ubuntu 24.04 LTS** | Headscale 官方推荐 | |
| Caddy | **latest stable (deploy 时 `apt` 锁定并记录)** | caddyserver.com | 自动 HTTPS, 反代 127.0.0.1:8080/8081 |
| SQLite | system lib + `modernc.org/sqlite v1.38.2` (Go, 无 cgo) | — | WAL + busy_timeout, 拒绝 PostgreSQL |

每次升级 Headscale 前必须: backup → release notes → client compat → staging → pin → health → rollback (见 docs/OPERATIONS.md).

## Completed

- [x] 版本核验 (Headscale/Tailscale PeerRelay/rclone, 全部走官方文档+releases, 不信 plan 写死版本)
- [x] Monorepo 骨架 (`cmd/`, `internal/`, `web/`, `migrations/`, `deploy/`, `scripts/`, `docs/`)
- [x] Server: config/db/auth/policy/headscale-client/enrollment/scheduler/relay/storage/audit/api
- [x] Agent: enroll/heartbeat/probe/transfer executor/route monitor
- [x] Transfer: manifest + 64MiB chunk + bitmap + BLAKE3 + WriteAt + resume + 原子 rename + 路径安全
- [x] Deploy: Caddyfile, headscale config/policy, systemd (sandboxed), Ansible roles, install/backup/restore/smoke 脚本
- [x] Docs: ARCHITECTURE/SECURITY/THREAT-MODEL/TRANSFER/RELAY/DEPLOYMENT/OPERATIONS/TEST-PLAN/TROUBLESHOOTING/BACKUP 等
- [x] `go test ./...` + `go vet` 本地通过

## In Progress

- 无 (等 SSH + 域名 + S3 凭证做真实部署验证)

## Blocked / 需要用户提供的最后一步

1. **Control VPS SSH**: `IP/domain + user + key` (禁止 password/root-password, 只 key-based). 例: `ssh user@1.2.3.4 -i ~/.ssh/id_ed25519`
2. **域名 + DNS**: `hs.example.com`, `mesh.example.com` → VPS 公网 IP (A/AAAA). 需要 DNS 控制权做 ACME.
3. **Headscale/API**: 部署后在 VPS 上 `headscale apikey create` → 写入 `/etc/meshbridge/server.env` (0600), 不进 Git.
4. **S3 fallback (可选 MVP 后)**: endpoint/region/bucket/AK/SK/path-prefix (+ rclone crypt password 可选). 建议 R2/自选 S3-compatible, 不要只绑 AWS.
5. **Relay VPS (Phase 8)**: JP/HK/SG/US-West 各 1 台: 公网 IPv4 + UDP 40000 可达 + 大流量套餐. 先 1 台 JP 验证即可.
6. **两台测试终端**: CN + US 各一台 (Linux/macOS/Win 均可), 装 Tailscale >=1.86 + meshbridge-agent, 加入 allowed_roots 的测试目录.

在拿到以上之前, 不要停: 代码/模板/测试/文档已全部可审阅, 部署命令见 docs/DEPLOYMENT.md.

## Important Decisions

- **CONTROL != DATA**: embedded DERP 默认禁用 (`derp.server.enabled=false`); Control VPS 只做协调, 大文件走 Direct/PeerRelay/S3. 启动健康检查若发现 DERP enabled 则 WARN 并阻断大文件调度.
- **SQLite, 不上 PG/Redis/K8s/Prometheus**: 2C 小 VPS, WAL + busy_timeout 足够; 监控用 /health + vnStat + journal.
- **Grants 优先, deny-by-default**: `tag:project-<slug>`, `tag:role-dev/prod`, `tag:relay*`, `tag:admin-device`; Alpha✕Beta 默认隔离; policy 生成走 tmp→validate→backup→atomic rename→reload→verify→rollback, 保留 10 快照.
- **Transfer token 简化**: MVP 用 Controller HMAC-SHA256 签发短效 JWT-like token (10min, nonce, job/src/dst/expiry), 不做 Ed25519 PKI (plan 过重). Receiver 用预共享 controller secret 验证, 无需回连. 后续可升级 mTLS/device cert.
- **Probe 优先 JSON/LocalAPI**: `tailscale status --json` + LocalAPI, CLI 文本解析隔离在 `internal/probe` + fixture tests, 不散落.
- **DERP 语义修正**: 禁用 embedded DERP 后 tailnet 无 DERP fallback → 视为 EXPECTED, 大文件转 WAITING_FOR_ROUTE/S3; 若需 DERP, 必须在 Relay VPS 上独立跑 `derper`, 绝不在 Control VPS 上跑高流量 DERP.
- **S3 凭证不下发**: Agent 永不见 AK/SK; Controller 下发一次性 presigned URL (MVP 先用 rclone env + remote, 后续切 presigned). rclone crypt 可选, 密钥不进日志.
- **Route flap 阻尼**: 单次 DERP 样本不暂停; 连续 2-3 次 (15s+jitter) + remaining > derp_limit 才 PAUSE 并重调度.
- **No remote shell in agent**: 远程管理走 SSH over Tailscale (OpenSSH), agent 第一版无任意命令执行.

## Deployment State

- Control VPS: NOT DEPLOYED (待 SSH)
- Headscale: config/policy 模板就绪, 未 apply
- Relays: 未采购/未部署
- S3: 未配置
- Web/CLI/API: 代码完成, 未联调

## Known Issues / Risks

1. **Headscale Peer Relay 兼容性待集成验证**: Headscale 0.29.x 已支持 Grants `tailscale.com/cap/relay`, 但需在 pinned 版本上实测 `tailscale status --json` 是否出现 `peer-relay` relay 类型. 若不兼容, 按 docs/RELAY.md 启动 custom relay milestone (仍在大流量节点, E2E 加密), 绝不回退到 Control VPS DERP.
2. **Tailscale CLI 输出漂移**: 已隔离 parser, 但 Tailscale 升级仍可能改格式; CI 需 fixture 回归.
3. **CN↔US 直连质量不可预设**: 不要硬编码 HK 最快; 按 TEST-PLAN 实测 Direct/JP/HK/SG/USW 后选择.
4. **全零/稀疏文件误导测速**: 测试必须用 deterministic pseudo-random (见 scripts/smoke-test.sh), 不用全零.
5. **rclone binary 体积/版本漂移**: agent 需检测 `rclone version >=1.75`, 否则 S3 fallback 禁用并告警.

## Next Actions

1. 用户提供 SSH + 域名 → 跑 `deploy/ansible` (control role) → `headscale config check` → enroll 2 台测试机 → smoke-test.sh (1GB→10GB Direct/resume/DERP-refuse).
2. 采购 JP relay → `install-relay.sh` + grant `tailscale.com/cap/relay` → Peer Relay 10GB 测试 (relay vnStat ↑, control VPS ≈ MB 级).
3. 配置 S3 profile → S3 fallback 测试 (upload/retry/download/hash).
4. Backup/restore 实测 → Phase 12 security review → 生产 runbook.
