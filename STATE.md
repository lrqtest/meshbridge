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
- [x] **2026-09-25 全面安全审计 + 修复 (commit 850bf0c)**: 见下方 Audit 2026-09-25

## Audit 2026-09-25 (全源码人工审计, 已修复并测试)

发现并修复 (commit 850bf0c):
1. **[严重-功能] Agent↔Server 从未联调**: agent 心跳打 `/api/v1/agents/heartbeat` 但 server 没注册该路由 (恒 404)。已加心跳路由 + device_tokens 表 + `POST /api/v1/devices` (管理员注册设备、一次性发 agent token), heartbeat upsert agents 表 + 120s 离线清扫。
2. **[严重-安全] Web UI 存储型 XSS**: hostname/错误串经 innerHTML 渲染, 恶意设备名可偷管理页里的 API token。已改 textContent。
3. **[高-安全] 登录无防爆破 + 用户名枚举**: 加 per-IP(信任 loopback XFF)+per-username 限速 (5次/15min→429); 未知用户走 DummyVerify 等时 Argon2 消耗。
4. **[高-安全] API token 永不过期/不可吊销**: 登录 token 24h 过期 (expires_at), 加 `/api/v1/auth/logout`。
5. **[高-安全] install-control.sh SSH 硬化无效**: OpenSSH 首值优先, 追加到主配置末尾会输给已有指令。改 `sshd_config.d/00-*.conf` drop-in + `sshd -t` 校验后才 reload; ufw 先探测实际 SSH 端口再 reset (防锁死)。
6. **[中-安全] Transfer token nonce 无重放检测**: VerifyTransfer 只查非空。新增 auth.ReplayGuard (GC + TTL), 接收端调用 CheckAndConsume。
7. **[中-安全] 传输创建无路径校验**: API 层拒绝绝对路径/`..`/盘符/src==dst; 权威校验仍在 agent 侧 SafeJoin。
8. **[中-可靠] Finalize 无 fsync**: rename 前后 fsync 文件+目录, 掉电不再产出已命名但空洞的"完成"文件。
9. **[中] Argon2 参数不解析**: 改为从 PHC 串解析 m/t/p + 合理性上限 (防篡改行放大计算)。
10. **[低] 其他**: relays/audit GET-only 守卫; slugify 去重 (api→policy.Slugify); agent 复用 http.Client; server `--create-admin` 引导 (TTY 双次输入或 stdin, ≥12字符); /health 反映真实 headscale 可达性; Caddyfile headscale 块改官方推荐的裸 reverse_proxy (去掉 h2c transport); backup.sh 仅 age 加密时含 /etc/meshbridge secrets 并加警告。

已知未修 (记录在案, MVP 可接受):
- transfer 执行器 (chunk 收发循环) 尚未在 agent main 里接线 (Phase 2 集成范围)
- probe ClassifyStatusJSON 匹配 peer 用 hostname 子串, 精确 key 匹配待 headscale 实测后定
- Web UI 无 CSP header (Caddy 层后续可加)
- policy Render 中 role-dev/role-prod tagOwner 循环内重复赋值 (无害)

## In Progress

- **真实部署 Phase 1 (进行中)**: 服务器 36.151.144.201 (公) / 172.16.0.3 (内), 域名 mineai.top (裸域 A 记录已生效; **hs./mesh. 子域名 A 记录待用户添加**)。SSH: agent.pem 对 12 个常见用户名均被拒 (公钥已签名提交 SHA256:rKVGpzJ15A0kGjl+okSvqDDF5TroObEf/Nzobibqb7Y 但服务器 authorized_keys 不认) → 用户正在重启服务器重试。部署物料已备: /tmp/mesh-deploy/{linux-amd64,linux-arm64}(3 binary×2 arch+SHA256SUMS), configs/{Caddyfile, Caddyfile.single-domain(裸域路径复用备选), headscale-config.yaml}。

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

## Web Onboarding (2026-09-26 新增, 已上线)

**网页全流程已部署到 https://mineai.top**（单域名，内嵌 SPA 无外部依赖）:

- **Setup 向导 /#/setup**（仅当无 admin 时可进）: ①邮箱+验证码+密码创建管理员 → ②SMTP 配置+测试发信 → ③设备接入（preauth key + agent token + 三步安装命令）
- **注册 /#/register**: 邮箱验证码制（沿袭 MineAI 旧项目机制, 加固版）: crypto/rand 6位码、DB 存 sha256 哈希不存明文、同邮箱冷却(settings 默认60s)、全局每分钟5/每日100限流、单码最多5次尝试
- **登录**: 邮箱或用户名 + Argon2id; token 24h; 忘记密码走 reset 验证码（重置后吊销全部 api_tokens）
- **控制台 /#/app**: 设备（接入弹窗: 调 headscale 真实签发 preauth key + agent token + 复制安装命令）/传输/中继/审计/设置（SMTP 修改密码留空=保留、注册开关）
- 后端新增: internal/mailer（隐式TLS 465/STARTTLS 587）、internal/secret（master key + AES-256-GCM, SMTP密码加密落库）、internal/settings、schema v2（002: users.email/verification codes/settings 默认值, db.RunMigrations 幂等 ALTER）、headscale client（ListUsers/CreateUser 幂等/CreatePreAuthKey 双字段名兼容）
- 二进制 go:embed 内嵌 web/; make build 自动 sync; Caddy @mesh path: / /api/v1/* /favicon.ico /login /register /setup /forgot /app
- **生产实测通过**: UI 登录（截图验证）、设备接入弹窗（真实 hskey-auth preauth 签发+安装命令）、深链路由、审计/设备表渲染。实测发现并修复: 前端 api() 把 GET+null body 序列化导致所有 GET 抛错（控制台曾不可用）+ 深链未归一化 + headscale CreateUser 重复建号
- master key: /etc/meshbridge/master.key (640 root:meshbridge); SMTP 密码加密存 settings.smtp_password_enc, 接口永不回显
- **SMTP 未通**: 用户提供的 QQ 授权码 535 被拒（Account abnormal/password incorrect/服务未开启）, 465/587 双端口均验证为授权码本身问题。→ 用户需到 QQ邮箱 设置-账号 开启 SMTP 并生成新授权码, 然后在网页"设置"里填入（密码留空=保留旧值）, 点"保存并发测试邮件"验证。未通期间注册/忘记密码不可用, setup 向导第2步可跳过

## Deployment State (2026-09-26 更新)

- **Control VPS 36.151.144.201 (Debian 12, x86_64, 2C/4G/59G): 已部署并验证**
  - SSH: root + agent.pem (key-only; 密码登录已禁用, MaxAuthTries 4, ufw 仅 22/80/443)
  - Headscale **v0.29.4** 运行中 (127.0.0.1:8080, SQLite, embedded DERP **disabled** + 占位 DERP map)
  - Caddy **2.11.4** (Let's Encrypt 已签发), **单域名方案**: `https://mineai.top` — meshbridge API 路径优先分流到 :8081, 其余 (含 /key /ts2021 /register /machine) → headscale (hs./mesh. 子域名 A 记录待用户添加后可切换标准双子域名布局, Caddyfile 已备)
  - meshbridge-server (systemd, meshbridge 用户, sandboxed) 运行中; 管理员 `mb-admin` (密码在服务器 /root/meshbridge-admin-credentials.txt, 0600, 未进 Git/日志)
  - headscale API key 已入 /etc/meshbridge/server.env (640 root:meshbridge)
  - **端到端验证 8/8 通过**: login→token / 5次错密→429 / 设备注册+一次性 agent token / heartbeat→online / 绝对路径+`..`→400 / audit 记录 / logout→401 / 内外网 HTTPS 一致
  - headscale preauthkey (1h reusable) 在 /root/mb-preauth.key — 曾在本会话输出中完整出现, **过期前不要外传; 建议测试前 expire**
- 入网测试: 待用户提供 CN/US 测试机 (本机无 Tailscale); preauthkey 就绪
- Relays: 未采购/未部署 (Phase 8); S3: 未配置

### 部署实测发现的 Headscale 0.29.4 版本漂移 (已回写仓库)

1. `headscale config check` 已改名 **`headscale configtest`**
2. **空 DERP map 拒绝启动** ("initial DERPMap is empty") — 与"禁用 embedded DERP"直接冲突; 用占位 DERP map (不可解析域名) 满足非空要求, 保持 tailnet 无 DERP fallback (符合 scheduler 语义: 转 WAITING/S3)
3. `derp.paths` 文件是 **YAML 小写字段名** (regions/regionid/hostname), 不是 urls 用的 PascalCase JSON — 写错则静默解析为空 map
4. policy tagOwners **不认 `autogroup:admin`** (Tailscale SaaS 专有), 必须用具体用户 `user@` 格式 (如 `mb-admin@`); policy.go 已改 Input.OwnerUser
5. `preauthkeys create --user` 要**数字 user ID**, 不是用户名

## Deployment State (旧)

- Control VPS: NOT DEPLOYED (待 SSH)
- Headscale: config/policy 模板就绪, 未 apply
- Relays: 未采购/未部署
- S3: 未配置
- Web/CLI/API: 代码完成, 未联调
(以上为旧状态, 最新见上方 Deployment State 2026-09-26)

## Known Issues / Risks

1. **Headscale Peer Relay 兼容性待集成验证**: Headscale 0.29.x 已支持 Grants `tailscale.com/cap/relay`, 但需在 pinned 版本上实测 `tailscale status --json` 是否出现 `peer-relay` relay 类型. 若不兼容, 按 docs/RELAY.md 启动 custom relay milestone (仍在大流量节点, E2E 加密), 绝不回退到 Control VPS DERP.
2. **Tailscale CLI 输出漂移**: 已隔离 parser, 但 Tailscale 升级仍可能改格式; CI 需 fixture 回归.
3. **CN↔US 直连质量不可预设**: 不要硬编码 HK 最快; 按 TEST-PLAN 实测 Direct/JP/HK/SG/USW 后选择.
4. **全零/稀疏文件误导测速**: 测试必须用 deterministic pseudo-random (见 scripts/smoke-test.sh), 不用全零.
5. **rclone binary 体积/版本漂移**: agent 需检测 `rclone version >=1.75`, 否则 S3 fallback 禁用并告警.

## Next Actions

1. ✅ Control VPS 部署完成 (见 Deployment State) — 待用户提供 CN/US 测试机做 enroll + smoke-test (1GB→10GB Direct/resume/DERP-refuse). enroll: `tailscale up --login-server https://mineai.top --hostname <name> --authkey <preauth>`, 再用管理员 token 调 `POST /api/v1/devices` 拿 agent token.
2. 用户添加 hs.mineai.top / mesh.mineai.top A 记录后可切标准双子域名 Caddyfile (configs 已备于服务器).
3. 采购 JP relay → `install-relay.sh` + grant `tailscale.com/cap/relay` → Peer Relay 10GB 测试 (relay vnStat ↑, control VPS ≈ MB 级).
4. 配置 S3 profile → S3 fallback 测试 (upload/retry/download/hash).
5. Backup/restore 实测 → Phase 12 security review → 生产 runbook.
