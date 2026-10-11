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
- Go **1.27.2** or later security patch (go.mod requires >=1.27.2)
- Debian 12 / Ubuntu 24.04 LTS, Caddy latest stable, SQLite (WAL)

快速开始见 `docs/DEPLOYMENT.md`, `docs/CLIENT-ONBOARDING.md`, `STATE.md`.

MeshBridge 与 MineAI 七应用使用同一份 `github.com/mineai/kit` 基础代码：
HTTP、连接与请求预算、密码/Token primitive、退出 owner，以及前端主题、语言和
项目导航。账户、SQLite、隧道、Headscale 和流量计量仍由各自服务管理。
构建前将匹配的 MineAI `kit/` 放在本仓库同级；`go.mod` 的本地 `replace => ../kit`
是构建契约，不使用 `go.work`，也不从网络拉取尚未发布的 `v0.0.0`。
kit 变化后需同时验证并重建八个服务；发布仍逐个进行。

MineAI 主平台也可作为六个账号应用的统一登录入口。此功能默认关闭；生产
显式设置 `MESH_SSO_ENABLED=true`、HTTPS `MESH_SSO_ISSUER` 和精确回调映射
`MESH_SSO_CLIENTS`，各项目配置自己的 BaseURL 与 SSO client。已有项目账号
首次绑定须验证原项目密码，保留 ID、数据和角色，不按邮箱自动绑定管理员。
主平台退出后，后续项目认证最迟 15 秒失效；已建立的 WebSocket/SSE 不承诺
同时断开。本地恢复登录仍可用。启用时所有 `/t/*` 路径隧道强制 opaque-origin
sandbox，完整原站权限应使用独立隧道子域。不要共享各项目密码或 master key。

MineAI 平台与 MeshBridge 项目是两个 origin、两个界面（`https://mineai.top/` 只有项目导航和
平台账号入口；`https://meshbridge.mineai.top/` 才是 MeshBridge 登录页与控制台），由同一进程按
Host 判定，配置见 `MESH_PROJECT_URL`（`docs/DEPLOYMENT.md`、仓库根目录 `docs/platform-surfaces.md`）。
MeshBridge 作为平台的第七个 SSO client：授权码 + PKCE，会话各自独立，退出平台即时失效；
Google 登录不会按邮箱接管管理员账号。

```bash
make tidy
make test
make build
make runtime-check                  # 路由规则表、缓存、SSO 运行时
python3 scripts/e2e_surfaces.py     # 真实浏览器验收（localhost=平台，127.0.0.1=项目）
bash scripts/dev-instance.sh        # 本地双 origin 开发实例（凭据随机生成，不打印）
```

安全模型见 `docs/SECURITY.md` + `docs/THREAT-MODEL.md`. 默认 deny-by-default Grants, 跨项目隔离.
