# DEPLOYMENT.md

Target: Debian 12 / Ubuntu 24.04 LTS, 2C/low-RAM/50GB.

## 0. 前置 (用户提供)

- SSH: `ssh user@VPS -i key` (key-only, 禁 password/root-password)
- DNS: `hs.example.com`, `mesh.example.com` → VPS IP, 生效后再申请证书
- S3 (可选): endpoint/region/bucket/AK/SK/prefix
- Relay VPS (Phase 8): 公网IPv4 + UDP 40000 + 大流量

## 1. Control VPS 初始化

```bash
scp -i key deploy/... user@VPS:/tmp/
ssh user@VPS
sudo bash /tmp/scripts/install-control.sh --headscale-version 0.29.4 \
  --hs-domain hs.example.com --mesh-domain mesh.example.com
```

检查: `ufw status`, `sshd -T | grep -i password`, `vnstat`.

## 2. Caddy

```bash
sudo cp deploy/caddy/Caddyfile.example /etc/caddy/Caddyfile
sudo sed -i 's/hs.example.com/<HS>/; s/mesh.example.com/<MESH>/' /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
curl -vk https://hs.example.com/ ; curl -vk https://mesh.example.com/api/v1/health
```

Caddy 自动 HTTPS; Headscale 反代需支持 WebSocket (默认即支持, 部署前按当时官方 reverse-proxy 文档核对).

## 3. Headscale (官方 DEB + SQLite, v0.29.4)

```bash
sudo cp deploy/headscale/config.yaml.example /etc/headscale/config.yaml
# edit server_url, base_domain; 确认 derp.server.enabled=false
sudo headscale configtest
sudo systemctl enable --now headscale
sudo headscale users create admin
sudo headscale apikey create   # → 写入 /etc/meshbridge/server.env (0600), 绝不进Git/日志
sudo headscale policy check -f /etc/headscale/policy.hujson
```

metrics `127.0.0.1:9090` 绝不公网开放.

## 4. MeshBridge Server

```bash
# 在本地: make build-all ; scp bin/meshbridge-server VPS:/tmp/
sudo install -m0755 /tmp/meshbridge-server /usr/local/bin/
sudo cp deploy/systemd/meshbridge-server.service /etc/systemd/system/
echo 'MESH_HEADSCALE_API_KEY=<key>' | sudo tee /etc/meshbridge/server.env
sudo chmod 600 /etc/meshbridge/server.env
openssl rand -hex 32 | sudo tee /etc/meshbridge/master.key >/dev/null
sudo chmod 600 /etc/meshbridge/master.key
sudo systemctl daemon-reload && sudo systemctl enable --now meshbridge-server
curl -sf http://127.0.0.1:8081/api/v1/health
```

### 平台与项目两个 origin

同一进程可以同时服务 MineAI 平台 origin 与 MeshBridge 项目 origin（生产：`mineai.top`
与 `meshbridge.mineai.top`，两者在 Caddy 里都反代到 `127.0.0.1:8081`，**必须保留原始 Host**）。
在 `/etc/meshbridge/platform-sso.env`（非机密）声明：

```text
MESH_BASE_URL=https://mineai.top                    # 平台 origin，兼 SSO issuer，保持不变
MESH_PROJECT_URL=https://meshbridge.mineai.top      # 项目 origin：规范形式，无尾斜杠，HTTPS
# MESH_PROJECT_SSO=false                            # 可选：保留分域，但项目页恢复自己的密码表单（默认是一套登录）
```

不设置 `MESH_PROJECT_URL` 就是独立安装：只有 MeshBridge 一个界面，任何主机名都显示它。
启用平台 SSO 且设置了 `MESH_PROJECT_URL` 时，`MESH_PROJECT_URL/sso/callback` 自动注册为第七个
SSO client（`MESH_SSO_CLIENTS` 仍只列六个应用）。迁移 `007`、`008` 必须随二进制放进
`/etc/meshbridge/migrations/`。边界与回滚见仓库根目录 `docs/platform-surfaces.md`。

### Google 登录（可选，与密码并列）

登录页只在配置了网页 OAuth Client ID（它不是密钥）时显示 Google。两种来源，**设置优先**：

- 管理员在 控制台 → 设置 → “MineAI 的登录与邮件”里保存：下一次打开登录页即生效，无需重启；
  保存空值表示明确关闭，即使环境变量里有值也忽略。
- 或在 `/etc/meshbridge/server.env` 写 `MESH_GOOGLE_CLIENT_ID=<id>.apps.googleusercontent.com`：
  只在启动时读取，修改后需要重启服务。

在 Google Cloud Console 的 OAuth 客户端 → Authorized JavaScript origins 中加入**两个**来源：
`https://mineai.top` 与 `https://meshbridge.mineai.top`（设置页会列出并可复制）。
服务器在中国大陆时，到 `www.googleapis.com`（JWKS）的访问可能不稳定：此时登录返回
`google_unavailable`（503，提示稍后重试或改用密码），不影响密码登录；需要时给服务设置
`HTTPS_PROXY`。浏览器访问不到 `accounts.google.com` 时，登录页显示说明与重试，而不是
悄悄隐藏按钮。Google 登录不会自动接管管理员或邮箱未验证的账号，详见 `docs/platform-surfaces.md`。

## 5. Ansible (幂等, 可选但推荐)

`deploy/ansible/inventory.example.ini` 复制为 `inventory.ini` (不进Git), 变量用 placeholders + ansible-vault:

```bash
ansible-playbook -i inventory.ini deploy/ansible/site.yml --ask-vault-pass
```

## 6. 回滚

任何变更: backup → validate → apply → verify → rollback. 见 OPERATIONS.md + scripts/backup.sh/restore.sh.
