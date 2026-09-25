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
sudo headscale config check
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
head -c 32 /dev/urandom | sudo tee /etc/meshbridge/master.key >/dev/null
sudo chmod 600 /etc/meshbridge/master.key
sudo systemctl daemon-reload && sudo systemctl enable --now meshbridge-server
curl -sf http://127.0.0.1:8081/api/v1/health
```

## 5. Ansible (幂等, 可选但推荐)

`deploy/ansible/inventory.example.ini` 复制为 `inventory.ini` (不进Git), 变量用 placeholders + ansible-vault:

```bash
ansible-playbook -i inventory.ini deploy/ansible/site.yml --ask-vault-pass
```

## 6. 回滚

任何变更: backup → validate → apply → verify → rollback. 见 OPERATIONS.md + scripts/backup.sh/restore.sh.
