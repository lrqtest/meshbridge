# SECURITY.md — 上线前 checklist

- [ ] TLS (Caddy 自动 HTTPS, HSTS), 证书有效, 跳转正确
- [ ] Session: Secure/HttpOnly/SameSite, CSRF token, expiry+rotate, 无 fixation
- [ ] 密码 Argon2id, API token 存 hash, enrollment 一次性+hash+30min
- [ ] S3 secret 用 master.key 加密, 0600, 不进 Git/日志; agent 不见 AK
- [ ] 路径: allowed_roots + canonicalize + 拒绝 `..` + symlink/junction 逃逸测试 (Linux/Win/macOS)
- [ ] 命令注入: rclone/Headscale 参数白名单, 不拼 shell; SQL 全参数化; policy 校验 + 禁宽授权
- [ ] Transfer 授权: Tailscale-IP bind + HMAC 10min token + nonce + 率限 + audit
- [ ] 爆破: 登录/API 率限; 日志 redact (password/apikey/preauth/token/SK/key/header)
- [ ] 文件权限: server.env/master.key/agent.token 0600; DB 0700 dir
- [ ] systemd sandbox: NoNewPrivileges/ProtectSystem/PrivateTmp (不破坏必要写路径)
- [ ] 防火墙: 公网仅 22/80/443 (+relay 40000/udp); 8080/9090/8081 loopback; 9090 绝不公网
- [ ] DERP: embedded 默认关, 启动检查 WARN; DERP 大文件默认拒 (>100MiB)
- [ ] 备份加密 + restore 实测; secrets 不进 Git (git status/diff/log 检查)
- [ ] `go vet`, `go test -race`, 依赖 pin (STATE.md)
