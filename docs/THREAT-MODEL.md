# THREAT-MODEL.md

## 资产

- 用户密码 / session / API token / enrollment token / Headscale API key / pre-auth key / S3 AK/SK + crypt 密码 / master.key / transfer token / 文件内容 + 完整性 / audit/policy/DB.

## 攻击面与缓解

| 威胁 | 缓解 |
|---|---|
| 公网扫描 Caddy/Headscale/MeshBridge | 仅 22/80/443 公网; 8080/9090/8081 loopback; firewall default-deny inbound; SSH key-only, 禁 root-password |
| 跨项目越权访问 | deny-by-default Grants; tag per-project; policy 原子发布+check+rollback+快照; 每次变更 audit; 集成测试 Alpha✕Beta |
| 设备冒充/未授权加入 | enrollment 256bit 一次性, 30min, hash存储, 一次失效; Headscale pre-auth key 最小 tag; device↔node 映射绑定 |
| 路径遍历/symlink/junction 逃逸 | allowed_roots 白名单, canonicalize + EvalSymlinks, 拒绝 `..`, 不 follow link, Win junction 同检; 默认关闭 admin mode |
| Transfer 未授权推送/重放 | Receiver 只 bind Tailscale IP; TLS + HMAC 短效 token (10min, nonce, job/src/dst/expiry); 失败率限 + 审计 |
| Secret 泄露 (日志/Git/备份) | 结构化日志 redact (password/apikey/preauth/token/SK/key/header); .gitignore secrets+DB; master.key 0600 不进Git; 备份加密 (restic/age), 不默认传公网; 最终输出绝不打印 secret |
| SQL注入/命令注入/策略注入 | 全参数化 SQL; rclone/Headscale 调用白名单参数, 不拼 shell; policy 用模板+校验, 拒绝 `*` 宽授权 |
| 会话固定/CSRF/爆破 | Secure/HttpOnly/SameSite cookie, CSRF token, expiry+rotate, 登录率限 + Argon2id (OWASP 参数) |
| DERP/Relay 流量盗用致 50GB 爆表 | embedded DERP 默认关 + 启动检查; DERP 大文件默认拒 (>100MiB → WAIT/S3); relay quota 80/95% 阈值; vnStat 三档告警; transfer endpoint 不绑公网 |
| 供应链 (Headscale/Tailscale/rclone/Go) | pin 版本 (STATE.md) + release notes + client compat 检查 + staging; 不用 nightly; agent 上报版本, 不静默全 fleet 升级 |
| 数据损坏/断电 | chunk BLAKE3 + final BLAKE3 + fsync + atomic rename; bitmap 持久化; Controller/Agent 重启不丢状态 (SQLite + state dir); backup+restore 实测 |
| 运维误操作 | 所有变更 backup→validate→apply→verify→rollback; systemd sandbox (NoNewPrivileges/ProtectSystem/PrivateTmp); firewall 最小; audit 不可删 |

## 非目标/明确不做

- 绕过法律/运营商政策/网络管制的功能. 本项目是个人/项目私网 + 远程管理 + 同步工具, 所有设备授权, 数据走 E2E (WireGuard) + 应用层校验.
- Agent 任意 shell 执行 (用 SSH over Tailscale 代替).
- 公网暴露终端 22 端口 (只走 overlay).

## 残余风险

- Headscale Peer Relay 兼容性需实测 (STATE.md risk #1).
- Tailscale CLI 格式漂移 (parser 隔离 + fixture).
- CN↔US 线路抖动致 flap (阻尼 + S3 兜底).
