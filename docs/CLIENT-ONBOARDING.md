# CLIENT-ONBOARDING.md

## Linux (尽量自动化)

1. 管理员在 Web UI 创建 enrollment (选 user/project/hostname/tags) → 得到一次性 token (30min)
2. `sudo bash scripts/install-agent.sh https://mesh.example.com`
3. `sudo tailscale up --login-server https://hs.example.com --hostname <hostname> --authkey <PREAUTH>`
4. `meshbridge-agent --controller https://mesh.example.com --device-id <id> --token-file /etc/meshbridge/agent.token --allowed-roots /home/user/projects,/data`
5. SSH: `ssh <hostname>` 或 `ssh 100.x.y.z` (只走 overlay, 终端 22 不暴露公网, 用 key)

## Windows/macOS

Tailscale GUI 若有限制: 先 GUI 登录 `--login-server https://hs.example.com`, 再运行 agent 二进制 (Windows Service / launchd, 见 deploy/windows + deploy/macos), allowed_roots 例 `D:\Projects` / `/Users/user/Projects`. 步骤由 Controller enrollment 页生成.

## allowed_roots

默认拒绝全盘; 所有 src/dst canonicalize, 拒绝 `..`/symlink/junction 逃逸; admin mode 默认关.
