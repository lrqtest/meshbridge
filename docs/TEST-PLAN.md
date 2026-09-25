# TEST-PLAN.md

`go test ./...` + `go vet` + `go test -race` 必须全过. 重点单测: 路径安全/policy渲染/chunk bitmap/resume/hash/Headscale mock/route parser/scheduler.

## 真机传输测试 (deterministic pseudo-random, 禁全零/稀疏)

生成: `python3 scripts` 片段或 `openssl rand` (1GB/10GB). 全零会因压缩/稀疏误导带宽, 禁止.

- A Direct: route=DIRECT, hash equal, Control VPS bytes << 文件 (MB 级)
- B 源中断: 30–60% kill source → restart → 已完成 chunk 不重发
- C 目的重启: 同上, receiver 恢复
- D Peer Relay: 制造 direct 失败 → route=PEER_RELAY, 10GB 走 Relay, 不经 Control
- E DERP 保护: route=DERP + 10GB job → WAITING/REFUSED/S3, 不偷传
- F S3: upload→retry→download→hash, Controller 不碰数据

## 跨境 (CN/US)

记录 RTT/loss/direct/peer/speed/resume; 对比 JP/HK/SG/USW, 不硬编码“香港最快”, 按实测选.

## 验收 25 条 (plan §51)

映射到 smoke-test.sh + 本文档每项打勾, 输出见最终报告 §52 (ARCH/SUMMARY, PINNED, PORT MATRIX, SECURITY, DEVICES/PROJECTS/RELAYS, 各 TEST 结果, TRAFFIC, BACKUP/RESTORE, LIMITS, COMMANDS, ROLLBACK, NEXT).
