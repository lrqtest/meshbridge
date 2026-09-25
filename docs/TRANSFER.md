# TRANSFER.md — chunk/resume/hash/transport

- 默认 chunk 64MiB (8–256MiB 可配), manifest {fileID,relPath,size,mtime,mode,chunkSize,count,perChunk BLAKE3,final BLAKE3}.
- Receiver `<name>.meshbridge.part` 预分配 (先检查磁盘) + bitmap (`transfer-state.json`/SQLite, 不用数万小文件) + `WriteAt(offset)` + per-chunk BLAKE3 → 全齐 → final BLAKE3 → fsync → atomic rename.
- 已存在目标默认 error (overwrite/rename/skip-if-identical 可选).
- Transport: Receiver 只 bind Tailscale IP (禁 0.0.0.0); TLS + Controller HMAC 短效 token (job/src/dst/expiry/nonce, 10min, 防重放). 并发默认 4 (1–16 自适应 throughput/RTT/loss), token-bucket 限速 (10/50/100Mbps/unlimited), bounded buffers (1MiB 流式, 不整文件进 RAM).
- 目录: 流式 manifest, 保留 relPath/size/mtime, 拒绝 socket/device, symlink 默认拒绝且绝不 follow (防逃逸), 小文件 batch.
- 中断恢复: kill source/destination 后重启, 已完成 chunk 不重发 (bitmap 持久化, `.meshbridge/` state dir). Receiver 重启同样恢复.
- Route monitor: 15s+jitter probe, DIRECT→DERP 连续 2–3 次 + remaining>derp_limit 才 PAUSE → 重调度 (Direct retry→PeerRelay→S3), 每次写 path_observations + audit.
