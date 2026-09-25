# Windows: NSSM 或 sc.exe 注册 meshbridge-agent 为 Service, token 存 %ProgramData%\meshbridge\agent.token (仅 Administrators/SYSTEM 可读).
# 例: sc.exe create MeshBridgeAgent binPath= "C:\Program Files\MeshBridge\meshbridge-agent.exe --controller https://mesh.example.com --device-id <id> --token-file C:\ProgramData\meshbridge\agent.token"
# 防火墙: 不开入站; allowed_roots 例 D:\Projects,D:\Transfer.
