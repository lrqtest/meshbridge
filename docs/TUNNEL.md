# TUNNEL.md — 公开 Web 隧道（内网网页暴露）

> 设计原则沿用全项目: agent **只出站、永不监听**; CONTROL != DATA(网页流量是例外,
> 用配额护栏兜底, 见下); 密钥只存哈希; 一切可审计。

## 是什么

内网机器上的 meshbridge-agent 主动向 Control VPS 建立一条出站 WebSocket;
公网访客的 HTTP 请求经 Caddy → 网关(loopback :8082) → 该 WebSocket → agent →
`127.0.0.1:<port>` 的本地网页。**内网机器不需要公网 IP、不需要开任何入站端口。**

```
访客 ──HTTPS──> Caddy :443 ──> 127.0.0.1:8082 网关
                                  │  (密钥门禁/限速/配额/头清洗)
                                  └── wss (agent 发起, yamux 多路复用)
                                        └── agent ──> 127.0.0.1:8080 本地网页
```

## 两种公开 URL

| 模式 | 形态 | 适用 | 前置条件 |
|---|---|---|---|
| 路径模式 | `https://mineai.top/t/<32hex>/` | API、相对路径应用、快速验证 | 无(默认可用) |
| 子域名模式 | `https://t-<12hex>.mineai.top` | 绝对路径的 HTML/SPA(资源引用 `/assets/...`) | 通配 DNS `*.mineai.top` A 记录 + Caddy on-demand TLS |

> **通配符标签**: Caddy/ACME 的通配符必须独占整个 DNS 标签——站点块写
> `*.mineai.top`(网关自身会对非 `t-<hex>` 主机返回 404), `t-*.mineai.top`
> 是**无效**写法。

路径模式会把 `/t/<slug>` 前缀剥掉再转发(应用看到根路径 `/`), 302/301 的
`Location: /x` 会被改写回带前缀; 子域名模式不做任何改写, 应用行为与直接部署一致。
若应用自身能处理前缀, 建隧道时可选 strip_prefix=false。

## 密钥门禁 (visitor gate)

- 每隧道独立访问密钥, `crypto/rand` 192bit, **DB 只存 SHA-256**, 创建/轮换时明文只显示一次
- 访客通过三种方式之一进门:
  1. 网页表单输入密钥 → HMAC 签名 cookie(7 天, HttpOnly, SameSite=Lax,
     路径模式下 Path 绑定 `/t/<slug>`, 子域名间互不可见)
  2. `Authorization: Bearer <key>`(curl/API 场景)
  3. `key_required=false` 完全开放(**不建议**)
- 防爆破: 单 IP+隧道 8 次错误 → 锁 15 分钟(429); 校验常数时间
- 密钥泄露即轮换: 控制台 "New key" 一次点击, 旧密钥立即失效
- gate/错误页零 JS、CSP `default-src 'none'`, 不泄露隧道存在性(404 与门禁页同形)

## 同源隔离 (2026-09-27 审阅修复)

路径模式的隧道页与控制台 **同源**, 而控制台把 API token 存在
`localStorage["mb_token"]`——若不隔离, 任何被隧道化的页面(包括普通用户
创建的)都能直接读走管理员的 token。因此:

- 路径模式默认对被代理响应注入 `Content-Security-Policy: sandbox
  allow-scripts allow-forms allow-modals allow-popups allow-downloads`
  (**不含** `allow-same-origin`): 页面进入**不透明源**, 读不了
  localStorage/document.cookie, 对 `/api/v1/*` 的凭据调用也会因 CORS 失败
- 注入用 `Add()`——应用自带的 CSP 与 sandbox 同时生效(只收紧不放松)
- 建隧道时可选 `sandbox=false`(仅对自己完全可控、且应用需要浏览器存储
  的内容关掉); PATCH 可随时改, 立即生效(网关重建代理配置)
- 子域名模式天然独立源, 不注入 sandbox, 应用行为与直接部署一致
- 残余面: sandbox 页面仍可用表单**提交**(非读取)无鉴权的 POST 端点
  (如 send-code), 已有全局频控兜底

## 安全边界

**服务端与 agent 双侧强制:**
- 上游仅限 `http/https` + **IP 字面量** + 环回/RFC1918/CGNAT 网段——
  不允许任意公网 IP(开放代理滥用), 不允许域名(DNS 可被外部改指向)
- agent 侧 `--tunnel-allow` 进一步限定可拨 CIDR(默认仅环回);
  控制面下发的配置**永远不能**放宽 agent 本地策略
- 不做裸 TCP 转发——SSH/RDP/SMB/Redis 打洞在架构上被排除

**网关卫生:**
- 请求体上限(默认 100 MiB, 硬顶 1 GiB), 超限 413
- 入站 `X-Forwarded-*` 全部丢弃重建(仅信任来自环回 Caddy 的 XFF 首跳)
- hop-by-hop 头由 ReverseProxy 剥离; `Host` 重写为上游地址
- WebSocket/101 升级、SSE 流式透传; 升级后字节继续计入用量
- 每隧道并发 ≤16 流, 全局 ≤256
- 响应头超时是 **30 分钟绝对上限**且从不覆盖请求体上传: 慢速上传
  (访客网速慢/上游消费慢)都是合法的; 真正的挂死由 yamux keepalive
  (agent 死链)与访客断开(ctx 取消)兜底

**配额(保护 50GB/月的小水管):**
- 每隧道默认 5 GiB/月(bytes_in+bytes_out), 80% 审计告警, 100% 自动停用+断开 agent
- 全局预算默认 20 GiB/月(settings: `tunnels_global_monthly_bytes`), 超出后所有隧道 503
- 访客限速默认 240 req/min/IP(settings: `tunnels_rate_per_min`)
- 记账口径: 请求体+响应体字节(不含 TCP/TLS 头部开销)

**审计:** created/updated/deleted/key rotated/agent online/offline(1 分钟内抖动去重)/
quota warning/quota exceeded/global budget exceeded。

## 运维

### Caddy 路由(生产)

```caddyfile
# 全局选项块(子域名模式的按需签发, ask 只答真实隧道)
{
  on_demand_tls {
    ask http://127.0.0.1:8081/api/v1/tunnels/cert-ask
  }
}

mineai.top {
  # ... 现有 @mesh 分流保持不变, 在其前面加:
  handle /t/* {
    reverse_proxy 127.0.0.1:8082
  }
}

t-*.mineai.top {
  tls { on_demand }
  reverse_proxy 127.0.0.1:8082
}
```

子域名模式需先加**通配 A 记录** `*.mineai.top → 36.151.144.201`(路径模式零 DNS 改动)。

### 服务端环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `MESH_GATEWAY_LISTEN` | `127.0.0.1:8082` | 网关监听(生产强制环回, config.Validate 拒绝 0.0.0.0) |
| `MESH_TUNNEL_BASE_DOMAIN` | 取 `MESH_BASE_URL` 的 host | 子域名模式的基域; 留空则路径模式 only |
| `MESH_TUNNEL_GATE_SECRET` | — | 门禁 cookie 密钥覆写(默认从 master.key 派生) |

### settings 键

管理员 API(控制台"设置 → 公开隧道"卡片即此封装, 变更 30s 内生效):
`GET/PUT /api/v1/tunnels/settings` `{enabled, global_monthly_bytes, rate_per_min}`

等价 DB 键: `tunnels_enabled` · `tunnels_global_monthly_bytes`(默认 20 GiB) ·
`tunnels_rate_per_min`(默认 240, 下限 10)

### 使用流程

1. 设备已装 agent(0.2.0+, 常规心跳即自动携带隧道功能)
2. 控制台 "Tunnels → New tunnel": 选设备/本地端口(可选名称、scheme、host、是否要密钥)
3. **立即保存一次性显示的访问密钥与 URL**
4. agent 下个心跳(≈30s)自动连上; 控制台状态 pill 变 online
5. 把 URL+密钥发给要访问的人; 泄露即点 "New key"

agent 手动限定可拨网段: `meshbridge-agent --tunnel-allow 10.0.0.0/8,192.168.1.0/24 ...`

## 已知限制(与威胁模型边界)

- 路径模式下绝对路径资源(`/x.js`)会逃出 `/t/<slug>/` 前缀——HTML 应用请用子域名模式
- 路径模式默认 sandbox 会挡掉应用自身的 localStorage/cookie 读取(不透明源);
  需要这些的应用要么用子域名模式, 要么对该隧道 `sandbox=false`(自担同源风险)
- 挂起但未断开的上游最坏占用流 30 分钟(响应头绝对上限); 无每流"无进展"检测
- 本地服务若**自身无认证**, 密钥门禁是唯一防线; 被暴露面=该服务全部攻击面
- `https` 上游使用 InsecureSkipVerify(本地自签证书常态); 保护跳是隧道本身
- 访客 cookie 不绑 IP(移动网络换 IP 友好); 拿到密钥的人可转交他人——需要更强控制就轮换密钥或加应用自身认证
- 流量经 Control VPS 中转, 速率受其带宽限制; 未来 Relay VPS 就位后可把网关整体迁过去(独立二进制即可, 架构不变)
- 审计的 agent online/offline 有 1 分钟去重窗口, 高频抖动会合并
- 无每访客身份区分(单一共享密钥); 不适合公开大流量站点——那是 CDN 的活
