# gately-rs

用 Rust 编写的边缘网关，借鉴 [Gately](https://github.com/wangwanjie/gately) 的功能设计，是一个**独立的重新实现**。

> 非官方项目，与上游 Gately 无隶属关系。v0.7.0 直接复用上游 Gately 的 Vue 网页管理端（随二进制内嵌），通过兼容 API 层读写 gately-rs 配置；旧的精简后台仍保留在 `/ui-legacy`。逐条功能对照见 [`docs/FEATURE-MATRIX.md`](docs/FEATURE-MATRIX.md)。仍是**功能对齐版**，不建议无防护地直接暴露到公网。

## 已实现功能

### 核心
- **配置**：明文 JSON，首次启动自动生成；每次修改前自动快照，支持 diff、查看历史与一键回滚；支持整份配置导入/导出。
- **管理后台**：默认使用上游 Gately 的 Vue 网页管理端（内嵌在 `/gately`，`/` 与 `/ui` 自动跳转），Cookie 会话登录；同时保留 REST API、OpenAPI（`GET /api/openapi.json`）与多 API Token。旧的精简后台位于 `/ui-legacy`。
- **反向代理**：按 Host 精确匹配（支持 `*`），可绑定监听器；WebSocket 透传、路径规则、后端权重/备用、错误页拦截、按路径缓存规则、限流、gzip 压缩、用户 Header 注入、**按登录用户分流后端**（等价 nginx `map $remote_user`）。
- **站点类型**：反向代理、重定向、静态文件、固定文本、断开连接、导航面板。
- **TLS**：rustls 加载静态 PEM；HTTP 与 HTTPS 可共用一个监听器，可附加纯 HTTP 端口；管理界面可单独启用 HTTPS。

### 网络
- **端口转发**：TCP/UDP、端口段、多目标故障转移、连接数与单来源连接限制、空闲超时、PROXY v1/v2、来源白名单/黑名单、敲门准入、流量统计。
- **协议分流**：单端口按 TLS SNI / ALPN、HTTP Host、Minecraft 服务器地址以及 SSH/RDP/SOCKS/OpenVPN/RTSP/SIP/XMPP/MQTT/AMQP/PostgreSQL/Redis/SMB/Git/IRC/ADB/BitTorrent 等 20+ 协议特征分流，TLS 不解密透传，支持默认目标、等待超时路由与逐路由 PROXY 协议。
- **DDNS**：Cloudflare、DuckDNS、dynv6、GoDaddy、Porkbun、Namecheap、Namesilo、Route53、阿里云、腾讯云/DNSPod、华为云、Vercel、Gcore、ClouDNS、deSEC、Bunny、NS1、Gandi、OVH 等模板化适配，另有自定义回调；IP 来源支持静态值、URL 与命令，可引用 STUN 变量；支持 Webhook、备注、分组与定时刷新。
- **STUN**：RFC 5389 UDP/TCP 探测、保活、UPnP 钩子、地址变化 Webhook/脚本与通知。
- **隧道托管**：frpc/frps/cloudflared/Tailscale/NetBird/EasyTier/自定义外部进程，自动重启、配置写入、在线安装/更新与回滚。
- **网络诊断**：Ping、路由追踪、端口探测、DNS 查询、测速、局域网扫描（目标白名单限制）。

### 安全
- **端口敲门**：自研 SPA（AES-256-CFB 加密 + HMAC-SHA256 校验 + 时间窗 + nonce 防重放 + 身份校验 + 单地址约束），成功后按规则放行来源地址（nftables / iptables / ipset），并与端口转发、协议分流、站点联动。
- **ACME**：HTTP-01 与 DNS-01（Cloudflare / 外部 hook / 手动），通配符、EAB、shortlived 配置、自动续期、证书部署（scp/ssh 与 Docker 容器重启）。
- **WAF**：内置 OWASP CRS 风格基线规则 + 自定义正则，path/query/header/cookie/body/all 检查目标，检测/拦截模式、配置集、请求体检查上限、按路径跳过、登录用户绕过。
- **入侵防护**：fail2ban 式文件/命令/Docker 日志规则、诱饵端口、端口扫描检测、Web 探测路径与连续 404、TLS 失败钩子、IPv6 /64 封禁、递增时长、白名单、永久封禁、nftables / iptables / ipset 内核封禁。
- **IP 列表**：URL/文件订阅 CIDR/IP 列表，供站点与端口转发引用。
- **认证**：密码 + 静态 Token + TOTP + OIDC Authorization Code + PKCE + 站点共享用户（Basic / 表单 / 转发认证）、登录失败限流。
- **管理端安全**：安全入口路径、仅内网访问、自定义未授权响应（404 / 空白 / 自定义页）、管理界面 HTTPS、可信反代真实 IP、运行时模块开关。

### 运维
- **统计与拓扑**：站点分钟级请求/流量/错误、热门 IP/路径/国家、系统资源与网卡信息、监听器→站点→后端拓扑、Prometheus 指标。
- **访客审计**：按来源地址统计站点/路径/身份/拦截次数，支持 CSV 导出与按天访问日志归档。
- **审计日志**：登录、配置变更与敏感操作记录，可设置保留天数。
- **通知中心**：Webhook、Telegram、Bark、ntfy、Gotify、Pushover、Discord、Slack、Server酱、PushPlus、企业微信、钉钉、飞书、邮件（SMTP）、命令；事件通配、静默去重、失败指数退避重试与补发队列。
- **计划任务与备份**：5 段 cron 执行命令或 HTTP 请求；定时备份支持 **scrypt + AES-256-GCM 加密**，保留策略与手动恢复。
- **列表统一管理**：所有列表统一支持分组、搜索、排序、批量启停/删除/复制/移动（`/api/lists/{kind}`）。
- **Docker 管理**：容器列表、日志、启停重启、镜像拉取与构建、Compose 操作、容器内执行；耗时任务后台运行且可中断。
- **Web 终端**：浏览器内本机 Shell、SSH、Telnet 会话，支持目录浏览、文件上传下载。
- **文件服务**：WebDAV（OPTIONS/PROPFIND/GET/PUT/DELETE/MKCOL/MOVE/COPY）与 FTP（含被动端口范围），按用户授权根目录，可只读。
- **CLI**：`reset-password`、`reset-totp`、`rollback`、`backup`、`ctl`、`mcp`。

## 明确限制

- **HTTP/3、Passkey/WebAuthn 未实现**；Coraza/完整 OWASP CRS v4 SecLang、SMB2、File Browser、存储挂载、网络唤醒、飞牛/OpenWrt 打包尚未移植。
- DDNS 的 30+ 服务商采用**模板化 HTTP 适配**，部分私有签名的服务商需填写 `options.endpoint` 自定义回调。
- 端口敲门为自研 SPA 协议（与 fwknop 原始报文格式不兼容），加密与防重放机制等价。
- GeoIP 依据上游 CDN 提供的国家头判定，无内置离线数据库。
- 配置热更新不完整：站点、规则、转发与分流立即生效；TLS 监听、管理员端口与安全入口变更需重启（保存前会校验监听地址可用性）。
- 封禁后端需要系统权限；无权限时仍保留内存封禁表。
- 配置中明文保存 API Token、TOTP secret 与 OIDC client secret，请设置文件权限（建议 `0600`）。

## 上游网页端兼容边界

`/gately` 提供的是上游 Gately 前端原版页面（Apache-2.0），由 `src/upstream.rs` 提供等价 API：

- 配置类页面（Web 站点/监听器、证书、DDNS、WAF、通知、计划任务、端口转发、协议分流、STUN、敲门、存储、WOL、Docker 设置等）可列表、新增、编辑、启停、删除，改动写回同一个 `gately.json`。
- 上游的 `XxxView` 运行态字段（`state`、`stats`、`running`、`error` 等）以安全默认值提供，**不等同于上游 Go 后端采集到的实时统计**。
- `frp` / `cloudflared` / `tailscale` / `netbird` / `easytier` 页面可展示，但其专属控制面字段被映射到本项目的通用隧道配置；Passkey、Coraza CRS 控制台、完整 Docker/终端协议仍以本项目已有实现为准。
- 兼容层覆盖了上游前端 148 个可 GET 的管理接口，均返回 JSON；写操作按资源映射到现有配置结构，字段差异在 `src/upstream.rs` 中集中转换。

## 预编译二进制

Releases 页面提供三个平台的产物，均带 `.sha256` 校验文件：

| 平台 | 文件名 |
|---|---|
| Windows x86_64 | `gately-rs-v0.6.0-windows-x86_64.exe` |
| Linux x86_64 | `gately-rs-v0.6.0-linux-x86_64`（musl 静态） |
| Linux ARM64 | `gately-rs-v0.6.0-linux-arm64`（musl 静态） |

## 快速开始

```bash
cargo build --release
./target/release/gately-rs ./gately.json
```

- 管理后台（上游网页端）：<http://127.0.0.1:16680/gately>（`/` 与 `/ui` 自动跳转）
- 旧版精简后台：<http://127.0.0.1:16680/ui-legacy>
- 已有 API Token 时可用 <http://127.0.0.1:16680/gately/set-cookie?token=你的令牌> 直接安装会话 Cookie
- 默认密码：`gately.cn`
- 默认 token：`dev-token-change-me`
- 默认代理监听：`0.0.0.0:18080`
- ACME HTTP-01 监听：`0.0.0.0:80`

### Windows (GNU 工具链)

```bash
cargo +stable-x86_64-pc-windows-gnu build --release --target x86_64-pc-windows-gnu
```

## API 示例

```bash
BASE=http://127.0.0.1:16680
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"password":"gately.cn"}' $BASE/api/login | jq -r .token)
AUTH="Authorization: Bearer $TOKEN"

curl -H "$AUTH" $BASE/api/status
curl -H "$AUTH" $BASE/api/metrics/prometheus
curl -H "$AUTH" $BASE/api/topology
curl -H "$AUTH" $BASE/api/audit
curl -H "$AUTH" $BASE/api/visitor-audit

# 网络诊断
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' -d '{"target":"1.1.1.1"}' $BASE/api/diag/ping

# 列表批量操作
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"action":"disable","ids":["site_1"]}' $BASE/api/lists/sites/bulk

# 模块配置（敲门 / Docker / 文件服务 / 终端 / 诊断）
curl -X PUT -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"enabled":true}' $BASE/api/modules/knock
```

主要接口分组：`/api/status`、`/api/config`、`/api/modules/{name}`、`/api/lists/{kind}`、`/api/sites`、`/api/certs`、`/api/ddns`、`/api/acme`、`/api/waf`、`/api/jail`、`/api/knock`、`/api/tunnels`、`/api/stun`、`/api/port-forwards`、`/api/proto-routes`、`/api/site-users`、`/api/ip-lists`、`/api/notifications`、`/api/tasks`、`/api/backups`、`/api/diag`、`/api/docker`、`/api/terminal`、`/api/files`、`/api/metrics`、`/api/topology`、`/api/visitor-audit`、`/api/audit`、`/api/history`、`/api/import`。

## 许可与致谢

本项目使用 [Apache License 2.0](LICENSE)。上游 [Gately](https://github.com/wangwanjie/gately) 同样采用 Apache-2.0，详见 [NOTICE](NOTICE)。
