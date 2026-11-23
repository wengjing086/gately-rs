# gately-rs

用 Rust 编写的边缘网关，借鉴 [Gately](https://github.com/wangwanjie/gately) 的功能设计，是一个**独立的重新实现**。

> 非官方项目，与上游 Gately 无隶属关系。v0.3.0 在原 v0.2.2 基础上补齐端口转发、协议分流、站点类型/认证、统计拓扑审计、通知中心、计划任务与备份、多服务商 DDNS、ACME DNS-01、IP 列表、隧道安装回滚、STUN TCP/UDP、CLI 与 OpenAPI。仍是**内网可用的功能对齐版**，不建议无防护地直接暴露到公网。

## 已实现功能

### 核心
- **配置**：明文 JSON，首次启动自动生成；每次修改前自动快照，支持 diff、查看历史与一键回滚；支持整份配置导入/导出。
- **管理后台**：内嵌单页 Web UI + 登录鉴权 + REST API + OpenAPI（`GET /api/openapi.json`）。
- **反向代理**：按 Host 精确匹配（支持 `*`），可绑定监听器；支持 WebSocket 透传、路径规则、后端权重/备用、错误页拦截、响应缓存、限流、用户 Header 注入。
- **站点类型**：反向代理、重定向、静态文件、固定文本、断开连接、导航面板。
- **TLS**：rustls 加载静态 PEM；HTTP 与 HTTPS 可共用一个监听器，可附加纯 HTTP 端口。

### 网络
- **端口转发**：TCP/UDP、端口段、多目标故障转移、连接数与单来源连接限制、空闲超时、PROXY v1/v2、来源白名单/黑名单、敲门准入、流量统计。
- **协议分流**：单端口按 TLS SNI / ALPN、HTTP Host、Minecraft 服务器地址以及 SSH/RDP/SOCKS/OpenVPN/RTSP/SIP/XMPP/MQTT/AMQP/PostgreSQL/Redis/SMB/Git/IRC/ADB/BitTorrent 等特征分流，支持默认目标、等待超时路由与逐路由 PROXY 协议。
- **DDNS**：Cloudflare、DuckDNS、dynv6、GoDaddy、Porkbun、Namecheap、Namesilo、Route53、阿里云、腾讯云/DNSPod、华为云、Vercel、Gcore、ClouDNS、deSEC、Bunny、NS1、Gandi、OVH 等模板化适配，另有自定义回调；IP 来源支持静态值、URL 与命令，可引用 STUN 变量；支持 Webhook、备注、分组、定时刷新与删除记录选项。
- **STUN**：RFC 5389 UDP/TCP 探测、XOR-MAPPED-ADDRESS、保活、UPnP 钩子、地址变化 Webhook/脚本与通知。
- **隧道托管**：frpc/frps/cloudflared/Tailscale/NetBird/EasyTier/自定义外部进程，自动重启、配置写入、在线安装/更新与回滚。

### 安全
- **ACME**：HTTP-01 与 DNS-01（Cloudflare / 外部 hook / 手动），通配符、EAB、shortlived 配置、自动续期、证书部署（scp/ssh 与 Docker 容器重启）。
- **WAF**：内置 OWASP CRS 风格基线规则 + 自定义正则，path/query/header/cookie/body/all 检查目标，检测/拦截模式、配置集、请求体检查上限、按路径跳过、登录用户绕过、SafeLine 入口。
- **入侵防护**：fail2ban 式文件/命令/Docker 日志规则、诱饵端口、端口扫描检测、Web 探测路径与连续 404、TLS 失败钩子、IPv6 /64 封禁、递增时长、白名单、永久封禁、nftables / iptables / ipset 内核封禁。
- **IP 列表**：URL/文件订阅 CIDR/IP 列表，供站点与端口转发引用。
- **认证**：密码 + 静态 Token + 多 API Token（作用域/只读）、TOTP、OIDC Authorization Code + PKCE、站点共享用户（Basic / 表单 / 转发认证）、登录失败限流、自定义未授权响应、安全入口字段。

### 运维
- **统计与拓扑**：站点分钟级请求/流量/错误、热门 IP/路径/国家、系统资源与网卡信息、监听器→站点→后端拓扑、Prometheus 指标。
- **审计日志**：登录、配置变更与敏感操作记录，可设置保留天数。
- **通知中心**：Webhook、Telegram、Bark、ntfy、Gotify、Pushover、Discord、Slack、Server酱、PushPlus、企业微信、钉钉、飞书、邮件（SMTP）、命令；事件通配、静默去重、失败指数退避重试与补发队列。
- **计划任务**：5 段 cron，命令或 HTTP 请求，执行记录。
- **配置备份**：定时 JSON 备份、保留策略。
- **CLI**：`reset-password`、`reset-totp`、`rollback`、`backup`、`ctl`、`mcp`。

## 明确限制

- **HTTP/3、Passkey/WebAuthn 未实现**；Coraza/OWASP CRS 完整 SecLang 引擎、Docker/Web 终端/SFTP、WebDAV/FTP/SMB、网络诊断与 WoL 等上游模块尚未移植。
- DDNS 的 30+ 服务商采用**模板化 HTTP 适配**，部分私有签名的服务商需要填写 `options.endpoint` 自定义回调。
- WAF 是内置正则基线规则，不等同于 Coraza CRS v4。
- 配置热更新不完整：站点、规则、转发与分流立即生效；TLS 监听、管理员端口变更需重启。
- 封禁后端需要系统权限；无权限时仍保留内存封禁表。
- 配置中明文保存 API Token、TOTP secret 与 OIDC client secret，请设置文件权限（建议 `0600`）。
- 管理后台不应无防护地暴露到公网。

## 预编译二进制

Releases 页面提供三个平台的产物，均带 `.sha256` 校验文件：

| 平台 | 文件名 |
|---|---|
| Windows x86_64 | `gately-rs-v0.3.0-windows-x86_64.exe` |
| Linux x86_64 | `gately-rs-v0.3.0-linux-x86_64` |
| Linux ARM64 | `gately-rs-v0.3.0-linux-arm64` |

## 快速开始

```bash
cargo build --release
./target/release/gately-rs ./gately.json
```

- 管理后台：<http://127.0.0.1:16680/>
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

curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"id":"fw1","name":"ssh","enabled":true,"protocol":"tcp","listen":"0.0.0.0:2222","targets":["127.0.0.1:22"]}' \
  $BASE/api/port-forwards

curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"ip":"1.2.3.4","reason":"manual","secs":3600}' $BASE/api/jail/ban

curl -X POST -H "$AUTH" $BASE/api/tasks/task_1/run
curl -H "$AUTH" $BASE/api/openapi.json
```

主要接口分组：`/api/status`、`/api/config`、`/api/sites`、`/api/certs`、`/api/ddns`、`/api/acme`、`/api/waf`、`/api/jail`、`/api/tunnels`、`/api/stun`、`/api/port-forwards`、`/api/proto-routes`、`/api/site-users`、`/api/ip-lists`、`/api/notifications`、`/api/tasks`、`/api/backups`、`/api/metrics`、`/api/topology`、`/api/audit`、`/api/history`、`/api/import`。

## 许可与致谢

本项目使用 [Apache License 2.0](LICENSE)。上游 [Gately](https://github.com/wangwanjie/gately) 同样采用 Apache-2.0，详见 [NOTICE](NOTICE)。
