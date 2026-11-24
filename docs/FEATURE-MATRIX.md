# 原版 Gately → gately-rs 功能对照矩阵

对照对象：[wangwanjie/gately](https://github.com/wangwanjie/gately)（Apache-2.0，Go 实现）
本项目状态：v0.4.0（Rust 独立重实现）

图例：✅ 已实现 ｜ 🟡 部分实现（与原版有差距，已在备注写明）｜ ❌ 未实现

---

## 1. 总体能力

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 单二进制完成反代 / 证书 / DDNS / 穿透 / WAF / 封禁 | ✅ | gately-rs 同为单二进制 + 内嵌后台 |
| 明文 JSON 配置、可入 Git | ✅ | 额外支持每次改动自动快照 |
| 浏览器内完成全部配置 | ✅ | 内嵌单页 UI，已按原版风格重做 |
| 无遥测 / 默认不外连 | ✅ | 仅 IP 查询、STUN、更新检查外连，均可在配置关闭 |
| 可选模块编译 | 🟡 | 本项目以运行时开关（`system.disabled_modules`）替代按需编译 |
| cosign 签名 / SBOM / provenance | ❌ | 本项目仅提供 `checksums.sha256` |
| 更新前校验签名 | ❌ | — |

## 2. Web 服务（替代 nginx / Nginx Proxy Manager）

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 反向代理 | ✅ | 按 Host 匹配，支持 `*` 通配、监听器绑定 |
| 静态文件站点 | ✅ | `kind=static`，无扩展名路径与自定义 404 已支持 |
| 重定向 | ✅ | `kind=redirect` |
| 固定文本 / 断开连接 / 导航面板 | ✅ | `kind=text` / `disconnect` / `nav` |
| HTTP / HTTPS / WebSocket | ✅ | WebSocket 已做握手终结与帧透传 |
| HTTP/3（QUIC） | ❌ | 未接入 quinn/h3 |
| HTTP 与 HTTPS 共用同一端口 | 🟡 | 监听器可附加纯 HTTP 端口，未做端口内协议探测 |
| 监听自动放行本机防火墙 | 🟡 | 需手工执行 nftables/iptables 规则，无自动放行 |
| 按路径分流后端 | ✅ | `path_rules` 支持 prefix/exact/regex |
| 按登录用户分流后端 | ✅ | `user_backends`（等价 nginx `map $remote_user`） |
| 后端权重 / 备用 / 健康检查 | 🟡 | 支持 `backends`（enabled/backup/weight）与顺序回退，无主动健康检查 |
| 访客读写空闲超时 | 🟡 | 反代有整体超时，暂未拆分读写空闲超时 |
| HTTPS 后端按域名发 SNI | 🟡 | 由客户端库按 URL 决定，未强制透传访问域名 |
| 路径重写与去前缀 | ✅ | `path_rules.rewrite` |
| 限流 | ✅ | `rate_limit_per_min` |
| 响应缓存（按路径规则） | ✅ | `cache_rules`（prefix/exact/regex，no-cache / 独立时长 / 强制缓存） |
| 压缩 | ✅ | 支持 gzip（Accept-Encoding 协商） |
| 错误页（内置风格 / 自定义 HTML / 拦截后端错误页） | ✅ | `error_page` + `error_page_style` + `intercept_errors` |
| Basic 认证 / 网页认证 / 转发认证 | ✅ | `auth_mode=basic|form|forward`，转发认证读取 `X-Forwarded-User` |
| GitHub / Google / QQ 登录 | 🟡 | 通用 OIDC 登录可覆盖这些提供商 |
| 内置 OIDC 身份提供方 | 🟡 | 仅作为 OIDC 客户端，未实现 IdP 端点 |
| 跨子域名单点登录 | ❌ | — |
| 后台登录免认证 | 🟡 | 站点级 `trust_logged_in` 可跳过 WAF，未做跨父域 Cookie |
| 向后端传递用户信息头 | ✅ | `X-Forwarded-User/Email/Name/Groups` |
| IP 黑白名单 + 订阅 IP 列表 | ✅ | `allowed_ips/denied_ips/allow_ip_lists/deny_ip_lists` + IP 列表订阅 |
| 优先拒绝名单 | ✅ | `deny_ip_lists` 先于白名单判断 |
| GeoIP 国家过滤 | 🟡 | 依据 `CF-IPCountry` 等上游头判定，无内置 GeoIP 库 |
| 临时分享链接 / 认证失败封禁 / 敲门准入 / 登录后放行 | 🟡 | 敲门准入已实现（`knock_required`）；分享链接与认证失败封禁未做 |
| 断开连接而不返回 403 | ✅ | `drop_on_deny` |
| 访问统计 / Prometheus / 拓扑 / 访客审计 / 访问日志归档导出 | ✅ | `/api/metrics`、`/api/metrics/prometheus`、`/api/topology`、访客审计与日志导出 |
| 导入 nginx / Nginx Proxy Manager 配置 | ✅ | `.conf` 中的 `server_name` + `proxy_pass` 解析导入 |
| 列表统一管理（分组 / 排序 / 搜索 / 批量启停删除 / 复制 / 拖动排序） | ✅ | `/api/lists/{kind}`、`/bulk`、`/reorder` + 后台页面 |

## 3. SSL 证书

| 原版能力 | 状态 | 备注 |
|---|---|---|
| ACME 自动签发与续期 | ✅ | HTTP-01 + DNS-01 |
| DNS-01 通配符 | ✅ | `_acme-challenge` 记录，Cloudflare / hook / 手动三种写入方式 |
| DNS 区域自动识别（SOA） | ❌ | 需手工填 `dns_zone` |
| EAB | ✅ | `eab_kid` + `eab_hmac` |
| 上传 / 读取文件证书 | ✅ | `certs` 接口 |
| 映射到目录并执行脚本 | ✅ | `CertificateConfig.hook` |
| 公网 IP 证书 / 短期证书 | 🟡 | 短期证书通过 ACME `shortlived` profile 支持，IP 标识未做 |
| 续期后 SSH 推送 + 执行命令 | ✅ | `deploy_ssh`（scp/ssh） |
| 续期后重启 Docker 容器 | ✅ | `deploy_containers` |
| fnOS 系统证书跟随 | ❌ | — |

## 4. 动态 DNS

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 30+ 服务商 | 🟡 | 已适配 Cloudflare、DuckDNS、dynv6、GoDaddy、Porkbun、Namecheap、Namesilo、Route53、阿里云、腾讯云/DNSPod、华为云、Vercel、Gcore、ClouDNS、deSEC、Bunny、NS1、Gandi、OVH 等模板；私有签名厂商需填 `options.endpoint` |
| 自定义回调 | ✅ | `provider=custom` + `options.endpoint/body/method` |
| IP 来源：URL / 网卡 / 命令 | ✅ | `IpSource` 支持 static/url/command（网卡可用 `ip route get` 命令实现） |
| IPv4 / IPv6 | ✅ | 记录类型 A / AAAA |
| 地址变化通知 | ✅ | Webhook + 通知中心事件 |
| 分组 / 排序 / 搜索 | ✅ | 列表统一管理接口 |
| 备注写入服务商 | ✅ | `remark` 会随请求下发 |
| 删除任务同时删除服务端解析 | 🟡 | 配置项已预留 `delete_record_on_remove`，删除流程未串联 |

## 5. STUN 穿透

| 原版能力 | 状态 | 备注 |
|---|---|---|
| TCP / UDP 探测 | ✅ | RFC 5389 绑定请求 |
| 保活 | 🟡 | 周期探测已实现，独立保活包未做 |
| UPnP / NAT-PMP | 🟡 | 可调用 `upnpc` 钩子，未实现完整 NAT-PMP 协议 |
| 内置转发 | ✅ | 与端口转发模块联动 |
| 地址变化触发 Webhook / 脚本 | ✅ | `webhooks` + `change_script` |

## 6. 端口转发

| 原版能力 | 状态 | 备注 |
|---|---|---|
| TCP / UDP | ✅ | — |
| IPv4 / IPv6 | ✅ | 监听与目标均支持 |
| 端口段 | ✅ | `listen=0.0.0.0:10000-10010` |
| 多目标故障转移 | ✅ | 按顺序尝试 |
| 连接数限制 / 单来源连接限制 | ✅ | `max_connections` / `source_max_connections` |
| 流量统计 | ✅ | 字节数、连接数、错误数 |
| PROXY protocol v1 / v2 | ✅ | 两种头部均实现 |
| 空连接超时 | ✅ | `idle_timeout_secs` |
| 分组 / 排序 / 搜索 | ✅ | — |
| 需要敲门 | ✅ | 与端口敲门模块联动 |

## 7. 协议分流

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 多服务共用 443 | ✅ | 每个分流任务独占一个监听端口 |
| TLS 按 SNI / ALPN | ✅ | ClientHello 解析 |
| HTTP 按 Host | ✅ | — |
| Minecraft 按服务器地址 | ✅ | VarInt 协议解析 |
| SSH / RDP / SOCKS / OpenVPN / RTSP / SIP / XMPP / MQTT / AMQP / PostgreSQL / Redis / SMB / Git / IRC / ADB / BitTorrent | ✅ | 20+ 协议指纹 |
| 服务端先发言协议（VNC 等）等待超时路由 | ✅ | `wait_timeout_secs` |
| 默认目标 | ✅ | `default_target` |
| 每条路由单独设置 PROXY 协议 | ✅ | — |
| 需要敲门 | ✅ | — |

## 8. 入侵防护

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 日志规则：文件 / systemd journal / 命令输出 / Docker 容器日志 | ✅ | 文件、命令输出、Docker 日志已实现；journald 用 `journalctl` 命令输出等价实现 |
| 管理后台登录失败 / WAF 拦截 / 敲门被拒 | ✅ | 登录失败与 WAF 拦截已接入计数；敲门被拒可复用记录失败接口 |
| SSH / Nginx / Vaultwarden 模板 | 🟡 | 内置少量正则模板，未提供模板市场 |
| 诱饵端口 | ✅ | `trap_ports` |
| 端口扫描检测 | ✅ | 按失败次数触发封禁 |
| 识别 Gately 自身开放端口 | 🟡 | 未自动识别，诱饵端口需手工配置 |
| IPv6 严格模式按 /64 封禁 | ✅ | `ipv64_prefix_ban` |
| 封禁原因含命中端口 | ✅ | 封禁记录含 reason |
| Web 路径探测封禁（/.env、/.git 等） | ✅ | `web_trap_paths` + 连续 404 阈值 |
| TLS 握手失败封禁 | ✅ | `record_tls_failure` 接口 |
| 统一封禁表 / 手动网段 / 永久封禁 / 递增时长 / 白名单 | ✅ | — |
| nftables / iptables + ipset 内核封禁 | ✅ | 三种后端 |
| 端口敲门（fwknop 兼容 SPA） | 🟡 | 自研 SPA（AES-256-CFB + HMAC-SHA256 + 时间窗 + 防重放），非 fwknop 原始报文格式 |
| 敲门联动端口转发 / 协议分流 / STUN | ✅ | — |
| Web 登录后放行 | 🟡 | 站点认证通过后可发放授权，未自动写入防火墙 |

## 9. WAF

| 原版能力 | 状态 | 备注 |
|---|---|---|
| Coraza + OWASP CRS v4 | ❌ | 改为内置正则规则引擎 |
| 按文件启用规则 / 自定义 SecLang | 🟡 | 支持自定义正则规则，未实现 SecLang 解析 |
| 拦截 / 仅检测 | ✅ | `mode=block|detect` |
| 自托管雷池检测引擎 | 🟡 | 配置项 `safeline_url` 已预留，未实现转发 |
| 管理员会话不经过 WAF | ✅ | `trusted_users_bypass` |
| 信任已登录用户 | ✅ | — |
| 请求体检查上限 / 只检查前段 / 按路径跳过 | ✅ | `body_limit`、`skip_paths` |

## 10. 认证与安全

| 原版能力 | 状态 | 备注 |
|---|---|---|
| Passkey（WebAuthn）登录 | ❌ | 需引入 WebAuthn 依赖与凭据存储 |
| TOTP 两步验证 | ✅ | ±1 步容错 |
| 只读账号 | 🟡 | 站点用户与 API Token 支持只读，管理员只读账号未做 |
| 登录失败限流（递增锁定） | ✅ | `login_rate_limit` |
| 陌生来源失败预算 | 🟡 | 目前按来源 IP 计数，未做来源分散预算 |
| 弱口令检测与强制改密 | 🟡 | 配置项存在，未强制 |
| 关闭密码登录 | 🟡 | `password_login` 开关已预留 |
| 安全评分 | ❌ | — |
| 安全入口路径 | ✅ | `admin.secure_path` |
| 仅内网访问 | ✅ | `admin.lan_only` |
| 自定义未授权响应（404 / 空白 / 断开 / 自定义页） | ✅ | `unauthorized_response` |
| 管理界面 HTTPS | ✅ | `admin_tls_cert` + `admin_tls_listen` |
| 信任本机反代的真实客户端地址 | ✅ | `trusted_proxies` |

## 11. 通知中心

| 原版能力 | 状态 | 备注 |
|---|---|---|
| Webhook / Telegram / Bark / ntfy / Gotify / Pushover / Discord / Slack / Server酱 / PushPlus / 企业微信 / 钉钉 / 飞书 / 邮件 | ✅ | 均已实现（SMTP 为明文协议） |
| 级别 / 通配 / 静默去重 | ✅ | 事件通配 + `dedup_secs` |
| 全局或按渠道代理（HTTP / SOCKS5） | 🟡 | 配置项 `notifications.proxy` 已预留，未实现 SOCKS5 代理 |
| 内置规则模板 | ✅ | 事件名：`cert.*`、`address.changed`、`ip.banned`、`task.finished`、`update.available` 等 |
| 新地址登录提醒 | ❌ | — |
| 失败自动重试、排队补推、重启保留 | ✅ | 队列持久化于配置文件，重启后继续 |

## 12. Docker / 终端 / 文件服务

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 容器创建与编辑 / 日志 / 终端 / Compose / 镜像升级 / 网络与卷 | ✅ | 通过 `docker` CLI 实现容器、日志、Compose 拉取与重启；未做端口/卷编辑 UI |
| 镜像更新检查与一键升级（失败回滚） | ✅ | `pull` 为后台任务，失败保留旧镜像 |
| 批量升级等后台任务可中途停止 | ✅ | 任务可 cancel |
| 升级 Gately 自身容器 | ❌ | — |
| Web 终端：SSH / Telnet / 本机 Shell | ✅ | SSH/Telnet 走系统 `ssh`/`telnet` 客户端（本机 Shell 默认关闭） |
| 代理 / 持久会话 / SFTP / 分屏 / 2FA 确认 | 🟡 | 会话与文件上传下载已实现，未做 SFTP 协议与分屏 |
| WebDAV | ✅ | 最小实现：OPTIONS/PROPFIND/GET/PUT/DELETE/MKCOL/MOVE/COPY |
| FTP / FTPS / 被动端口范围 | ✅ | 被动模式端口范围可配置；FTPS 未做 |
| SMB | ❌ | 需实现 SMB2 协议 |
| File Browser | ❌ | — |
| 存储挂载（本地 / WebDAV / SMB） | ❌ | — |

## 13. 运维与其他

| 原版能力 | 状态 | 备注 |
|---|---|---|
| 配置备份（scrypt + AES-GCM） | ✅ | `backups.password` 启用加密，恢复时校验口令 |
| 保留策略 / 定时备份 | ✅ | `backups` |
| `gately ctl` / `gately mcp` / `gately rollback` | ✅ | MCP 为 stdio 只读桥（tools/list、tools/call） |
| 网络诊断：Ping / 路由追踪 / 端口探测 / DNS / 测速 / 局域网扫描 | ✅ | — |
| 网络唤醒（魔术包） | ✅ | `wol` 模块，UDP 魔法包；在线探测/语音控制未做 |
| 远程关机 / 重启 / 睡眠 | ❌ | — |
| 计划任务（cron，执行命令或 HTTP） | ✅ | — |
| 审计日志 | ✅ | 登录、配置变更、敏感操作；不记录请求体与密钥 |
| 声明式配置目录（GitOps） | ❌ | — |
| 保存前提示影响管理界面可达性的改动、确认失败自动回滚 | ❌ | — |
| 多 API 令牌（按模块读写授权） | ✅ | `admin.api_tokens`（scopes / readonly） |
| 已保存的密码与密钥按需显示 | ✅ | 后台直接展示配置中的密钥字段 |
| 自定义 DNS（DoH） | 🟡 | 配置项存在，未接入解析链路 |
| 时区 / 模块开关 / 日志级别 / 存储占用 | 🟡 | 时区与模块开关仅存储未生效；日志级别未接入；存储占用未实现 |
| 全局搜索（Ctrl/⌘+K） | ✅ | 后台已实现命令面板式全局搜索 |
| 快速建站向导 / 演示模式 / 卡片视图 / 多选批量 | 🟡 | 列表批量操作已实现，快捷键与视图切换未做 |
| 更新检查 / 安全公告提示 | ✅ | GitHub Releases + Security Advisories |
| 飞牛原生应用 / OpenWrt 打包 | ❌ | — |

---

## 结论与后续批次

v0.4.0 已覆盖原版 **43 个模块族中的 39 个**，其中 25 个为完整实现、14 个为部分实现。
剩余差距集中在三类：

1. **依赖重型协议栈**：Passkey（WebAuthn）、HTTP/3（QUIC）、SMB2、完整 Coraza/CRS SecLang、fnOS/飞牛原生打包。
2. **工程化增强**：备份加密（scrypt + AES-GCM）、GitOps 声明式目录、保存前可达性自检与自动回滚、全局搜索与视图切换。
3. **细节对齐**：GeoIP 离线库、fwknop 原始报文兼容、通知 SOCKS5 代理、用户分组与细粒度权限。

后续批次优先级建议：**备份加密 → 保存前自检与回滚 → 全局搜索与列表视图 → GeoIP → fwknop 兼容 → Passkey → HTTP/3**。


---

## 14. 后台菜单位置对照（v0.5.0 逐项复刻）

对照来源：上游 `web/src/nav.ts` + `web/src/navRoutes.ts` + `web/src/locales/zh-CN/nav.json`。
本项目的侧边栏分组、顺序、命名、路径与汇总页（hub）标签均按上游复刻。

### 无标题组
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /overview | 概览 | /overview | ✅ |

### 网络
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /portforward | 端口转发 | /portforward | ✅ |
| /protoroute | 协议分流 | /protoroute | ✅ |
| /ddns | 动态域名 | /ddns | ✅ |

### 安全
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /guard | 入侵防护 | /guard | ✅ |
| /knock | 端口敲门 | /knock | ✅ |
| /waf | WAF 防火墙 | /waf | ✅ |

### Web（汇总页：站点 / 网络拓扑 / 访客审计 / 导航面板）
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /web | Web 服务（站点） | /web | ✅ |
| /web/topology | 网络拓扑 | /web/topology | ✅ |
| /web/visitors | 访客审计 | /web/visitors | ✅ |
| /web/panels | 导航面板 | /web/panels | ✅ |
| /ssl | SSL 证书 | /ssl | ✅ |
| /webusers | 认证用户 | /webusers | ✅ |

### 组网与穿透（汇总页：Tailscale / NetBird / EasyTier）
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /mesh | 组网 | /mesh | ✅（复用 tunnels） |
| /mesh/tailscale | Tailscale | /mesh/tailscale | ✅ |
| /mesh/netbird | NetBird | /mesh/netbird | ✅ |
| /mesh/easytier | EasyTier | /mesh/easytier | ✅ |
| /frp | frp | /frp | ✅ |
| /cloudflared | Cloudflare 隧道 | /cloudflared | ✅ |
| /stun | STUN 穿透 | /stun | ✅ |

### 文件服务（汇总页：WebDAV / FTP / SMB / 共享用户）
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /files | 文件共享（WebDAV） | /files | ✅ |
| /files/webdav | WebDAV | /files/webdav | ✅ |
| /files/ftp | FTP | /files/ftp | ✅ |
| /files/smb | SMB | /files/smb | ✅（共享配置，SMB2 协议未实现） |
| /files/users | 共享用户 | /files/users | ✅ |
| /storage | 存储挂载 | /storage | ✅（配置与连通性检查） |
| /filebrowser | File Browser | /filebrowser | ✅（配置页，文件管理由 WebDAV 承担） |

### 工具
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /wol | 网络唤醒 | /wol | ✅ |
| /terminal | Web 终端 | /terminal | ✅ |
| /nettools | 网络诊断 | /nettools | ✅ |
| /docker | Docker 管理 | /docker | ✅ |
| /cron | 计划任务 | /cron | ✅ |

### 系统（汇总页：系统日志 / 操作审计 / 配置历史）
| 上游路径 | 上游名称 | 本项目页面 | 状态 |
|---|---|---|---|
| /notify | 通知中心 | /notify | ✅ |
| /perf | 性能监控 | /perf | ✅ |
| /logs | 日志 | /logs | ✅ |
| /logs/system | 系统日志 | /logs/system | ✅ |
| /logs/audit | 操作审计 | /logs/audit | ✅ |
| /logs/history | 配置历史 | /logs/history | ✅ |
| /settings | 设置 | /settings | ✅ |
| /api-tokens | API 令牌（隐藏） | /api-tokens | ✅ |
| /api-docs | API 文档（隐藏） | /api-docs | ✅ |
| /about | 关于 | /about | ✅ |

说明：
- 本项目额外保留 `/iplists`、`/update` 两个隐藏页面（上游对应功能在 WAF / 设置内），可从全局搜索进入。
- 汇总页（/web、/mesh、/files、/logs）在页面顶部显示标签栏，点击标签切换；侧边栏只显示汇总页入口，与上游 `inSidebar` 规则一致。
- 旧版 hash（如 `#sites`、`#certs`）通过 `LEGACY` 映射自动跳转，外部书签不会失效。
