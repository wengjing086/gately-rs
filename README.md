# gately-rs

用 Rust 编写的边缘网关，借鉴 [Gately](https://github.com/wangwanjie/gately) 的功能设计，是一个**独立的重新实现**。

> 非官方项目，与上游 Gately 无隶属关系。v0.2.0 已补齐配置历史、ACME、WAF、封禁、STUN、隧道托管、TOTP/OIDC 和 WebSocket，但仍是**内网可用的 MVP**，不建议无防护地直接暴露到公网。

## 已实现功能

### 核心
- **配置**：明文 JSON，首次启动自动生成；每次修改前自动快照（保留最近 50 份），支持 diff、查看历史与一键回滚。
- **管理后台**：内嵌单页 Web UI + 登录鉴权 + 完整 REST API。
- **反向代理**：按 Host 精确匹配（支持 `*`），可绑定监听器；动态增删立即生效；支持 WebSocket 透传（终止后端握手，仅转发原始帧）。
- **TLS**：rustls 加载静态 PEM 证书，可为监听器指定证书。

### 安全
- **ACME**：`instant-acme` 实现 HTTP-01 自动签发与续期（Let's Encrypt / ZeroSSL / 自定义目录），80 端口内置挑战服务，证书与私钥自动落盘。
- **WAF**：按站点启用的正则规则引擎，支持 path/query/user_agent/header/body 目标、detect/block 模式、按规则集引用；IP 黑白名单支持精确值、通配前缀和 CIDR。
- **入侵防护**：fail2ban 式日志扫描，按失败次数/时间窗封禁 IP，可写入 nftables 或 iptables（默认 `none`，需自行开启并确保权限）。
- **认证**：密码 + 静态 token；可选 TOTP 二步验证（RFC 6238，±1 步容错）；OIDC Authorization Code + PKCE，支持 userinfo 获取身份与用户白名单。

### 网络与运维
- **DDNS**：Cloudflare A/AAAA 记录更新，IP 来源支持静态值或 URL，URL 可引用 `{STUN_任务ID_ADDR}` / `{STUN_任务ID_PORT}`；定时轮询 + 手动执行 + 错误状态记录。
- **STUN**：RFC 5389 绑定请求，解析 XOR-MAPPED-ADDRESS，定期探测公网 IP/端口。
- **隧道托管**：以子进程方式启动/监控 frpc、frps、cloudflared 等外部二进制，支持自动重启、环境变量、工作目录和状态 API。
- **迁移导入**：接受 JSON 备份、Lucky `.lkcf` 明文 JSON 或整站 ZIP 备份，启发式映射站点/DDNS/证书/隧道/STUN；导入的规则默认停用，重复导入按 ID 跳过。

## 明确限制

- **HTTP/3 未实现**：当前仅 HTTP/1.1 反代（含 WebSocket）。
- **Passkey / WebAuthn 未实现**：OIDC 可用，但没有无密码通行密钥。
- **WAF 不是 Coraza/OWASP CRS**：是内置正则规则引擎，规则需自行维护。
- **DDNS 仅 Cloudflare**：没有 libdns 式的 30+ 服务商适配。
- **Lucky 加密 `.lkcf` 无法解析**：只识别其中明文 JSON 部分；上游的字段映射远多于这里的启发式规则。
- **配置热更新不完整**：站点/规则改动立即生效；TLS 监听、管理员端口变更需重启。
- **封禁后端需系统权限**：nftables/iptables 命令在非 root 环境会失败并保留内存封禁表。
- **OIDC 不校验 ID Token 签名**：通过 userinfo 端点验证 access token，仅适合受信任的 IdP。

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

**首次登录后请立即修改密码和 token。** 配置文件会明文保存 Cloudflare API Token、TOTP secret 和 OIDC client secret，请设置文件权限（建议 `0600`）并不要提交到版本库。

### Windows (GNU 工具链)

默认 MSVC 工具链需要 Visual Studio 的 `link.exe`；如果没有，安装 MinGW-w64 并把 `bin` 目录加入 PATH：

```bash
cargo +stable-x86_64-pc-windows-gnu build --target x86_64-pc-windows-gnu
```

## API 示例

```bash
BASE=http://127.0.0.1:16680
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"password":"gately.cn"}' $BASE/api/login | jq -r .token)
AUTH="Authorization: Bearer $TOKEN"

# 添加站点
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"domains":["localhost"],"backend":"http://127.0.0.1:3000","listener":null}' $BASE/api/sites

# 验证代理
curl -H 'Host: localhost' http://127.0.0.1:18080/

# 配置历史与回滚
curl -H "$AUTH" $BASE/api/history
curl -H "$AUTH" $BASE/api/history/{id}/diff
curl -X POST -H "$AUTH" $BASE/api/history/{id}/rollback

# 触发 ACME 签发
curl -X POST -H "$AUTH" $BASE/api/acme/{id}/run

# 导入 Lucky / JSON / ZIP
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"paths":["/path/lucky_reverseproxy.lkcf"],"keep_enabled":false}' $BASE/api/import
```

主要接口分组：`/api/status`、`/api/config`、`/api/sites`、`/api/certs`、`/api/ddns`、`/api/acme`、`/api/waf/rules`、`/api/waf/profiles`、`/api/jail`、`/api/tunnels`、`/api/stun`、`/api/auth`、`/api/history`、`/api/import`。

## 目录结构

```
src/config.rs      配置模型与持久化
src/state.rs       共享运行时状态
src/proxy.rs       HTTP / WebSocket 反向代理
src/waf.rs         WAF、IP 过滤、fail2ban
src/acme.rs        ACME HTTP-01 签发与续期
src/ddns.rs        Cloudflare DDNS
src/stun.rs        STUN 公网地址探测
src/tunnel.rs      外部隧道进程托管
src/auth_ext.rs    TOTP 与 OIDC
src/history.rs     配置快照 / diff
src/migrate.rs     Lucky / JSON / ZIP 导入
src/admin.rs       管理 API
src/ui.html        内嵌管理页
```

## 许可与致谢

本项目使用 [Apache License 2.0](LICENSE)。上游 [Gately](https://github.com/wangwanjie/gately) 同样采用 Apache-2.0，详见 [NOTICE](NOTICE)。
