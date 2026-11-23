# gately-rs

用 Rust 编写的边缘网关 **MVP**，借鉴了 [Gately](https://github.com/wangwanjie/gately) 的功能设计，但是一个**独立的重新实现**。

> 非官方项目，与上游 Gately 无隶属关系；当前功能远未达到上游同等水平，请勿直接暴露到公网。

## 已实现

- **配置层**：明文 JSON，首次启动自动生成，API 修改后落盘（临时文件 + 原子改名）。
- **管理后台**：内嵌单页 Web UI，登录鉴权，status / config / sites / certs / ddns API。
- **反向代理**：按 Host 精确匹配（支持 `*`），可限制监听器，动态增删站点立即生效。
- **TLS**：rustls 加载静态 PEM 证书，可为监听器指定证书。
- **DDNS**：Cloudflare A/AAAA 记录更新，IP 来源支持静态值或 URL；定时轮询 + 手动执行 + 错误状态记录。
- **配置重载**：`/api/config/reload` 从磁盘重新读取配置。

## 尚未实现

ACME 自动签发/续期、WAF、入侵防护与 nftables 封禁、STUN 穿透、隧道托管（frp/Tailscale 等）、Lucky `.lkcf` 导入、配置 diff/回滚、OIDC/Passkey、HTTP/3、WebSocket 透传。

认证目前是**明文密码 + 静态 token**，仅适合本地或受信任内网环境。

## 快速开始

```bash
cargo build --release
./target/release/gately-rs ./gately.json
```

- 管理后台：<http://127.0.0.1:16680/>
- 默认密码：`gately.cn`
- 默认 token：`dev-token-change-me`
- 默认代理监听：`0.0.0.0:18080`

**首次登录后请立即修改密码和 token。** 配置文件里会明文保存 Cloudflare API Token，请设置文件权限（建议 `0600`）并不要提交到版本库。

### Windows (GNU 工具链)

默认 MSVC 工具链需要 Visual Studio 的 `link.exe`；如果没有，可安装 MinGW-w64 并把 `bin` 目录加入 PATH：

```bash
cargo +stable-x86_64-pc-windows-gnu build --target x86_64-pc-windows-gnu
```

## API 示例

```bash
BASE=http://127.0.0.1:16680

# 登录，拿到 token
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"password":"gately.cn"}' $BASE/api/login | jq -r .token)

# 添加站点：localhost -> 本地 3000 端口
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domains":["localhost"],"backend":"http://127.0.0.1:3000","listener":null}' \
  $BASE/api/sites

# 验证代理
curl -H 'Host: localhost' http://127.0.0.1:18080/
```

## 配置结构

```json
{
  "admin": { "listen": "0.0.0.0:16680", "password": "CHANGE_ME", "token": "CHANGE_ME" },
  "listeners": [
    { "name": "http", "listen": "0.0.0.0:18080", "tls_cert": null }
  ],
  "sites": [
    { "id": "site_1", "domains": ["example.com"], "backend": "http://127.0.0.1:3000", "listener": null }
  ],
  "certificates": [
    { "id": "default", "cert_path": "/path/cert.pem", "key_path": "/path/key.pem" }
  ],
  "ddns": []
}
```

`tls_cert` 填证书 ID；证书增删后需要重启程序才会重新创建 TLS 监听。

## 目录结构

```
src/config.rs   配置模型与持久化
src/state.rs    共享状态
src/proxy.rs    反向代理
src/ddns.rs     Cloudflare DDNS
src/admin.rs    管理 API
src/ui.html     内嵌管理页
```

## 许可与致谢

本项目使用 [Apache License 2.0](LICENSE)。上游 [Gately](https://github.com/wangwanjie/gately) 同样采用 Apache-2.0，详见 [NOTICE](NOTICE)。
