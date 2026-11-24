//! 端口敲门 SPA（Single Packet Authentication，单包认证）模块。
//!
//! # 协议设计（自研 SPA，**与 fwknop 报文格式不兼容**）
//!
//! 一次敲门 = 一个 HTTP 请求（`POST /api/knock/{rule_id}`），请求体里带一个 base64 载荷。
//! 载荷的构造与校验流程：
//!
//! 1. **明文** `plaintext = u64 时间戳(大端, 8 字节) || 16 字节随机 nonce || 身份标识(UTF-8)`
//!    - 时间戳为 Unix 秒级时间戳，用于校验时间窗；
//!    - nonce 为 16 字节随机数（客户端可用 UUID v4），用于防重放；
//!    - 身份标识允许为空串，由调用方在请求体 `identity` 字段中补充。
//! 2. **加密**：`AES-256-CFB128`，密钥为规则里的 `aes_key`（base64，解码后必须 32 字节）。
//!    - CFB128 需要 IV，而载荷格式里没有单独的 IV 字段，因此 IV 由密钥材料确定性派生：
//!      `IV = SHA-256("gately-knock-iv-v1" || aes_key || hmac_key)[0..16]`，
//!      客户端与服务端用同一对密钥即可算出相同 IV，无需额外传参。
//!    - 注：`ctr` crate 只提供 CTR 变体、没有 CFB，故此处基于 `aes::Aes256` 的分组加密原语
//!      自行实现 CFB128（与标准 CFB128 字节级一致）。
//! 3. **完整性**：对**密文**计算 `HMAC-SHA256(hmac_key, ciphertext)`，取前 16 字节追加在
//!    密文之后（Encrypt-then-MAC：先验签、再解密）。
//! 4. **载荷**：`payload = base64(ciphertext || hmac[0..16])`。
//!
//! 服务端校验顺序：规则存在 → 功能/规则启用 → 解析请求体 → 定位来源地址 →
//! base64 解码 → 长度检查 → HMAC 校验（常量时间比较）→ AES 解密 → 解析时间戳/nonce/身份 →
//! 时间窗校验 → nonce 防重放 → 身份一致性与白名单 → single_address 独占检查 → 写入授权。
//!
//! # 与 fwknop 的差异
//!
//! | 维度 | fwknop | 本模块（自研 SPA） |
//! |---|---|---|
//! | 传输层 | UDP 单包（端口 62201/62202） | HTTP(S) `POST /api/knock/{rule_id}` |
//! | 加密 | AES-256-CFB，**每包随机 IV 且随包传输** | AES-256-CFB128，IV 由密钥材料派生（不随包传输） |
//! | 完整性 | HMAC-SHA1 摘要 | HMAC-SHA256 截断 16 字节，覆盖密文 |
//! | 身份 | 客户端 IP 白名单 | 规则内 `identities` 白名单（明文身份 + 请求体身份需一致） |
//! | 时间窗 | `--time-stamp` 等开关，默认 30s | 统一 `knock.window_secs`（默认 30s，允许时钟偏移） |
//! | 防重放 | 依赖时间戳 + 本地 nonce 表 | 16 字节 nonce + 进程内 10 分钟重放缓存 |
//! | 授权结果 | 直接改写防火墙规则 | 写入进程内授权表 `knock_grants`，再由后台循环同步防火墙 |
//!
//! 即：**报文格式与 fwknop 不兼容**，不能直接使用 fwknop 客户端；fwknop 客户端请继续走原版流程。
//!
//! # 与其它模块的联动
//!
//! - 授权写入 `AppState::knock_grants`，站点（`site_ext`）、端口转发（`portforward`）、
//!   协议分流（`protoroute`）中的 `knock_required` 判定直接读取该表；
//! - `spawn_knock_loop` 定时清理过期授权，并把有效授权同步到系统防火墙
//!   （`nftables` / `iptables` / `ipset`，命令失败只打印日志，不影响授权本身）。

use crate::config::{Config, KnockConfig, KnockRule};
use crate::history;
use crate::state::{AppState, KnockGrant};
use crate::waf::ip_match;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration as StdDuration, Instant};
use tokio::process::Command;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// nonce 长度（字节）
const NONCE_LEN: usize = 16;
/// HMAC 截断长度（字节）
const MAC_LEN: usize = 16;
/// 时间戳长度（字节）
const TS_LEN: usize = 8;
/// 重放缓存保留时长（秒）：最近 10 分钟
const SEEN_TTL_SECS: u64 = 600;
/// 后台清理 / 防火墙同步周期（秒）
const LOOP_INTERVAL_SECS: u64 = 5;

/// 已使用过的 nonce（防重放），值为首次使用时刻。
static SEEN: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

/// 防火墙放行状态：已下发到系统防火墙的规则。
static FIREWALL: OnceLock<tokio::sync::Mutex<FirewallState>> = OnceLock::new();

// ---------------------------------------------------------------------------
// 请求 / 内部结构
// ---------------------------------------------------------------------------

/// 敲门请求体。
#[derive(Debug, Deserialize)]
pub struct KnockRequest {
    /// base64 编码的敲门载荷
    #[serde(default)]
    pub payload: String,
    /// 身份标识（可选）
    #[serde(default)]
    pub identity: Option<String>,
    /// 来源地址（可选，默认取 x-forwarded-for 请求头）
    #[serde(default)]
    pub ip: Option<String>,
}

/// 一条已放行授权在防火墙侧的状态。
#[derive(Clone, Debug, PartialEq)]
struct Applied {
    rule_id: String,
    ports: Vec<u16>,
}

/// 防火墙放行状态：记录已经下发到系统防火墙的规则，便于精确撤销。
#[derive(Default)]
struct FirewallState {
    applied: HashMap<String, Applied>,
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

fn bad_request(msg: impl std::fmt::Display) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

fn forbidden(msg: impl std::fmt::Display) -> Response {
    (StatusCode::FORBIDDEN, msg.to_string()).into_response()
}

fn not_found(msg: impl std::fmt::Display) -> Response {
    (StatusCode::NOT_FOUND, msg.to_string()).into_response()
}

fn internal(msg: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()).into_response()
}

/// base64 解码，兼容标准 / 无填充 / URL-safe 变体。
fn b64_decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    let engines = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    for engine in engines {
        if let Ok(bytes) = engine.decode(value) {
            return Ok(bytes);
        }
    }
    Err("载荷不是合法的 base64 编码".to_string())
}

/// base64 编码（标准字母表，带填充）。
fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 常量时间比较，避免签名被旁路计时攻击。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 解析来源地址：只接受合法的 IP 字面量（防止非法值进入防火墙命令）。
fn parse_ip(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("来源地址为空".to_string());
    }
    match IpAddr::from_str(value) {
        Ok(ip) => Ok(ip.to_string()),
        Err(_) => Err(format!("来源地址不是合法的 IP 地址: {value}")),
    }
}

/// 从请求头解析来源地址（x-forwarded-for 取第一段，其次 x-real-ip）。
fn peer_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = forwarded.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let first = real.trim();
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 加解密
// ---------------------------------------------------------------------------

/// 由密钥材料派生 CFB 的初始向量：SHA-256("gately-knock-iv-v1" || aes_key || hmac_key)[0..16]。
///
/// 载荷格式里没有单独的 IV 字段，客户端与服务端用同一对密钥即可算出相同 IV。
fn derive_iv(aes_key: &[u8], hmac_key: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"gately-knock-iv-v1");
    hasher.update(aes_key);
    hasher.update(hmac_key);
    let digest = hasher.finalize();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&digest[..16]);
    iv
}

/// 计算 HMAC-SHA256 的前 16 字节。
fn mac16(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| "HMAC 密钥不能为空".to_string())?;
    mac.update(data);
    Ok(mac.finalize().into_bytes()[..MAC_LEN].to_vec())
}

/// AES-256-CFB128 加密（CFB 是流式模式，明文与密文等长）。
///
/// 基于 `aes::Aes256` 的分组加密原语自行实现（`ctr` crate 只有 CTR 变体）。
/// CFB128 的反馈方式是**密文分组**：第 0 块的密钥流来自 `E(IV)`，之后每一块都以
/// 上一块的**密文**作为新的反馈输入。
fn cfb128_encrypt(aes_key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<(), String> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

    if aes_key.len() != 32 {
        return Err(format!(
            "AES 密钥必须是 32 字节，当前为 {} 字节",
            aes_key.len()
        ));
    }
    let cipher = aes::Aes256::new_from_slice(aes_key)
        .map_err(|_| "AES 密钥长度非法，必须是 32 字节".to_string())?;
    let mut feedback = *iv;
    for chunk in data.chunks_mut(16) {
        // 密钥流 = E(feedback)
        let mut stream = GenericArray::clone_from_slice(&feedback);
        cipher.encrypt_block(&mut stream);
        for (byte, key_byte) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key_byte;
        }
        // 反馈取**输出密文**分组
        let mut next = [0u8; 16];
        next[..chunk.len()].copy_from_slice(chunk);
        feedback = next;
    }
    Ok(())
}

/// AES-256-CFB128 解密（与 `cfb128_encrypt` 严格互逆）。
fn cfb128_decrypt(aes_key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<(), String> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

    if aes_key.len() != 32 {
        return Err(format!(
            "AES 密钥必须是 32 字节，当前为 {} 字节",
            aes_key.len()
        ));
    }
    let cipher = aes::Aes256::new_from_slice(aes_key)
        .map_err(|_| "AES 密钥长度非法，必须是 32 字节".to_string())?;
    let mut feedback = *iv;
    for chunk in data.chunks_mut(16) {
        // 密钥流 = E(feedback)
        let mut stream = GenericArray::clone_from_slice(&feedback);
        cipher.encrypt_block(&mut stream);
        // 反馈取**输入密文**分组（解密时输入即密文）
        let mut next = [0u8; 16];
        next[..chunk.len()].copy_from_slice(chunk);
        for (byte, key_byte) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key_byte;
        }
        feedback = next;
    }
    Ok(())
}

/// 解密后的明文内容。
struct PlainPayload {
    timestamp: u64,
    nonce: Vec<u8>,
    identity: String,
}

/// 解析解密后的明文：`时间戳(8) || nonce(16) || 身份标识`。
fn parse_plain(plain: &[u8]) -> Result<PlainPayload, String> {
    if plain.len() < TS_LEN + NONCE_LEN {
        return Err("载荷明文长度不足".to_string());
    }
    let mut ts_bytes = [0u8; TS_LEN];
    ts_bytes.copy_from_slice(&plain[..TS_LEN]);
    let timestamp = u64::from_be_bytes(ts_bytes);
    let nonce = plain[TS_LEN..TS_LEN + NONCE_LEN].to_vec();
    let identity = String::from_utf8_lossy(&plain[TS_LEN + NONCE_LEN..]).to_string();
    Ok(PlainPayload {
        timestamp,
        nonce,
        identity,
    })
}

/// 生成测试用敲门载荷（base64）。
///
/// 与服务端使用完全一致的协议：明文 = 时间戳 || nonce || 身份标识（本函数身份为空），
/// AES-256-CFB128 加密后拼接 HMAC-SHA256 前 16 字节。
pub fn spawn_payload(aes_key_b64: &str, hmac_key_b64: &str) -> Result<String, String> {
    let aes_key = b64_decode(aes_key_b64)?;
    if aes_key.len() != 32 {
        return Err(format!(
            "AES 密钥必须是 32 字节，当前为 {} 字节",
            aes_key.len()
        ));
    }
    let hmac_key = b64_decode(hmac_key_b64)?;
    if hmac_key.is_empty() {
        return Err("HMAC 密钥不能为空".to_string());
    }

    let timestamp = Utc::now().timestamp().max(0) as u64;
    let nonce = Uuid::new_v4();
    let mut plain = Vec::with_capacity(TS_LEN + NONCE_LEN);
    plain.extend_from_slice(&timestamp.to_be_bytes());
    plain.extend_from_slice(nonce.as_bytes());

    let iv = derive_iv(&aes_key, &hmac_key);
    let mut ciphertext = plain;
    cfb128_encrypt(&aes_key, &iv, &mut ciphertext)?;

    let tag = mac16(&hmac_key, &ciphertext)?;
    ciphertext.extend_from_slice(&tag);
    Ok(b64_encode(&ciphertext))
}

// ---------------------------------------------------------------------------
// 防重放
// ---------------------------------------------------------------------------

fn seen_cache() -> MutexGuard<'static, HashMap<String, Instant>> {
    match SEEN.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// 判断 nonce 是否已经用过；未用过则登记，返回 true 表示重放。
fn nonce_replayed(nonce: &[u8]) -> bool {
    let key = b64_encode(nonce);
    let mut cache = seen_cache();
    let now = Instant::now();
    // 只保留最近 10 分钟的记录
    cache.retain(|_, at| {
        now.checked_duration_since(*at)
            .map(|elapsed| elapsed < StdDuration::from_secs(SEEN_TTL_SECS))
            .unwrap_or(false)
    });
    if cache.contains_key(&key) {
        return true;
    }
    cache.insert(key, now);
    false
}

// ---------------------------------------------------------------------------
// 防火墙同步
// ---------------------------------------------------------------------------

/// 执行防火墙命令；失败只打印日志，不影响授权本身。
async fn run_firewall(program: &str, args: &[String]) -> bool {
    let output = match Command::new(program).args(args).output().await {
        Ok(output) => output,
        Err(err) => {
            eprintln!("[knock] 防火墙命令执行失败: {program} {} ({err})", args.join(" "));
            return false;
        }
    };
    if output.status.success() {
        return true;
    }
    eprintln!(
        "[knock] 防火墙命令返回失败: {program} {} -> {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    false
}

/// 端口列表渲染为 nft 的集合语法：`{ 80, 443 }`。
fn nft_ports(ports: &[u16]) -> String {
    let list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {list} }}")
}

/// nft 规则里的地址族关键字。
fn nft_family(ip: &str) -> &'static str {
    if ip.contains(':') { "ip6" } else { "ip" }
}

/// ipset 集合名：优先用 nft_chain，其次 gately_knock（KnockConfig 没有独立的 ipset 名字段）。
fn ipset_name(cfg: &KnockConfig) -> String {
    if cfg.nft_chain.trim().is_empty() {
        "gately_knock".to_string()
    } else {
        cfg.nft_chain.trim().to_string()
    }
}

/// 确保 nft 表与链存在（best effort，失败只打印日志）。
async fn ensure_nft_chain(cfg: &KnockConfig) {
    let table = cfg.nft_table.trim();
    if table.is_empty() {
        return;
    }
    let _ = run_firewall(
        "nft",
        &[
            "add".into(),
            "table".into(),
            "inet".into(),
            table.to_string(),
        ],
    )
    .await;
    // 敲门链挂在 input hook 的更靠前位置（priority -10），让 accept 先于封禁链生效
    let chain = format!(
        "{} {{ type filter hook input priority -10 ; }}",
        cfg.nft_chain.trim()
    );
    let _ = run_firewall(
        "nft",
        &[
            "add".into(),
            "chain".into(),
            "inet".into(),
            table.to_string(),
            chain,
        ],
    )
    .await;
}

/// 构造"放行"命令；None 表示该后端无需（或无法）下发。
fn allow_command(cfg: &KnockConfig, rule: &KnockRule, ip: &str) -> Option<(String, Vec<String>)> {
    let backend = cfg.backend.trim().to_lowercase();
    match backend.as_str() {
        "nftables" | "nft" => {
            if rule.ports.is_empty() {
                return None;
            }
            Some((
                "nft".to_string(),
                vec![
                    "add".into(),
                    "rule".into(),
                    "inet".into(),
                    cfg.nft_table.clone(),
                    cfg.nft_chain.clone(),
                    nft_family(ip).into(),
                    "saddr".into(),
                    ip.to_string(),
                    "tcp".into(),
                    "dport".into(),
                    nft_ports(&rule.ports),
                    "accept".into(),
                ],
            ))
        }
        "iptables" => {
            if rule.ports.is_empty() {
                return None;
            }
            let program = if ip.contains(':') { "ip6tables" } else { "iptables" };
            let mut args = vec![
                "-I".to_string(),
                "INPUT".to_string(),
                "-s".to_string(),
                ip.to_string(),
                "-p".to_string(),
                "tcp".to_string(),
            ];
            if rule.ports.len() == 1 {
                args.push("--dport".into());
                args.push(rule.ports[0].to_string());
            } else {
                // 多个端口需要 multiport 扩展
                args.push("-m".into());
                args.push("multiport".into());
                args.push("--dports".into());
                args.push(
                    rule.ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            args.push("-j".into());
            args.push("ACCEPT".into());
            Some((program.to_string(), args))
        }
        "ipset" => Some((
            "ipset".to_string(),
            vec![
                "add".into(),
                ipset_name(cfg),
                ip.to_string(),
                "-exist".into(),
            ],
        )),
        _ => None,
    }
}

/// 构造"撤销"命令。
///
/// nft 后端无法按规则内容可靠地删除单条规则（需要 rule handle），因此 nft 走
/// "整链重建"路径，不使用这里的撤销命令；iptables / ipset 支持精确撤销。
fn revoke_command(cfg: &KnockConfig, rule: &KnockRule, ip: &str) -> Option<(String, Vec<String>)> {
    let backend = cfg.backend.trim().to_lowercase();
    match backend.as_str() {
        "iptables" => {
            if rule.ports.is_empty() {
                return None;
            }
            let program = if ip.contains(':') { "ip6tables" } else { "iptables" };
            let mut args = vec![
                "-D".to_string(),
                "INPUT".to_string(),
                "-s".to_string(),
                ip.to_string(),
                "-p".to_string(),
                "tcp".to_string(),
            ];
            if rule.ports.len() == 1 {
                args.push("--dport".into());
                args.push(rule.ports[0].to_string());
            } else {
                args.push("-m".into());
                args.push("multiport".into());
                args.push("--dports".into());
                args.push(
                    rule.ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            args.push("-j".into());
            args.push("ACCEPT".into());
            Some((program.to_string(), args))
        }
        "ipset" => Some((
            "ipset".to_string(),
            vec![
                "del".into(),
                ipset_name(cfg),
                ip.to_string(),
                "-exist".into(),
            ],
        )),
        _ => None,
    }
}

/// 当前有效授权应当对应的防火墙放行集合：IP -> (规则, 端口)。
async fn desired_grants(state: &AppState, cfg: &KnockConfig) -> HashMap<String, Applied> {
    let now = Utc::now();
    let grants = state.knock_grants.read().await;
    let mut desired = HashMap::new();
    for grant in grants.values() {
        if grant.until <= now {
            continue;
        }
        let rule = match cfg.rules.iter().find(|rule| rule.id == grant.rule_id) {
            Some(rule) => rule,
            None => continue,
        };
        desired.insert(
            grant.ip.clone(),
            Applied {
                rule_id: rule.id.clone(),
                ports: rule.ports.clone(),
            },
        );
    }
    desired
}

/// 同步系统防火墙：新增缺失的放行规则，撤销已经失效的放行规则。
///
/// 整个过程串行化（由 FIREWALL 互斥锁保护），避免后台循环与敲门请求并发下发重复规则。
async fn sync_firewall(state: &AppState) {
    let cfg = { state.config.read().await.knock.clone() };
    let backend = cfg.backend.trim().to_lowercase();
    if backend.is_empty() || backend == "none" {
        return;
    }

    let mut fw = FIREWALL
        .get_or_init(|| tokio::sync::Mutex::new(FirewallState::default()))
        .lock()
        .await;

    // 功能关闭时不保留任何放行
    let desired = if cfg.enabled {
        desired_grants(state, &cfg).await
    } else {
        HashMap::new()
    };

    // 需要撤销的：已放行但不再有效（或端口发生变化）
    let stale: Vec<(String, Applied)> = fw
        .applied
        .iter()
        .filter(|(ip, entry)| desired.get(*ip) != Some(*entry))
        .map(|(ip, entry)| (ip.clone(), entry.clone()))
        .collect();
    // 需要新增的：有效但尚未放行
    let missing: Vec<(String, Applied)> = desired
        .iter()
        .filter(|(ip, entry)| fw.applied.get(*ip) != Some(*entry))
        .map(|(ip, entry)| (ip.clone(), entry.clone()))
        .collect();
    if stale.is_empty() && missing.is_empty() {
        return;
    }

    if backend == "nftables" || backend == "nft" {
        // nft 无法按内容删除单条规则，改为整链重建，保证不残留已过期地址
        ensure_nft_chain(&cfg).await;
        let flushed = run_firewall(
            "nft",
            &[
                "flush".into(),
                "chain".into(),
                "inet".into(),
                cfg.nft_table.clone(),
                cfg.nft_chain.clone(),
            ],
        )
        .await;
        let mut ok = flushed;
        for (ip, entry) in &desired {
            let rule = match cfg.rules.iter().find(|rule| rule.id == entry.rule_id) {
                Some(rule) => rule,
                None => continue,
            };
            if let Some((program, args)) = allow_command(&cfg, rule, ip) {
                ok = run_firewall(&program, &args).await && ok;
            }
        }
        // 下发成功才记录状态，失败则下一轮重试
        if ok {
            fw.applied = desired;
        }
        return;
    }

    // iptables / ipset：先撤销失效的旧规则，再放行新增的
    for (ip, entry) in &stale {
        let rule = match cfg.rules.iter().find(|rule| rule.id == entry.rule_id) {
            Some(rule) => rule,
            None => continue,
        };
        if let Some((program, args)) = revoke_command(&cfg, rule, ip) {
            if run_firewall(&program, &args).await {
                fw.applied.remove(ip);
            }
        } else {
            fw.applied.remove(ip);
        }
    }
    for (ip, entry) in &missing {
        let rule = match cfg.rules.iter().find(|rule| rule.id == entry.rule_id) {
            Some(rule) => rule,
            None => continue,
        };
        if backend == "ipset" {
            // ipset 需要先把集合建出来
            let _ = run_firewall(
                "ipset",
                &[
                    "create".into(),
                    ipset_name(&cfg),
                    "hash:ip".into(),
                    "-exist".into(),
                ],
            )
            .await;
        }
        if let Some((program, args)) = allow_command(&cfg, rule, ip) {
            if run_firewall(&program, &args).await {
                fw.applied.insert(ip.clone(), entry.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 配置持久化
// ---------------------------------------------------------------------------

/// 保存配置前先对旧版本做一次快照（与 `crate::admin` 的 persist 写法保持一致）。
fn persist(state: &AppState, config: &Config) -> Result<(), String> {
    if let Ok(text) = std::fs::read_to_string(&state.config_path) {
        let _ = history::snapshot(&state.config_path, &text);
    }
    config.save(&state.config_path)
}

// ---------------------------------------------------------------------------
// 授权查询
// ---------------------------------------------------------------------------

/// 判断某个地址当前是否处于放行状态（授权存在且未过期）。
pub async fn is_granted(state: &AppState, ip: &str) -> bool {
    let now = Utc::now();
    let grants = state.knock_grants.read().await;
    grants
        .values()
        .any(|grant| grant.until > now && ip_match(&grant.ip, ip))
}

// ---------------------------------------------------------------------------
// 后台任务
// ---------------------------------------------------------------------------

/// 启动后台循环：每 5 秒清理过期授权并同步防火墙放行规则。
pub fn spawn_knock_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            // 1) 清理过期授权
            let now = Utc::now();
            let expired: Vec<String> = {
                let grants = state.knock_grants.read().await;
                grants
                    .iter()
                    .filter(|(_, grant)| grant.until <= now)
                    .map(|(ip, _)| ip.clone())
                    .collect()
            };
            if !expired.is_empty() {
                let mut grants = state.knock_grants.write().await;
                for ip in &expired {
                    grants.remove(ip);
                }
            }
            // 2) 同步防火墙
            sync_firewall(&state).await;
            tokio::time::sleep(StdDuration::from_secs(LOOP_INTERVAL_SECS)).await;
        }
    });
}

// ---------------------------------------------------------------------------
// HTTP 接口
// ---------------------------------------------------------------------------

/// 列出全部敲门规则。
async fn list_rules(State(state): State<AppState>) -> Response {
    let rules = { state.config.read().await.knock.rules.clone() };
    Json(rules).into_response()
}

/// 校验规则中的密钥配置（留空表示尚未配置，敲门时会给出明确错误）。
fn validate_rule_keys(rule: &KnockRule) -> Result<(), String> {
    if !rule.aes_key.trim().is_empty() {
        let key = b64_decode(&rule.aes_key)?;
        if key.len() != 32 {
            return Err(format!(
                "AES 密钥必须是 base64 编码的 32 字节，当前为 {} 字节",
                key.len()
            ));
        }
    }
    if !rule.hmac_key.trim().is_empty() && b64_decode(&rule.hmac_key)?.is_empty() {
        return Err("HMAC 密钥不能为空".to_string());
    }
    Ok(())
}

/// 新增或覆盖一条敲门规则，并落盘。
async fn create_rule(
    State(state): State<AppState>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let value = match body {
        Ok(Json(value)) => value,
        Err(rejection) => return bad_request(format!("请求体不是合法 JSON: {rejection}")),
    };
    let mut rule: KnockRule = match serde_json::from_value(value) {
        Ok(rule) => rule,
        Err(err) => return bad_request(format!("敲门规则格式错误: {err}")),
    };
    if rule.id.trim().is_empty() {
        rule.id = format!("knock_{}", Uuid::new_v4().simple());
    }
    if rule.name.trim().is_empty() {
        rule.name = rule.id.clone();
    }
    if let Err(err) = validate_rule_keys(&rule) {
        return bad_request(err);
    }

    let mut config = state.config.write().await;
    match config.knock.rules.iter_mut().find(|item| item.id == rule.id) {
        Some(existing) => *existing = rule.clone(),
        None => config.knock.rules.push(rule.clone()),
    }
    if let Err(err) = persist(&state, &config) {
        return internal(err);
    }
    Json(rule).into_response()
}

/// 删除一条敲门规则（同时撤销该规则签发的授权）。
async fn delete_rule(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    if !config.knock.rules.iter().any(|rule| rule.id == id) {
        return not_found(format!("敲门规则不存在: {id}"));
    }
    config.knock.rules.retain(|rule| rule.id != id);
    if let Err(err) = persist(&state, &config) {
        return internal(err);
    }
    drop(config);

    // 规则被删除后，其授权不再有效
    let mut grants = state.knock_grants.write().await;
    grants.retain(|_, grant| grant.rule_id != id);
    Json(json!({"ok": true, "id": id})).into_response()
}

/// 列出当前有效授权。
async fn list_grants(State(state): State<AppState>) -> Response {
    let now = Utc::now();
    let grants = state.knock_grants.read().await;
    let mut items: Vec<KnockGrant> = grants
        .values()
        .filter(|grant| grant.until > now)
        .cloned()
        .collect();
    items.sort_by(|a, b| a.ip.cmp(&b.ip));
    Json(items).into_response()
}

/// 撤销某个地址的授权。
async fn revoke_grant(State(state): State<AppState>, Path(ip): Path<String>) -> Response {
    let ip = match parse_ip(&ip) {
        Ok(ip) => ip,
        Err(err) => return bad_request(err),
    };
    let removed = {
        let mut grants = state.knock_grants.write().await;
        grants.remove(&ip)
    };
    if removed.is_none() {
        return not_found(format!("地址没有有效授权: {ip}"));
    }
    // 同步撤销防火墙放行
    sync_firewall(&state).await;
    Json(json!({"ok": true, "ip": ip})).into_response()
}

/// 处理一次敲门：校验载荷并写入授权。
async fn knock(
    State(state): State<AppState>,
    Path(rule_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let value = match body {
        Ok(Json(value)) => value,
        Err(rejection) => return bad_request(format!("请求体不是合法 JSON: {rejection}")),
    };
    let request: KnockRequest = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(err) => return bad_request(format!("敲门请求格式错误: {err}")),
    };
    if request.payload.trim().is_empty() {
        return bad_request("缺少 payload 字段");
    }

    let cfg = { state.config.read().await.knock.clone() };
    if !cfg.enabled {
        return forbidden("端口敲门功能未启用（config.knock.enabled = false）");
    }
    let rule = match cfg.rules.iter().find(|rule| rule.id == rule_id) {
        Some(rule) => rule.clone(),
        None => return not_found(format!("敲门规则不存在: {rule_id}")),
    };
    if !rule.enabled {
        return forbidden(format!("敲门规则已停用: {rule_id}"));
    }

    // 来源地址：请求体优先，其次 x-forwarded-for
    let raw_ip = match request.ip.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => value.to_string(),
        None => match peer_ip(&headers) {
            Some(value) => value,
            None => {
                return bad_request(
                    "无法确定来源地址，请提供 ip 字段或 x-forwarded-for 请求头",
                );
            }
        },
    };
    let ip = match parse_ip(&raw_ip) {
        Ok(ip) => ip,
        Err(err) => return bad_request(err),
    };

    // 载荷校验：base64 → 长度 → HMAC → 解密
    let raw = match b64_decode(&request.payload) {
        Ok(raw) => raw,
        Err(err) => return bad_request(err),
    };
    if raw.len() < TS_LEN + NONCE_LEN + MAC_LEN {
        return bad_request("载荷长度不足，无法解析");
    }
    let (ciphertext, tag) = raw.split_at(raw.len() - MAC_LEN);

    let aes_key = match b64_decode(&rule.aes_key) {
        Ok(key) if key.len() == 32 => key,
        Ok(key) => {
            return bad_request(format!(
                "规则 AES 密钥必须是 32 字节，当前为 {} 字节",
                key.len()
            ));
        }
        Err(err) => return bad_request(format!("规则 AES 密钥配置错误: {err}")),
    };
    let hmac_key = match b64_decode(&rule.hmac_key) {
        Ok(key) if !key.is_empty() => key,
        Ok(_) => return bad_request("规则未配置有效的 HMAC 密钥"),
        Err(err) => return bad_request(format!("规则 HMAC 密钥配置错误: {err}")),
    };

    let expected = match mac16(&hmac_key, ciphertext) {
        Ok(tag) => tag,
        Err(err) => return bad_request(err),
    };
    if !ct_eq(&expected, tag) {
        return forbidden("载荷签名校验失败");
    }

    let iv = derive_iv(&aes_key, &hmac_key);
    let mut plain = ciphertext.to_vec();
    if let Err(err) = cfb128_decrypt(&aes_key, &iv, &mut plain) {
        return bad_request(err);
    }
    let parsed = match parse_plain(&plain) {
        Ok(parsed) => parsed,
        Err(err) => return bad_request(err),
    };

    // 时间窗校验（允许时钟偏移）
    let now = Utc::now().timestamp().max(0) as u64;
    let drift = now.abs_diff(parsed.timestamp);
    if drift > cfg.window_secs {
        return forbidden(format!(
            "载荷时间戳超出允许窗口（±{} 秒）",
            cfg.window_secs
        ));
    }

    // 防重放：nonce 全局唯一，10 分钟内不允许重复使用
    if nonce_replayed(&parsed.nonce) {
        return forbidden("检测到重放攻击：该 nonce 已被使用");
    }

    // 身份一致性：明文身份与请求体身份必须一致
    let body_identity = request
        .identity
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !body_identity.is_empty()
        && !parsed.identity.is_empty()
        && body_identity != parsed.identity
    {
        return bad_request("请求体身份标识与载荷内身份标识不一致");
    }
    let identity = if !parsed.identity.is_empty() {
        parsed.identity.clone()
    } else {
        body_identity.clone()
    };
    // 规则身份白名单
    if !rule.identities.is_empty() && !rule.identities.contains(&identity) {
        return forbidden(format!("身份标识不在允许列表内: {identity}"));
    }

    // single_address：同一地址若已在其它规则下授权，则拒绝本次敲门
    {
        let grants = state.knock_grants.read().await;
        if let Some(existing) = grants.get(&ip) {
            if existing.rule_id != rule.id && rule.single_address {
                return forbidden(format!(
                    "地址 {ip} 已在其它敲门规则下授权（规则 {}），拒绝本次敲门",
                    existing.rule_id
                ));
            }
        }
    }

    // 写入授权
    let until: DateTime<Utc> = Utc::now() + Duration::seconds(cfg.grant_ttl_secs as i64);
    let grant = KnockGrant {
        ip: ip.clone(),
        rule_id: rule.id.clone(),
        identity: identity.clone(),
        until,
    };
    {
        let mut grants = state.knock_grants.write().await;
        grants.insert(ip.clone(), grant);
    }

    // 立即下发防火墙放行规则
    sync_firewall(&state).await;

    crate::metrics::audit(
        &state,
        &ip,
        "knock",
        &rule.id,
        &format!("敲门成功: {ip}"),
    )
    .await;
    crate::notify::emit(
        &state,
        "knock.granted",
        &format!("{ip} 通过规则 {} 敲门成功", rule.name),
    )
    .await;

    Json(json!({
        "ok": true,
        "ip": ip,
        "rule_id": rule.id,
        "identity": identity,
        "ports": rule.ports,
        "until": until,
    }))
    .into_response()
}

/// 生成某条规则的测试敲门载荷（管理员调试用）。
async fn make_payload(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let rule = {
        state
            .config
            .read()
            .await
            .knock
            .rules
            .iter()
            .find(|rule| rule.id == id)
            .cloned()
    };
    let Some(rule) = rule else {
        return not_found(format!("敲门规则不存在: {id}"));
    };
    match spawn_payload(&rule.aes_key, &rule.hmac_key) {
        Ok(payload) => Json(json!({ "payload": payload })).into_response(),
        Err(err) => bad_request(err),
    }
}

/// 组装敲门相关的 HTTP 路由。
///
/// 路由以 `/knock` 为前缀，由调用方合并进 `/api` 下，因此这里不再带 `/api` 前缀。
/// 后台通用编辑入口：整对象 PUT / 局部 PATCH 敲门规则。
async fn update_rule(
    State(state): State<AppState>,
    method: axum::http::Method,
    Path(id): Path<String>,
    Json(patch): Json<Value>,
) -> Response {
    crate::admin::apply_item(&state, "knock.rules", Some(&id), patch, method == axum::http::Method::PUT).await
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/knock/rules", get(list_rules).post(create_rule))
        .route("/knock/rules/{id}", axum::routing::put(update_rule).patch(update_rule).delete(delete_rule))
        .route("/knock/rules/{id}/payload", get(make_payload))
        .route("/knock/grants", get(list_grants))
        .route("/knock/grants/{ip}", delete(revoke_grant))
        .route("/knock/{rule_id}", post(knock))
}
