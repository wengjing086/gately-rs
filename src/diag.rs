//! 网络诊断模块：Ping、路由追踪、端口探测、DNS 查询、测速与局域网扫描。
//!
//! 所有诊断目标都受 `config.diag.allowed_targets` 白名单约束（支持 CIDR 与前缀通配，
//! 复用 `crate::waf::ip_match`），`config.diag.enabled == false` 时全部接口返回 403。

use crate::config::DiagConfig;
use crate::state::AppState;
use crate::waf::ip_match;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const DEFAULT_SPEEDTEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=10000000";
const MAX_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;
const SPEEDTEST_TIMEOUT_SECS: u64 = 30;
const MAX_SCAN_HOSTS: usize = 254;
const MAX_SCAN_PORTS: usize = 16;
const SCAN_CONCURRENCY: usize = 64;
const SCAN_PORT_TIMEOUT_MS: u64 = 1500;

// ---------------------------------------------------------------- 请求 / 响应结构

#[derive(Debug, Default, Deserialize)]
pub struct PingRequest {
    #[serde(default)]
    pub target: String,
}

#[derive(Debug, Serialize)]
pub struct PingResponse {
    pub target: String,
    pub sent: u32,
    pub received: u32,
    pub loss: f64,
    pub avg_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub output: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct TracerouteRequest {
    #[serde(default)]
    pub target: String,
}

#[derive(Debug, Serialize)]
pub struct TracerouteHop {
    pub hop: u32,
    pub ip: String,
    pub time_ms: f64,
    pub ttl: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct TracerouteResponse {
    pub target: String,
    pub hops: Vec<TracerouteHop>,
    pub output: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct PortRequest {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PortResponse {
    pub target: String,
    pub port: u16,
    pub open: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Default, Deserialize)]
pub struct DnsRequest {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub record: String,
}

#[derive(Debug, Serialize)]
pub struct DnsAnswer {
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct DnsResponse {
    pub name: String,
    pub record: String,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SpeedtestRequest {
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct SpeedtestResponse {
    pub bytes: u64,
    pub seconds: f64,
    pub mbps: f64,
    pub url: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    pub cidr: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Serialize)]
pub struct ScanHost {
    pub ip: String,
    pub open_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub cidr: String,
    pub hosts: Vec<ScanHost>,
}

// ---------------------------------------------------------------- 通用辅助

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn internal(msg: impl Into<String>) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, msg.into()).into_response()
}

fn forbidden(msg: impl Into<String>) -> Response {
    (StatusCode::FORBIDDEN, msg.into()).into_response()
}

fn ensure_enabled(cfg: &DiagConfig) -> Result<(), Response> {
    if cfg.enabled { Ok(()) } else { Err(forbidden("诊断功能已禁用（diag.enabled = false）")) }
}

/// 解析目标地址（支持域名），用于白名单校验。
async fn resolve_ips(host: &str, timeout: Duration) -> Vec<IpAddr> {
    match tokio::time::timeout(timeout, tokio::net::lookup_host((host, 0u16))).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => Vec::new(),
    }
}

/// 目标 IP 是否命中白名单；白名单为空表示允许一切。
fn target_allowed(cfg: &DiagConfig, ips: &[IpAddr]) -> bool {
    if cfg.allowed_targets.is_empty() { return true; }
    cfg.allowed_targets.iter().any(|pattern| ips.iter().any(|ip| ip_match(pattern, &ip.to_string())))
}

/// 网段是否整体落在白名单内（同时校验首尾地址）。
fn range_allowed(cfg: &DiagConfig, base: &str, last: &str) -> bool {
    if cfg.allowed_targets.is_empty() { return true; }
    cfg.allowed_targets.iter().any(|pattern| ip_match(pattern, base) && ip_match(pattern, last))
}

/// 从文本中取 label 之后的数字。
fn num_after(text: &str, label: &str) -> Option<f64> {
    let idx = text.find(label)? + label.len();
    let rest = &text[idx..];
    let bytes = rest.as_bytes();
    let mut end = 0;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') { end += 1; }
    rest[..end].parse::<f64>().ok()
}

/// 从文本中取 marker 之前的数字。
fn num_before(text: &str, marker: &str) -> Option<f64> {
    let idx = text.find(marker)?;
    let head = &text[..idx];
    let bytes = head.as_bytes();
    let mut end = head.len();
    while end > 0 {
        let c = bytes[end - 1];
        if c.is_ascii_digit() || c == b'.' { end -= 1; } else { break; }
    }
    head[end..].parse::<f64>().ok()
}

/// 校验目标是否可以安全地拼接到命令行，避免命令注入。
fn is_safe_target(target: &str) -> bool {
    if target.parse::<IpAddr>().is_ok() { return true; }
    let trimmed = target.strip_suffix('.').unwrap_or(target);
    !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// 校验 DNS 名称是否可以安全地拼接到命令行。
fn is_safe_dns_name(name: &str) -> bool {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let trimmed = trimmed.strip_prefix("*.").unwrap_or(trimmed);
    !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// 执行系统诊断命令。
///
/// Windows 下通过 `cmd` 先切换到 UTF-8 代码页：`ping`/`tracert`/`nslookup` 会据此
/// 输出英文 + UTF-8 文本，便于统一解析统计信息（默认代码页下它们输出的是本地化 GBK 文本）。
/// 所有参数均已做字符白名单校验，不会引入命令注入。
async fn run_tool(program: &str, args: &[String], timeout: Duration) -> Result<(String, String), String> {
    let output = if cfg!(windows) {
        let mut line = format!("chcp 65001 > nul && {program}");
        for arg in args {
            line.push(' ');
            line.push_str(arg);
        }
        Command::new("cmd").args(["/c", &line]).output().await
    } else {
        Command::new(program).args(args).output().await
    }
    .map_err(|err| format!("{program} 命令不可用：{err}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((stdout, stderr))
}

// ---------------------------------------------------------------- Ping

#[derive(Debug, Default)]
struct PingStat {
    sent: u32,
    received: u32,
    loss: f64,
    avg_ms: f64,
    min_ms: f64,
    max_ms: f64,
    /// 是否成功解析出统计信息（用于判断是否需要回退到 TCP 探测）。
    parsed: bool,
}

/// 解析 Windows `ping` 与 Linux `ping` 的统计输出。
fn parse_ping(text: &str, requested: u32) -> PingStat {
    let mut stat = PingStat { sent: requested, received: 0, loss: 100.0, ..Default::default() };

    let sent = num_after(text, "Sent = ").or_else(|| num_before(text, " packets transmitted")).map(|v| v as u32);
    if let Some(sent) = sent { stat.sent = sent; }

    let received = num_after(text, "Received = ").or_else(|| num_before(text, " received")).map(|v| v as u32);
    match received {
        Some(received) => stat.received = received,
        None => {
            // Windows 逐条回显："Reply from 1.1.1.1: bytes=32 time=11ms TTL=57"
            stat.received = text.lines().filter(|l| l.contains("time=")).count() as u32;
        }
    }
    stat.parsed = stat.sent > 0 && (received.is_some() || text.contains("time="));

    let parsed_loss = num_before(text, "% packet loss").or_else(|| num_before(text, "% loss"));
    stat.loss = match parsed_loss {
        Some(v) => v,
        None => {
            if stat.sent > 0 { (stat.sent.saturating_sub(stat.received) as f64) / stat.sent as f64 * 100.0 } else { 100.0 }
        }
    };

    // Linux: "rtt min/avg/max/mdev = 0.062/0.085/0.109/0.014 ms"
    if let Some(idx) = text.find("min/avg/max") {
        if let Some((_, tail)) = text[idx..].split_once('=') {
            let first = tail.split_whitespace().next().unwrap_or("");
            let parts: Vec<&str> = first.split('/').collect();
            if parts.len() >= 3 {
                stat.min_ms = parts[0].parse().unwrap_or(0.0);
                stat.avg_ms = parts[1].parse().unwrap_or(0.0);
                stat.max_ms = parts[2].parse().unwrap_or(0.0);
            }
        }
    }
    // Windows: "Minimum = 11ms, Maximum = 22ms, Average = 15ms"
    if let Some(v) = num_after(text, "Minimum = ") { stat.min_ms = v; }
    if let Some(v) = num_after(text, "Maximum = ") { stat.max_ms = v; }
    if let Some(v) = num_after(text, "Average = ") { stat.avg_ms = v; }

    stat
}

/// 调用系统 ping；命令缺失或输出无法解析时返回 Err，调用方回退到 TCP 探测。
async fn run_ping(target: &str, count: u32, cfg: &DiagConfig) -> Result<(PingStat, String), String> {
    let timeout_secs = cfg.timeout_secs.clamp(1, 60);
    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        ("ping", vec!["-n".into(), count.to_string(), "-w".into(), (timeout_secs * 1000).to_string(), target.to_string()])
    } else {
        ("ping", vec!["-c".into(), count.to_string(), "-W".into(), timeout_secs.to_string(), target.to_string()])
    };

    let (stdout, stderr) = run_tool(program, &args, Duration::from_secs(timeout_secs * count as u64 + 10)).await?;
    let text = format!("{stdout}{stderr}");
    let stat = parse_ping(&text, count);
    if !stat.parsed {
        return Err(text);
    }
    Ok((stat, text))
}

/// 系统 ping 不可用时的回退方案：TCP 连通性探测（80 端口，其次 443）。
async fn tcp_probe(target: &str, count: u32, timeout: Duration) -> (PingStat, String) {
    let mut stat = PingStat { sent: count, received: 0, loss: 100.0, ..Default::default() };
    let mut samples: Vec<f64> = Vec::new();
    let mut log = String::new();
    for _ in 0..count {
        let started = Instant::now();
        let mut connected = false;
        for port in [80u16, 443u16] {
            match tokio::time::timeout(timeout, TcpStream::connect((target, port))).await {
                Ok(Ok(_)) => { connected = true; break; }
                Ok(Err(_)) => {}
                Err(_) => {}
            }
        }
        if connected {
            stat.received += 1;
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            log.push_str("tcp connect ok\n");
        } else {
            log.push_str("tcp connect failed\n");
        }
    }
    if !samples.is_empty() {
        stat.min_ms = samples.iter().cloned().fold(f64::INFINITY, f64::min);
        stat.max_ms = samples.iter().cloned().fold(0.0f64, f64::max);
        stat.avg_ms = samples.iter().sum::<f64>() / samples.len() as f64;
        stat.loss = (stat.sent.saturating_sub(stat.received) as f64) / stat.sent.max(1) as f64 * 100.0;
    }
    (stat, log)
}

async fn ping_handler(State(state): State<AppState>, Json(request): Json<PingRequest>) -> Response {
    let cfg = state.config.read().await.diag.clone();
    if let Err(resp) = ensure_enabled(&cfg) { return resp; }

    let target = request.target.trim().to_string();
    if target.is_empty() { return bad_request("target 不能为空"); }
    if !is_safe_target(&target) { return bad_request("target 含非法字符"); }

    let timeout = Duration::from_secs(cfg.timeout_secs.clamp(1, 60));
    let ips = resolve_ips(&target, timeout).await;
    if !target_allowed(&cfg, &ips) {
        return forbidden(format!("目标 {target} 不在允许的诊断网段内"));
    }

    let count = cfg.ping_count.clamp(1, 20);
    let mut output = String::new();
    let stat = match run_ping(&target, count, &cfg).await {
        Ok((stat, text)) => { output.push_str(&text); stat }
        Err(text) => {
            output.push_str(&text);
            output.push('\n');
            output.push_str("系统 ping 不可用，已回退到 TCP 连通性探测\n");
            let (stat, log) = tcp_probe(&target, count, timeout).await;
            output.push_str(&log);
            stat
        }
    };

    Json(PingResponse {
        target,
        sent: stat.sent,
        received: stat.received,
        loss: stat.loss,
        avg_ms: stat.avg_ms,
        min_ms: stat.min_ms,
        max_ms: stat.max_ms,
        output,
    })
    .into_response()
}

// ---------------------------------------------------------------- Traceroute

/// 解析 `tracert -d` / `traceroute -n` 的逐跳输出。
fn parse_traceroute(text: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let mut parts = trimmed.split_whitespace();
        let hop = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
            Some(v) => v,
            None => continue,
        };
        let mut ip = String::new();
        let mut time_ms = 0.0f64;
        let mut found_time = false;
        for token in parts {
            if ip.is_empty() {
                let bare = token.trim_matches(|c| c == '(' || c == ')');
                if let Ok(addr) = bare.parse::<IpAddr>() {
                    ip = addr.to_string();
                    continue;
                }
            }
            let cleaned = token.trim_start_matches('<').trim_end_matches('>');
            if let Ok(value) = cleaned.parse::<f64>() {
                if !found_time { time_ms = value; found_time = true; }
            }
        }
        hops.push(TracerouteHop { hop, ip, time_ms, ttl: None });
    }
    hops
}

async fn traceroute_handler(State(state): State<AppState>, Json(request): Json<TracerouteRequest>) -> Response {
    let cfg = state.config.read().await.diag.clone();
    if let Err(resp) = ensure_enabled(&cfg) { return resp; }

    let target = request.target.trim().to_string();
    if target.is_empty() { return bad_request("target 不能为空"); }
    if !is_safe_target(&target) { return bad_request("target 含非法字符"); }

    let timeout = Duration::from_secs(cfg.timeout_secs.clamp(1, 60));
    let ips = resolve_ips(&target, timeout).await;
    if !target_allowed(&cfg, &ips) {
        return forbidden(format!("目标 {target} 不在允许的诊断网段内"));
    }

    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        ("tracert", vec!["-d".into(), "-h".into(), "20".into(), target.clone()])
    } else {
        ("traceroute", vec!["-n".into(), "-m".into(), "20".into(), target.clone()])
    };

    let (hops, output) = match run_tool(program, &args, Duration::from_secs(cfg.timeout_secs.clamp(10, 120))).await {
        Ok((stdout, stderr)) => {
            let text = format!("{stdout}{stderr}");
            (parse_traceroute(&text), text)
        }
        Err(err) => (Vec::new(), err),
    };

    Json(TracerouteResponse { target, hops, output }).into_response()
}

// ---------------------------------------------------------------- 端口探测

async fn probe_port(target: &str, port: u16, timeout: Duration) -> bool {
    matches!(tokio::time::timeout(timeout, TcpStream::connect((target, port))).await, Ok(Ok(_)))
}

async fn port_handler(State(state): State<AppState>, Json(request): Json<PortRequest>) -> Response {
    let cfg = state.config.read().await.diag.clone();
    if let Err(resp) = ensure_enabled(&cfg) { return resp; }

    let target = request.target.trim().to_string();
    if target.is_empty() { return bad_request("target 不能为空"); }
    if !is_safe_target(&target) { return bad_request("target 含非法字符"); }
    if request.port == 0 { return bad_request("port 必须是 1-65535 之间的有效端口"); }

    let timeout_ms = request.timeout_ms.unwrap_or(3000).clamp(100, 30_000);
    let ips = resolve_ips(&target, Duration::from_secs(cfg.timeout_secs.clamp(1, 60))).await;
    if !target_allowed(&cfg, &ips) {
        return forbidden(format!("目标 {target} 不在允许的诊断网段内"));
    }

    let started = Instant::now();
    let open = probe_port(&target, request.port, Duration::from_millis(timeout_ms)).await;
    Json(PortResponse {
        target,
        port: request.port,
        open,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
    .into_response()
}

// ---------------------------------------------------------------- DNS 查询

const DNS_RECORDS: [&str; 10] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA"];

/// 解析 Windows `nslookup` 的应答段。
fn parse_nslookup(text: &str) -> Vec<DnsAnswer> {
    let mut answers = Vec::new();
    let mut in_answer = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("server:") { in_answer = false; continue; }
        if lower.starts_with("name:") { in_answer = true; continue; }
        if lower.starts_with("non-authoritative") || lower.starts_with("authoritative") { in_answer = true; continue; }
        if !in_answer { continue; }
        if lower.starts_with("address:") || lower.starts_with("aliases:") {
            let value = trimmed.split_once(':').map(|(_, rest)| rest.trim()).unwrap_or_default().trim_end_matches('.').to_string();
            if !value.is_empty() { answers.push(DnsAnswer { value, ttl: None }); }
            continue;
        }
        if let Some(pos) = trimmed.find('=') {
            let value = trimmed[pos + 1..].trim().trim_end_matches('.').to_string();
            if !value.is_empty() { answers.push(DnsAnswer { value, ttl: None }); }
        }
    }
    answers
}

/// 解析 Linux `dig +short` 的输出（每行一条记录）。
fn parse_dig_short(text: &str) -> Vec<DnsAnswer> {
    text.lines()
        .map(|line| line.trim().trim_end_matches('.').to_string())
        .filter(|line| !line.is_empty())
        .map(|value| DnsAnswer { value, ttl: None })
        .collect()
}

/// 使用标准库解析（仅 A/AAAA）。
fn resolve_with_std(name: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    match (name, 0u16).to_socket_addrs() {
        Ok(iter) => iter.map(|addr| addr.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

async fn dns_handler(State(state): State<AppState>, Json(request): Json<DnsRequest>) -> Response {
    let cfg = state.config.read().await.diag.clone();
    if let Err(resp) = ensure_enabled(&cfg) { return resp; }

    let name = request.name.trim().to_string();
    if name.is_empty() { return bad_request("name 不能为空"); }
    if !is_safe_dns_name(&name) { return bad_request("name 含非法字符"); }

    let record = if request.record.trim().is_empty() { "A".to_string() } else { request.record.trim().to_ascii_uppercase() };
    if !DNS_RECORDS.contains(&record.as_str()) {
        return bad_request(format!("不支持的记录类型：{record}（支持 {}）", DNS_RECORDS.join("/")));
    }

    let timeout = Duration::from_secs(cfg.timeout_secs.clamp(1, 60));
    let ips = resolve_ips(&name, timeout).await;
    if !cfg.allowed_targets.is_empty() {
        if ips.is_empty() {
            return forbidden(format!("无法解析目标 {name}，无法校验白名单"));
        }
        if !target_allowed(&cfg, &ips) {
            return forbidden(format!("目标 {name} 不在允许的诊断网段内"));
        }
    }

    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        ("nslookup", vec![format!("-type={record}"), name.clone()])
    } else {
        ("dig", vec!["+short".into(), name.clone(), record.clone()])
    };

    let mut answers: Vec<DnsAnswer> = Vec::new();
    match run_tool(program, &args, timeout).await {
        Ok((stdout, stderr)) => {
            let text = format!("{stdout}{stderr}");
            answers = if cfg!(windows) { parse_nslookup(&text) } else { parse_dig_short(&text) };
        }
        Err(_) => {}
    }

    if answers.is_empty() && (record == "A" || record == "AAAA") {
        let target = name.clone();
        let resolved = tokio::task::spawn_blocking(move || resolve_with_std(&target)).await.unwrap_or_default();
        answers = resolved
            .into_iter()
            .filter(|ip| match record.as_str() {
                "A" => ip.is_ipv4(),
                _ => ip.is_ipv6(),
            })
            .map(|ip| DnsAnswer { value: ip.to_string(), ttl: None })
            .collect();
    }

    if answers.is_empty() {
        return bad_request(format!("DNS 查询失败：{name} 无 {record} 记录"));
    }

    Json(DnsResponse { name, record, answers }).into_response()
}

// ---------------------------------------------------------------- 测速

async fn speedtest_handler(State(state): State<AppState>, Json(request): Json<SpeedtestRequest>) -> Response {
    let cfg = state.config.read().await.diag.clone();
    if let Err(resp) = ensure_enabled(&cfg) { return resp; }

    let url = if request.url.trim().is_empty() { DEFAULT_SPEEDTEST_URL.to_string() } else { request.url.trim().to_string() };
    let parsed = match reqwest::Url::parse(&url) {
        Ok(url) => url,
        Err(err) => return bad_request(format!("无效的下载 URL：{err}")),
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return bad_request("下载 URL 仅支持 http/https");
    }

    let host = parsed.host_str().unwrap_or_default().to_string();
    let ips = resolve_ips(&host, Duration::from_secs(cfg.timeout_secs.clamp(1, 60))).await;
    if !target_allowed(&cfg, &ips) {
        return forbidden(format!("下载目标 {host} 不在允许的诊断网段内"));
    }

    let mut response = match state.client.get(&url).send().await {
        Ok(response) => response,
        Err(err) => return internal(format!("下载失败：{err}")),
    };
    if !response.status().is_success() {
        return internal(format!("下载失败：HTTP {}", response.status()));
    }

    let started = Instant::now();
    let mut bytes: u64 = 0;
    let outcome = tokio::time::timeout(Duration::from_secs(SPEEDTEST_TIMEOUT_SECS), async {
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    bytes += chunk.len() as u64;
                    if bytes >= MAX_DOWNLOAD_BYTES { break; }
                }
                Ok(None) => break,
                Err(err) => return Err(err),
            }
        }
        Ok::<(), reqwest::Error>(())
    })
    .await;

    match outcome {
        Err(_) => return internal(format!("测速超时（超过 {SPEEDTEST_TIMEOUT_SECS}s）")),
        Ok(Err(err)) => return internal(format!("下载失败：{err}")),
        Ok(Ok(())) => {}
    }

    let seconds = started.elapsed().as_secs_f64().max(0.0001);
    let mbps = bytes as f64 * 8.0 / seconds / 1_000_000.0;
    Json(SpeedtestResponse { bytes, seconds, mbps, url }).into_response()
}

// ---------------------------------------------------------------- 局域网扫描

/// 解析 CIDR，返回（网络地址, 前缀长度, 主机地址列表）。
fn parse_cidr(spec: &str) -> Result<(Ipv4Addr, u8, Vec<Ipv4Addr>), String> {
    let (addr_part, prefix_part) = match spec.trim().split_once('/') {
        Some((addr, prefix)) => (addr, prefix),
        None => (spec.trim(), "32"),
    };
    let base: Ipv4Addr = addr_part.parse().map_err(|_| format!("无效的 CIDR：{spec}"))?;
    let prefix: u32 = prefix_part.trim().parse().map_err(|_| format!("无效的 CIDR 前缀：{spec}"))?;
    if prefix > 32 { return Err(format!("无效的 CIDR 前缀：{prefix}")); }

    let size: u64 = 1u64 << (32 - prefix);
    let network = ((u32::from(base) as u64) & !(size - 1)) as u32;
    let count = if prefix >= 31 { size } else { size - 2 };
    if count as usize > MAX_SCAN_HOSTS {
        return Err(format!("扫描范围过大（{count} 个地址），最多支持 {MAX_SCAN_HOSTS} 个地址"));
    }

    let offset = if prefix >= 31 { 0 } else { 1 };
    let mut hosts = Vec::with_capacity(count as usize);
    for i in 0..count {
        let ip = network + i as u32 + offset;
        hosts.push(Ipv4Addr::from(ip));
    }
    Ok((Ipv4Addr::from(network), prefix as u8, hosts))
}

/// 使用系统 ping 做单包存活探测（等价 ICMP echo）。
async fn ping_alive(ip: &str) -> bool {
    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        ("ping", vec!["-n".into(), "1".into(), "-w".into(), "1000".into(), ip.to_string()])
    } else {
        ("ping", vec!["-c".into(), "1".into(), "-W".into(), "1".into(), ip.to_string()])
    };
    match run_tool(program, &args, Duration::from_secs(3)).await {
        Ok((stdout, _)) => stdout.contains("TTL=") || stdout.contains("ttl=") || stdout.contains("bytes from") || stdout.contains("来自"),
        Err(_) => false,
    }
}

/// 反向解析主机名（可选信息）。
async fn reverse_lookup(ip: &str) -> Option<String> {
    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        ("nslookup", vec![ip.to_string()])
    } else {
        ("dig", vec!["-x".into(), ip.to_string(), "+short".into()])
    };
    let (stdout, _) = run_tool(program, &args, Duration::from_secs(3)).await.ok()?;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if let Some(rest) = trimmed.strip_prefix("Name:") {
            let name = rest.trim().trim_end_matches('.').to_string();
            if !name.is_empty() { return Some(name); }
            continue;
        }
        if trimmed.starts_with("Server:") || trimmed.starts_with("Address:") { continue; }
        let name = trimmed.trim_end_matches('.').to_string();
        if !name.is_empty() && !name.contains(' ') { return Some(name); }
    }
    None
}

async fn scan_handler(State(state): State<AppState>, Json(request): Json<ScanRequest>) -> Response {
    let cfg = state.config.read().await.diag.clone();
    if let Err(resp) = ensure_enabled(&cfg) { return resp; }

    let cidr = request.cidr.trim().to_string();
    if cidr.is_empty() { return bad_request("cidr 不能为空"); }
    let (base, _prefix, hosts) = match parse_cidr(&cidr) {
        Ok(parsed) => parsed,
        Err(err) => return bad_request(err),
    };
    let last = hosts.last().copied().unwrap_or(base);
    if !range_allowed(&cfg, &base.to_string(), &last.to_string()) {
        return forbidden(format!("扫描网段 {cidr} 不在允许的诊断网段内"));
    }

    let mut ports: Vec<u16> = request
        .ports
        .iter()
        .copied()
        .filter(|port| *port > 0)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    ports.sort_unstable();
    ports.truncate(MAX_SCAN_PORTS);

    let semaphore = std::sync::Arc::new(Semaphore::new(SCAN_CONCURRENCY));

    if ports.is_empty() {
        // 仅做主机存活探测；无 ICMP（系统 ping）能力时跳过。
        let mut probes = JoinSet::new();
        for host in hosts {
            let permit = semaphore.clone().acquire_owned().await.ok();
            let ip = host.to_string();
            probes.spawn(async move {
                let _permit = permit;
                let alive = ping_alive(&ip).await;
                (ip, alive)
            });
        }
        let mut alive = Vec::new();
        while let Some(joined) = probes.join_next().await {
            if let Ok((ip, ok)) = joined {
                if ok { alive.push(ScanHost { ip, open_ports: Vec::new(), name: None }); }
            }
        }
        alive.sort_by(|a, b| a.ip.cmp(&b.ip));
        return Json(ScanResponse { cidr, hosts: alive }).into_response();
    }

    let mut set = JoinSet::new();
    for host in hosts {
        let permit = semaphore.clone().acquire_owned().await.ok();
        let ip = host.to_string();
        let ports = ports.clone();
        set.spawn(async move {
            let _permit = permit;
            let mut open = Vec::new();
            for port in ports {
                if probe_port(&ip, port, Duration::from_millis(SCAN_PORT_TIMEOUT_MS)).await {
                    open.push(port);
                }
            }
            (ip, open)
        });
    }

    let mut responsive = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((ip, open)) = joined {
            if !open.is_empty() { responsive.push(ScanHost { ip, open_ports: open, name: None }); }
        }
    }
    responsive.sort_by(|a, b| a.ip.cmp(&b.ip));

    // 反查主机名（可选）。
    if !responsive.is_empty() {
        let semaphore = std::sync::Arc::new(Semaphore::new(8));
        let mut names = JoinSet::new();
        for host in responsive.iter() {
            let permit = semaphore.clone().acquire_owned().await.ok();
            let ip = host.ip.clone();
            names.spawn(async move {
                let _permit = permit;
                let name = reverse_lookup(&ip).await;
                (ip, name)
            });
        }
        let mut resolved: HashMap<String, Option<String>> = HashMap::new();
        while let Some(joined) = names.join_next().await {
            if let Ok((ip, name)) = joined { resolved.insert(ip, name); }
        }
        for host in responsive.iter_mut() {
            if let Some(name) = resolved.get(&host.ip).cloned().flatten() { host.name = Some(name); }
        }
    }

    Json(ScanResponse { cidr, hosts: responsive }).into_response()
}

// ---------------------------------------------------------------- 路由

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/diag/ping", post(ping_handler))
        .route("/diag/traceroute", post(traceroute_handler))
        .route("/diag/port", post(port_handler))
        .route("/diag/dns", post(dns_handler))
        .route("/diag/speedtest", post(speedtest_handler))
        .route("/diag/scan", post(scan_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_windows_ping() {
        let out = "\r\nPinging 1.1.1.1 [1.1.1.1] with 32 bytes of data:\r\n\
Reply from 1.1.1.1: bytes=32 time=11ms TTL=57\r\n\
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57\r\n\r\n\
Ping statistics for 1.1.1.1:\r\n\
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\n\
    Approximate round trip times in milli-seconds:\r\n\
        Minimum = 11ms, Maximum = 12ms, Average = 11ms\r\n";
        let s = parse_ping(out, 2);
        assert_eq!(s.sent, 2);
        assert_eq!(s.received, 2);
        assert!((s.loss - 0.0).abs() < 0.01, "loss={}", s.loss);
        assert!((s.min_ms - 11.0).abs() < 0.01, "min={}", s.min_ms);
        assert!((s.max_ms - 12.0).abs() < 0.01, "max={}", s.max_ms);
        assert!((s.avg_ms - 11.0).abs() < 0.01, "avg={}", s.avg_ms);
        assert!(s.parsed);
    }

    #[test]
    fn parse_linux_ping() {
        let out = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.5 ms\n\
--- 1.1.1.1 ping statistics ---\n\
2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n\
rtt min/avg/max/mdev = 10.400/10.950/11.500/0.550 ms\n";
        let s = parse_ping(out, 2);
        assert_eq!(s.sent, 2);
        assert_eq!(s.received, 2);
        assert!((s.loss - 0.0).abs() < 0.01, "loss={}", s.loss);
        assert!((s.min_ms - 10.4).abs() < 0.01, "min={}", s.min_ms);
        assert!((s.avg_ms - 10.95).abs() < 0.01, "avg={}", s.avg_ms);
        assert!((s.max_ms - 11.5).abs() < 0.01, "max={}", s.max_ms);
        assert!(s.parsed);
    }

    #[test]
    fn parse_ping_partial_loss() {
        let out = "Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),\r\n\
    Minimum = 5ms, Maximum = 9ms, Average = 7ms\r\n";
        let s = parse_ping(out, 4);
        assert_eq!(s.sent, 4);
        assert_eq!(s.received, 2);
        assert!((s.loss - 50.0).abs() < 0.01, "loss={}", s.loss);
    }

    #[test]
    fn parse_cidr_ranges() {
        let (base, prefix, hosts) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(base.to_string(), "192.168.1.0");
        assert_eq!(prefix, 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0].to_string(), "192.168.1.1");
        assert_eq!(hosts[253].to_string(), "192.168.1.254");

        let (_, _, hosts) = parse_cidr("10.0.0.5/30").unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].to_string(), "10.0.0.5");
        assert_eq!(hosts[1].to_string(), "10.0.0.6");

        let (_, _, hosts) = parse_cidr("10.0.0.7/32").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].to_string(), "10.0.0.7");

        assert!(parse_cidr("192.168.0.0/16").is_err());
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("192.168.1.0/33").is_err());
    }

    #[test]
    fn parse_traceroute_windows_and_linux() {
        let win = "  1     <1 ms    <1 ms    <1 ms  192.168.1.1\r\n  2     10 ms     9 ms     9 ms  10.0.0.1\r\n";
        let hops = parse_traceroute(win);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[0].ip, "192.168.1.1");
        assert_eq!(hops[1].ip, "10.0.0.1");
        assert!((hops[1].time_ms - 10.0).abs() < 0.01);

        let linux = " 1  192.168.1.1 (192.168.1.1)  0.352 ms  0.256 ms  0.221 ms\n 2  10.0.0.1 (10.0.0.1)  12.345 ms  11.2 ms  10.1 ms\n";
        let hops = parse_traceroute(linux);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].ip, "192.168.1.1");
        assert!((hops[1].time_ms - 12.345).abs() < 0.001, "t={}", hops[1].time_ms);
    }

    #[test]
    fn parse_nslookup_and_dig() {
        let ns = "Server:  8.8.8.8\nAddress:  8.8.8.8\n\nNon-authoritative answer:\nName:\texample.com\nAddress: 93.184.216.34\n";
        let a = parse_nslookup(ns);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].value, "93.184.216.34");

        let dig = "93.184.216.34\n";
        let d = parse_dig_short(dig);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].value, "93.184.216.34");
    }

    #[test]
    fn ip_match_whitelist() {
        let cfg = DiagConfig { ping_count: 4, timeout_secs: 10, allowed_targets: vec!["192.168.1.0/24".into()], enabled: true };
        assert!(target_allowed(&cfg, &[IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10))]));
        assert!(!target_allowed(&cfg, &[IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))]));
        assert!(range_allowed(&cfg, "192.168.1.1", "192.168.1.254"));

        let empty = DiagConfig { allowed_targets: vec![], ..cfg.clone() };
        assert!(target_allowed(&empty, &[IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))]));
    }

    #[test]
    fn rejects_shell_metacharacters() {
        assert!(is_safe_target("1.1.1.1"));
        assert!(is_safe_target("example.com"));
        assert!(is_safe_target("::1"));
        assert!(!is_safe_target("1.1.1.1 & calc.exe"));
        assert!(!is_safe_target("a;rm -rf /"));
        assert!(!is_safe_target("$(whoami)"));
        assert!(!is_safe_target("a|b"));
        assert!(!is_safe_target(""));
        assert!(is_safe_dns_name("example.com"));
        assert!(!is_safe_dns_name("ex ample.com"));
        assert!(!is_safe_dns_name("a&b.com"));
    }
}
