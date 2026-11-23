use crate::config::{Config, JailConfig, SiteConfig, WafProfile};
use crate::state::{AppState, BanEntry};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;

#[derive(Debug)]
pub enum Decision { Allow, Log(String), Deny(String) }

fn ip_bytes(ip: &str) -> Option<Vec<u8>> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => Some(v.octets().to_vec()),
        IpAddr::V6(v) => Some(v.octets().to_vec()),
    }
}

pub fn ip_match(pattern: &str, ip: &str) -> bool {
    if pattern == ip { return true; }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return ip.starts_with(prefix);
    }
    if let Some((network, bits)) = pattern.split_once('/') {
        return (|| {
            let bits = bits.parse::<usize>().ok()?;
            let net = ip_bytes(network)?;
            let addr = ip_bytes(ip)?;
            if net.len() != addr.len() || bits > net.len() * 8 { return Some(false); }
            let full = bits / 8;
            let rest = bits % 8;
            if net[..full] != addr[..full] { return Some(false); }
            if rest == 0 { return Some(true); }
            let mask = 0xffu8 << (8 - rest);
            Some(net[full] & mask == addr[full] & mask)
        })().unwrap_or(false);
    }
    false
}

pub fn ip_match_list(list: &[String], ip: &str) -> bool { list.iter().any(|p| ip_match(p, ip)) }

fn target_value(target: &str, path: &str, query: &str, headers: &HashMap<String, String>, body: &str) -> String {
    match target {
        "query" => query.to_string(),
        "user_agent" => headers.get("user-agent").cloned().unwrap_or_default(),
        "header" => headers.values().cloned().collect::<Vec<_>>().join("\n"),
        "body" => body.to_string(),
        "cookie" => headers.get("cookie").cloned().unwrap_or_default(),
        "all" => format!("{path}\n{query}\n{}\n{body}", headers.values().cloned().collect::<Vec<_>>().join("\n")),
        _ => path.to_string(),
    }
}

fn builtin_rules() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("CRS-921-path-traversal", "(?:\\.\\./|%2e%2e%2f|\\.\\.\\\\)", "path"),
        ("CRS-930-xss", "(?i)<script|javascript:|onerror\\s*=", "all"),
        ("CRS-942-sqli", "(?i)(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\()", "all"),
        ("CRS-932-rce", "(?:;|\\|)\\s*(?:cat|wget|curl|bash|sh)\\b", "all"),
        ("CRS-913-scanner", "(?i)(sqlmap|nikto|acunetix|masscan|nmap|gobuster)", "user_agent"),
        ("CRS-922-sensitive-file", "(?i)/\\.(env|git|svn|htaccess|ssh|aws)", "path"),
    ]
}

pub async fn evaluate(
    config: &Config,
    site: &SiteConfig,
    path: &str,
    query: &str,
    headers: &HashMap<String, String>,
    body: &str,
    logged_in: bool,
    state: Option<&AppState>,
) -> Decision {
    let ip = client_ip(headers);
    if !site.denied_ips.is_empty() && ip_match_list(&site.denied_ips, &ip) { return Decision::Deny("ip denied".into()); }
    if !site.allowed_ips.is_empty() && !ip_match_list(&site.allowed_ips, &ip) { return Decision::Deny("ip not allowed".into()); }
    if let Some(s) = state {
        if !site.deny_ip_lists.is_empty() && list_hit(s, &site.deny_ip_lists, &ip).await {
            return Decision::Deny("ip list denied".into());
        }
        if !site.allow_ip_lists.is_empty() && !list_hit(s, &site.allow_ip_lists, &ip).await {
            return Decision::Deny("ip list not allowed".into());
        }
    }

    let mode = site.waf_mode.as_str();
    let profile_id = match &site.waf_profile { Some(id) => id.as_str(), None => return Decision::Allow };
    if mode == "off" { return Decision::Allow; }
    let profile: &WafProfile = match config.waf_profiles.iter().find(|p| &p.id == profile_id) {
        Some(p) => p, None => return Decision::Allow,
    };
    if profile.trusted_users_bypass && logged_in { return Decision::Allow; }
    if profile.skip_paths.iter().any(|p| path.starts_with(p)) { return Decision::Allow; }
    let effective = if profile.mode == "off" { mode } else { &profile.mode };
    if effective == "off" { return Decision::Allow; }
    let limit = if profile.body_limit > 0 { profile.body_limit } else { 256 * 1024 };
    let body = if body.len() > limit { &body[..limit] } else { body };

    let mut matches = Vec::new();
    for (id, pattern, target) in builtin_rules() {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&target_value(target, path, query, headers, body)) { matches.push(id.to_string()); }
        }
    }
    for rule in config.waf_rules.iter().filter(|r| r.enabled && profile.rule_ids.contains(&r.id)) {
        if let Ok(re) = Regex::new(&rule.pattern) {
            if re.is_match(&target_value(&rule.target, path, query, headers, body)) { matches.push(rule.id.clone()); }
        }
    }
    if matches.is_empty() { return Decision::Allow; }
    let msg = format!("waf: {}", matches.join(","));
    if effective == "detect" || matches.iter().any(|id| config.waf_rules.iter().find(|r| &r.id == id).is_some_and(|r| r.action == "log")) {
        Decision::Log(msg)
    } else { Decision::Deny(msg) }
}

async fn list_hit(state: &AppState, ids: &[String], ip: &str) -> bool {
    let cfg = state.config.read().await;
    ids.iter().any(|id| cfg.ip_lists.iter().find(|l| &l.id == id)
        .is_some_and(|l| l.entries.iter().any(|e| ip_match(e, ip))))
}

fn client_ip(headers: &HashMap<String, String>) -> String {
    headers.get("x-forwarded-for").and_then(|v| v.split(',').next())
        .or_else(|| headers.get("x-real-ip").map(|s| s.as_str()))
        .unwrap_or("").trim().to_string()
}

pub async fn is_banned(state: &AppState, ip: &str) -> bool {
    let mut bans = state.banned_ips.write().await;
    let now = Utc::now();
    bans.retain(|_, e| e.permanent || e.banned_until.map(|u| u > now).unwrap_or(true));
    bans.contains_key(ip) || bans.values().any(|e| e.permanent && ip_match_list(&[e.ip.clone()], ip))
}

async fn apply_ban(jail: &JailConfig, ip: &str, ban: bool) {
    if jail.backend == "none" || ip.is_empty() { return; }
    if !ip.contains(':') && ip.parse::<Ipv4Addr>().is_err() { return; }
    match jail.backend.as_str() {
        "nftables" => {
            let _ = Command::new("nft").args(["add", "table", "inet", &jail.nft_table]).stdout(Stdio::null()).stderr(Stdio::null()).status().await;
            let chain = format!("{} {{ type filter hook input priority 0 ; }}", jail.nft_chain);
            let _ = Command::new("nft").args(["add", "chain", "inet", &jail.nft_table, &chain]).stdout(Stdio::null()).stderr(Stdio::null()).status().await;
            if ban {
                let _ = Command::new("nft").args(["add", "rule", "inet", &jail.nft_table, &jail.nft_chain, "ip", "saddr", ip, "drop"])
                    .stdout(Stdio::null()).stderr(Stdio::null()).status().await;
            }
        }
        "ipset" => {
            let name = if jail.ipset_name.is_empty() { "gately_ban" } else { &jail.ipset_name };
            let _ = Command::new("ipset").args(["create", name, "hash:ip", "timeout", "86400", "-exist"]).stdout(Stdio::null()).stderr(Stdio::null()).status().await;
            let action = if ban { "add" } else { "del" };
            let _ = Command::new("ipset").args([action, name, ip, "-exist"]).stdout(Stdio::null()).stderr(Stdio::null()).status().await;
        }
        _ => {
            let action = if ban { "-I" } else { "-D" };
            let _ = Command::new("iptables").args([action, "INPUT", "-s", ip, "-j", "DROP"])
                .stdout(Stdio::null()).stderr(Stdio::null()).status().await;
        }
    }
}

pub async fn ban_ip(state: &AppState, ip: &str, reason: &str, secs: u64, permanent: bool) {
    let jail = state.config.read().await.jail.clone();
    let now = Utc::now();
    let mut bans = state.banned_ips.write().await;
    let entry = bans.entry(ip.to_string()).or_insert_with(|| BanEntry {
        ip: ip.to_string(), reason: reason.to_string(), failures: 0,
        first_seen: now, last_seen: now, banned_until: None, permanent,
    });
    entry.reason = reason.to_string();
    entry.permanent = permanent;
    entry.banned_until = if permanent { None } else { Some(now + Duration::seconds(secs as i64)) };
    entry.last_seen = now;
    drop(bans);
    apply_ban(&jail, ip, true).await;
    crate::notify::emit(state, "ip.banned", &format!("{ip}: {reason}")).await;
}

pub async fn unban_ip(state: &AppState, ip: &str) {
    let jail = state.config.read().await.jail.clone();
    state.banned_ips.write().await.remove(ip);
    apply_ban(&jail, ip, false).await;
}

pub async fn ban_handler(State(state): State<AppState>, Json(payload): Json<serde_json::Value>) -> Response {
    let ip = payload.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    if ip.is_empty() { return (axum::http::StatusCode::BAD_REQUEST, "ip required").into_response(); }
    let reason = payload.get("reason").and_then(|v| v.as_str()).unwrap_or("manual");
    let secs = payload.get("secs").and_then(|v| v.as_u64()).unwrap_or(3600);
    let permanent = payload.get("permanent").and_then(|v| v.as_bool()).unwrap_or(false);
    ban_ip(&state, ip, reason, secs, permanent).await;
    Json(json!({"ok": true})).into_response()
}

pub async fn unban_handler(State(state): State<AppState>, Path(ip): Path<String>) -> Response {
    unban_ip(&state, &ip).await;
    Json(json!({"ok": true})).into_response()
}

pub fn spawn_jail_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let jail = state.config.read().await.jail.clone();
            if jail.enabled {
                for source in jail.log_sources.iter().filter(|s| s.enabled) {
                    match source.kind.as_str() {
                        "file" => {
                            if let Ok(text) = tokio::fs::read_to_string(&source.value).await {
                                let lines = text.lines().rev().take(200);
                                for line in lines { check_line(&state, source.pattern.as_str(), source, line, &jail.whitelist).await; }
                            }
                        }
                        "command" => {
                            let mut parts = source.value.split_whitespace();
                            if let Some(program) = parts.next() {
                                if let Ok(out) = Command::new(program).args(parts.collect::<Vec<_>>()).output().await {
                                    let text = String::from_utf8_lossy(&out.stdout);
                                    for line in text.lines().rev().take(200) { check_line(&state, &source.pattern, source, line, &jail.whitelist).await; }
                                }
                            }
                        }
                        "docker" => {
                            let container = &source.value;
                            if let Ok(out) = Command::new("docker").args(["logs", "--tail", "200", container]).output().await {
                                let text = String::from_utf8_lossy(&out.stderr);
                                for line in text.lines().rev().take(200) { check_line(&state, &source.pattern, source, line, &jail.whitelist).await; }
                            }
                        }
                        _ => {}
                    }
                }
                let mut bans = state.banned_ips.write().await;
                let now = Utc::now();
                let expired: Vec<String> = bans.iter()
                    .filter(|(_, e)| !e.permanent && e.banned_until.map(|u| u <= now).unwrap_or(false))
                    .map(|(k, _)| k.clone()).collect();
                for ip in expired { bans.remove(&ip); apply_ban(&jail, &ip, false).await; }
            }
            tokio::time::sleep(StdDuration::from_secs(10)).await;
        }
    });
}

async fn check_line(state: &AppState, pattern: &str, source: &crate::config::LogSource, line: &str, whitelist: &[String]) {
    if pattern.is_empty() || Regex::new(pattern).map(|r| r.is_match(line)).unwrap_or(false) {
        if let Some(ip) = extract_ip(line) {
            if !ip_match_list(whitelist, &ip) { record_failure(state, source.max_failures, source.window_secs, source.ban_secs, &ip, &source.template).await; }
        }
    }
}

fn extract_ip(line: &str) -> Option<String> {
    if let Some(v) = line.split_whitespace().find_map(|word| word.parse::<IpAddr>().ok()) { return Some(v.to_string()); }
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?.find(line).map(|m| m.as_str().to_string())
}

pub async fn record_failure(state: &AppState, max: u32, window: u64, ban: u64, ip: &str, reason: &str) {
    if ip.is_empty() { return; }
    let jail = state.config.read().await.jail.clone();
    if ip_match_list(&jail.whitelist, ip) { return; }
    let now = Utc::now();
    let mut bans = state.banned_ips.write().await;
    let entry = bans.entry(ip.to_string()).or_insert_with(|| BanEntry {
        ip: ip.to_string(), reason: reason.to_string(), failures: 0,
        first_seen: now, last_seen: now, banned_until: None, permanent: false,
    });
    if entry.banned_until.is_some() || entry.permanent { return; }
    if now - entry.first_seen > Duration::seconds(window as i64) { entry.first_seen = now; entry.failures = 0; }
    entry.failures += 1;
    entry.last_seen = now;
    entry.reason = reason.to_string();
    if entry.failures >= max {
        let secs = if jail.escalation { ban.saturating_mul(u64::from(entry.failures / max)) } else { ban };
        entry.banned_until = Some(now + Duration::seconds(secs as i64));
        drop(bans);
        apply_ban(&jail, ip, true).await;
        crate::notify::emit(state, "ip.banned", &format!("{ip}: {reason}")).await;
    }
}

pub async fn record_404(state: &AppState, ip: &str) {
    let jail = state.config.read().await.jail.clone();
    if jail.web_trap_paths.is_empty() && jail.trap_404_threshold == 0 { return; }
    record_failure(state, jail.trap_404_threshold.max(1), 300, jail.ban_secs, ip, "web probe").await;
}

pub async fn record_tls_failure(state: &AppState, ip: &str, kind: &str) {
    let jail = state.config.read().await.jail.clone();
    if !jail.tls_failure_ban { return; }
    record_failure(state, 5, 300, jail.ban_secs, ip, &format!("tls:{kind}")).await;
}

pub fn spawn_trap_ports(state: AppState) {
    tokio::spawn(async move {
        loop {
            let ports = state.config.read().await.jail.trap_ports.clone();
            for port in ports {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{port}")).await {
                        loop {
                            if let Ok((_, peer)) = listener.accept().await {
                                let jail = state.config.read().await.jail.clone();
                                record_failure(&state, 1, jail.window_secs, jail.ban_secs, &peer.ip().to_string(), &format!("trap port {port}")).await;
                            }
                        }
                    }
                });
            }
            tokio::time::sleep(StdDuration::from_secs(60)).await;
        }
    });
}
