use crate::config::{Config, JailConfig, SiteConfig, WafRule};
use crate::state::AppState;
use chrono::{Duration, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Debug)]
pub enum Decision {
    Allow,
    Log(String),
    Deny(String),
}

fn parse_ipv4(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if parts.len() != 4 { return None; }
    Some(u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]]))
}

pub fn ip_match(pattern: &str, ip: &str) -> bool {
    if pattern == ip { return true; }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return ip.starts_with(prefix);
    }
    if let Some((network, bits)) = pattern.split_once('/') {
        if let (Some(n), Some(bits), Some(addr)) = (parse_ipv4(network), bits.parse::<u32>().ok(), parse_ipv4(ip)) {
            if bits > 32 { return false; }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            return n & mask == addr & mask;
        }
    }
    false
}

fn ip_in_list(list: &[String], ip: &str) -> bool {
    list.iter().any(|p| ip_match(p, ip))
}

fn rule_target_value(target: &str, path: &str, query: &str, headers: &HashMap<String, String>, body: &str) -> String {
    match target {
        "query" => query.to_string(),
        "user_agent" => headers.get("user-agent").cloned().unwrap_or_default(),
        "header" => headers.values().cloned().collect::<Vec<_>>().join("\n"),
        "body" => body.to_string(),
        _ => path.to_string(),
    }
}

pub fn evaluate(
    config: &Config,
    site: &SiteConfig,
    path: &str,
    query: &str,
    headers: &HashMap<String, String>,
    body: &str,
) -> Decision {
    if site.denied_ips.iter().any(|p| ip_match(p, &client_ip(headers))) {
        return Decision::Deny("ip denied".into());
    }

    let mode = site.waf_mode.as_str();
    let profile_id = match &site.waf_profile { Some(id) => id.as_str(), None => return Decision::Allow };
    if mode == "off" { return Decision::Allow; }
    let profile = match config.waf_profiles.iter().find(|p| &p.id == profile_id) {
        Some(p) => p,
        None => return Decision::Allow,
    };
    let effective = if profile.mode == "off" { mode } else { &profile.mode };
    if effective == "off" { return Decision::Allow; }

    for rule in config.waf_rules.iter().filter(|r| r.enabled && profile.rule_ids.contains(&r.id)) {
        let value = rule_target_value(&rule.target, path, query, headers, body);
        if let Ok(re) = Regex::new(&rule.pattern) {
            if re.is_match(&value) {
                let msg = format!("waf rule {} ({})", rule.id, rule.name);
                if rule.action == "log" || effective == "detect" {
                    match decision_log(&msg) { d => return d }
                } else {
                    return Decision::Deny(msg);
                }
            }
        }
    }
    Decision::Allow
}

fn decision_log(msg: &str) -> Decision { Decision::Log(msg.to_string()) }

fn client_ip(headers: &HashMap<String, String>) -> String {
    headers.get("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .or_else(|| headers.get("x-real-ip").map(|s| s.as_str()))
        .unwrap_or("")
        .trim().to_string()
}

pub async fn is_banned(state: &AppState, ip: &str) -> bool {
    let mut bans = state.banned_ips.write().await;
    let now = Utc::now();
    bans.retain(|_, e| e.banned_until.map(|until| until > now).unwrap_or(true));
    bans.contains_key(ip)
}

async fn apply_ban(jail: &JailConfig, ip: &str, ban: bool) {
    if jail.backend == "none" || ip.is_empty() { return; }
    let mut cmd = Command::new(if jail.backend == "nftables" { "nft" } else { "iptables" });
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    match jail.backend.as_str() {
        "nftables" => {
            let _ = Command::new("nft").args(["add", "table", "inet", &jail.nft_table]).stdout(Stdio::null()).stderr(Stdio::null()).status().await;
            let chain = format!("{} {{ type filter hook input priority 0 ; }}", jail.nft_chain);
            let _ = Command::new("nft").args(["add", "chain", "inet", &jail.nft_table, &chain]).stdout(Stdio::null()).stderr(Stdio::null()).status().await;
            if ban {
                let _ = cmd.args(["add", "rule", "inet", &jail.nft_table, &jail.nft_chain, "ip", "saddr", ip, "drop"]).status().await;
            }
        }
        "iptables" => {
            let action = if ban { "-I" } else { "-D" };
            let _ = cmd.args([action, "INPUT", "-s", ip, "-j", "DROP"]).status().await;
        }
        _ => {}
    }
}

pub fn spawn_jail_loop(state: AppState) {
    tokio::spawn(async move {
        if !state.config.read().await.jail.enabled { return; }
        let mut pos: u64 = 0;
        loop {
            {
                let (jail, whitelist) = {
                    let cfg = state.config.read().await;
                    (cfg.jail.clone(), cfg.jail.whitelist.clone())
                };
                if jail.enabled && !jail.log_path.is_empty() {
                    if let Ok(file) = tokio::fs::File::open(&jail.log_path).await {
                        let mut reader = BufReader::new(file);
                        // Seek to the previous position; newly appended lines are read from there.
                        use tokio::io::AsyncSeekExt;
                        if reader.seek(std::io::SeekFrom::Start(pos)).await.is_ok() {
                            let mut line = String::new();
                            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                                if let Some(ip) = extract_ip(&line, &jail.patterns) {
                                    if !whitelist.iter().any(|p| ip_match(p, &ip)) {
                                        record_failure(&state, &jail, &ip).await;
                                    }
                                }
                                line.clear();
                            }
                            pos = reader.stream_position().await.unwrap_or(pos);
                        }
                    }
                }
            }
            {
                let jail = state.config.read().await.jail.clone();
                let mut bans = state.banned_ips.write().await;
                let now = Utc::now();
                let expired: Vec<String> = bans.iter()
                    .filter(|(_, e)| e.banned_until.map(|u| u <= now).unwrap_or(false))
                    .map(|(k, _)| k.clone()).collect();
                for ip in expired {
                    bans.remove(&ip);
                    apply_ban(&jail, &ip, false).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

fn extract_ip(line: &str, patterns: &[String]) -> Option<String> {
    if patterns.iter().any(|p| Regex::new(p).map(|r| r.is_match(line)).unwrap_or(false)) {
        let re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?;
        return re.find(line).map(|m| m.as_str().to_string());
    }
    None
}

async fn record_failure(state: &AppState, jail: &JailConfig, ip: &str) {
    let now = Utc::now();
    let mut bans = state.banned_ips.write().await;
    let entry = bans.entry(ip.to_string()).or_insert_with(|| crate::state::BanEntry {
        ip: ip.to_string(), failures: 0, first_seen: now, last_seen: now, banned_until: None,
    });
    if entry.banned_until.is_some() { return; }
    if now - entry.first_seen > Duration::seconds(jail.window_secs as i64) {
        entry.first_seen = now;
        entry.failures = 0;
    }
    entry.failures += 1;
    entry.last_seen = now;
    if entry.failures >= jail.max_failures {
        entry.banned_until = Some(now + Duration::seconds(jail.ban_secs as i64));
        apply_ban(jail, ip, true).await;
    }
}
