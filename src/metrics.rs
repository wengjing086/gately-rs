use crate::state::{AppState, AuditEntry, SiteStats, TrafficCounter};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;

pub async fn audit(state: &AppState, actor: &str, action: &str, target: &str, detail: &str) {
    let entry = AuditEntry {
        id: Uuid::new_v4().to_string(),
        time: Utc::now(),
        actor: actor.to_string(),
        action: action.to_string(),
        target: target.to_string(),
        detail: detail.chars().take(2000).collect(),
    };
    let retention = state.config.read().await.system.audit_retention_days.max(1);
    let mut log = state.audit_log.write().await;
    log.push(entry);
    if log.len() > 5000 { let excess = log.len() - 5000; log.drain(0..excess); }
    let cutoff = Utc::now() - chrono::Duration::days(retention as i64);
    log.retain(|e| e.time >= cutoff);
}

pub async fn record_request(
    state: &AppState,
    site_id: &str,
    ip: &str,
    path: &str,
    status: u16,
    bytes_in: u64,
    bytes_out: u64,
    country: &str,
) {
    let now = Utc::now().format("%Y-%m-%dT%H:%M").to_string();
    let mut all = state.site_stats.write().await;
    let stats: &mut SiteStats = all.entry(site_id.to_string()).or_default();
    stats.traffic.requests += 1;
    stats.traffic.bytes_in += bytes_in;
    stats.traffic.bytes_out += bytes_out;
    if status >= 400 { stats.traffic.errors += 1; }
    if !ip.is_empty() { *stats.top_ips.entry(ip.to_string()).or_insert(0) += 1; }
    if !path.is_empty() { *stats.top_paths.entry(path.to_string()).or_insert(0) += 1; }
    if !country.is_empty() { *stats.countries.entry(country.to_string()).or_insert(0) += 1; }
    let minute: &mut TrafficCounter = stats.minutes.entry(now).or_default();
    minute.requests += 1;
    minute.bytes_in += bytes_in;
    minute.bytes_out += bytes_out;
    if status >= 400 { minute.errors += 1; }
}

pub async fn record_connection(state: &AppState, id: &str, target: &str, kind: &str) {
    let mut all = state.site_stats.write().await;
    let stats: &mut SiteStats = all.entry(id.to_string()).or_default();
    stats.traffic.connections += 1;
    stats.backend_health.insert(target.to_string(), true);
    let _ = kind;
}

fn read_first_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.lines().next()?.split_whitespace().next()?.parse().ok()
}

fn proc_stat_cpu() -> f64 {
    let text = match fs::read_to_string("/proc/stat") { Ok(v) => v, Err(_) => return 0.0 };
    let line = text.lines().find(|l| l.starts_with("cpu "));
    let idle = line.and_then(|l| l.split_whitespace().nth(4)).and_then(|v| v.parse::<f64>().ok());
    let total: f64 = line.map(|l| l.split_whitespace().skip(1)
        .filter_map(|v| v.parse::<f64>().ok()).sum()).unwrap_or(0.0);
    match idle { Some(idle) if total > 0.0 => 100.0 * (1.0 - idle / total), _ => 0.0 }
}

fn mem_info() -> (u64, u64) {
    let text = match fs::read_to_string("/proc/meminfo") { Ok(v) => v, Err(_) => return (0, 0) };
    let mut total = 0u64; let mut avail = 0u64;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") { total = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0) * 1024; }
        if let Some(v) = line.strip_prefix("MemAvailable:") { avail = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0) * 1024; }
    }
    (total, avail)
}

fn net_dev() -> Vec<Value> {
    let text = match fs::read_to_string("/proc/net/dev") { Ok(v) => v, Err(_) => return Vec::new() };
    text.lines().skip(2).filter_map(|line| {
        let (name, rest) = line.split_once(':')?;
        let nums: Vec<u64> = rest.split_whitespace().filter_map(|v| v.parse().ok()).collect();
        if nums.len() < 16 { return None; }
        Some(json!({"name": name.trim(), "rx_bytes": nums[0], "tx_bytes": nums[8]}))
    }).collect()
}

pub async fn system_info() -> Value {
    let (mem_total, mem_avail) = mem_info();
    let disk = fs::metadata(".");
    json!({
        "cpu_percent": proc_stat_cpu(),
        "memory_total": mem_total,
        "memory_available": mem_avail,
        "memory_percent": if mem_total > 0 { 100.0 * (mem_total - mem_avail) as f64 / mem_total as f64 } else { 0.0 },
        "disk_total": 0,
        "disk_free": 0,
        "disk_ok": disk.is_ok(),
        "interfaces": net_dev(),
        "load1": read_first_u64("/proc/loadavg").unwrap_or(0),
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}

pub async fn site_stats_handler(State(state): State<AppState>) -> Response {
    Json(state.site_stats.read().await.clone()).into_response()
}

pub async fn topology_handler(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    let stats = state.site_stats.read().await;
    let listeners: Vec<Value> = config.listeners.iter().map(|l| {
        let sites: Vec<Value> = config.sites.iter().filter(|s| s.listener.as_deref().map(|n| n == &l.name).unwrap_or(true)).map(|s| {
            let st = stats.get(&s.id);
            json!({
                "id": s.id, "name": s.domains.first().cloned().unwrap_or_else(|| s.id.clone()),
                "backends": s.backends.iter().map(|b| b.url.clone()).collect::<Vec<_>>(),
                "backend": if s.backends.is_empty() { s.backend.clone() } else { String::new() },
                "requests": st.map(|x| x.traffic.requests).unwrap_or(0),
                "bytes_out": st.map(|x| x.traffic.bytes_out).unwrap_or(0),
                "active_ips": st.map(|x| x.top_ips.len()).unwrap_or(0),
            })
        }).collect();
        json!({"id": l.name, "listen": l.listen, "sites": sites})
    }).collect();
    let forwards: Vec<Value> = state.forward_stats.read().await.iter().map(|(id, s)| {
        json!({"id": id, "requests": s.connections, "bytes_in": s.bytes_in, "bytes_out": s.bytes_out})
    }).collect();
    Json(json!({"listeners": listeners, "port_forwards": forwards})).into_response()
}

pub async fn audit_handler(State(state): State<AppState>) -> Response {
    let log = state.audit_log.read().await;
    let mut items: Vec<&AuditEntry> = log.iter().collect();
    items.sort_by(|a, b| b.time.cmp(&a.time));
    Json(items).into_response()
}

pub async fn system_handler() -> Response { Json(system_info().await).into_response() }

pub async fn metrics_prometheus(State(state): State<AppState>) -> Response {
    let stats = state.site_stats.read().await;
    let mut out = String::from("# TYPE gately_requests_total counter\n");
    for (id, s) in stats.iter() {
        out.push_str(&format!("gately_requests_total{{site=\"{}\"}} {}\n", id, s.traffic.requests));
        out.push_str(&format!("gately_bytes_out_total{{site=\"{}\"}} {}\n", id, s.traffic.bytes_out));
        out.push_str(&format!("gately_errors_total{{site=\"{}\"}} {}\n", id, s.traffic.errors));
    }
    let bans = state.banned_ips.read().await.len();
    out.push_str(&format!("# TYPE gately_banned_ips gauge\ngately_banned_ips {bans}\n"));
    (axum::http::StatusCode::OK, [("content-type", "text/plain; version=0.0.4")], out).into_response()
}

pub fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<Value> {
    let mut items: Vec<(&String, &u64)> = map.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1));
    items.into_iter().take(n).map(|(k, v)| json!({"key": k, "count": v})).collect()
}

pub async fn stats_summary(State(state): State<AppState>) -> Response {
    let stats = state.site_stats.read().await;
    let mut requests = 0u64; let mut bytes_in = 0u64; let mut bytes_out = 0u64; let mut errors = 0u64;
    let mut top_ips: HashMap<String, u64> = HashMap::new();
    let mut top_paths: HashMap<String, u64> = HashMap::new();
    let mut countries: HashMap<String, u64> = HashMap::new();
    for s in stats.values() {
        requests += s.traffic.requests; bytes_in += s.traffic.bytes_in; bytes_out += s.traffic.bytes_out; errors += s.traffic.errors;
        for (k, v) in &s.top_ips { *top_ips.entry(k.clone()).or_insert(0) += *v; }
        for (k, v) in &s.top_paths { *top_paths.entry(k.clone()).or_insert(0) += *v; }
        for (k, v) in &s.countries { *countries.entry(k.clone()).or_insert(0) += *v; }
    }
    Json(json!({
        "requests": requests, "bytes_in": bytes_in, "bytes_out": bytes_out, "errors": errors,
        "top_ips": top_n(&top_ips, 20), "top_paths": top_n(&top_paths, 20), "top_countries": top_n(&countries, 20)
    })).into_response()
}
