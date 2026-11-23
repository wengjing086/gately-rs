use crate::config::{CertificateConfig, Config, DdnsTask, IpSource, SiteConfig, StunTask, TunnelTask};
use crate::state::AppState;
use chrono::Utc;
use serde_json::{Value, json};
use std::fs;
use std::io::Read;
use uuid::Uuid;

#[derive(Default, serde::Serialize)]
pub struct Report {
    pub sites: usize,
    pub ddns: usize,
    pub certificates: usize,
    pub tunnels: usize,
    pub stun: usize,
    pub notices: Vec<String>,
}

fn text(v: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) { return s.to_string(); }
    }
    String::new()
}

fn strings(v: &Value, keys: &[&str]) -> Vec<String> {
    for key in keys {
        if let Some(value) = v.get(key) {
            if let Some(arr) = value.as_array() {
                return arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
            }
            if let Some(s) = value.as_str() {
                return s.split([',', ';']).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
            }
        }
    }
    Vec::new()
}

fn new_id(prefix: &str) -> String { format!("{}_{}", prefix, Uuid::new_v4().simple()) }

fn merge_object(cfg: &mut Config, v: &Value, keep_enabled: bool, report: &mut Report) {
    if !v.is_object() { return; }

    let domains = strings(v, &["domains", "Domains", "host", "Host"]);
    let backend = text(v, &["backend", "Backend", "target", "forwardTo"]);
    if !domains.is_empty() && !backend.is_empty() {
        let id = text(v, &["id", "ID", "name"]);
        let id = if id.is_empty() { new_id("site") } else { id };
        if !cfg.sites.iter().any(|s| s.id == id) {
            cfg.sites.push(SiteConfig { id, domains, backend, ..Default::default() });
            report.sites += 1;
        }
    }

    let record_name = text(v, &["name", "domain", "recordName"]);
    let zone_id = text(v, &["zone_id", "zoneID", "zoneId", "zone"]);
    if !record_name.is_empty() && !zone_id.is_empty() {
        let ip = text(v, &["ip", "address", "value", "content"]);
        let url = text(v, &["url", "ipUrl", "getIpUrl"]);
        let ip_source = if url.is_empty() { IpSource::Static { ip } } else { IpSource::Url { url } };
        let id = text(v, &["id", "ID"]);
        let id = if id.is_empty() { new_id("ddns") } else { id };
        if !cfg.ddns.iter().any(|t| t.id == id) {
            cfg.ddns.push(DdnsTask {
                id, enabled: keep_enabled && v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                provider: "cloudflare".into(), zone_id, api_token: text(v, &["api_token", "apiToken", "token"]),
                name: record_name, record_type: text(v, &["record_type", "type", "recordType"]).to_ascii_uppercase().or_else_if_empty("A"),
                ip_source, interval_secs: v.get("interval_secs").and_then(|x| x.as_u64()).unwrap_or(300), last_ip: None,
                ..Default::default()
            });
            report.ddns += 1;
        }
    }

    let cert = text(v, &["cert_path", "certPath", "cert", "crt"]);
    let key = text(v, &["key_path", "keyPath", "key"]);
    if !cert.is_empty() && !key.is_empty() {
        let id = text(v, &["id", "ID", "name"]);
        let id = if id.is_empty() { new_id("cert") } else { id };
        if !cfg.certificates.iter().any(|c| c.id == id) {
            cfg.certificates.push(CertificateConfig { id, cert_path: cert, key_path: key, acme_id: None, ..Default::default() });
            report.certificates += 1;
        }
    }

    let binary = text(v, &["binary", "bin", "binaryPath"]);
    if !binary.is_empty() {
        let id = text(v, &["id", "ID", "name"]);
        let id = if id.is_empty() { new_id("tunnel") } else { id };
        if !cfg.tunnels.iter().any(|t| t.id == id) {
            cfg.tunnels.push(TunnelTask {
                id, name: text(v, &["name", "Name"]), binary,
                args: strings(v, &["args", "arguments"]), workdir: None, env: Default::default(),
                enabled: false, auto_restart: true, ..Default::default()
            });
            report.tunnels += 1;
        }
    }

    let server = text(v, &["server", "stunServer", "addr"]);
    if !server.is_empty() && server.contains(':') {
        let id = text(v, &["id", "ID", "name"]);
        let id = if id.is_empty() { new_id("stun") } else { id };
        if !cfg.stun.iter().any(|t| t.id == id) {
            cfg.stun.push(StunTask { id, server, enabled: false, interval_secs: 300, ..Default::default() });
            report.stun += 1;
        }
    }
}

fn parse_nginx(cfg: &mut Config, text: &str, report: &mut Report) {
    for block in text.split("server").skip(1) {
        let body_start = match block.find('{') { Some(i) => i, None => continue };
        let body_end = match block.find('}') { Some(i) => i, None => continue };
        if body_end <= body_start { continue; }
        let body = &block[body_start + 1..body_end];
        let domains: Vec<String> = body.split(';').find_map(|part| {
            let part = part.trim();
            if part.starts_with("server_name ") {
                Some(part.trim_start_matches("server_name ").split_whitespace().map(|s| s.to_string()).collect())
            } else { None }
        }).unwrap_or_default();
        let backend = body.split(';').find_map(|part| {
            let part = part.trim();
            part.strip_prefix("proxy_pass ").map(|v| v.trim().trim_end_matches(';').trim().to_string())
        }).unwrap_or_default();
        if domains.is_empty() || backend.is_empty() { continue; }
        let id = new_id("site");
        if !cfg.sites.iter().any(|s| s.id == id) {
            cfg.sites.push(SiteConfig { id, domains, backend, ..Default::default() });
            report.sites += 1;
        }
    }
}

fn parse_frp(cfg: &mut Config, text: &str, report: &mut Report) {
    let mut current: Option<TunnelTask> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(task) = current.take() { push_tunnel(cfg, task, report); }
            let name = line.trim_start_matches('[').trim_end_matches(']').to_string();
            let mut task = TunnelTask::default();
            task.id = new_id("tunnel"); task.name = name; task.kind = "frpc".into();
            task.binary = "frpc".into(); task.config_text = format!("{line}\n");
            current = Some(task);
        } else if let Some(task) = current.as_mut() {
            task.config_text.push_str(line); task.config_text.push('\n');
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "serverAddr" { task.public_address = Some(v.trim().to_string()); }
            }
        }
    }
    if let Some(task) = current { push_tunnel(cfg, task, report); }
}

fn push_tunnel(cfg: &mut Config, task: TunnelTask, report: &mut Report) {
    if !cfg.tunnels.iter().any(|t| t.id == task.id) {
        report.tunnels += 1;
        cfg.tunnels.push(task);
    }
}

trait OrElseIfEmpty { fn or_else_if_empty(self, fallback: &str) -> String; }
impl OrElseIfEmpty for String {
    fn or_else_if_empty(self, fallback: &str) -> String { if self.is_empty() { fallback.to_string() } else { self } }
}

fn walk(cfg: &mut Config, value: &Value, keep_enabled: bool, report: &mut Report) {
    match value {
        Value::Object(map) => {
            merge_object(cfg, value, keep_enabled, report);
            for v in map.values() { walk(cfg, v, keep_enabled, report); }
        }
        Value::Array(arr) => for v in arr { walk(cfg, v, keep_enabled, report); },
        _ => {}
    }
}

fn parse_json(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok().or_else(|| {
        let start = text.find('{')?;
        let end = text.rfind('}')? + 1;
        serde_json::from_str(&text[start..end]).ok()
    })
}

pub async fn import_paths(state: &AppState, paths: Vec<String>, keep_enabled: bool) -> Result<Value, String> {
    let mut report = Report::default();
    for path in paths {
        let bytes = fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
        if path.to_ascii_lowercase().ends_with(".zip") {
            let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("zip: {e}"))?;
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(|e| format!("zip entry: {e}"))?;
                if !file.name().to_ascii_lowercase().ends_with(".lkcf") { continue; }
                let mut text = String::new();
                let _ = file.read_to_string(&mut text);
                if let Some(value) = parse_json(&text) {
                    let mut cfg = state.config.write().await;
                    walk(&mut cfg, &value, keep_enabled, &mut report);
                } else {
                    report.notices.push(format!("{}: unsupported encrypted/binary format", file.name()));
                }
            }
        } else {
            let text = String::from_utf8_lossy(&bytes);
            let lower = path.to_ascii_lowercase();
            if lower.ends_with(".conf") && text.contains("proxy_pass") {
                let mut cfg = state.config.write().await;
                parse_nginx(&mut cfg, &text, &mut report);
            } else if lower.ends_with(".ini") || lower.ends_with(".toml") {
                let mut cfg = state.config.write().await;
                parse_frp(&mut cfg, &text, &mut report);
            } else if let Some(value) = parse_json(&text) {
                let mut cfg = state.config.write().await;
                walk(&mut cfg, &value, keep_enabled, &mut report);
            } else {
                report.notices.push(format!("{path}: unsupported encrypted/binary format"));
            }
        }
    }
    report.notices.push(format!("imported at {}", Utc::now().to_rfc3339()));
    report.notices.push("imported rules are disabled unless keep_enabled was set".into());
    let mut cfg = state.config.write().await;
    cfg.save(&state.config_path).map_err(|e| format!("save config: {e}"))?;
    Ok(json!(report))
}
