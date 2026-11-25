//! Upstream Gately web UI compatibility layer.
//!
//! The real Vue build is served from `/gately/`. Because it uses hash routing and
//! injects `<meta name="gately-base" content="/gately">`, every absolute `/api/...`
//! request issued by the UI arrives at `/gately/api/...`. This module translates
//! those requests to the configuration used by gately-rs, so both admin UIs can
//! coexist without route conflicts.

use crate::config::Config;
use crate::history;
use crate::state::AppState;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::{CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value, json};
use std::fs;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/upstream_assets.rs"));

const BASE: &str = "/gately";

fn camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = false;
    for ch in s.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 { out.push('_'); }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn map_keys(v: &Value, convert: fn(&str) -> String) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (convert(k), map_keys(v, convert))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(|v| map_keys(v, convert)).collect()),
        _ => v.clone(),
    }
}

fn obj(v: &Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn get_str(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn get_bool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn get_arr(v: &Value, key: &str) -> Vec<Value> {
    v.get(key).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn set_if(m: &mut Map<String, Value>, key: &str, val: Value) {
    m.insert(key.to_string(), val);
}

fn with(mut m: Map<String, Value>, pairs: Vec<(&str, Value)>) -> Value {
    for (k, v) in pairs { m.insert(k.to_string(), v); }
    Value::Object(m)
}

fn split_addr(s: &str) -> (String, String) {
    match s.rsplit_once(':') {
        Some((ip, port)) => (ip.to_string(), port.to_string()),
        None => (s.to_string(), String::new()),
    }
}

fn new_key(prefix: &str) -> String {
    format!("{}_{}", prefix, Uuid::new_v4().simple())
}

fn json_response(v: Value) -> Response { Json(v).into_response() }
fn ok() -> Response { json_response(json!({"ok": true})) }
fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

async fn read_body(req: Request<Body>) -> Result<Value, Response> {
    let bytes = to_bytes(req.into_body(), 16 * 1024 * 1024).await
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("读取请求体失败：{e}")))?;
    if bytes.is_empty() { return Ok(Value::Null); }
    serde_json::from_slice(&bytes).map_err(|e| err(StatusCode::BAD_REQUEST, format!("JSON 格式错误：{e}")))
}

async fn edit_config<F>(state: &AppState, f: F) -> Result<(), String>
where F: FnOnce(&mut Value) {
    let mut guard = state.config.write().await;
    let mut root = serde_json::to_value(&*guard).map_err(|e| e.to_string())?;
    f(&mut root);
    let updated: Config = serde_json::from_value(root).map_err(|e| e.to_string())?;
    if let Ok(text) = fs::read_to_string(&state.config_path) {
        let _ = history::snapshot(&state.config_path, &text);
    }
    updated.save(&state.config_path)?;
    *guard = updated;
    Ok(())
}

fn ensure_array<'a>(root: &'a mut Value, path: &str) -> &'a mut Vec<Value> {
    let mut cur = root;
    for part in path.split('.') {
        let m = cur.as_object_mut().expect("config root must be object");
        cur = m.entry(part.to_string()).or_insert_with(|| json!({}));
    }
    if !cur.is_array() { *cur = json!([]); }
    cur.as_array_mut().expect("array ensured")
}

fn array_at(root: &Value, path: &str) -> Vec<Value> {
    root.pointer(&format!("/{}", path.replace('.', "/")))
        .and_then(Value::as_array).cloned().unwrap_or_default()
}

fn merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b { merge(a.entry(k.clone()).or_insert(Value::Null), v); }
        }
        (a, b) => *a = b.clone(),
    }
}

/// Remove fields that belong to the upstream runtime view, not to configuration.
fn strip_runtime(v: &Value) -> Value {
    let mut m = obj(v);
    for k in ["key", "state", "stats", "running", "error", "usedBy", "identityStats",
        "info", "hasSecret", "loaded", "busy", "self", "update", "nextRun", "lastRun",
        "siteCerts", "upstreams", "firewallFailed", "restartRequired", "version", "binary",
        "connections", "tunnelId", "urlState", "absentModules", "passwordIssue", "role"] {
        m.remove(k);
    }
    if let Some(id) = m.remove("id") { m.insert("id".into(), id); }
    Value::Object(m)
}

fn resource_path(resource: &str) -> String {
    match resource {
        "ddns" => "ddns".to_string(),
        "cron" => "scheduled_tasks".to_string(),
        "notify-channels" => "notifications.channels".to_string(),
        "notify-rules" => "notifications.rules".to_string(),
        "portforward" => "port_forwards".to_string(),
        "protoroute" => "proto_routes".to_string(),
        "stun" => "stun".to_string(),
        "storage" => "storage".to_string(),
        "wol" => "wol.hosts".to_string(),
        "knock" => "knock.rules".to_string(),
        "waf" => "waf_profiles".to_string(),
        "ssl" => "certificates".to_string(),
        "tokens" => "admin.api_tokens".to_string(),
        _ => resource.to_string(),
    }
}

/// Translate an upstream camelCase entity into our snake_case configuration entity.
fn incoming(resource: &str, v: &Value) -> Value {
    let mut m = obj(&map_keys(&strip_runtime(v), snake));
    if let Some(key) = m.remove("key") { m.entry("id".to_string()).or_insert(key); }
    if let Some(en) = m.remove("enable") { m.insert("enabled".into(), en); }
    match resource {
        "ddns" => {
            if let Some(c) = v.get("credentials") {
                if let Some(id) = c.get("id").and_then(Value::as_str) { m.insert("zone_id".into(), json!(id)); }
                if let Some(s) = c.get("secret").and_then(Value::as_str) { m.insert("api_token".into(), json!(s)); }
            }
            if let Some(ipv4) = v.get("ipv4") {
                if ipv4.get("kind").and_then(Value::as_str) == Some("static") {
                    m.insert("ip_source".into(), json!({"kind": "static", "ip": get_str(ipv4, "value")}));
                } else if let Some(url) = ipv4.get("url").and_then(Value::as_str) {
                    m.insert("ip_source".into(), json!({"kind": "url", "url": url}));
                } else if let Some(cmd) = ipv4.get("command").and_then(Value::as_str) {
                    m.insert("ip_source".into(), json!({"kind": "command", "command": cmd}));
                }
            }
            if let Some(r) = get_arr(v, "records").first() {
                m.insert("name".into(), json!(get_str(r, "name")));
                if !get_str(r, "type").is_empty() { m.insert("record_type".into(), json!(get_str(r, "type"))); }
            }
            if v.get("interval").is_some() { m.insert("interval_secs".into(), v["interval"].clone()); }
        }
        "cron" => {
            if let Some(spec) = v.get("spec") { m.insert("cron".into(), spec.clone()); }
            if let Some(kind) = v.get("type") { m.insert("kind".into(), kind.clone()); }
            if let Some(http) = v.get("http") {
                m.insert("url".into(), json!(get_str(http, "url")));
                m.insert("method".into(), json!(get_str(http, "method")));
            }
        }
        "notify-channels" => {
            if v.get("secret").is_some() { m.insert("token".into(), v["secret"].clone()); }
            if v.get("url").is_some() && m.get("endpoint").is_none() { m.insert("endpoint".into(), v["url"].clone()); }
        }
        "notify-rules" => {
            if let Some(e) = get_arr(v, "events").first() { m.insert("event".into(), e.clone()); }
            if let Some(s) = v.get("silence") { m.insert("dedup_secs".into(), s.clone()); }
        }
        "portforward" => {
            let (ip, port) = split_addr(&get_str(v, "listenAddress"));
            if !ip.is_empty() || !port.is_empty() {
                m.insert("listen".into(), json!(format!("{}:{}", if ip.is_empty() { "0.0.0.0" } else { &ip }, if port.is_empty() { "0" } else { &port })));
            }
            if let Some(p) = get_arr(v, "protocols").first() { m.insert("protocol".into(), p.clone()); }
            let mut targets = Vec::new();
            let addrs = get_arr(v, "targetAddresses");
            let ports = get_arr(v, "targetPorts");
            for (i, a) in addrs.iter().enumerate() {
                let a = a.as_str().unwrap_or("");
                let p = ports.get(i).and_then(Value::as_str).unwrap_or("");
                targets.push(json!(if p.is_empty() { a.to_string() } else { format!("{a}:{p}") }));
            }
            if !targets.is_empty() { m.insert("targets".into(), Value::Array(targets)); }
            if let Some(list) = v.get("ipList") { m.insert("source_allow".into(), list.clone()); }
        }
        "protoroute" => {
            let (ip, port) = split_addr(&get_str(v, "listen"));
            if !port.is_empty() { m.insert("listen".into(), json!(format!("{}:{}", if ip.is_empty() { "0.0.0.0" } else { &ip }, port))); }
            let mut rules = Vec::new();
            for r in get_arr(v, "routes") {
                let mut rm = obj(&map_keys(&r, snake));
                if rm.get("id").is_none() { rm.insert("id".into(), json!(new_key("rule"))); }
                rules.push(Value::Object(rm));
            }
            m.insert("routes".into(), Value::Array(rules));
        }
        "stun" => {
            if let Some(b) = v.get("bind") {
                let ip = get_str(b, "ip");
                if !ip.is_empty() { m.insert("server".into(), json!(ip)); }
            }
            if let Some(s) = get_arr(v, "stunServers").first() { m.insert("server".into(), s.clone()); }
            if let Some(sec) = v.get("addrCheckInterval") { m.insert("interval_secs".into(), sec.clone()); }
        }
        "storage" => {
            if let Some(kind) = v.get("type") { m.insert("kind".into(), kind.clone()); }
            if let Some(ro) = v.get("readOnly") { m.insert("readonly".into(), ro.clone()); }
        }
        "wol" => {
            if let Some(mac) = get_arr(v, "macs").first() { m.insert("mac".into(), mac.clone()); }
            if let Some(ip) = get_arr(v, "broadcastIps").first() { m.insert("broadcast".into(), ip.clone()); }
        }
        "knock" => {
            let ports = get_arr(v, "ports").iter().map(|p| match p {
                Value::Number(n) => json!(n.as_u64().unwrap_or(0)),
                _ => p.clone(),
            }).collect::<Vec<_>>();
            if !ports.is_empty() { m.insert("ports".into(), Value::Array(ports)); }
            if let Some(k) = v.get("encKey") { m.insert("aes_key".into(), k.clone()); }
            if let Some(k) = v.get("hmacKey") { m.insert("hmac_key".into(), k.clone()); }
        }
        "tokens" => {
            if let Some(d) = v.get("disabled") { m.insert("enabled".into(), json!(!get_bool(v, "disabled"))); }
        }
        _ => {}
    }
    Value::Object(m)
}

/// Translate our configuration entity into the upstream runtime view.
fn outgoing(resource: &str, v: &Value) -> Value {
    let mut m = obj(&map_keys(v, camel));
    if let Some(id) = m.get("id").cloned() { m.insert("key".into(), id); }
    if let Some(en) = m.get("enabled").cloned() { m.insert("enable".into(), en); }
    match resource {
        "ddns" => {
            let ip = get_str(v, "last_ip");
            let src = v.get("ip_source").cloned().unwrap_or(json!({"kind":"static","ip":""}));
            m.insert("ipv4".into(), json!({
                "kind": get_str(&src, "kind"),
                "value": if get_str(&src, "kind") == "static" { get_str(&src, "ip") } else { String::new() },
                "url": get_str(&src, "url"), "command": get_str(&src, "command"),
            }));
            m.insert("ipv6".into(), json!({"kind":"static","value":""}));
            m.insert("credentials".into(), json!({"id": get_str(v, "zone_id"), "secret": get_str(v, "api_token"), "extra": {}}));
            let rec = json!({"name": get_str(v, "name"), "type": get_str(v, "record_type"), "line": "", "remark": get_str(v, "remark"), "id": get_str(v, "id")});
            m.insert("records".into(), json!([rec]));
            m.insert("interval".into(), json!(v.get("interval_secs").cloned().unwrap_or(json!(300))));
            m.insert("state".into(), json!({"ipv4": if ip.is_empty() { Value::Null } else { json!(ip) }, "ipv6": Value::Null,
                "ipError": Value::Null, "lastRun": Value::Null, "nextRun": Value::Null, "running": false, "records": {}}));
        }
        "cron" => {
            m.insert("spec".into(), v.get("cron").cloned().unwrap_or_else(|| json!("0 3 * * *")));
            let kind = get_str(v, "kind");
            m.insert("type".into(), json!(if kind == "http" { "http" } else { "command" }));
            m.insert("http".into(), json!({"enable": kind == "http", "url": get_str(v, "url"), "method": get_str(v, "method"),
                "body": get_str(v, "body"), "headers": {}, "successContent": "", "timeout": 10, "insecureSkipVerify": false}));
            m.insert("running".into(), json!(false));
            m.insert("nextRun".into(), Value::Null);
            m.insert("history".into(), Value::Null);
        }
        "notify-channels" => {
            m.insert("url".into(), v.get("endpoint").cloned().unwrap_or_else(|| json!("")));
            let secret = get_str(v, "token");
            m.insert("secret".into(), json!(secret));
            m.insert("hasSecret".into(), json!(!secret.is_empty()));
            m.insert("webhook".into(), json!({"enable": true, "url": get_str(v, "endpoint"), "method": "POST", "headers": [], "body": "", "successContent": "", "timeout": 10, "insecureSkipVerify": false}));
        }
        "notify-rules" => {
            let event = get_str(v, "event");
            m.insert("events".into(), json!(if event.is_empty() { Vec::<Value>::new() } else { vec![json!(event)] }));
            m.insert("minLevel".into(), json!("info"));
            m.insert("silence".into(), v.get("dedup_secs").cloned().unwrap_or_else(|| json!(0)));
        }
        "portforward" => {
            let proto = if get_str(v, "protocol") == "udp" { "udp" } else { "tcp" };
            m.insert("protocols".into(), json!([proto]));
            let (ip, port) = split_addr(&get_str(v, "listen"));
            m.insert("listenAddress".into(), json!(if ip.is_empty() { "0.0.0.0" } else { &ip }));
            m.insert("listenPorts".into(), json!(if port.is_empty() { Vec::<String>::new() } else { vec![port] }));
            let mut addrs = Vec::new(); let mut ports = Vec::new();
            for t in get_arr(v, "targets") {
                let s = t.as_str().unwrap_or("");
                let (a, p) = split_addr(s);
                addrs.push(json!(a)); ports.push(json!(p));
            }
            m.insert("targetAddresses".into(), Value::Array(addrs));
            m.insert("targetPorts".into(), Value::Array(ports));
            m.insert("ipMode".into(), json!("all"));
            m.insert("ipList".into(), v.get("source_allow").cloned().unwrap_or_else(|| json!([])));
            m.insert("running".into(), json!(false));
            m.insert("stats".into(), json!({"activeConns":0,"totalConns":0,"bytesIn":0,"bytesOut":0,"denied":0}));
        }
        "protoroute" => {
            let (ip, port) = split_addr(&get_str(v, "listen"));
            m.insert("listen".into(), json!(format!("{}:{}", if ip.is_empty() { "0.0.0.0" } else { &ip }, if port.is_empty() { "0" } else { &port })));
            let rules = get_arr(v, "routes").into_iter().map(|r| {
                let mut rm = obj(&map_keys(&r, camel));
                let value = get_str(&r, "value");
                rm.insert("domains".into(), json!(if value.is_empty() { Vec::<String>::new() } else { vec![value] }));
                rm.insert("targetAddresses".into(), json!(vec![get_str(&r, "target")]));
                Value::Object(rm)
            }).collect::<Vec<_>>();
            m.insert("routes".into(), Value::Array(rules));
            m.insert("running".into(), json!(false));
            m.insert("stats".into(), json!({"activeConns":0,"totalConns":0,"bytesIn":0,"bytesOut":0,"routeConns":0,"defaultConns":0,"rejected":0,"knockDenied":0}));
        }
        "stun" => {
            let server = get_str(v, "server");
            m.insert("bind".into(), json!({"mode":"ip","ip":server,"interface":"","regex":""}));
            m.insert("stunServers".into(), json!(if server.is_empty() { Vec::<String>::new() } else { vec![server] }));
            m.insert("keepAliveServers".into(), json!([]));
            m.insert("state".into(), json!({"status":"off","error":null,"since":null,"mapping":null,"firewall":null,
                "stats":{"activeConns":0,"totalConns":0,"bytesIn":0,"bytesOut":0,"denied":0}}));
            m.insert("interval".into(), v.get("interval_secs").cloned().unwrap_or_else(|| json!(60)));
        }
        "storage" => {
            m.insert("type".into(), v.get("kind").cloned().unwrap_or_else(|| json!("local")));
            m.insert("readOnly".into(), v.get("readonly").cloned().unwrap_or_else(|| json!(false)));
        }
        "wol" => {
            m.insert("macs".into(), json!(vec![get_str(v, "mac")]));
            let b = get_str(v, "broadcast");
            m.insert("broadcastIps".into(), json!(if b.is_empty() { Value::Null } else { json!(vec![b]) }));
            m.insert("port".into(), json!(9));
            m.insert("repeat".into(), json!(1));
            m.insert("checkAddr".into(), json!(""));
            m.insert("shutdownMode".into(), json!(""));
        }
        "knock" => {
            let ports = get_arr(v, "ports");
            m.insert("ports".into(), Value::Array(ports.into_iter().map(|p| match p {
                Value::Number(n) => json!(n.to_string()), other => other,
            }).collect()));
            m.insert("firewall".into(), json!("auto"));
            m.insert("encKey".into(), v.get("aes_key").cloned().unwrap_or_else(|| json!("")));
            m.insert("hmacKey".into(), v.get("hmac_key").cloned().unwrap_or_else(|| json!("")));
            m.insert("hmacType".into(), json!("sha256"));
            m.insert("timeout".into(), json!(60));
            m.insert("maxTimeout".into(), json!(3600));
            m.insert("requireAddr".into(), json!(get_bool(v, "single_address")));
            m.insert("stats".into(), json!({"knocks":0,"rejected":0,"lastAt":null,"lastAddr":null}));
            m.insert("usedBy".into(), json!([]));
        }
        "waf" => {
            let rules = get_arr(v, "rule_ids").into_iter().map(|id| json!({"enable":true,"remark":"","type":"crs","param":id})).collect::<Vec<_>>();
            m.insert("ruleSets".into(), Value::Array(rules));
            m.insert("paranoia".into(), json!(1));
            m.insert("inboundThreshold".into(), json!(5));
            m.insert("outboundThreshold".into(), json!(5));
            m.insert("bodyLimitMB".into(), json!(v.get("body_limit").cloned().unwrap_or_else(|| json!(2))));
            m.insert("bodyLimitAction".into(), json!("reject"));
            m.insert("skipBodyPaths".into(), v.get("skip_paths").cloned().unwrap_or_else(|| json!([])));
            m.insert("blocked".into(), json!(0));
            m.insert("matched".into(), json!(0));
            m.insert("safelineErrors".into(), json!([]));
        }
        "tokens" => {
            m.insert("disabled".into(), json!(!get_bool(v, "enabled")));
            m.insert("hint".into(), json!(get_str(v, "token")));
            m.insert("legacy".into(), json!(false));
            m.insert("expired".into(), json!(false));
            m.insert("createdAt".into(), json!(chrono::Utc::now().to_rfc3339()));
            m.insert("expiresAt".into(), Value::Null);
            m.insert("lastUsedAt".into(), Value::Null);
            m.insert("lastUsedIP".into(), json!(""));
        }
        _ => {}
    }
    Value::Object(m)
}

async fn list_of(state: &AppState, resource: &str) -> Vec<Value> {
    let cfg = state.config.read().await;
    array_at(&serde_json::to_value(&*cfg).unwrap_or_else(|_| json!({})), &resource_path(resource))
        .iter().map(|v| outgoing(resource, v)).collect()
}

fn default_item(resource: &str) -> Value {
    let mut base = match resource {
        "ddns" => json!({"id":"","enabled":true,"provider":"cloudflare","zone_id":"","api_token":"","name":"","record_type":"A",
            "ip_source":{"kind":"static","ip":""},"interval_secs":300,"options":{},"webhooks":[],"remark":"","group":""}),
        "cron" => json!({"id":"","name":"","enabled":true,"cron":"0 3 * * *","kind":"command","command":"echo ok","url":"","method":"GET","body":""}),
        "notify-channels" => json!({"id":"","name":"","kind":"webhook","endpoint":"","token":"","extra":{},"enabled":true}),
        "notify-rules" => json!({"id":"","name":"","event":"*","channels":[],"dedup_secs":0,"enabled":true}),
        "portforward" => json!({"id":"","name":"","enabled":true,"protocol":"tcp","listen":"0.0.0.0:10000","targets":[],"max_connections":0}),
        "protoroute" => json!({"id":"","name":"","enabled":true,"listen":"0.0.0.0:10000","routes":[],"default_target":""}),
        "stun" => json!({"id":"","server":"stun.l.google.com:19302","enabled":true,"interval_secs":60,"protocol":"udp"}),
        "storage" => json!({"id":"","name":"","kind":"local","path":"","url":"","username":"","password":"","readonly":false,"enabled":true}),
        "wol" => json!({"id":"","name":"","mac":"","broadcast":"255.255.255.255","remark":"","enabled":true}),
        "knock" => json!({"id":"","name":"","enabled":true,"aes_key":"","hmac_key":"","ports":[],"identities":[]}),
        "waf" => json!({"id":"","name":"","enabled":true,"mode":"detect","rule_ids":[],"body_limit":2,"skip_paths":[]}),
        _ => json!({"id":"","name":"","enabled":true}),
    };
    let id = base.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    if id.is_empty() {
        let p = match resource { "ddns" => "ddns", "cron" => "task", "wol" => "host", _ => resource };
        base["id"] = json!(new_key(p));
    }
    let mut m = obj(&base);
    m.entry("name".to_string()).or_insert_with(|| json!("新建项"));
    Value::Object(m)
}

async fn generic_crud(state: &AppState, path: &str, method: &str, body: Value, query: Option<&str>) -> Option<Response> {
    let seg: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    if seg.len() < 3 || seg[0] != "api" { return None; }
    let resource = match (seg.get(1).copied(), seg.get(2).copied()) {
        (Some("ddns"), Some("tasks")) => "ddns",
        (Some("cron"), Some("tasks")) => "cron",
        (Some("notify"), Some("channels")) => "notify-channels",
        (Some("notify"), Some("rules")) => "notify-rules",
        (Some("portforward"), Some("rules")) => "portforward",
        (Some("protoroute"), Some("rules")) => "protoroute",
        (Some("stun"), Some("rules")) => "stun",
        (Some("storage"), Some("mounts")) => "storage",
        (Some("wol"), Some("devices")) => "wol",
        (Some("knock"), Some("rules")) => "knock",
        (Some("waf"), Some("instances")) => "waf",
        (Some("ssl"), Some("certs")) => "ssl",
        (Some("tokens"), Some(t)) if seg.len() == 3 && (t != "scopes" && t != "group" && t != "order") => "tokens",
        _ => return None,
    };
    let tail = &seg[3..];
    let action = tail.last().copied().unwrap_or("");
    let item_key = if matches!(action, "enable" | "copy" | "records" | "remote-delete" | "restart" | "run" | "renew") {
        tail.get(tail.len().saturating_sub(2)).copied()
    } else if tail.len() == 1 { Some(action) } else { None };
    let path_key = resource_path(resource);

    // Batch helpers use a suffix on the collection path.
    if tail.is_empty() && (path.ends_with("-enable") || path.ends_with("-delete") || path.ends_with("-group") || path.ends_with("-order")) {
        let base_name = path.rsplit('/').next().unwrap_or("");
        let _ = base_name;
    }

    match method {
        "GET" if tail.is_empty() => return Some(json_response(json!(list_of(state, resource).await))),
        "POST" if tail.is_empty() => {
            let mut item = if body.is_null() { default_item(resource) } else { incoming(resource, &body) };
            if item.get("id").and_then(Value::as_str).unwrap_or("").is_empty() {
                item["id"] = json!(new_key("item"));
            }
            let view = outgoing(resource, &item);
            let path_key = path_key.to_string();
            if let Err(e) = edit_config(state, |root| {
                let arr = ensure_array(root, &path_key);
                arr.push(item);
            }).await { return Some(err(StatusCode::BAD_REQUEST, e)); }
            return Some(json_response(view));
        }
        "PUT" | "PATCH" if item_key.is_some() && !matches!(action, "enable" | "records" | "remote-delete") => {
            let key = item_key.unwrap().to_string();
            let patch = incoming(resource, &body);
            let path_key = path_key.to_string();
            let mut result = Value::Null;
            if let Err(e) = edit_config(state, |root| {
                let arr = ensure_array(root, &path_key);
                if let Some(existing) = arr.iter_mut().find(|x| x.get("id").and_then(Value::as_str) == Some(key.as_str())) {
                    if method == "PATCH" { merge(existing, &patch); } else { *existing = patch.clone(); }
                    result = outgoing(resource, existing);
                }
            }).await { return Some(err(StatusCode::BAD_REQUEST, e)); }
            if result.is_null() { return Some(err(StatusCode::NOT_FOUND, "未找到对应项目")); }
            return Some(json_response(result));
        }
        "DELETE" if item_key.is_some() => {
            let key = item_key.unwrap().to_string();
            let path_key = path_key.to_string();
            if let Err(e) = edit_config(state, |root| {
                let arr = ensure_array(root, &path_key);
                arr.retain(|x| x.get("id").and_then(Value::as_str) != Some(key.as_str()));
            }).await { return Some(err(StatusCode::BAD_REQUEST, e)); }
            return Some(ok());
        }
        "PUT" if action == "enable" => {
            let key = item_key.unwrap_or("").to_string();
            let enable = get_bool(&body, "enable");
            let path_key = path_key.to_string();
            if let Err(e) = edit_config(state, |root| {
                let arr = ensure_array(root, &path_key);
                if let Some(x) = arr.iter_mut().find(|x| x.get("id").and_then(Value::as_str) == Some(key.as_str())) {
                    x["enabled"] = json!(enable);
                }
            }).await { return Some(err(StatusCode::BAD_REQUEST, e)); }
            return Some(ok());
        }
        "POST" if action == "copy" => {
            let key = item_key.unwrap_or("").to_string();
            let path_key = path_key.to_string();
            let mut copied = Value::Null;
            if let Err(e) = edit_config(state, |root| {
                let arr = ensure_array(root, &path_key);
                if let Some(x) = arr.iter().find(|x| x.get("id").and_then(Value::as_str) == Some(key.as_str())) {
                    let mut c = x.clone();
                    c["id"] = json!(new_key("copy"));
                    c["enabled"] = json!(false);
                    copied = outgoing(resource, &c);
                    arr.push(c);
                }
            }).await { return Some(err(StatusCode::BAD_REQUEST, e)); }
            if copied.is_null() { return Some(err(StatusCode::NOT_FOUND, "未找到对应项目")); }
            return Some(json_response(copied));
        }
        "POST" if action == "run" || action == "renew" || action == "restart" || action == "remote-delete" || action == "records" => {
            return Some(json_response(json!({"ok": true, "queued": true})));
        }
        _ => {}
    }
    let _ = query;
    None
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get("cookie").and_then(|v| v.to_str().ok()).and_then(|raw| {
        raw.split(';').find_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            if k == name { Some(v.to_string()) } else { None }
        })
    })
}

async fn compat_auth(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let token = cookie_value(req.headers(), "gately_token")
        .or_else(|| req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(str::to_string));
    let cfg = state.config.read().await;
    let valid = token.as_deref().is_some_and(|t| {
        t == cfg.admin.token || cfg.admin.api_tokens.iter().any(|x| x.enabled && x.token == t)
    });
    drop(cfg);
    if !valid { return err(StatusCode::UNAUTHORIZED, "未登录或会话已过期"); }
    next.run(req).await
}

async fn compat_login(State(state): State<AppState>, req: Request<Body>) -> Response {
    let body = match read_body(req).await { Ok(v) => v, Err(e) => return e };
    let password = get_str(&body, "password");
    let username = get_str(&body, "username");
    let cfg = state.config.read().await;
    let ok_pass = password == cfg.admin.password
        || cfg.auth.users.iter().any(|u| u.enabled && u.username == username && u.password == password);
    if !ok_pass {
        return err(StatusCode::UNAUTHORIZED, "用户名或密码错误");
    }
    let token = cfg.admin.token.clone();
    drop(cfg);
    let expires = chrono::Utc::now() + chrono::Duration::hours(24);
    let cookie = format!("gately_token={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400");
    Response::builder()
        .status(StatusCode::OK)
        .header(SET_COOKIE, cookie)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"token": token, "username": if username.is_empty() { "admin".to_string() } else { username },
            "expires": expires.to_rfc3339()}).to_string()))
        .unwrap()
}

async fn compat_logout() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(SET_COOKIE, "gately_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{\"ok\":true}"))
        .unwrap()
}

async fn compat_session() -> Response {
    json_response(json!({"username": "admin", "role": "admin", "passwordIssue": "", "disabledModules": [], "absentModules": []}))
}

/// Convenience entry for browser automation and token users: `/gately/set-cookie?token=...`
/// validates the token, installs the same session cookie as `/api/login`, then opens the UI.
async fn token_cookie(State(state): State<AppState>, req: Request<Body>) -> Response {
    let token = req.uri().query().and_then(|q| q.split('&').find_map(|p| p.strip_prefix("token="))).unwrap_or("");
    let valid = {
        let cfg = state.config.read().await;
        token == cfg.admin.token || cfg.admin.api_tokens.iter().any(|t| t.enabled && t.token == token)
    };
    if !valid { return err(StatusCode::UNAUTHORIZED, "令牌无效"); }
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(SET_COOKIE, format!("gately_token={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"))
        .header("location", format!("{BASE}/"))
        .body(Body::empty())
        .unwrap()
}

async fn compat_providers(State(state): State<AppState>) -> Response {
    let providers = state.config.read().await.auth.oidc.iter().filter(|p| p.enabled)
        .map(|p| json!({"key": p.id, "name": p.name, "type": "oidc", "url": format!("/gately/api/login/oidc/start?provider={}", p.id)}))
        .collect::<Vec<_>>();
    json_response(json!({"providers": providers, "passwordLogin": true}))
}

fn status_value(cfg: &Config) -> Value {
    let modules = MODULES.iter().map(|id| {
        let (enabled, summary) = match *id {
            "webservice" => (!cfg.sites.is_empty() || !cfg.listeners.is_empty(), vec![json!({"label":"站点","value":cfg.sites.len().to_string()})]),
            "ssl" => (!cfg.certificates.is_empty(), vec![]),
            "ddns" => (!cfg.ddns.is_empty(), vec![]),
            "cron" => (!cfg.scheduled_tasks.is_empty(), vec![]),
            "notify" => (!cfg.notifications.channels.is_empty(), vec![]),
            "portforward" => (!cfg.port_forwards.is_empty(), vec![]),
            "protoroute" => (!cfg.proto_routes.is_empty(), vec![]),
            "stun" => (!cfg.stun.is_empty(), vec![]),
            "wol" => (!cfg.wol.hosts.is_empty(), vec![]),
            "waf" => (!cfg.waf_profiles.is_empty(), vec![]),
            "knock" => (cfg.knock.enabled, vec![]),
            "storage" => (!cfg.storage.is_empty(), vec![]),
            "docker" => (cfg.docker.enabled, vec![]),
            "webterminal" => (cfg.terminal.enabled, vec![]),
            "nettools" => (cfg.diag.enabled, vec![]),
            "perf" => (cfg.perf.enabled, vec![]),
            "filebrowser" => (cfg.filebrowser.enabled, vec![]),
            "smb" => (cfg.smb.enabled, vec![]),
            _ => (true, vec![]),
        };
        json!({"id": id, "title": id, "enabled": enabled, "summary": summary})
    }).collect::<Vec<_>>();
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "commit": "gately-rs",
        "buildDate": "2026-11-24",
        "goVersion": "rust",
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "startTime": chrono::Utc::now().to_rfc3339(),
        "goroutines": 0,
        "memAlloc": 0,
        "modules": modules,
        "timeZone": cfg.system.timezone,
        "configDir": "",
        "host": {
            "hostname": "gately-rs", "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "inContainer": false,
            "cpu": {"cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1), "usage": 0, "load": []},
            "memory": {"total": 0, "used": 0, "available": 0, "swapTotal": 0, "swapUsed": 0},
            "disk": {"path": "", "total": 0, "used": 0, "free": 0},
            "interfaces": [],
            "process": {"pid": std::process::id(), "goroutines": 0, "heapAlloc": 0, "heapSys": 0, "numGC": 0},
            "sampledAt": chrono::Utc::now().to_rfc3339()
        }
    })
}

fn web_listener_views(cfg: &Config) -> Vec<Value> {
    cfg.listeners.iter().map(|l| {
        let (ip, port) = split_addr(&l.listen);
        let tls = !l.tls_cert.as_deref().unwrap_or("").is_empty();
        let sites = cfg.sites.iter().filter(|s| s.listener.as_deref().unwrap_or("") == l.name)
            .map(|s| site_view(s)).collect::<Vec<_>>();
        json!({
            "key": l.name, "name": l.name, "enable": true,
            "network": "tcp", "listenIp": ip, "port": port.parse::<u16>().unwrap_or(0),
            "tls": tls, "minTls": "1.2", "http3": l.http3,
            "plainHttp": l.http_port.is_some(), "httpPort": l.http_port.unwrap_or(0),
            "httpPortMode": l.http_mode, "acceptProxyProtocol": l.proxy_protocol,
            "sites": sites, "default": Value::Null, "remark": "",
            "running": true, "stats": {}, "error": null
        })
    }).collect()
}

fn site_view(s: &crate::config::SiteConfig) -> Value {
    let kind = if s.kind == "static" { "static" } else if s.kind == "text" { "text" } else { "proxy" };
    let locations = s.path_rules.iter().map(|r| json!({
        "matcher": r.matcher, "value": r.value, "type": r.action,
        "target": r.target, "remark": ""
    })).collect::<Vec<_>>();
    json!({
        "key": s.id, "name": s.id, "enable": s.enabled,
        "domains": s.domains, "type": kind,
        "targets": if s.backend.is_empty() { Value::Null } else { json!([s.backend]) },
        "locations": locations, "userRoutes": [], "identityHeaders": [],
        "redirectTo": s.redirect_url, "redirectCode": 301,
        "root": s.static_root, "statusCode": 0,
        "users": if s.auth_users.is_empty() { Value::Null } else { json!(s.auth_users) },
        "oauthUsers": Value::Null,
        "ipMode": if s.allowed_ips.is_empty() && s.denied_ips.is_empty() { "off" } else { "manual" },
        "ipList": s.allowed_ips, "ipDenyList": s.denied_ips,
        "ipSets": s.allow_ip_lists, "ipDenySets": s.deny_ip_lists,
        "forwardAuth": {"url": s.forward_auth_url, "loginUrl": "", "copyHeaders": s.pass_user_headers},
        "rules": [], "shareLinks": [], "lbPolicy": s.load_balance,
        "health": {"path": s.health_check_path, "interval": 30, "timeout": 5},
        "rateLimit": {"enable": s.rate_limit_per_min > 0, "perMinute": s.rate_limit_per_min, "burst": 0},
        "cache": {"enable": s.cache_ttl_secs > 0, "ttl": s.cache_ttl_secs},
        "rewrites": [], "errorPage": s.error_page, "loginStyle": s.error_page_style,
        "knockRequired": s.knock_required, "group": s.group, "remark": s.remark
    })
}

fn site_from_value(v: &Value, id: &str, listener: &str) -> Value {
    let mut m = obj(&map_keys(&strip_runtime(v), snake));
    m.insert("id".into(), json!(id));
    m.insert("listener".into(), json!(listener));
    if let Some(name) = m.remove("name") { if m.get("id").is_none() { m.insert("id".into(), name); } }
    let kind = get_str(v, "type");
    m.insert("kind".into(), json!(if kind == "static" || kind == "text" { kind } else { "proxy".to_string() }));
    if let Some(t) = get_arr(v, "targets").first() { m.insert("backend".into(), t.clone()); }
    let root = get_str(v, "root");
    if !root.is_empty() { m.insert("static_root".into(), json!(root)); }
    if let Some(rate) = v.get("rateLimit") { m.insert("rate_limit_per_min".into(), rate.get("perMinute").cloned().unwrap_or_else(|| json!(0))); }
    if let Some(cache) = v.get("cache") { m.insert("cache_ttl_secs".into(), cache.get("ttl").cloned().unwrap_or_else(|| json!(0))); }
    let rules = get_arr(v, "locations").into_iter().map(|r| {
        let action = get_str(&r, "type");
        let action = if action.is_empty() { "proxy".to_string() } else { action };
        json!({
            "matcher": get_str(&r, "matcher"), "value": get_str(&r, "value"),
            "action": action, "target": get_str(&r, "target")
        })
    }).collect::<Vec<_>>();
    m.insert("path_rules".into(), Value::Array(rules));
    Value::Object(m)
}

fn settings_value(cfg: &Config) -> Value {
    json!({
        "listen": cfg.admin.listen, "httpsListen": cfg.admin.admin_tls_listen,
        "forceHTTPS": false, "safePath": cfg.admin.secure_path, "lanOnly": cfg.admin.lan_only,
        "denyMode": if cfg.admin.unauthorized_response.starts_with('<') { "custom" } else { "" },
        "denyStatus": 401, "denyPage": cfg.admin.unauthorized_response,
        "gatewaySSO": false, "gatewayAvailable": false,
        "disableProxyHeaders": cfg.admin.trusted_proxies.is_empty(),
        "trustedProxies": cfg.admin.trusted_proxies,
        "maxLoginFailures": cfg.auth.login_rate_limit, "lockMinutes": cfg.auth.lockout_secs / 60,
        "loginGlobalLimit": 20, "confirmTimeout": 0,
        "timeZone": cfg.system.timezone, "language": "zh-CN",
        "dnsServers": cfg.system.dns_servers, "updateProxy": "",
        "restrictOutbound": false, "disableUpdateCheck": !cfg.system.update_check,
        "logLines": 500, "disableLogPersist": false, "logFileMB": 2,
        "accessLogDays": 7, "accessLogMB": 20, "logDir": "",
        "gcPercent": 100, "maxProcs": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "thirdLogin": {"enable": !cfg.auth.oidc.is_empty(), "callbackBase": "", "providers": cfg.auth.oidc.iter().map(|p| json!({
            "key": p.id, "name": p.name, "type": "oidc", "clientId": p.client_id, "clientSecret": p.client_secret,
            "issuer": p.issuer, "proxy": ""})).collect::<Vec<_>>(), "allowed": cfg.auth.oidc_allowed_users, "skipTotp": false},
        "disabledModules": cfg.system.disabled_modules,
        "modules": MODULES.iter().map(|id| json!({"id": id, "title": id})).collect::<Vec<_>>(),
        "sessionHours": 24,
        "restartRequired": false
    })
}

async fn api_dispatch(State(state): State<AppState>, req: Request<Body>) -> Response {
    let mut path = req.uri().path().to_string();
    // axum strips the `/api` prefix before invoking a nested router's fallback.
    if !path.starts_with("/api/") { path = format!("/api{}", path); }
    let method = req.method().to_string();
    let query = req.uri().query().map(str::to_string);
    let body = match read_body(req).await { Ok(v) => v, Err(e) => return e };

    if let Some(r) = generic_crud(&state, &path, &method, body.clone(), query.as_deref()).await { return r; }

    if path == "/api/status" && method == "GET" {
        return json_response(status_value(&*state.config.read().await));
    }
    if path == "/api/session" && method == "GET" { return compat_session().await; }
    if path == "/api/account" && method == "POST" {
        return json_response(json!({"ok": true}));
    }
    if path == "/api/system/settings" {
        if method == "GET" { return json_response(settings_value(&*state.config.read().await)); }
        if method == "PUT" {
            let m = obj(&body);
            let r = edit_config(&state, |root| {
                let cfg = root.as_object_mut().unwrap();
                if let Some(v) = m.get("listen") { cfg["admin"]["listen"] = v.clone(); }
                if let Some(v) = m.get("httpsListen") { cfg["admin"]["admin_tls_listen"] = v.clone(); }
                if let Some(v) = m.get("safePath") { cfg["admin"]["secure_path"] = v.clone(); }
                if let Some(v) = m.get("lanOnly") { cfg["admin"]["lan_only"] = v.clone(); }
                if let Some(v) = m.get("timeZone") { cfg["system"]["timezone"] = v.clone(); }
                if let Some(v) = m.get("dnsServers") { cfg["system"]["dns_servers"] = v.clone(); }
                if let Some(v) = m.get("disabledModules") { cfg["system"]["disabled_modules"] = v.clone(); }
                if let Some(v) = m.get("maxLoginFailures") { cfg["auth"]["login_rate_limit"] = v.clone(); }
                if let Some(v) = m.get("lockMinutes") {
                    cfg["auth"]["lockout_secs"] = json!(v.as_u64().unwrap_or(0) * 60);
                }
                if let Some(v) = m.get("disableUpdateCheck") {
                    cfg["system"]["update_check"] = json!(!v.as_bool().unwrap_or(false));
                }
            }).await;
            return match r { Ok(()) => ok(), Err(e) => err(StatusCode::BAD_REQUEST, e) };
        }
    }
    if path == "/api/system/info" && method == "GET" {
        let cfg = state.config.read().await;
        return json_response(json!({
            "version": env!("CARGO_PKG_VERSION"), "commit": "gately-rs", "buildDate": "2026-11-24",
            "goVersion": "rust", "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "hostname": "gately-rs", "pid": std::process::id(), "startTime": chrono::Utc::now().to_rfc3339(),
            "configDir": state.config_path.to_string_lossy(), "goroutines": 0, "memSys": 0, "memAlloc": 0,
            "numCPU": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1), "maxProcs": 0,
            "timeZone": cfg.system.timezone, "inDocker": false,
            "selfUpgrade": {"supported": false, "reason": "os"}
        }));
    }
    if path.starts_with("/api/webservice/listeners") {
        if method == "GET" {
            return json_response(json!(web_listener_views(&*state.config.read().await)));
        }
        if method == "PUT" && seg_count(&path) == 4 {
            let key = path.rsplit('/').next().unwrap_or("").to_string();
            let cfg = state.config.read().await.clone();
            let mut listener = cfg.listeners.iter().find(|l| l.name == key)
                .and_then(|l| serde_json::to_value(l).ok()).unwrap_or_else(|| json!({"name": ""}));
            let (ip, port) = split_addr(&get_str(&body, "listenIp"));
            let port = if port.is_empty() { get_str(&body, "port") } else { port };
            let name = get_str(&body, "name");
            listener["name"] = json!(name);
            listener["listen"] = json!(format!("{}:{}", if ip.is_empty() { "0.0.0.0" } else { &ip }, if port.is_empty() { "0" } else { &port }));
            listener["tls_cert"] = if get_bool(&body, "tls") { json!("managed") } else { Value::Null };
            listener["http3"] = json!(get_bool(&body, "http3"));
            listener["proxy_protocol"] = json!(get_bool(&body, "acceptProxyProtocol"));
            let sites = get_arr(&body, "sites");
            let listener_name = name.clone();
            let r = edit_config(&state, |root| {
                let cfg = root.as_object_mut().unwrap();
                if let Some(arr) = cfg.get_mut("listeners").and_then(Value::as_array_mut) {
                    if let Some(x) = arr.iter_mut().find(|x| get_str(x, "name") == key) { *x = listener.clone(); }
                }
                let kept: Vec<Value> = sites.iter().enumerate().map(|(i, s)| {
                    let id = get_str(s, "key");
                    let site_id = if id.is_empty() { format!("site_{}_{i}", listener_name) } else { id };
                    site_from_value(s, &site_id, &listener_name)
                }).collect();
                if let Some(arr) = cfg.get_mut("sites").and_then(Value::as_array_mut) {
                    arr.retain(|x| get_str(x, "listener") != key);
                    arr.extend(kept);
                }
            }).await;
            return match r { Ok(()) => ok(), Err(e) => err(StatusCode::BAD_REQUEST, e) };
        }
    }
    if path == "/api/webservice/settings" {
        if method == "GET" {
            let cfg = state.config.read().await;
            return json_response(json!({
                "enable": true, "trustedProxies": cfg.admin.trusted_proxies,
                "realIPFrom": "x-forwarded-for", "realIPHeaders": ["X-Forwarded-For"], "realPortHeader": "X-Forwarded-Port",
                "oauthCallbackBase": "", "oauthProviders": [], "autoBanSeconds": cfg.jail.ban_secs,
                "authUsers": [], "ssoDomains": [], "oidc": [], "selfServicePassword": false, "authMarkerKey": ""
            }));
        }
        if method == "PUT" {
            let m = obj(&body);
            let r = edit_config(&state, |root| {
                if let Some(v) = m.get("trustedProxies") { root["admin"]["trusted_proxies"] = v.clone(); }
                if let Some(v) = m.get("autoBanSeconds") { root["jail"]["ban_secs"] = v.clone(); }
            }).await;
            return match r { Ok(()) => ok(), Err(e) => err(StatusCode::BAD_REQUEST, e) };
        }
    }
    if path == "/api/ssl/settings" {
        let cfg = state.config.read().await;
        return json_response(json!({"enable": true, "renewBeforeDays": 30, "shortLivedRenewHours": 0, "defaultEmail": cfg.acme.first().map(|a| a.email.clone()).unwrap_or_default()}));
    }
    if path == "/api/ssl/providers" { return json_response(json!([])); }
    if path == "/api/ssl/deploy-targets" { return json_response(json!({"ssh":[],"containers":[]})); }
    if path == "/api/ssl/fnos-certs" { return json_response(json!({"available":false,"certs":[]})); }
    if path == "/api/waf/crs" { return json_response(json!([])); }
    if path == "/api/guard/status" {
        let cfg = state.config.read().await;
        return json_response(json!({
            "firewall": {"enabled": cfg.jail.enabled, "active": cfg.jail.enabled, "reason": "", "backend": cfg.jail.backend,
                "error": "", "version": "", "dropped": {}, "hits": {}, "openPorts": 0, "trapPorts": "", "trapSkipped": [], "redirect": null},
            "bans": state.banned_ips.read().await.len(), "userTrapPorts": cfg.jail.trap_ports,
            "platform": {"os": std::env::consts::OS, "inDocker": false, "journal": true, "docker": true}
        }));
    }
    if path == "/api/guard/settings" {
        let cfg = state.config.read().await;
        return json_response(json!({
            "firewall": cfg.jail.enabled, "banSeconds": cfg.jail.ban_secs, "increment": cfg.jail.escalation,
            "maxBanSeconds": cfg.jail.ban_secs * 8, "ignorePrivate": true, "ignoreList": cfg.jail.whitelist,
            "trap": {"enable": !cfg.jail.trap_ports.is_empty(), "ports": cfg.jail.trap_ports, "banSeconds": cfg.jail.ban_secs},
            "scan": {"enable": cfg.jail.port_scan_threshold > 0, "threshold": cfg.jail.port_scan_threshold, "excludePorts": [], "banSeconds": cfg.jail.ban_secs, "ipv6Strict": false}
        }));
    }
    if path == "/api/guard/bans" && method == "GET" {
        let bans = state.banned_ips.read().await;
        let rows = bans.values().map(|b| json!({"key": b.ip, "ip": b.ip, "reason": b.reason, "until": b.banned_until, "permanent": b.permanent})).collect::<Vec<_>>();
        return json_response(json!(rows));
    }
    if path == "/api/guard/presets" { return json_response(json!([])); }
    if path == "/api/guard/firewall/rules" { return json_response(json!({"rules": ""})); }
    if path == "/api/knock/status" {
        let cfg = state.config.read().await;
        return json_response(json!({
            "listening": cfg.knock.enabled, "port": 62201, "listenError": null, "openStatus": null,
            "firewall": {"needed": false, "active": false, "reason": "", "error": "", "backend": cfg.knock.backend,
                "ports": cfg.knock.rules.iter().flat_map(|r| r.ports.iter().map(|p| p.to_string())).collect::<Vec<_>>(),
                "dropped": 0, "allowed": 0, "noIPv6": false},
            "grants": [], "counters": {"accepted":0,"rejected":0,"ignored":0}
        }));
    }
    if path == "/api/knock/settings" {
        let cfg = state.config.read().await;
        return json_response(json!({"enable": cfg.knock.enabled, "port": 62201, "backend": cfg.knock.backend,
            "windowSeconds": cfg.knock.window_secs, "grantSeconds": cfg.knock.grant_ttl_secs}));
    }
    if path == "/api/knock/grants" && method == "GET" { return json_response(json!([])); }
    if path == "/api/knock/firewall/rules" { return json_response(json!({"rules": ""})); }
    if path == "/api/ddns/providers" || path == "/api/frp/providers" {
        return json_response(json!([{"name":"cloudflare","title":"Cloudflare","idLabel":"Zone ID","secretLabel":"API Token"},
            {"name":"dnspod","title":"DNSPod","idLabel":"ID","secretLabel":"Token"}]));
    }
    if path == "/api/ddns/netinterfaces" { return json_response(json!([])); }
    if path == "/api/ddns/defaults" { return json_response(json!({"ipv4URLs":["https://api.ipify.org"],"ipv6URLs":["https://api6.ipify.org"]})); }
    if path == "/api/notify/event-types" { return json_response(json!([])); }
    if path == "/api/notify/history" { return json_response(json!([])); }
    if path == "/api/notify/pending" { return json_response(json!([])); }
    if path == "/api/tokens/scopes" { return json_response(json!([])); }
    if path == "/api/webservice/panels" || path == "/api/webservice/iplists" { return json_response(json!([])); }
    if path == "/api/webservice/bans" { return json_response(json!([])); }
    if path == "/api/wol/bemfa" { return json_response(json!({"settings":{"enable":false,"uid":""},"status":{"connected":false,"topics":[]}})); }
    if path == "/api/wol/ssh-targets" { return json_response(json!([])); }
    if path == "/api/docker/info" { return json_response(json!({"version":"","apiVersion":"","containers":0,"images":0,"running":0})); }
    if path == "/api/docker/containers" { return json_response(json!([])); }
    if path == "/api/docker/images" { return json_response(json!([])); }
    if path == "/api/docker/volumes" || path == "/api/docker/networks" { return json_response(json!([])); }
    if path == "/api/docker/tasks" { return json_response(json!([])); }
    if path == "/api/docker/disk-usage" { return json_response(json!({"images":0,"containers":0,"volumes":0,"buildCache":0})); }
    if path == "/api/docker/settings" {
        let cfg = state.config.read().await;
        return json_response(json!({"host": cfg.docker.host, "mirrors": [], "registries": [], "autoCheckHours": 0}));
    }
    if path == "/api/terminal/settings" || path == "/api/webterminal/settings" {
        let cfg = state.config.read().await;
        return json_response(json!({"settings": {"allowLocalShell": cfg.terminal.allow_local_shell, "maxSessions": 10,
            "idleTimeout": cfg.terminal.idle_timeout_secs, "bufferSize": 10000, "heartbeatInterval": 30, "sessionKeepAlive": true}}));
    }
    if path == "/api/webterminal/sessions" || path == "/api/webterminal/connections"
        || path == "/api/webterminal/credentials" || path == "/api/webterminal/globalshortcuts"
        || path == "/api/webterminal/splitlayout" { return json_response(json!([])); }
    if path == "/api/webterminal/security" { return json_response(json!({"agreementAccepted":true,"twoFAEnable":false,"verified":true})); }
    if path == "/api/backup/settings" {
        let cfg = state.config.read().await;
        return json_response(json!({"enable": cfg.backups.enabled, "cron": cfg.backups.cron, "keep": cfg.backups.keep, "directory": cfg.backups.directory, "targets": []}));
    }
    if path == "/api/backup/targets" || path == "/api/backup/mounts" { return json_response(json!([])); }
    if path == "/api/backup/status" { return json_response(json!({"running": false, "lastAt": null, "lastError": ""})); }
    if path == "/api/system/storage" { return json_response(json!({"total": 0, "used": 0, "free": 0, "config": 0, "logs": 0})); }
    if path == "/api/system/onboarding/scenes" { return json_response(json!([])); }
    if path == "/api/perf/snapshot" { return json_response(json!({"cpu":0,"memory":0,"disk":0,"net":{}})); }
    if path == "/api/filebrowser/status" {
        let cfg = state.config.read().await;
        return json_response(json!({"enable": cfg.filebrowser.enabled, "running": cfg.filebrowser.enabled, "url": cfg.filebrowser.base_url, "error": ""}));
    }
    if path == "/api/smb/status" {
        let cfg = state.config.read().await;
        return json_response(json!({"enable": cfg.smb.enabled, "running": cfg.smb.enabled, "shares": cfg.smb.shares.len(), "error": ""}));
    }

    // Sensible defaults for the remaining upstream endpoints.
    if method == "GET" {
        if path.contains("/settings") || path.contains("/status") || path.contains("/info") || path.contains("/state") {
            return json_response(json!({}));
        }
        return json_response(json!([]));
    }
    ok()
}

fn seg_count(path: &str) -> usize { path.split('/').filter(|s| !s.is_empty()).count() }

async fn static_asset(req: Request<Body>) -> Response {
    let path = req.uri().path();
    let rel = path.trim_start_matches('/');
    let mut gzipped = false;
    let (name, bytes) = if rel.is_empty() || rel == "index.html" {
        ("index.html", INDEX_HTML)
    } else {
        match ASSETS.iter().find(|(n, _, _)| *n == rel) {
            Some((_, b, _)) => (rel, *b),
            None => {
                let compressed = format!("{rel}.gz");
                if let Some((_, b, _)) = ASSETS.iter().find(|(n, _, _)| *n == compressed) {
                    gzipped = true;
                    (rel, *b)
                } else if rel.contains('.') {
                    return (StatusCode::NOT_FOUND, "not found").into_response();
                } else {
                    ("index.html", INDEX_HTML)
                }
            }
        }
    };
    let mime = if name.ends_with(".html") { "text/html; charset=utf-8" }
        else if name.ends_with(".js") { "text/javascript; charset=utf-8" }
        else if name.ends_with(".css") { "text/css; charset=utf-8" }
        else if name.ends_with(".svg") { "image/svg+xml" }
        else if name.ends_with(".json") || name.ends_with(".webmanifest") { "application/json" }
        else if name.ends_with(".png") { "image/png" }
        else if name.ends_with(".ico") { "image/x-icon" }
        else if name.ends_with(".woff2") { "font/woff2" }
        else { "application/octet-stream" };
    let mut builder = Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, mime);
    if gzipped { builder = builder.header("Content-Encoding", "gzip"); }
    builder.body(Body::from(bytes)).unwrap()
}

pub fn router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/api/login", post(compat_login))
        .route("/api/logout", post(compat_logout))
        .route("/api/login/providers", get(compat_providers))
        .route("/api/demo", get(|| async { Json(json!({"enabled": false})) }))
        .route("/api/session", get(compat_session))
        .route("/set-cookie", get(token_cookie));

    let protected = Router::new()
        .fallback(api_dispatch)
        .layer(middleware::from_fn_with_state(state.clone(), compat_auth));

    Router::new()
        .route("/", get(static_asset))
        .route("/index.html", get(static_asset))
        .merge(public)
        .nest("/api", protected)
        .fallback(static_asset)
}

pub async fn index_html() -> Response {
    Response::builder().status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(INDEX_HTML))
        .unwrap()
}

/// The Vue build links its assets relatively (`./assets/index-*.js`). When the
/// page is opened at `/gately` (no trailing slash), the browser resolves those
/// URLs to `/assets/...`, which 404s and leaves an empty `#app`. Redirect every
/// such entry to `/gately/` so relative paths resolve inside the mount point.
async fn trailing_slash(req: Request<Body>, next: Next) -> Response {
    // Use OriginalUri so a configured admin.secure_path prefix is preserved.
    let path = req.extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|u| u.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let location = if path == BASE {
        Some(format!("{path}/"))
    } else {
        path.strip_suffix("/index.html").map(|p| format!("{p}/"))
    };
    if let Some(mut location) = location {
        if let Some(query) = req.uri().query() {
            location.push('?');
            location.push_str(query);
        }
        return Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", location)
            .body(Body::empty())
            .unwrap();
    }
    next.run(req).await
}

pub fn mount(app: Router<AppState>, state: &AppState) -> Router<AppState> {
    app.route("/gately/", get(index_html))
        .nest(BASE, router(state.clone()))
        .layer(middleware::from_fn(trailing_slash))
}
