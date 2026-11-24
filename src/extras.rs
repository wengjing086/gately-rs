//! Extra modules that fill the remaining upstream Gately navigation positions:
//! Wake-on-LAN, storage mounts, File Browser, SMB sharing and performance monitoring.
//!
//! All handlers are mounted under `/api` by `admin.rs`. State lives in `config`,
//! so every change is covered by the existing snapshot/backup machinery.

use crate::config::{FileBrowserConfig, PerfConfig, SmbConfig, StorageMount, WolConfig, WolHost};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

fn bad(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}
fn gone(msg: impl Into<String>) -> Response {
    (StatusCode::NOT_FOUND, msg.into()).into_response()
}
fn fail(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_GATEWAY, msg.into()).into_response()
}

/// Parse a MAC address into six octets. Accepts `aa:bb:cc:dd:ee:ff`,
/// `aa-bb-cc-dd-ee-ff` and `aabb.ccdd.eeff`.
fn parse_mac(input: &str) -> Result<[u8; 6], String> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 12 {
        return Err(format!("MAC 地址无效: {input}"));
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("MAC 地址无效: {input}"))?;
    }
    Ok(out)
}

/// Build and send a Wake-on-LAN magic packet: 6 x 0xFF followed by the MAC repeated 16 times.
fn send_magic_packet(host: &WolHost, port: u16) -> Result<(), String> {
    let mac = parse_mac(&host.mac)?;
    let mut packet = Vec::with_capacity(102);
    packet.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    let broadcast = if host.broadcast.is_empty() {
        Ipv4Addr::BROADCAST
    } else {
        host.broadcast
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("广播地址无效: {}", host.broadcast))?
    };
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
    socket.set_broadcast(true).map_err(|e| e.to_string())?;
    socket
        .send_to(&packet, SocketAddrV4::new(broadcast, port))
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Wake-on-LAN
// ---------------------------------------------------------------------------

pub async fn wol_config(State(state): State<AppState>) -> Response {
    let cfg = state.config.read().await;
    Json(serde_json::to_value(&cfg.wol).unwrap_or_else(|_| json!({}))).into_response()
}

pub async fn wol_hosts(State(state): State<AppState>) -> Response {
    let cfg = state.config.read().await;
    Json(serde_json::to_value(&cfg.wol.hosts).unwrap_or_else(|_| json!([]))).into_response()
}

pub async fn wol_wake(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let cfg = state.config.read().await;
    if !cfg.wol.enabled {
        return (StatusCode::FORBIDDEN, "网络唤醒模块未启用").into_response();
    }
    let host = match cfg.wol.hosts.iter().find(|h| h.id == id) {
        Some(h) => h.clone(),
        None => return gone(format!("主机不存在: {id}")),
    };
    let port = cfg.wol.port;
    drop(cfg);
    match send_magic_packet(&host, port) {
        Ok(()) => Json(json!({ "ok": true, "id": id, "mac": host.mac })).into_response(),
        Err(err) => fail(format!("唤醒失败: {err}")).into_response(),
    }
}

pub async fn wol_wake_mac(State(state): State<AppState>, Json(body): Json<Value>) -> Response {
    let cfg = state.config.read().await;
    if !cfg.wol.enabled {
        return (StatusCode::FORBIDDEN, "网络唤醒模块未启用").into_response();
    }
    let port = cfg.wol.port;
    drop(cfg);
    let mac = body.get("mac").and_then(|v| v.as_str()).unwrap_or("");
    if mac.is_empty() {
        return bad("缺少 mac 参数");
    }
    let broadcast = body.get("broadcast").and_then(|v| v.as_str()).unwrap_or("");
    let host = WolHost {
        id: "transient".into(),
        name: "transient".into(),
        mac: mac.to_string(),
        broadcast: broadcast.to_string(),
        remark: String::new(),
    };
    match send_magic_packet(&host, port) {
        Ok(()) => Json(json!({ "ok": true, "mac": mac })).into_response(),
        Err(err) => fail(format!("唤醒失败: {err}")).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Storage mounts
// ---------------------------------------------------------------------------

pub async fn storage_list(State(state): State<AppState>) -> Response {
    let cfg = state.config.read().await;
    Json(serde_json::to_value(&cfg.storage).unwrap_or_else(|_| json!([]))).into_response()
}

/// Check whether a mount's local path exists / remote URL is configured.
/// No network probe is performed to keep this endpoint fast and side-effect free.
pub async fn storage_check(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let cfg = state.config.read().await;
    let mount: StorageMount = match cfg.storage.iter().find(|m| m.id == id) {
        Some(m) => m.clone(),
        None => return gone(format!("挂载不存在: {id}")),
    };
    drop(cfg);
    let (reachable, detail) = match mount.kind.as_str() {
        "local" | "" => {
            let p = std::path::Path::new(&mount.path);
            (p.exists(), format!("本地路径 {}", if p.exists() { "存在" } else { "不存在" }))
        }
        "webdav" | "smb" => (
            !mount.url.is_empty(),
            if mount.url.is_empty() { "未配置远程地址".into() } else { format!("远程地址 {}", mount.url) },
        ),
        other => (false, format!("未知挂载类型: {other}")),
    };
    Json(json!({ "id": id, "ok": reachable, "detail": detail })).into_response()
}

// ---------------------------------------------------------------------------
// File Browser
// ---------------------------------------------------------------------------

pub async fn filebrowser_config(State(state): State<AppState>) -> Response {
    let cfg = state.config.read().await;
    Json(serde_json::to_value(&cfg.filebrowser).unwrap_or_else(|_| json!({}))).into_response()
}

pub async fn filebrowser_status(State(state): State<AppState>) -> Response {
    let cfg: FileBrowserConfig = state.config.read().await.filebrowser.clone();
    let root_ok = !cfg.root.is_empty() && std::path::Path::new(&cfg.root).is_dir();
    Json(json!({
        "enabled": cfg.enabled,
        "listen": cfg.listen,
        "root": cfg.root,
        "root_ok": root_ok,
        "readonly": cfg.readonly,
        "users": cfg.users.len(),
        "url": if cfg.enabled { format!("http://{}{}", cfg.listen, cfg.base_url) } else { String::new() },
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// SMB
// ---------------------------------------------------------------------------

pub async fn smb_config(State(state): State<AppState>) -> Response {
    let cfg = state.config.read().await;
    Json(serde_json::to_value(&cfg.smb).unwrap_or_else(|_| json!({}))).into_response()
}

pub async fn smb_status(State(state): State<AppState>) -> Response {
    let cfg: SmbConfig = state.config.read().await.smb.clone();
    let shares = cfg
        .shares
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "path": s.path,
                "readonly": s.readonly,
                "exists": std::path::Path::new(&s.path).is_dir(),
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "enabled": cfg.enabled,
        "workgroup": cfg.workgroup,
        "shares": shares,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Performance monitoring
// ---------------------------------------------------------------------------

pub async fn perf_config(State(state): State<AppState>) -> Response {
    let cfg: PerfConfig = state.config.read().await.perf.clone();
    Json(serde_json::to_value(cfg).unwrap_or_else(|_| json!({}))).into_response()
}

/// Current performance snapshot. Reuses the OS-level metrics already collected
/// by `metrics::system_info()` and adds thresholds from configuration.
pub async fn perf_snapshot(State(state): State<AppState>) -> Response {
    let cfg: PerfConfig = state.config.read().await.perf.clone();
    let mut info = crate::metrics::system_info().await;
    if let Some(obj) = info.as_object_mut() {
        let cpu = obj.get("cpu_usage_percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let mem = obj.get("memory_usage_percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
        obj.insert("cpu_warn".into(), json!(cfg.cpu_warn));
        obj.insert("mem_warn".into(), json!(cfg.mem_warn));
        obj.insert("disk_warn".into(), json!(cfg.disk_warn));
        obj.insert("cpu_alert".into(), json!(cpu >= cfg.cpu_warn));
        obj.insert("mem_alert".into(), json!(mem >= cfg.mem_warn));
        obj.insert("interval_secs".into(), json!(cfg.interval_secs));
        obj.insert("enabled".into(), json!(cfg.enabled));
    }
    Json(info).into_response()
}

/// Aggregate module availability for the "About" / settings pages.
pub async fn modules_status(State(state): State<AppState>) -> Response {
    let cfg = state.config.read().await;
    let w: WolConfig = cfg.wol.clone();
    let fb: FileBrowserConfig = cfg.filebrowser.clone();
    let smb: SmbConfig = cfg.smb.clone();
    let perf: PerfConfig = cfg.perf.clone();
    Json(json!({
        "wol": { "enabled": w.enabled, "hosts": w.hosts.len() },
        "storage": { "mounts": cfg.storage.len() },
        "filebrowser": { "enabled": fb.enabled },
        "smb": { "enabled": smb.enabled, "shares": smb.shares.len() },
        "perf": { "enabled": perf.enabled }
    }))
    .into_response()
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/wol/config", axum::routing::get(wol_config))
        .route("/wol/hosts", axum::routing::get(wol_hosts))
        .route("/wol/wake/{id}", axum::routing::post(wol_wake))
        .route("/wol/wake", axum::routing::post(wol_wake_mac))
        .route("/storage", axum::routing::get(storage_list))
        .route("/storage/check/{id}", axum::routing::get(storage_check))
        .route("/filebrowser/config", axum::routing::get(filebrowser_config))
        .route("/filebrowser/status", axum::routing::get(filebrowser_status))
        .route("/smb/config", axum::routing::get(smb_config))
        .route("/smb/status", axum::routing::get(smb_status))
        .route("/perf/config", axum::routing::get(perf_config))
        .route("/perf/snapshot", axum::routing::get(perf_snapshot))
        .route("/modules/status", axum::routing::get(modules_status))
}
