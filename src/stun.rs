use crate::state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::Utc;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command;

const MAGIC: u32 = 0x2112_A442;

fn parse_mapped(payload: &[u8]) -> Option<(String, u16)> {
    if payload.len() < 20 { return None; }
    let mut offset = 20;
    while offset + 4 <= payload.len() {
        let kind = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + len > payload.len() { break; }
        let value = &payload[offset..offset + len];
        if kind == 0x0020 && len >= 8 {
            let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
            let octets = [value[4] ^ 0x21, value[5] ^ 0x12, value[6] ^ 0xA4, value[7] ^ 0x42];
            return Some((octets.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."), port));
        }
        if kind == 0x0001 && len >= 8 {
            let port = u16::from_be_bytes([value[2], value[3]]);
            let octets = [value[4], value[5], value[6], value[7]];
            return Some((octets.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."), port));
        }
        offset += len + (4 - len % 4) % 4;
    }
    None
}

fn request() -> Vec<u8> {
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&MAGIC.to_be_bytes());
    packet.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    packet
}

pub async fn discover_udp(server: &str) -> Result<(String, u16), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| format!("bind udp: {e}"))?;
    sock.connect(server).await.map_err(|e| format!("connect stun: {e}"))?;
    sock.send(&request()).await.map_err(|e| format!("send stun: {e}"))?;
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await.map_err(|_| "stun timeout".to_string())?.map_err(|e| format!("recv stun: {e}"))?;
    if n < 20 || buf[4..8] != MAGIC.to_be_bytes() { return Err("bad stun response".into()); }
    parse_mapped(&buf[..n]).ok_or_else(|| "no mapped address".into())
}

pub async fn discover_tcp(server: &str) -> Result<(String, u16), String> {
    let mut sock = TcpStream::connect(server).await.map_err(|e| format!("connect stun tcp: {e}"))?;
    let req = request();
    let mut framed = Vec::with_capacity(req.len() + 2);
    framed.extend_from_slice(&(req.len() as u16).to_be_bytes());
    framed.extend_from_slice(&req);
    sock.write_all(&framed).await.map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), sock.read_exact(&mut len_buf)).await
        .map_err(|_| "stun tcp timeout".to_string())?.map_err(|e| e.to_string())?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len < 20 || len > 1500 { return Err("bad stun tcp length".into()); }
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    if buf[4..8] != MAGIC.to_be_bytes() { return Err("bad stun cookie".into()); }
    parse_mapped(&buf).ok_or_else(|| "no mapped address".into())
}

pub async fn discover_prefer(server: &str, protocol: &str) -> Result<(String, u16), String> {
    match protocol {
        "tcp" => discover_tcp(server).await,
        "both" => match discover_udp(server).await {
            Ok(v) => Ok(v),
            Err(udp_err) => discover_tcp(server).await.map_err(|tcp_err| format!("udp: {udp_err}; tcp: {tcp_err}")),
        },
        _ => discover_udp(server).await,
    }
}

async fn run_hook(state: &AppState, task: &crate::config::StunTask, ip: &str, port: u16) {
    for url in &task.webhooks {
        let replaced = url.replace("{ip}", ip).replace("{port}", &port.to_string());
        let _ = state.client.get(&replaced).send().await;
    }
    if !task.change_script.is_empty() {
        let mut parts = task.change_script.split_whitespace();
        if let Some(program) = parts.next() {
            let _ = Command::new(program).args(parts.collect::<Vec<_>>())
                .env("GATELY_PUBLIC_IP", ip).env("GATELY_PUBLIC_PORT", port.to_string()).status().await;
        }
    }
    if task.upnp {
        let _ = Command::new("upnpc").arg("-l").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await;
    }
    crate::notify::emit(state, "address.changed", &format!("{}:{}:{}", task.id, ip, port)).await;
}

pub fn spawn_stun_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let tasks = state.config.read().await.stun.clone();
            for task in tasks.into_iter().filter(|t| t.enabled) {
                let last = state.stun_status.read().await.get(&task.id).and_then(|s| s.last_run);
                let due = last.map(|t| (Utc::now() - t).num_seconds() as u64 >= task.interval_secs.max(30)).unwrap_or(true);
                if !due { continue; }
                match discover_prefer(&task.server, &task.protocol).await {
                    Ok((ip, port)) => {
                        let changed = {
                            let mut statuses = state.stun_status.write().await;
                            let entry = statuses.entry(task.id.clone()).or_default();
                            let changed = entry.public_ip.as_deref() != Some(ip.as_str()) || entry.public_port != Some(port);
                            entry.public_ip = Some(ip.clone());
                            entry.public_port = Some(port);
                            entry.last_run = Some(Utc::now());
                            entry.last_error = None;
                            entry.changed = changed;
                            changed
                        };
                        if changed { run_hook(&state, &task, &ip, port).await; }
                    }
                    Err(err) => {
                        let mut statuses = state.stun_status.write().await;
                        let entry = statuses.entry(task.id.clone()).or_default();
                        entry.last_run = Some(Utc::now());
                        entry.last_error = Some(err);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

pub async fn run_handler(State(state): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>) -> axum::response::Response {
    let task = state.config.read().await.stun.iter().find(|t| t.id == id).cloned();
    match task {
        Some(task) => match discover_prefer(&task.server, &task.protocol).await {
            Ok((ip, port)) => {
                let mut statuses = state.stun_status.write().await;
                let entry = statuses.entry(id).or_default();
                entry.public_ip = Some(ip.clone()); entry.public_port = Some(port);
                entry.last_run = Some(Utc::now()); entry.last_error = None;
                axum::Json(json!({"ok": true, "ip": ip, "port": port})).into_response()
            }
            Err(err) => (axum::http::StatusCode::BAD_GATEWAY, err).into_response(),
        },
        None => (axum::http::StatusCode::NOT_FOUND, "task not found").into_response(),
    }
}
