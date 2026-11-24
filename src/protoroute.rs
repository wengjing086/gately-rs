use crate::config::{Config, ProtoRouteRule, ProtoRouteTask};
use crate::state::AppState;
use crate::waf;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Default)]
struct Sniff {
    sni: String,
    alpn: Vec<String>,
    host: String,
    minecraft_host: String,
    protocol: String,
}

fn read_u16(b: &[u8], i: usize) -> Option<u16> { Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?])) }

fn parse_varint(b: &[u8], i: &mut usize) -> Option<usize> {
    let mut value = 0usize; let mut shift = 0;
    loop {
        let byte = *b.get(*i)?; *i += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 { return Some(value); }
        shift += 7;
        if shift > 28 { return None; }
    }
}

fn sniff_tls(buf: &[u8]) -> Sniff {
    let mut out = Sniff::default();
    if buf.len() < 5 || buf[0] != 0x16 { return out; }
    let len = read_u16(buf, 3).unwrap_or(0) as usize;
    if buf.len() < len + 5 || *buf.get(5).unwrap_or(&0) != 0x01 { return out; }
    let handshake_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
    if handshake_len + 9 > buf.len() { return out; }
    let mut i = 9usize;
    i += 2; // client version
    i += 32; // random
    if i >= buf.len() { return out; }
    let session_len = buf[i] as usize; i += 1 + session_len;
    let cipher_len = read_u16(buf, i).unwrap_or(0) as usize; i += 2 + cipher_len;
    let comp_len = read_u16(buf, i).unwrap_or(0) as usize; i += 2 + comp_len;
    if i + 2 > buf.len() { return out; }
    let ext_len = read_u16(buf, i).unwrap_or(0) as usize; i += 2;
    let end = (i + ext_len).min(buf.len());
    while i + 4 <= end {
        let typ = read_u16(buf, i).unwrap_or(0); let len = read_u16(buf, i + 2).unwrap_or(0) as usize; i += 4;
        if i + len > end { break; }
        if typ == 0 && len >= 5 {
            let mut p = i + 1;
            let list_len = read_u16(buf, p).unwrap_or(0) as usize; p += 2;
            let stop = (p + list_len).min(i + len);
            while p + 3 <= stop {
                let name_len = read_u16(buf, p + 1).unwrap_or(0) as usize;
                if p + 3 + name_len <= stop {
                    out.sni = String::from_utf8_lossy(&buf[p + 3..p + 3 + name_len]).to_string();
                    break;
                }
                p += 3 + name_len;
            }
        }
        if typ == 16 && i + 2 <= end {
            let list_len = read_u16(buf, i + 1).unwrap_or(0) as usize;
            let mut p = i + 3;
            let stop = (p + list_len).min(i + len);
            while p + 1 <= stop {
                let n = buf[p] as usize; p += 1;
                if p + n <= stop { out.alpn.push(String::from_utf8_lossy(&buf[p..p + n]).to_string()); p += n; }
            }
        }
        i += len;
    }
    out.protocol = "tls".into();
    out
}

fn sniff_http(buf: &[u8]) -> Option<Sniff> {
    let text = String::from_utf8_lossy(buf);
    if !text.starts_with("GET ") && !text.starts_with("POST ") && !text.starts_with("HEAD ")
        && !text.starts_with("PUT ") && !text.starts_with("OPTIONS ") && !text.starts_with("CONNECT ") { return None; }
    let host = text.lines().find_map(|l| {
        let lower = l.to_ascii_lowercase();
        lower.strip_prefix("host:").map(|v| v.trim().to_string())
    }).unwrap_or_default();
    let mut out = Sniff { host, protocol: "http".into(), ..Default::default() };
    if text.starts_with("OPTIONS ") || text.contains("rtsp://") { out.protocol = "rtsp".into(); }
    if text.starts_with("REGISTER ") || text.starts_with("INVITE ") { out.protocol = "sip".into(); }
    if text.contains("<stream:stream") { out.protocol = "xmpp".into(); }
    Some(out)
}

fn sniff_minecraft(buf: &[u8]) -> Option<Sniff> {
    if buf.first() != Some(&0x00) { return None; }
    let mut i = 1usize;
    let _protocol = parse_varint(buf, &mut i)?;
    let len = parse_varint(buf, &mut i)?;
    if i + len > buf.len() { return None; }
    let host = String::from_utf8_lossy(&buf[i..i + len]).to_string();
    Some(Sniff { minecraft_host: host.clone(), protocol: "minecraft".into(), host, ..Default::default() })
}

fn sniff(buf: &[u8]) -> Sniff {
    if let Some(s) = sniff_http(buf) { return s; }
    if buf.starts_with(&[0x16, 0x03]) { return sniff_tls(buf); }
    if let Some(s) = sniff_minecraft(buf) { return s; }
    let text = String::from_utf8_lossy(buf);
    let protocol = if text.starts_with("SSH-") { "ssh" }
        else if buf.starts_with(&[0x03, 0x00, 0x00]) { "rdp" }
        else if buf.first() == Some(&0x05) || buf.first() == Some(&0x04) { "socks" }
        else if text.starts_with("host:") || text.starts_with("HOST:") { "adb" }
        else if text.starts_with("NICK ") || text.starts_with("USER ") { "irc" }
        else if text.starts_with("PING") || text.starts_with("AUTH") || text.starts_with("*") { "redis" }
        else if text.starts_with("AMQP") { "amqp" }
        else if text.starts_with("GIT-") { "git" }
        else if buf.len() > 20 && &buf[1..20] == b"BitTorrent protocol" { "bittorrent" }
        else if buf.starts_with(&[0x00, 0x00, 0x00]) && buf.get(4) == Some(&0x04) { "postgresql" }
        else if buf.len() >= 4 && &buf[..4] == b"\x00\x00SMB" { "smb" }
        else if buf.first() == Some(&0x00) || buf.first() == Some(&0x20) { "openvpn" }
        else { "" };
    Sniff { protocol: protocol.to_string(), ..Default::default() }
}

fn route_matches(rule: &ProtoRouteRule, s: &Sniff) -> bool {
    let value = rule.value.trim().to_ascii_lowercase();
    match rule.matcher.as_str() {
        "sni" => !s.sni.is_empty() && (value == "*" || s.sni.to_ascii_lowercase() == value || s.sni.to_ascii_lowercase().ends_with(&format!(".{}", value.trim_start_matches('.')))),
        "alpn" => s.alpn.iter().any(|a| a.eq_ignore_ascii_case(&value)),
        "http_host" => !s.host.is_empty() && (value == "*" || s.host.to_ascii_lowercase() == value),
        "minecraft" => !s.minecraft_host.is_empty() && (value == "*" || s.minecraft_host.to_ascii_lowercase() == value),
        "protocol" => s.protocol.eq_ignore_ascii_case(&value),
        _ => false,
    }
}

fn proxy_header(proto: &str, client: SocketAddr, target: SocketAddr) -> Vec<u8> {
    if proto.is_empty() || proto == "off" { return Vec::new(); }
    let family = if client.is_ipv4() { "TCP4" } else { "TCP6" };
    format!("PROXY {family} {} {} {} {}\r\n", client.ip(), target.ip(), client.port(), target.port()).into_bytes()
}

async fn source_allowed(state: &AppState, task: &ProtoRouteTask, ip: &str) -> bool {
    if task.source_deny.iter().any(|p| waf::ip_match(p, ip)) { return false; }
    let deny_lists = {
        let cfg = state.config.read().await;
        task.source_deny.iter().any(|pattern| {
            cfg.ip_lists.iter().find(|l| &l.id == pattern)
                .is_some_and(|l| l.entries.iter().any(|e| waf::ip_match(e, ip)))
        })
    };
    if deny_lists { return false; }
    if !task.source_allow.is_empty() && !task.source_allow.iter().any(|p| waf::ip_match(p, ip)) {
        // 允许列表也可以引用 IP 列表 ID。
        let allowed_by_list = {
            let cfg = state.config.read().await;
            task.source_allow.iter().any(|pattern| {
                cfg.ip_lists.iter().find(|l| &l.id == pattern)
                    .is_some_and(|l| l.entries.iter().any(|e| waf::ip_match(e, ip)))
            })
        };
        if !allowed_by_list { return false; }
    }
    if let Some(grant) = state.knock_grants.read().await.values().find(|g| g.ip == ip && g.until > Utc::now()) {
        let _ = grant;
    }
    true
}

async fn handle_connection(state: AppState, task: ProtoRouteTask, mut client: TcpStream, peer: SocketAddr) {
    let ip = peer.ip().to_string();
    if !source_allowed(&state, &task, &ip).await { return; }
    let wait = task.wait_timeout_secs.max(1) as u64;
    let mut first = vec![0u8; 8192];
    let n = match tokio::time::timeout(StdDuration::from_secs(wait), client.read(&mut first)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => 0,
        Ok(Ok(n)) => n,
    };
    first.truncate(n);
    let sniffed = sniff(&first);
    let rule: Option<ProtoRouteRule> = task.routes.iter().find(|r| route_matches(r, &sniffed)).cloned();
    let (target_str, proto, knock) = match &rule {
        Some(r) => (r.target.clone(), r.proxy_protocol.clone(), r.knock_required),
        None => (task.default_target.clone(), String::new(), false),
    };
    if target_str.is_empty() { return; }
    if knock && !state.knock_grants.read().await.values().any(|g| g.ip == ip && g.until > Utc::now()) { return; }
    let target = match tokio::net::lookup_host(&target_str).await {
        Ok(mut addrs) => match addrs.next() { Some(a) => a, None => return },
        Err(_) => return,
    };
    let mut backend = match TcpStream::connect(target).await { Ok(s) => s, Err(_) => return };
    let header = proxy_header(&proto, peer, target);
    if !header.is_empty() && backend.write_all(&header).await.is_err() { return; }
    if !first.is_empty() && backend.write_all(&first).await.is_err() { return; }
    {
        let mut stats = state.route_stats.write().await;
        let e = stats.entry(task.id.clone()).or_default();
        e.connections += 1; e.active += 1; e.bytes_in += first.len() as u64;
    }
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut br, mut bw) = tokio::io::split(backend);
    let id = task.id.clone();
    let state_c = state.clone(); let id_c = id.clone();
    let c2b = async {
        let mut buf = vec![0u8; 32768];
        while let Ok(n) = cr.read(&mut buf).await {
            if n == 0 || bw.write_all(&buf[..n]).await.is_err() { break; }
            state_c.route_stats.write().await.entry(id_c.clone()).or_default().bytes_in += n as u64;
        }
    };
    let state_b = state.clone(); let id_b = id.clone();
    let b2c = async {
        let mut buf = vec![0u8; 32768];
        while let Ok(n) = br.read(&mut buf).await {
            if n == 0 || cw.write_all(&buf[..n]).await.is_err() { break; }
            state_b.route_stats.write().await.entry(id_b.clone()).or_default().bytes_out += n as u64;
        }
    };
    tokio::select! { _ = c2b => {}, _ = b2c => {} }
    let mut stats = state.route_stats.write().await;
    let entry = stats.entry(id).or_default();
    entry.active = entry.active.saturating_sub(1);
}

fn spawn_listener(state: AppState, task: ProtoRouteTask) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&task.listen).await {
            Ok(l) => l,
            Err(err) => { eprintln!("[route {}] bind: {err}", task.id); return; }
        };
        loop {
            let (client, peer) = match listener.accept().await { Ok(v) => v, Err(_) => break };
            let task = task.clone(); let state = state.clone();
            tokio::spawn(async move { handle_connection(state, task, client, peer).await });
        }
    })
}

pub fn spawn_proto_route_supervisor(state: AppState) {
    tokio::spawn(async move {
        let mut running: HashMap<String, (String, tokio::task::JoinHandle<()>)> = HashMap::new();
        loop {
            let config: Config = state.config.read().await.clone();
            let mut seen = Vec::new();
            for task in config.proto_routes.into_iter().filter(|t| t.enabled) {
                seen.push(task.id.clone());
                let sig = serde_json::to_string(&task).unwrap_or_default();
                if running.get(&task.id).is_some_and(|(old, _)| old == &sig) { continue; }
                if let Some((_, h)) = running.remove(&task.id) { h.abort(); }
                running.insert(task.id.clone(), (sig, spawn_listener(state.clone(), task)));
            }
            let stale: Vec<String> = running.keys().filter(|id| !seen.contains(id)).cloned().collect();
            for id in stale { if let Some((_, h)) = running.remove(&id) { h.abort(); } }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
}

pub async fn status_handler(State(state): State<AppState>) -> Response {
    Json(state.route_stats.read().await.clone()).into_response()
}
