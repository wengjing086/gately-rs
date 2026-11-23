use crate::config::{Config, PortForwardTask};
use axum::extract::State;
use axum::response::IntoResponse;
use crate::state::{AppState, TrafficCounter};
use crate::waf;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;

fn expand_ports(listen: &str) -> Result<(String, Vec<u16>), String> {
    let (host, port_part) = listen.rsplit_once(':').ok_or_else(|| format!("invalid listen {listen}"))?;
    let ports = if let Some((a, b)) = port_part.split_once('-') {
        let a: u16 = a.parse().map_err(|_| "bad port")?;
        let b: u16 = b.parse().map_err(|_| "bad port")?;
        if a > b { return Err("bad port range".into()); }
        (a..=b).collect()
    } else {
        vec![port_part.parse::<u16>().map_err(|_| "bad port")?]
    };
    Ok((host.to_string(), ports))
}

fn ip_of(addr: SocketAddr) -> String { addr.ip().to_string() }

async fn list_contains(state: &AppState, list_ids: &[String], ip: &str) -> bool {
    if list_ids.is_empty() { return false; }
    let cfg = state.config.read().await;
    for id in list_ids {
        if let Some(list) = cfg.ip_lists.iter().find(|l| &l.id == id) {
            if list.entries.iter().any(|e| waf::ip_match(e, ip)) { return true; }
        }
        if let Some(status) = state.ip_list_status.read().await.get(id) {
            if status.entries > 0 && list_contains_runtime(state, id, ip).await { return true; }
        }
    }
    false
}

async fn list_contains_runtime(state: &AppState, id: &str, ip: &str) -> bool {
    let key = format!("__entries__{id}");
    let guard = state.ip_list_status.read().await;
    guard.get(&key).is_some_and(|_| true) && {
        drop(guard);
        let cfg = state.config.read().await;
        cfg.ip_lists.iter().find(|l| l.id == id)
            .is_some_and(|l| l.entries.iter().any(|e| waf::ip_match(e, ip)))
    }
}

async fn allowed_source(state: &AppState, task: &PortForwardTask, ip: &str) -> bool {
    if !task.source_deny.is_empty() && task.source_deny.iter().any(|p| waf::ip_match(p, ip)) { return false; }
    if list_contains(state, &task.source_deny, ip).await { return false; }
    if !task.source_allow.is_empty() && !task.source_allow.iter().any(|p| waf::ip_match(p, ip)) {
        if !list_contains(state, &task.source_allow, ip).await { return false; }
    }
    if task.knock_required {
        let grants = state.knock_grants.read().await;
        if !grants.values().any(|g| g.ip == ip && g.until > Utc::now()) { return false; }
    }
    true
}

async fn connection_ok(state: &AppState, task: &PortForwardTask, ip: &str) -> bool {
    let stats = state.forward_stats.read().await;
    let total = stats.get(&task.id).map(|s| s.active).unwrap_or(0);
    if task.max_connections > 0 && total >= task.max_connections { return false; }
    if let Some(max) = task.source_max_connections.get(ip) {
        let key = format!("{}:{ip}", task.id);
        if stats.get(&key).map(|s| s.active).unwrap_or(0) >= *max { return false; }
    }
    true
}

async fn pick_target(state: &AppState, task: &PortForwardTask) -> Result<SocketAddr, String> {
    let stats = state.forward_stats.read().await;
    let mut candidates: Vec<(u32, &String)> = task.targets.iter().enumerate()
        .map(|(i, t)| (i as u32, t)).collect();
    candidates.sort_by_key(|(i, _)| *i);
    for (_, target) in candidates {
        if let Ok(addr) = target.parse::<SocketAddr>() { return Ok(addr); }
        if let Ok(port) = target.parse::<u16>() { return Ok(SocketAddr::from(([127, 0, 0, 1], port))); }
        if let Ok(addrs) = tokio::net::lookup_host(target).await {
            if let Some(addr) = addrs.into_iter().next() { return Ok(addr); }
        }
        let key = format!("{}:{}", task.id, target);
        let failures = stats.get(&key).map(|s| s.errors).unwrap_or(0);
        if failures == 0 { continue; }
    }
    Err("no reachable target".into())
}

fn proxy_header(proto: &str, client: SocketAddr, target: SocketAddr) -> Vec<u8> {
    if proto == "off" || proto.is_empty() { return Vec::new(); }
    if proto == "v1" {
        let family = if client.ip().is_ipv4() { "TCP4" } else { "TCP6" };
        return format!("PROXY {family} {} {} {} {}\r\n", client.ip(), target.ip(), client.port(), target.port()).into_bytes();
    }
    let (ver_cmd, fam, addr) = match (client.ip(), target.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (0x21u8, 0x11u8, [&src.octets()[..], &dst.octets()[..], &client.port().to_be_bytes()[..], &target.port().to_be_bytes()[..]].concat()),
        _ => {
            let mut bytes = vec![];
            if let IpAddr::V6(src) = client.ip() { bytes.extend_from_slice(&src.octets()); } else { bytes.extend_from_slice(&[0; 16]); }
            if let IpAddr::V6(dst) = target.ip() { bytes.extend_from_slice(&dst.octets()); } else { bytes.extend_from_slice(&[0; 16]); }
            bytes.extend_from_slice(&client.port().to_be_bytes());
            bytes.extend_from_slice(&target.port().to_be_bytes());
            (0x21u8, 0x21u8, bytes)
        }
    };
    let mut out = vec![0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x0a, ver_cmd, fam, (addr.len() as u8)];
    out.extend_from_slice(&addr);
    out
}

async fn tcp_connection(state: AppState, task: PortForwardTask, client: TcpStream, peer: SocketAddr, local: SocketAddr) {
    let ip = ip_of(peer);
    if !allowed_source(&state, &task, &ip).await || !connection_ok(&state, &task, &ip).await { return; }
    let target = match pick_target(&state, &task).await {
        Ok(t) => t,
        Err(err) => { record_failure(&state, &task, &err).await; return; }
    };
    let mut backend = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(err) => { record_failure(&state, &task, &format!("{err}")).await; return; }
    };
    let header = proxy_header(&task.proxy_protocol, peer, local);
    if !header.is_empty() && backend.write_all(&header).await.is_err() { return; }
    {
        let mut stats = state.forward_stats.write().await;
        let entry: &mut TrafficCounter = stats.entry(task.id.clone()).or_default();
        entry.connections += 1; entry.active += 1;
        let source_key = format!("{}:{ip}", task.id);
        stats.entry(source_key).or_default().active += 1;
    }
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);
    let c2b = async {
        let mut buf = vec![0u8; 32768];
        loop {
            let n = match client_read.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => n };
            if backend_write.write_all(&buf[..n]).await.is_err() { break; }
            let mut stats = state.forward_stats.write().await;
            let e = stats.entry(task.id.clone()).or_default(); e.bytes_in += n as u64;
        }
    };
    let b2c = async {
        let mut buf = vec![0u8; 32768];
        loop {
            let n = match backend_read.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => n };
            if client_write.write_all(&buf[..n]).await.is_err() { break; }
            let mut stats = state.forward_stats.write().await;
            let e = stats.entry(task.id.clone()).or_default(); e.bytes_out += n as u64;
        }
    };
    tokio::select! {
        _ = c2b => {}
        _ = b2c => {}
        _ = tokio::time::sleep(StdDuration::from_secs(task.idle_timeout_secs.max(1))) => {}
    }
    {
        let mut stats = state.forward_stats.write().await;
        let e = stats.entry(task.id.clone()).or_default();
        e.active = e.active.saturating_sub(1);
        stats.entry(format!("{}:{ip}", task.id)).or_default().active = stats.entry(format!("{}:{ip}", task.id)).or_default().active.saturating_sub(1);
    }
}

async fn record_failure(state: &AppState, task: &PortForwardTask, err: &str) {
    let mut stats = state.forward_stats.write().await;
    let entry = stats.entry(format!("{}:{}", task.id, task.targets.first().cloned().unwrap_or_default())).or_default();
    entry.errors += 1;
    drop(stats);
    crate::notify::emit(state, "portforward.failed", &format!("{}: {err}", task.name)).await;
}

fn spawn_tcp(state: AppState, task: PortForwardTask, host: String, ports: Vec<u16>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for port in ports {
            let listener = match TcpListener::bind(format!("{host}:{port}")).await {
                Ok(l) => l,
                Err(err) => { eprintln!("[forward {}] bind {port}: {err}", task.id); continue; }
            };
            let task = task.clone(); let state = state.clone();
            tokio::spawn(async move {
                loop {
                    let (client, peer) = match listener.accept().await { Ok(v) => v, Err(_) => break };
                    let local = listener.local_addr().unwrap_or(peer);
                    let task = task.clone(); let state = state.clone();
                    tokio::spawn(async move { tcp_connection(state, task, client, peer, local).await });
                }
            });
        }
    })
}

fn spawn_udp(state: AppState, task: PortForwardTask, host: String, ports: Vec<u16>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for port in ports {
            let socket = match UdpSocket::bind(format!("{host}:{port}")).await {
                Ok(s) => Arc::new(s),
                Err(err) => { eprintln!("[forward {}] bind udp {port}: {err}", task.id); continue; }
            };
            let sessions: Arc<RwLock<HashMap<SocketAddr, (SocketAddr, tokio::time::Instant)>>> = Arc::new(RwLock::new(HashMap::new()));
            let outbound = Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("bind udp outbound"));
            let task_recv = task.clone(); let state_recv = state.clone();
            let socket_recv = socket.clone(); let outbound_recv = outbound.clone(); let sessions_recv = sessions.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (n, peer) = match socket_recv.recv_from(&mut buf).await { Ok(v) => v, Err(_) => break };
                    let ip = ip_of(peer);
                    if !allowed_source(&state_recv, &task_recv, &ip).await { continue; }
                    let target = match pick_target(&state_recv, &task_recv).await { Ok(t) => t, Err(_) => continue };
                    let mut map = sessions_recv.write().await;
                    map.retain(|_, (_, t)| t.elapsed() < StdDuration::from_secs(180));
                    let first = !map.contains_key(&peer);
                    map.insert(peer, (target, tokio::time::Instant::now()));
                    drop(map);
                    let mut packet = Vec::new();
                    if first { packet.extend_from_slice(&proxy_header(&task_recv.proxy_protocol, peer, target)); }
                    packet.extend_from_slice(&buf[..n]);
                    let _ = outbound_recv.send_to(&packet, target).await;
                    let mut stats = state_recv.forward_stats.write().await;
                    stats.entry(task_recv.id.clone()).or_default().bytes_in += n as u64;
                }
            });
            let task = task.clone(); let state = state.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (n, remote) = match outbound.recv_from(&mut buf).await { Ok(v) => v, Err(_) => break };
                    let sessions = sessions.read().await;
                    let clients: Vec<SocketAddr> = sessions.iter()
                        .filter(|(_, (target, _))| *target == remote)
                        .map(|(client, _)| *client)
                        .collect();
                    drop(sessions);
                    for client in clients { let _ = socket.send_to(&buf[..n], client).await; }
                    let mut stats = state.forward_stats.write().await;
                    stats.entry(task.id.clone()).or_default().bytes_out += n as u64;
                }
            });
        }
    })
}

fn task_signature(task: &PortForwardTask) -> String {
    serde_json::to_string(task).unwrap_or_default()
}

pub fn spawn_port_forward_supervisor(state: AppState) {
    tokio::spawn(async move {
        let mut running: HashMap<String, (String, tokio::task::JoinHandle<()>)> = HashMap::new();
        loop {
            let config: Config = state.config.read().await.clone();
            let desired: Vec<PortForwardTask> = config.port_forwards.into_iter().filter(|t| t.enabled).collect();
            let mut seen = Vec::new();
            for task in desired {
                seen.push(task.id.clone());
                let sig = task_signature(&task);
                if running.get(&task.id).is_some_and(|(old, _)| old == &sig) { continue; }
                if let Some((_, handle)) = running.remove(&task.id) { handle.abort(); }
                let (host, ports) = match expand_ports(&task.listen) {
                    Ok(v) => v,
                    Err(err) => { eprintln!("[forward {}] {err}", task.id); continue; }
                };
                let id = task.id.clone();
                let handle = if task.protocol.eq_ignore_ascii_case("udp") {
                    spawn_udp(state.clone(), task, host, ports)
                } else {
                    spawn_tcp(state.clone(), task, host, ports)
                };
                running.insert(id, (sig, handle));
            }
            let stale: Vec<String> = running.keys().filter(|id| !seen.contains(id)).cloned().collect();
            for id in stale {
                if let Some((_, handle)) = running.remove(&id) { handle.abort(); }
                state.forward_stats.write().await.remove(&id);
            }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
}

pub async fn status_handler(State(state): State<AppState>) -> axum::response::Response {
    let stats = state.forward_stats.read().await.clone();
    axum::Json(stats).into_response()
}

pub async fn ip_lists_status(State(state): State<AppState>) -> axum::response::Response {
    axum::Json(json!(state.ip_list_status.read().await.clone())).into_response()
}
