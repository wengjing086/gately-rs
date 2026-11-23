use crate::state::AppState;
use chrono::Utc;
use std::time::Duration;
use tokio::net::UdpSocket;

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
            let octets = [
                value[4] ^ 0x21, value[5] ^ 0x12, value[6] ^ 0xA4, value[7] ^ 0x42,
            ];
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

pub async fn discover(server: &str) -> Result<(String, u16), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| format!("bind udp: {e}"))?;
    sock.connect(server).await.map_err(|e| format!("connect stun: {e}"))?;

    let txid = uuid::Uuid::new_v4().as_bytes().to_vec();
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&MAGIC.to_be_bytes());
    packet.extend_from_slice(&txid);

    sock.send(&packet).await.map_err(|e| format!("send stun: {e}"))?;
    let mut buf = [0u8; 1500];
    let timeout = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await.map_err(|_| "stun timeout".to_string())?
        .map_err(|e| format!("recv stun: {e}"))?;
    if timeout < 20 { return Err("short stun response".into()); }
    if buf[4..8] != MAGIC.to_be_bytes() { return Err("bad stun cookie".into()); }
    parse_mapped(&buf[..timeout]).ok_or_else(|| "no mapped address in stun response".into())
}

pub fn spawn_stun_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let tasks = state.config.read().await.stun.clone();
            for task in tasks.into_iter().filter(|t| t.enabled) {
                let last = state.stun_status.read().await.get(&task.id).and_then(|s| s.last_run);
                let due = last.map(|t| (Utc::now() - t).num_seconds() as u64 >= task.interval_secs.max(30)).unwrap_or(true);
                if !due { continue; }
                match discover(&task.server).await {
                    Ok((ip, port)) => {
                        let mut statuses = state.stun_status.write().await;
                        let entry = statuses.entry(task.id.clone()).or_default();
                        entry.public_ip = Some(ip);
                        entry.public_port = Some(port);
                        entry.last_run = Some(Utc::now());
                        entry.last_error = None;
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
