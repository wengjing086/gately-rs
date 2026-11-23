use crate::config::{NotificationConfig, NotifyChannel};
use crate::state::{AppState, NotifyQueueItem};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration as StdDuration;
use uuid::Uuid;

fn wildcard_match(pattern: &str, event: &str) -> bool {
    if pattern == "*" || pattern == event { return true; }
    if let Some(prefix) = pattern.strip_suffix(".*") { return event.starts_with(prefix); }
    false
}

fn channel_ids(config: &NotificationConfig, event: &str) -> Vec<String> {
    let defaults: Vec<String> = config.channels.iter().filter(|c| c.enabled).map(|c| c.id.clone()).collect();
    let mut selected = Vec::new();
    for rule in config.rules.iter().filter(|r| r.enabled && wildcard_match(&r.event, event)) {
        for id in &rule.channels {
            if !selected.contains(id) { selected.push(id.clone()); }
        }
    }
    if selected.is_empty() { defaults } else { selected }
}

pub async fn emit(state: &AppState, event: &str, message: &str) {
    let (config, dedup) = {
        let cfg = state.config.read().await;
        let dedup = cfg.notifications.rules.iter()
            .find(|r| r.enabled && wildcard_match(&r.event, event))
            .map(|r| r.dedup_secs).unwrap_or(0);
        (cfg.notifications.clone(), dedup)
    };
    if dedup > 0 {
        let key = format!("{event}:{message}");
        let mut sent = state.notify_sent.write().await;
        if let Some(last) = sent.get(&key) {
            if (Utc::now() - *last).num_seconds() < dedup as i64 { return; }
        }
        sent.insert(key, Utc::now());
    }
    let ids = channel_ids(&config, event);
    let mut queue = state.notify_queue.write().await;
    for channel_id in ids {
        queue.push(NotifyQueueItem {
            id: Uuid::new_v4().to_string(),
            event: event.to_string(),
            channel_id,
            message: message.to_string(),
            attempts: 0,
            next_at: Utc::now(),
            last_error: None,
        });
    }
    if queue.len() > 1000 { let excess = queue.len() - 1000; queue.drain(0..excess); }
}

fn telegram_url(endpoint: &str, token: &str) -> String {
    if endpoint.contains("bot") { endpoint.to_string() } else { format!("https://api.telegram.org/bot{token}/sendMessage") }
}

async fn send_http(client: &reqwest::Client, channel: &NotifyChannel, message: &str) -> Result<(), String> {
    let text = message;
    let payload: Value = match channel.kind.as_str() {
        "telegram" => json!({"chat_id": channel.extra.get("chat_id").cloned().unwrap_or_default(), "text": text}),
        "discord" | "slack" => json!({"text": text, "content": text}),
        "ntfy" => json!({"topic": channel.extra.get("topic").cloned().unwrap_or_else(|| "gately".to_string()), "message": text, "title": "gately-rs"}),
        "gotify" => json!({"message": text, "title": "gately-rs", "priority": 5}),
        "bark" => json!({"title": "gately-rs", "body": text}),
        "serverchan" => json!({"title": "gately-rs", "desp": text}),
        "pushplus" => json!({"token": channel.token, "title": "gately-rs", "content": text, "template": "txt"}),
        "wecom" | "dingtalk" | "feishu" => json!({"msgtype": "text", "text": {"content": text}}),
        _ => json!({"event": "gately", "message": text}),
    };
    let url = match channel.kind.as_str() {
        "telegram" => telegram_url(&channel.endpoint, &channel.token),
        _ => channel.endpoint.clone(),
    };
    if url.is_empty() { return Err("empty endpoint".into()); }
    let mut req = client.post(&url).json(&payload);
    if !channel.token.is_empty() && !matches!(channel.kind.as_str(), "telegram" | "pushplus") {
        req = req.bearer_auth(&channel.token);
    }
    let resp = req.timeout(StdDuration::from_secs(10)).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() { return Err(format!("http {}", resp.status())); }
    Ok(())
}

fn send_smtp(channel: &NotifyChannel, message: &str) -> Result<(), String> {
    let host = channel.extra.get("host").cloned().unwrap_or_default();
    let port: u16 = channel.extra.get("port").and_then(|v| v.parse().ok()).unwrap_or(25);
    let from = channel.extra.get("from").cloned().unwrap_or_else(|| "gately@localhost".into());
    let to = channel.extra.get("to").cloned().unwrap_or_default();
    if host.is_empty() || to.is_empty() { return Err("smtp host/to missing".into()); }
    let mut stream = TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(StdDuration::from_secs(10))).ok();
    let mut buf = [0u8; 1024];
    let read = |s: &mut TcpStream, b: &mut [u8; 1024]| -> String {
        let n = s.read(b).unwrap_or(0);
        String::from_utf8_lossy(&b[..n]).to_string()
    };
    read(&mut stream, &mut buf);
    let mut cmd = |s: &mut TcpStream, line: String| -> Result<String, String> {
        s.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        Ok(read(s, &mut buf))
    };
    cmd(&mut stream, format!("EHLO gately\r\n"))?;
    cmd(&mut stream, format!("MAIL FROM:<{from}>\r\n"))?;
    cmd(&mut stream, format!("RCPT TO:<{to}>\r\n"))?;
    cmd(&mut stream, "DATA\r\n".into())?;
    let body = format!("From: {from}\r\nTo: {to}\r\nSubject: gately-rs\r\n\r\n{message}\r\n.\r\n");
    cmd(&mut stream, body)?;
    cmd(&mut stream, "QUIT\r\n".into())?;
    Ok(())
}

async fn deliver(state: &AppState, channel: &NotifyChannel, message: &str) -> Result<(), String> {
    match channel.kind.as_str() {
        "command" => {
            let mut parts = channel.endpoint.split_whitespace();
            let program = parts.next().ok_or("empty command")?;
            let args: Vec<&str> = parts.collect();
            let output = tokio::process::Command::new(program).args(&args)
                .env("GATELY_MESSAGE", message).output().await.map_err(|e| e.to_string())?;
            if output.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&output.stderr).to_string()) }
        }
        "email" => tokio::task::spawn_blocking({
            let channel = channel.clone(); let message = message.to_string();
            move || send_smtp(&channel, &message)
        }).await.map_err(|e| e.to_string())?,
        _ => send_http(&state.client, channel, message).await,
    }
}

pub async fn test_channel(State(state): State<AppState>, axum::extract::Path(id): axum::extract::Path<String>) -> Response {
    let channel = state.config.read().await.notifications.channels.iter().find(|c| c.id == id).cloned();
    match channel {
        Some(c) => match deliver(&state, &c, "gately-rs 测试通知").await {
            Ok(_) => Json(json!({"ok": true})).into_response(),
            Err(err) => (axum::http::StatusCode::BAD_GATEWAY, err).into_response(),
        },
        None => (axum::http::StatusCode::NOT_FOUND, "channel not found").into_response(),
    }
}

pub async fn queue_handler(State(state): State<AppState>) -> Response {
    Json(state.notify_queue.read().await.clone()).into_response()
}

pub fn spawn_notify_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let due: Vec<NotifyQueueItem> = {
                let q = state.notify_queue.read().await;
                q.iter().filter(|i| i.next_at <= Utc::now()).cloned().collect()
            };
            for item in due {
                let channel = {
                    let cfg = state.config.read().await;
                    cfg.notifications.channels.iter().find(|c| c.id == item.channel_id).cloned()
                };
                let result = match channel {
                    Some(c) => deliver(&state, &c, &item.message).await,
                    None => Err("channel not found".to_string()),
                };
                let retry = state.config.read().await.notifications.retry;
                let mut queue = state.notify_queue.write().await;
                if let Some(pos) = queue.iter().position(|x| x.id == item.id) {
                    match result {
                        Ok(_) => { queue.remove(pos); }
                        Err(err) => {
                            let attempts = item.attempts + 1;
                            if retry && attempts < 5 {
                                queue[pos].attempts = attempts;
                                queue[pos].last_error = Some(err);
                                queue[pos].next_at = Utc::now() + Duration::seconds(2i64.pow(attempts));
                            } else {
                                queue.remove(pos);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
}
