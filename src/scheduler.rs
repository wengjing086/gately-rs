use crate::config::{Config, ScheduledTask};
use crate::state::{AppState, RuntimeTaskStatus};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Datelike, Timelike, Utc};
use serde_json::json;
use std::process::Stdio;
use std::time::Duration as StdDuration;
use tokio::process::Command;

fn field_matches(field: &str, value: u32) -> bool {
    if field == "*" { return true; }
    for part in field.split(',') {
        if let Some((start, end)) = part.split_once('/') {
            let step = end.parse::<u32>().unwrap_or(1).max(1);
            if start == "*" && value % step == 0 { return true; }
            if let Some((a, b)) = start.split_once('-') {
                let a = a.parse::<u32>().unwrap_or(0); let b = b.parse::<u32>().unwrap_or(0);
                if value >= a && value <= b && (value - a) % step == 0 { return true; }
            }
        } else if let Some((a, b)) = part.split_once('-') {
            let a = a.parse::<u32>().unwrap_or(0); let b = b.parse::<u32>().unwrap_or(0);
            if value >= a && value <= b { return true; }
        } else if part.parse::<u32>().ok() == Some(value) {
            return true;
        }
    }
    false
}

pub fn cron_matches(expr: &str) -> bool {
    let now = chrono::Local::now();
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 { return false; }
    field_matches(fields[0], now.minute())
        && field_matches(fields[1], now.hour())
        && field_matches(fields[2], now.day() as u32)
        && field_matches(fields[3], now.month() as u32)
        && field_matches(fields[4], now.weekday().num_days_from_sunday())
}

pub async fn run_task(state: &AppState, id: &str) -> Result<String, String> {
    let task = {
        let cfg = state.config.read().await;
        cfg.scheduled_tasks.iter().find(|t| t.id == id).cloned()
            .ok_or_else(|| format!("task {id} not found"))?
    };
    {
        let mut statuses = state.task_status.write().await;
        statuses.entry(id.to_string()).or_default().running = true;
    }
    let result = match task.kind.as_str() {
        "command" => {
            let mut parts = task.command.split_whitespace();
            let program = parts.next().ok_or("empty command")?;
            let args: Vec<&str> = parts.collect();
            let output = tokio::time::timeout(
                StdDuration::from_secs(task.timeout_secs.max(1)),
                Command::new(program).args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).output(),
            ).await.map_err(|_| "command timeout".to_string())?.map_err(|e| e.to_string())?;
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).chars().take(1000).collect())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).chars().take(1000).collect())
            }
        }
        "http" | _ => {
            let method = if task.method.is_empty() { "GET".to_string() } else { task.method.to_ascii_uppercase() };
            let mut req = state.client.request(method.parse().map_err(|_| "bad method")?, &task.url);
            if !task.body.is_empty() { req = req.body(task.body.clone()); }
            let resp = tokio::time::timeout(
                StdDuration::from_secs(task.timeout_secs.max(1)),
                req.send(),
            ).await.map_err(|_| "http timeout".to_string())?.map_err(|e| e.to_string())?;
            if resp.status().is_success() { Ok(format!("http {}", resp.status())) } else { Err(format!("http {}", resp.status())) }
        }
    };
    {
        let mut statuses = state.task_status.write().await;
        let entry: &mut RuntimeTaskStatus = statuses.entry(id.to_string()).or_default();
        entry.running = false;
        entry.last_run = Some(Utc::now());
        match &result {
            Ok(r) => { entry.last_result = Some(r.clone()); entry.last_error = None; }
            Err(e) => { entry.last_error = Some(e.clone()); }
        }
    }
    crate::notify::emit(state, "task.finished", &format!("{}: {}", task.name, match &result { Ok(v) => v.clone(), Err(e) => e.clone() })).await;
    result
}

pub async fn run_handler(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match run_task(&state, &id).await {
        Ok(v) => Json(json!({"ok": true, "result": v})).into_response(),
        Err(err) => (axum::http::StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

const BACKUP_MAGIC: &[u8] = b"GATELYBAK1";

/// Encrypt a backup with scrypt + AES-256-GCM (scrypt derives the key from the password).
pub fn encrypt_backup(plain: &[u8], password: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    let salt = uuid::Uuid::new_v4().as_bytes()[..16].to_vec();
    let mut key_bytes = [0u8; 32];
    let params = scrypt::Params::new(14, 8, 1, 32).map_err(|e| e.to_string())?;
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key_bytes).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce_bytes = uuid::Uuid::new_v4().as_bytes()[..12].to_vec();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plain).map_err(|_| "encrypt failed".to_string())?;
    let mut out = Vec::new();
    out.extend_from_slice(BACKUP_MAGIC);
    out.push(1); // version
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_backup(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    if data.len() < BACKUP_MAGIC.len() + 1 + 16 + 12 || !data.starts_with(BACKUP_MAGIC) {
        return Err("not an encrypted gately backup".into());
    }
    let mut offset = BACKUP_MAGIC.len() + 1;
    let salt = &data[offset..offset + 16]; offset += 16;
    let nonce = Nonce::from_slice(&data[offset..offset + 12]); offset += 12;
    let ciphertext = &data[offset..];
    let mut key_bytes = [0u8; 32];
    let params = scrypt::Params::new(14, 8, 1, 32).map_err(|e| e.to_string())?;
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key_bytes).map_err(|e| e.to_string())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    cipher.decrypt(nonce, ciphertext).map_err(|_| "wrong password or corrupted backup".into())
}

pub async fn create_backup(state: &AppState) -> Result<String, String> {
    let config: Config = state.config.read().await.clone();
    let text = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    let dir = if config.backups.directory.is_empty() {
        state.config_path.parent().unwrap_or_else(|| std::path::Path::new(".")).join("backups")
    } else {
        std::path::PathBuf::from(&config.backups.directory)
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let encrypted = !config.backups.password.is_empty();
    let name = if encrypted { format!("gately-{stamp}.enc") } else { format!("gately-{stamp}.json") };
    let path = dir.join(&name);
    let payload = if encrypted {
        encrypt_backup(text.as_bytes(), &config.backups.password)?
    } else { text.into_bytes() };
    std::fs::write(&path, payload).map_err(|e| e.to_string())?;
    let mut files: Vec<_> = std::fs::read_dir(&dir).map_err(|e| e.to_string())?
        .filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("gately-")).collect();
    files.sort_by_key(|e| e.file_name());
    while files.len() > config.backups.keep as usize {
        if let Some(old) = files.first() { let _ = std::fs::remove_file(old.path()); }
        files.remove(0);
    }
    Ok(path.to_string_lossy().to_string())
}

pub async fn restore_backup(state: &AppState, path: &str, password: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("read backup: {e}"))?;
    let plain = if data.starts_with(BACKUP_MAGIC) {
        decrypt_backup(&data, password)?
    } else { data };
    let text = String::from_utf8(plain).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_str(&text).map_err(|e| format!("parse backup: {e}"))?;
    if let Ok(old) = std::fs::read_to_string(&state.config_path) { let _ = crate::history::snapshot(&state.config_path, &old); }
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *state.config.write().await = config;
    crate::notify::emit(state, "backup.restored", path).await;
    Ok(())
}

pub fn spawn_ip_list_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let lists: Vec<crate::config::IpList> = state.config.read().await.ip_lists.clone();
            for list in lists.into_iter().filter(|l| l.enabled) {
                let text = if !list.url.is_empty() {
                    match state.client.get(&list.url).timeout(StdDuration::from_secs(20)).send().await {
                        Ok(resp) => resp.text().await.ok(),
                        Err(err) => {
                            state.ip_list_status.write().await.entry(list.id.clone()).or_default().last_error = Some(err.to_string());
                            None
                        }
                    }
                } else if !list.file.is_empty() {
                    tokio::fs::read_to_string(&list.file).await.ok()
                } else { None };
                if let Some(text) = text {
                    let entries: Vec<String> = text.lines().map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(|l| l.split_whitespace().next().unwrap_or(l).to_string()).collect();
                    let changed = {
                        let cfg = state.config.read().await;
                        cfg.ip_lists.iter().find(|l| l.id == list.id).map(|l| l.entries.len() != entries.len()).unwrap_or(true)
                    };
                    let count = entries.len();
                    {
                        let mut cfg = state.config.write().await;
                        if let Some(l) = cfg.ip_lists.iter_mut().find(|l| l.id == list.id) {
                            l.entries = entries;
                            l.last_update = Some(Utc::now().to_rfc3339());
                            l.last_error = None;
                        }
                        let _ = cfg.save(&state.config_path);
                    }
                    let mut statuses = state.ip_list_status.write().await;
                    let status = statuses.entry(list.id.clone()).or_default();
                    status.entries = count;
                    status.last_update = Some(Utc::now());
                    status.last_error = None;
                    drop(statuses);
                    if changed { crate::notify::emit(&state, "iplist.updated", &format!("{}: {} 条", list.name, count)).await; }
                }
            }
            tokio::time::sleep(StdDuration::from_secs(60)).await;
        }
    });
}

/// Periodically probe site backends and update their health flags.
pub fn spawn_health_check_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let targets: Vec<(String, String, String)> = {
                let cfg = state.config.read().await;
                cfg.sites.iter().filter(|s| !s.backends.is_empty()).map(|s| {
                    let path = if s.health_check_path.is_empty() { "/".to_string() } else { s.health_check_path.clone() };
                    (s.id.clone(), s.backends.iter().map(|b| b.url.clone()).collect::<Vec<_>>().join(","), path)
                }).collect()
            };
            for (site_id, backends, path) in targets {
                let mut results: Vec<(String, bool)> = Vec::new();
                for url in backends.split(',').filter(|u| !u.trim().is_empty()) {
                    let target = format!("{}{}", url.trim_end_matches('/'), path);
                    let ok = state.client.get(&target).timeout(StdDuration::from_secs(5)).send().await
                        .map(|r| r.status().is_success()).unwrap_or(false);
                    results.push((url.trim().to_string(), ok));
                }
                let mut cfg = state.config.write().await;
                if let Some(site) = cfg.sites.iter_mut().find(|s| s.id == site_id) {
                    for backend in site.backends.iter_mut() {
                        if let Some((_, ok)) = results.iter().find(|(url, _)| url == &backend.url) { backend.healthy = *ok; }
                    }
                }
                let _ = cfg.save(&state.config_path);
            }
            tokio::time::sleep(StdDuration::from_secs(60)).await;
        }
    });
}

/// Compress yesterday's access log so the audit trail stays small on disk.
pub fn spawn_log_archive_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let dir = state.config.read().await.system.access_log_dir.clone();
            if !dir.is_empty() {
                let yesterday = (Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
                let path = std::path::Path::new(&dir).join(format!("access-{yesterday}.log"));
                if path.exists() {
                    if let Ok(data) = std::fs::read(&path) {
                        let gz = crate::site_ext::gzip_bytes(&data);
                        let _ = std::fs::write(path.with_extension("log.gz"), gz);
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
            tokio::time::sleep(StdDuration::from_secs(3600)).await;
        }
    });
}

pub fn spawn_task_loop(state: AppState) {
    tokio::spawn(async move {
        let mut last_minute = String::new();
        loop {
            let now_minute = chrono::Local::now().format("%Y-%m-%dT%H:%M").to_string();
            if now_minute != last_minute {
                last_minute = now_minute.clone();
                let tasks: Vec<ScheduledTask> = {
                    let cfg = state.config.read().await;
                    cfg.scheduled_tasks.iter().filter(|t| t.enabled && cron_matches(&t.cron)).cloned().collect()
                };
                for task in tasks {
                    let last = state.task_status.read().await.get(&task.id).and_then(|s| s.last_run);
                    if last.map(|t| t.format("%Y-%m-%dT%H:%M").to_string() != now_minute).unwrap_or(true) {
                        if let Err(err) = run_task(&state, &task.id).await {
                            eprintln!("[task {}] {}", task.id, err);
                        }
                    }
                }
                let backup = {
                    let cfg = state.config.read().await;
                    cfg.backups.enabled && cron_matches(&cfg.backups.cron)
                };
                if backup {
                    match create_backup(&state).await {
                        Ok(path) => crate::notify::emit(&state, "backup.created", &format!("备份完成: {path}")).await,
                        Err(err) => crate::notify::emit(&state, "backup.failed", &err).await,
                    }
                }
            }
            tokio::time::sleep(StdDuration::from_secs(10)).await;
        }
    });
}
