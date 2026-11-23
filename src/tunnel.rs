use crate::config::TunnelTask;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

async fn start_task(state: &AppState, task: &TunnelTask) -> Result<u32, String> {
    if !task.config_text.is_empty() && !task.binary.is_empty() {
        let path = std::path::Path::new(&task.binary);
        let config_path = path.parent().unwrap_or_else(|| std::path::Path::new(".")).join(format!("{}.toml", task.id));
        tokio::fs::write(&config_path, &task.config_text).await.map_err(|e| e.to_string())?;
    }
    let mut cmd = Command::new(&task.binary);
    cmd.args(&task.args).envs(&task.env);
    if let Some(dir) = &task.workdir { cmd.current_dir(dir); }
    cmd.stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null());
    let child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", task.binary))?;
    let pid = child.id().unwrap_or(0);
    state.tunnel_children.write().await.insert(task.id.clone(), child);
    Ok(pid)
}

pub fn spawn_tunnel_supervisor(state: AppState) {
    tokio::spawn(async move {
        loop {
            let tasks: Vec<TunnelTask> = state.config.read().await.tunnels.clone();
            let ids: Vec<String> = tasks.iter().map(|t| t.id.clone()).collect();
            for task in &tasks {
                let running = {
                    let mut children = state.tunnel_children.write().await;
                    match children.get_mut(&task.id) { Some(child) => matches!(child.try_wait(), Ok(None)), None => false }
                };
                if running { continue; }
                {
                    let mut children = state.tunnel_children.write().await;
                    if let Some(mut child) = children.remove(&task.id) { let _ = child.kill().await; }
                }
                let mut statuses = state.tunnel_status.write().await;
                let entry = statuses.entry(task.id.clone()).or_default();
                entry.running = false; entry.pid = None;
                if !task.enabled { entry.last_error = None; continue; }
                if !task.auto_restart && entry.restarts > 0 {
                    entry.last_error = Some("auto_restart disabled".into());
                    continue;
                }
                match start_task(&state, task).await {
                    Ok(pid) => { entry.running = true; entry.pid = Some(pid); entry.restarts += 1; entry.last_error = None; }
                    Err(err) => entry.last_error = Some(err),
                }
            }
            {
                let mut children = state.tunnel_children.write().await;
                let stale: Vec<String> = children.keys().filter(|k| !ids.contains(k)).cloned().collect();
                for id in stale { if let Some(mut child) = children.remove(&id) { let _ = child.kill().await; } }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

pub async fn stop_all(state: &AppState) {
    let mut children = state.tunnel_children.write().await;
    let ids: Vec<String> = children.keys().cloned().collect();
    for id in ids { if let Some(mut child) = children.remove(&id) { let _ = child.kill().await; } }
}

pub async fn install(state: &AppState, id: &str) -> Result<String, String> {
    let task = state.config.read().await.tunnels.iter().find(|t| t.id == id).cloned()
        .ok_or_else(|| format!("tunnel {id} not found"))?;
    if task.install_url.is_empty() || task.binary.is_empty() { return Err("install_url and binary are required".into()); }
    let bytes = state.client.get(&task.install_url).send().await.map_err(|e| e.to_string())?
        .bytes().await.map_err(|e| e.to_string())?;
    let path = std::path::Path::new(&task.binary);
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?; }
    if path.exists() {
        let backup = path.with_extension(format!("bak.{}", chrono::Utc::now().format("%Y%m%d%H%M%S")));
        let _ = tokio::fs::copy(path, backup).await;
    }
    tokio::fs::write(path, &bytes).await.map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(path).await.map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(path, perms).await.map_err(|e| e.to_string())?;
    }
    {
        let mut cfg = state.config.write().await;
        if let Some(t) = cfg.tunnels.iter_mut().find(|t| t.id == id) { t.version = chrono::Utc::now().to_rfc3339(); }
        let _ = cfg.save(&state.config_path);
    }
    crate::notify::emit(state, "tunnel.updated", &format!("{} 已安装/更新", task.name)).await;
    Ok("installed".into())
}

pub async fn rollback(state: &AppState, id: &str) -> Result<String, String> {
    let task = state.config.read().await.tunnels.iter().find(|t| t.id == id).cloned()
        .ok_or_else(|| format!("tunnel {id} not found"))?;
    let path = std::path::Path::new(&task.binary);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path.file_name().ok_or("bad binary path")?.to_string_lossy();
    let mut dir = tokio::fs::read_dir(parent).await.map_err(|e| e.to_string())?;
    let mut backups = Vec::new();
    while let Some(entry) = dir.next_entry().await.map_err(|e| e.to_string())? {
        if entry.file_name().to_string_lossy().starts_with(&format!("{file_name}.bak.")) {
            backups.push(entry);
        }
    }
    backups.sort_by_key(|e| e.file_name());
    let latest = backups.pop().ok_or("no backup found")?;
    if let Some(mut child) = state.tunnel_children.write().await.remove(id) { let _ = child.kill().await; }
    tokio::fs::copy(latest.path(), path).await.map_err(|e| e.to_string())?;
    Ok("rolled back".into())
}

pub async fn install_handler(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match install(&state, &id).await {
        Ok(v) => Json(json!({"ok": true, "result": v})).into_response(),
        Err(err) => (axum::http::StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

pub async fn rollback_handler(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match rollback(&state, &id).await {
        Ok(v) => Json(json!({"ok": true, "result": v})).into_response(),
        Err(err) => (axum::http::StatusCode::BAD_GATEWAY, err).into_response(),
    }
}
