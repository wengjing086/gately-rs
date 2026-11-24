use crate::state::{AppState, UpdateInfo};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::{Value, json};
use std::time::Duration;

async fn fetch_latest(state: &AppState, repo: &str) -> Result<(String, String, Option<String>), String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let value: Value = state.client.get(&url)
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(10))
        .send().await.map_err(|e| e.to_string())?
        .json().await.map_err(|e| e.to_string())?;
    if let Some(message) = value.get("message").and_then(|v| v.as_str()) {
        return Err(message.to_string());
    }
    let tag = value.get("tag_name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let html = value.get("html_url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let published = value.get("published_at").and_then(|v| v.as_str()).map(str::to_string);
    Ok((tag, html, published))
}

async fn fetch_advisories(state: &AppState, repo: &str) -> Vec<String> {
    let url = format!("https://api.github.com/repos/{repo}/security-advisories?per_page=10");
    match state.client.get(&url).timeout(Duration::from_secs(10)).send().await {
        Ok(resp) => match resp.json::<Vec<Value>>().await {
            Ok(items) => items.iter().filter_map(|item| {
                let summary = item.get("summary").and_then(|v| v.as_str())?;
                let severity = item.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown");
                Some(format!("[{severity}] {summary}"))
            }).collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

pub async fn check(state: &AppState, repo: &str) -> UpdateInfo {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let (latest, url, published, advisories, error) = match fetch_latest(state, repo).await {
        Ok((tag, url, published)) => {
            let advisories = fetch_advisories(state, repo).await;
            (tag, url, published, advisories, None)
        }
        Err(err) => (current.clone(), String::new(), None, Vec::new(), Some(err)),
    };
    UpdateInfo { current, latest, release_url: url, published_at: published, checked_at: Utc::now(), advisories, error }
}

pub async fn check_handler(State(state): State<AppState>) -> Response {
    let repo = state.config.read().await.system.update_repo.clone();
    let info = check(&state, &repo).await;
    let payload = serde_json::to_value(&info).unwrap_or(json!({}));
    *state.update_info.write().await = Some(info);
    Json(payload).into_response()
}

pub async fn info_handler(State(state): State<AppState>) -> Response {
    match state.update_info.read().await.clone() {
        Some(info) => Json(serde_json::to_value(info).unwrap_or(json!({}))).into_response(),
        None => Json(json!({ "current": env!("CARGO_PKG_VERSION"), "checked_at": null })).into_response(),
    }
}

pub fn spawn_update_loop(state: AppState) {
    tokio::spawn(async move {
        loop {
            let (enabled, repo) = {
                let cfg = state.config.read().await;
                (cfg.system.update_check, cfg.system.update_repo.clone())
            };
            if enabled && !repo.is_empty() {
                let info = check(&state, &repo).await;
                let previous = state.update_info.read().await.clone();
                let changed = previous.as_ref().map(|p| p.latest != info.latest).unwrap_or(false);
                *state.update_info.write().await = Some(info);
                if changed {
                    crate::notify::emit(&state, "update.available", &format!("发现新版本 {repo}")).await;
                }
            }
            tokio::time::sleep(Duration::from_secs(21600)).await;
        }
    });
}

pub fn router(state: AppState) -> axum::Router<AppState> {
    axum::Router::new()
        .route("/update/check", axum::routing::post(check_handler))
        .route("/update/info", axum::routing::get(info_handler))
}
