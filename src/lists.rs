use crate::config::Config;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Config field path for each logical list kind.
fn kind_path(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "sites" => "sites",
        "port-forwards" => "port_forwards",
        "proto-routes" => "proto_routes",
        "ddns" => "ddns",
        "tasks" => "scheduled_tasks",
        "waf-rules" => "waf_rules",
        "waf-profiles" => "waf_profiles",
        "acme" => "acme",
        "tunnels" => "tunnels",
        "stun" => "stun",
        "ip-lists" => "ip_lists",
        "site-users" => "site_users",
        "certificates" => "certificates",
        "notification-channels" => "notifications.channels",
        "notification-rules" => "notifications.rules",
        "api-tokens" => "admin.api_tokens",
        _ => return None,
    })
}

fn config_value(config: &Config) -> Result<Value, String> {
    serde_json::to_value(config).map_err(|e| e.to_string())
}

fn array_mut<'a>(root: &'a mut Value, path: &str) -> Option<&'a mut Vec<Value>> {
    let mut cursor = root;
    for part in path.split('.') {
        cursor = cursor.get_mut(part)?;
    }
    cursor.as_array_mut()
}

fn array_ref<'a>(root: &'a Value, path: &str) -> Option<&'a Vec<Value>> {
    let mut cursor = root;
    for part in path.split('.') {
        cursor = cursor.get(part)?;
    }
    cursor.as_array()
}

fn item_id(item: &Value) -> String {
    item.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

fn item_group(item: &Value) -> String {
    item.get("group").and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

fn item_search_text(item: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(obj) = item.as_object() {
        for (key, value) in obj {
            match value {
                Value::String(s) => parts.push(format!("{key}={s}")),
                Value::Number(n) => parts.push(format!("{key}={n}")),
                Value::Array(arr) => {
                    for entry in arr {
                        if let Some(s) = entry.as_str() { parts.push(s.to_string()); }
                    }
                }
                _ => {}
            }
        }
    }
    parts.join(" ").to_ascii_lowercase()
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct BulkRequest {
    /// enable | disable | delete | duplicate | move | set-group
    pub action: String,
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub order_delta: i32,
}

pub async fn list_handler(State(state): State<AppState>, Path(kind): Path<String>, Query(query): Query<ListQuery>) -> Response {
    let path = match kind_path(&kind) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, format!("unknown list: {kind}")).into_response(),
    };
    let config = state.config.read().await.clone();
    let root = match config_value(&config) { Ok(v) => v, Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response() };
    let items = match array_ref(&root, path) { Some(items) => items.clone(), None => return Json(json!([])).into_response() };
    let needle = query.search.trim().to_ascii_lowercase();
    let filtered: Vec<Value> = items.into_iter().filter(|item| {
        if !query.group.is_empty() && item_group(item) != query.group { return false; }
        if !needle.is_empty() && !item_search_text(item).contains(&needle) { return false; }
        true
    }).collect();
    let filtered = match query.limit { Some(n) => filtered.into_iter().take(n).collect(), None => filtered };
    Json(json!({ "kind": kind, "total": filtered.len(), "items": filtered })).into_response()
}

pub async fn bulk_handler(State(state): State<AppState>, Path(kind): Path<String>, Json(payload): Json<BulkRequest>) -> Response {
    let path = match kind_path(&kind) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, format!("unknown list: {kind}")).into_response(),
    };
    let snapshot = { state.config.read().await.clone() };
    let mut root = match config_value(&snapshot) { Ok(v) => v, Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response() };
    let items = match array_mut(&mut root, path) { Some(items) => items, None => return (StatusCode::NOT_FOUND, "list not found").into_response() };
    let mut affected = 0usize;
    match payload.action.as_str() {
        "enable" | "disable" => {
            let enabled = payload.action == "enable";
            for item in items.iter_mut() {
                if payload.ids.is_empty() || payload.ids.contains(&item_id(item)) {
                    if let Some(obj) = item.as_object_mut() { obj.insert("enabled".into(), Value::Bool(enabled)); affected += 1; }
                }
            }
        }
        "delete" => {
            let before = items.len();
            items.retain(|item| !payload.ids.contains(&item_id(item)));
            affected = before - items.len();
        }
        "duplicate" => {
            let mut copies = Vec::new();
            for item in items.iter() {
                if payload.ids.contains(&item_id(item)) {
                    let mut copy = item.clone();
                    if let Some(obj) = copy.as_object_mut() {
                        let new_id = format!("{}_copy_{}", item_id(item), chrono::Utc::now().timestamp_millis());
                        obj.insert("id".into(), Value::String(new_id));
                        if let Some(name) = obj.get("name").and_then(|v| v.as_str()).map(str::to_string) {
                            obj.insert("name".into(), Value::String(format!("{name} 副本")));
                        }
                        obj.insert("enabled".into(), Value::Bool(false));
                    }
                    copies.push(copy);
                    affected += 1;
                }
            }
            items.extend(copies);
        }
        "move" => {
            for item in items.iter_mut() {
                if payload.ids.contains(&item_id(item)) {
                    if let Some(obj) = item.as_object_mut() { obj.insert("group".into(), Value::String(payload.group.clone())); affected += 1; }
                }
            }
        }
        "set-group" => {
            for item in items.iter_mut() {
                if payload.ids.is_empty() || payload.ids.contains(&item_id(item)) {
                    if let Some(obj) = item.as_object_mut() { obj.insert("group".into(), Value::String(payload.group.clone())); affected += 1; }
                }
            }
        }
        "order" => {
            let delta = payload.order_delta;
            for item in items.iter_mut() {
                if payload.ids.is_empty() || payload.ids.contains(&item_id(item)) {
                    let current = item.get("order").and_then(|v| v.as_i64()).unwrap_or(0);
                    if let Some(obj) = item.as_object_mut() { obj.insert("order".into(), Value::Number((current + delta as i64).into())); affected += 1; }
                }
            }
        }
        other => return (StatusCode::BAD_REQUEST, format!("unsupported action: {other}")).into_response(),
    }
    let updated: Config = match serde_json::from_value(root) { Ok(c) => c, Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid config after edit: {e}")).into_response() };
    if let Ok(text) = std::fs::read_to_string(&state.config_path) { let _ = crate::history::snapshot(&state.config_path, &text); }
    if let Err(err) = updated.save(&state.config_path) { return (StatusCode::INTERNAL_SERVER_ERROR, err).into_response(); }
    {
        let mut guard = state.config.write().await;
        *guard = updated;
    }
    crate::metrics::audit(&state, "admin", &format!("list.{}", payload.action), &kind, &payload.ids.join(",")).await;
    Json(json!({ "ok": true, "affected": affected })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ReorderRequest { pub ids: Vec<String> }

pub async fn reorder_handler(State(state): State<AppState>, Path(kind): Path<String>, Json(payload): Json<ReorderRequest>) -> Response {
    let path = match kind_path(&kind) { Some(p) => p, None => return (StatusCode::NOT_FOUND, format!("unknown list: {kind}")).into_response() };
    let snapshot = { state.config.read().await.clone() };
    let mut root = match config_value(&snapshot) { Ok(v) => v, Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response() };
    let items = match array_mut(&mut root, path) { Some(items) => items, None => return (StatusCode::NOT_FOUND, "list not found").into_response() };
    let order: HashMap<String, i64> = payload.ids.iter().enumerate().map(|(idx, id)| (id.clone(), idx as i64)).collect();
    for item in items.iter_mut() {
        let id = item_id(item);
        if let Some(pos) = order.get(&id) {
            if let Some(obj) = item.as_object_mut() { obj.insert("order".into(), Value::Number((*pos).into())); }
        }
    }
    items.sort_by_key(|item| item.get("order").and_then(|v| v.as_i64()).unwrap_or(0));
    let updated: Config = match serde_json::from_value(root) { Ok(c) => c, Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid config after reorder: {e}")).into_response() };
    if let Ok(text) = std::fs::read_to_string(&state.config_path) { let _ = crate::history::snapshot(&state.config_path, &text); }
    if let Err(err) = updated.save(&state.config_path) { return (StatusCode::INTERNAL_SERVER_ERROR, err).into_response(); }
    {
        let mut guard = state.config.write().await;
        *guard = updated;
    }
    Json(json!({ "ok": true })).into_response()
}

pub fn router(state: AppState) -> axum::Router<AppState> {
    axum::Router::new()
        .route("/lists/{kind}", get(list_handler))
        .route("/lists/{kind}/bulk", axum::routing::post(bulk_handler))
        .route("/lists/{kind}/reorder", axum::routing::post(reorder_handler))
}
