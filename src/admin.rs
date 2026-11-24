use crate::acme;
use crate::auth_ext;
use crate::config::{
    ApiToken, AuthConfig, CertificateConfig, Config, DdnsTask, IpSource, JailConfig, SiteConfig,
};
use crate::ddns::run_and_record;
use crate::extras;
use crate::diag;
use crate::docker;
use crate::history;
use crate::knock;
use crate::lists;
use crate::metrics;
use crate::migrate;
use crate::notify;
use crate::scheduler;
use crate::site_ext;
use crate::state::AppState;
use crate::terminal;
use crate::tunnel;
use crate::update;
use crate::waf;
use crate::{portforward, protoroute, stun};
use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LoginRequest { pub password: String }
#[derive(Debug, Deserialize)]
pub struct SiteRequest {
    pub domains: Vec<String>, pub backend: String, pub listener: Option<String>,
    #[serde(default)] pub kind: String,
}
#[derive(Debug, Deserialize)]
pub struct CertRequest { pub id: String, pub cert_path: String, pub key_path: String }
#[derive(Debug, Deserialize)]
pub struct DdnsRequest {
    pub id: Option<String>, pub enabled: bool, pub provider: String, pub zone_id: String,
    pub api_token: String, pub name: String, pub record_type: String, pub ip_source: Value,
    pub interval_secs: u64,
    #[serde(default)] pub options: std::collections::HashMap<String, String>,
    #[serde(default)] pub webhooks: Vec<String>,
}
#[derive(Debug, Deserialize)]
pub struct ImportRequest { pub paths: Vec<String>, #[serde(default)] pub keep_enabled: bool }

fn new_id(prefix: &str) -> String { format!("{prefix}_{}", Uuid::new_v4().simple()) }
fn bad_request(err: impl std::fmt::Display) -> Response { (StatusCode::BAD_REQUEST, err.to_string()).into_response() }
fn internal(err: impl std::fmt::Display) -> Response { (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response() }

fn persist(state: &AppState, config: &Config) -> Result<(), String> {
    if let Ok(text) = fs::read_to_string(&state.config_path) { let _ = history::snapshot(&state.config_path, &text); }
    config.save(&state.config_path)
}

async fn authenticated_token(state: &AppState, headers: &axum::http::HeaderMap, query: Option<&str>) -> Option<String> {
    let supplied = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
        .or_else(|| {
            // WebSocket 等无法自定义请求头的场景允许通过 ?token= 传递。
            let raw = query?;
            raw.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "token" { Some(v.to_string()) } else { None }
            })
        })?;
    let cfg = state.config.read().await;
    if supplied == cfg.admin.token { return Some("admin".into()); }
    cfg.admin.api_tokens.iter().find(|t| t.enabled && t.token == supplied).map(|t| t.id.clone())
}

async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let actor = authenticated_token(&state, req.headers(), req.uri().query()).await;
    match actor {
        Some(actor) => {
            let method = req.method().to_string();
            let uri = req.uri().to_string();
            let response = next.run(req).await;
            if method != "GET" {
                metrics::audit(&state, &actor, &method, &uri, "").await;
            }
            response
        }
        None => {
            let cfg = state.config.read().await;
            let custom = if cfg.admin.unauthorized_response.is_empty() { cfg.system.unauth_response.clone() } else { cfg.admin.unauthorized_response.clone() };
            match custom.as_str() {
                "404" => (StatusCode::NOT_FOUND, "").into_response(),
                "blank" => (StatusCode::OK, "").into_response(),
                "" => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
                page if page.starts_with('<') => (StatusCode::UNAUTHORIZED, [("content-type", "text/html; charset=utf-8")], page.to_string()).into_response(),
                page => (StatusCode::UNAUTHORIZED, page.to_string()).into_response(),
            }
        }
    }
}

/// Secret entry path: everything must be prefixed with `admin.secure_path`.
async fn secure_entry(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let prefix = state.config.read().await.admin.secure_path.clone();
    if prefix.is_empty() { return next.run(req).await; }
    let prefix = if prefix.starts_with('/') { prefix } else { format!("/{prefix}") };
    let path = req.uri().path().to_string();
    if !path.starts_with(&prefix) {
        return (StatusCode::NOT_FOUND, "").into_response();
    }
    let stripped = path.strip_prefix(&prefix).unwrap_or("/");
    let stripped = if stripped.is_empty() { "/" } else { stripped };
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    if let Ok(uri) = format!("{stripped}{query}").parse::<axum::http::Uri>() {
        *req.uri_mut() = uri;
    }
    next.run(req).await
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback()
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Reject non-LAN clients when `admin.lan_only` is enabled.
async fn lan_only_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let enabled = state.config.read().await.admin.lan_only;
    if !enabled { return next.run(req).await; }
    let peer = req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|c| c.0.ip());
    match peer {
        Some(ip) if is_private_ip(ip) => next.run(req).await,
        Some(ip) => (StatusCode::FORBIDDEN, format!("仅允许内网访问（来源 {ip}）")).into_response(),
        None => (StatusCode::FORBIDDEN, "仅允许内网访问").into_response(),
    }
}

/// Resolve the real client address, honouring trusted reverse proxies.
pub async fn client_ip(state: &AppState, req: &Request) -> String {
    let peer = req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|c| c.0.ip());
    let trusted_proxies = state.config.read().await.admin.trusted_proxies.clone();
    let is_trusted = peer.is_some_and(|ip| {
        trusted_proxies.iter().any(|pattern| crate::waf::ip_match(pattern, &ip.to_string()))
    });
    if is_trusted {
        if let Some(forwarded) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = forwarded.split(',').next() {
                let candidate = first.trim();
                if !candidate.is_empty() { return candidate.to_string(); }
            }
        }
    }
    peer.map(|ip| ip.to_string()).unwrap_or_default()
}

async fn ui() -> Html<&'static str> { Html(include_str!("ui.html")) }

/// Default entry point now serves the upstream Gately web UI under `/gately`.
async fn upstream_home(State(state): State<AppState>) -> Response {
    let prefix = state.config.read().await.admin.secure_path.clone();
    let prefix = if prefix.is_empty() { String::new() } else if prefix.starts_with('/') { prefix } else { format!("/{prefix}") };
    axum::response::Redirect::temporary(&format!("{prefix}/gately")).into_response()
}

async fn openapi() -> Response {
    Json(json!({
        "openapi": "3.0.3",
        "info": {"title": "gately-rs API", "version": env!("CARGO_PKG_VERSION")},
        "servers": [{"url": "/api"}],
        "paths": {
            "/login": {"post": {"summary": "管理员登录"}},
            "/status": {"get": {"summary": "运行状态"}},
            "/config": {"get": {"summary": "读取配置"}},
            "/sites": {"get": {"summary": "站点列表"}, "post": {"summary": "新建站点"}},
            "/port-forwards": {"get": {"summary": "端口转发列表"}, "post": {"summary": "新建端口转发"}},
            "/proto-routes": {"get": {"summary": "协议分流列表"}, "post": {"summary": "新建协议分流"}},
            "/notifications/channels": {"get": {"summary": "通知渠道"}, "post": {"summary": "新建通知渠道"}},
            "/tasks": {"get": {"summary": "计划任务"}, "post": {"summary": "新建计划任务"}},
            "/metrics/prometheus": {"get": {"summary": "Prometheus 指标"}}
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}
    })).into_response()
}

async fn oidc_providers(State(state): State<AppState>) -> Response {
    let providers = state.config.read().await.auth.oidc.iter().filter(|p| p.enabled)
        .map(|p| json!({"id": p.id, "name": p.name})).collect::<Vec<_>>();
    Json(providers).into_response()
}

async fn login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Response {
    let cfg = state.config.read().await;
    let ip = "admin";
    let fail_limit = cfg.auth.login_rate_limit;
    drop(cfg);
    let now = Utc::now();
    {
        let mut failures = state.login_failures.write().await;
        let entry = failures.entry(ip.to_string()).or_insert((0, now));
        if (now - entry.1).num_seconds() > 300 { *entry = (0, now); }
        if fail_limit > 0 && entry.0 >= fail_limit {
            metrics::audit(&state, ip, "login", "denied", "rate limited").await;
            return (StatusCode::TOO_MANY_REQUESTS, "too many login attempts").into_response();
        }
    }
    let admin = state.config.read().await.admin.clone();
    if payload.password != admin.password {
        let mut failures = state.login_failures.write().await;
        let entry = failures.entry(ip.to_string()).or_insert((0, now));
        entry.0 += 1; entry.1 = now;
        metrics::audit(&state, ip, "login", "failed", "").await;
        return (StatusCode::UNAUTHORIZED, "bad password").into_response();
    }
    state.login_failures.write().await.remove(ip);
    metrics::audit(&state, ip, "login", "success", "").await;
    Json(json!({"token": admin.token})).into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "listeners": config.listeners.len(), "sites": config.sites.len(),
        "certificates": config.certificates.len(), "ddns_tasks": config.ddns.len(),
        "ddns_status": state.ddns_status.read().await.clone(),
        "acme_tasks": config.acme.len(), "waf_rules": config.waf_rules.len(),
        "waf_profiles": config.waf_profiles.len(), "jail": config.jail.enabled,
        "tunnels": state.tunnel_status.read().await.clone(),
        "stun": state.stun_status.read().await.clone(),
        "banned_ips": state.banned_ips.read().await.len(),
        "oidc_providers": config.auth.oidc.len(),
        "port_forwards": config.port_forwards.len(), "proto_routes": config.proto_routes.len(),
        "notifications": config.notifications.channels.len(), "scheduled_tasks": config.scheduled_tasks.len(),
        "ip_lists": config.ip_lists.len(), "site_users": config.site_users.len(),
    })).into_response()
}

async fn get_config(State(state): State<AppState>) -> Response { Json(state.config.read().await.clone()).into_response() }

async fn reload_config(State(state): State<AppState>) -> Response {
    let config = match Config::load(&state.config_path) { Ok(c) => c, Err(err) => return internal(err) };
    *state.config.write().await = config;
    Json(json!({"ok": true})).into_response()
}

/// Verify that every changed listen address can actually be bound before saving.
async fn verify_listeners(old: &Config, new: &Config) -> Result<(), String> {
    let mut candidates: Vec<String> = Vec::new();
    if old.admin.listen != new.admin.listen { candidates.push(new.admin.listen.clone()); }
    let old_listeners: Vec<String> = old.listeners.iter().map(|l| l.listen.clone()).collect();
    for listener in &new.listeners {
        if !old_listeners.contains(&listener.listen) { candidates.push(listener.listen.clone()); }
    }
    let old_forwards: Vec<String> = old.port_forwards.iter().map(|f| f.listen.clone()).collect();
    for forward in &new.port_forwards {
        if !old_forwards.contains(&forward.listen) { candidates.push(forward.listen.clone()); }
    }
    let old_routes: Vec<String> = old.proto_routes.iter().map(|r| r.listen.clone()).collect();
    for route in &new.proto_routes {
        if !old_routes.contains(&route.listen) { candidates.push(route.listen.clone()); }
    }
    for address in candidates {
        let target = address.replace("0.0.0.0", "127.0.0.1").replace("[::]", "::1");
        match std::net::TcpListener::bind(&target) {
            Ok(listener) => drop(listener),
            Err(err) => return Err(format!("监听地址 {address} 不可用：{err}")),
        }
    }
    Ok(())
}

async fn set_config(State(state): State<AppState>, Json(payload): Json<Config>) -> Response {
    let old = state.config.read().await.clone();
    if let Err(err) = verify_listeners(&old, &payload).await {
        return (StatusCode::BAD_REQUEST, format!("配置未保存：{err}")).into_response();
    }
    if let Err(err) = persist(&state, &payload) { return internal(err); }
    *state.config.write().await = payload;
    Json(json!({"ok": true})).into_response()
}

async fn list_sites(State(state): State<AppState>) -> Response { Json(state.config.read().await.sites.clone()).into_response() }

async fn add_site(State(state): State<AppState>, Json(payload): Json<SiteRequest>) -> Response {
    if payload.backend.is_empty() && payload.kind == "proxy" { return bad_request("backend is required for proxy sites"); }
    let site = SiteConfig {
        id: new_id("site"), domains: payload.domains, backend: payload.backend, listener: payload.listener,
        kind: if payload.kind.is_empty() { "proxy".into() } else { payload.kind }, ..Default::default()
    };
    let mut config = state.config.write().await;
    config.sites.push(site.clone());
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(site).into_response()
}

async fn update_site(State(state): State<AppState>, Path(id): Path<String>, Json(payload): Json<Value>) -> Response {
    let mut config = state.config.write().await;
    let site = match config.sites.iter_mut().find(|s| s.id == id) { Some(s) => s, None => return StatusCode::NOT_FOUND.into_response() };
    if let Ok(patch) = serde_json::from_value::<SiteConfig>(payload.clone()) { *site = patch; }
    else {
        let merged: Value = match serde_json::to_value(&*site).map(|mut v| { merge_json(&mut v, &payload); v }) { Ok(v) => v, Err(e) => return bad_request(e) };
        match serde_json::from_value(merged) { Ok(v) => *site = v, Err(e) => return bad_request(e) }
    }
    let out = site.clone();
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(out).into_response()
}

fn merge_json(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(a), Value::Object(b)) => for (k, v) in b { merge_json(a.entry(k.clone()).or_insert(Value::Null), v) },
        (a, b) => *a = b.clone(),
    }
}

/// 点分路径定位配置块，例如 `notifications.channels`。
fn json_path_mut<'a>(root: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let mut cur = root;
    for part in path.split('.') { cur = cur.get_mut(part)?; }
    Some(cur)
}

/// 后台所有列表项共用的新增 / 更新实现。
/// PUT 表示整体替换（保留 id），PATCH 表示局部合并；两者都会整体反序列化校验后写盘。
pub(crate) async fn apply_item(
    state: &AppState,
    resource: &str,
    id: Option<&str>,
    patch: Value,
    replace: bool,
) -> Response {
    let mut config = state.config.write().await;
    let mut root = match serde_json::to_value(&*config) { Ok(v) => v, Err(e) => return internal(e) };
    let arr = match json_path_mut(&mut root, resource).and_then(Value::as_array_mut) {
        Some(a) => a,
        None => return bad_request(format!("未知资源: {resource}")),
    };
    let mut item = match patch.as_object() {
        Some(o) => o.clone(),
        None => return bad_request("请求体必须是 JSON 对象"),
    };
    let item_id = match id {
        Some(i) => i.to_string(),
        None => item.get("id").and_then(Value::as_str).map(str::to_string)
            .unwrap_or_else(|| new_id(resource.rsplit('.').next().unwrap_or(resource))),
    };
    item.insert("id".into(), json!(item_id));
    match id {
        Some(_) => {
            let idx = match arr.iter().position(|v| v.get("id").and_then(Value::as_str) == Some(&item_id)) {
                Some(i) => i,
                None => return (StatusCode::NOT_FOUND, "配置项不存在").into_response(),
            };
            if replace { arr[idx] = Value::Object(item); } else { merge_json(&mut arr[idx], &Value::Object(item)); }
        }
        None => {
            if arr.iter().any(|v| v.get("id").and_then(Value::as_str) == Some(&item_id)) {
                return bad_request("ID 已存在");
            }
            arr.push(Value::Object(item));
        }
    }
    let updated: Config = match serde_json::from_value(root) { Ok(c) => c, Err(e) => return bad_request(format!("配置无效: {e}")) };
    if let Err(err) = persist(state, &updated) { return internal(err); }
    *config = updated;
    Json(json!({ "ok": true })).into_response()
}

macro_rules! item_handlers {
    ($($name:ident => $key:expr),+ $(,)?) => {
        $(
            async fn $name(
                State(state): State<AppState>,
                method: axum::http::Method,
                Path(id): Path<String>,
                Json(patch): Json<Value>,
            ) -> Response {
                apply_item(&state, $key, Some(&id), patch, method == axum::http::Method::PUT).await
            }
        )+
    };
}

item_handlers! {
    update_listener_item => "listeners",
    update_site_item => "sites",
    update_cert_item => "certificates",
    update_ddns_item => "ddns",
    update_acme_item => "acme",
    update_waf_rule_item => "waf_rules",
    update_waf_profile_item => "waf_profiles",
    update_tunnel_item => "tunnels",
    update_stun_item => "stun",
    update_forward_item => "port_forwards",
    update_route_item => "proto_routes",
    update_site_user_item => "site_users",
    update_ip_list_item => "ip_lists",
    update_task_item => "scheduled_tasks",
    update_channel_item => "notifications.channels",
    update_notify_rule_item => "notifications.rules",
    update_api_token_item => "admin.api_tokens",
}

/// 通用新增：用于后台高级表单一次性提交完整配置对象。
async fn create_item(
    State(state): State<AppState>,
    Path(resource): Path<String>,
    Json(patch): Json<Value>,
) -> Response {
    let key = match resource.as_str() {
        "listeners" => "listeners",
        "sites" => "sites", "certs" => "certificates", "certificates" => "certificates",
        "ddns" => "ddns", "acme" => "acme", "waf-rules" | "waf_rules" => "waf_rules",
        "waf-profiles" | "waf_profiles" => "waf_profiles", "tunnels" => "tunnels", "stun" => "stun",
        "port-forwards" | "port_forwards" => "port_forwards", "proto-routes" | "proto_routes" => "proto_routes",
        "site-users" | "site_users" => "site_users", "ip-lists" | "ip_lists" => "ip_lists",
        "tasks" | "scheduled_tasks" => "scheduled_tasks",
        "channels" => "notifications.channels", "notify-rules" | "notify_rules" => "notifications.rules",
        "api-tokens" | "api_tokens" => "admin.api_tokens", "storage" => "storage",
        "knock-rules" | "knock_rules" => "knock.rules", "wol-hosts" | "wol_hosts" => "wol.hosts",
        _ => return bad_request(format!("未知资源: {resource}")),
    };
    apply_item(&state, key, None, patch, true).await
}

async fn delete_site(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.sites.retain(|s| s.id != id);
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({"ok": true})).into_response()
}

async fn list_certs(State(state): State<AppState>) -> Response { Json(state.config.read().await.certificates.clone()).into_response() }

async fn add_cert(State(state): State<AppState>, Json(payload): Json<CertRequest>) -> Response {
    let cert = CertificateConfig { id: payload.id, cert_path: payload.cert_path, key_path: payload.key_path, ..Default::default() };
    let mut config = state.config.write().await;
    config.certificates.push(cert.clone());
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(cert).into_response()
}

async fn delete_cert(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.certificates.retain(|c| c.id != id);
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({"ok": true})).into_response()
}

async fn list_ddns(State(state): State<AppState>) -> Response { Json(state.config.read().await.ddns.clone()).into_response() }

async fn add_ddns(State(state): State<AppState>, Json(payload): Json<DdnsRequest>) -> Response {
    let ip_source: IpSource = match serde_json::from_value(payload.ip_source) { Ok(s) => s, Err(err) => return bad_request(err) };
    let task = DdnsTask {
        id: payload.id.unwrap_or_else(|| new_id("ddns")), enabled: payload.enabled, provider: payload.provider,
        zone_id: payload.zone_id, api_token: payload.api_token, name: payload.name,
        record_type: payload.record_type.to_ascii_uppercase(), ip_source,
        interval_secs: payload.interval_secs.max(30), last_ip: None, options: payload.options,
        webhooks: payload.webhooks, ..Default::default()
    };
    let mut config = state.config.write().await;
    config.ddns.push(task.clone());
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(task).into_response()
}

async fn delete_ddns(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.ddns.retain(|t| t.id != id);
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({"ok": true})).into_response()
}

async fn run_ddns(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match run_and_record(&state, &id).await {
        Ok(ip) => Json(json!({"ok": true, "ip": ip})).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

async fn import_config(State(state): State<AppState>, Json(payload): Json<ImportRequest>) -> Response {
    match migrate::import_paths(&state, payload.paths, payload.keep_enabled).await {
        Ok(report) => Json(report).into_response(), Err(err) => bad_request(err),
    }
}

async fn history_list(State(state): State<AppState>) -> Response {
    match history::list(&state.config_path) { Ok(ids) => Json(ids).into_response(), Err(err) => internal(err) }
}
async fn history_get(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match history::read(&state.config_path, &id) { Ok(text) => (StatusCode::OK, text).into_response(), Err(err) => bad_request(err) }
}
async fn history_diff(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match history::diff_with_current(&state.config_path, &id) { Ok(d) => (StatusCode::OK, d).into_response(), Err(err) => bad_request(err) }
}
async fn history_diff_two(State(state): State<AppState>, Path((a, b)): Path<(String, String)>) -> Response {
    match history::diff(&state.config_path, &a, &b) { Ok(d) => (StatusCode::OK, d).into_response(), Err(err) => bad_request(err) }
}
async fn history_rollback(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let text = match history::read(&state.config_path, &id) { Ok(t) => t, Err(err) => return bad_request(err) };
    let config: Config = match serde_json::from_str(&text) { Ok(c) => c, Err(err) => return bad_request(err) };
    if let Err(err) = config.save(&state.config_path) { return internal(err); }
    *state.config.write().await = config;
    metrics::audit(&state, "admin", "rollback", &id, "").await;
    Json(json!({"ok": true, "id": id})).into_response()
}

async fn list_generic(state: AppState, kind: &str) -> Response {
    let config = state.config.read().await;
    let value = match kind {
        "acme" => json!(config.acme), "waf_rules" => json!(config.waf_rules),
        "waf_profiles" => json!(config.waf_profiles), "tunnels" => json!(config.tunnels),
        "stun" => json!(config.stun), "port_forwards" => json!(config.port_forwards),
        "proto_routes" => json!(config.proto_routes), "site_users" => json!(config.site_users),
        "ip_lists" => json!(config.ip_lists), "notify_channels" => json!(config.notifications.channels),
        "notify_rules" => json!(config.notifications.rules), "tasks" => json!(config.scheduled_tasks),
        "api_tokens" => json!(config.admin.api_tokens), _ => json!([]),
    };
    Json(value).into_response()
}

async fn add_generic(state: AppState, kind: &str, value: Value) -> Response {
    let mut config = state.config.write().await;
    let result: Result<Value, String> = match kind {
        "acme" => serde_json::from_value(value).map(|v: crate::config::AcmeTask| { config.acme.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "waf_rules" => serde_json::from_value(value).map(|v: crate::config::WafRule| { config.waf_rules.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "waf_profiles" => serde_json::from_value(value).map(|v: crate::config::WafProfile| { config.waf_profiles.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "tunnels" => serde_json::from_value(value).map(|v: crate::config::TunnelTask| { config.tunnels.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "stun" => serde_json::from_value(value).map(|v: crate::config::StunTask| { config.stun.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "port_forwards" => serde_json::from_value(value).map(|v: crate::config::PortForwardTask| { config.port_forwards.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "proto_routes" => serde_json::from_value(value).map(|v: crate::config::ProtoRouteTask| { config.proto_routes.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "site_users" => serde_json::from_value(value).map(|v: crate::config::SiteUser| { config.site_users.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "ip_lists" => serde_json::from_value(value).map(|v: crate::config::IpList| { config.ip_lists.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "notify_channels" => serde_json::from_value(value).map(|v: crate::config::NotifyChannel| { config.notifications.channels.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "notify_rules" => serde_json::from_value(value).map(|v: crate::config::NotifyRule| { config.notifications.rules.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "tasks" => serde_json::from_value(value).map(|v: crate::config::ScheduledTask| { config.scheduled_tasks.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        "api_tokens" => serde_json::from_value(value).map(|v: ApiToken| { config.admin.api_tokens.push(v.clone()); json!(v) }).map_err(|e| e.to_string()),
        _ => Err("unknown kind".into()),
    };
    let item = match result { Ok(v) => v, Err(err) => return bad_request(err) };
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(item).into_response()
}

async fn delete_generic(state: AppState, kind: &str, id: &str) -> Response {
    let mut config = state.config.write().await;
    match kind {
        "acme" => config.acme.retain(|x| x.id != id),
        "waf_rules" => config.waf_rules.retain(|x| x.id != id),
        "waf_profiles" => config.waf_profiles.retain(|x| x.id != id),
        "tunnels" => config.tunnels.retain(|x| x.id != id),
        "stun" => config.stun.retain(|x| x.id != id),
        "port_forwards" => config.port_forwards.retain(|x| x.id != id),
        "proto_routes" => config.proto_routes.retain(|x| x.id != id),
        "site_users" => config.site_users.retain(|x| x.id != id),
        "ip_lists" => config.ip_lists.retain(|x| x.id != id),
        "notify_channels" => config.notifications.channels.retain(|x| x.id != id),
        "notify_rules" => config.notifications.rules.retain(|x| x.id != id),
        "tasks" => config.scheduled_tasks.retain(|x| x.id != id),
        "api_tokens" => config.admin.api_tokens.retain(|x| x.id != id),
        _ => {}
    }
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({"ok": true})).into_response()
}

macro_rules! generic_routes {
    ($kind:literal,$list:ident,$add:ident,$del:ident) => {
        async fn $list(State(state): State<AppState>) -> Response { list_generic(state, $kind).await }
        async fn $add(State(state): State<AppState>, Json(payload): Json<Value>) -> Response { add_generic(state, $kind, payload).await }
        async fn $del(State(state): State<AppState>, Path(id): Path<String>) -> Response { delete_generic(state, $kind, &id).await }
    };
}

generic_routes!("acme", list_acme, add_acme, delete_acme);
generic_routes!("waf_rules", list_waf_rules, add_waf_rule, delete_waf_rule);
generic_routes!("waf_profiles", list_waf_profiles, add_waf_profile, delete_waf_profile);
generic_routes!("tunnels", list_tunnels, add_tunnel, delete_tunnel);
generic_routes!("stun", list_stun, add_stun, delete_stun);
generic_routes!("port_forwards", list_forwards, add_forward, delete_forward);
generic_routes!("proto_routes", list_routes, add_route, delete_route);
generic_routes!("site_users", list_site_users, add_site_user, delete_site_user);
generic_routes!("ip_lists", list_ip_lists, add_ip_list, delete_ip_list);
generic_routes!("notify_channels", list_channels, add_channel, delete_channel);
generic_routes!("notify_rules", list_rules, add_rule, delete_rule);
generic_routes!("tasks", list_tasks, add_task, delete_task);
generic_routes!("api_tokens", list_api_tokens, add_api_token, delete_api_token);

async fn set_jail(State(state): State<AppState>, Json(payload): Json<JailConfig>) -> Response {
    let mut config = state.config.write().await;
    config.jail = payload.clone();
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(payload).into_response()
}
async fn set_auth(State(state): State<AppState>, Json(payload): Json<AuthConfig>) -> Response {
    let mut config = state.config.write().await;
    config.auth = payload.clone();
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(payload).into_response()
}
async fn set_notifications(State(state): State<AppState>, Json(payload): Json<crate::config::NotificationConfig>) -> Response {
    let mut config = state.config.write().await;
    config.notifications = payload.clone();
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(payload).into_response()
}
async fn set_system(State(state): State<AppState>, Json(payload): Json<crate::config::SystemConfig>) -> Response {
    let mut config = state.config.write().await;
    config.system = payload.clone();
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(payload).into_response()
}
async fn set_backups(State(state): State<AppState>, Json(payload): Json<crate::config::BackupConfig>) -> Response {
    let mut config = state.config.write().await;
    config.backups = payload.clone();
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(payload).into_response()
}

async fn site_login(State(state): State<AppState>, headers: axum::http::HeaderMap, axum::Form(form): axum::Form<String>) -> Response {
    let _ = &form;
    let body = form;
    let site_id = body.split('&').find_map(|p| p.strip_prefix("site=")).map(|v| v.to_string()).unwrap_or_default();
    let site = state.config.read().await.sites.iter().find(|s| s.id == site_id).cloned();
    match site {
        Some(site) => site_ext::handle_login(state, site, headers, &body).await,
        None => (StatusCode::NOT_FOUND, "site not found").into_response(),
    }
}

async fn banned_ips(State(state): State<AppState>) -> Response {
    Json(state.banned_ips.read().await.clone()).into_response()
}

/// Read or update a sub-module configuration block (knock/docker/files/terminal/diag/...).
async fn module_config(State(state): State<AppState>, Path(name): Path<String>, payload: Option<Json<Value>>) -> Response {
    let mut config = state.config.write().await;
    let mut root = match serde_json::to_value(&*config) { Ok(v) => v, Err(e) => return internal(e) };
    let key = match name.as_str() {
        "knock" => "knock", "docker" => "docker", "files" => "files",
        "terminal" => "terminal", "diag" => "diag", "system" => "system",
        "notifications" => "notifications", "backups" => "backups", "admin" => "admin",
        "wol" => "wol", "storage" => "storage", "filebrowser" => "filebrowser",
        "smb" => "smb", "perf" => "perf",
        _ => return (StatusCode::NOT_FOUND, format!("unknown module: {name}")).into_response(),
    };
    match payload {
        None => {
            let value = root.get(key).cloned().unwrap_or(Value::Null);
            Json(value).into_response()
        }
        Some(Json(patch)) => {
            let current = root.get(key).cloned().unwrap_or(json!({}));
            let mut merged = current;
            merge_json(&mut merged, &patch);
            if let Some(obj) = root.as_object_mut() { obj.insert(key.to_string(), merged); }
            let updated: Config = match serde_json::from_value(root) { Ok(c) => c, Err(e) => return bad_request(format!("配置无效: {e}")) };
            if let Ok(text) = fs::read_to_string(&state.config_path) { let _ = history::snapshot(&state.config_path, &text); }
            if let Err(err) = updated.save(&state.config_path) { return internal(err); }
            *config = updated;
            Json(json!({ "ok": true })).into_response()
        }
    }
}

async fn run_backup(State(state): State<AppState>) -> Response {
    match scheduler::create_backup(&state).await {
        Ok(path) => Json(json!({"ok": true, "path": path})).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct RestoreRequest { pub path: String, #[serde(default)] pub password: String }

async fn restore_backup(State(state): State<AppState>, Json(payload): Json<RestoreRequest>) -> Response {
    match scheduler::restore_backup(&state, &payload.path, &payload.password).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

pub async fn admin_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/login", post(login))
        .route("/login/totp", post(auth_ext::totp_handler))
        .route("/login/oidc/providers", get(oidc_providers))
        .route("/login/oidc/start", get(auth_ext::oidc_start))
        .route("/auth/oidc/callback", get(auth_ext::oidc_callback))
        .route("/login/oidc/token", post(auth_ext::oidc_token))
        .route("/site-login", post(site_login))
        .route("/openapi.json", get(openapi));

    let protected = Router::new()
        .route("/status", get(status))
        .route("/config", get(get_config).put(set_config))
        .route("/config/reload", post(reload_config))
        .route("/metrics", get(metrics::stats_summary))
        .route("/metrics/prometheus", get(metrics::metrics_prometheus))
        .route("/system", get(metrics::system_handler).put(set_system))
        .route("/topology", get(metrics::topology_handler))
        .route("/audit", get(metrics::audit_handler))
        .route("/import", post(import_config))
        .route("/history", get(history_list))
        .route("/history/diff/{a}/{b}", get(history_diff_two))
        .route("/history/{id}", get(history_get))
        .route("/history/{id}/diff", get(history_diff))
        .route("/history/{id}/rollback", post(history_rollback))
        .route("/listeners/{id}", axum::routing::put(update_listener_item).patch(update_listener_item))
        .route("/sites", get(list_sites).post(add_site))
        .route("/sites/{id}", axum::routing::put(update_site_item).patch(update_site_item).delete(delete_site))
        .route("/certs", get(list_certs).post(add_cert))
        .route("/certs/{id}", axum::routing::put(update_cert_item).patch(update_cert_item).delete(delete_cert))
        .route("/ddns", get(list_ddns).post(add_ddns))
        .route("/ddns/{id}", axum::routing::put(update_ddns_item).patch(update_ddns_item).delete(delete_ddns))
        .route("/ddns/{id}/run", post(run_ddns))
        .route("/acme", get(list_acme).post(add_acme))
        .route("/acme/{id}", axum::routing::put(update_acme_item).patch(update_acme_item).delete(delete_acme))
        .route("/acme/{id}/run", post(acme::run_handler))
        .route("/acme/dns-tokens", get(acme::dns_tokens_handler))
        .route("/waf/rules", get(list_waf_rules).post(add_waf_rule))
        .route("/waf/rules/{id}", axum::routing::put(update_waf_rule_item).patch(update_waf_rule_item).delete(delete_waf_rule))
        .route("/waf/profiles", get(list_waf_profiles).post(add_waf_profile))
        .route("/waf/profiles/{id}", axum::routing::put(update_waf_profile_item).patch(update_waf_profile_item).delete(delete_waf_profile))
        .route("/jail", get(|| async { Json(json!({})) }).post(set_jail))
        .route("/jail/bans", get(banned_ips))
        .route("/jail/ban", post(waf::ban_handler))
        .route("/jail/unban/{ip}", post(waf::unban_handler))
        .route("/tunnels", get(list_tunnels).post(add_tunnel))
        .route("/tunnels/{id}", axum::routing::put(update_tunnel_item).patch(update_tunnel_item).delete(delete_tunnel))
        .route("/tunnels/status", get(crate::state::tunnel_status_handler))
        .route("/tunnels/{id}/install", post(tunnel::install_handler))
        .route("/tunnels/{id}/rollback", post(tunnel::rollback_handler))
        .route("/stun", get(list_stun).post(add_stun))
        .route("/stun/{id}", axum::routing::put(update_stun_item).patch(update_stun_item).delete(delete_stun))
        .route("/stun/status", get(crate::state::stun_status_handler))
        .route("/stun/{id}/run", post(stun::run_handler))
        .route("/port-forwards", get(list_forwards).post(add_forward))
        .route("/port-forwards/{id}", axum::routing::put(update_forward_item).patch(update_forward_item).delete(delete_forward))
        .route("/port-forwards/status", get(portforward::status_handler))
        .route("/proto-routes", get(list_routes).post(add_route))
        .route("/proto-routes/{id}", axum::routing::put(update_route_item).patch(update_route_item).delete(delete_route))
        .route("/proto-routes/status", get(protoroute::status_handler))
        .route("/site-users", get(list_site_users).post(add_site_user))
        .route("/site-users/{id}", axum::routing::put(update_site_user_item).patch(update_site_user_item).delete(delete_site_user))
        .route("/ip-lists", get(list_ip_lists).post(add_ip_list))
        .route("/ip-lists/{id}", axum::routing::put(update_ip_list_item).patch(update_ip_list_item).delete(delete_ip_list))
        .route("/ip-lists/status", get(portforward::ip_lists_status))
        .route("/notifications", get(|| async { Json(json!({})) }).put(set_notifications))
        .route("/notifications/channels", get(list_channels).post(add_channel))
        .route("/notifications/channels/{id}", axum::routing::put(update_channel_item).patch(update_channel_item).delete(delete_channel))
        .route("/notifications/rules", get(list_rules).post(add_rule))
        .route("/notifications/rules/{id}", axum::routing::put(update_notify_rule_item).patch(update_notify_rule_item).delete(delete_rule))
        .route("/notifications/queue", get(notify::queue_handler))
        .route("/notifications/test/{id}", post(notify::test_channel))
        .route("/tasks", get(list_tasks).post(add_task))
        .route("/tasks/{id}", axum::routing::put(update_task_item).patch(update_task_item).delete(delete_task))
        .route("/tasks/{id}/run", post(scheduler::run_handler))
        .route("/tasks/status", get(crate::state::task_status_handler))
        .route("/backups", get(|| async { Json(json!({})) }).put(set_backups))
        .route("/backups/run", post(run_backup))
        .route("/backups/restore", post(restore_backup))
        .route("/api-tokens", get(list_api_tokens).post(add_api_token))
        .route("/api-tokens/{id}", axum::routing::put(update_api_token_item).patch(update_api_token_item).delete(delete_api_token))
        .route("/items/{resource}", post(create_item))
        .route("/auth", get(|| async { Json(json!({})) }).post(set_auth))
        .route("/certificates/report", get(metrics::certificate_report))
        .route("/visitor-audit", get(metrics::visitor_audit_handler))
        .route("/visitor-audit/export", get(metrics::visitor_audit_export))
        .route("/modules/{name}", get(module_config).put(module_config))
        .merge(extras::router())
        .merge(knock::router(state.clone()))
        .merge(terminal::router(state.clone()))
        .merge(diag::router(state.clone()))
        .merge(docker::router(state.clone()))
        .merge(lists::router(state.clone()))
        .merge(update::router(state.clone()))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let api = public.merge(protected);
    let app = Router::new()
        .route("/", get(upstream_home))
        .route("/ui", get(upstream_home))
        .route("/ui-legacy", get(ui))
        .nest("/api", api);
    let app = crate::upstream::mount(app, &state);

    // Secret entry path: the whole admin surface lives under the configured prefix.
    let prefix = state.config.read().await.admin.secure_path.clone();
    let app = if prefix.is_empty() {
        app
    } else {
        let prefix = if prefix.starts_with('/') { prefix } else { format!("/{prefix}") };
        Router::new().nest(&prefix, app)
    };

    app.layer(middleware::from_fn_with_state(state.clone(), lan_only_guard))
        .with_state(state)
}
