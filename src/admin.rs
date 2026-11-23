use crate::acme;
use crate::auth_ext;
use crate::config::{AuthConfig, CertificateConfig, Config, DdnsTask, IpSource, JailConfig, SiteConfig};
use crate::ddns::run_and_record;
use crate::history;
use crate::migrate;
use crate::state::AppState;
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

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SiteRequest {
    pub domains: Vec<String>,
    pub backend: String,
    pub listener: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CertRequest {
    pub id: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize)]
pub struct DdnsRequest {
    pub id: Option<String>,
    pub enabled: bool,
    pub provider: String,
    pub zone_id: String,
    pub api_token: String,
    pub name: String,
    pub record_type: String,
    pub ip_source: Value,
    pub interval_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub paths: Vec<String>,
    #[serde(default)]
    pub keep_enabled: bool,
}

fn new_id(prefix: &str) -> String {
    format!("{}_{}", prefix, Utc::now().timestamp_millis())
}

fn bad_request(err: impl std::fmt::Display) -> Response {
    (StatusCode::BAD_REQUEST, err.to_string()).into_response()
}

fn internal(err: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
}

fn persist(state: &AppState, config: &Config) -> Result<(), String> {
    if let Ok(text) = fs::read_to_string(&state.config_path) {
        let _ = history::snapshot(&state.config_path, &text);
    }
    config.save(&state.config_path)
}

async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let expected = state.config.read().await.admin.token.clone();
    let authorized = req.headers().get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == expected)
        .unwrap_or(false);
    if !authorized { return (StatusCode::UNAUTHORIZED, "unauthorized").into_response(); }
    next.run(req).await
}

async fn ui() -> Html<&'static str> { Html(include_str!("ui.html")) }

async fn oidc_providers(State(state): State<AppState>) -> Response {
    let providers = state.config.read().await.auth.oidc.iter()
        .filter(|p| p.enabled)
        .map(|p| json!({ "id": p.id, "name": p.name }))
        .collect::<Vec<_>>();
    Json(providers).into_response()
}

async fn login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Response {
    let admin = state.config.read().await.admin.clone();
    if payload.password != admin.password { return (StatusCode::UNAUTHORIZED, "bad password").into_response(); }
    Json(json!({ "token": admin.token })).into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    let ddns = state.ddns_status.read().await.clone();
    let tunnels = state.tunnel_status.read().await.clone();
    let stun = state.stun_status.read().await.clone();
    let bans = state.banned_ips.read().await.len();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "listeners": config.listeners.len(),
        "sites": config.sites.len(),
        "certificates": config.certificates.len(),
        "ddns_tasks": config.ddns.len(),
        "ddns_status": ddns,
        "acme_tasks": config.acme.len(),
        "waf_rules": config.waf_rules.len(),
        "waf_profiles": config.waf_profiles.len(),
        "jail": config.jail.enabled,
        "tunnels": tunnels,
        "stun": stun,
        "banned_ips": bans,
        "oidc_providers": config.auth.oidc.len(),
    })).into_response()
}

async fn get_config(State(state): State<AppState>) -> Response {
    Json(state.config.read().await.clone()).into_response()
}

async fn reload_config(State(state): State<AppState>) -> Response {
    let config = match Config::load(&state.config_path) { Ok(c) => c, Err(err) => return internal(err) };
    *state.config.write().await = config;
    Json(json!({ "ok": true })).into_response()
}

async fn list_sites(State(state): State<AppState>) -> Response {
    Json(state.config.read().await.sites.clone()).into_response()
}

async fn add_site(State(state): State<AppState>, Json(payload): Json<SiteRequest>) -> Response {
    if payload.backend.is_empty() || payload.domains.is_empty() { return bad_request("domains and backend are required"); }
    let site = SiteConfig {
        id: new_id("site"), domains: payload.domains, backend: payload.backend, listener: payload.listener,
        waf_profile: None, waf_mode: "off".into(), allowed_ips: vec![], denied_ips: vec![],
    };
    let mut config = state.config.write().await;
    config.sites.push(site.clone());
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(site).into_response()
}

async fn delete_site(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.sites.retain(|s| s.id != id);
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({ "ok": true })).into_response()
}

async fn list_certs(State(state): State<AppState>) -> Response {
    Json(state.config.read().await.certificates.clone()).into_response()
}

async fn add_cert(State(state): State<AppState>, Json(payload): Json<CertRequest>) -> Response {
    let cert = CertificateConfig { id: payload.id, cert_path: payload.cert_path, key_path: payload.key_path, acme_id: None };
    let mut config = state.config.write().await;
    config.certificates.push(cert.clone());
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(cert).into_response()
}

async fn delete_cert(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.certificates.retain(|c| c.id != id);
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({ "ok": true })).into_response()
}

async fn list_ddns(State(state): State<AppState>) -> Response {
    Json(state.config.read().await.ddns.clone()).into_response()
}

async fn add_ddns(State(state): State<AppState>, Json(payload): Json<DdnsRequest>) -> Response {
    let ip_source: IpSource = match serde_json::from_value(payload.ip_source) { Ok(s) => s, Err(err) => return bad_request(err) };
    let task = DdnsTask {
        id: payload.id.unwrap_or_else(|| new_id("ddns")),
        enabled: payload.enabled, provider: payload.provider, zone_id: payload.zone_id, api_token: payload.api_token,
        name: payload.name, record_type: payload.record_type.to_ascii_uppercase(), ip_source,
        interval_secs: payload.interval_secs.max(30), last_ip: None,
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
    Json(json!({ "ok": true })).into_response()
}

async fn run_ddns(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match run_and_record(&state, &id).await {
        Ok(ip) => Json(json!({ "ok": true, "ip": ip })).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

async fn import_config(State(state): State<AppState>, Json(payload): Json<ImportRequest>) -> Response {
    match migrate::import_paths(&state, payload.paths, payload.keep_enabled).await {
        Ok(report) => Json(report).into_response(),
        Err(err) => bad_request(err),
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
    Json(json!({ "ok": true, "id": id })).into_response()
}

async fn list_generic(state: AppState, kind: &str) -> Response {
    let config = state.config.read().await;
    let value = match kind {
        "acme" => json!(config.acme),
        "waf_rules" => json!(config.waf_rules),
        "waf_profiles" => json!(config.waf_profiles),
        "tunnels" => json!(config.tunnels),
        "stun" => json!(config.stun),
        _ => json!([]),
    };
    Json(value).into_response()
}

async fn add_generic(state: AppState, kind: &str, value: Value) -> Response {
    let mut config = state.config.write().await;
    let result = match kind {
        "acme" => serde_json::from_value(value).map(|v: crate::config::AcmeTask| { config.acme.push(v.clone()); json!(v) }),
        "waf_rules" => serde_json::from_value(value).map(|v: crate::config::WafRule| { config.waf_rules.push(v.clone()); json!(v) }),
        "waf_profiles" => serde_json::from_value(value).map(|v: crate::config::WafProfile| { config.waf_profiles.push(v.clone()); json!(v) }),
        "tunnels" => serde_json::from_value(value).map(|v: crate::config::TunnelTask| { config.tunnels.push(v.clone()); json!(v) }),
        "stun" => serde_json::from_value(value).map(|v: crate::config::StunTask| { config.stun.push(v.clone()); json!(v) }),
        _ => Err(serde_json::from_str::<Value>("null").unwrap_err()),
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
        _ => {}
    }
    if let Err(err) = persist(&state, &config) { return internal(err); }
    Json(json!({ "ok": true })).into_response()
}

macro_rules! generic_routes {
    ($router:expr, $kind:literal, $list:ident, $add:ident, $del:ident) => {
        async fn $list(State(state): State<AppState>) -> Response { list_generic(state, $kind).await }
        async fn $add(State(state): State<AppState>, Json(payload): Json<Value>) -> Response { add_generic(state, $kind, payload).await }
        async fn $del(State(state): State<AppState>, Path(id): Path<String>) -> Response { delete_generic(state, $kind, &id).await }

    };
}

generic_routes!(r, "acme", list_acme, add_acme, delete_acme);
generic_routes!(r, "waf_rules", list_waf_rules, add_waf_rule, delete_waf_rule);
generic_routes!(r, "waf_profiles", list_waf_profiles, add_waf_profile, delete_waf_profile);
generic_routes!(r, "tunnels", list_tunnels, add_tunnel, delete_tunnel);
generic_routes!(r, "stun", list_stun, add_stun, delete_stun);

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

async fn tunnel_status(State(state): State<AppState>) -> Response {
    Json(state.tunnel_status.read().await.clone()).into_response()
}

async fn stun_status(State(state): State<AppState>) -> Response {
    Json(state.stun_status.read().await.clone()).into_response()
}

async fn banned_ips(State(state): State<AppState>) -> Response {
    Json(state.banned_ips.read().await.clone()).into_response()
}

pub fn admin_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/login", post(login))
        .route("/login/totp", post(auth_ext::totp_handler))
        .route("/login/oidc/providers", get(oidc_providers))
        .route("/login/oidc/start", get(auth_ext::oidc_start))
        .route("/auth/oidc/callback", get(auth_ext::oidc_callback))
        .route("/login/oidc/token", post(auth_ext::oidc_token));

    let protected = Router::new()
        .route("/status", get(status))
        .route("/config", get(get_config))
        .route("/config/reload", post(reload_config))
        .route("/import", post(import_config))
        .route("/history", get(history_list))
        .route("/history/diff/{a}/{b}", get(history_diff_two))
        .route("/history/{id}", get(history_get))
        .route("/history/{id}/diff", get(history_diff))
        .route("/history/{id}/rollback", post(history_rollback))
        .route("/sites", get(list_sites).post(add_site))
        .route("/sites/{id}", delete(delete_site))
        .route("/certs", get(list_certs).post(add_cert))
        .route("/certs/{id}", delete(delete_cert))
        .route("/ddns", get(list_ddns).post(add_ddns))
        .route("/ddns/{id}", delete(delete_ddns))
        .route("/ddns/{id}/run", post(run_ddns))
        .route("/acme", get(list_acme).post(add_acme))
        .route("/acme/{id}", delete(delete_acme))
        .route("/acme/{id}/run", post(acme::run_handler))
        .route("/waf/rules", get(list_waf_rules).post(add_waf_rule))
        .route("/waf/rules/{id}", delete(delete_waf_rule))
        .route("/waf/profiles", get(list_waf_profiles).post(add_waf_profile))
        .route("/waf/profiles/{id}", delete(delete_waf_profile))
        .route("/jail", post(set_jail))
        .route("/jail/bans", get(banned_ips))
        .route("/tunnels", get(list_tunnels).post(add_tunnel))
        .route("/tunnels/{id}", delete(delete_tunnel))
        .route("/tunnels/status", get(tunnel_status))
        .route("/stun", get(list_stun).post(add_stun))
        .route("/stun/{id}", delete(delete_stun))
        .route("/stun/status", get(stun_status))
        .route("/auth", post(set_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/", get(ui))
        .route("/ui", get(ui))
        .nest("/api", public.merge(protected))
        .with_state(state)
}
