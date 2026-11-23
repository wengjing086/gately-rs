use crate::config::{CertificateConfig, Config, DdnsTask, IpSource, SiteConfig};
use crate::ddns::run_and_record;
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
use serde_json::json;

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
    pub ip_source: serde_json::Value,
    pub interval_secs: u64,
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

async fn require_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let expected = state.config.read().await.admin.token.clone();
    let authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == expected)
        .unwrap_or(false);
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(req).await
}

async fn ui() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

async fn login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Response {
    let admin = state.config.read().await.admin.clone();
    if payload.password != admin.password {
        return (StatusCode::UNAUTHORIZED, "bad password").into_response();
    }
    Json(json!({ "token": admin.token })).into_response()
}

async fn status(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    let ddns = state.ddns_status.read().await.clone();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "listeners": config.listeners.len(),
        "sites": config.sites.len(),
        "certificates": config.certificates.len(),
        "ddns_tasks": config.ddns.len(),
        "ddns_status": ddns,
    }))
    .into_response()
}

async fn get_config(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    Json(config.clone()).into_response()
}

async fn reload_config(State(state): State<AppState>) -> Response {
    let config = match Config::load(&state.config_path) {
        Ok(config) => config,
        Err(err) => return internal(err),
    };
    let mut current = state.config.write().await;
    *current = config;
    Json(json!({ "ok": true })).into_response()
}

async fn list_sites(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    Json(config.sites.clone()).into_response()
}

async fn add_site(State(state): State<AppState>, Json(payload): Json<SiteRequest>) -> Response {
    if payload.backend.is_empty() || payload.domains.is_empty() {
        return bad_request("domains and backend are required");
    }
    let site = SiteConfig {
        id: new_id("site"),
        domains: payload.domains,
        backend: payload.backend,
        listener: payload.listener,
    };
    let mut config = state.config.write().await;
    config.sites.push(site.clone());
    if let Err(err) = config.save(&state.config_path) {
        return internal(err);
    }
    Json(site).into_response()
}

async fn delete_site(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.sites.retain(|s| s.id != id);
    if let Err(err) = config.save(&state.config_path) {
        return internal(err);
    }
    Json(json!({ "ok": true })).into_response()
}

async fn list_certs(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    Json(config.certificates.clone()).into_response()
}

async fn add_cert(State(state): State<AppState>, Json(payload): Json<CertRequest>) -> Response {
    let cert = CertificateConfig {
        id: payload.id,
        cert_path: payload.cert_path,
        key_path: payload.key_path,
    };
    let mut config = state.config.write().await;
    config.certificates.push(cert.clone());
    if let Err(err) = config.save(&state.config_path) {
        return internal(err);
    }
    Json(cert).into_response()
}

async fn delete_cert(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.certificates.retain(|c| c.id != id);
    if let Err(err) = config.save(&state.config_path) {
        return internal(err);
    }
    Json(json!({ "ok": true })).into_response()
}

async fn list_ddns(State(state): State<AppState>) -> Response {
    let config = state.config.read().await;
    Json(config.ddns.clone()).into_response()
}

async fn add_ddns(State(state): State<AppState>, Json(payload): Json<DdnsRequest>) -> Response {
    let ip_source: IpSource = match serde_json::from_value(payload.ip_source) {
        Ok(source) => source,
        Err(err) => return bad_request(err),
    };
    let task = DdnsTask {
        id: payload.id.unwrap_or_else(|| new_id("ddns")),
        enabled: payload.enabled,
        provider: payload.provider,
        zone_id: payload.zone_id,
        api_token: payload.api_token,
        name: payload.name,
        record_type: payload.record_type.to_ascii_uppercase(),
        ip_source,
        interval_secs: payload.interval_secs.max(30),
        last_ip: None,
    };
    let mut config = state.config.write().await;
    config.ddns.push(task.clone());
    if let Err(err) = config.save(&state.config_path) {
        return internal(err);
    }
    Json(task).into_response()
}

async fn delete_ddns(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let mut config = state.config.write().await;
    config.ddns.retain(|t| t.id != id);
    if let Err(err) = config.save(&state.config_path) {
        return internal(err);
    }
    Json(json!({ "ok": true })).into_response()
}

async fn run_ddns(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match run_and_record(&state, &id).await {
        Ok(ip) => Json(json!({ "ok": true, "ip": ip })).into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, err).into_response(),
    }
}

pub fn admin_router(state: AppState) -> Router {
    let public = Router::new().route("/login", post(login));

    let protected = Router::new()
        .route("/status", get(status))
        .route("/config", get(get_config))
        .route("/config/reload", post(reload_config))
        .route("/sites", get(list_sites).post(add_site))
        .route("/sites/{id}", delete(delete_site))
        .route("/certs", get(list_certs).post(add_cert))
        .route("/certs/{id}", delete(delete_cert))
        .route("/ddns", get(list_ddns).post(add_ddns))
        .route("/ddns/{id}", delete(delete_ddns))
        .route("/ddns/{id}/run", post(run_ddns))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/", get(ui))
        .route("/ui", get(ui))
        .nest("/api", public.merge(protected))
        .with_state(state)
}
