use crate::config::Config;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize)]
pub struct DdnsStatus {
    pub last_ip: Option<String>,
    pub last_run: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}
impl Default for DdnsStatus {
    fn default() -> Self { Self { last_ip: None, last_run: None, last_error: None } }
}

#[derive(Clone, Debug, Serialize)]
pub struct TunnelStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub restarts: u32,
    pub last_error: Option<String>,
}
impl Default for TunnelStatus {
    fn default() -> Self { Self { running: false, pid: None, restarts: 0, last_error: None } }
}

#[derive(Clone, Debug, Serialize)]
pub struct StunStatus {
    pub public_ip: Option<String>,
    pub public_port: Option<u16>,
    pub last_run: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub changed: bool,
}
impl Default for StunStatus {
    fn default() -> Self { Self { public_ip: None, public_port: None, last_run: None, last_error: None, changed: false } }
}

#[derive(Clone, Debug, Serialize)]
pub struct BanEntry {
    pub ip: String,
    pub reason: String,
    pub failures: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub banned_until: Option<DateTime<Utc>>,
    pub permanent: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TrafficCounter {
    pub requests: u64,
    pub connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
    pub active: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SiteStats {
    pub traffic: TrafficCounter,
    pub top_ips: HashMap<String, u64>,
    pub top_paths: HashMap<String, u64>,
    pub countries: HashMap<String, u64>,
    pub minutes: HashMap<String, TrafficCounter>,
    pub backend_health: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub time: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct NotifyQueueItem {
    pub id: String,
    pub event: String,
    pub channel_id: String,
    pub message: String,
    pub attempts: u32,
    pub next_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct IpListStatus {
    pub entries: usize,
    pub last_update: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeTaskStatus {
    pub last_run: Option<DateTime<Utc>>,
    pub last_result: Option<String>,
    pub last_error: Option<String>,
    pub running: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KnockGrant {
    pub ip: String,
    pub rule_id: String,
    pub identity: String,
    pub until: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobStatus {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub status: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VisitorAudit {
    pub ip: String,
    pub sites: HashMap<String, u64>,
    pub paths: HashMap<String, u64>,
    pub identities: HashMap<String, u64>,
    pub blocked: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub release_url: String,
    pub published_at: Option<String>,
    pub checked_at: DateTime<Utc>,
    pub advisories: Vec<String>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub config: Arc<RwLock<Config>>,
    pub ddns_status: Arc<RwLock<HashMap<String, DdnsStatus>>>,
    pub tunnel_status: Arc<RwLock<HashMap<String, TunnelStatus>>>,
    pub tunnel_children: Arc<RwLock<HashMap<String, tokio::process::Child>>>,
    pub stun_status: Arc<RwLock<HashMap<String, StunStatus>>>,
    pub banned_ips: Arc<RwLock<HashMap<String, BanEntry>>>,
    pub acme_tokens: Arc<RwLock<HashMap<String, String>>>,
    /// DNS-01 challenge token -> TXT value.
    pub acme_dns_tokens: Arc<RwLock<HashMap<String, String>>>,
    pub oidc_states: Arc<RwLock<HashMap<String, String>>>,
    pub oidc_verifiers: Arc<RwLock<HashMap<String, String>>>,
    pub oidc_codes: Arc<RwLock<HashMap<String, String>>>,
    pub site_stats: Arc<RwLock<HashMap<String, SiteStats>>>,
    pub forward_stats: Arc<RwLock<HashMap<String, TrafficCounter>>>,
    pub route_stats: Arc<RwLock<HashMap<String, TrafficCounter>>>,
    pub audit_log: Arc<RwLock<Vec<AuditEntry>>>,
    pub notify_queue: Arc<RwLock<Vec<NotifyQueueItem>>>,
    pub notify_sent: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    pub ip_list_status: Arc<RwLock<HashMap<String, IpListStatus>>>,
    pub task_status: Arc<RwLock<HashMap<String, RuntimeTaskStatus>>>,
    pub knock_grants: Arc<RwLock<HashMap<String, KnockGrant>>>,
    pub login_failures: Arc<RwLock<HashMap<String, (u32, DateTime<Utc>)>>>,
    pub rate_limits: Arc<RwLock<HashMap<String, (u32, DateTime<Utc>)>>>,
    pub site_cache: Arc<RwLock<HashMap<String, (DateTime<Utc>, u16, Vec<(String, String)>, Vec<u8>)>>>,
    /// Background jobs (docker pull/build, backups, upgrades).
    pub jobs: Arc<RwLock<HashMap<String, JobStatus>>>,
    /// Per-visitor audit entries keyed by client address.
    pub visitor_audit: Arc<RwLock<HashMap<String, VisitorAudit>>>,
    pub update_info: Arc<RwLock<Option<UpdateInfo>>>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config_path: PathBuf, config: Config) -> Self {
        Self {
            config_path,
            config: Arc::new(RwLock::new(config)),
            ddns_status: Arc::new(RwLock::new(HashMap::new())),
            tunnel_status: Arc::new(RwLock::new(HashMap::new())),
            tunnel_children: Arc::new(RwLock::new(HashMap::new())),
            stun_status: Arc::new(RwLock::new(HashMap::new())),
            banned_ips: Arc::new(RwLock::new(HashMap::new())),
            acme_tokens: Arc::new(RwLock::new(HashMap::new())),
            acme_dns_tokens: Arc::new(RwLock::new(HashMap::new())),
            oidc_states: Arc::new(RwLock::new(HashMap::new())),
            oidc_verifiers: Arc::new(RwLock::new(HashMap::new())),
            oidc_codes: Arc::new(RwLock::new(HashMap::new())),
            site_stats: Arc::new(RwLock::new(HashMap::new())),
            forward_stats: Arc::new(RwLock::new(HashMap::new())),
            route_stats: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            notify_queue: Arc::new(RwLock::new(Vec::new())),
            notify_sent: Arc::new(RwLock::new(HashMap::new())),
            ip_list_status: Arc::new(RwLock::new(HashMap::new())),
            task_status: Arc::new(RwLock::new(HashMap::new())),
            knock_grants: Arc::new(RwLock::new(HashMap::new())),
            login_failures: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            site_cache: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            visitor_audit: Arc::new(RwLock::new(HashMap::new())),
            update_info: Arc::new(RwLock::new(None)),
            client: reqwest::Client::builder()
                .user_agent(concat!("gately-rs/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("build http client"),
        }
    }
}

pub async fn tunnel_status_handler(State(state): State<AppState>) -> Response {
    Json(state.tunnel_status.read().await.clone()).into_response()
}

pub async fn stun_status_handler(State(state): State<AppState>) -> Response {
    Json(state.stun_status.read().await.clone()).into_response()
}

pub async fn task_status_handler(State(state): State<AppState>) -> Response {
    Json(state.task_status.read().await.clone()).into_response()
}
