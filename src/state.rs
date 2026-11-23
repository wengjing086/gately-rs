use crate::config::Config;
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
    fn default() -> Self {
        Self { last_ip: None, last_run: None, last_error: None }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TunnelStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub restarts: u32,
    pub last_error: Option<String>,
}

impl Default for TunnelStatus {
    fn default() -> Self {
        Self { running: false, pid: None, restarts: 0, last_error: None }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StunStatus {
    pub public_ip: Option<String>,
    pub public_port: Option<u16>,
    pub last_run: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

impl Default for StunStatus {
    fn default() -> Self {
        Self { public_ip: None, public_port: None, last_run: None, last_error: None }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BanEntry {
    pub ip: String,
    pub failures: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub banned_until: Option<DateTime<Utc>>,
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
    /// ACME HTTP-01 token -> key authorization.
    pub acme_tokens: Arc<RwLock<HashMap<String, String>>>,
    /// Pending OIDC flows: state -> provider id.
    pub oidc_states: Arc<RwLock<HashMap<String, String>>>,
    /// OIDC state -> PKCE code verifier.
    pub oidc_verifiers: Arc<RwLock<HashMap<String, String>>>,
    /// OIDC callback code -> user email, consumed by /api/login/oidc/token.
    pub oidc_codes: Arc<RwLock<HashMap<String, String>>>,
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
            oidc_states: Arc::new(RwLock::new(HashMap::new())),
            oidc_verifiers: Arc::new(RwLock::new(HashMap::new())),
            oidc_codes: Arc::new(RwLock::new(HashMap::new())),
            client: reqwest::Client::builder()
                .user_agent(concat!("gately-rs/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("build http client"),
        }
    }
}
