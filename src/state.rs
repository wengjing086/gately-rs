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
        Self {
            last_ip: None,
            last_run: None,
            last_error: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub config: Arc<RwLock<Config>>,
    pub ddns_status: Arc<RwLock<HashMap<String, DdnsStatus>>>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config_path: PathBuf, config: Config) -> Self {
        Self {
            config_path,
            config: Arc::new(RwLock::new(config)),
            ddns_status: Arc::new(RwLock::new(HashMap::new())),
            client: reqwest::Client::builder()
                .user_agent(concat!("gately-rs/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("build http client"),
        }
    }
}
