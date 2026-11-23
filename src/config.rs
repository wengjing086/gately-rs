use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub admin: AdminConfig,
    pub listeners: Vec<ListenerConfig>,
    pub sites: Vec<SiteConfig>,
    pub certificates: Vec<CertificateConfig>,
    pub ddns: Vec<DdnsTask>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminConfig {
    pub listen: String,
    pub password: String,
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub listen: String,
    /// None means plain HTTP; Some(id) refers to CertificateConfig.id.
    pub tls_cert: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteConfig {
    pub id: String,
    /// Exact host names (port is stripped before matching). Wildcard "*" matches any host.
    pub domains: Vec<String>,
    /// Backend origin, e.g. http://127.0.0.1:3000
    pub backend: String,
    /// Optional listener name restriction.
    pub listener: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub id: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DdnsTask {
    pub id: String,
    pub enabled: bool,
    /// MVP only supports "cloudflare".
    pub provider: String,
    pub zone_id: String,
    pub api_token: String,
    pub name: String,
    /// A or AAAA.
    pub record_type: String,
    pub ip_source: IpSource,
    pub interval_secs: u64,
    pub last_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpSource {
    Static { ip: String },
    Url { url: String },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            admin: AdminConfig {
                listen: "0.0.0.0:16680".into(),
                password: "gately.cn".into(),
                token: "dev-token-change-me".into(),
            },
            listeners: vec![ListenerConfig {
                name: "http".into(),
                listen: "0.0.0.0:18080".into(),
                tls_cert: None,
            }],
            sites: Vec::new(),
            certificates: Vec::new(),
            ddns: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            let cfg = Self::default();
            cfg.save(path)?;
            return Ok(cfg);
        }
        let text = fs::read_to_string(path).map_err(|e| format!("read config: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("parse config: {e}"))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create config dir: {e}"))?;
        }
        let tmp: PathBuf = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self).map_err(|e| format!("serialize config: {e}"))?;
        fs::write(&tmp, text).map_err(|e| format!("write config: {e}"))?;
        if path.exists() {
            fs::remove_file(path).map_err(|e| format!("remove old config: {e}"))?;
        }
        fs::rename(&tmp, path).map_err(|e| format!("rename config: {e}"))?;
        Ok(())
    }
}
