use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub admin: AdminConfig,
    pub listeners: Vec<ListenerConfig>,
    pub sites: Vec<SiteConfig>,
    pub certificates: Vec<CertificateConfig>,
    pub ddns: Vec<DdnsTask>,
    #[serde(default)]
    pub acme: Vec<AcmeTask>,
    #[serde(default)]
    pub waf_rules: Vec<WafRule>,
    #[serde(default)]
    pub waf_profiles: Vec<WafProfile>,
    #[serde(default)]
    pub jail: JailConfig,
    #[serde(default)]
    pub tunnels: Vec<TunnelTask>,
    #[serde(default)]
    pub stun: Vec<StunTask>,
    #[serde(default)]
    pub auth: AuthConfig,
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
    /// WAF profile id; empty means no profile.
    #[serde(default)]
    pub waf_profile: Option<String>,
    /// off | detect | block
    #[serde(default = "default_waf_mode")]
    pub waf_mode: String,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub denied_ips: Vec<String>,
}

fn default_waf_mode() -> String {
    "off".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub id: String,
    pub cert_path: String,
    pub key_path: String,
    /// If issued by an ACME task, record its id here.
    #[serde(default)]
    pub acme_id: Option<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcmeTask {
    pub id: String,
    pub domains: Vec<String>,
    pub email: String,
    /// letsencrypt | zerossl | custom
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_directory")]
    pub directory: String,
    /// http-01 only in this MVP.
    #[serde(default = "default_challenge")]
    pub challenge: String,
    pub cert_id: String,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    #[serde(default = "default_renew_days")]
    pub renew_before_days: u64,
    #[serde(default)]
    pub last_issued: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

fn default_provider() -> String { "letsencrypt".into() }
fn default_directory() -> String { String::new() }
fn default_challenge() -> String { "http-01".into() }
fn default_true() -> bool { true }
fn default_renew_days() -> u64 { 30 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    /// regex pattern
    pub pattern: String,
    /// path | query | user_agent | header | body
    #[serde(default = "default_target")]
    pub target: String,
    /// deny | log
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_target() -> String { "path".into() }
fn default_action() -> String { "deny".into() }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WafProfile {
    pub id: String,
    pub name: String,
    pub rule_ids: Vec<String>,
    /// off | detect | block
    #[serde(default = "default_waf_mode")]
    pub mode: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JailConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Optional log file to scan for failure lines.
    #[serde(default)]
    pub log_path: String,
    /// Regex patterns marking a failed login attempt.
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_ban_secs")]
    pub ban_secs: u64,
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// none | nftables | iptables
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_nft_table")]
    pub nft_table: String,
    #[serde(default = "default_nft_chain")]
    pub nft_chain: String,
}

fn default_max_failures() -> u32 { 5 }
fn default_window_secs() -> u64 { 600 }
fn default_ban_secs() -> u64 { 3600 }
fn default_backend() -> String { "none".into() }
fn default_nft_table() -> String { "gately".into() }
fn default_nft_chain() -> String { "gately_jail".into() }

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: String::new(),
            patterns: Vec::new(),
            max_failures: default_max_failures(),
            window_secs: default_window_secs(),
            ban_secs: default_ban_secs(),
            whitelist: Vec::new(),
            backend: default_backend(),
            nft_table: default_nft_table(),
            nft_chain: default_nft_chain(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelTask {
    pub id: String,
    pub name: String,
    /// Path to frpc/frps/cloudflared/... binary.
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_restart: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StunTask {
    pub id: String,
    /// e.g. stun.l.google.com:19302
    pub server: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_stun_interval")]
    pub interval_secs: u64,
}

fn default_stun_interval() -> u64 { 300 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Base32 secret for TOTP.
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub require_totp: bool,
    #[serde(default)]
    pub oidc: Vec<OidcProvider>,
    /// Allow list of OIDC user identifiers (sub or email). Empty allows any authenticated user.
    #[serde(default)]
    pub oidc_allowed_users: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self { totp_secret: None, require_totp: false, oidc: Vec::new(), oidc_allowed_users: Vec::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcProvider {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub enabled: bool,
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
            acme: Vec::new(),
            waf_rules: Vec::new(),
            waf_profiles: Vec::new(),
            jail: JailConfig::default(),
            tunnels: Vec::new(),
            stun: Vec::new(),
            auth: AuthConfig::default(),
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
