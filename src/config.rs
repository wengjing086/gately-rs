use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn default_true() -> bool { true }
fn default_waf_mode() -> String { "off".into() }
fn default_site_kind() -> String { "proxy".into() }
fn default_auth_mode() -> String { "none".into() }
fn default_challenge() -> String { "http-01".into() }
fn default_max_failures() -> u32 { 5 }
fn default_window_secs() -> u64 { 600 }
fn default_ban_secs() -> u64 { 3600 }
fn default_backend() -> String { "none".into() }
fn default_nft_table() -> String { "gately".into() }
fn default_nft_chain() -> String { "gately_jail".into() }
fn default_stun_interval() -> u64 { 300 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub admin: AdminConfig,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
    #[serde(default)]
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
    #[serde(default)]
    pub port_forwards: Vec<PortForwardTask>,
    #[serde(default)]
    pub proto_routes: Vec<ProtoRouteTask>,
    #[serde(default)]
    pub site_users: Vec<SiteUser>,
    #[serde(default)]
    pub ip_lists: Vec<IpList>,
    #[serde(default)]
    pub notifications: NotificationConfig,
    #[serde(default)]
    pub scheduled_tasks: Vec<ScheduledTask>,
    #[serde(default)]
    pub backups: BackupConfig,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(default)]
    pub knock: KnockConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub diag: DiagConfig,
    #[serde(default)]
    pub files: FilesConfig,
    #[serde(default)]
    pub terminal: TerminalConfig,
    #[serde(default)]
    pub wol: WolConfig,
    #[serde(default)]
    pub storage: Vec<StorageMount>,
    #[serde(default)]
    pub filebrowser: FileBrowserConfig,
    #[serde(default)]
    pub smb: SmbConfig,
    #[serde(default)]
    pub perf: PerfConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminConfig {
    pub listen: String,
    pub password: String,
    pub token: String,
    #[serde(default)]
    pub api_tokens: Vec<ApiToken>,
    #[serde(default)]
    pub security_entry: String,
    #[serde(default)]
    pub lan_only: bool,
    #[serde(default)]
    pub unauthorized_response: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Secret path prefix required to reach the admin UI, e.g. "/secret-abc".
    #[serde(default)]
    pub secure_path: String,
    /// TLS certificate id used to serve the admin UI over HTTPS.
    #[serde(default)]
    pub admin_tls_cert: Option<String>,
    /// Serve the admin UI on a separate HTTPS port.
    #[serde(default)]
    pub admin_tls_listen: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub token: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Comma separated module names, empty means all modules.
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub listen: String,
    /// None means plain HTTP; Some(id) refers to CertificateConfig.id.
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// Extra plain HTTP port sharing this listener, e.g. 80.
    #[serde(default)]
    pub http_port: Option<u16>,
    /// redirect | serve | none for the extra HTTP port.
    #[serde(default)]
    pub http_mode: String,
    #[serde(default)]
    pub http3: bool,
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default)]
    pub firewall_open: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteConfig {
    pub id: String,
    /// Disabled sites are skipped by the proxy.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Exact host names (port is stripped before matching). Wildcard "*" matches any host.
    pub domains: Vec<String>,
    /// Backend origin, e.g. http://127.0.0.1:3000
    #[serde(default)]
    pub backend: String,
    /// Optional listener name restriction.
    #[serde(default)]
    pub listener: Option<String>,
    /// proxy | redirect | static | text | disconnect | nav
    #[serde(default = "default_site_kind")]
    pub kind: String,
    #[serde(default)]
    pub redirect_url: String,
    #[serde(default)]
    pub static_root: String,
    #[serde(default)]
    pub text_body: String,
    #[serde(default)]
    pub nav_html: String,
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
    #[serde(default)]
    pub allow_ip_lists: Vec<String>,
    #[serde(default)]
    pub deny_ip_lists: Vec<String>,
    /// none | basic | form | forward
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub auth_users: Vec<String>,
    #[serde(default)]
    pub forward_auth_url: String,
    #[serde(default)]
    pub pass_user_headers: bool,
    #[serde(default)]
    pub trust_logged_in: bool,
    #[serde(default)]
    pub path_rules: Vec<PathRule>,
    #[serde(default)]
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub load_balance: String,
    #[serde(default)]
    pub health_check_path: String,
    #[serde(default)]
    pub rate_limit_per_min: u64,
    #[serde(default)]
    pub cache_ttl_secs: u64,
    #[serde(default)]
    pub compression: bool,
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default)]
    pub knock_required: bool,
    #[serde(default)]
    pub drop_on_deny: bool,
    #[serde(default)]
    pub geo_allow: Vec<String>,
    #[serde(default)]
    pub geo_deny: Vec<String>,
    #[serde(default)]
    pub error_page: String,
    #[serde(default)]
    pub intercept_errors: bool,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub remark: String,
    /// Login user name -> backend url (nginx map $remote_user).
    #[serde(default)]
    pub user_backends: HashMap<String, String>,
    /// Per-path cache rules.
    #[serde(default)]
    pub cache_rules: Vec<CacheRule>,
    /// Built-in error page style id or custom HTML.
    #[serde(default)]
    pub error_page_style: String,
    /// Record per-visitor audit entries.
    #[serde(default)]
    pub visitor_audit: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathRule {
    /// prefix | exact | regex
    #[serde(default)]
    pub matcher: String,
    #[serde(default)]
    pub value: String,
    /// backend | redirect | static | text | deny
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub rewrite: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheRule {
    /// prefix | exact | regex
    #[serde(default)]
    pub matcher: String,
    #[serde(default)]
    pub value: String,
    /// no-cache | ttl
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub ttl_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Backend {
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub weight: u32,
    #[serde(default)]
    pub backup: bool,
    #[serde(default)]
    pub healthy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub acme_id: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub deploy_ssh: Vec<CertDeploySsh>,
    #[serde(default)]
    pub deploy_containers: Vec<String>,
    #[serde(default)]
    pub hook: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertDeploySsh {
    pub host: String,
    pub user: String,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DdnsTask {
    pub id: String,
    pub enabled: bool,
    pub provider: String,
    #[serde(default)]
    pub zone_id: String,
    #[serde(default)]
    pub api_token: String,
    pub name: String,
    pub record_type: String,
    pub ip_source: IpSource,
    pub interval_secs: u64,
    #[serde(default)]
    pub last_ip: Option<String>,
    /// Provider-specific fields: TTl, proxied, endpoint, secret, etc.
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub webhooks: Vec<String>,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub delete_record_on_remove: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpSource {
    Static { ip: String },
    Url { url: String },
    Command { command: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcmeTask {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub domains: Vec<String>,
    pub email: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_directory")]
    pub directory: String,
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
    /// http-01 | dns-01 | tls-alpn-01
    #[serde(default)]
    pub dns_provider: String,
    #[serde(default)]
    pub dns_zone: String,
    #[serde(default)]
    pub dns_credentials: HashMap<String, String>,
    /// External command receiving DNS_CHALLENGE_NAME / DNS_CHALLENGE_VALUE.
    #[serde(default)]
    pub dns_hook: String,
    #[serde(default)]
    pub eab_kid: String,
    #[serde(default)]
    pub eab_hmac: String,
    /// default | shortlived
    #[serde(default)]
    pub profile: String,
}

fn default_provider() -> String { "letsencrypt".into() }
fn default_directory() -> String { String::new() }
fn default_renew_days() -> u64 { 30 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// builtin | custom | coraza-seclang
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub severity: String,
}

fn default_target() -> String { "path".into() }
fn default_action() -> String { "deny".into() }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WafProfile {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub rule_ids: Vec<String>,
    #[serde(default = "default_waf_mode")]
    pub mode: String,
    /// Maximum inspected body bytes; 0 uses the global default.
    #[serde(default)]
    pub body_limit: usize,
    #[serde(default)]
    pub skip_paths: Vec<String>,
    #[serde(default)]
    pub trusted_users_bypass: bool,
    #[serde(default)]
    pub safeline_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JailConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub log_path: String,
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
    /// none | nftables | iptables | ipset
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_nft_table")]
    pub nft_table: String,
    #[serde(default = "default_nft_chain")]
    pub nft_chain: String,
    #[serde(default)]
    pub log_sources: Vec<LogSource>,
    #[serde(default)]
    pub trap_ports: Vec<u16>,
    #[serde(default)]
    pub port_scan_threshold: u32,
    #[serde(default)]
    pub web_trap_paths: Vec<String>,
    #[serde(default)]
    pub trap_404_threshold: u32,
    #[serde(default)]
    pub tls_failure_ban: bool,
    #[serde(default)]
    pub ipv64_prefix_ban: bool,
    #[serde(default)]
    pub escalation: bool,
    #[serde(default)]
    pub permanent_bans: Vec<String>,
    #[serde(default)]
    pub ipset_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogSource {
    pub id: String,
    /// file | journal | command | docker | admin_login | waf | knock
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_ban_secs")]
    pub ban_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub template: String,
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            enabled: false, log_path: String::new(), patterns: Vec::new(),
            max_failures: default_max_failures(), window_secs: default_window_secs(),
            ban_secs: default_ban_secs(), whitelist: Vec::new(), backend: default_backend(),
            nft_table: default_nft_table(), nft_chain: default_nft_chain(),
            log_sources: Vec::new(), trap_ports: Vec::new(), port_scan_threshold: 0,
            web_trap_paths: Vec::new(), trap_404_threshold: 0, tls_failure_ban: false,
            ipv64_prefix_ban: false, escalation: false, permanent_bans: Vec::new(),
            ipset_name: "gately_ban".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelTask {
    pub id: String,
    pub name: String,
    /// frpc | frps | cloudflared | tailscale | netbird | easytier | custom
    #[serde(default)]
    pub kind: String,
    /// Path to binary.
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
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub install_url: String,
    #[serde(default)]
    pub config_text: String,
    #[serde(default)]
    pub public_address: Option<String>,
    #[serde(default)]
    pub group: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StunTask {
    pub id: String,
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_stun_interval")]
    pub interval_secs: u64,
    /// udp | tcp | both
    #[serde(default = "default_stun_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub keepalive_secs: u64,
    #[serde(default)]
    pub upnp: bool,
    #[serde(default)]
    pub webhooks: Vec<String>,
    #[serde(default)]
    pub change_script: String,
    #[serde(default)]
    pub knock_required: bool,
}

fn default_stun_protocol() -> String { "udp".into() }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub require_totp: bool,
    #[serde(default)]
    pub oidc: Vec<OidcProvider>,
    #[serde(default)]
    pub oidc_allowed_users: Vec<String>,
    /// Shared users used by Web sites and the built-in OIDC provider.
    #[serde(default)]
    pub users: Vec<SharedUser>,
    #[serde(default)]
    pub password_login: bool,
    #[serde(default)]
    pub login_rate_limit: u32,
    #[serde(default)]
    pub lockout_secs: u64,
    #[serde(default)]
    pub weak_password_check: bool,
    #[serde(default)]
    pub security_score: bool,
    #[serde(default)]
    pub builtin_oidc: bool,
    #[serde(default)]
    pub forward_auth_cookie_domain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedUser {
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub passkey_credentials: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteUser {
    pub id: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortForwardTask {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// tcp | udp
    #[serde(default = "default_tcp")]
    pub protocol: String,
    /// listen address; port may be a range such as 10000-10010.
    pub listen: String,
    /// Fallback targets in priority order.
    pub targets: Vec<String>,
    #[serde(default)]
    pub max_connections: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// off | v1 | v2
    #[serde(default)]
    pub proxy_protocol: String,
    #[serde(default)]
    pub source_allow: Vec<String>,
    #[serde(default)]
    pub source_deny: Vec<String>,
    #[serde(default)]
    pub source_max_connections: HashMap<String, u64>,
    #[serde(default)]
    pub knock_required: bool,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub remark: String,
}

fn default_tcp() -> String { "tcp".into() }
fn default_idle_timeout() -> u64 { 300 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtoRouteTask {
    pub id: String,
    pub name: String,
    pub listen: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub routes: Vec<ProtoRouteRule>,
    #[serde(default)]
    pub default_target: String,
    /// Seconds to wait for the first bytes of server-first protocols such as VNC.
    #[serde(default = "default_wait_timeout")]
    pub wait_timeout_secs: u64,
    #[serde(default)]
    pub source_allow: Vec<String>,
    #[serde(default)]
    pub source_deny: Vec<String>,
    #[serde(default)]
    pub group: String,
}

fn default_wait_timeout() -> u64 { 5 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtoRouteRule {
    pub id: String,
    /// sni | alpn | http_host | minecraft | protocol | wait
    pub matcher: String,
    pub value: String,
    pub target: String,
    /// off | v1 | v2
    #[serde(default)]
    pub proxy_protocol: String,
    #[serde(default)]
    pub knock_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpList {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub file: String,
    #[serde(default = "default_stun_interval")]
    pub refresh_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default)]
    pub last_update: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default)]
    pub channels: Vec<NotifyChannel>,
    #[serde(default)]
    pub rules: Vec<NotifyRule>,
    #[serde(default = "default_true")]
    pub retry: bool,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub quiet_hours: String,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self { channels: Vec::new(), rules: Vec::new(), retry: true, proxy: String::new(), quiet_hours: String::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotifyChannel {
    pub id: String,
    pub name: String,
    /// webhook | telegram | bark | ntfy | gotify | pushover | discord | slack |
    /// serverchan | pushplus | wecom | dingtalk | feishu | email | command
    pub kind: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub extra: HashMap<String, String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotifyRule {
    pub id: String,
    /// Event name or wildcard, e.g. cert.*, address.changed.
    pub event: String,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub dedup_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub id: String,
    pub name: String,
    /// Five-field cron expression: minute hour day month weekday.
    pub cron: String,
    /// command | http
    pub kind: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub body: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_backup_cron")]
    pub cron: String,
    #[serde(default)]
    pub directory: String,
    #[serde(default = "default_keep_backups")]
    pub keep: u32,
    #[serde(default)]
    pub password: String,
}

fn default_backup_cron() -> String { "0 3 * * *".into() }
fn default_keep_backups() -> u32 { 14 }

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cron: default_backup_cron(),
            directory: String::new(),
            keep: default_keep_backups(),
            password: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemConfig {
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub doh_url: String,
    #[serde(default)]
    pub log_level: String,
    #[serde(default = "default_true")]
    pub update_check: bool,
    #[serde(default)]
    pub disabled_modules: Vec<String>,
    #[serde(default)]
    pub audit_retention_days: u64,
    #[serde(default)]
    pub unauth_response: String,
    #[serde(default = "default_audit_days")]
    pub visitor_audit_days: u64,
    #[serde(default)]
    pub access_log_dir: String,
    #[serde(default)]
    pub update_repo: String,
}

fn default_audit_days() -> u64 { 7 }

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            timezone: String::new(), dns_servers: Vec::new(), doh_url: String::new(),
            log_level: "info".into(), update_check: true, disabled_modules: Vec::new(),
            audit_retention_days: 30, unauth_response: String::new(),
            visitor_audit_days: default_audit_days(), access_log_dir: String::new(),
            update_repo: "wengjing086/gately-rs".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnockConfig {
    #[serde(default)]
    pub enabled: bool,
    /// none | nftables | iptables | ipset
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub nft_table: String,
    #[serde(default)]
    pub nft_chain: String,
    /// Allowed clock skew in seconds for a knock packet.
    #[serde(default = "default_knock_window")]
    pub window_secs: u64,
    /// How long a successful knock unlocks the source address.
    #[serde(default = "default_knock_ttl")]
    pub grant_ttl_secs: u64,
    #[serde(default)]
    pub rules: Vec<KnockRule>,
}

fn default_knock_window() -> u64 { 30 }
fn default_knock_ttl() -> u64 { 300 }

impl Default for KnockConfig {
    fn default() -> Self {
        Self {
            enabled: false, backend: "none".into(), nft_table: "gately".into(),
            nft_chain: "gately_knock".into(), window_secs: default_knock_window(),
            grant_ttl_secs: default_knock_ttl(), rules: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnockRule {
    pub id: String,
    pub name: String,
    /// Base64 encoded 32-byte AES key.
    #[serde(default)]
    pub aes_key: String,
    /// Base64 encoded 32-byte HMAC key.
    #[serde(default)]
    pub hmac_key: String,
    /// Ports that become reachable after a successful knock.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Shared users allowed to knock (identity per user).
    #[serde(default)]
    pub identities: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Reject knocks from an address that is already granted by another rule.
    #[serde(default)]
    pub single_address: bool,
    #[serde(default)]
    pub group: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DockerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub socket: String,
    #[serde(default)]
    pub compose_file: String,
    #[serde(default)]
    pub compose_dir: String,
    #[serde(default)]
    pub registry: String,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self { enabled: false, host: String::new(), socket: String::new(), compose_file: String::new(), compose_dir: String::new(), registry: String::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagConfig {
    #[serde(default = "default_ping_count")]
    pub ping_count: u32,
    #[serde(default = "default_diag_timeout")]
    pub timeout_secs: u64,
    /// Allowed target CIDRs; empty means everything is allowed.
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

fn default_ping_count() -> u32 { 4 }
fn default_diag_timeout() -> u64 { 10 }

impl Default for DiagConfig {
    fn default() -> Self {
        Self { ping_count: default_ping_count(), timeout_secs: default_diag_timeout(), allowed_targets: Vec::new(), enabled: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilesConfig {
    #[serde(default)]
    pub webdav: FileServiceConfig,
    #[serde(default)]
    pub ftp: FileServiceConfig,
}

impl Default for FilesConfig {
    fn default() -> Self { Self { webdav: FileServiceConfig::default(), ftp: FileServiceConfig::default() } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileServiceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub roots: Vec<FileRoot>,
    #[serde(default)]
    pub passive_port_start: u16,
    #[serde(default)]
    pub passive_port_end: u16,
    #[serde(default)]
    pub readonly: bool,
    /// Account -> password for anonymous-safe access.
    #[serde(default)]
    pub users: Vec<FileUser>,
    /// Password hash is stored as plain text in the JSON config.
    #[serde(default)]
    pub require_login: bool,
}

impl Default for FileServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false, listen: String::new(), roots: Vec::new(),
            passive_port_start: 40000, passive_port_end: 40100, readonly: false,
            users: Vec::new(), require_login: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRoot {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub users: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileUser {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub roots: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_local_shell: bool,
    #[serde(default)]
    pub allow_ssh: bool,
    #[serde(default)]
    pub allow_telnet: bool,
    #[serde(default)]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub motd: String,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self { enabled: false, allow_local_shell: false, allow_ssh: false, allow_telnet: false, idle_timeout_secs: 1800, motd: String::new() }
    }
}

impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            id: String::new(), enabled: true, domains: Vec::new(), backend: String::new(), listener: None,
            kind: default_site_kind(), redirect_url: String::new(), static_root: String::new(),
            text_body: String::new(), nav_html: String::new(), waf_profile: None,
            waf_mode: default_waf_mode(), allowed_ips: Vec::new(), denied_ips: Vec::new(),
            allow_ip_lists: Vec::new(), deny_ip_lists: Vec::new(), auth_mode: default_auth_mode(),
            auth_users: Vec::new(), forward_auth_url: String::new(), pass_user_headers: false,
            trust_logged_in: false, path_rules: Vec::new(), backends: Vec::new(),
            load_balance: String::new(), health_check_path: String::new(), rate_limit_per_min: 0,
            cache_ttl_secs: 0, compression: false, proxy_protocol: false, knock_required: false,
            drop_on_deny: false, geo_allow: Vec::new(), geo_deny: Vec::new(), error_page: String::new(),
            intercept_errors: false, group: String::new(), order: 0, remark: String::new(),
            user_backends: HashMap::new(), cache_rules: Vec::new(), error_page_style: String::new(),
            visitor_audit: false,
        }
    }
}

impl Default for DdnsTask {
    fn default() -> Self {
        Self {
            id: String::new(), enabled: false, provider: "cloudflare".into(), zone_id: String::new(),
            api_token: String::new(), name: String::new(), record_type: "A".into(),
            ip_source: IpSource::Static { ip: String::new() }, interval_secs: 300, last_ip: None,
            options: HashMap::new(), webhooks: Vec::new(), remark: String::new(), group: String::new(),
            delete_record_on_remove: false,
        }
    }
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            id: String::new(), enabled: true, cert_path: String::new(), key_path: String::new(), acme_id: None,
            domains: Vec::new(), deploy_ssh: Vec::new(), deploy_containers: Vec::new(), hook: String::new(),
        }
    }
}

impl Default for TunnelTask {
    fn default() -> Self {
        Self {
            id: String::new(), name: String::new(), kind: String::new(), binary: String::new(),
            args: Vec::new(), workdir: None, env: HashMap::new(), enabled: false,
            auto_restart: true, managed: false, version: String::new(), install_url: String::new(),
            config_text: String::new(), public_address: None, group: String::new(),
        }
    }
}

impl Default for StunTask {
    fn default() -> Self {
        Self {
            id: String::new(), server: String::new(), enabled: false, interval_secs: 300,
            protocol: default_stun_protocol(), keepalive_secs: 0, upnp: false, webhooks: Vec::new(),
            change_script: String::new(), knock_required: false,
        }
    }
}



// ---------------------------------------------------------------------------
// Additional modules (aligned with upstream Gately navigation positions)
// ---------------------------------------------------------------------------

/// Wake-on-LAN: send magic packets to hosts on the local network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_wol_port")]
    pub port: u16,
    #[serde(default)]
    pub hosts: Vec<WolHost>,
}
fn default_wol_port() -> u16 { 9 }
impl Default for WolConfig {
    fn default() -> Self { Self { enabled: false, port: 9, hosts: Vec::new() } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WolHost {
    pub id: String,
    pub name: String,
    pub mac: String,
    #[serde(default)]
    pub broadcast: String,
    #[serde(default)]
    pub remark: String,
}

/// A local / remote directory mounted for online file management.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageMount {
    pub id: String,
    pub name: String,
    /// local | webdav | smb
    #[serde(default)]
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub enabled: bool,
}

/// File Browser: web-based file manager settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileBrowserConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_fb_listen")]
    pub listen: String,
    pub root: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub users: Vec<FileUser>,
}
fn default_fb_listen() -> String { "127.0.0.1:18088".into() }
impl Default for FileBrowserConfig {
    fn default() -> Self { Self { enabled: false, listen: default_fb_listen(), root: String::new(), base_url: String::new(), readonly: false, users: Vec::new() } }
}

/// SMB file sharing service settings (shares reuse `config.files.roots`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmbConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_smb_name")]
    pub workgroup: String,
    #[serde(default)]
    pub shares: Vec<SmbShare>,
}
fn default_smb_name() -> String { "WORKGROUP".into() }
impl Default for SmbConfig {
    fn default() -> Self { Self { enabled: false, workgroup: default_smb_name(), shares: Vec::new() } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmbShare {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub users: Vec<String>,
}

/// Performance monitoring thresholds (data source is `/api/metrics`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_perf_interval")]
    pub interval_secs: u64,
    #[serde(default)]
    pub cpu_warn: f64,
    #[serde(default)]
    pub mem_warn: f64,
    #[serde(default)]
    pub disk_warn: f64,
    #[serde(default)]
    pub retention_hours: u64,
}
fn default_perf_interval() -> u64 { 30 }
impl Default for PerfConfig {
    fn default() -> Self { Self { enabled: true, interval_secs: 30, cpu_warn: 80.0, mem_warn: 85.0, disk_warn: 90.0, retention_hours: 24 } }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            admin: AdminConfig {
                listen: "0.0.0.0:16680".into(),
                password: "gately.cn".into(),
                token: "dev-token-change-me".into(),
                api_tokens: Vec::new(),
                security_entry: String::new(),
                lan_only: false,
                unauthorized_response: String::new(),
                trusted_proxies: Vec::new(),
                secure_path: String::new(),
                admin_tls_cert: None,
                admin_tls_listen: None,
            },
            listeners: vec![ListenerConfig {
                name: "http".into(), listen: "0.0.0.0:18080".into(), tls_cert: None,
                http_port: None, http_mode: String::new(), http3: false,
                proxy_protocol: false, firewall_open: false,
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
            port_forwards: Vec::new(),
            proto_routes: Vec::new(),
            site_users: Vec::new(),
            ip_lists: Vec::new(),
            notifications: NotificationConfig::default(),
            scheduled_tasks: Vec::new(),
            backups: BackupConfig::default(),
            system: SystemConfig::default(),
            knock: KnockConfig::default(),
            docker: DockerConfig::default(),
            diag: DiagConfig::default(),
            files: FilesConfig::default(),
            terminal: TerminalConfig::default(),
            wol: WolConfig::default(),
            storage: Vec::new(),
            filebrowser: FileBrowserConfig::default(),
            smb: SmbConfig::default(),
            perf: PerfConfig::default(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            totp_secret: None, require_totp: false, oidc: Vec::new(), oidc_allowed_users: Vec::new(),
            users: Vec::new(), password_login: true, login_rate_limit: 5, lockout_secs: 300,
            weak_password_check: true, security_score: true, builtin_oidc: false,
            forward_auth_cookie_domain: String::new(),
        }
    }
}

impl Config {
    /// Runtime module switch: `system.disabled_modules` may list "ddns", "waf", ...
    pub fn module_disabled(&self, name: &str) -> bool {
        self.system.disabled_modules.iter().any(|m| m.eq_ignore_ascii_case(name))
    }

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
