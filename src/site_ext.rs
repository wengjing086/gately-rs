use crate::config::SiteConfig;
use crate::state::AppState;
use crate::waf;
use axum::body::Body;
use axum::http::header::{COOKIE, HOST, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use regex::Regex;
use sha1::Sha1;
use std::path::Path;

async fn sign(state: &AppState, value: &str) -> String {
    let secret = state.config.read().await.admin.token.clone();
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap_or_else(|_| Hmac::<Sha1>::new_from_slice(b"gately").unwrap());
    mac.update(value.as_bytes());
    format!("{}.{}", value, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

async fn unsign(state: &AppState, signed: &str, secret_hint: &str) -> Option<String> {
    let (value, sig) = signed.rsplit_once('.')?;
    let secret = if secret_hint.is_empty() { state.config.read().await.admin.token.clone() } else { secret_hint.to_string() };
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(value.as_bytes());
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    if expected == sig { Some(value.to_string()) } else { None }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(COOKIE)?.to_str().ok()?.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        if k == name { Some(v.to_string()) } else { None }
    })
}

pub async fn site_user(state: &AppState, site: &SiteConfig, headers: &HeaderMap) -> Option<String> {
    let value = cookie_value(headers, &format!("gately_user_{}", site.id))?;
    unsign(state, &value, "").await
}

fn login_page(site_id: &str, error: &str) -> Response {
    let html = format!(r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 · {site_id}</title><style>body{{font-family:system-ui,sans-serif;background:#f4f6f8;display:grid;place-items:center;min-height:100vh;margin:0}}form{{background:#fff;padding:28px;border-radius:12px;box-shadow:0 10px 30px -20px #000;width:min(360px,90vw)}}input,button{{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border-radius:8px;border:1px solid #ddd}}button{{background:#0e7c66;color:#fff;border:0;cursor:pointer}}.e{{color:#d92d20;font-size:13px}}</style></head><body><form method="post" action="/_gately_login"><h2>需要登录</h2><input name="username" placeholder="用户名" required><input name="password" type="password" placeholder="密码" required><input name="site" type="hidden" value="{site_id}"><button>登录</button><div class="e">{error}</div></form></body></html>"#);
    (StatusCode::OK, [("content-type", "text/html; charset=utf-8")], html).into_response()
}

async fn check_basic(state: &AppState, site: &SiteConfig, headers: &HeaderMap) -> Option<Response> {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let provided = auth.strip_prefix("Basic ").and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());
    let ok = match provided.as_deref() {
        Some(p) => {
            let (user, pass) = p.split_once(':').unwrap_or((p, ""));
            check_users(state, site, user, pass).await
        }
        None => false,
    };
    if ok { None } else {
        Some((StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic realm=\"gately\"")], "unauthorized").into_response())
    }
}

async fn check_users(state: &AppState, site: &SiteConfig, user: &str, pass: &str) -> bool {
    let cfg = state.config.read().await;
    let allowed = &site.auth_users;
    for u in &cfg.site_users {
        if u.enabled && u.username == user && u.password == pass
            && (allowed.is_empty() || allowed.contains(&u.id) || allowed.contains(&u.username)) { return true; }
    }
    for u in &cfg.auth.users {
        if u.enabled && u.username == user && u.password == pass
            && (allowed.is_empty() || allowed.contains(&u.username)) { return true; }
    }
    false
}

pub async fn handle_login(state: AppState, site: SiteConfig, headers: HeaderMap, form: &str) -> Response {
    let params: HashMapLite = HashMapLite::parse(form);
    let user = params.get("username").unwrap_or_default();
    let pass = params.get("password").unwrap_or_default();
    let site_id = params.get("site").unwrap_or_else(|| site.id.clone());
    let auth_site = if site_id == site.id { site } else {
        state.config.read().await.sites.iter().find(|s| s.id == site_id).cloned().unwrap_or(site)
    };
    if !check_users(&state, &auth_site, &user, &pass).await {
        return login_page(&auth_site.id, "用户名或密码错误");
    }
    let value = sign(&state, &format!("{}:{}:{}", auth_site.id, user, Utc::now().timestamp())).await;
    let cookie = format!("gately_user_{}={}; Path=/; HttpOnly; SameSite=Lax", auth_site.id, value);
    let redirect = headers.get("referer").and_then(|v| v.to_str().ok()).unwrap_or("/");
    (StatusCode::FOUND, [(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))), (axum::http::header::LOCATION, HeaderValue::from_str(redirect).unwrap_or_else(|_| HeaderValue::from_static("/")))], "").into_response()
}

struct HashMapLite(Vec<(String, String)>);
impl HashMapLite {
    fn parse(input: &str) -> Self {
        let items = input.split('&').filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((url_decode(k), url_decode(v)))
        }).collect();
        Self(items)
    }
    fn get(&self, key: &str) -> Option<String> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }
}
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes(); let mut out = Vec::new(); let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&input[i + 1..i + 3], 16) { out.push(v); i += 3; continue; }
        }
        if bytes[i] == b'+' { out.push(b' '); } else { out.push(bytes[i]); }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub async fn precheck(state: &AppState, site: &SiteConfig, headers: &HeaderMap, method: &Method, host: &str, ip: &str, path: &str) -> Option<Response> {
    if path == "/_gately_login" && *method == Method::POST { return None; }
    if site.rate_limit_per_min > 0 && !ip.is_empty() {
        let key = format!("{}:{}", site.id, ip);
        let mut limits = state.rate_limits.write().await;
        let entry = limits.entry(key).or_insert((0, Utc::now()));
        if (Utc::now() - entry.1) >= Duration::minutes(1) { *entry = (0, Utc::now()); }
        entry.0 += 1;
        if u64::from(entry.0) > site.rate_limit_per_min {
            return Some((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response());
        }
    }
    if site.knock_required && !state.knock_grants.read().await.values().any(|g| g.ip == ip && g.until > Utc::now()) {
        return Some((StatusCode::FORBIDDEN, "knock required").into_response());
    }
    if !site.geo_allow.is_empty() || !site.geo_deny.is_empty() {
        let country = headers.get("cf-ipcountry").and_then(|v| v.to_str().ok()).unwrap_or("");
        if !site.geo_deny.is_empty() && site.geo_deny.iter().any(|c| c.eq_ignore_ascii_case(country)) {
            return Some((StatusCode::FORBIDDEN, "country denied").into_response());
        }
        if !site.geo_allow.is_empty() && !site.geo_allow.iter().any(|c| c.eq_ignore_ascii_case(country)) {
            return Some((StatusCode::FORBIDDEN, "country not allowed").into_response());
        }
    }
    let user = site_user(state, site, headers).await;
    if site.trust_logged_in && user.is_some() { return None; }
    match site.auth_mode.as_str() {
        "basic" => check_basic(state, site, headers).await,
        "form" => {
            if user.is_none() { Some(login_page(&site.id, "")) } else { None }
        }
        "forward" => {
            if site.forward_auth_url.is_empty() { return None; }
            let url = format!("{}?uri={}", site.forward_auth_url.trim_end_matches('?'), urlencode(&format!("{host}{path}")));
            let mut builder = state.client.get(url);
            for (k, v) in headers { if let Ok(v) = v.to_str() { builder = builder.header(k, v); } }
            match builder.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let mut out = None;
                    if let Some(name) = resp.headers().get("x-forwarded-user").and_then(|v| v.to_str().ok()) {
                        let cookie = format!("gately_user_{}={}; Path=/; HttpOnly; SameSite=Lax", site.id, sign(state, &format!("{}:{}:{}", site.id, name, Utc::now().timestamp())).await);
                        let mut response = Response::new(Body::empty());
                        response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static("")));
                        out = Some(response);
                    }
                    out
                }
                _ => Some((StatusCode::UNAUTHORIZED, "forward auth rejected").into_response()),
            }
        }
        _ => None,
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') { out.push(b as char); }
        else { out.push_str(&format!("%{b:02X}")); }
    }
    out
}

pub enum Resolved {
    Proxy { backend: String, path: String },
    Response(Response),
}

fn rule_match(rule: &crate::config::PathRule, path: &str) -> bool {
    match rule.matcher.as_str() {
        "exact" => rule.value == path,
        "regex" => Regex::new(&rule.value).map(|r| r.is_match(path)).unwrap_or(false),
        _ => path.starts_with(&rule.value),
    }
}

pub fn resolve(state: &AppState, site: &SiteConfig, path: &str, query: Option<&str>, user: Option<&str>) -> Resolved {
    for rule in &site.path_rules {
        if !rule_match(rule, path) { continue; }
        let target_path = if rule.rewrite.is_empty() { path.to_string() } else { rule.rewrite.clone() };
        return match rule.action.as_str() {
            "redirect" => Resolved::Response((StatusCode::FOUND, [("location", rule.target.as_str())], "").into_response()),
            "text" => Resolved::Response((StatusCode::OK, [( "content-type", "text/plain; charset=utf-8")], rule.target.clone()).into_response()),
            "static" => Resolved::Response(static_file(&rule.target, target_path.as_str())),
            "deny" => Resolved::Response((StatusCode::FORBIDDEN, "denied by path rule").into_response()),
            _ => {
                let backend = if rule.target.is_empty() { site.backend.clone() } else { rule.target.clone() };
                let full = format!("{}{}", backend.trim_end_matches('/'), target_path);
                let full = if let Some(q) = query { format!("{full}?{q}") } else { full };
                let _ = state;
                Resolved::Proxy { backend: full, path: target_path }
            }
        };
    }
    match site.kind.as_str() {
        "redirect" => Resolved::Response((StatusCode::FOUND, [("location", site.redirect_url.as_str())], "").into_response()),
        "text" => Resolved::Response((StatusCode::OK, [("content-type", "text/plain; charset=utf-8")], site.text_body.clone()).into_response()),
        "disconnect" => Resolved::Response(Response::new(Body::empty())),
        "static" => Resolved::Response(static_file(&site.static_root, path)),
        "nav" => Resolved::Response((StatusCode::OK, [("content-type", "text/html; charset=utf-8")], site.nav_html.clone()).into_response()),
        _ => {
            let mut backend = site.backend.clone();
            // nginx map $remote_user: pick a dedicated backend for the signed-in user.
            if let Some(name) = user {
                if let Some(target) = site.user_backends.get(name) {
                    if !target.is_empty() { backend = target.clone(); }
                }
            }
            if !site.backends.is_empty() && site.user_backends.is_empty() {
                let active: Vec<_> = site.backends.iter().filter(|b| b.enabled && b.healthy).collect();
                if let Some(b) = active.first() { backend = b.url.clone(); }
                else if let Some(b) = site.backends.iter().find(|b| b.enabled) { backend = b.url.clone(); }
            }
            let full = format!("{}{}", backend.trim_end_matches('/'), path);
            let full = if let Some(q) = query { format!("{full}?{q}") } else { full };
            Resolved::Proxy { backend: full, path: path.to_string() }
        }
    }
}

fn static_file(root: &str, path: &str) -> Response {
    let clean = path.trim_start_matches('/').replace("..", "");
    let file = Path::new(root).join(clean);
    let file = if file.is_dir() { file.join("index.html") } else { file };
    match std::fs::read(&file) {
        Ok(bytes) => {
            let mime = match file.extension().and_then(|e| e.to_str()) {
                Some("html") => "text/html; charset=utf-8", Some("css") => "text/css", Some("js") => "application/javascript",
                Some("json") => "application/json", Some("png") => "image/png", Some("jpg") | Some("jpeg") => "image/jpeg",
                Some("svg") => "image/svg+xml", _ => "application/octet-stream",
            };
            (StatusCode::OK, [("content-type", mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub async fn cache_get(state: &AppState, key: &str) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    let cache = state.site_cache.read().await;
    let (time, status, headers, body) = cache.get(key)?;
    if *time > Utc::now() { Some((*status, headers.clone(), body.clone())) } else { None }
}

pub async fn cache_put(state: &AppState, key: &str, ttl: u64, status: u16, headers: Vec<(String, String)>, body: Vec<u8>) {
    let mut cache = state.site_cache.write().await;
    cache.insert(key.to_string(), (Utc::now() + Duration::seconds(ttl as i64), status, headers, body));
    if cache.len() > 2000 { cache.clear(); }
}

pub async fn add_user_headers(state: &AppState, site: &SiteConfig, headers: &mut HeaderMap, req_headers: &HeaderMap) {
    if !site.pass_user_headers { return; }
    if let Some(user) = site_user(state, site, req_headers).await {
        let cfg = state.config.read().await;
        let (username, email, display_name, groups) = if let Some(u) = cfg.site_users.iter().find(|u| u.username == user || u.id == user) {
            (u.username.clone(), u.email.clone(), u.display_name.clone(), u.groups.clone())
        } else if let Some(u) = cfg.auth.users.iter().find(|u| u.username == user) {
            (u.username.clone(), u.email.clone(), u.display_name.clone(), u.groups.clone())
        } else { return; };
        headers.insert("x-forwarded-user", HeaderValue::from_str(&username).unwrap_or_else(|_| HeaderValue::from_static("")));
        headers.insert("x-forwarded-email", HeaderValue::from_str(&email).unwrap_or_else(|_| HeaderValue::from_static("")));
        headers.insert("x-forwarded-name", HeaderValue::from_str(&display_name).unwrap_or_else(|_| HeaderValue::from_static("")));
        headers.insert("x-forwarded-groups", HeaderValue::from_str(&groups.join(",")).unwrap_or_else(|_| HeaderValue::from_static("")));
    }
}

pub fn build_cache_key(host: &str, path: &str) -> String { format!("{host}{path}") }

/// Resolve the cache TTL for a path: `None` disables caching, `Some(0)` means cache forever.
pub fn cache_ttl(site: &SiteConfig, path: &str) -> Option<u64> {
    for rule in &site.cache_rules {
        let matched = match rule.matcher.as_str() {
            "exact" => rule.value == path,
            "regex" => Regex::new(&rule.value).map(|r| r.is_match(path)).unwrap_or(false),
            _ => path.starts_with(&rule.value),
        };
        if !matched { continue; }
        return match rule.mode.as_str() {
            "no-cache" | "none" => None,
            _ => Some(rule.ttl_secs),
        };
    }
    if site.cache_ttl_secs > 0 { Some(site.cache_ttl_secs) } else { None }
}

pub fn wants_gzip(headers: &HeaderMap) -> bool {
    headers.get("accept-encoding").and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("gzip")).unwrap_or(false)
}

pub fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    if encoder.write_all(data).is_err() { return data.to_vec(); }
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

/// Ten built-in error page styles, mirroring the upstream gallery.
pub fn error_page_html(style: &str, status: u16, message: &str) -> String {
    let palettes = [
        ("#0f172a", "#38bdf8"), ("#1f2937", "#f472b6"), ("#0b3d2e", "#34d399"),
        ("#3b0764", "#c084fc"), ("#450a0a", "#fb7185"), ("#111827", "#facc15"),
        ("#0c4a6e", "#22d3ee"), ("#2e1065", "#f9a8d4"), ("#052e16", "#a3e635"),
        ("#1c1917", "#fdba74"),
    ];
    let index = match style {
        "minimal" => 0, "ocean" => 1, "forest" => 2, "purple" => 3, "crimson" => 4,
        "amber" => 5, "cyan" => 6, "pink" => 7, "lime" => 8, "sand" => 9, _ => 0,
    };
    let (bg, accent) = palettes[index];
    let title = match status {
        400 => "请求有误", 401 => "需要认证", 403 => "拒绝访问", 404 => "页面不存在",
        429 => "请求过于频繁", 502 => "后端不可用", 503 => "服务暂不可用", _ => "出错了",
    };
    format!(r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{status} · {title}</title><style>html,body{{margin:0;height:100%;background:{bg};color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;display:grid;place-items:center}}.card{{text-align:center;padding:48px 56px;border-radius:18px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(8px)}}.code{{font-size:72px;font-weight:700;color:{accent};line-height:1}}.msg{{margin-top:12px;color:#cbd5e1;font-size:15px}}</style></head><body><div class="card"><div class="code">{status}</div><div class="msg">{title}</div><div class="msg">{message}</div></div></body></html>"#)
}

pub fn error_response(status: StatusCode, custom: &str, message: &str) -> Response {
    error_response_with_style(status, custom, "", message)
}

pub fn error_response_with_style(status: StatusCode, custom: &str, style: &str, message: &str) -> Response {
    if custom.is_empty() {
        if style.is_empty() { return (status, message.to_string()).into_response(); }
        let html = error_page_html(style, status.as_u16(), message);
        return (status, [("content-type", "text/html; charset=utf-8")], html).into_response();
    }
    (status, [("content-type", "text/html; charset=utf-8")], custom.replace("{{status}}", &status.as_u16().to_string()).replace("{{message}}", message)).into_response()
}

pub fn country_from(headers: &HeaderMap) -> String {
    headers.get("cf-ipcountry").and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

pub async fn waf_extra(state: &AppState, site: &SiteConfig, ip: &str) -> Option<Response> {
    let cfg = state.config.read().await;
    if ip.is_empty() { return None; }
    if waf::ip_match_list(&cfg.jail.permanent_bans, ip) {
        return Some(crate::site_ext::error_response(StatusCode::FORBIDDEN, &site.error_page, "ip permanently banned"));
    }
    None
}
