use crate::config::SiteConfig;
use crate::state::AppState;
use crate::{metrics, site_ext, waf};
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use std::collections::HashMap;
use std::str::FromStr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct ListenerCtx { pub name: String }

fn hop_by_hop(name: &str) -> bool {
    matches!(name, "host" | "connection" | "keep-alive" | "transfer-encoding" | "upgrade"
        | "proxy-authorization" | "proxy-connection" | "te" | "trailer")
}

fn client_ip(headers: &HeaderMap) -> String {
    headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("").trim().to_string()
}

async fn find_site(state: &AppState, host: &str, listener: &str) -> Option<SiteConfig> {
    state.config.read().await.sites.iter().find(|s| {
        let listener_ok = match &s.listener { Some(name) => name == listener, None => true };
        listener_ok && s.domains.iter().any(|d| d == "*" || d.eq_ignore_ascii_case(host))
    }).cloned()
}

fn is_websocket(req: &Request) -> bool {
    let upgrade = req.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let connection = req.headers().get(CONNECTION).and_then(|v| v.to_str().ok()).unwrap_or("");
    upgrade.eq_ignore_ascii_case("websocket") && connection.to_ascii_lowercase().contains("upgrade")
}

async fn websocket_proxy(state: &AppState, mut req: Request, site: &SiteConfig) -> Response {
    let url = match reqwest::Url::parse(&site.backend) {
        Ok(u) => u,
        Err(err) => return (StatusCode::BAD_GATEWAY, format!("bad backend: {err}")).into_response(),
    };
    let host = url.host_str().unwrap_or("127.0.0.1");
    let port = url.port_or_known_default().unwrap_or(80);
    let backend = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(err) => return (StatusCode::BAD_GATEWAY, format!("backend error: {err}")).into_response(),
    };
    let mut backend = BufReader::new(backend);
    let mut request_bytes = format!("{} {} {:?}\r\n", req.method(), req.uri(), req.version()).into_bytes();
    for (name, value) in req.headers() {
        request_bytes.extend_from_slice(format!("{}: {}\r\n", name, value.to_str().unwrap_or("")).as_bytes());
    }
    request_bytes.extend_from_slice(b"\r\n");
    if let Err(err) = backend.write_all(&request_bytes).await {
        return (StatusCode::BAD_GATEWAY, format!("backend write: {err}")).into_response();
    }
    let mut line = Vec::new();
    let mut handshake = Vec::new();
    loop {
        line.clear();
        let n = match backend.read_until(b'\n', &mut line).await {
            Ok(n) => n,
            Err(err) => return (StatusCode::BAD_GATEWAY, format!("backend handshake: {err}")).into_response(),
        };
        if n == 0 { return (StatusCode::BAD_GATEWAY, "backend closed handshake").into_response(); }
        handshake.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" { break; }
        if handshake.len() > 8192 { return (StatusCode::BAD_GATEWAY, "backend handshake too large").into_response(); }
    }
    if !handshake.starts_with(b"HTTP/1.1 101") && !handshake.starts_with(b"HTTP/1.0 101") {
        return (StatusCode::BAD_GATEWAY, "backend rejected websocket upgrade").into_response();
    }
    let key = req.headers().get("sec-websocket-key").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if key.is_empty() { return (StatusCode::BAD_REQUEST, "missing sec-websocket-key").into_response(); }
    use sha1::{Digest, Sha1};
    let mut sha = Sha1::new();
    sha.update(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
    let accept = base64::engine::general_purpose::STANDARD.encode(sha.finalize());
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, HeaderValue::from_static("Upgrade"))
        .header(UPGRADE, HeaderValue::from_static("websocket"))
        .header("sec-websocket-accept", accept)
        .body(Body::empty()).unwrap();
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(&mut req).await {
            Ok(u) => u,
            Err(err) => { eprintln!("[ws] upgrade: {err}"); return; }
        };
        let mut client = hyper_util::rt::TokioIo::new(upgraded);
        if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut backend).await {
            eprintln!("[ws] tunnel: {err}");
        }
    });
    response
}

#[axum::debug_handler]
pub async fn proxy_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ListenerCtx>,
    req: Request,
) -> Response {
    let host = req.headers().get(HOST).and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase()).unwrap_or_default();
    let site = match find_site(&state, &host, &ctx.name).await {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, "no matching site").into_response(),
    };
    let ip = client_ip(req.headers());
    if !ip.is_empty() && waf::is_banned(&state, &ip).await {
        return site_ext::error_response(StatusCode::FORBIDDEN, &site.error_page, "ip banned");
    }
    if let Some(resp) = site_ext::waf_extra(&state, &site, &ip).await { return resp; }
    let path = req.uri().path().to_string();
    if let Some(resp) = site_ext::precheck(&state, &site, req.headers(), req.method(), &host, &ip, &path).await { return resp; }

    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let bytes = match to_bytes(body, 64 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
    };
    if path == "/_gately_login" && parts.method == axum::http::Method::POST {
        let form = String::from_utf8_lossy(&bytes).to_string();
        return site_ext::handle_login(state, site, parts.headers, &form).await;
    }
    if is_websocket_req(&parts.method, &parts.headers) {
        let req = Request::from_parts(parts, Body::from(bytes));
        return websocket_proxy(&state, req, &site).await;
    }

    let mut headers = HashMap::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() { headers.insert(name.as_str().to_ascii_lowercase(), v.to_string()); }
    }
    let logged_in = site_ext::site_user(&state, &site, &parts.headers).await;
    let decision = waf::evaluate(&state.config.read().await.clone(), &site, &path, &query, &headers, &String::from_utf8_lossy(&bytes), logged_in.is_some(), Some(&state)).await;
    match decision {
        waf::Decision::Deny(msg) => {
            waf::record_failure(&state, 5, 300, 3600, &ip, "waf block").await;
            metrics::record_visitor(&state, &ip, &site.id, &path, logged_in.as_deref(), true).await;
            return site_ext::error_response_with_style(StatusCode::FORBIDDEN, &site.error_page, &site.error_page_style, &msg);
        }
        waf::Decision::Log(msg) => eprintln!("[waf] {msg}"),
        waf::Decision::Allow => {}
    }

    let target = site_ext::resolve(&state, &site, &path, if query.is_empty() { None } else { Some(&query) }, logged_in.as_deref());
    let url = match target {
        site_ext::Resolved::Response(resp) => return resp,
        site_ext::Resolved::Proxy { backend, .. } => backend,
    };

    let cache_key = site_ext::build_cache_key(&host, &format!("{path}?{query}"));
    let cache_ttl = site_ext::cache_ttl(&site, &path);
    if let Some(ttl) = cache_ttl {
        if let Some((status, cached_headers, cached_body)) = site_ext::cache_get(&state, &cache_key).await {
            let mut builder = Response::builder().status(status);
            for (name, value) in cached_headers {
                if let Ok(n) = HeaderName::from_str(&name) { builder = builder.header(n, value); }
            }
            return builder.body(Body::from(cached_body)).unwrap_or_default();
        }
    }

    let mut out_headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if hop_by_hop(name.as_str()) { continue; }
        if let Ok(name) = HeaderName::from_str(name.as_str()) { out_headers.append(name, value.clone()); }
    }
    site_ext::add_user_headers(&state, &site, &mut out_headers, &parts.headers).await;

    let started = std::time::Instant::now();
    let upstream = match state.client.request(parts.method.clone(), &url).headers(out_headers).body(bytes.clone()).send().await {
        Ok(resp) => resp,
        Err(err) => {
            metrics::record_request(&state, &site.id, &ip, &path, 502, bytes.len() as u64, 0, &site_ext::country_from(&parts.headers)).await;
            return site_ext::error_response(StatusCode::BAD_GATEWAY, &site.error_page, &format!("backend error: {err}"));
        }
    };
    let status = upstream.status();
    if site.intercept_errors && (status.is_client_error() || status.is_server_error()) {
        return site_ext::error_response(status, &site.error_page, &format!("backend returned {status}"));
    }
    let mut builder = Response::builder().status(status);
    let mut response_headers = Vec::new();
    for (name, value) in upstream.headers().iter() {
        if name == CONNECTION || name.as_str() == "keep-alive" || name == TRANSFER_ENCODING
            || name == UPGRADE || name == AUTHORIZATION || name == CONTENT_LENGTH { continue; }
        if let Ok(name) = HeaderName::from_str(name.as_str()) { builder = builder.header(name, value.clone()); }
        response_headers.push((name.to_string(), value.to_str().unwrap_or("").to_string()));
    }
    let body = match upstream.bytes().await {
        Ok(b) => b,
        Err(err) => return (StatusCode::BAD_GATEWAY, format!("read backend body: {err}")).into_response(),
    };
    let elapsed = started.elapsed();
    metrics::record_request(&state, &site.id, &ip, &path, status.as_u16(), bytes.len() as u64, body.len() as u64, &site_ext::country_from(&parts.headers)).await;
    metrics::record_visitor(&state, &ip, &site.id, &path, logged_in.as_deref(), false).await;
    let _ = elapsed;
    if status == StatusCode::NOT_FOUND && !ip.is_empty() { waf::record_404(&state, &ip).await; }
    let compressible = body.len() > 512
        && site_ext::wants_gzip(&parts.headers)
        && response_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && (value.contains("text/") || value.contains("json") || value.contains("javascript") || value.contains("svg"))
        });
    let raw_body = body.to_vec();
    let (body, extra_headers) = if compressible {
        (Body::from(site_ext::gzip_bytes(&body)), vec![("content-encoding".to_string(), "gzip".to_string())])
    } else { (Body::from(body), Vec::new()) };
    for (name, value) in extra_headers {
        if let Ok(n) = HeaderName::from_str(&name) { builder = builder.header(n, value); }
    }
    if let Some(ttl) = cache_ttl {
        if status.is_success() {
            site_ext::cache_put(&state, &cache_key, ttl, status.as_u16(), response_headers, raw_body.clone()).await;
        }
    }
    builder.body(Body::from(body)).unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response())
}

fn is_websocket_req(method: &axum::http::Method, headers: &HeaderMap) -> bool {
    let upgrade = headers.get(UPGRADE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let connection = headers.get(CONNECTION).and_then(|v| v.to_str().ok()).unwrap_or("");
    method == axum::http::Method::GET && upgrade.eq_ignore_ascii_case("websocket") && connection.to_ascii_lowercase().contains("upgrade")
}
