use crate::state::AppState;
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName};
use axum::response::{IntoResponse, Response};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct ListenerCtx {
    pub name: String,
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
    )
}

pub async fn proxy_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<ListenerCtx>,
    req: Request,
) -> Response {
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
        .unwrap_or_default();

    let (parts, body) = req.into_parts();

    let site = {
        let cfg = state.config.read().await;
        cfg.sites
            .iter()
            .find(|s| {
                let listener_ok = match &s.listener {
                    Some(name) => name == &ctx.name,
                    None => true,
                };
                listener_ok
                    && s.domains
                        .iter()
                        .any(|d| d == "*" || d.eq_ignore_ascii_case(&host))
            })
            .cloned()
    };

    let site = match site {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, "no matching site").into_response(),
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", site.backend.trim_end_matches('/'), path_and_query);

    let mut out_headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if hop_by_hop(name.as_str()) {
            continue;
        }
        if let Ok(name) = HeaderName::from_str(name.as_str()) {
            out_headers.append(name, value.clone());
        }
    }

    let bytes = match to_bytes(body, 16 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
    };

    let upstream = match state
        .client
        .request(parts.method, url)
        .headers(out_headers)
        .body(bytes)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(err) => {
            return (StatusCode::BAD_GATEWAY, format!("backend error: {err}")).into_response();
        }
    };

    let status = upstream.status();
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        if name == CONNECTION
            || name.as_str() == "keep-alive"
            || name == TRANSFER_ENCODING
            || name == UPGRADE
            || name == AUTHORIZATION
            || name == CONTENT_LENGTH
        {
            continue;
        }
        if let Ok(name) = HeaderName::from_str(name.as_str()) {
            builder = builder.header(name, value.clone());
        }
    }

    match upstream.bytes().await {
        Ok(body) => builder
            .body(Body::from(body))
            .unwrap_or_else(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()),
        Err(err) => (StatusCode::BAD_GATEWAY, format!("read backend body: {err}")).into_response(),
    }
}
