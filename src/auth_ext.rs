use crate::config::OidcProvider;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, Form};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct TotpRequest { pub code: String }

#[derive(Deserialize)]
pub struct OidcStart { pub provider: String }

#[derive(Deserialize)]
pub struct OidcCallback {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct OidcTokenRequest { pub code: String }

fn base32_decode(secret: &str) -> Option<Vec<u8>> {
    let normalized = secret.trim().to_ascii_uppercase();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
}

pub fn verify_totp(secret: &str, code: &str) -> bool {
    let key = match base32_decode(secret) { Some(k) => k, None => return false };
    let now = Utc::now().timestamp() / 30;
    for step in [now - 1, now, now + 1] {
        let mut mac = match Hmac::<Sha1>::new_from_slice(&key) { Ok(m) => m, Err(_) => return false };
        mac.update(&step.to_be_bytes());
        let bytes = mac.finalize().into_bytes();
        let offset = (bytes[19] & 0x0f) as usize;
        let value = u32::from_be_bytes([bytes[offset] & 0x7f, bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) % 1_000_000;
        if format!("{value:06}") == code { return true; }
    }
    false
}

pub async fn totp_handler(State(state): State<AppState>, Json(payload): Json<TotpRequest>) -> Response {
    let secret = state.config.read().await.auth.totp_secret.clone();
    match secret {
        Some(secret) if verify_totp(&secret, &payload.code) => Json(json!({ "ok": true })).into_response(),
        _ => (StatusCode::UNAUTHORIZED, "invalid totp code").into_response(),
    }
}

async fn discovery(client: &reqwest::Client, provider: &OidcProvider) -> Result<Value, String> {
    let url = format!("{}/.well-known/openid-configuration", provider.issuer.trim_end_matches('/'));
    let value: Value = client.get(url).send().await.map_err(|e| format!("discovery: {e}"))?
        .json().await.map_err(|e| format!("discovery json: {e}"))?;
    Ok(value)
}

pub async fn oidc_start(State(state): State<AppState>, Query(query): Query<OidcStart>) -> Response {
    let provider = {
        let config = state.config.read().await;
        config.auth.oidc.iter().find(|p| p.id == query.provider && p.enabled).cloned()
    };
    let provider = match provider { Some(p) => p, None => return (StatusCode::NOT_FOUND, "provider not found").into_response() };
    let doc = match discovery(&state.client, &provider).await { Ok(d) => d, Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response() };
    let auth_endpoint = match doc.get("authorization_endpoint").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return (StatusCode::BAD_GATEWAY, "no authorization_endpoint").into_response(),
    };
    let state_id = Uuid::new_v4().to_string();
    let verifier = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    state.oidc_states.write().await.insert(state_id.clone(), provider.id.clone());
    state.oidc_verifiers.write().await.insert(state_id.clone(), verifier);
    let url = reqwest::Url::parse(&auth_endpoint).unwrap_or_else(|_| reqwest::Url::parse("http://localhost").unwrap());
    let mut url = url;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state_id)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    Redirect::temporary(url.as_str()).into_response()
}

pub async fn oidc_callback(State(state): State<AppState>, Query(query): Query<OidcCallback>) -> Response {
    if let Some(err) = query.error { return (StatusCode::BAD_REQUEST, format!("oidc error: {err}")).into_response(); }
    let provider_id = match state.oidc_states.write().await.remove(&query.state) {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "invalid state").into_response(),
    };
    let verifier = state.oidc_verifiers.write().await.remove(&query.state).unwrap_or_default();
    let provider = {
        let config = state.config.read().await;
        config.auth.oidc.iter().find(|p| p.id == provider_id).cloned()
    };
    let provider = match provider { Some(p) => p, None => return (StatusCode::BAD_REQUEST, "provider not found").into_response() };
    let code = match query.code { Some(c) => c, None => return (StatusCode::BAD_REQUEST, "missing code").into_response() };
    let doc = match discovery(&state.client, &provider).await { Ok(d) => d, Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response() };
    let token_endpoint = doc.get("token_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", provider.redirect_uri.as_str()),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let token: Value = match state.client.post(token_endpoint).form(&form).send().await {
        Ok(r) => match r.json().await { Ok(v) => v, Err(e) => return (StatusCode::BAD_GATEWAY, format!("token json: {e}")).into_response() },
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("token exchange: {e}")).into_response(),
    };
    let access = token.get("access_token").and_then(|v| v.as_str()).unwrap_or("");
    if access.is_empty() { return (StatusCode::BAD_GATEWAY, "no access token").into_response(); }
    let userinfo = doc.get("userinfo_endpoint").and_then(|v| v.as_str()).unwrap_or("");
    let user: Value = if userinfo.is_empty() {
        token.get("id_token").cloned().unwrap_or(json!({}))
    } else {
        match state.client.get(userinfo).bearer_auth(access).send().await {
            Ok(r) => r.json().await.unwrap_or(json!({})),
            Err(_) => json!({}),
        }
    };
    let identity = user.get("email").or_else(|| user.get("sub")).and_then(|v| v.as_str()).unwrap_or("");
    if identity.is_empty() { return (StatusCode::UNAUTHORIZED, "no identity").into_response(); }
    let one_time = Uuid::new_v4().to_string();
    state.oidc_codes.write().await.insert(one_time.clone(), identity.to_string());
    Redirect::temporary(&format!("/?oidc_code={one_time}")).into_response()
}

pub async fn oidc_token(State(state): State<AppState>, Form(payload): Form<OidcTokenRequest>) -> Response {
    let identity = state.oidc_codes.write().await.remove(&payload.code);
    let identity = match identity { Some(i) => i, None => return (StatusCode::UNAUTHORIZED, "invalid oidc code").into_response() };
    let (allowed, token) = {
        let config = state.config.read().await;
        let auth = &config.auth;
        let allowed = auth.oidc_allowed_users.is_empty() || auth.oidc_allowed_users.iter().any(|u| u == &identity);
        (allowed, config.admin.token.clone())
    };
    if !allowed { return (StatusCode::FORBIDDEN, "user not allowed").into_response(); }
    Json(json!({ "token": token, "user": identity })).into_response()
}

pub fn oidc_login_url(provider: &OidcProvider) -> String {
    format!("{}/authorize", provider.issuer.trim_end_matches('/'))
}
