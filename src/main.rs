use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use clap::Parser;
use reqwest::{Client, Url, redirect::Policy};
use serde::Deserialize;

const MEDIA_TYPE: &str = "application/oblivious-dns-message";
const MAX_BODY: usize = 256 * 1024;

#[derive(Parser)]
#[command(about = "RFC 9230 Oblivious DoH HTTPS proxy")]
struct Args {
    #[arg(
        long,
        help = "HTTP socket to bind (use TLS termination for public access)"
    )]
    listen: SocketAddr,
    #[arg(long, help = "Additional PEM CA certificate for private HTTPS targets")]
    target_ca_cert: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetParams {
    targethost: String,
    targetpath: String,
}

#[derive(Clone)]
struct AppState {
    client: Client,
}

fn authority(raw: &str) -> Option<(String, u16)> {
    if raw.is_empty()
        || raw.bytes().any(|b| {
            matches!(
                b,
                b'/' | b'@' | b'?' | b'#' | b'%' | b'\\' | b' ' | b'\t' | b'\r' | b'\n'
            )
        })
    {
        return None;
    }
    let url = Url::parse(&format!("https://{raw}/")).ok()?;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some((
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default()?,
    ))
}

fn target_url(host: &str, path: &str) -> Option<Url> {
    if !path.starts_with('/') || path.contains(['?', '#', '\\']) {
        return None;
    }
    let (host, port) = authority(host)?;
    let url = Url::parse(&format!("https://{host}:{port}{path}")).ok()?;
    (url.path() == path && url.query().is_none() && url.fragment().is_none()).then_some(url)
}

fn encoded_query_is_valid(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

async fn handle_query(
    State(state): State<AppState>,
    targetparams: Result<Query<TargetParams>, QueryRejection>,
    request: Request,
) -> Response {
    let Ok(Query(targetparams)) = targetparams else {
        return error(StatusCode::BAD_REQUEST, "http_request_error");
    };
    if !request.uri().query().is_some_and(encoded_query_is_valid)
        || targetparams.targethost.contains('\u{fffd}')
        || targetparams.targetpath.contains('\u{fffd}')
    {
        return error(StatusCode::BAD_REQUEST, "http_request_error");
    }
    let Some(target) = target_url(&targetparams.targethost, &targetparams.targetpath) else {
        return error(StatusCode::BAD_REQUEST, "http_request_error");
    };
    forward(state, target, request).await
}

async fn handle_path(
    State(state): State<AppState>,
    Path((host, path)): Path<(String, String)>,
    request: Request,
) -> Response {
    if request.uri().query().is_some() {
        return error(StatusCode::BAD_REQUEST, "http_request_error");
    }
    let path = format!("/{}", path.strip_prefix('/').unwrap_or(&path));
    let Some(target) = target_url(&host, &path) else {
        return error(StatusCode::BAD_REQUEST, "http_request_error");
    };
    forward(state, target, request).await
}

fn reply(
    status: StatusCode,
    proxy_status: &str,
    content_type: Option<&HeaderValue>,
    body: Vec<u8>,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        "proxy-status",
        HeaderValue::from_str(proxy_status).expect("static proxy status"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(content_type) = content_type {
        headers.insert(header::CONTENT_TYPE, content_type.clone());
    }
    response
}

fn error(status: StatusCode, kind: &'static str) -> Response {
    reply(
        status,
        &format!("odoh-proxy; error={kind}"),
        None,
        Vec::new(),
    )
}

async fn forward(state: AppState, target: Url, request: Request) -> Response {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .is_none_or(|v| v != MEDIA_TYPE)
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
    {
        return error(StatusCode::BAD_REQUEST, "http_request_error");
    }
    // The target URI is validated before the body is read.
    let body = match to_bytes(request.into_body(), MAX_BODY).await {
        Ok(body) if !body.is_empty() => body,
        Ok(_) => return error(StatusCode::BAD_REQUEST, "http_request_error"),
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "http_request_error"),
    };
    let upstream = match state
        .client
        .post(target)
        .header(header::CONTENT_TYPE, MEDIA_TYPE)
        .header(header::ACCEPT, MEDIA_TYPE)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) if err.is_timeout() => {
            return error(StatusCode::GATEWAY_TIMEOUT, "http_response_timeout");
        }
        Err(_) => return error(StatusCode::BAD_GATEWAY, "destination_unavailable"),
    };
    let status = upstream.status();
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    if status.is_success() && content_type.as_ref().is_none_or(|v| v != MEDIA_TYPE) {
        return error(StatusCode::BAD_GATEWAY, "http_protocol_error");
    }
    let mut upstream = upstream;
    let mut body = Vec::new();
    while let Some(chunk) = match upstream.chunk().await {
        Ok(chunk) => chunk,
        Err(err) if err.is_timeout() => {
            return error(StatusCode::GATEWAY_TIMEOUT, "http_response_timeout");
        }
        Err(_) => return error(StatusCode::BAD_GATEWAY, "destination_unavailable"),
    } {
        if chunk.len() > MAX_BODY - body.len() {
            return error(StatusCode::BAD_GATEWAY, "http_response_body_too_large");
        }
        body.extend_from_slice(&chunk);
    }
    reply(
        status,
        &format!("odoh-proxy; received-status={}", status.as_u16()),
        content_type.as_ref(),
        body,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30));
    if let Some(file) = args.target_ca_cert {
        let pem = tokio::fs::read(&file)
            .await
            .with_context(|| format!("read target CA certificate {}", file.display()))?;
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&pem).context("parse target CA certificate")?,
        );
    }
    let state = AppState {
        client: builder.build().context("build HTTPS target client")?,
    };
    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("register SIGTERM handler")?;
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind ODoH listener {}", args.listen))?;
    println!("LISTENING {}", listener.local_addr()?);
    let app = Router::new()
        .route(
            "/dns-query",
            axum::routing::post(handle_query)
                .fallback(|| async { error(StatusCode::METHOD_NOT_ALLOWED, "http_request_error") }),
        )
        .route(
            "/{targethost}/{*targetpath}",
            axum::routing::post(handle_path)
                .fallback(|| async { error(StatusCode::METHOD_NOT_ALLOWED, "http_request_error") }),
        )
        .fallback(|| async { error(StatusCode::NOT_FOUND, "http_request_error") })
        .with_state(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown(sigterm))
        .await
        .context("serve ODoH requests")?;
    Ok(())
}

async fn shutdown(mut sigterm: tokio::signal::unix::Signal) {
    tokio::select! { _ = sigterm.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
}
