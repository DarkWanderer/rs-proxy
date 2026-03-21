use crate::allowlist::Allowlist;
use crate::security::is_private_ip;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use serde_json::json;

use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(s: &str) -> BoxBody {
    Full::new(Bytes::from(s.to_string()))
        .map_err(|never| match never {})
        .boxed()
}

fn json_response(status: StatusCode, body: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full_body(body))
        .unwrap()
}

/// Hop-by-hop headers that MUST NOT be forwarded to the upstream server
/// (RFC 2616 §13.5.1, RFC 7230 §6.1).
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Handle an HTTP forward proxy request (e.g. GET http://example.com/path HTTP/1.1)
pub async fn handle_http(
    req: Request<hyper::body::Incoming>,
    allowlist: Arc<Allowlist>,
    connect_timeout_ms: u64,
    block_private_ips: bool,
    allowed_ports: &[u16],
    client_cn: Option<String>,
) -> Response<BoxBody> {
    let uri = req.uri().clone();
    let host = match uri.host() {
        Some(h) => h.to_string(),
        None => {
            warn!(client_cn = ?client_cn, "Bad request: missing host in URI");
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"bad_request","detail":"missing host in request URI"}"#,
            );
        }
    };

    let port = uri.port_u16().unwrap_or(80);

    // Port restriction: restrict HTTP forwarding to allowed ports (mirrors CONNECT restriction)
    if !allowed_ports.is_empty() && !allowed_ports.contains(&port) {
        warn!(
            client_cn = ?client_cn,
            method = %req.method(),
            host = %host,
            port = port,
            reason = "port_not_allowed",
            "Request denied: port not in allowed set"
        );
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "port_not_allowed", "host": host, "port": port}).to_string(),
        );
    }

    let host_with_port = format!("{}:{}", host, port);

    if !allowlist.is_allowed(&host) {
        warn!(
            client_cn = ?client_cn,
            method = %req.method(),
            host = %host,
            port = port,
            reason = "domain_not_allowed",
            "Request denied"
        );
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "domain_not_allowed", "host": host}).to_string(),
        );
    }

    let matched_rule = allowlist.matched_rule(&host).unwrap_or_default();
    info!(
        client_cn = ?client_cn,
        method = %req.method(),
        host = %host,
        port = port,
        matched_rule = %matched_rule,
        "Request allowed"
    );

    // Resolve DNS asynchronously and check for private IPs before connecting.
    // IMPORTANT: We connect to the resolved SocketAddr directly to prevent
    // TOCTOU DNS rebinding attacks.
    let resolved: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(&host_with_port).await {
        Ok(addrs) => addrs.collect(),
        Err(e) => {
            warn!(client_cn = ?client_cn, host = %host, port = port, error = %e, "DNS resolution failed");
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({"error": "upstream_unreachable", "host": host}).to_string(),
            );
        }
    };

    if resolved.is_empty() {
        warn!(client_cn = ?client_cn, host = %host, port = port, "DNS resolution returned no addresses");
        return json_response(
            StatusCode::BAD_GATEWAY,
            &json!({"error": "upstream_unreachable", "host": host}).to_string(),
        );
    }

    // SSRF protection: reject if any resolved address is private
    if block_private_ips {
        for resolved_addr in &resolved {
            if is_private_ip(resolved_addr.ip()) {
                warn!(
                    client_cn = ?client_cn,
                    host = %host,
                    port = port,
                    resolved_ip = %resolved_addr.ip(),
                    reason = "private_ip_blocked",
                    "Request denied: host resolves to private IP"
                );
                return json_response(
                    StatusCode::FORBIDDEN,
                    &json!({"error": "private_ip_blocked", "host": host}).to_string(),
                );
            }
        }
    }

    // Connect to the already-resolved address (no second DNS lookup)
    let stream = match tokio::time::timeout(
        Duration::from_millis(connect_timeout_ms),
        tokio::net::TcpStream::connect(resolved.as_slice()),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(host = %host, error = %e, "Upstream unreachable");
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({"error": "upstream_unreachable", "host": host}).to_string(),
            );
        }
        Err(_) => {
            warn!(host = %host, "Upstream connect timeout");
            return json_response(
                StatusCode::GATEWAY_TIMEOUT,
                &json!({"error": "upstream_timeout", "host": host}).to_string(),
            );
        }
    };

    // Use hyper to forward the request
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(r) => r,
        Err(e) => {
            warn!(host = %host, error = %e, "HTTP handshake failed");
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({"error": "upstream_unreachable", "host": host}).to_string(),
            );
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("HTTP connection error: {}", e);
        }
    });

    // Rebuild request without proxy absolute URI
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

    let (mut parts, body) = req.into_parts();
    parts.uri = path.parse().unwrap_or_else(|_| "/".parse().unwrap());

    // Always set Host header to match the URI to prevent host header smuggling.
    // A client could send Host: internal-service while targeting an allowed host.
    parts
        .headers
        .insert(hyper::header::HOST, host.parse().unwrap());

    // Strip hop-by-hop headers that must not be forwarded to the upstream
    for header in HOP_BY_HOP_HEADERS {
        parts.headers.remove(*header);
    }

    let new_req = Request::from_parts(parts, body);

    match sender.send_request(new_req).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body = body.map_err(|e| e).boxed();
            Response::from_parts(parts, body)
        }
        Err(e) => {
            warn!(host = %host, error = %e, "Upstream request failed");
            json_response(
                StatusCode::BAD_GATEWAY,
                &json!({"error": "upstream_unreachable", "host": host}).to_string(),
            )
        }
    }
}
