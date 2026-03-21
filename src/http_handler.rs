use crate::allowlist::Allowlist;
use crate::proxy::ConnOpts;
use crate::{json_response, BoxBody};
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use serde_json::json;

use std::sync::Arc;
use tracing::{info, warn};

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
    opts: &ConnOpts,
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

    if !opts.allowed_connect_ports.is_empty() && !opts.allowed_connect_ports.contains(&port) {
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

    let stream = match crate::proxy::resolve_and_connect(&host, port, opts, &client_cn).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

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
