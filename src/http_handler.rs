use crate::allowlist::Allowlist;
use crate::security::{escape_json, is_private_ip};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::net::ToSocketAddrs;
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

/// Handle an HTTP forward proxy request (e.g. GET http://example.com/path HTTP/1.1)
pub async fn handle_http(
    req: Request<hyper::body::Incoming>,
    allowlist: Arc<Allowlist>,
    connect_timeout_ms: u64,
    block_private_ips: bool,
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
            &format!(
                r#"{{"error":"domain_not_allowed","host":"{}"}}"#,
                escape_json(&host)
            ),
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

    // SSRF protection: resolve DNS and check that all addresses are public
    if block_private_ips {
        match host_with_port.to_socket_addrs() {
            Ok(addrs) => {
                let resolved: Vec<_> = addrs.collect();
                if resolved.is_empty() {
                    warn!(client_cn = ?client_cn, host = %host, port = port, "DNS resolution returned no addresses");
                    return json_response(
                        StatusCode::BAD_GATEWAY,
                        &format!(
                            r#"{{"error":"upstream_unreachable","host":"{}"}}"#,
                            escape_json(&host)
                        ),
                    );
                }
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
                            &format!(
                                r#"{{"error":"private_ip_blocked","host":"{}"}}"#,
                                escape_json(&host)
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                warn!(client_cn = ?client_cn, host = %host, port = port, error = %e, "DNS resolution failed");
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    &format!(
                        r#"{{"error":"upstream_unreachable","host":"{}"}}"#,
                        escape_json(&host)
                    ),
                );
            }
        }
    }

    // Connect to upstream
    let stream = match tokio::time::timeout(
        Duration::from_millis(connect_timeout_ms),
        tokio::net::TcpStream::connect(&host_with_port),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(host = %host, error = %e, "Upstream unreachable");
            return json_response(
                StatusCode::BAD_GATEWAY,
                &format!(
                    r#"{{"error":"upstream_unreachable","host":"{}"}}"#,
                    escape_json(&host)
                ),
            );
        }
        Err(_) => {
            warn!(host = %host, "Upstream connect timeout");
            return json_response(
                StatusCode::GATEWAY_TIMEOUT,
                &format!(
                    r#"{{"error":"upstream_timeout","host":"{}"}}"#,
                    escape_json(&host)
                ),
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
                &format!(r#"{{"error":"upstream_unreachable","host":"{}"}}"#, host),
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

    // Ensure Host header is set
    if !parts.headers.contains_key(hyper::header::HOST) {
        parts
            .headers
            .insert(hyper::header::HOST, host.parse().unwrap());
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
                &format!(
                    r#"{{"error":"upstream_unreachable","host":"{}"}}"#,
                    escape_json(&host)
                ),
            )
        }
    }
}
