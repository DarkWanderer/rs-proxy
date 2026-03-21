use crate::allowlist::Allowlist;
use crate::config::Config;
use crate::pac::generate_pac;
use crate::security::is_private_ip;
use crate::tls::{build_server_tls_config, extract_client_cn};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

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

/// Shared proxy state, hot-swappable on SIGHUP.
pub struct ProxyState {
    pub config: Config,
    pub allowlist: Arc<Allowlist>,
    pub pac_script: String,
    pub tls_acceptor: TlsAcceptor,
}

impl ProxyState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let allowlist = Arc::new(Allowlist::new(&config.allowlist.domains));
        let pac_script = generate_pac(&allowlist, &config.pac_proxy_addr());
        let tls_config = build_server_tls_config(
            &config.tls.server_cert,
            &config.tls.server_key,
            &config.tls.ca_cert,
        )?;
        let tls_acceptor = TlsAcceptor::from(tls_config);
        Ok(ProxyState {
            config,
            allowlist,
            pac_script,
            tls_acceptor,
        })
    }
}

pub struct ProxyServer {
    pub state: Arc<ArcSwap<ProxyState>>,
    pub config_path: String,
}

impl ProxyServer {
    pub fn new(state: Arc<ArcSwap<ProxyState>>, config_path: String) -> Self {
        ProxyServer { state, config_path }
    }

    pub fn reload_config(&self) {
        match Config::load(&self.config_path) {
            Ok(new_config) => match ProxyState::new(new_config) {
                Ok(new_state) => {
                    let domain_count = new_state.allowlist.len();
                    self.state.store(Arc::new(new_state));
                    info!(
                        success = true,
                        domain_count = domain_count,
                        "Config reload successful"
                    );
                }
                Err(e) => {
                    error!(success = false, error = %e, "Config reload failed: could not build proxy state");
                }
            },
            Err(e) => {
                error!(success = false, error = %e, "Config reload failed: invalid config");
            }
        }
    }
}

pub async fn run_proxy(server: Arc<ProxyServer>) -> anyhow::Result<()> {
    let bind_addr = {
        let state = server.state.load();
        state.config.proxy.bind.clone()
    };

    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to '{}': {}", bind_addr, e))?;

    info!(addr = %bind_addr, "Proxy listening");

    let max_connections = {
        let state = server.state.load();
        state.config.proxy.max_connections
    };

    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Accept error");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(peer = %peer_addr, "Max connections reached, dropping connection");
                drop(stream);
                continue;
            }
        };

        let server = server.clone();
        tokio::spawn(async move {
            handle_connection(stream, peer_addr, server).await;
            drop(permit);
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    server: Arc<ProxyServer>,
) {
    // Peek the first byte to determine if TLS or plaintext
    let mut peek_buf = [0u8; 1];
    match stream.peek(&mut peek_buf).await {
        Ok(0) => return, // Connection closed immediately
        Err(e) => {
            warn!(peer = %peer_addr, error = %e, "Peek failed");
            return;
        }
        Ok(_) => {}
    }

    if peek_buf[0] == 0x16 {
        // TLS ClientHello — do mTLS handshake
        handle_tls_connection(stream, peer_addr, server).await;
    } else {
        // Plaintext HTTP — only serve PAC endpoint
        handle_plaintext_connection(stream, peer_addr, server).await;
    }
}

async fn handle_tls_connection(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    server: Arc<ProxyServer>,
) {
    let tls_acceptor = {
        let state = server.state.load();
        state.tls_acceptor.clone()
    };

    let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!(client_addr = %peer_addr, error = %e, "TLS handshake failed");
            return;
        }
    };

    // Extract client CN from TLS connection
    let client_cn = {
        let (_, server_conn) = tls_stream.get_ref();
        extract_client_cn(server_conn)
    };

    // Now handle as HTTP proxy
    let state = server.state.load();
    let allowlist = state.allowlist.clone();
    let opts = ConnOpts {
        connect_timeout_ms: state.config.proxy.connect_timeout_ms,
        idle_timeout_ms: state.config.proxy.idle_timeout_ms,
        block_private_ips: state.config.proxy.block_private_ips,
        allowed_connect_ports: state.config.proxy.allowed_connect_ports.clone(),
    };
    drop(state);

    handle_proxy_http(tls_stream, peer_addr, allowlist, opts, client_cn).await;
}

#[derive(Clone)]
struct ConnOpts {
    connect_timeout_ms: u64,
    idle_timeout_ms: u64,
    block_private_ips: bool,
    allowed_connect_ports: Vec<u16>,
}

async fn handle_proxy_http<S>(
    stream: S,
    peer_addr: std::net::SocketAddr,
    allowlist: Arc<Allowlist>,
    opts: ConnOpts,
    client_cn: Option<String>,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    use hyper::server::conn::http1;

    let cn = client_cn.clone();
    let al = allowlist.clone();
    let opts2 = opts.clone();

    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let cn = cn.clone();
        let al = al.clone();
        let opts = opts2.clone();
        async move {
            Ok::<Response<BoxBody>, std::convert::Infallible>(
                dispatch_proxy_request(req, al, opts, cn).await,
            )
        }
    });

    // For CONNECT, we need raw stream access after the 200 response.
    // hyper doesn't easily support this in service_fn. We'll use the
    // upgraded connection approach.
    let conn = http1::Builder::new()
        .keep_alive(false)
        .serve_connection(io, service)
        .with_upgrades();

    if let Err(e) = conn.await {
        tracing::debug!(peer = %peer_addr, error = %e, "HTTP connection error");
    }
}

async fn dispatch_proxy_request(
    req: Request<hyper::body::Incoming>,
    allowlist: Arc<Allowlist>,
    opts: ConnOpts,
    client_cn: Option<String>,
) -> Response<BoxBody> {
    if req.method() == Method::CONNECT {
        handle_connect_request(req, allowlist, opts, client_cn).await
    } else {
        crate::http_handler::handle_http(
            req,
            allowlist,
            opts.connect_timeout_ms,
            opts.block_private_ips,
            client_cn,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect_request(
    req: Request<hyper::body::Incoming>,
    allowlist: Arc<Allowlist>,
    opts: ConnOpts,
    client_cn: Option<String>,
) -> Response<BoxBody> {
    let authority = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"bad_request","detail":"missing authority in CONNECT"}"#,
            );
        }
    };

    let (host, port) = match crate::connect_handler::parse_connect_authority(&authority) {
        Some(hp) => hp,
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"bad_request","detail":"invalid authority in CONNECT"}"#,
            );
        }
    };

    if !allowlist.is_allowed(&host) {
        warn!(
            client_cn = ?client_cn,
            method = "CONNECT",
            host = %host,
            port = port,
            reason = "domain_not_allowed",
            "CONNECT denied"
        );
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "domain_not_allowed", "host": host}).to_string(),
        );
    }

    // Restrict CONNECT to configured ports (default: 443, 8443)
    if !opts.allowed_connect_ports.is_empty() && !opts.allowed_connect_ports.contains(&port) {
        warn!(
            client_cn = ?client_cn,
            method = "CONNECT",
            host = %host,
            port = port,
            reason = "port_not_allowed",
            "CONNECT denied: port not in allowed set"
        );
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "port_not_allowed", "host": host, "port": port}).to_string(),
        );
    }

    let matched_rule = allowlist.matched_rule(&host).unwrap_or_default();

    // Connect to upstream
    let addr = format!("{}:{}", host, port);

    // SSRF protection: resolve DNS and check that all addresses are public
    if opts.block_private_ips {
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                let resolved: Vec<_> = addrs.collect();
                if resolved.is_empty() {
                    warn!(client_cn = ?client_cn, host = %host, port = port, "CONNECT: DNS resolution returned no addresses");
                    return json_response(
                        StatusCode::BAD_GATEWAY,
                        &json!({"error": "upstream_unreachable", "host": host}).to_string(),
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
                            "CONNECT denied: host resolves to private IP"
                        );
                        return json_response(
                            StatusCode::FORBIDDEN,
                            &json!({"error": "private_ip_blocked", "host": host}).to_string(),
                        );
                    }
                }
            }
            Err(e) => {
                warn!(client_cn = ?client_cn, host = %host, port = port, error = %e, "CONNECT: DNS resolution failed");
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    &json!({"error": "upstream_unreachable", "host": host}).to_string(),
                );
            }
        }
    }

    let upstream = match tokio::time::timeout(
        Duration::from_millis(opts.connect_timeout_ms),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(client_cn = ?client_cn, host = %host, port = port, error = %e, "CONNECT: upstream unreachable");
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({"error": "upstream_unreachable", "host": host}).to_string(),
            );
        }
        Err(_) => {
            warn!(client_cn = ?client_cn, host = %host, port = port, "CONNECT: upstream timeout");
            return json_response(
                StatusCode::GATEWAY_TIMEOUT,
                &json!({"error": "upstream_timeout", "host": host}).to_string(),
            );
        }
    };

    let upstream_addr = upstream
        .peer_addr()
        .ok()
        .map(|a| a.to_string())
        .unwrap_or_default();
    info!(
        client_cn = ?client_cn,
        host = %host,
        port = port,
        upstream_addr = %upstream_addr,
        matched_rule = %matched_rule,
        "CONNECT tunnel open"
    );

    let cn_close = client_cn.clone();
    let host_close = host.clone();
    let idle_timeout = Duration::from_millis(opts.idle_timeout_ms);

    // Use hyper's upgrade mechanism
    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let start = std::time::Instant::now();
                let (tx, rx) = bidirectional_copy(io, upstream, idle_timeout).await;
                let duration_ms = start.elapsed().as_millis();
                info!(
                    client_cn = ?cn_close,
                    host = %host_close,
                    duration_ms = duration_ms,
                    bytes_tx = tx,
                    bytes_rx = rx,
                    "CONNECT tunnel closed"
                );
            }
            Err(e) => {
                warn!(host = %host_close, error = %e, "CONNECT upgrade failed");
            }
        }
    });

    // Return 200 Connection Established
    Response::builder()
        .status(StatusCode::OK)
        .body(full_body(""))
        .unwrap()
}

async fn bidirectional_copy<A, B>(a: A, b: B, idle_timeout: Duration) -> (u64, u64)
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    B: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let a_to_b = copy_with_timeout(&mut ar, &mut bw, idle_timeout);
    let b_to_a = copy_with_timeout(&mut br, &mut aw, idle_timeout);

    tokio::join!(a_to_b, b_to_a)
}

async fn copy_with_timeout<R, W>(reader: &mut R, writer: &mut W, idle_timeout: Duration) -> u64
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; 16384];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(idle_timeout, reader.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
    }
    let _ = writer.shutdown().await;
    total
}

async fn handle_plaintext_connection(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    server: Arc<ProxyServer>,
) {
    // Only serve GET /proxy.pac; everything else gets 403
    let io = TokioIo::new(stream);
    let state = server.state.load();
    let pac_script = state.pac_script.clone();
    drop(state);

    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let pac = pac_script.clone();
        let peer = peer_addr;
        async move {
            let resp = handle_plaintext_request(req, pac, peer).await;
            Ok::<Response<BoxBody>, std::convert::Infallible>(resp)
        }
    });

    let conn = hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(io, service);

    if let Err(e) = conn.await {
        tracing::debug!(peer = %peer_addr, error = %e, "Plaintext connection error");
    }
}

async fn handle_plaintext_request(
    req: Request<hyper::body::Incoming>,
    pac_script: String,
    peer_addr: std::net::SocketAddr,
) -> Response<BoxBody> {
    let path = req.uri().path();

    if req.method() == Method::GET && path == "/proxy.pac" {
        info!(client_addr = %peer_addr, "PAC served");
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/x-ns-proxy-autoconfig")
            .body(full_body(&pac_script))
            .unwrap()
    } else {
        warn!(client_addr = %peer_addr, path = %path, "Non-PAC plaintext request denied");
        json_response(StatusCode::FORBIDDEN, r#"{"error":"tls_required"}"#)
    }
}
