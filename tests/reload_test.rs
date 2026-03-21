#![allow(unused_crate_dependencies)]
mod common;
use common::{build_client_tls_config, fetch_pac, generate_test_pki};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// Returns the status code for a CONNECT request to the given host:port.
/// For denied domains, returns 403 immediately (no DNS lookup).
/// For allowed-but-unreachable domains, returns 502/504.
async fn connect_status(
    proxy_addr: std::net::SocketAddr,
    host: &str,
    port: u16,
    config: Arc<rustls::ClientConfig>,
) -> u16 {
    let connector = TlsConnector::from(config);
    let stream = match tokio::net::TcpStream::connect(proxy_addr).await {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = match connector.connect(domain, stream).await {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        host, port, host, port
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while tls_stream.read_exact(&mut byte).await.is_ok() {
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    response_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Spawn a listener, immediately close it, return the port (guaranteed closed).
async fn find_closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    // Give the OS a moment to release the port
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    port
}

/// I12: Config reload — valid new config updates allowlist
///
/// Uses localhost for all CONNECT targets (fast DNS, fast TCP failure).
/// Allowlist switches from ["localhost"] to ["other.local"].
/// - "localhost" → allowed before, denied after
/// - "other.local" → denied before, allowed after
///
/// Verification:
/// - Denied domains return 403 immediately (no DNS needed, fast)
/// - Allowed + unreachable returns non-403 (502 for localhost, which is fast)
/// - PAC script reflects the new allowlist
#[tokio::test]
async fn i12_config_reload_valid() {
    use arc_swap::ArcSwap;
    use gatekeeper::config::Config;
    use gatekeeper::proxy::{ProxyServer, ProxyState};
    use tokio::net::TcpListener;

    let pki = generate_test_pki();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);

    let closed_port = find_closed_port().await;

    let dir = common::TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let make_config = |domains: &[&str]| {
        format!(
            r#"[proxy]
bind = "{addr}"
connect_timeout_ms = 200
idle_timeout_ms = 1000

[tls]
server_cert = "{server_cert}"
server_key  = "{server_key}"
ca_cert     = "{ca_cert}"

[allowlist]
domains = [{domains}]

[logging]
level = "error"
format = "pretty"
"#,
            addr = proxy_addr,
            server_cert = pki.server_cert_path.display(),
            server_key = pki.server_key_path.display(),
            ca_cert = pki.ca_cert_path.display(),
            domains = domains
                .iter()
                .map(|d| format!("\"{}\"", d))
                .collect::<Vec<_>>()
                .join(", "),
        )
    };

    std::fs::write(&config_path, make_config(&["localhost"])).unwrap();

    let config = Config::load(config_path.to_str().unwrap()).unwrap();
    let state = ProxyState::new(config).unwrap();
    let shared = Arc::new(ArcSwap::from(Arc::new(state)));
    let server = Arc::new(ProxyServer::new(
        shared,
        config_path.to_str().unwrap().to_string(),
    ));

    let server_clone = server.clone();
    tokio::spawn(async move {
        let _ = gatekeeper::proxy::run_proxy(server_clone).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let cfg = build_client_tls_config(&pki);

    // Before reload: localhost → allowed (502, fast), neverallowed.xyz → denied (403, fast/no DNS)
    let s1 = connect_status(proxy_addr, "localhost", closed_port, cfg.clone()).await;
    let s2 = connect_status(proxy_addr, "neverallowed.xyz", 443, cfg.clone()).await;
    assert!(
        s1 != 403,
        "localhost should be allowed before reload (got {})",
        s1
    );
    assert_eq!(s2, 403, "neverallowed.xyz should be denied before reload");

    // Verify PAC contains localhost
    let pac = fetch_pac(proxy_addr).await;
    let pac_body = pac.split("\r\n\r\n").nth(1).unwrap_or(&pac);
    assert!(
        pac_body.contains("localhost"),
        "PAC should contain localhost before reload"
    );

    // Reload with new allowlist: neverallowed.xyz allowed, localhost removed
    std::fs::write(&config_path, make_config(&["neverallowed.xyz"])).unwrap();
    server.reload_config();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // After reload:
    // - localhost → denied (403, fast — no DNS needed)
    // - neverallowed.xyz → allowed, but DNS fails fast (it's a real TLD that returns NXDOMAIN)
    //   We verify via PAC rather than CONNECT to avoid DNS timing dependency
    let s1_after = connect_status(proxy_addr, "localhost", closed_port, cfg.clone()).await;
    assert_eq!(
        s1_after, 403,
        "localhost should be denied after reload (got {})",
        s1_after
    );

    // Verify PAC updated (no DNS needed)
    let pac_after = fetch_pac(proxy_addr).await;
    let pac_body_after = pac_after.split("\r\n\r\n").nth(1).unwrap_or(&pac_after);
    assert!(
        pac_body_after.contains("neverallowed.xyz"),
        "PAC should contain neverallowed.xyz after reload"
    );
    assert!(
        !pac_body_after.contains("host === \"localhost\""),
        "PAC should not contain localhost after reload"
    );
}

/// I13: Config reload — invalid config keeps previous state
#[tokio::test]
async fn i13_config_reload_invalid() {
    use arc_swap::ArcSwap;
    use gatekeeper::config::Config;
    use gatekeeper::proxy::{ProxyServer, ProxyState};
    use tokio::net::TcpListener;

    let pki = generate_test_pki();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);

    let closed_port = find_closed_port().await;

    let dir = common::TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let initial_config = format!(
        r#"[proxy]
bind = "{addr}"
connect_timeout_ms = 200
idle_timeout_ms = 1000

[tls]
server_cert = "{server_cert}"
server_key  = "{server_key}"
ca_cert     = "{ca_cert}"

[allowlist]
domains = ["localhost"]

[logging]
level = "error"
format = "pretty"
"#,
        addr = proxy_addr,
        server_cert = pki.server_cert_path.display(),
        server_key = pki.server_key_path.display(),
        ca_cert = pki.ca_cert_path.display(),
    );

    std::fs::write(&config_path, &initial_config).unwrap();

    let config = Config::load(config_path.to_str().unwrap()).unwrap();
    let state = ProxyState::new(config).unwrap();
    let shared = Arc::new(ArcSwap::from(Arc::new(state)));
    let server = Arc::new(ProxyServer::new(
        shared,
        config_path.to_str().unwrap().to_string(),
    ));

    let server_clone = server.clone();
    tokio::spawn(async move {
        let _ = gatekeeper::proxy::run_proxy(server_clone).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // Verify initial state: localhost allowed
    let cfg = build_client_tls_config(&pki);
    let s1 = connect_status(proxy_addr, "localhost", closed_port, cfg.clone()).await;
    assert!(
        s1 != 403,
        "localhost should be allowed initially (got {})",
        s1
    );

    // Write broken TOML
    std::fs::write(&config_path, "this is ][[ not valid toml").unwrap();
    server.reload_config(); // Should log error but keep old config

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Old config still active: localhost still allowed
    let s2 = connect_status(proxy_addr, "localhost", closed_port, cfg.clone()).await;
    assert!(
        s2 != 403,
        "Previous config should still be active after failed reload (got {})",
        s2
    );
}
