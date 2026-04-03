#![allow(unused_crate_dependencies)]
mod common;
use common::{
    build_client_tls_config, generate_test_pki, spawn_proxy, spawn_proxy_with, TestProxyConfig,
};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// Spawn a minimal mock HTTP server.
/// Returns the listener address and a join handle.
async fn spawn_mock_http_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Note: bind to 127.0.0.1 but allowlist uses "localhost" (which resolves to 127.0.0.1)
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                let _ = stream.write_all(response).await;
            });
        }
    });

    (addr, handle)
}

/// I1: HTTP forward proxy — allowed domain
#[tokio::test]
async fn i1_http_forward_proxy_allowed_domain() {
    let pki = generate_test_pki();
    let (mock_addr, _mock) = spawn_mock_http_server().await;

    let target_host = format!("localhost:{}", mock_addr.port());
    let proxy = spawn_proxy(&pki, &["localhost"]).await;

    let config = build_client_tls_config(&pki);
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    let request = format!(
        "GET http://{}/test HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_host, target_host
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    tls_stream.read_to_string(&mut response).await.unwrap();

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "Expected 200, got: {}",
        response.lines().next().unwrap_or("")
    );
}

/// I2: HTTP forward proxy — denied domain
#[tokio::test]
async fn i2_http_forward_proxy_denied_domain() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &["allowed.test"]).await;

    let config = build_client_tls_config(&pki);
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    let request =
        "GET http://denied.test/path HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n";
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    tls_stream.read_to_string(&mut response).await.unwrap();

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "Expected 403, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(
        response.contains("domain_not_allowed"),
        "Missing domain_not_allowed body"
    );
}

/// I6: HTTP forward proxy — SSRF blocked (block_private_ips = true)
#[tokio::test]
async fn i6_http_forward_proxy_ssrf_blocked() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy_with(
        &pki,
        TestProxyConfig {
            allowlist: &["localhost"],
            block_private_ips: true,
            ..Default::default()
        },
    )
    .await;

    let config = build_client_tls_config(&pki);
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    // HTTP GET to localhost (resolves to 127.0.0.1 — private)
    let request =
        "GET http://localhost/test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    tls_stream.read_to_string(&mut response).await.unwrap();

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "Expected 403 for SSRF attempt, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(
        response.contains("private_ip_blocked"),
        "Expected private_ip_blocked in response"
    );
}

/// I7: HTTP forward proxy — port not allowed
#[tokio::test]
async fn i7_http_forward_proxy_port_not_allowed() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy_with(
        &pki,
        TestProxyConfig {
            allowlist: &["localhost"],
            allowed_connect_ports: vec![443],
            ..Default::default()
        },
    )
    .await;

    let config = build_client_tls_config(&pki);
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    // Port 8080 is not in allowed_connect_ports = [443]
    let request = "GET http://localhost:8080/test HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n";
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    tls_stream.read_to_string(&mut response).await.unwrap();

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "Expected 403 port_not_allowed, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(
        response.contains("port_not_allowed"),
        "Expected port_not_allowed in response"
    );
}
