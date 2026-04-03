#![allow(unused_crate_dependencies)]
mod common;
use common::{
    build_client_tls_config, generate_test_pki, spawn_proxy, spawn_proxy_with, TestProxyConfig,
};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

async fn spawn_mock_tcp_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::net::TcpListener;
    // Bind to localhost explicitly
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (port, handle)
}

async fn send_connect_and_get_status(
    proxy_addr: std::net::SocketAddr,
    host: &str,
    port: u16,
    config: std::sync::Arc<rustls::ClientConfig>,
) -> u16 {
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n\r\n",
        host, port, host, port
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    // Read response status line + headers
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        tls_stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    let status: u16 = response_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    status
}

/// I3: CONNECT tunnel — allowed domain, bidirectional bytes flow
#[tokio::test]
async fn i3_connect_tunnel_allowed_domain() {
    let pki = generate_test_pki();
    let (echo_port, _echo) = spawn_mock_tcp_echo_server().await;

    // Use "localhost" in allowlist (not an IP address)
    let proxy = spawn_proxy(&pki, &["localhost"]).await;

    let config = build_client_tls_config(&pki);
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    let request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: keep-alive\r\n\r\n",
        echo_port, echo_port
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    // Read until end of headers
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        tls_stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "Expected 200 Connection Established, got: {}",
        response_str.lines().next().unwrap_or("")
    );

    // Verify tunnel works — send data and receive echo
    let test_data = b"hello tunnel";
    tls_stream.write_all(test_data).await.unwrap();

    let mut recv = vec![0u8; test_data.len()];
    tls_stream.read_exact(&mut recv).await.unwrap();
    assert_eq!(&recv, test_data, "Tunnel echo mismatch");
}

/// I4: CONNECT tunnel — denied domain
#[tokio::test]
async fn i4_connect_tunnel_denied_domain() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &["allowed.test"]).await;

    let config = build_client_tls_config(&pki);
    let status = send_connect_and_get_status(proxy.addr, "denied.test", 443, config).await;
    assert_eq!(status, 403, "Expected 403 for denied domain");
}

/// I5: CONNECT tunnel — upstream unreachable
#[tokio::test]
async fn i5_connect_tunnel_upstream_unreachable() {
    let pki = generate_test_pki();
    // localhost is in allowlist, but port 1 should be unreachable
    let proxy = spawn_proxy(&pki, &["localhost"]).await;

    let config = build_client_tls_config(&pki);
    let status = send_connect_and_get_status(proxy.addr, "localhost", 1, config).await;
    assert!(
        status == 502 || status == 504,
        "Expected 502 or 504 for unreachable upstream, got {}",
        status
    );
}

/// I14: CONNECT idle timeout — tunnel closed after idle_timeout_ms
#[tokio::test]
async fn i14_connect_idle_timeout() {
    let pki = generate_test_pki();
    let (echo_port, _echo) = spawn_mock_tcp_echo_server().await;

    // Set short idle timeout
    let proxy = spawn_proxy_with(
        &pki,
        TestProxyConfig {
            allowlist: &["localhost"],
            idle_timeout_ms: 300,
            ..Default::default()
        },
    )
    .await;

    let config = build_client_tls_config(&pki);
    let connector = TlsConnector::from(config);
    let stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, stream).await.unwrap();

    let request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: keep-alive\r\n\r\n",
        echo_port, echo_port
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    // Read until end of CONNECT response headers
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        tls_stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // Don't send any data — wait for idle timeout
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // Tunnel should be closed
    let mut buf = [0u8; 64];
    let result = tls_stream.read(&mut buf).await;
    match result {
        Ok(0) | Err(_) => {} // expected: tunnel closed
        Ok(n) => panic!("Expected tunnel close, got {} bytes", n),
    }
}

/// I15: Concurrent tunnels — max_connections enforced
#[tokio::test]
async fn i15_concurrent_connections_limit() {
    let pki = generate_test_pki();
    let (echo_port, _echo) = spawn_mock_tcp_echo_server().await;

    let proxy = spawn_proxy_with(
        &pki,
        TestProxyConfig {
            allowlist: &["localhost"],
            idle_timeout_ms: 30000,
            ..Default::default()
        },
    )
    .await;

    // Open 5 tunnels simultaneously
    let mut handles = Vec::new();
    for _ in 0..5 {
        let addr = proxy.addr;
        let port = echo_port;
        let config = build_client_tls_config(&pki);
        handles.push(tokio::spawn(async move {
            let connector = TlsConnector::from(config);
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let domain = ServerName::try_from("localhost".to_string())?;
            let mut tls_stream = connector.connect(domain, stream).await?;

            let request = format!(
                "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: keep-alive\r\n\r\n",
                port, port
            );
            tls_stream.write_all(request.as_bytes()).await?;

            let mut response = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                tls_stream.read_exact(&mut byte).await?;
                response.push(byte[0]);
                if response.ends_with(b"\r\n\r\n") { break; }
            }

            let status_line = String::from_utf8_lossy(&response);
            let status: u16 = status_line.lines().next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            anyhow::Ok(status)
        }));
    }

    let results: Vec<u16> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap().unwrap())
        .collect();

    // All should succeed since max_connections defaults to 1024
    assert!(
        results.iter().all(|&s| s == 200),
        "Expected all tunnels to succeed, got: {:?}",
        results
    );
}

/// I16: CONNECT to a domain that resolves to a private IP is blocked when block_private_ips = true
#[tokio::test]
async fn i16_connect_ssrf_blocked() {
    let pki = generate_test_pki();
    // "localhost" resolves to 127.0.0.1 which is private
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
    let status = send_connect_and_get_status(proxy.addr, "localhost", 443, config).await;
    assert_eq!(
        status, 403,
        "Expected 403 private_ip_blocked for CONNECT to localhost"
    );
}

/// I17: CONNECT to a disallowed port is rejected with 403
#[tokio::test]
async fn i17_connect_port_not_allowed() {
    let pki = generate_test_pki();
    let (echo_port, _echo) = spawn_mock_tcp_echo_server().await;

    // Only allow port 443; echo_port is ephemeral and will not be 443
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
    let status = send_connect_and_get_status(proxy.addr, "localhost", echo_port, config).await;
    assert_eq!(status, 403, "Expected 403 port_not_allowed");
}

/// I18: CONNECT to an allowed port succeeds
#[tokio::test]
async fn i18_connect_port_allowed() {
    let pki = generate_test_pki();
    let (echo_port, _echo) = spawn_mock_tcp_echo_server().await;

    // Allow the echo port specifically
    let proxy = spawn_proxy_with(
        &pki,
        TestProxyConfig {
            allowlist: &["localhost"],
            allowed_connect_ports: vec![echo_port],
            ..Default::default()
        },
    )
    .await;

    let config = build_client_tls_config(&pki);
    let status = send_connect_and_get_status(proxy.addr, "localhost", echo_port, config).await;
    assert_eq!(status, 200, "Expected 200 for allowed port");
}

/// I19: Connection limit — 3rd connection is dropped when max_connections = 2
#[tokio::test]
async fn i19_connection_limit_rejection() {
    let pki = generate_test_pki();

    let proxy = spawn_proxy_with(
        &pki,
        TestProxyConfig {
            allowlist: &["localhost"],
            max_connections: 2,
            idle_timeout_ms: 30000,
            ..Default::default()
        },
    )
    .await;

    let config = build_client_tls_config(&pki);

    // Open 2 TLS connections and hold them open without sending any HTTP data.
    // The proxy is waiting for an HTTP request on each, so the semaphore permits
    // are held for the duration.
    let connector1 = TlsConnector::from(config.clone());
    let stream1 = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let _tls1 = connector1.connect(domain.clone(), stream1).await.unwrap();

    let connector2 = TlsConnector::from(config.clone());
    let stream2 = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let _tls2 = connector2.connect(domain.clone(), stream2).await.unwrap();

    // Brief pause to ensure both connections are registered with the semaphore
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3rd connection — the proxy drops the TCP stream immediately after accept,
    // so the TLS handshake fails
    let connector3 = TlsConnector::from(config.clone());
    let stream3 = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let result = connector3.connect(domain, stream3).await;
    assert!(
        result.is_err(),
        "Expected TLS handshake to fail when max_connections is reached"
    );

    // Keep the first two connections alive until after the assertion
    drop(_tls1);
    drop(_tls2);
}
