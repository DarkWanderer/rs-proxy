mod common;
use common::{fetch_pac, generate_test_pki, spawn_proxy};

/// I6: PAC endpoint served without client auth (plain HTTP)
#[tokio::test]
async fn i6_pac_endpoint_unauthenticated() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &["example.com"]).await;

    let response = fetch_pac(proxy.addr).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "Expected 200, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(
        response.contains("application/x-ns-proxy-autoconfig"),
        "Missing PAC content type"
    );
    assert!(
        response.contains("FindProxyForURL"),
        "Missing PAC function"
    );
}

/// I7: PAC content correctness — exact and wildcard domains
#[tokio::test]
async fn i7_pac_content_correctness() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &["github.com", "*.crates.io"]).await;

    let response = fetch_pac(proxy.addr).await;

    // Split headers and body
    let body = response.split("\r\n\r\n").nth(1).unwrap_or(&response);

    assert!(
        body.contains("host === \"github.com\""),
        "PAC missing exact match for github.com: {}", body
    );
    assert!(
        body.contains("dnsDomainIs(host, \".crates.io\")"),
        "PAC missing wildcard for *.crates.io: {}", body
    );
    assert!(
        body.contains("PROXY 0.0.0.0:0"),
        "PAC missing default deny: {}", body
    );
}

/// I8: Non-PAC plaintext request returns 403 tls_required
#[tokio::test]
async fn i8_non_pac_plaintext_request_denied() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &[]).await;

    let mut stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let request = format!(
        "GET /anything-else HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        proxy.addr
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "Expected 403, got: {}",
        response.lines().next().unwrap_or("")
    );
    assert!(response.contains("tls_required"), "Missing tls_required body: {}", response);
}
