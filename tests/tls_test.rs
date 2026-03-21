#![allow(unused_crate_dependencies)]
mod common;
use common::{
    build_client_tls_config, build_client_tls_config_with_cert, generate_test_pki, spawn_proxy,
};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// In TLS 1.3, the server sends its CertificateVerified/Finished before it processes
/// the client's cert. So `connector.connect()` may return Ok even if the server will
/// subsequently reject the cert. We must attempt to send data and check the result.
async fn try_proxy_connection(
    proxy_addr: std::net::SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
) -> Result<(), String> {
    let connector = TlsConnector::from(client_config);
    let stream = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("TCP connect failed: {}", e))?;
    let domain =
        ServerName::try_from("localhost".to_string()).map_err(|e| format!("Bad domain: {}", e))?;

    let mut tls_stream = match connector.connect(domain, stream).await {
        Ok(s) => s,
        Err(e) => return Err(format!("TLS handshake failed (connect): {}", e)),
    };

    // In TLS 1.3 the server validates client cert AFTER connect() returns.
    // Try to send an HTTP-like request to trigger server-side validation.
    let req = b"GET /proxy.pac HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if tls_stream.write_all(req).await.is_err() {
        return Err("Write failed (connection rejected post-handshake)".to_string());
    }

    let mut buf = [0u8; 256];
    match tls_stream.read(&mut buf).await {
        Ok(0) => Err("Connection closed (empty read — server rejected)".to_string()),
        Ok(_n) => {
            // Got some data back — connection actually worked
            Ok(())
        }
        Err(e) => Err(format!(
            "Read failed (server rejected post-handshake): {}",
            e
        )),
    }
}

async fn tls_connect_no_cert(
    proxy_addr: std::net::SocketAddr,
    ca_path: &std::path::PathBuf,
) -> Result<(), String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;

    let ca_file = std::fs::File::open(ca_path).map_err(|e| e.to_string())?;
    let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| e.to_string())?;
    }

    // No client cert
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth(),
    );

    try_proxy_connection(proxy_addr, config).await
}

/// I9: No client cert → connection should be rejected by server
#[tokio::test]
async fn i9_no_client_cert_handshake_failure() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &[]).await;

    let result = tls_connect_no_cert(proxy.addr, &pki.ca_cert_path).await;
    assert!(
        result.is_err(),
        "Expected TLS failure without client cert, but got success"
    );
}

/// I10: Wrong CA client cert → connection should be rejected by server
#[tokio::test]
async fn i10_wrong_ca_client_cert_handshake_failure() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &[]).await;

    // Use wrong client cert (signed by wrong CA) but trust the correct CA for server verification
    let config = build_client_tls_config_with_cert(
        &pki.wrong_client_cert_path,
        &pki.wrong_client_key_path,
        &pki.ca_cert_path,
    );

    let result = try_proxy_connection(proxy.addr, config).await;
    assert!(
        result.is_err(),
        "Expected TLS failure with wrong CA cert, but got success"
    );
}

/// I11: Valid client cert → handshake succeeds and proxy responds
#[tokio::test]
async fn i11_valid_client_cert_handshake_succeeds() {
    let pki = generate_test_pki();
    let proxy = spawn_proxy(&pki, &[]).await;

    let config = build_client_tls_config(&pki);
    let result = try_proxy_connection(proxy.addr, config).await;
    assert!(
        result.is_ok(),
        "Expected TLS success with valid client cert: {:?}",
        result.err()
    );
}
