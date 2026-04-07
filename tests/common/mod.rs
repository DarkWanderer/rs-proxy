#![allow(dead_code)]

pub mod certs;

pub use certs::{generate_test_pki, TempDir, TestPkiOwned};

use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

/// A running test proxy instance
pub struct TestProxy {
    pub addr: std::net::SocketAddr,
    pub config_path: PathBuf,
    _handle: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

/// Configuration for spawning a test proxy
pub struct TestProxyConfig<'a> {
    pub allowlist: &'a [&'a str],
    pub connect_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub block_private_ips: bool,
    pub allowed_connect_ports: Vec<u16>,
    pub max_connections: usize,
}

impl Default for TestProxyConfig<'_> {
    fn default() -> Self {
        TestProxyConfig {
            allowlist: &[],
            connect_timeout_ms: 2000,
            idle_timeout_ms: 30000,
            block_private_ips: false,
            allowed_connect_ports: vec![],
            max_connections: 1024,
        }
    }
}

/// Spawn a test proxy on a random port.
pub async fn spawn_proxy(pki: &TestPkiOwned, allowlist: &[&str]) -> TestProxy {
    spawn_proxy_with(
        pki,
        TestProxyConfig {
            allowlist,
            ..Default::default()
        },
    )
    .await
}

pub async fn spawn_proxy_with(pki: &TestPkiOwned, cfg: TestProxyConfig<'_>) -> TestProxy {
    // Find a free port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Write config to temp file
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let domains_toml = cfg
        .allowlist
        .iter()
        .map(|d| format!("  \"{}\",", d))
        .collect::<Vec<_>>()
        .join("\n");

    let ports_toml = if cfg.allowed_connect_ports.is_empty() {
        "[]".to_string()
    } else {
        format!(
            "[{}]",
            cfg.allowed_connect_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let config_content = format!(
        r#"[proxy]
bind = "{addr}"
connect_timeout_ms = {connect_timeout}
idle_timeout_ms = {idle_timeout}
block_private_ips = {block_private_ips}
max_connections = {max_connections}
allowed_connect_ports = {ports}

[tls]
mode = "manual"
server_cert = "{server_cert}"
server_key  = "{server_key}"
ca_cert     = "{ca_cert}"

[allowlist]
domains = [
{domains}
]

[logging]
level = "error"
format = "pretty"
"#,
        addr = addr,
        connect_timeout = cfg.connect_timeout_ms,
        idle_timeout = cfg.idle_timeout_ms,
        block_private_ips = cfg.block_private_ips,
        max_connections = cfg.max_connections,
        ports = ports_toml,
        server_cert = pki.server_cert_path.display(),
        server_key = pki.server_key_path.display(),
        ca_cert = pki.ca_cert_path.display(),
        domains = domains_toml,
    );

    std::fs::write(&config_path, &config_content).unwrap();

    let config = gatekeeper::config::Config::load(config_path.to_str().unwrap()).unwrap();
    let state = gatekeeper::proxy::ProxyState::new(config).unwrap();
    let shared = Arc::new(arc_swap::ArcSwap::from(Arc::new(state)));
    let server = Arc::new(gatekeeper::proxy::ProxyServer::new(
        shared,
        config_path.to_str().unwrap().to_string(),
    ));

    let handle = tokio::spawn(async move {
        let _ = gatekeeper::proxy::run_proxy(server).await;
    });

    // Give the proxy a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    TestProxy {
        addr,
        config_path,
        _handle: handle,
        _dir: dir,
    }
}

/// Build a rustls client config with mTLS using the test PKI
pub fn build_client_tls_config(pki: &TestPkiOwned) -> Arc<rustls::ClientConfig> {
    build_client_tls_config_with_cert(
        &pki.client_cert_path,
        &pki.client_key_path,
        &pki.ca_cert_path,
    )
}

pub fn build_client_tls_config_with_cert(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    ca_path: &PathBuf,
) -> Arc<rustls::ClientConfig> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let key = PrivateKeyDer::from_pem_file(key_path).unwrap();

    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(ca_path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).unwrap();
    }

    Arc::new(
        rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key)
        .unwrap(),
    )
}

/// Fetch the PAC script via plain HTTP (no TLS)
pub async fn fetch_pac(proxy_addr: std::net::SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET /proxy.pac HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        proxy_addr
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}
