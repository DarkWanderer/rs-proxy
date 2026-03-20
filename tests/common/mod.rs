pub mod certs;

pub use certs::{generate_test_pki, TestPkiOwned, TempDir};

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
}

impl Default for TestProxyConfig<'_> {
    fn default() -> Self {
        TestProxyConfig {
            allowlist: &[],
            connect_timeout_ms: 2000,
            idle_timeout_ms: 30000,
        }
    }
}

/// Spawn a test proxy on a random port.
pub async fn spawn_proxy(pki: &TestPkiOwned, allowlist: &[&str]) -> TestProxy {
    spawn_proxy_with(pki, TestProxyConfig { allowlist, ..Default::default() }).await
}

pub async fn spawn_proxy_with(pki: &TestPkiOwned, cfg: TestProxyConfig<'_>) -> TestProxy {
    // Find a free port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Write config to temp file
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    let domains_toml = cfg.allowlist
        .iter()
        .map(|d| format!("  \"{}\",", d))
        .collect::<Vec<_>>()
        .join("\n");

    let config_content = format!(
        r#"[proxy]
bind = "{addr}"
connect_timeout_ms = {connect_timeout}
idle_timeout_ms = {idle_timeout}

[tls]
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
    build_client_tls_config_with_cert(&pki.client_cert_path, &pki.client_key_path, &pki.ca_cert_path)
}

pub fn build_client_tls_config_with_cert(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    ca_path: &PathBuf,
) -> Arc<rustls::ClientConfig> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    let cert_file = std::fs::File::open(cert_path).unwrap();
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

    let key_file = std::fs::File::open(key_path).unwrap();
    let key = private_key(&mut BufReader::new(key_file)).unwrap().unwrap();

    let ca_file = std::fs::File::open(ca_path).unwrap();
    let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(ca_file))
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
