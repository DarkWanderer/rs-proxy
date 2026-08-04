#![allow(unused_crate_dependencies)]
mod common;
use common::{generate_test_pki, TestPkiOwned};

use gatekeeper::proxy::accept_tls_stream;
use rustls::pki_types::ServerName;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

fn load_server_cert_and_key(
    pki: &TestPkiOwned,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(&pki.server_cert_path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_file(&pki.server_key_path).unwrap();
    (cert_chain, key)
}

fn load_root_store(pki: &TestPkiOwned) -> RootCertStore {
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&pki.ca_cert_path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).unwrap();
    }
    root_store
}

/// Mirrors the mTLS `ServerConfig` gatekeeper builds for normal (non-challenge) TLS
/// connections: mandatory client cert verification, no ALPN configured.
fn build_mtls_config(pki: &TestPkiOwned) -> Arc<ServerConfig> {
    let (cert_chain, key) = load_server_cert_and_key(pki);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(load_root_store(pki)),
        provider.clone(),
    )
    .build()
    .unwrap();
    Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .unwrap(),
    )
}

/// Mirrors what `AcmeState::challenge_rustls_config_with_provider` builds: no client
/// auth, and "acme-tls/1" negotiated via ALPN.
fn build_challenge_config(pki: &TestPkiOwned) -> Arc<ServerConfig> {
    let (cert_chain, key) = load_server_cert_and_key(pki);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();
    config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
    Arc::new(config)
}

/// Spawn a bare listener that runs gatekeeper's real `accept_tls_stream` dispatch
/// (the exact function `handle_tls_connection` calls in ACME mode) on every
/// connection, without going through `ProxyState`/`AcmeState` — a real `AcmeState`
/// would try to reach Let's Encrypt.
async fn spawn_dispatch_server(
    mtls_config: Arc<ServerConfig>,
    challenge_config: Arc<ServerConfig>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls_acceptor = TlsAcceptor::from(mtls_config);

    tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let tls_acceptor = tls_acceptor.clone();
            let challenge_config = Some(challenge_config.clone());
            tokio::spawn(async move {
                let _ = accept_tls_stream(stream, &tls_acceptor, challenge_config, peer_addr).await;
            });
        }
    });

    addr
}

async fn connect_with_alpn(
    addr: std::net::SocketAddr,
    root_store: RootCertStore,
    alpn_protocols: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut client_config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
    client_config.alpn_protocols = alpn_protocols;

    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(addr).await?;
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    connector.connect(domain, stream).await
}

/// A client offering only "acme-tls/1" must get that protocol negotiated against the
/// ACME challenge config, not silently fall through to the mTLS config. This is the
/// exact assertion that fails without the ALPN dispatch: today's single `ServerConfig`
/// never sets `alpn_protocols`, so rustls completes the handshake with no ALPN protocol
/// negotiated at all, and Let's Encrypt's TLS-ALPN-01 validator fails every time.
#[tokio::test]
async fn acme_challenge_client_negotiates_acme_tls_alpn() {
    let pki = generate_test_pki();
    let addr = spawn_dispatch_server(build_mtls_config(&pki), build_challenge_config(&pki)).await;

    let tls_stream = connect_with_alpn(
        addr,
        load_root_store(&pki),
        vec![ACME_TLS_ALPN_NAME.to_vec()],
    )
    .await
    .expect("handshake with acme-tls/1 ALPN offer should succeed");

    let (_, client_conn) = tls_stream.get_ref();
    assert_eq!(
        client_conn.alpn_protocol(),
        Some(ACME_TLS_ALPN_NAME),
        "expected acme-tls/1 to be negotiated for a challenge connection"
    );
}

/// A normal client (no ALPN offer, no client cert) must still be routed to the mTLS
/// config and rejected for lacking a client certificate — the challenge config must
/// never leak into the regular proxy path.
#[tokio::test]
async fn normal_client_without_cert_is_routed_to_mtls_and_rejected() {
    let pki = generate_test_pki();
    let addr = spawn_dispatch_server(build_mtls_config(&pki), build_challenge_config(&pki)).await;

    let mut tls_stream = match connect_with_alpn(addr, load_root_store(&pki), vec![]).await {
        Ok(s) => s,
        Err(_) => return, // rejected during handshake — also a valid outcome
    };

    // In TLS 1.3 the server may complete its handshake flight before processing the
    // client's (missing) certificate, so the rejection can only surface once we try
    // to exchange data. See tests/tls_test.rs for the same pattern.
    let write_result = tls_stream.write_all(b"ping").await;
    let mut buf = [0u8; 16];
    let read_result = tls_stream.read(&mut buf).await;

    let rejected = write_result.is_err() || matches!(read_result, Ok(0) | Err(_));
    assert!(
        rejected,
        "expected connection without a client cert to be rejected by the mTLS config"
    );
}
