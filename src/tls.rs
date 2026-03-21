use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub fn build_server_tls_config(
    server_cert: &Path,
    server_key: &Path,
    ca_cert: &Path,
) -> anyhow::Result<Arc<ServerConfig>> {
    // Load server cert chain
    let cert_file = std::fs::File::open(server_cert)
        .map_err(|e| anyhow::anyhow!("Failed to open server cert '{}': {}", server_cert.display(), e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse server cert: {}", e))?;

    // Load server private key
    let key_file = std::fs::File::open(server_key)
        .map_err(|e| anyhow::anyhow!("Failed to open server key '{}': {}", server_key.display(), e))?;
    let mut key_reader = BufReader::new(key_file);
    let private_key = private_key(&mut key_reader)
        .map_err(|e| anyhow::anyhow!("Failed to parse server key: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in '{}'", server_key.display()))?;

    // Load CA cert for client verification
    let ca_file = std::fs::File::open(ca_cert)
        .map_err(|e| anyhow::anyhow!("Failed to open CA cert '{}': {}", ca_cert.display(), e))?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> = certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse CA cert: {}", e))?;

    // Build root cert store from CA
    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    // Build client cert verifier (mandatory)
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        provider.clone(),
    )
    .build()
    .map_err(|e| anyhow::anyhow!("Failed to build client verifier: {}", e))?;

    let config = ServerConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions: {}", e))?
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(cert_chain, private_key)
    .map_err(|e| anyhow::anyhow!("Failed to build TLS config: {}", e))?;

    Ok(Arc::new(config))
}

/// Extract the client's Common Name from a verified TLS connection.
pub fn extract_client_cn(conn: &rustls::ServerConnection) -> Option<String> {
    let certs = conn.peer_certificates()?;
    let cert = certs.first()?;
    extract_cn_from_der(cert.as_ref())
}

fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // Simple ASN.1 DER parser to extract CN from Subject
    // We look for the CN OID: 2.5.4.3 = 55 04 03
    let cn_oid = &[0x55, 0x04, 0x03u8];
    let mut i = 0;
    while i + cn_oid.len() + 2 < der.len() {
        if &der[i..i + cn_oid.len()] == cn_oid {
            // Found CN OID. Next bytes: tag (0x0c UTF8String or 0x13 PrintableString), length, value
            let tag_pos = i + cn_oid.len();
            if tag_pos + 2 <= der.len() {
                let len = der[tag_pos + 1] as usize;
                let val_start = tag_pos + 2;
                let val_end = val_start + len;
                if val_end <= der.len() {
                    return std::str::from_utf8(&der[val_start..val_end])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
        }
        i += 1;
    }
    None
}
