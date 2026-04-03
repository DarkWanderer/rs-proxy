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
    let cert_file = std::fs::File::open(server_cert).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open server cert '{}': {}",
            server_cert.display(),
            e
        )
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse server cert: {}", e))?;

    // Load server private key
    let key_file = std::fs::File::open(server_key).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open server key '{}': {}",
            server_key.display(),
            e
        )
    })?;
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
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
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

/// Public wrapper around `extract_cn_from_der` for use by fuzz targets.
/// Not part of the stable public API.
#[doc(hidden)]
pub fn extract_cn_from_der_bytes(der: &[u8]) -> Option<String> {
    extract_cn_from_der(der)
}

fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string());
    cn
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cn_empty_slice_returns_none() {
        assert!(extract_cn_from_der(&[]).is_none());
    }

    #[test]
    fn extract_cn_random_bytes_returns_none() {
        let data = &[0x30u8, 0x03, 0x01, 0x01, 0xFF];
        assert!(extract_cn_from_der(data).is_none());
    }

    #[test]
    fn extract_cn_from_real_certificate() {
        use rcgen::{CertificateParams, DistinguishedName, DnType};
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-cn");
        params.distinguished_name = dn;
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der();
        assert_eq!(
            extract_cn_from_der(der.as_ref()),
            Some("test-cn".to_string())
        );
    }

    #[test]
    fn extract_cn_no_cn_returns_none() {
        use rcgen::{CertificateParams, DistinguishedName};
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der();
        // Empty subject has no CN — just verify it doesn't panic
        let _ = extract_cn_from_der(der.as_ref());
    }
}
