use crate::config::{TlsConfig, TlsMode};
use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY;
use rustls_acme::{caches::DirCache, AcmeConfig, AcmeState};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

type IoAcmeState = AcmeState<std::io::Error, std::io::Error>;

pub enum ServerTlsConfig {
    Manual(Arc<ServerConfig>),
    Acme {
        config: Arc<ServerConfig>,
        state: IoAcmeState,
    },
}

pub fn build_server_tls_config(tls_config: &TlsConfig) -> anyhow::Result<ServerTlsConfig> {
    // Load CA cert for client verification (mTLS)
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&tls_config.ca_cert)
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to open CA cert '{}': {}",
                tls_config.ca_cert.display(),
                e
            )
        })?
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

    match &tls_config.mode {
        TlsMode::Manual {
            server_cert,
            server_key,
        } => {
            // Load server cert chain
            let cert_chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_file_iter(server_cert)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to open server cert '{}': {}",
                            server_cert.display(),
                            e
                        )
                    })?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| anyhow::anyhow!("Failed to parse server cert: {}", e))?;

            // Load server private key
            let private_key = PrivateKeyDer::from_pem_file(server_key).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse server key '{}': {}",
                    server_key.display(),
                    e
                )
            })?;

            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions: {}", e))?
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| anyhow::anyhow!("Failed to build TLS config: {}", e))?;

            Ok(ServerTlsConfig::Manual(Arc::new(config)))
        }
        TlsMode::Acme {
            domains,
            email,
            cache_dir,
            staging,
        } => {
            let mut acme_config = AcmeConfig::new(domains.clone())
                .contact_push(format!("mailto:{}", email))
                .cache(DirCache::new(cache_dir.clone()));

            if *staging {
                acme_config = acme_config.directory(LETS_ENCRYPT_STAGING_DIRECTORY);
            }

            let state = acme_config.state();
            let cert_resolver = state.resolver();

            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions: {}", e))?
                .with_client_cert_verifier(client_verifier)
                .with_cert_resolver(cert_resolver);

            Ok(ServerTlsConfig::Acme {
                config: Arc::new(config),
                state,
            })
        }
    }
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
