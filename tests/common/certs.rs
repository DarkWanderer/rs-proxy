use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::path::PathBuf;

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> std::io::Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("gatekeeper-test-{}-{}", std::process::id(), ts));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub struct TestPkiOwned {
    pub _dir: TempDir,
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub wrong_client_cert_path: PathBuf,
    pub wrong_client_key_path: PathBuf,
    pub wrong_ca_cert_path: PathBuf,
}

pub fn generate_test_pki() -> TestPkiOwned {
    let dir = TempDir::new().expect("create temp dir");

    // Generate CA
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Generate server cert signed by CA
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.distinguished_name.push(DnType::CommonName, "localhost");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    // Generate valid client cert signed by CA
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec![]).unwrap();
    client_params.distinguished_name.push(DnType::CommonName, "test-client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    // Generate wrong CA
    let wrong_ca_key = KeyPair::generate().unwrap();
    let mut wrong_ca_params = CertificateParams::new(vec![]).unwrap();
    wrong_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    wrong_ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    wrong_ca_params.distinguished_name.push(DnType::CommonName, "Wrong CA");
    let wrong_ca_cert = wrong_ca_params.self_signed(&wrong_ca_key).unwrap();

    // Generate client cert signed by wrong CA
    let wrong_client_key = KeyPair::generate().unwrap();
    let mut wrong_client_params = CertificateParams::new(vec![]).unwrap();
    wrong_client_params.distinguished_name.push(DnType::CommonName, "wrong-client");
    wrong_client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let wrong_client_cert = wrong_client_params
        .signed_by(&wrong_client_key, &wrong_ca_cert, &wrong_ca_key)
        .unwrap();

    // Write all to files
    let p = dir.path();
    let ca_cert_path = p.join("ca.crt");
    let server_cert_path = p.join("server.crt");
    let server_key_path = p.join("server.key");
    let client_cert_path = p.join("client.crt");
    let client_key_path = p.join("client.key");
    let wrong_ca_cert_path = p.join("wrong_ca.crt");
    let wrong_client_cert_path = p.join("wrong_client.crt");
    let wrong_client_key_path = p.join("wrong_client.key");

    std::fs::write(&ca_cert_path, ca_cert.pem()).unwrap();
    // Server cert chain includes server cert + CA cert
    let server_chain = format!("{}\n{}", server_cert.pem(), ca_cert.pem());
    std::fs::write(&server_cert_path, &server_chain).unwrap();
    std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
    std::fs::write(&client_cert_path, client_cert.pem()).unwrap();
    std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
    std::fs::write(&wrong_ca_cert_path, wrong_ca_cert.pem()).unwrap();
    std::fs::write(&wrong_client_cert_path, wrong_client_cert.pem()).unwrap();
    std::fs::write(&wrong_client_key_path, wrong_client_key.serialize_pem()).unwrap();

    TestPkiOwned {
        _dir: dir,
        ca_cert_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
        wrong_ca_cert_path,
        wrong_client_cert_path,
        wrong_client_key_path,
    }
}
