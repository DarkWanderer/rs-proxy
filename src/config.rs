use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub tls: TlsConfig,
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub bind: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    pub pac_proxy_addr: Option<String>,
    /// Block connections to private/loopback IPs (SSRF protection). Default: true.
    #[serde(default = "default_block_private_ips")]
    pub block_private_ips: bool,
    /// Restrict CONNECT to these ports. Empty list means all ports allowed.
    #[serde(default = "default_allowed_connect_ports")]
    pub allowed_connect_ports: Vec<u16>,
}

fn default_max_connections() -> usize {
    1024
}
fn default_connect_timeout_ms() -> u64 {
    5000
}
fn default_idle_timeout_ms() -> u64 {
    30000
}
fn default_block_private_ips() -> bool {
    true
}
fn default_allowed_connect_ports() -> Vec<u16> {
    vec![443, 8443]
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub ca_cert: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistConfig {
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", path, e))?;
        let config: Config = toml::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", path, e))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        // Validate all domain rules
        for domain in &self.allowlist.domains {
            validate_domain_rule(domain)?;
        }
        Ok(())
    }

    /// Returns the address to use in PAC script output
    pub fn pac_proxy_addr(&self) -> String {
        if let Some(addr) = &self.proxy.pac_proxy_addr {
            return addr.clone();
        }
        let bind = &self.proxy.bind;
        // If binding to 0.0.0.0, use hostname
        if bind.starts_with("0.0.0.0:") {
            let port = bind.split(':').next_back().unwrap_or("3128");
            let hostname = hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".to_string());
            format!("{}:{}", hostname, port)
        } else {
            bind.clone()
        }
    }
}

pub fn validate_domain_rule(domain: &str) -> anyhow::Result<()> {
    // Reject bare wildcard
    if domain == "*" {
        return Err(anyhow::anyhow!(
            "Bare wildcard '*' is not allowed as a domain rule"
        ));
    }

    // Check for IP address
    if is_ip_address(domain) {
        return Err(anyhow::anyhow!(
            "IP address '{}' is not allowed in allowlist (use DNS names only)",
            domain
        ));
    }

    if let Some(rest) = domain.strip_prefix("*.") {
        // Wildcard: validate the rest has no wildcards and is a valid domain
        if rest.contains('*') {
            return Err(anyhow::anyhow!(
                "Invalid wildcard pattern '{}': wildcard only allowed as leftmost label",
                domain
            ));
        }
        if rest.is_empty() {
            return Err(anyhow::anyhow!(
                "Invalid wildcard pattern '{}': missing domain after '*.'",
                domain
            ));
        }
        validate_hostname(rest, domain)?;
    } else if domain.contains('*') {
        return Err(anyhow::anyhow!(
            "Invalid wildcard pattern '{}': wildcard only allowed as leftmost label (*.example.com)",
            domain
        ));
    } else {
        validate_hostname(domain, domain)?;
    }

    Ok(())
}

fn validate_hostname(host: &str, original: &str) -> anyhow::Result<()> {
    if host.is_empty() {
        return Err(anyhow::anyhow!("Empty hostname in rule '{}'", original));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(anyhow::anyhow!(
                "Invalid hostname in rule '{}': empty label",
                original
            ));
        }
        // Labels must only contain alphanumeric, hyphens, and (for
        // internationalized names) non-ASCII characters.
        // They must not start or end with a hyphen.
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow::anyhow!(
                "Invalid hostname in rule '{}': label '{}' starts or ends with hyphen",
                original,
                label
            ));
        }
        for ch in label.chars() {
            if !ch.is_alphanumeric() && ch != '-' {
                return Err(anyhow::anyhow!(
                    "Invalid hostname in rule '{}': label '{}' contains invalid character '{}'",
                    original,
                    label,
                    ch
                ));
            }
        }
    }
    Ok(())
}

fn is_ip_address(s: &str) -> bool {
    let s = s.trim_start_matches('[').trim_end_matches(']');
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(bind: &str, pac_proxy_addr: Option<&str>) -> Config {
        Config {
            proxy: ProxyConfig {
                bind: bind.to_string(),
                max_connections: 1024,
                connect_timeout_ms: 5000,
                idle_timeout_ms: 30000,
                pac_proxy_addr: pac_proxy_addr.map(|s| s.to_string()),
                block_private_ips: true,
                allowed_connect_ports: vec![443, 8443],
            },
            tls: TlsConfig {
                server_cert: "cert.pem".into(),
                server_key: "key.pem".into(),
                ca_cert: "ca.pem".into(),
            },
            allowlist: AllowlistConfig { domains: vec![] },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn pac_proxy_addr_explicit_overrides_bind() {
        let config = make_config("0.0.0.0:3128", Some("proxy.example.com:3128"));
        assert_eq!(config.pac_proxy_addr(), "proxy.example.com:3128");
    }

    #[test]
    fn pac_proxy_addr_loopback_returned_as_is() {
        let config = make_config("127.0.0.1:3128", None);
        assert_eq!(config.pac_proxy_addr(), "127.0.0.1:3128");
    }

    #[test]
    fn pac_proxy_addr_wildcard_bind_uses_hostname() {
        let config = make_config("0.0.0.0:3128", None);
        let addr = config.pac_proxy_addr();
        // Must include the port
        assert!(addr.ends_with(":3128"), "expected port 3128 in '{}'", addr);
        // Must not be the raw wildcard bind address
        assert!(!addr.starts_with("0.0.0.0"));
    }

    #[test]
    fn validate_valid_domain_with_hyphen() {
        assert!(validate_domain_rule("my-host.example.com").is_ok());
        assert!(validate_domain_rule("a1-b2.example.com").is_ok());
    }

    #[test]
    fn validate_leading_hyphen_in_label_rejected() {
        assert!(validate_domain_rule("-example.com").is_err());
        assert!(validate_domain_rule("sub.-example.com").is_err());
    }

    #[test]
    fn validate_trailing_hyphen_in_label_rejected() {
        assert!(validate_domain_rule("example-.com").is_err());
        assert!(validate_domain_rule("sub.example-.com").is_err());
    }

    #[test]
    fn validate_wildcard_with_valid_subdomain() {
        assert!(validate_domain_rule("*.my-host.example.com").is_ok());
    }

    #[test]
    fn validate_single_label_domain_accepted() {
        // Single-label domains are technically valid for local use
        assert!(validate_domain_rule("localhost").is_ok());
        assert!(validate_domain_rule("intranet").is_ok());
    }

    #[test]
    fn config_load_missing_file_returns_error() {
        let result = Config::load("/nonexistent/path/to/config.toml");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Failed to read config file"));
    }

    #[test]
    fn config_load_invalid_toml_returns_error() {
        let path = "/tmp/gatekeeper_test_invalid_toml.toml";
        std::fs::write(path, "this is not valid toml !!@#$%%").unwrap();
        let result = Config::load(path);
        std::fs::remove_file(path).ok();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Failed to parse config file"));
    }

    #[test]
    fn config_load_invalid_domain_rule_returns_error() {
        let path = "/tmp/gatekeeper_test_invalid_domain.toml";
        let content = r#"
[proxy]
bind = "127.0.0.1:3128"
[tls]
server_cert = "cert.pem"
server_key = "key.pem"
ca_cert = "ca.pem"
[allowlist]
domains = ["*"]
"#;
        std::fs::write(path, content).unwrap();
        let result = Config::load(path);
        std::fs::remove_file(path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn validate_domain_rule_single_wildcard_prefix_ok() {
        assert!(validate_domain_rule("*.example.com").is_ok());
    }

    #[test]
    fn validate_domain_rule_double_wildcard_rejected() {
        assert!(validate_domain_rule("*.*.example.com").is_err());
    }
}

// hostname crate shim — just use std
mod hostname {
    pub fn get() -> std::io::Result<std::ffi::OsString> {
        let mut buf = [0u8; 256];
        unsafe {
            if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                Ok(std::ffi::OsString::from(
                    std::str::from_utf8(&buf[..len]).unwrap_or("localhost"),
                ))
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }
}
