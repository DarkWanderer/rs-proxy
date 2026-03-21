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
    // Try IPv4
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // Try IPv6 (possibly with brackets)
    let s = s.trim_start_matches('[').trim_end_matches(']');
    if s.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    false
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
