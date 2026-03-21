/// Parse host and port from CONNECT target (e.g. "example.com:443")
pub fn parse_connect_authority(authority: &str) -> Option<(String, u16)> {
    // Handle IPv6: [::1]:443
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = authority[1..close].to_string();
        if host.is_empty() {
            return None;
        }
        let port_str = authority.get(close + 2..)?;
        let port: u16 = port_str.parse().ok()?;
        return Some((host, port));
    }
    let mut parts = authority.rsplitn(2, ':');
    let port: u16 = parts.next()?.parse().ok()?;
    let host = parts.next()?.to_string();
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}
