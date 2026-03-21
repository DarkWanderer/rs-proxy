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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_host_and_port() {
        let r = parse_connect_authority("example.com:443").unwrap();
        assert_eq!(r.0, "example.com");
        assert_eq!(r.1, 443);
    }

    #[test]
    fn valid_ipv6_and_port() {
        let r = parse_connect_authority("[::1]:8443").unwrap();
        assert_eq!(r.0, "::1");
        assert_eq!(r.1, 8443);
    }

    #[test]
    fn valid_ipv6_full_address() {
        let r = parse_connect_authority("[2001:db8::1]:443").unwrap();
        assert_eq!(r.0, "2001:db8::1");
        assert_eq!(r.1, 443);
    }

    #[test]
    fn missing_port_returns_none() {
        assert!(parse_connect_authority("example.com").is_none());
    }

    #[test]
    fn empty_host_returns_none() {
        assert!(parse_connect_authority(":443").is_none());
        assert!(parse_connect_authority(":80").is_none());
    }

    #[test]
    fn port_overflow_returns_none() {
        assert!(parse_connect_authority("example.com:65536").is_none());
    }

    #[test]
    fn non_numeric_port_returns_none() {
        assert!(parse_connect_authority("example.com:abc").is_none());
        assert!(parse_connect_authority("example.com:").is_none());
    }

    #[test]
    fn ipv6_missing_close_bracket_returns_none() {
        assert!(parse_connect_authority("[::1:443").is_none());
    }

    #[test]
    fn ipv6_no_port_returns_none() {
        assert!(parse_connect_authority("[::1]").is_none());
    }

    #[test]
    fn ipv6_empty_brackets_returns_none() {
        assert!(parse_connect_authority("[]:443").is_none());
    }

    #[test]
    fn port_zero_is_valid() {
        let r = parse_connect_authority("example.com:0").unwrap();
        assert_eq!(r.0, "example.com");
        assert_eq!(r.1, 0);
    }

    #[test]
    fn port_max_valid() {
        let r = parse_connect_authority("example.com:65535").unwrap();
        assert_eq!(r.1, 65535);
    }

    #[test]
    fn empty_string_returns_none() {
        assert!(parse_connect_authority("").is_none());
    }

    #[test]
    fn subpath_in_host_parsed_into_host() {
        // rsplitn on ':' means "user@example.com:443" → host = "user@example.com"
        let r = parse_connect_authority("user@example.com:443").unwrap();
        assert_eq!(r.0, "user@example.com");
        assert_eq!(r.1, 443);
    }
}
