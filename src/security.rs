use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Escape a string for safe interpolation in a JavaScript string literal.
pub fn escape_js(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<' => out.push_str("\\x3c"), // prevent </script> injection
            '>' => out.push_str("\\x3e"),
            c if c.is_control() => {
                for unit in c.encode_utf16(&mut [0u16; 2]) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Returns `true` if the given IP address is in a private, loopback,
/// link-local, or otherwise non-globally-routable range.
pub fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254/16
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_unspecified()  // 0.0.0.0
        || ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64  // 100.64/10 (CGNAT)
        || ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0  // 192.0.0/24
        || ip.octets()[0] == 198 && (ip.octets()[1] & 0xFE) == 18 // 198.18/15 (benchmarking)
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()            // ::1
        || ip.is_unspecified()  // ::
        || is_ipv6_ula(&ip)     // fc00::/7 (unique local)
        || is_ipv6_link_local(&ip) // fe80::/10
        // Check if it's an IPv4-mapped IPv6 (::ffff:x.x.x.x)
        || match ip.to_ipv4_mapped() {
            Some(v4) => is_private_ipv4(v4),
            None => false,
        }
}

fn is_ipv6_ula(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFE00) == 0xFC00
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFFC0) == 0xFE80
}

/// Allowed ports for CONNECT tunnels.
const ALLOWED_CONNECT_PORTS: &[u16] = &[443, 8443];

/// Check if a port is allowed for CONNECT tunneling.
pub fn is_allowed_connect_port(port: u16) -> bool {
    ALLOWED_CONNECT_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_escape_script_tag() {
        assert_eq!(escape_js("</script>"), "\\x3c/script\\x3e");
    }

    #[test]
    fn private_ipv4_loopback() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_rfc1918() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_link_local() {
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_cgnat() {
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv4() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_loopback() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_ula() {
        assert!(is_private_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_mapped_v4() {
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv6() {
        assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn allowed_connect_ports() {
        assert!(is_allowed_connect_port(443));
        assert!(is_allowed_connect_port(8443));
        assert!(!is_allowed_connect_port(22));
        assert!(!is_allowed_connect_port(25));
        assert!(!is_allowed_connect_port(80));
    }
}
