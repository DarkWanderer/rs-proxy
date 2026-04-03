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
        // Check if it's an IPv4-mapped or compatible IPv6 (::ffff:x.x.x.x or ::x.x.x.x)
        || match ip.to_ipv4() {
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
    fn private_ipv4_broadcast() {
        assert!(is_private_ip("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_unspecified() {
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_iana_special() {
        assert!(is_private_ip("192.0.0.1".parse().unwrap()));
        assert!(is_private_ip("192.0.0.255".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_benchmarking() {
        assert!(is_private_ip("198.18.0.1".parse().unwrap()));
        assert!(is_private_ip("198.19.255.255".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_cgnat_edges() {
        // Bottom and top of CGNAT range (100.64/10 = 100.64.0.0 – 100.127.255.255)
        assert!(is_private_ip("100.64.0.0".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));
        // Just outside: 100.128.0.0 is public
        assert!(!is_private_ip("100.128.0.0".parse().unwrap()));
    }

    #[test]
    fn private_ipv4_just_outside_rfc1918() {
        // 172.15.x is NOT private (172.16-172.31 is private)
        assert!(!is_private_ip("172.15.255.255".parse().unwrap()));
        // 172.32.x is NOT private
        assert!(!is_private_ip("172.32.0.0".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_unspecified() {
        assert!(is_private_ip("::".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_link_local() {
        assert!(is_private_ip("fe80::1".parse().unwrap()));
        // fe80::/10 covers fe80:: through febf::
        assert!(is_private_ip("febf::1".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_ula_fc_prefix() {
        // fc00::/7 covers fc00:: through fdff::, test fc prefix specifically
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fc80::1".parse().unwrap()));
    }

    #[test]
    fn private_ipv6_mapped_rfc1918() {
        // ::ffff:172.16.0.1 — mapped private IPv4
        assert!(is_private_ip("::ffff:172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ipv6_global_unicast() {
        assert!(!is_private_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!is_private_ip("2001:4860:4860::8844".parse().unwrap()));
    }

    #[test]
    fn js_escape_backslash() {
        assert_eq!(escape_js("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn js_escape_single_quote() {
        assert_eq!(escape_js("it's"), "it\\'s");
    }

    #[test]
    fn js_escape_double_quote() {
        assert_eq!(escape_js("say \"hi\""), "say \\\"hi\\\"");
    }

    #[test]
    fn js_escape_newlines() {
        assert_eq!(escape_js("line1\nline2\r"), "line1\\nline2\\r");
    }

    #[test]
    fn js_escape_control_char() {
        // ASCII BEL (0x07) is a control character → should become \u0007
        let result = escape_js("\x07");
        assert!(result.starts_with("\\u"));
    }

    #[test]
    fn js_escape_passthrough_normal() {
        assert_eq!(
            escape_js("hello-world.example.com:3128"),
            "hello-world.example.com:3128"
        );
    }

    #[test]
    fn js_escape_angle_brackets() {
        assert_eq!(escape_js("<>"), "\\x3c\\x3e");
    }

    #[test]
    fn js_escape_empty_string() {
        assert_eq!(escape_js(""), "");
    }
}
