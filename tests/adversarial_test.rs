//! Adversarial tests for the gatekeeper allowlist, CONNECT parser, domain
//! validator, and PAC generator.
//!
//! These tests exercise inputs that historically break parsers or allow security
//! bypass: Unicode/homographs, embedded control characters, port overflows,
//! deeply-nested labels, IPv6 edge cases, and whitespace tricks.
#![allow(unused_crate_dependencies)]

use gatekeeper::allowlist::Allowlist;
use gatekeeper::config::validate_domain_rule;
use gatekeeper::connect_handler::parse_connect_authority;
use gatekeeper::pac::generate_pac;

// ── helpers ──────────────────────────────────────────────────────────────────

fn allowlist(domains: &[&str]) -> Allowlist {
    let v: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
    Allowlist::new(&v)
}

// ── Allowlist: construction safety ───────────────────────────────────────────

#[test]
fn adv_allowlist_empty_string_rule_does_not_panic() {
    let al = allowlist(&[""]);
    // Empty rule should not crash; it simply won't match real hosts.
    assert!(!al.is_allowed("example.com"));
}

#[test]
fn adv_allowlist_whitespace_only_rule() {
    // The allowlist stores rules verbatim (lowercased) without sanitisation.
    // A whitespace-only rule is accepted as-is and will match the identical
    // whitespace string — this documents the current behaviour.
    let al = allowlist(&["   ", "\t", "\n"]);
    // Whitespace rules match their exact whitespace query (exact-match logic).
    assert!(al.is_allowed("   "));
    // Real hostnames are still unaffected.
    assert!(!al.is_allowed("example.com"));
}

#[test]
fn adv_allowlist_control_chars_in_rule() {
    // Rules with null bytes or control characters must not panic.
    let al = allowlist(&["\x00example.com", "exa\x01mple.com", "example.com\x00"]);
    assert!(!al.is_allowed("example.com"));
}

#[test]
fn adv_allowlist_null_byte_in_host() {
    let al = allowlist(&["example.com"]);
    // A host containing a null byte must not match the clean rule.
    assert!(!al.is_allowed("example.com\x00"));
    assert!(!al.is_allowed("\x00example.com"));
}

#[test]
fn adv_allowlist_unicode_homograph_not_matched() {
    // "example.com" with Cyrillic 'е' (U+0435) vs ASCII 'e' (U+0065)
    let al = allowlist(&["example.com"]);
    assert!(!al.is_allowed("еxample.com")); // Cyrillic е
    assert!(!al.is_allowed("ехаmple.com")); // mix of Cyrillic/Latin
}

#[test]
fn adv_allowlist_punycode_vs_unicode_not_conflated() {
    // The allowlist stores rules as-is (lowercased). A punycode rule should
    // not match its raw Unicode equivalent and vice-versa.
    let al = allowlist(&["xn--nxasmq6b.com"]); // punycode
    assert!(!al.is_allowed("münchen.com")); // Unicode
}

#[test]
fn adv_allowlist_very_long_domain() {
    // 253-char hostname (DNS max) must not panic.
    let long_label = "a".repeat(63);
    let domain = format!("{0}.{0}.{0}.com", long_label);
    let al = allowlist(&[&domain]);
    assert!(al.is_allowed(&domain));

    // Exceeding DNS limits still must not panic.
    let too_long = "a".repeat(300);
    let _ = al.is_allowed(&too_long);
}

#[test]
fn adv_allowlist_many_duplicate_rules_dedup() {
    let rules: Vec<&str> = std::iter::repeat_n("github.com", 10_000).collect();
    let al = allowlist(&rules);
    assert_eq!(al.len(), 1);
    assert!(al.is_allowed("github.com"));
}

#[test]
fn adv_allowlist_wildcard_only_suffix_does_not_match_apex() {
    // "*." + TLD only — "*.com" must not match "com" itself.
    let al = allowlist(&["*.com"]);
    assert!(!al.is_allowed("com"));
    assert!(!al.is_allowed("com:443"));
    assert!(al.is_allowed("example.com"));
}

#[test]
fn adv_allowlist_ipv6_host_not_matched_by_domain_rule() {
    // Note: validate_domain_rule() rejects IP addresses, so "::1" can never
    // appear in a production allowlist. This test verifies that strip_port
    // correctly handles bracketed IPv6 literals: [::1] → ::1, [::1]:443 → ::1.
    let al = allowlist(&["::1", "example.com"]);
    // With correct bracket stripping, the bare "::1" rule does match.
    assert!(al.is_allowed("[::1]"));
    assert!(al.is_allowed("[::1]:443"));
    // Ensure that IPv6 literals don't match unrelated domain rules.
    assert!(!al.is_allowed("[2001:db8::1]"));
}

#[test]
fn adv_allowlist_port_variations() {
    let al = allowlist(&["example.com"]);
    assert!(al.is_allowed("example.com:80"));
    assert!(al.is_allowed("example.com:443"));
    assert!(al.is_allowed("example.com:65535"));
    assert!(al.is_allowed("example.com:0"));
    // strip_port strips everything after the last ':', without validating the
    // port number.  "example.com:99999" → "example.com" which IS in the
    // allowlist, so is_allowed returns true.  This documents the behaviour.
    assert!(al.is_allowed("example.com:99999"));
    // Non-numeric ports: strip_port still strips the suffix leaving "example.com".
    assert!(al.is_allowed("example.com:abc"));
    assert!(!al.is_allowed("example.com::443"));
}

#[test]
fn adv_allowlist_trailing_dot_not_matched() {
    // "example.com." (trailing dot, FQDN form) should not match "example.com".
    let al = allowlist(&["example.com"]);
    assert!(!al.is_allowed("example.com."));
}

#[test]
fn adv_allowlist_subdomain_does_not_match_exact_rule() {
    let al = allowlist(&["example.com"]);
    assert!(!al.is_allowed("sub.example.com"));
    assert!(!al.is_allowed("example.com.evil.org"));
}

#[test]
fn adv_allowlist_wildcard_does_not_match_sibling_tld() {
    let al = allowlist(&["*.example.com"]);
    assert!(!al.is_allowed("example.com.au"));
    assert!(!al.is_allowed("notexample.com"));
    assert!(!al.is_allowed("xexample.com")); // suffix match without dot boundary
}

#[test]
fn adv_allowlist_newline_in_host_does_not_match() {
    let al = allowlist(&["example.com"]);
    assert!(!al.is_allowed("example.com\nexample.com"));
    assert!(!al.is_allowed("example.com\r\n"));
}

#[test]
fn adv_allowlist_is_allowed_matched_rule_consistency() {
    // Property: is_allowed(h) == matched_rule(h).is_some() for all h.
    let domains = &["github.com", "*.crates.io", "registry.npmjs.org"];
    let al = allowlist(domains);

    let hosts = &[
        "github.com",
        "www.github.com",
        "sub.crates.io",
        "crates.io",
        "registry.npmjs.org",
        "evil.com",
        "",
        ".",
        "*.crates.io",
        "[::1]:443",
        "github.com:443",
    ];
    for h in hosts {
        assert_eq!(
            al.is_allowed(h),
            al.matched_rule(h).is_some(),
            "is_allowed / matched_rule disagree for {:?}",
            h
        );
    }
}

#[test]
fn adv_allowlist_unbracketed_ipv6() {
    // Ensure that unbracketed IPv6 literals don't get mangled by strip_port
    // (currently they do, returning "::" for "::1").
    let al = allowlist(&["::1"]);
    // This is currently expected to FAIL if strip_port isn't fixed
    assert!(al.is_allowed("::1"));
}

// ── CONNECT authority parser ──────────────────────────────────────────────────

#[test]
fn adv_connect_empty_string() {
    assert!(parse_connect_authority("").is_none());
}

#[test]
fn adv_connect_no_port() {
    assert!(parse_connect_authority("example.com").is_none());
}

#[test]
fn adv_connect_colon_only() {
    assert!(parse_connect_authority(":").is_none());
}

#[test]
fn adv_connect_empty_host_rejected() {
    // ":443" has no host — must be rejected to prevent bypass attempts
    assert!(parse_connect_authority(":443").is_none());
    assert!(parse_connect_authority(":80").is_none());
}

#[test]
fn adv_connect_port_overflow() {
    // 65536 exceeds u16::MAX
    assert!(parse_connect_authority("example.com:65536").is_none());
    assert!(parse_connect_authority("example.com:99999").is_none());
    assert!(parse_connect_authority("example.com:4294967295").is_none());
}

#[test]
fn adv_connect_port_zero_is_valid_u16() {
    // Port 0 is representable as u16; the parser should return it.
    let result = parse_connect_authority("example.com:0");
    assert!(result.is_some());
    let (host, port) = result.unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 0);
}

#[test]
fn adv_connect_port_max_valid() {
    let result = parse_connect_authority("example.com:65535");
    assert!(result.is_some());
    let (_, port) = result.unwrap();
    assert_eq!(port, 65535);
}

#[test]
fn adv_connect_non_numeric_port() {
    assert!(parse_connect_authority("example.com:abc").is_none());
    assert!(parse_connect_authority("example.com:80abc").is_none());
    assert!(parse_connect_authority("example.com:").is_none());
}

#[test]
fn adv_connect_ipv6_valid() {
    let r = parse_connect_authority("[::1]:443");
    assert!(r.is_some());
    let (host, port) = r.unwrap();
    assert_eq!(host, "::1");
    assert_eq!(port, 443);
}

#[test]
fn adv_connect_ipv6_full_address() {
    let r = parse_connect_authority("[2001:db8::1]:8080");
    assert!(r.is_some());
    let (host, port) = r.unwrap();
    assert_eq!(host, "2001:db8::1");
    assert_eq!(port, 8080);
}

#[test]
fn adv_connect_ipv6_missing_close_bracket() {
    // "[::1:443" — no closing bracket → None
    assert!(parse_connect_authority("[::1:443").is_none());
}

#[test]
fn adv_connect_ipv6_missing_port() {
    // "[::1]" with no ":port" after bracket
    assert!(parse_connect_authority("[::1]").is_none());
}

#[test]
fn adv_connect_ipv6_empty_brackets() {
    assert!(parse_connect_authority("[]:443").is_none());
}

#[test]
fn adv_connect_very_long_host() {
    let host = "a".repeat(10_000);
    let authority = format!("{}:443", host);
    // Must not panic; may return Some or None.
    let _ = parse_connect_authority(&authority);
}

#[test]
fn adv_connect_unicode_in_authority() {
    // Unicode hosts must not panic.
    let _ = parse_connect_authority("münchen.de:443");
    let _ = parse_connect_authority("еxample.com:443");
}

#[test]
fn adv_connect_control_chars() {
    assert!(
        parse_connect_authority("exa\x00mple.com:443").is_none()
            || parse_connect_authority("exa\x00mple.com:443").is_some()
    ); // must not panic
    let _ = parse_connect_authority("\x00:443");
    let _ = parse_connect_authority("example.com:\x00");
}

#[test]
fn adv_connect_newline_in_authority() {
    // HTTP request-line injection attempt.
    let _ = parse_connect_authority("example.com:443\r\nX-Injected: true");
    let _ = parse_connect_authority("example.com:443\nGET / HTTP/1.1");
}

#[test]
fn adv_connect_multiple_at_signs() {
    // "user@host:port" style — only the last colon determines host/port split.
    let r = parse_connect_authority("user@example.com:443");
    assert!(r.is_some());
    let (host, port) = r.unwrap();
    assert_eq!(host, "user@example.com");
    assert_eq!(port, 443);
}

#[test]
fn adv_connect_userinfo_with_colon() {
    // "user:pass@host:port" — should still extract the correct port
    let r = parse_connect_authority("user:pass@example.com:443");
    assert!(r.is_some());
    let (host, port) = r.unwrap();
    assert_eq!(host, "user:pass@example.com");
    assert_eq!(port, 443);
}

#[test]
fn adv_security_ipv4_compatible_ipv6() {
    // ::127.0.0.1 is an IPv4-compatible IPv6 address.
    // While deprecated, some stacks might still resolve it as loopback.
    let ip: std::net::IpAddr = "::127.0.0.1".parse().unwrap();
    assert!(gatekeeper::security::is_private_ip(ip));
}

// ── Domain rule validation ────────────────────────────────────────────────────

#[test]
fn adv_validate_empty_string_is_error() {
    assert!(validate_domain_rule("").is_err());
}

#[test]
fn adv_validate_bare_wildcard_rejected() {
    assert!(validate_domain_rule("*").is_err());
}

#[test]
fn adv_validate_double_wildcard_rejected() {
    assert!(validate_domain_rule("*.*.com").is_err());
}

#[test]
fn adv_validate_trailing_wildcard_rejected() {
    assert!(validate_domain_rule("example.*").is_err());
}

#[test]
fn adv_validate_internal_wildcard_rejected() {
    assert!(validate_domain_rule("foo.*.com").is_err());
    assert!(validate_domain_rule("foo*.com").is_err());
}

#[test]
fn adv_validate_ip_v4_rejected() {
    assert!(validate_domain_rule("192.168.1.1").is_err());
    assert!(validate_domain_rule("10.0.0.1").is_err());
    assert!(validate_domain_rule("0.0.0.0").is_err());
    assert!(validate_domain_rule("255.255.255.255").is_err());
}

#[test]
fn adv_validate_ip_v6_rejected() {
    assert!(validate_domain_rule("::1").is_err());
    assert!(validate_domain_rule("2001:db8::1").is_err());
    assert!(validate_domain_rule("[::1]").is_err());
}

#[test]
fn adv_validate_empty_label_rejected() {
    assert!(validate_domain_rule("example..com").is_err());
    assert!(validate_domain_rule(".example.com").is_err());
    assert!(validate_domain_rule("example.com.").is_err());
    assert!(validate_domain_rule("*.example..com").is_err());
}

#[test]
fn adv_validate_wildcard_with_empty_rest_rejected() {
    assert!(validate_domain_rule("*.").is_err());
}

#[test]
fn adv_validate_valid_rules_accepted() {
    assert!(validate_domain_rule("example.com").is_ok());
    assert!(validate_domain_rule("*.example.com").is_ok());
    assert!(validate_domain_rule("sub.example.com").is_ok());
    assert!(validate_domain_rule("a.b.c.d.e.f").is_ok());
    assert!(validate_domain_rule("xn--nxasmq6b.com").is_ok()); // punycode
}

#[test]
fn adv_validate_control_chars_in_domain() {
    // Domains with control characters must either be rejected or not panic.
    let _ = validate_domain_rule("\x00example.com");
    let _ = validate_domain_rule("example\x01.com");
    let _ = validate_domain_rule("example.com\n");
}

#[test]
fn adv_validate_very_long_domain_does_not_panic() {
    let label = "a".repeat(1000);
    let _ = validate_domain_rule(&label);
    let long_chain: String = (0..100).map(|_| "abc").collect::<Vec<_>>().join(".");
    let _ = validate_domain_rule(&long_chain);
}

#[test]
fn adv_validate_unicode_labels_do_not_panic() {
    let _ = validate_domain_rule("münchen.de");
    let _ = validate_domain_rule("例え.jp");
    let _ = validate_domain_rule("*.例え.jp");
}

#[test]
fn adv_validate_punycode_mixed_case() {
    // Punycode rules are case-insensitive by normalization.
    let al = allowlist(&["xn--NXASMQ6B.com"]);
    assert!(al.is_allowed("xn--nxasmq6b.com"));
    assert!(al.is_allowed("XN--NXASMQ6B.COM"));
}

// ── PAC generation ────────────────────────────────────────────────────────────

#[test]
fn adv_pac_empty_allowlist() {
    let al = allowlist(&[]);
    let pac = generate_pac(&al, "proxy.internal:3128");
    assert!(pac.starts_with("function FindProxyForURL"));
    assert!(pac.contains("return \"PROXY 0.0.0.0:0\";"));
}

#[test]
fn adv_pac_proxy_addr_with_quotes_does_not_break_structure() {
    // A proxy_addr containing `"` would break JS string literals — document
    // the current behaviour (no panic) and assert structural invariants hold.
    let al = allowlist(&["example.com"]);
    let pac = generate_pac(&al, "proxy\"evil:3128");
    // Must not panic; output must still contain the function wrapper.
    assert!(pac.starts_with("function FindProxyForURL"));
    assert!(pac.ends_with('}'));
}

#[test]
fn adv_pac_domain_with_quotes_does_not_break_structure() {
    // Domain with embedded `"` must not crash the generator.
    let al = allowlist(&["exa\"mple.com"]);
    let pac = generate_pac(&al, "proxy.internal:3128");
    assert!(pac.starts_with("function FindProxyForURL"));
    assert!(pac.ends_with('}'));
}

#[test]
fn adv_pac_very_large_allowlist() {
    let domains: Vec<String> = (0..10_000)
        .map(|i| format!("host{}.example.com", i))
        .collect();
    let al = Allowlist::new(&domains);
    let pac = generate_pac(&al, "proxy.internal:3128");
    assert!(pac.starts_with("function FindProxyForURL"));
    assert!(pac.contains("return \"PROXY 0.0.0.0:0\";"));
}

#[test]
fn adv_pac_brace_balance() {
    let al = allowlist(&["github.com", "*.crates.io", "registry.npmjs.org"]);
    let pac = generate_pac(&al, "proxy.internal:3128");
    let opens = pac.chars().filter(|&c| c == '{').count();
    let closes = pac.chars().filter(|&c| c == '}').count();
    assert_eq!(opens, closes);
}

#[test]
fn adv_pac_wildcard_uses_dns_domain_is() {
    let al = allowlist(&["*.crates.io"]);
    let pac = generate_pac(&al, "proxy.internal:3128");
    assert!(
        pac.contains("dnsDomainIs"),
        "wildcard rules must use dnsDomainIs"
    );
    assert!(
        !pac.contains("host === \".crates.io\""),
        "wildcard should not use exact match"
    );
}

#[test]
fn adv_pac_wildcard_apex_discrepancy() {
    // Current gatekeeper behavior: *.example.com does NOT match example.com.
    // PAC behavior: dnsDomainIs(host, ".example.com") DOES match example.com in
    // many browser implementations. This test documents the current state.
    let al = allowlist(&["*.example.com"]);
    assert!(!al.is_allowed("example.com"));
    let pac = generate_pac(&al, "proxy.internal:3128");
    // PAC script will use .example.com as the suffix
    assert!(pac.contains("\".example.com\""));
}

#[test]
fn adv_pac_exact_rule_uses_equality() {
    let al = allowlist(&["github.com"]);
    let pac = generate_pac(&al, "proxy.internal:3128");
    assert!(pac.contains("host === \"github.com\""));
    assert!(!pac.contains("dnsDomainIs(host, \"github.com\")"));
}
