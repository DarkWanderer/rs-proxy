use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum DomainRule {
    Exact(String),
    Wildcard(String), // stores the suffix, e.g. ".crates.io" for "*.crates.io"
}

#[derive(Debug, Clone)]
pub struct Allowlist {
    rules: Vec<DomainRule>,
}

impl Allowlist {
    pub fn new(domains: &[String]) -> Self {
        let mut seen = HashSet::new();
        let mut rules = Vec::new();

        for domain in domains {
            let normalized = domain.to_lowercase();
            if seen.insert(normalized.clone()) {
                if let Some(rest) = normalized.strip_prefix("*.") {
                    rules.push(DomainRule::Wildcard(format!(".{}", rest)));
                } else {
                    rules.push(DomainRule::Exact(normalized));
                }
            }
        }

        Allowlist { rules }
    }

    /// Check if a host (possibly with port) is allowed.
    pub fn is_allowed(&self, host: &str) -> bool {
        self.matched_rule(host).is_some()
    }

    /// Returns the matching rule string for logging
    pub fn matched_rule(&self, host: &str) -> Option<String> {
        let host = strip_port(host);
        for rule in &self.rules {
            match rule {
                DomainRule::Exact(exact) => {
                    if host.eq_ignore_ascii_case(exact) {
                        return Some(exact.clone());
                    }
                }
                DomainRule::Wildcard(suffix) => {
                    if host.len() > suffix.len()
                        && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
                    {
                        return Some(format!("*{}", suffix));
                    }
                }
            }
        }
        None
    }

    pub fn rules(&self) -> &[DomainRule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn strip_port(host: &str) -> &str {
    // Handle IPv6 [::1]:port → extract content between brackets
    if host.starts_with('[') {
        if let Some(close) = host.find(']') {
            return &host[1..close];
        }
        return host;
    }
    if let Some(pos) = host.rfind(':') {
        &host[..pos]
    } else {
        host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist(domains: &[&str]) -> Allowlist {
        let domains: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        Allowlist::new(&domains)
    }

    #[test]
    fn u1_exact_domain_match() {
        let al = allowlist(&["github.com"]);
        assert!(al.is_allowed("github.com"));
    }

    #[test]
    fn u2_exact_domain_no_subdomain_leak() {
        let al = allowlist(&["github.com"]);
        assert!(!al.is_allowed("www.github.com"));
    }

    #[test]
    fn u3_wildcard_single_subdomain() {
        let al = allowlist(&["*.crates.io"]);
        assert!(al.is_allowed("www.crates.io"));
    }

    #[test]
    fn u4_wildcard_nested_subdomain() {
        let al = allowlist(&["*.crates.io"]);
        assert!(al.is_allowed("a.b.crates.io"));
    }

    #[test]
    fn u5_wildcard_does_not_match_apex() {
        let al = allowlist(&["*.crates.io"]);
        assert!(!al.is_allowed("crates.io"));
    }

    #[test]
    fn u6_case_insensitivity() {
        let al = allowlist(&["github.com"]);
        assert!(al.is_allowed("GitHub.COM"));
    }

    #[test]
    fn u7_port_stripping() {
        let al = allowlist(&["github.com"]);
        assert!(al.is_allowed("github.com:8443"));
    }

    #[test]
    fn u8_invalid_wildcard_rejected() {
        let result = crate::config::validate_domain_rule("foo.*.com");
        assert!(result.is_err());
    }

    #[test]
    fn u9_bare_wildcard_rejected() {
        let result = crate::config::validate_domain_rule("*");
        assert!(result.is_err());
    }

    #[test]
    fn u10_empty_allowlist() {
        let al = allowlist(&[]);
        assert!(!al.is_allowed("anything.com"));
    }

    #[test]
    fn u11_ip_address_in_allowlist_rejected() {
        let result = crate::config::validate_domain_rule("192.168.1.1");
        assert!(result.is_err());
    }

    #[test]
    fn u12_duplicate_rule_dedup() {
        let al = allowlist(&["github.com", "github.com"]);
        assert_eq!(al.len(), 1);
    }

    #[test]
    fn u13_matched_rule_exact_returns_domain() {
        let al = allowlist(&["github.com"]);
        assert_eq!(
            al.matched_rule("github.com"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn u14_matched_rule_wildcard_returns_pattern() {
        let al = allowlist(&["*.crates.io"]);
        assert_eq!(
            al.matched_rule("www.crates.io"),
            Some("*.crates.io".to_string())
        );
    }

    #[test]
    fn u15_matched_rule_no_match_returns_none() {
        let al = allowlist(&["github.com"]);
        assert_eq!(al.matched_rule("evil.com"), None);
        assert_eq!(al.matched_rule("www.github.com"), None);
    }

    #[test]
    fn u16_is_empty_and_len() {
        let empty = allowlist(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let one = allowlist(&["github.com"]);
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);

        let two = allowlist(&["github.com", "*.crates.io"]);
        assert_eq!(two.len(), 2);
    }

    #[test]
    fn u17_rules_accessor_returns_all_rules() {
        let al = allowlist(&["github.com", "*.crates.io"]);
        assert_eq!(al.rules().len(), 2);
    }

    #[test]
    fn u18_matched_rule_with_port_strips_port() {
        let al = allowlist(&["github.com"]);
        assert_eq!(
            al.matched_rule("github.com:443"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn u19_matched_rule_wildcard_apex_returns_none() {
        let al = allowlist(&["*.crates.io"]);
        // Apex domain must not match the wildcard rule
        assert_eq!(al.matched_rule("crates.io"), None);
    }

    #[test]
    fn u20_wildcard_case_insensitive() {
        let al = allowlist(&["*.crates.io"]);
        assert_eq!(
            al.matched_rule("WWW.CRATES.IO"),
            Some("*.crates.io".to_string())
        );
    }
}
