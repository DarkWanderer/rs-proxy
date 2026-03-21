use crate::allowlist::{Allowlist, DomainRule};
use crate::security::escape_js;

pub fn generate_pac(allowlist: &Allowlist, proxy_addr: &str) -> String {
    let escaped_proxy = escape_js(proxy_addr);
    let mut lines = vec![
        "function FindProxyForURL(url, host) {".to_string(),
        "    host = host.toLowerCase();".to_string(),
    ];

    for rule in allowlist.rules() {
        match rule {
            DomainRule::Exact(domain) => {
                lines.push(format!(
                    "    if (host === \"{}\") return \"PROXY {}\";",
                    escape_js(domain),
                    escaped_proxy
                ));
            }
            DomainRule::Wildcard(suffix) => {
                // suffix is ".crates.io", PAC uses dnsDomainIs with the suffix
                lines.push(format!(
                    "    if (dnsDomainIs(host, \"{}\")) return \"PROXY {}\";",
                    escape_js(suffix),
                    escaped_proxy
                ));
            }
        }
    }

    lines.push("    return \"PROXY 0.0.0.0:0\";".to_string());
    lines.push("}".to_string());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_contains_exact_and_wildcard() {
        let domains: Vec<String> = vec!["github.com".to_string(), "*.crates.io".to_string()];
        let al = Allowlist::new(&domains);
        let pac = generate_pac(&al, "proxy.internal:3128");
        assert!(pac.contains("host === \"github.com\""));
        assert!(pac.contains("dnsDomainIs(host, \".crates.io\")"));
        assert!(pac.contains("PROXY proxy.internal:3128"));
        assert!(pac.contains("PROXY 0.0.0.0:0"));
    }

    #[test]
    fn pac_function_header_present() {
        let al = Allowlist::new(&[]);
        let pac = generate_pac(&al, "proxy:3128");
        assert!(pac.starts_with("function FindProxyForURL(url, host) {"));
    }

    #[test]
    fn pac_lowercases_host() {
        let al = Allowlist::new(&[]);
        let pac = generate_pac(&al, "proxy:3128");
        assert!(pac.contains("host = host.toLowerCase();"));
    }

    #[test]
    fn pac_deny_all_default_present() {
        let al = Allowlist::new(&[]);
        let pac = generate_pac(&al, "proxy:3128");
        assert!(pac.contains("return \"PROXY 0.0.0.0:0\";"));
    }

    #[test]
    fn pac_ends_with_closing_brace() {
        let domains: Vec<String> = vec!["github.com".to_string()];
        let al = Allowlist::new(&domains);
        let pac = generate_pac(&al, "proxy:3128");
        assert!(pac.trim_end().ends_with('}'));
    }

    #[test]
    fn pac_empty_allowlist_only_deny() {
        let al = Allowlist::new(&[]);
        let pac = generate_pac(&al, "proxy:3128");
        // No PROXY entry for a real host, only the deny-all fallback
        assert!(!pac.contains("host ==="));
        assert!(!pac.contains("dnsDomainIs"));
    }

    #[test]
    fn pac_special_chars_in_proxy_addr_escaped() {
        // Use a real domain so the proxy_addr appears in the generated PROXY line
        let domains: Vec<String> = vec!["example.com".to_string()];
        let al = Allowlist::new(&domains);
        let pac = generate_pac(&al, "proxy\"evil:3128");
        // escape_js turns " into \" so the PAC output contains the literal two-char
        // sequence backslash + double-quote, not a raw unescaped double-quote.
        assert!(pac.contains("\\\""));
    }
}
