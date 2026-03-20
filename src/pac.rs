use crate::allowlist::{Allowlist, DomainRule};

pub fn generate_pac(allowlist: &Allowlist, proxy_addr: &str) -> String {
    let mut lines = vec![
        "function FindProxyForURL(url, host) {".to_string(),
        "    host = host.toLowerCase();".to_string(),
    ];

    for rule in allowlist.rules() {
        match rule {
            DomainRule::Exact(domain) => {
                lines.push(format!(
                    "    if (host === \"{}\") return \"PROXY {}\";",
                    domain, proxy_addr
                ));
            }
            DomainRule::Wildcard(suffix) => {
                // suffix is ".crates.io", PAC uses dnsDomainIs with the suffix
                lines.push(format!(
                    "    if (dnsDomainIs(host, \"{}\")) return \"PROXY {}\";",
                    suffix, proxy_addr
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
}
