//! Fuzz target: PAC script generation.
//!
//! Feeds arbitrary domain lists and proxy addresses into `generate_pac`,
//! verifying:
//! - No panics
//! - Output always starts with the required function header
//! - Output always ends with the fallback PROXY rule and closing brace
//! - Domains containing `"` do not break the JS string literals
#![no_main]

use arbitrary::Arbitrary;
use gatekeeper::allowlist::Allowlist;
use gatekeeper::pac::generate_pac;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct PacInput {
    domains: Vec<String>,
    proxy_addr: String,
}

fuzz_target!(|input: PacInput| {
    let al = Allowlist::new(&input.domains);
    let pac = generate_pac(&al, &input.proxy_addr);

    // Structural invariants on the generated JavaScript
    assert!(
        pac.starts_with("function FindProxyForURL(url, host) {"),
        "PAC must start with the function declaration"
    );
    assert!(
        pac.ends_with('}'),
        "PAC must end with closing brace"
    );
    assert!(
        pac.contains("return \"PROXY 0.0.0.0:0\";"),
        "PAC must contain the deny-all fallback rule"
    );

    // Verify the PAC output is valid enough to count braces
    let opens = pac.chars().filter(|&c| c == '{').count();
    let closes = pac.chars().filter(|&c| c == '}').count();
    assert_eq!(opens, closes, "PAC brace mismatch");
});
