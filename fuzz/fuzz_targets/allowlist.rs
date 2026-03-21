//! Fuzz target: Allowlist construction and domain matching.
//!
//! Feeds arbitrary domain rule lists and host strings into the allowlist engine,
//! verifying:
//! - No panics on any input
//! - `is_allowed` and `matched_rule` are consistent (if `matched_rule` returns
//!   Some then `is_allowed` must return true, and vice-versa)
#![no_main]

use arbitrary::Arbitrary;
use gatekeeper::allowlist::Allowlist;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct AllowlistInput {
    /// Domain rules to build the allowlist from.
    rules: Vec<String>,
    /// Host strings to check against the allowlist.
    queries: Vec<String>,
}

fuzz_target!(|input: AllowlistInput| {
    let al = Allowlist::new(&input.rules);

    // Structural invariants
    assert_eq!(al.is_empty(), al.len() == 0);

    for host in &input.queries {
        let allowed = al.is_allowed(host);
        let matched = al.matched_rule(host);

        // Consistency: is_allowed ↔ matched_rule is Some
        assert_eq!(
            allowed,
            matched.is_some(),
            "is_allowed and matched_rule disagree for host {:?}",
            host
        );
    }
});
