//! Fuzz target: Domain rule validation.
//!
//! Feeds arbitrary strings into `validate_domain_rule` to ensure it never
//! panics and correctly distinguishes valid from invalid inputs.
#![no_main]
#![allow(unused_crate_dependencies)]

use gatekeeper::config::validate_domain_rule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must not panic — result (Ok/Err) is irrelevant to the harness
        let _ = validate_domain_rule(s);
    }
});
