//! Fuzz target: CONNECT authority parsing.
//!
//! Feeds arbitrary byte sequences (as strings and raw bytes) into
//! `parse_connect_authority`, verifying no panics occur and that any
//! returned port fits in u16.
#![no_main]
#![allow(unused_crate_dependencies)]

use gatekeeper::connect_handler::parse_connect_authority;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test with arbitrary UTF-8 strings
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some((host, port)) = parse_connect_authority(s) {
            // Port is u16 by type, but host must be non-empty for a valid result
            assert!(!host.is_empty(), "parsed host should not be empty");
            let _ = port; // u16 is always in range
        }
    }

    // Also try common adversarial patterns derived from the raw bytes
    let patterns: &[&str] = &[
        // Port overflow
        "example.com:65536",
        "example.com:99999",
        "example.com:0",
        // IPv6 edge cases
        "[::1]:443",
        "[::]:0",
        "[2001:db8::1]:8080",
        "[]:",
        "[]:443",
        "[::]:",
        // Missing port
        "example.com:",
        "example.com",
        ":443",
        // Empty
        "",
        ":",
        "::",
        // Multiple colons
        "a:b:c",
        "a:b:443",
        // Very long host
        &"a".repeat(1000),
    ];

    for p in patterns {
        let _ = parse_connect_authority(p);
    }
});
