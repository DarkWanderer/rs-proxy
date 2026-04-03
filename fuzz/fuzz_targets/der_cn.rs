//! Fuzz target: DER certificate CN extraction.
//!
//! Feeds arbitrary byte slices into `extract_cn_from_der_bytes`, verifying:
//! - No panics on any input
//! - If a CN is returned, it is valid UTF-8 (always true since we return String)
#![no_main]

use gatekeeper::tls::extract_cn_from_der_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input, including truncated/malformed DER
    let _ = extract_cn_from_der_bytes(data);
});
