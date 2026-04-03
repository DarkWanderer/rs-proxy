//! Fuzz target: JavaScript string escaping.
//!
//! Feeds arbitrary strings into `escape_js`, verifying:
//! - No panics on any input
//! - Output never contains unescaped double-quotes (which would break JS string literals)
//! - Output length is always >= input length (escaping only adds characters)
#![no_main]

use gatekeeper::security::escape_js;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let output = escape_js(input);

    // Output must be at least as long as the input (escaping only expands)
    assert!(
        output.len() >= input.len(),
        "escape_js output shorter than input: {:?} -> {:?}",
        input,
        output
    );

    // Scan for unescaped double-quotes — these would break JS string literals.
    // A double-quote in the output is only valid if preceded by a backslash.
    let bytes = output.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            // Skip the next byte (it is the escaped character)
            i += 2;
        } else {
            assert_ne!(
                bytes[i], b'"',
                "Unescaped double-quote in escape_js output for input {:?}",
                input
            );
            i += 1;
        }
    }
});
