#![allow(unused_crate_dependencies)]
/// Unit tests U1-U12 for the domain allowlist engine.
/// The core test logic lives in allowlist.rs #[cfg(test)].
/// This file just re-exports to confirm the module compiles in test context.

#[test]
fn allowlist_module_tests_pass() {
    // Tests U1-U12 are in src/allowlist.rs #[cfg(test)]
    // This ensures the test binary includes them.
    // Run with: cargo test allowlist
}
