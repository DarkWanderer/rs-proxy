# Gatekeeper — development guidelines for Claude

* This project does not have external dependants. If any function becomes unused, it can be safely deleted

## After every change

Run **both** of the following before committing:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
```

`cargo fmt` must produce no diff and `cargo clippy` must emit zero errors or
warnings.  The CI pipeline enforces this, so fixes must happen locally first.

## Running tests

```bash
cargo test
```

All tests must pass.  The test suite includes unit tests, integration tests
(full proxy stack), and adversarial edge-case tests (`tests/adversarial_test.rs`).

## Fuzzing

The `fuzz/` directory is a separate cargo workspace targeting four entry points:

| Target            | Entry point                              |
|-------------------|------------------------------------------|
| `allowlist`       | `Allowlist::new` + `is_allowed`          |
| `connect_authority` | `parse_connect_authority`              |
| `domain_validation` | `validate_domain_rule`                 |
| `pac_generation`  | `generate_pac`                           |

Run a fuzz target (requires nightly + `cargo install cargo-fuzz`):

```bash
cargo +nightly fuzz run allowlist
```

Add newly discovered crash inputs as regression tests in
`tests/adversarial_test.rs`.
