// clap is only used by the binary (src/main.rs) but lives in [dependencies]
// because Cargo does not support binary-only dependencies in a single-crate project.
#![allow(unused_crate_dependencies)]

pub mod allowlist;
pub mod config;
pub mod connect_handler;
pub mod http_handler;
pub mod logging;
pub mod pac;
pub mod proxy;
pub mod tls;
