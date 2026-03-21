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
pub mod security;
pub mod tls;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub fn full_body(s: &str) -> BoxBody {
    Full::new(Bytes::from(s.to_string()))
        .map_err(|never| match never {})
        .boxed()
}

pub fn json_response(status: StatusCode, body: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full_body(body))
        .unwrap()
}
