# Gatekeeper

An opinionated forward proxy with mTLS client authentication and domain-allowlist enforcement, written in Rust.

Clients must present a valid TLS certificate signed by a trusted CA. Every outbound request is checked against a configured domain allowlist — anything not on the list is rejected. A PAC (Proxy Auto-Config) file is served over plaintext HTTP so browsers and tools can be pointed at the proxy automatically.

## Features

- **mTLS authentication** — all clients must present a certificate signed by your CA
- **Domain allowlist** — exact matches (`github.com`) and subdomain wildcards (`*.crates.io`)
- **CONNECT tunneling** — transparent HTTPS passthrough for allowed destinations
- **HTTP forward proxy** — plain HTTP requests are also filtered and forwarded
- **PAC file endpoint** — served at `http://<proxy>/proxy.pac` for easy client configuration
- **Hot reload** — send `SIGHUP` to reload config without dropping connections
- **Structured logging** — JSON or pretty format, configurable log level
- **Connection limiting** — configurable semaphore caps concurrent connections

## Getting started

### Prerequisites

- Rust stable toolchain (`rustup` is recommended)
- A TLS PKI: server certificate/key and a CA certificate for client verification

### Build

```bash
cargo build --release
# Binary at: ./target/release/gatekeeper
```

### Minimal config

Create a TOML config file (see [examples/gatekeeper.toml](examples/gatekeeper.toml) for a fully-commented version):

```toml
[proxy]
bind = "0.0.0.0:3128"

[tls]
server_cert = "/etc/gatekeeper/server.crt"
server_key  = "/etc/gatekeeper/server.key"
ca_cert     = "/etc/gatekeeper/ca.crt"

[allowlist]
domains = [
    "github.com",
    "*.github.com",
    "registry.npmjs.org",
    "*.crates.io",
]
```

### Run

```bash
./target/release/gatekeeper --config /etc/gatekeeper/gatekeeper.toml
```

The proxy listens on the configured address and is ready immediately.

## Configuration reference

All configuration lives in a single TOML file. Pass it with `--config` / `-c`.

### `[proxy]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind` | string | — | Address and port to listen on, e.g. `"0.0.0.0:3128"` |
| `max_connections` | integer | `1024` | Maximum concurrent connections |
| `connect_timeout_ms` | integer | `5000` | Timeout in ms for upstream TCP connects |
| `idle_timeout_ms` | integer | `30000` | Idle CONNECT tunnel teardown timeout in ms |
| `pac_proxy_addr` | string | derived from `bind` | Address written into PAC output, e.g. `"proxy.internal:3128"` |

### `[tls]`

| Key | Type | Description |
|-----|------|-------------|
| `server_cert` | path | Proxy's own TLS certificate (PEM, chain included) |
| `server_key` | path | Proxy's own TLS private key (PEM) |
| `ca_cert` | path | CA certificate used to verify client certificates (PEM) |

mTLS is mandatory — clients without a valid certificate are rejected at the TLS layer.

### `[allowlist]`

| Key | Type | Description |
|-----|------|-------------|
| `domains` | list of strings | Allowed destinations |

Domain rule syntax:

| Rule | Matches | Does not match |
|------|---------|----------------|
| `"github.com"` | `github.com` | `api.github.com` |
| `"*.github.com"` | `api.github.com`, `raw.github.com` | `github.com` |

Rules are case-insensitive. IP addresses are not allowed as rules. Ports are stripped before matching.

### `[logging]`

| Key | Type | Default | Options |
|-----|------|---------|---------|
| `level` | string | `"info"` | `trace`, `debug`, `info`, `warn`, `error` |
| `format` | string | `"json"` | `json`, `pretty` |

## Client configuration

### PAC file

The proxy serves a PAC file at `http://<bind-address>/proxy.pac` over **plaintext HTTP** (no TLS, no authentication required). Point browsers, package managers, or OS proxy settings at this URL.

Example browser setting:
```
Automatic proxy configuration URL: http://proxy.internal:3128/proxy.pac
```

The PAC script routes allowed domains through the proxy and sends everything else direct. If you need the PAC output to advertise a different address than the bind address (e.g. behind a load balancer), set `pac_proxy_addr` in `[proxy]`.

### Proxy environment variables

For CLI tools and package managers that respect standard proxy env vars, configure them to use the proxy with client certificate authentication:

```bash
export HTTPS_PROXY="https://proxy.internal:3128"
# Provide client cert/key for mTLS:
export SSL_CERT_FILE=/path/to/client.crt
export SSL_KEY_FILE=/path/to/client.key
```

Exact variable names vary by tool. Check your tool's documentation for mTLS/client certificate support.

## Certificate setup

You need three files:

1. **CA certificate** (`ca.crt`) — signs client certificates; the proxy trusts this CA
2. **Server certificate** (`server.crt`) and **server key** (`server.key`) — the proxy's own identity; clients verify this

A minimal setup using `openssl`:

```bash
# 1. Create a CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 3650 -nodes \
    -subj "/CN=Gatekeeper CA"

# 2. Create server cert signed by the CA
openssl req -newkey rsa:4096 -keyout server.key -out server.csr -nodes \
    -subj "/CN=proxy.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365

# 3. Create a client cert signed by the same CA
openssl req -newkey rsa:4096 -keyout client.key -out client.csr -nodes \
    -subj "/CN=my-service"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365
```

The CN of the client certificate is extracted and included in audit log entries.

## Deployment

### systemd

```ini
# /etc/systemd/system/gatekeeper.service
[Unit]
Description=Gatekeeper forward proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/gatekeeper --config /etc/gatekeeper/gatekeeper.toml
Restart=on-failure
User=gatekeeper

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now gatekeeper
```

### Hot reload

To reload configuration without restarting:

```bash
systemctl reload gatekeeper
# or directly:
kill -HUP $(pidof gatekeeper)
```

If the new config is valid, it takes effect for all new connections immediately. In-flight connections are not interrupted. If the config is invalid, the proxy logs an error and continues with the previous config.

## Development

```bash
# Run tests
cargo test

# Lint (must be clean before committing)
cargo clippy --all-targets -- -D warnings

# Format (must produce no diff before committing)
cargo fmt
```

### Fuzzing

Requires the nightly toolchain and `cargo-fuzz`:

```bash
cargo install cargo-fuzz

cargo +nightly fuzz run allowlist           # Allowlist matching
cargo +nightly fuzz run connect_authority   # CONNECT authority parsing
cargo +nightly fuzz run domain_validation   # Domain rule validation
cargo +nightly fuzz run pac_generation      # PAC script generation
```

Add any crash inputs discovered by the fuzzer as regression tests in `tests/adversarial_test.rs`.

## License

MIT
