# DNS Ingress

> **v2 migration:** upstream hostnames are always the rewritten targets.
> Replace legacy fixed `upstream.default` and protocol URL/address values with
> per-protocol endpoint settings. Legacy fixed-upstream configuration is rejected.

[中文文档](README.zh-CN.md)

DNS-Ingress is a DNS request router that forwards queries to different upstream servers based on subdomain prefixes. For example: forwarding api.example.org to api.example.cn, and www.example.org to www.example.cn. Supports DoT, DoH, DoQ, DoH3 protocols.

## Features

- **DoT (DNS over TLS)** - TCP 853
- **DoH (DNS over HTTPS)** - TCP 443
- **DoQ (DNS over QUIC)** - UDP 853
- **DoH3 (DNS over HTTP/3)** - UDP 443
- **Dynamic TLS Certificate Selection** - Automatic certificate selection based on SNI
- **Multi-domain Support** - Prefix extraction and rewriting for multiple base domains
- **High Performance** - Built on Tokio async runtime for high concurrency
- **Zero-copy Optimization** - Minimize memory copies for better performance
- **Modular Architecture** - Clear module separation for easy extension and maintenance
- **Performance Monitoring** - Prometheus metrics collection and export
- **Health Checks** - HTTP health check endpoints with JSON and Prometheus format
- **Logging System** - Multi-level logging, file output, JSON format, and log rotation

## How It Works

### Overall Architecture

DNS Ingress Server receives DNS query requests from clients, processes them through Protocol Readers (DoH, DoT, DoQ, DoH3). The system extracts SNI (Server Name Indication) from requests, rewrites domain names via SNI Rewriter, dynamically selects TLS certificates using Certificate Resolver based on SNI, and finally forwards requests to upstream DNS servers. The system also collects performance metrics and provides monitoring interfaces through health check servers.

### Workflow Details

#### 1. Startup Phase

The program starts from `main.rs`, initializes the Rustls cryptographic provider, loads the required `config.toml`, validates the configuration, initializes the logging system, creates an `App` instance (including SNI Rewriter and metrics collector initialization), and finally starts servers for each protocol (DoT, DoH, DoQ, DoH3) and the health check server.

#### 2. Request Processing Flow (DoH Example)

1. **Client Request**: Client sends GET/POST request to `https://www.example.org/dns-query` with `Host: www.example.org` header

2. **DoH Server Receives**: Server extracts SNI from Host header ("www.example.org"), then calls SNI Rewriter

3. **SNI Rewriter Processing**: Rewriter matches base domain list (e.g., `["example.com", "example.org"]`), finds the match, extracts prefix ("www"), builds target hostname ("www.example.cn"), and caches the mapping

4. **Forward Request**: Builds upstream URI (`https://www.example.cn/dns-query`), copies and updates Host header, forwards to upstream server, returns response to client

#### 3. SNI Rewrite Logic

**Prefix Extraction Algorithm:**

```rust
Input: SNI = "www.example.org"
Config: base_domains = ["example.com", "example.org"]
        target_suffix = ".example.cn"

Steps:
1. Iterate through base_domains
2. Check if SNI ends with base_domain
   - "www.example.org".ends_with("example.org") ✓
3. Extract remaining part
   - rest = "www.example.org".strip_suffix("example.org") = "www."
4. Validate format (must end with '.' and not empty)
   - rest.ends_with('.') && !rest.is_empty() ✓
5. Extract prefix
   - prefix = "www.".strip_suffix('.') = "www"
6. Build target hostname
   - target = prefix + target_suffix = "www.example.cn"
```

**Examples:**

| Input SNI         | Matched Base Domain | Prefix | Target Hostname      |
|-------------------|---------------------|--------|----------------------|
| `www.example.org` | `example.org`       | `www`  | `www.example.cn`     |
| `api.example.com` | `example.com`       | `api`  | `api.example.cn`     |
| `sub.example.org` | `example.org`       | `sub`  | `sub.example.cn`     |
| `example.org`     | -                   | -      | No match (no prefix) |
| `www.other.com`   | -                   | -      | No match (not in list)|

#### 4. TLS Certificate Selection

When a TLS handshake request is received (SNI: www.example.org), `CertificateResolver.resolve()` first checks the certificate cache. If cache hit, returns cached certificate. If not found, looks up certificate config: first exact match `tls.certs["www.example.org"]`, then base domain `tls.certs["example.org"]`, then falls back to `tls.default`. Once config is found, loads certificate file, caches, and returns.

**Certificate Selection Priority:**

1. **Exact Match** - `tls.certs[SNI]` (e.g., `tls.certs["www.example.org"]`)
2. **Base Domain Match** - `tls.certs[base_domain]` (e.g., `tls.certs["example.org"]`)
3. **Default Certificate** - `tls.default` (if configured)
4. **Error** - If no certificate config found

#### 5. Protocol Implementation Details

**DoH (DNS over HTTPS)**

- Listening port: TCP 443
- SNI extraction: From HTTP `Host` header
- Request forwarding: Using Hyper HTTP client
- Supported methods: GET, POST

**DoT (DNS over TLS)**

The listener and its upstream TLS client advertise the `dot` ALPN identifier.

- Listening port: TCP 853
- SNI extraction: From TLS handshake (via `ClientHello`)
- Request forwarding: TLS tunnel forwarding
- Certificate selection: Dynamic certificate resolver

**DoQ (DNS over QUIC)**

- Listening port: UDP 853
- SNI extraction: From QUIC connection
- Request forwarding: QUIC bidirectional stream forwarding
- Implementation: Using quinn 0.11 and modular QUIC client

**DoH3 (DNS over HTTP/3)**

- Listening port: UDP 443
- SNI extraction: From HTTP Host header
- Request forwarding: HTTP/3 request forwarding (using h3 and h3-quinn)
- Implementation: Full HTTP/3 server and client support

## Project Structure

### Directory Structure

```
src/
├── main.rs              # Program entry point, initializes logging and config
├── app.rs               # Application lifecycle management, starts protocol servers
├── config.rs            # Config struct definition and loading logic
├── server.rs            # Server startup utilities and shared resources
├── metrics.rs           # Prometheus metrics collection and export
├── logging.rs           # Logging system initialization
├── sni.rs               # SNI Rewriter trait definition
├── rewrite.rs           # Rewriter factory function
├── tls_utils.rs         # TLS certificate loading and dynamic selection
├── utils.rs             # Utility functions
├── quic/                # QUIC related modules
│   ├── mod.rs          # Module exports
│   ├── config.rs       # QUIC server configuration
│   └── client.rs       # QUIC client connection
├── upstream/            # Upstream connection module
│   ├── mod.rs          # Module exports
│   ├── http.rs         # HTTP client and forwarding
│   ├── quic.rs         # QUIC stream forwarding
│   └── pool.rs         # Connection pool management
├── proxy/               # Proxy forwarding module
│   ├── mod.rs          # Module exports
│   └── http.rs         # HTTP request handling and SNI rewrite
├── readers/             # Protocol server implementations
│   ├── mod.rs          # Module exports
│   ├── doh.rs          # DoH server implementation
│   ├── dot.rs          # DoT server implementation
│   ├── doq.rs          # DoQ server implementation
│   ├── doh3.rs         # DoH3 server implementation
│   └── healthcheck.rs  # Health check server
└── rewriters/          # SNI Rewriter implementations
    ├── mod.rs          # Module exports
    └── base.rs         # Base prefix extraction rewriter

tests/                   # Test cases
├── config.rs           # Config module tests
├── rewriters_base.rs   # Rewriter tests
├── rewrite.rs          # Factory function tests
├── tls_utils.rs        # TLS utilities tests
├── app.rs              # App tests
├── quic.rs             # QUIC module tests
├── upstream.rs         # Upstream module tests
├── proxy.rs            # Proxy module tests
├── metrics.rs          # Metrics module tests
└── performance.rs      # Performance tests
```

### Core Module Descriptions

#### `sni.rs` - SNI Rewriter Interface

Defines the `SniRewriter` trait that all rewriters must implement:

```rust
pub trait SniRewriter {
    async fn rewrite(&self, sni: &str) -> Option<RewriteResult>;
}
```

#### `rewriters/base.rs` - Base Rewriter

Implements prefix extraction and rewrite logic:

- Support for multiple base domains
- Prefix extraction algorithm
- Target hostname building
- SNI mapping cache

#### `quic/` - QUIC Module

QUIC-related configuration and connection management:

- `config.rs` - Unified QUIC server endpoint creation
- `client.rs` - QUIC client connection management

#### `upstream/` - Upstream Connection Module

Upstream server connection and forwarding logic:

- `http.rs` - HTTP client creation and request forwarding (shared client instance)
- `quic.rs` - QUIC stream forwarding (zero-copy optimization)

#### `proxy/` - Proxy Forwarding Module

Proxy forwarding logic abstraction:

- `http.rs` - HTTP request handling, SNI rewrite, and upstream forwarding

#### `readers/` - Protocol Servers

Individual protocol server implementations (simplified, using shared modules):

- Listen on specified port
- Use `proxy` module to handle requests
- Use `upstream` module to forward to upstream

#### `tls_utils.rs` - TLS Certificate Management

- Dynamic certificate loading
- SNI-based certificate selection
- Certificate caching mechanism
- Lock poisoning detection

#### `metrics.rs` - Performance Monitoring

- Prometheus metrics collection
- Request statistics (total, success, failed)
- Traffic statistics (bytes received, sent)
- SNI rewrite statistics
- Upstream error statistics
- Processing time histogram
- Metrics snapshot caching (reduce lock contention)
- Support Prometheus text format and JSON format export

#### `server.rs` - Server Utilities

- Unified server startup interface
- Shared resource management (config, rewriter, metrics)
- Graceful shutdown support

#### `readers/healthcheck.rs` - Health Check Server

- HTTP health check endpoints
- Prometheus metrics export (`/metrics` or `/stats`)
- JSON format metrics export (`/metrics/json`)
- Configurable check paths

#### `app.rs` - Application Management

- Configuration loading and validation
- Rewriter creation
- Metrics collector initialization
- Protocol server startup (parallel)
- Health check server startup
- Lifecycle management

## Configuration

### Configuration File Format

Copy `config.toml.example` to `config.toml` and modify as needed:

```toml
[rewrite]
# Base domain list, supports multiple domains
# Rewriter extracts prefixes from hostnames matching these base domains
base_domains = ["example.com", "example.org"]
# Target domain suffix, extracted prefixes are combined with this suffix to form target hostname
target_suffix = ".example.cn"

[servers]
# DNS over TLS (DoT) - TCP 853
[servers.dot]
enabled = true
bind_address = "0.0.0.0"
port = 853

# DNS over HTTPS (DoH) - TCP 443
[servers.doh]
enabled = true
bind_address = "0.0.0.0"
port = 443
path = "/dns-query"

# DNS over QUIC (DoQ) - UDP 853
[servers.doq]
enabled = true
bind_address = "0.0.0.0"
port = 853

# DNS over HTTP/3 (DoH3) - UDP 443
[servers.doh3]
enabled = false
bind_address = "0.0.0.0"
port = 443
path = "/dns-query"

# Healthcheck server - HTTP endpoint for health checks
[servers.healthcheck]
enabled = true
bind_address = "0.0.0.0"
port = 8080
path = "/health"

[upstream]
[upstream.dot]
port = 853
[upstream.doh]
port = 443
path = "/dns-query"
[upstream.doq]
port = 853
[upstream.doh3]
port = 443
path = "/dns-query"

[limits]
max_connections_per_listener = 1024
max_inflight_requests_per_connection = 64
max_upstream_pool_entries = 256
transaction_timeout_seconds = 30

[tls]
# Default certificate config (optional, used when no domain-specific certificate found)
[tls.default]
cert_file = "/path/to/default-cert.pem"
key_file = "/path/to/default-key.pem"

# Separate certificates for each base domain
[tls.certs.example.com]
cert_file = "/path/to/example-com-cert.pem"
key_file = "/path/to/example-com-key.pem"

[tls.certs.example.org]
cert_file = "/path/to/example-org-cert.pem"
key_file = "/path/to/example-org-key.pem"
```

### Configuration Options

#### `[rewrite]` - Rewrite Config

- **`base_domains`** (required): List of base domains for matching and prefix extraction
- **`target_suffix`** (required): Target domain suffix, combined with extracted prefix

#### `[servers.*]` - Server Config

Each protocol server configuration:

- **`enabled`**: Whether to enable this protocol server
- **`bind_address`**: Bind address (e.g., "0.0.0.0" or "127.0.0.1")
- **`port`**: Listening port

Health check server config (`[servers.healthcheck]`):

- **`enabled`**: Whether to enable health check server
- **`bind_address`**: Bind address
- **`port`**: Listening port (default: 8080)
- **`path`**: Health check path (default: `/health`)

Health check server provides:

- `GET /health` - Returns service health status (JSON format)
- `GET /metrics` or `GET /stats` - Returns Prometheus format metrics
- `GET /metrics/json` - Returns JSON format metrics

#### `[upstream]` - Upstream Endpoint Config

The rewriter supplies the upstream hostname. `dot` and `doq` configure `port`;
`doh` and `doh3` configure `port` and `path`. Fixed upstream hosts are not supported.

#### `[limits]` - Resource Limits

`max_connections_per_listener` bounds every public listener. The in-flight
limit applies to multiplexed DoH/DoQ/DoH3 request streams. The upstream pool is
keyed by rewritten authority and protocol; DoQ and DoH3 retain QUIC sessions
for reuse. `transaction_timeout_seconds` is a no-progress I/O timeout.

#### `[tls]` - TLS Certificate Config

- **`[tls.default]`**: Default certificate config (optional)
- **`[tls.certs.<domain>]`**: Domain-specific certificate config
  - **`cert_file`**: Certificate file path (PEM format)
  - **`key_file`**: Private key file path (PEM format)

#### `[logging]` - Logging Config

- **`level`**: Log level, options: `trace`, `debug`, `info`, `warn`, `error` (default: `info`)
  - Can also be set via environment variable `RUST_LOG`, which takes priority
- **`file`**: Log file path (optional, if not set, logs only output to stdout/stderr)
- **`json`**: Enable JSON format logs (default: `false`)
  - JSON format facilitates later analysis and log aggregation tools
- **`rotation`**: Enable log rotation (default: `true`, only effective when `file` is set)
- **`max_file_size`**: Maximum log file size in bytes (default: 10485760 = 10MB)
- **`max_files`**: Number of log files to retain (default: `5`)

**Logging Config Example:**

```toml
[logging]
level = "info"
file = "/var/log/dns-ingress/dns-ingress.log"
json = false
rotation = true
max_file_size = 10485760  # 10MB
max_files = 5
```

**Logging Features:**

- Multi-level log support (trace, debug, info, warn, error)
- File output and stdout/stderr simultaneous logging
- JSON format log support (for log analysis tools)
- Log rotation (by size)
- Detailed error context information
- Structured logging (includes file, line number, timestamp, etc.)

## Usage

### Build

```bash
# Development mode
cargo build

# Release mode
cargo build --release
```

### Run

```bash
# Use default config (loaded from config.toml, or use defaults if not exists)
cargo run

# Or run the compiled binary directly
./target/release/dns-ingress
```

### Test

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test --test config
cargo test --test quic
cargo test --test upstream
cargo test --test proxy
cargo test --test metrics

# Run unit tests
cargo test --lib

# Show test output
cargo test -- --nocapture
```

### Monitoring and Health Checks

After starting the service, you can monitor via health check endpoints:

```bash
# Check process liveness and listener readiness
curl http://localhost:8080/live
curl http://localhost:8080/ready

# Get Prometheus format metrics
curl http://localhost:8080/metrics

# Get JSON format metrics
curl http://localhost:8080/metrics/json
```

`/live` reports process liveness. `/ready` becomes successful only after every
enabled listener has bound its production socket; it becomes unavailable again
if an ingress task exits. `transaction_timeout_seconds` is an idle-I/O timeout,
so streamed AXFR/IXFR responses are not capped by a total transfer duration.

Metrics returned by health check endpoints include:

- Total requests
- Successful/failed requests
- Bytes received/sent
- SNI rewrite count
- Upstream error count
- Average processing time
- Success rate
- Throughput (requests/second)

## Extensibility

### Adding New Protocol Support

To add new protocol support, refer to `src/readers/README.md`:

1. Create new protocol file in `readers/` directory (e.g., `new_protocol.rs`)
2. Implement server struct and `start()` method
3. Export in `readers/mod.rs`
4. Add startup logic in `app.rs`

### Adding New Rewriters

To add custom SNI rewrite logic, refer to `src/rewriters/README.md`:

1. Create new rewriter file in `rewriters/` directory
2. Implement `SniRewriter` trait
3. Export in `rewriters/mod.rs`
4. Update factory function in `rewrite.rs` (optional)

## Performance Optimization

The project employs multiple performance optimizations:

1. **Shared Config** - Use `Arc<AppConfig>` to avoid config copying
2. **Certificate Caching** - TLS certificates cached after loading to avoid repeated file I/O
3. **SNI Mapping Cache** - Rewrite result caching for faster queries
4. **Async I/O** - Tokio-based async runtime for high concurrency
5. **Zero-copy Optimization** - Minimize unnecessary memory copies:
   - Use `Bytes` and slice references instead of `Vec<u8>` copying
   - Reuse buffers (e.g., reuse buffer in DoT reader)
   - Use `to_bytes()` directly instead of additional copying
   - Pass data using slice references (`&[u8]` instead of `Vec<u8>`)
6. **Shared Client Instance** - HTTP client shared between server instances to avoid repeated creation
7. **Metrics Snapshot Caching** - Metrics snapshot cached for 1 second to reduce lock contention and duplicate calculations
8. **Batch Metrics Update** - Use `record_request()` to batch update multiple metrics, reducing atomic operation count
9. **Modular Design** - Clear module separation reduces code duplication and improves maintainability
10. **Connection Pool Management** - Upstream connection pool reuses connections to reduce connection establishment overhead

## Roadmap

- [ ] TLS certificate dynamic loading and hot reload
- [x] Comprehensive error handling and logging
- [x] Performance monitoring and statistics
- [ ] Configuration hot reload
- [ ] Request rate limiting
- [ ] More granular metrics labels (by protocol, domain, etc.)

## Dependencies

### Core Dependencies

- `tokio` - Async runtime
- `rustls` / `tokio-rustls` - TLS support
- `quinn` (0.11) - QUIC protocol support
- `h3` (0.0.8) / `h3-quinn` (0.0.10) - HTTP/3 support
- `hyper` / `hyper-util` - HTTP support
- `rustls-native-certs` - System root certificate support

### Utility Dependencies

- `serde` / `toml` - Config parsing
- `tracing` / `tracing-subscriber` - Logging (supports JSON format and log rotation)
- `tracing-appender` - Log file output and rotation
- `anyhow` - Error handling (provides detailed error context)
- `thiserror` - Error type definition
- `bytes` - Byte handling (zero-copy optimization)
- `http-body-util` - HTTP body utilities
- `async-trait` - Async trait support
- `futures` - Future utilities
- `prometheus` - Prometheus metrics collection and export
- `dashmap` - Concurrent hashmap (for SNI mapping cache)

### Development Dependencies

- `tempfile` - Temporary files (for testing)
- `reqwest` - HTTP client (for testing)
- `tokio-test` - Tokio testing utilities

## License

AGPL3
