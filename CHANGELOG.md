# Changelog

## [v1.0.6-alpha.1] - 2026-01-24

### CI Improvements
- Use Docker for cross-platform builds (amd64 + arm64)
- Optimize release workflow order
- Add commit hooks for code quality

### Bug Fixes
- Correct RPM binary path in build script
- Fix graceful shutdown mechanism

## [v1.0.5] - 2026-01-24

### Features
- Remove Prometheus metrics, use logging instead for personal use
- Add certificate preloading at startup to avoid TLS handshake delay

### Improvements
- Add graceful shutdown mechanism with timeout (10s per server)
- Add commit hooks (fmt + clippy) for code quality
- Reorganize code structure for better maintainability

### Bug Fixes
- Fix connection pool cleanup on shutdown
- Fix server graceful shutdown sequence

### Code Cleanup
- Remove unused `shutdown()` method from ConnectionPool
- Simplify healthcheck server (removed metrics endpoint)
- Update dependencies

### Documentation
- Add commit message auto-formatting hook

