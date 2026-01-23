# Changelog

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

