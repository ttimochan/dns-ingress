# Changelog

## [v1.0.7] - 2026-01-24

### CI Improvements
- Use zigbuild for cross-platform compilation
- Parallelize build and package jobs for faster releases
- Use native ARM64 runners for arm64 packaging
- Add GitHub Actions release workflow with multi-platform support

### Features
- Release automation for Debian, RPM, Arch Linux packages
- Multi-architecture Docker image builds

### Bug Fixes
- Fix RPM build script with proper path handling
- Fix RPM version compatibility (replace '-' with '.')
- Fix systemd unit path in RPM spec

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

