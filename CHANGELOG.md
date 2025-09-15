# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-09-15

### Added
- Initial implementation of RSA-PKCS1v15-SHA256 signature verification
- Hardware binding support for MAC addresses, disk IDs, and hostnames
- Cross-platform hardware detection (Linux, Windows, macOS)
- Binary license format support (go-license v2.0+)
- JSON license format support (legacy go-license v1.x)
- License expiry validation
- Command-line interface for license verification
- Comprehensive documentation with examples
- GitHub Actions CI/CD pipeline
- Cross-platform testing (Linux, Windows, macOS)
- Multiple Rust toolchain support (stable, beta)
- Complete license verification system compatible with go-license

### Security
- Cryptographic signature validation using 2048-bit RSA keys
- Hardware-locked licensing to prevent license sharing
- Automatic license expiry enforcement
- Secure error handling without information leakage
