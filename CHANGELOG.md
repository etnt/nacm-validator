# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-09-02

### Added
- **Multiple Configuration Files Support** 🎉
  - New `--config-dir` CLI option to load multiple XML files from a directory
  - YANG merge semantics implementation for proper configuration combining
  - Alphabetical file ordering with predictable precedence rules
  - Error resilience: invalid files are skipped with warnings, valid ones continue
  - Mutual exclusion between `--config` and `--config-dir` options for safety
  - Comprehensive examples in `nacm-validator-bin/examples/test-configs/`
  - Interactive demo script: `nacm-validator-bin/examples/multiple_files_demo.sh`

- **Library Enhancements**
  - `NacmConfig::merge()` function for combining multiple configurations  
  - `NacmConfig::default()` for creating base configurations
  - YANG merge semantics: last-wins for global settings, additive for groups/rules
  - Rule precedence adjustment with `file_index * 10000 + rule_index` formula
  - Comprehensive merge functionality with proper error handling

- **CLI Improvements**
  - Verbose logging shows merge progress and statistics
  - Enhanced error messages with file-specific context
  - Backward compatible: all existing usage patterns work unchanged
  - Updated help text and examples

### Changed
- **Breaking**: Minimum supported Rust version remains 1.70
- Library version bumped to 0.2.0 to reflect significant new functionality
- CLI version bumped to 0.2.0 for feature parity
- Enhanced documentation with multiple files usage examples
- Improved project structure with examples properly organized by crate

### Fixed
- CLI dependency now uses local library path for development
- All tests pass including new doctests for merge functionality
- Proper error handling for malformed XML files in directory mode

## [0.1.0] - 2024-XX-XX

### Added
- Initial implementation of NACM (RFC 8341) validator
- Tail-f ACM extensions support:
  - Command-based access control (`<cmdrule>`)
  - Context-aware rules (CLI, WebUI, NETCONF)
  - Enhanced logging with `log-if-permit`/`log-if-deny`
  - Group ID (GID) mapping for OS integration
- Comprehensive CLI tool with JSON I/O support
- Real-world XML configuration parsing
- Complete test suite with example configurations
- Rust library and CLI tool published to crates.io

[0.2.0]: https://github.com/etnt/nacm-validator/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/etnt/nacm-validator/releases/tag/v0.1.0
