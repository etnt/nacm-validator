# NACM Validator Release HOWTO

This document provides step-by-step instructions for publishing new releases of the NACM Validator project to crates.io.

## Overview

The NACM Validator project consists of two crates that must be published in order:
1. **`nacm-validator`** (library) - Must be published first
2. **`nacm-validator-cli`** (binary) - Depends on the library, published second

## Pre-Release Checklist

### 1. Code Readiness
- [ ] All features implemented and tested
- [ ] All tests passing: `cargo test --workspace`
- [ ] Documentation updated (both library and CLI)
- [ ] Examples working and up-to-date
- [ ] CHANGELOG.md updated with new version

### 2. Version Management
- [ ] Bump version in both `Cargo.toml` files:
  - `nacm-validator-lib/Cargo.toml`
  - `nacm-validator-bin/Cargo.toml`
- [ ] Update dependency version in CLI crate to match library version
- [ ] Update version references in README.md if needed

### 3. Documentation Review
- [ ] Library documentation (`nacm-validator-lib/src/lib.rs`) reflects new features
- [ ] CLI documentation (`nacm-validator-bin/src/main.rs`) reflects new options
- [ ] All doctests pass: `cargo test --doc --workspace`
- [ ] Examples in documentation are current and working

### 4. Crates.io Requirements Check
- [ ] Keywords count ≤ 5 per crate (crates.io limit)
- [ ] Categories are valid and relevant
- [ ] License is specified and files exist
- [ ] Repository and homepage URLs are correct
- [ ] Description is clear and under 200 characters

## Release Process

### Step 1: Final Preparations

```bash
# Ensure working directory is clean
git status

# Run full test suite
cargo test --workspace

# Check documentation builds cleanly
cargo doc --workspace --no-deps

# Verify examples work
cd nacm-validator-bin/examples
./multiple_files_demo.sh
cd ../..
```

### Step 2: Create and Tag Release Commit

```bash
# Commit all version changes
git add -A
git commit -m "chore: bump version to v<VERSION> for release"

# Create and push tag
git tag v<VERSION>
git push origin main
git push origin v<VERSION>
```

**Note:** If you need to move a tag after additional commits:
```bash
# Move tag locally
git tag -d v<VERSION>
git tag v<VERSION>

# Move tag on remote
git push origin :refs/tags/v<VERSION>
git push origin v<VERSION>
```

### Step 3: Publish Library Crate

```bash
# Dry run first to catch issues
cargo publish --dry-run --manifest-path nacm-validator-lib/Cargo.toml

# If dry run succeeds, publish
cargo publish --manifest-path nacm-validator-lib/Cargo.toml
```

**Common Issues:**
- Too many keywords: Reduce to 5 maximum
- Invalid categories: Check [crates.io categories](https://crates.io/category_slugs)
- Uncommitted changes: Commit or use `--allow-dirty`

### Step 4: Publish CLI Crate

```bash
# Wait for library to propagate (usually ~30 seconds)
sleep 30

# Dry run first
cargo publish --dry-run --manifest-path nacm-validator-bin/Cargo.toml

# If dry run succeeds, publish
cargo publish --manifest-path nacm-validator-bin/Cargo.toml
```

### Step 5: Verify Publication

```bash
# Test installation from crates.io
cargo install nacm-validator-cli --version <VERSION> --force

# Verify new features work
nacm-validator --help
nacm-validator --version

# Test basic functionality
nacm-validator --config nacm-validator-bin/examples/test-configs/01-base.xml \
  --user alice --operation read --format json
```

## Post-Release Tasks

### 1. Verify Online Presence
- [ ] Check library page: https://crates.io/crates/nacm-validator
- [ ] Check CLI page: https://crates.io/crates/nacm-validator-cli  
- [ ] Verify documentation: https://docs.rs/nacm-validator
- [ ] Check GitHub release appears correctly

### 2. Update Development Environment
```bash
# Switch CLI dependency back to local development
# Edit nacm-validator-bin/Cargo.toml:
[dependencies]
nacm-validator = { path = "../nacm-validator-lib" }  # For development
# nacm-validator = "^<VERSION>"                     # For release
```

### 3. Communication
- [ ] Update project README if needed
- [ ] Announce release (if applicable)
- [ ] Update any dependent projects

## Version Numbering Guidelines

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes to public API
- **MINOR** (0.X.0): New features, backward compatible
- **PATCH** (0.0.X): Bug fixes, backward compatible

### Release Types

- **Major Release**: Breaking changes to library API or CLI interface
- **Minor Release**: New features like `--config-dir`, new validation rules
- **Patch Release**: Bug fixes, documentation improvements, performance

## Troubleshooting

### Publication Fails

**Error: Too many keywords**
```bash
# Edit Cargo.toml to reduce keywords to 5 maximum
# Common good keywords: "nacm", "netconf", "access-control", "yang", "configuration"
```

**Error: Crate version already exists**
```bash
# You cannot republish the same version
# Bump version number and try again
```

**Error: Invalid category**
```bash
# Check valid categories at: https://crates.io/category_slugs
# Common valid ones: "network-programming", "authentication", "config", "parsing"
```

**Error: Dependency not found**
```bash
# Wait longer for crates.io index to update
# Check library was actually published successfully
```

### Git Tag Issues

**Tag points to wrong commit**
```bash
# Delete and recreate tag (see Step 2 above)
git tag -d v<VERSION>
git tag v<VERSION>
git push origin :refs/tags/v<VERSION>  # Delete remote
git push origin v<VERSION>              # Push new
```

## File Checklist for Release

Before releasing, ensure these files are up-to-date:

- [ ] `nacm-validator-lib/Cargo.toml` - Version, dependencies, metadata
- [ ] `nacm-validator-bin/Cargo.toml` - Version, library dependency, metadata  
- [ ] `nacm-validator-lib/src/lib.rs` - Module documentation
- [ ] `nacm-validator-bin/src/main.rs` - CLI documentation
- [ ] `README.md` - Installation instructions, version badges
- [ ] `CHANGELOG.md` - Release notes
- [ ] Examples in `nacm-validator-bin/examples/` - Working and current

## Quick Reference Commands

```bash
# Full release sequence (after version bumps and commits)
git tag v<VERSION> && git push origin main && git push origin v<VERSION>
cargo publish --manifest-path nacm-validator-lib/Cargo.toml
sleep 30
cargo publish --manifest-path nacm-validator-bin/Cargo.toml
cargo install nacm-validator-cli --version <VERSION> --force
```

## Historical Releases

- **v0.1.0** - Initial release with single file support
- **v0.2.0** - Added multiple configuration files with YANG merge semantics
- **v<NEXT>** - (Future release notes here)

---

*Keep this document updated with lessons learned from each release!*
