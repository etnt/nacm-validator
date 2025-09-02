# NACM Validator

[![Crates.io](https://img.shields.io/crates/v/nacm-validator.svg)](https://crates.io/crates/nacm-validator)
[![Crates.io](https://img.shields.io/crates/v/nacm-validator-cli.svg?label=CLI)](https://crates.io/crates/nacm-validator-cli)
[![Documentation](https://docs.rs/nacm-validator/badge.svg)](https://docs.rs/nacm-validator)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A Rust implementation of **NACM** (Network Access Control Model) validator as defined in [RFC 8341](https://tools.ietf.org/rfc/rfc8341.txt), with support for [Tail-f ACM extensions](doc/rfc-tailf-acm-proposal.md) for command-based access control. This library and CLI tool demonstrate parsing real NACM XML configurations and validating access requests against defined rules.

## Installation

The NACM Validator provides both a **library** (`nacm-validator`) for developers and a **command-line tool** (`nacm-validator`) for end users.

### Installing the CLI Tool

The CLI tool is now published to crates.io! Install it with:

```bash
cargo install nacm-validator-cli
```

This will install the `nacm-validator` binary to `~/.cargo/bin/` (make sure it's in your PATH).

Alternatively, you can install from source:

```bash
# Clone the repository
git clone https://github.com/etnt/nacm-validator.git
cd nacm-validator

# Install the CLI tool globally from source
cargo install --path nacm-validator-bin
```

After installation, you can run the tool from anywhere:

```bash
nacm-validator --help
```

### Using the Library

To use the validator library in your own Rust project, add it to your `Cargo.toml`:

```toml
[dependencies]
nacm-validator = "0.2"
```

You can also use the git dependency for the latest development version:

```toml
[dependencies]
# For the latest published version (recommended):
nacm-validator = "0.2"

# Or for the latest development version:
# nacm-validator = { git = "https://github.com/etnt/nacm-validator.git", package = "nacm-validator" }
```

Then import the library in your Rust code:

```rust
use nacm_validator::{NacmConfig, AccessRequest, Operation, RequestContext};
```

### Development Setup

If you want to develop or contribute to the project:

```bash
# Clone the repository
git clone https://github.com/etnt/nacm-validator.git
cd nacm-validator

# Build the workspace (both library and CLI)
cargo build

# Run tests
cargo test

# Build documentation
cargo doc --open

# Run examples
cargo run --example tailf_acm_demo
```

## Quick Start

### CLI Tool - Multiple Configuration Files (NEW!)

The NACM Validator now supports loading and merging multiple configuration files from a directory, enabling modular configuration management:

```bash
# Load multiple configuration files from a directory
./target/release/nacm-validator \
    --config-dir nacm-validator-bin/examples/test-configs \
    --user alice \
    --operation read \
    --verbose
# Output: Loads and merges all XML files in nacm-validator-bin/examples/test-configs/ directory

# Run the comprehensive multiple files demo
./nacm-validator-bin/examples/multiple_files_demo.sh

# Traditional single file still works (backward compatible)
./target/release/nacm-validator \
    --config single-config.xml \
    --user alice \
    --operation read
```

**Key Benefits of Multiple Files:**
- 🔧 **Modular Configuration**: Split settings across logical files
- 👥 **Team Collaboration**: Different teams manage separate files
- 🌍 **Environment-Specific**: Override settings per environment  
- 🔄 **YANG Compliance**: Proper YANG merge semantics implementation
- ⚠️ **Error Resilience**: Invalid files don't break entire configuration
- 🔙 **Backward Compatible**: Single file mode still fully supported

#### Multiple Files Configuration Structure

The `nacm-validator-bin/examples/test-configs/` directory demonstrates a typical modular setup:

```
nacm-validator-bin/examples/test-configs/
├── 01-base.xml          # Base NACM settings and admin group
├── 02-operators.xml     # Operator groups and data access rules  
├── 03-commands.xml      # Command-based access rules (Tail-f ACM)
├── invalid.xml          # Invalid XML to demonstrate error handling
└── test-file.xml        # Additional config to show merging capabilities
```

**File Processing Rules:**
- Files are processed in **alphabetical order** (01-, 02-, 03-, etc.)
- **YANG merge semantics**: Global settings use last-wins, groups/rules are additive
- **Error resilience**: Invalid files are skipped with warnings
- **Rule precedence**: Later files get higher precedence numbers automatically

#### Example Multiple Files Usage

```bash
# Load all configurations and show merge results
./target/release/nacm-validator \
    --config-dir nacm-validator-bin/examples/test-configs \
    --user alice \
    --operation read \
    --verbose

# Output shows:
# Loading config directory: "nacm-validator-bin/examples/test-configs"
# Found 5 XML configuration files:
#   1. "01-base.xml"
#   2. "02-operators.xml" 
#   3. "03-commands.xml"
#   4. "invalid.xml"
#   5. "test-file.xml"
# ✓ Successfully loaded: "01-base.xml"
# ✓ Successfully loaded: "02-operators.xml"
# ✓ Successfully loaded: "03-commands.xml"
# ✗ Failed to load "invalid.xml": Syntax error...
# ✓ Successfully loaded: "test-file.xml"
# Warning: 1 out of 5 files failed to load, continuing with 4 valid configurations
# Merging 4 configurations...
# ✓ Configuration merge completed
#   - 4 groups loaded
#   - 3 rule lists loaded
#   - 3 total rules loaded
```

### CLI Tool - Traditional NACM

```bash
# Build the CLI tool (if developing from source)
cargo build --release

# Test data access (standard NACM)
./target/release/nacm-validator \
    --config nacm-validator-lib/examples/data/aaa_ncm_init_secure.xml \
    --user admin \
    --operation exec \
    --rpc edit-config \
    --context netconf
# Output: PERMIT

# Test with denied user  
./target/release/nacm-validator \
    --config nacm-validator-lib/examples/data/aaa_ncm_init_secure.xml \
    --user unknown \
    --operation exec \
    --rpc edit-config \
    --context netconf
# Output: DENY (exit code 1)
```

### CLI Tool - Tail-f ACM Extensions
```bash
# Test command-based access control
./target/release/nacm-validator \
    --config nacm-validator-lib/examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context cli \
    --command "show status"
# Output: PERMIT [LOGGED]

# Test context-aware access
./target/release/nacm-validator \
    --config nacm-validator-lib/examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context netconf \
    --module "ietf-interfaces" \
    --path "/interfaces"
# Output: PERMIT [LOGGED]

# JSON batch processing with enhanced fields
echo '{"user":"alice","operation":"read","context":"cli","command":"show status"}' | \
    ./target/release/nacm-validator \
    --config nacm-validator-lib/examples/data/tailf_acm_example.xml \
    --json-input
# Output: {"decision":"permit","user":"alice","context":"cli","command":"show status","should_log":true,...}
```

### Library Usage
```rust
use nacm_validator::{AccessRequest, NacmConfig, Operation, RequestContext};

let config = NacmConfig::from_xml(&xml_content)?;
let context = RequestContext::CLI;

let request = AccessRequest {
    user: "alice",
    operation: Operation::Read,
    context: Some(&context),
    command: Some("show status"),
    module_name: None,
    rpc_name: None,
    path: None,
};

let result = config.validate(&request);
println!("Access {}: {}", 
         if result.effect == nacm_validator::RuleEffect::Permit { "GRANTED" } else { "DENIED" },
         if result.should_log { "[LOGGED]" } else { "" });
```

### Run Examples
```bash
# NEW: Multiple files configuration demo
./nacm-validator-bin/examples/multiple_files_demo.sh

# Comprehensive feature demonstration
cargo run --example tailf_acm_comprehensive_demo

# Interactive shell examples  
cd nacm-validator-bin/examples && bash bash_examples.sh

# JSON batch processing
cd nacm-validator-bin/examples && bash json_batch_example.sh
```

## 🚀 Features

### NEW: Multiple Configuration Files Support
- **Directory Loading**: Load and merge multiple XML files from a directory using `--config-dir`
- **YANG Merge Semantics**: Proper implementation of YANG merge rules for configuration combining
- **File Precedence**: Alphabetical file ordering determines merge precedence
- **Error Resilience**: Invalid files are skipped with warnings, valid ones continue processing
- **Mutual Exclusion**: `--config` and `--config-dir` options are mutually exclusive for safety
- **Backward Compatible**: Existing `--config` single file usage unchanged
- **Team Workflows**: Enables modular configuration management and team collaboration

### Standard NACM (RFC 8341)
- **XML Configuration Parsing**: Parse real-world NACM XML configurations
- **Rule-based Access Control**: Support for permit/deny rules with precedence
- **Group Management**: User groups with inheritance
- **Operation Support**: Read, Create, Update, Delete, and Exec operations
- **Path Matching**: XPath-style path matching for fine-grained access control
- **RPC-level Control**: Control access to specific NETCONF RPCs
- **Module-based Rules**: Control access to specific YANG modules

### Tail-f ACM Extensions
- **Command Rules**: Access control for CLI and Web UI operations (`<cmdrule>`)
- **Enhanced Logging**: Fine-grained logging control with `log-if-permit`/`log-if-deny`
- **Context-Aware Rules**: Different rules for NETCONF, CLI, WebUI contexts
- **Group ID Mapping**: OS-level group integration with `<gid>` mapping
- **Command Default Policies**: Separate default policies for command operations
- **Symmetric Logging**: Control logging for both permit and deny decisions

## 📋 Prerequisites

- **Rust toolchain** (1.70 or later recommended)
- **Cargo** package manager

## 🔧 Building the Project

```bash
# Clone the repository
git clone <repository-url>
cd nacm-validator

# Build the project (library and CLI tool)
cargo build

# Build in release mode (optimized)
cargo build --release

# Build just the CLI tool
cargo build --bin nacm-validator

# Build just the library
cargo build --lib
```

## 🧪 Running Tests

The project includes comprehensive tests covering XML parsing and access validation:

```bash
# Run all tests
cargo test

# Run tests with detailed output
cargo test -- --nocapture

# Run a specific test
cargo test test_real_nacm_xml

# Run tests and show successful test output
cargo test -- --show-output
```

### Test Coverage

The tests include:
- ✅ XML parsing validation
- ✅ Basic rule matching
- ✅ Real-world NACM configuration parsing
- ✅ Access validation scenarios
- ✅ Group membership resolution

## 📖 Running Examples

### Access Validation Example

The main example demonstrates parsing a real NACM XML file and validating various access scenarios:

```bash
cargo run --example validate_access
```

This example shows:
- Loading NACM configuration from XML
- Validating different user access scenarios
- Demonstrating permit/deny decisions based on rules

### Tail-f ACM Extensions Demo

Run the comprehensive Tail-f ACM demo to see all the advanced features in action:

```bash
cargo run --example tailf_acm_demo
```

This demo showcases:
- Command rules with context awareness (CLI, WebUI, NETCONF)
- Enhanced logging configuration and validation
- Group ID (GID) mapping for external authentication
- ValidationResult with both access decision and logging information
- Context-specific access control policies

**Example Output:**
```
🔧 Tail-f ACM Configuration loaded:
- NACM enabled: true
- Default policies:
  * Data: read=Deny, write=Deny, exec=Deny
  * Commands: cmd_read=Deny, cmd_exec=Deny
- Logging: default_permit=true, default_deny=true
- Groups: ["operators", "admin"]
  * operators (GID: 1000): ["alice", "bob"]
  * admin (GID: 0): ["admin"]
- Rule lists: 2

🔍 Command access validation results:
  ✅ Alice (operator) - CLI show status: PERMIT 📝[LOG]
  ❌ Bob (operator) - CLI reboot: DENY 📝[LOG]
  ✅ Admin - WebUI config backup: PERMIT
...
```

**Example Output:**
```
NACM Configuration loaded:
- NACM enabled: true
- Default policies: read=Deny, write=Deny, exec=Deny
- Groups: ["oper", "admin"]
- Rule lists: 3

Access validation results:
- Admin executing edit-config: ✅ PERMIT
- Oper executing edit-config: ❌ DENY
- Oper modifying NACM config: ❌ DENY
- Guest reading example/misc/data: ✅ PERMIT
- Guest creating example/misc: ✅ PERMIT
- Unknown user reading data: ✅ PERMIT
```

## 📁 Project Structure

```
nacm-validator/
├── nacm-validator-lib/
│   ├── src/lib.rs                          # Main library with Tail-f ACM extensions
│   └── examples/
│       ├── validate_access.rs              # Basic access validation example
│       ├── tailf_acm_demo.rs               # Tail-f ACM features demonstration
│       ├── tailf_acm_comprehensive_demo.rs # Comprehensive feature showcase
│       ├── README.md                       # Examples documentation
│       └── data/
│           ├── aaa_ncm_init.xml            # Basic NACM configuration (insecure)
│           ├── aaa_ncm_init_secure.xml     # Secure NACM configuration  
│           └── tailf_acm_example.xml       # Comprehensive Tail-f ACM example
├── nacm-validator-bin/
│   ├── src/main.rs                         # Enhanced CLI tool with multiple files support
│   └── examples/
│       ├── bash_examples.sh                # Bash integration with Tail-f ACM
│       ├── json_batch_example.sh           # JSON batch processing example
│       ├── multiple_files_demo.sh          # NEW: Multiple files functionality demo
│       └── test-configs/                   # NEW: Example multiple config files
│           ├── 01-base.xml                 # Base configuration
│           ├── 02-operators.xml            # Operator groups and rules
│           ├── 03-commands.xml             # Command-based rules
│           ├── invalid.xml                 # Invalid XML (for error demo)
│           └── test-file.xml               # Additional config (for merging demo)
├── doc/
│   └── rfc-tailf-acm-proposal.md           # Tail-f ACM RFC proposal document
├── Cargo.toml                              # Workspace configuration
└── README.md                               # This file
```

## ⚠️ Security Note

The original `aaa_ncm_init.xml` contains a security vulnerability - it has a catch-all rule that permits access for **any user** (including unknown users). This is dangerous:

```xml
<rule>
  <name>any-access</name>
  <action>permit</action>
</rule>
```

### Testing the Security Issue

```bash
# ❌ INSECURE: Unknown user 'bill' gets access with original config
./target/release/nacm-validator \
    --config examples/data/aaa_ncm_init.xml \
    --user bill \
    --operation exec \
    --rpc edit-config
# Output: PERMIT (this is wrong!)

# ✅ SECURE: Unknown user 'bill' denied with secure config
./target/release/nacm-validator \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user bill \
    --operation exec \
    --rpc edit-config
# Output: DENY (this is correct!)
```

**Always use `aaa_ncm_init_secure.xml` for production-like testing.**

## 🛠️ Using as a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
nacm-validator = "0.2.0"
```

### Basic Library Usage

```rust
use nacm_validator::{AccessRequest, NacmConfig, Operation, RequestContext, ValidationResult, RuleEffect};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load NACM configuration from XML
    let xml_content = std::fs::read_to_string("examples/data/tailf_acm_example.xml")?;
    let config = NacmConfig::from_xml(&xml_content)?;
    
    // Create a data access request
    let netconf_context = RequestContext::NETCONF;
    let data_request = AccessRequest {
        user: "alice",
        module_name: Some("ietf-interfaces"),
        rpc_name: None,
        operation: Operation::Read,
        path: Some("/interfaces"),
        context: Some(&netconf_context),
        command: None,
    };
    
    // Validate the data request
    let result = config.validate(&data_request);
    println!("Data access {}: {}", 
             if result.effect == RuleEffect::Permit { "PERMITTED" } else { "DENIED" },
             if result.should_log { "[LOGGED]" } else { "" });
    
    // Create a command access request (Tail-f extension)
    let cli_context = RequestContext::CLI;
    let command_request = AccessRequest {
        user: "alice",
        module_name: None,
        rpc_name: None,
        operation: Operation::Read,
        path: None,
        context: Some(&cli_context),
        command: Some("show interfaces"),
    };
    
    // Validate the command request
    let cmd_result = config.validate(&command_request);
    println!("Command access {}: {}", 
             if cmd_result.effect == RuleEffect::Permit { "PERMITTED" } else { "DENIED" },
             if cmd_result.should_log { "[LOGGED]" } else { "" });
    
    Ok(())
}
```

### Advanced Library Usage with Context Awareness

```rust
use nacm_validator::{AccessRequest, NacmConfig, Operation, RequestContext, ValidationResult};

fn validate_multi_context_access(config: &NacmConfig, user: &str, command: &str) {
    let contexts = [
        ("CLI", RequestContext::CLI),
        ("WebUI", RequestContext::WebUI), 
        ("NETCONF", RequestContext::NETCONF),
    ];
    
    println!("Validating command '{}' for user '{}' across contexts:", command, user);
    
    for (name, context) in contexts {
        let request = AccessRequest {
            user,
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&context),
            command: Some(command),
        };
        
        let result = config.validate(&request);
        let status = if result.effect == nacm_validator::RuleEffect::Permit { "✅ PERMIT" } else { "❌ DENY" };
        let log_indicator = if result.should_log { " [LOGGED]" } else { "" };
        
        println!("  {}: {}{}", name, status, log_indicator);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let xml_content = std::fs::read_to_string("examples/data/tailf_acm_example.xml")?;
    let config = NacmConfig::from_xml(&xml_content)?;
    
    // Test command access across different contexts
    validate_multi_context_access(&config, "alice", "show status");
    validate_multi_context_access(&config, "bob", "reboot");
    validate_multi_context_access(&config, "charlie", "help");
    
    Ok(())
}
```

The `validate()` method returns a `ValidationResult` struct containing:
- `effect`: `RuleEffect::Permit` or `RuleEffect::Deny`
- `should_log`: Whether this decision should be logged based on the rule's logging configuration (Tail-f ACM extension)

### Key Tail-f ACM Features

#### Command Rules Priority
Command rules take priority over data access rules when a command is specified:

```rust
let request = AccessRequest {
    user: "alice",
    module_name: Some("ietf-interfaces"), // This would normally match data rules
    rpc_name: None,
    operation: Operation::Read,
    path: Some("/interfaces"),
    context: Some(&RequestContext::CLI),
    command: Some("show status"), // Command rules take priority
};

// The validator will check command rules first, then fall back to data rules
let result = config.validate(&request);
```

#### Enhanced Logging Control
Rules can specify granular logging behavior:

```rust
// Check if access decision should be logged
let result = config.validate(&request);
if result.should_log {
    log::info!("Access {} for user {} on command {:?}", 
               if result.effect == RuleEffect::Permit { "granted" } else { "denied" },
               request.user,
               request.command);
}
```

#### Group ID Integration
Groups can include GID mapping for OS-level integration:

```rust
// Configuration parsing includes GID information
let config = NacmConfig::from_xml(&xml_content)?;
for (group_name, group) in &config.groups {
    if let Some(gid) = group.gid {
        println!("Group {} maps to OS GID {}", group_name, gid);
    }
}
```

### Quick CLI Usage

```bash
# Build the CLI tool
cargo build --bin nacm-validator

# Validate a simple request (using secure config)
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user admin \
    --operation exec \
    --rpc edit-config
# Output: PERMIT (exit code 0)

# Test denied access
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user oper \
    --operation exec \
    --rpc edit-config
# Output: DENY (exit code 1)

# Test unknown user (should be denied)
cargo run --bin nacm-validator -- \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user unknown \
    --operation exec \
    --rpc edit-config  
# Output: DENY (exit code 1)
```

## 📚 API Documentation

Generate and view the complete API documentation:

```bash
cargo doc --open
```

This opens the documentation in your browser, showing all available types, traits, and functions.

## 🧩 Core Types

### Key Structures

#### Standard NACM Types
- **`NacmConfig`**: Main configuration containing groups, rule lists, and policies
- **`NacmRule`**: Individual data access control rule  
- **`NacmRuleList`**: Named collection of rules applying to specific groups
- **`NacmGroup`**: User group definition with member list
- **`AccessRequest`**: Represents an access attempt with context information
- **`RuleEffect`**: Permit or Deny decision
- **`Operation`**: CRUD + Exec operations

#### Tail-f ACM Extensions
- **`NacmCommandRule`**: Command-based access control rule
- **`RequestContext`**: Management interface context (CLI, NETCONF, WebUI)
- **`ValidationResult`**: Enhanced result with access decision and logging flag

### Enhanced AccessRequest Structure

```rust
AccessRequest {
    user: "alice",                           // Username making the request
    module_name: Some("ietf-interfaces"),    // YANG module (for data access)
    rpc_name: Some("edit-config"),           // RPC name (for RPC operations)  
    operation: Operation::Read,              // Type of operation
    path: Some("/interfaces/*"),             // XPath or data path
    context: Some(&RequestContext::CLI),     // Request context (Tail-f ACM)
    command: Some("show status"),            // Command (Tail-f ACM)
}
```

### Enhanced ValidationResult

```rust
ValidationResult {
    effect: RuleEffect::Permit,              // Access decision
    should_log: true,                        // Whether to log this decision (Tail-f ACM)
}
```

### Example Rule Structures

#### Standard Data Access Rule
```rust
NacmRule {
    name: "allow-admin-read".to_string(),
    module_name: Some("ietf-interfaces".to_string()),
    rpc_name: None,
    path: Some("/interfaces/*".to_string()),
    access_operations: [Operation::Read].into(),
    effect: RuleEffect::Permit,
    order: 10,
    context: None,                           // Apply to all contexts
    log_if_permit: false,                    // Don't log permits
    log_if_deny: false,                      // Don't log denies
}
```

#### Tail-f ACM Command Rule
```rust
NacmCommandRule {
    name: "cli-show-commands".to_string(),
    context: Some("cli".to_string()),        // Apply only to CLI context
    command: Some("show *".to_string()),     // Wildcard command matching
    access_operations: [Operation::Read].into(),
    effect: RuleEffect::Permit,
    order: 10,
    log_if_permit: true,                     // Log successful commands
    log_if_deny: true,                       // Log blocked commands
    comment: Some("Allow operators to view system state".to_string()),
}
```

#### Enhanced Group with GID
```rust
NacmGroup {
    name: "operators".to_string(),
    users: vec!["alice".to_string(), "bob".to_string()],
    gid: Some(1000),                         // OS group ID mapping (Tail-f ACM)
}
```

### Request Context Enum

```rust
pub enum RequestContext {
    NETCONF,           // NETCONF protocol access
    CLI,               // Command-line interface access
    WebUI,             // Web-based user interface access
    Other(String),     // Custom interface
}

// Context matching supports wildcards
context.matches("*")     // Matches any context
context.matches("cli")   // Matches CLI exactly
```

## �️ Command Line Interface

The project includes a powerful CLI tool with full support for Tail-f ACM extensions, enabling both traditional data access validation and command-based access control from bash scripts and automation.

### Building the CLI

```bash
# Build the CLI tool
cargo build --bin nacm-validator

# Build optimized version
cargo build --bin nacm-validator --release

# The binary will be available at:
# ./target/debug/nacm-validator (debug build)
# ./target/release/nacm-validator (release build)
```

### Basic Usage

```bash
# Standard NACM data access validation
./target/release/nacm-validator \
    --config examples/data/aaa_ncm_init_secure.xml \
    --user admin \
    --operation exec \
    --rpc edit-config

# Tail-f ACM command access validation
./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context cli \
    --command "show status"

# Context-aware data access
./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context netconf \
    --module "ietf-interfaces" \
    --path "/interfaces"

# Output: PERMIT [LOGGED] or DENY [LOGGED] - shows logging indicator
```

### CLI Options

```
Options:
  -c, --config <CONFIG>        Path to the NACM XML configuration file
      --config-dir <DIR>       Path to directory containing multiple XML files (NEW!)
  -u, --user <USER>            Username making the request
  -m, --module <MODULE>        Module name (optional)
  -r, --rpc <RPC>              RPC name (optional)
  -o, --operation <OPERATION>  Operation type [read, create, update, delete, exec]
  -p, --path <PATH>            Path (optional)
  -x, --context <CONTEXT>      Request context [netconf, cli, webui] (Tail-f ACM)
  -C, --command <COMMAND>      Command being executed (Tail-f ACM)
      --format <FORMAT>        Output format [text, json, exit-code]
  -v, --verbose                Verbose output
      --json-input             JSON input mode - read requests from stdin
```

**Multiple Files Usage:**
```bash
# Load all XML files from directory (NEW!)
./target/release/nacm-validator \
    --config-dir /etc/nacm/configs.d \
    --user alice \
    --operation read \
    --verbose

# Files are processed alphabetically: 01-base.xml, 02-groups.xml, etc.
# Later files can override settings from earlier files (YANG merge semantics)

# Cannot combine both options (mutual exclusion)
./target/release/nacm-validator \
    --config single.xml \
    --config-dir multi/ \
    --user alice --operation read
# Error: cannot use both --config and --config-dir
```

### Enhanced Features

#### Context-Aware Validation
```bash
# Different contexts may have different access policies
./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context cli \
    --command "show status"
# Output: PERMIT [LOGGED]

./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context netconf \
    --module "ietf-interfaces"
# Output: PERMIT [LOGGED]
```

#### Enhanced JSON I/O
```bash
# JSON input with Tail-f ACM fields
echo '{"user":"alice","operation":"read","context":"cli","command":"show status"}' | \
    ./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --json-input

# Output includes enhanced fields:
{
  "decision": "permit",
  "user": "alice",
  "operation": "read",
  "context": "cli",
  "command": "show status",
  "should_log": true,
  "config_loaded": true
}
```

### Bash Script Integration

#### Exit Code Based Validation with Context
```bash
#!/bin/bash
CONFIG="examples/data/tailf_acm_example.xml"

# Command-based validation
if ./target/release/nacm-validator \
    --config "$CONFIG" \
    --user alice \
    --operation read \
    --context cli \
    --command "show status" \
    --format exit-code; then
    echo "CLI command access granted"
else
    echo "CLI command access denied"
fi

# Context-aware function
validate_command() {
    local user="$1"
    local context="$2" 
    local command="$3"
    
    if ./target/release/nacm-validator \
        --config "$CONFIG" \
        --user "$user" \
        --operation read \
        --context "$context" \
        --command "$command" \
        --format exit-code; then
        echo "✅ $user can execute '$command' via $context"
    else
        echo "❌ $user cannot execute '$command' via $context"
    fi
}

validate_command "alice" "cli" "show status"
validate_command "alice" "webui" "help"
validate_command "charlie" "cli" "show status"
```

#### JSON Processing with Enhanced Fields
```bash
# Process enhanced JSON output
JSON_OUTPUT=$(./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --user alice \
    --operation read \
    --context cli \
    --command "show interfaces" \
    --format json)

# Extract enhanced fields
DECISION=$(echo "$JSON_OUTPUT" | jq -r '.decision')
SHOULD_LOG=$(echo "$JSON_OUTPUT" | jq -r '.should_log')
CONTEXT=$(echo "$JSON_OUTPUT" | jq -r '.context')
COMMAND=$(echo "$JSON_OUTPUT" | jq -r '.command')

echo "Decision: $DECISION"
echo "Should log: $SHOULD_LOG" 
echo "Context: $CONTEXT"
echo "Command: $COMMAND"
```

#### Batch Processing with Tail-f ACM
```bash
# Create batch requests with enhanced fields
cat > requests.json << 'EOF'
{"user": "alice", "operation": "read", "context": "cli", "command": "show status"}
{"user": "bob", "operation": "exec", "context": "cli", "command": "reboot"}
{"user": "admin", "operation": "read", "context": "netconf", "module": "ietf-interfaces"}
{"user": "charlie", "operation": "read", "context": "webui", "command": "help"}
EOF

# Process batch requests
./target/release/nacm-validator \
    --config examples/data/tailf_acm_example.xml \
    --json-input < requests.json

# Output shows enhanced information:
{"decision":"permit","user":"alice","operation":"read","context":"cli","command":"show status","should_log":true,"config_loaded":true}
{"decision":"deny","user":"bob","operation":"exec","context":"cli","command":"reboot","should_log":true,"config_loaded":true}
{"decision":"permit","user":"admin","operation":"read","context":"netconf","module":"ietf-interfaces","should_log":false,"config_loaded":true}
{"decision":"deny","user":"charlie","operation":"read","context":"webui","command":"help","should_log":true,"config_loaded":true}
```

### Example Scripts and Programs

The project includes comprehensive working examples demonstrating all features:

#### Rust Examples

```bash
# Standard NACM access validation with context awareness
cargo run --example validate_access

# Focused Tail-f ACM extensions demonstration  
cargo run --example tailf_acm_demo

# Comprehensive Tail-f ACM feature showcase
cargo run --example tailf_acm_comprehensive_demo
```

#### Shell Script Examples

```bash
# Interactive bash integration examples with Tail-f ACM
cd nacm-validator-bin/examples && bash bash_examples.sh

# JSON batch processing with enhanced fields
cd nacm-validator-bin/examples && bash json_batch_example.sh
```

#### Example Outputs

**Standard Validation:**
```
NACM Configuration loaded:
- NACM enabled: true
- Standard defaults: read=Deny, write=Deny, exec=Deny
- Command defaults: cmd_read=Permit, cmd_exec=Permit
- Groups: ["oper", "admin"]
- Rule lists: 3

Access validation results:
- Admin executing edit-config (NETCONF): ✅ PERMIT
- Alice - CLI read interfaces (no command rule): ❌ DENY [LOGGED]
- Admin via WebUI (no command - should use data rules): ✅ PERMIT
```

**Comprehensive Tail-f ACM Demo:**
```
🔧 Comprehensive Tail-f ACM Extensions Demo
==================================================
📋 Configuration Summary:
- NACM enabled: true
- Standard defaults: read=Deny, write=Deny, exec=Deny
- Command defaults: cmd_read=Deny, cmd_exec=Deny
- Logging: default_permit=true, default_deny=true

👥 Groups:
  operators (GID: 1000): ["alice", "bob"]
  admin (GID: 0): ["admin"]

📜 Rule Lists:
  1. operator-rules (groups: ["operators"])
     - Standard rules: 1
       • read-interfaces -> Permit [context: netconf]
     - Command rules: 4
       • cli-show-status -> Permit [context: cli] [command: show status]
       • any-help -> Permit [context: *] [command: help]

🧪 Test Scenarios:

1️⃣ Command-Based Access Control:
   ✅ alice (operator) - CLI 'show status': Permit 📝
   ❌ charlie (not in group) - CLI 'show status': Deny 📝
   ✅ admin - CLI 'reboot' (exec operation): Permit

2️⃣ Context-Aware Data Access:  
   ✅ alice - NETCONF read interfaces: Permit 📝
   ❌ alice - CLI read interfaces (no command rule): Deny 📝
   ❌ alice - WebUI read interfaces (no command rule): Deny 📝
```

These examples demonstrate:
- ✅ Standard NACM access validation with real configurations
- ✅ Tail-f ACM command rules with context awareness  
- ✅ ValidationResult usage with logging information
- ✅ CLI integration with exit codes and enhanced output
- ✅ JSON I/O processing with extended fields
- ✅ Batch request processing with context support
- ✅ Error handling for invalid contexts and commands
- ✅ Multi-interface access control simulation
- ✅ Group ID mapping and OS integration patterns

## 🔍 Development

### Adding New Tests

Tests are located in `src/lib.rs` within the `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_scenario() {
        // Your test here
    }
}
```

### Creating New Examples

Add new examples in the `examples/` directory:

```rust
// examples/my_example.rs
use nacm_validator::*;

fn main() {
    // Your example code
}
```

Run with: `cargo run --example my_example`

## 📄 License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0). See the [LICENSE](LICENSE) file for details.

This is a prototype implementation for educational and research purposes.

## 🤝 Contributing

This is a prototype project. Feel free to experiment and extend the functionality!

### Development Commands

```bash
# Format code
cargo fmt

# Run clippy for lints
cargo clippy

# Check without building
cargo check

# Clean build artifacts
cargo clean
```

### Releasing New Versions

For maintainers publishing new releases to crates.io, see the detailed [RELEASE_HOWTO.md](RELEASE_HOWTO.md) guide which covers:

- Pre-release checklist and version management
- Step-by-step publication process for both crates
- Common issues and troubleshooting
- Post-release verification and tasks

## 📖 References

- [RFC 8341 - Network Configuration Access Control Model](https://tools.ietf.org/rfc/rfc8341.txt)
- [YANG Data Modeling Language](https://tools.ietf.org/rfc/rfc7950.txt)  
- [NETCONF Protocol](https://tools.ietf.org/rfc/rfc6241.txt)
- [Tail-f ACM Extensions Proposal](doc/rfc-tailf-acm-proposal.md)

## ✨ What Makes This Implementation Special

### 🎯 **Production-Ready Features**
- **Real-World XML Parsing**: Handles actual NACM configurations from network devices
- **Comprehensive Rule Support**: All RFC 8341 rule types with proper precedence
- **Robust Error Handling**: Graceful parsing errors and validation feedback
- **Performance Optimized**: Rust's zero-cost abstractions for high-performance validation

### 🚀 **Advanced Tail-f ACM Extensions**  
- **Command-Based Rules**: First-class support for CLI/WebUI command validation
- **Context Awareness**: Different policies for different management interfaces
- **Enhanced Logging**: Granular audit trail control with `log-if-permit`/`log-if-deny`
- **OS Integration**: Group ID mapping for external authentication systems
- **Backward Compatible**: Seamless integration with existing NACM deployments

### 🛠️ **Developer Experience**
- **Dual Interface**: Both library API and CLI tool for maximum flexibility  
- **Rich Documentation**: Comprehensive examples and API documentation
- **Type Safety**: Rust's type system prevents common access control bugs
- **Test Coverage**: Extensive test suite with real-world scenarios
- **Shell Integration**: Exit codes and JSON I/O for seamless automation

### 📊 **Integration Patterns**
- **Shell Scripting**: Exit codes and silent modes for bash automation
- **Web APIs**: JSON batch processing for REST service integration  
- **CLI Tools**: Context-aware validation for management interface security
- **Audit Systems**: Enhanced logging for compliance and security monitoring
- **Multi-Tenant**: Group-based access control for shared infrastructure

This implementation bridges the gap between academic NACM specifications and real-world network device security requirements, making enterprise-grade access control accessible to Rust developers and system integrators.
