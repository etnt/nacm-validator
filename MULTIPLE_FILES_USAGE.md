# Multiple Files Configuration Guide

The NACM Validator now supports loading and merging multiple NACM configuration files from a directory, implementing proper YANG merge semantics. This feature enables modular configuration management while maintaining full backward compatibility.

## Overview

The multiple files functionality allows you to:

- **Split configuration** across multiple XML files for better organization
- **Merge configurations** automatically using YANG merge semantics
- **Maintain modularity** with team-based or feature-based file organization
- **Handle errors gracefully** - invalid files don't break the entire configuration
- **Preserve compatibility** - single file mode still works as before

## Usage

### Command Line Interface

```bash
# Load multiple files from a directory
nacm-validator --config-dir /path/to/configs --user alice --operation read

# Traditional single file (still supported)
nacm-validator --config /path/to/config.xml --user alice --operation read

# Mutual exclusion - cannot use both
nacm-validator --config file.xml --config-dir configs/ # ❌ ERROR
```

### Directory Structure

```
configs/
├── 01-base.xml          # Base configuration with global settings
├── 02-groups.xml        # Group definitions
├── 03-admin-rules.xml   # Administrator rules
├── 04-user-rules.xml    # Regular user rules
├── 05-commands.xml      # Tail-f ACM command rules
└── invalid.xml          # Invalid files are skipped with warnings
```

Files are processed in alphabetical order by filename, so use prefixes like `01-`, `02-` to control merge order.

## YANG Merge Semantics

The implementation follows YANG merge semantics:

### Leaf Values (Last-Wins Strategy)
Global settings like defaults use the last-wins strategy:

```xml
<!-- File 01-base.xml -->
<read-default>deny</read-default>
<write-default>deny</write-default>

<!-- File 02-overrides.xml -->
<read-default>permit</read-default>
<!-- Result: read-default=permit, write-default=deny -->
```

### List Elements (Additive Merge)
Groups and rules are merged additively:

```xml
<!-- File 01-groups.xml -->
<groups>
    <group>
        <name>admin</name>
        <user-name>alice</user-name>
    </group>
</groups>

<!-- File 02-groups.xml -->
<groups>
    <group>
        <name>admin</name>        <!-- Same group name -->
        <user-name>bob</user-name> <!-- Additional user -->
    </group>
    <group>
        <name>operators</name>     <!-- New group -->
        <user-name>charlie</user-name>
    </group>
</groups>

<!-- Result: admin group has both alice and bob, operators group added -->
```

### Rule Precedence
Rules maintain proper precedence with file-based ordering:

```xml
<!-- File 01-rules.xml (file_index=0) -->
<rule>
    <name>rule1</name>
    <action>permit</action>
    <!-- Internal order: 0 * 10000 + 0 = 0 (highest priority) -->
</rule>

<!-- File 02-rules.xml (file_index=1) -->
<rule>
    <name>rule2</name>
    <action>deny</action>
    <!-- Internal order: 1 * 10000 + 0 = 10000 (lower priority) -->
</rule>
```

Rules from earlier files (alphabetically) have higher precedence.

## Configuration Examples

### Example 1: Base + Environment Overrides

**base-config.xml:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<config xmlns="http://tail-f.com/ns/config/1.0">
    <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
        <enable-nacm>true</enable-nacm>
        <read-default>deny</read-default>
        <write-default>deny</write-default>
        <exec-default>deny</exec-default>
        
        <groups>
            <group>
                <name>admin</name>
                <user-name>admin</user-name>
            </group>
        </groups>
        
        <rule-list>
            <name>admin-rules</name>
            <group>admin</group>
            <rule>
                <name>permit-all</name>
                <action>permit</action>
            </rule>
        </rule-list>
    </nacm>
</config>
```

**development-overrides.xml:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<config xmlns="http://tail-f.com/ns/config/1.0">
    <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
        <read-default>permit</read-default>  <!-- Override for dev environment -->
        
        <groups>
            <group>
                <name>admin</name>
                <user-name>alice</user-name>  <!-- Add dev user to admin group -->
                <user-name>bob</user-name>    <!-- Add another dev user -->
            </group>
            <group>
                <name>developers</name>       <!-- New group for dev environment -->
                <user-name>dev1</user-name>
                <user-name>dev2</user-name>
            </group>
        </groups>
        
        <rule-list>
            <name>dev-rules</name>
            <group>developers</group>
            <rule>
                <name>dev-read-access</name>
                <access-operations>read</access-operations>
                <action>permit</action>
            </rule>
        </rule-list>
    </nacm>
</config>
```

**Usage:**
```bash
nacm-validator --config-dir configs/ --user alice --operation read
# Result: alice (now in admin group) gets PERMIT due to admin rules
```

### Example 2: Team-Based Configuration

**01-global.xml:**
```xml
<!-- Global settings and basic groups -->
<nacm>
    <enable-nacm>true</enable-nacm>
    <read-default>deny</read-default>
    <write-default>deny</write-default>
    <exec-default>deny</exec-default>
    
    <groups>
        <group>
            <name>admins</name>
            <user-name>admin</user-name>
        </group>
    </groups>
</nacm>
```

**02-network-team.xml:**
```xml
<!-- Network team rules -->
<nacm>
    <groups>
        <group>
            <name>network-ops</name>
            <user-name>net-alice</user-name>
            <user-name>net-bob</user-name>
        </group>
    </groups>
    
    <rule-list>
        <name>network-rules</name>
        <group>network-ops</group>
        <rule>
            <name>interfaces-access</name>
            <module-name>ietf-interfaces</module-name>
            <access-operations>read create update delete</access-operations>
            <action>permit</action>
        </rule>
    </rule-list>
</nacm>
```

**03-security-team.xml:**
```xml
<!-- Security team rules -->
<nacm>
    <groups>
        <group>
            <name>security-ops</name>
            <user-name>sec-charlie</user-name>
            <user-name>sec-diana</user-name>
        </group>
    </groups>
    
    <rule-list>
        <name>security-rules</name>
        <group>security-ops</group>
        <rule>
            <name>nacm-config-access</name>
            <module-name>ietf-netconf-acm</module-name>
            <access-operations>read create update delete</access-operations>
            <action>permit</action>
        </rule>
    </rule-list>
</nacm>
```

### Example 3: Tail-f ACM Command Rules

**commands-base.xml:**
```xml
<nacm xmlns:tailf="http://tail-f.com/yang/acm">
    <cmd-read-default>deny</cmd-read-default>
    <cmd-exec-default>deny</cmd-exec-default>
    
    <groups>
        <group>
            <name>operators</name>
            <user-name>op-alice</user-name>
        </group>
    </groups>
</nacm>
```

**commands-cli.xml:**
```xml
<nacm xmlns:tailf="http://tail-f.com/yang/acm">
    <rule-list>
        <name>cli-commands</name>
        <group>operators</group>
        <cmdrule>
            <name>show-commands</name>
            <context>cli</context>
            <command>show *</command>
            <access-operations>read</access-operations>
            <action>permit</action>
            <log-if-permit/>
        </cmdrule>
    </rule-list>
</nacm>
```

## Error Handling

The multiple files loader handles errors gracefully:

### Invalid XML Files
```bash
$ nacm-validator --config-dir configs/ --user alice --operation read --verbose

Loading config directory: "configs"
Found 3 XML configuration files:
  1. "01-valid.xml"
  2. "02-invalid.xml"  
  3. "03-valid.xml"

✓ Successfully loaded: "01-valid.xml"
✗ Failed to load "02-invalid.xml": Syntax: 1:1 Unexpected characters outside the root element
✓ Successfully loaded: "03-valid.xml"

Warning: 1 out of 3 files failed to load, continuing with 2 valid configurations
Merging 2 configurations...
✓ Configuration merge completed

Decision: PERMIT
```

### No Valid Files
```bash
$ nacm-validator --config-dir empty-configs/ --user alice --operation read

Loading config directory: "empty-configs"
Found 0 XML configuration files in directory: "empty-configs"
Error: No XML configuration files found in directory: "empty-configs"
```

### Mixed Valid/Invalid Files
Invalid files are skipped with warnings, but the tool continues with valid files.

## Best Practices

### File Naming Convention
Use numeric prefixes to control load order:
```
configs/
├── 01-globals.xml       # Global settings (highest precedence)
├── 02-base-groups.xml   # Core groups
├── 10-team-a.xml        # Team-specific configs
├── 11-team-b.xml
├── 20-env-dev.xml       # Environment overrides
├── 21-env-prod.xml
└── 99-local.xml         # Local overrides (lowest precedence)
```

### Logical Separation
- **Global settings**: Base configuration, defaults, logging settings
- **Groups**: User and group definitions
- **Data rules**: Standard NACM rules for data access
- **Command rules**: Tail-f ACM command rules for CLI/WebUI
- **Environment**: Environment-specific overrides

### Team Workflows
- **Base team**: Maintains global settings and core groups
- **Feature teams**: Maintain their own rule files
- **Operations**: Manage environment-specific overrides
- **Security**: Review and approve all configuration changes

### Version Control
Structure for better Git workflows:
```
nacm-configs/
├── global/
│   ├── 01-base.xml
│   └── 02-groups.xml
├── teams/
│   ├── network/
│   │   └── network-rules.xml
│   └── security/
│       └── security-rules.xml
├── environments/
│   ├── dev-overrides.xml
│   ├── staging-overrides.xml
│   └── prod-overrides.xml
└── README.md
```

## Migration from Single File

### Step 1: Analyze Current Configuration
```bash
# Test your current single file
nacm-validator --config current-config.xml --user testuser --operation read
```

### Step 2: Split Configuration
Break your configuration into logical files:
- Extract global settings to `01-globals.xml`
- Extract groups to `02-groups.xml`  
- Extract rule lists to separate files by function

### Step 3: Test Migration
```bash
# Create configs directory
mkdir nacm-configs
cp 01-globals.xml 02-groups.xml 03-rules.xml nacm-configs/

# Test multiple files give same result as single file
nacm-validator --config old-config.xml --user testuser --operation read
nacm-validator --config-dir nacm-configs/ --user testuser --operation read
```

### Step 4: Validate Equivalence
Ensure the split configuration behaves identically to the original single file for all test cases.

## Library Usage

The multiple files functionality is also available in the library:

```rust
use nacm_validator::NacmConfig;

// Load and merge multiple configurations
let configs = vec![
    (NacmConfig::from_xml(&xml1)?, 0),
    (NacmConfig::from_xml(&xml2)?, 1),
    (NacmConfig::from_xml(&xml3)?, 2),
];

let merged_config = NacmConfig::merge(configs)?;

// Use merged configuration normally
let result = merged_config.validate(&request);
```

## Troubleshooting

### Configuration Not Loading
- Check file permissions
- Verify XML syntax with `xmllint`
- Use `--verbose` flag for detailed loading information

### Unexpected Behavior
- Check file load order (alphabetical)
- Verify YANG merge semantics understanding
- Use single file mode to isolate issues

### Performance Considerations
- Multiple files add minimal overhead
- XML parsing is cached per file
- Consider file count vs. file size tradeoffs

## Integration Examples

### CI/CD Pipeline
```yaml
# .github/workflows/nacm-validation.yml
name: NACM Configuration Validation
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Install NACM Validator
        run: cargo install nacm-validator-cli
      - name: Validate configurations
        run: |
          for env in dev staging prod; do
            echo "Validating $env environment..."
            nacm-validator --config-dir configs/$env --user testuser --operation read
          done
```

### Docker Integration
```dockerfile
FROM rust:1.70 as builder
COPY . /app
WORKDIR /app
RUN cargo build --release --bin nacm-validator

FROM debian:bullseye-slim
COPY --from=builder /app/target/release/nacm-validator /usr/local/bin/
COPY configs/ /etc/nacm/
CMD ["nacm-validator", "--config-dir", "/etc/nacm", "--json-input"]
```

### Kubernetes ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nacm-configs
data:
  01-base.xml: |
    <?xml version="1.0" encoding="UTF-8"?>
    <config xmlns="http://tail-f.com/ns/config/1.0">
      <!-- Base configuration -->
    </config>
  02-env.xml: |
    <?xml version="1.0" encoding="UTF-8"?>  
    <config xmlns="http://tail-f.com/ns/config/1.0">
      <!-- Environment-specific overrides -->
    </config>
```

This multiple files functionality provides a robust foundation for scalable NACM configuration management while maintaining backward compatibility and following established YANG merge semantics.
