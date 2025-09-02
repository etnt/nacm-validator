#!/bin/bash

# Multiple Files Configuration Example
# ====================================
# This script demonstrates the new multiple files functionality in NACM Validator,
# showing how configuration can be split across multiple XML files and merged
# according to YANG merge semantics.

set -e

echo "🚀 NACM Validator - Multiple Files Configuration Demo"
echo "======================================================"
echo

# Build the project if needed
if [ ! -f "./target/debug/nacm-validator" ]; then
    echo "🔧 Building NACM validator..."
    cargo build
    echo
fi

NACM_VALIDATOR="./target/debug/nacm-validator"
CONFIG_DIR="test-configs"

echo "📁 Configuration Directory Structure:"
echo "   $CONFIG_DIR/"
for file in "$CONFIG_DIR"/*.xml; do
    if [ -f "$file" ]; then
        echo "   ├── $(basename "$file")"
    fi
done
echo

echo "📋 Individual Configuration Files:"
echo

# Show content of each configuration file
for file in "$CONFIG_DIR"/*.xml; do
    if [ -f "$file" ] && [[ $(basename "$file") =~ ^[0-9] ]]; then
        echo "━━━ $(basename "$file") ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        # Extract key information from each file
        echo "📄 Content summary:"
        
        # Extract groups
        if grep -q "<group>" "$file" 2>/dev/null; then
            echo "   Groups:"
            grep -A 1 "<name>" "$file" | grep -v "^--$" | while IFS= read -r line; do
                if [[ $line =~ \<name\>([^<]+)\</name\> ]]; then
                    group_name="${BASH_REMATCH[1]}"
                    echo "   - $group_name"
                fi
            done
        fi
        
        # Extract rule lists
        if grep -q "<rule-list>" "$file" 2>/dev/null; then
            echo "   Rule Lists:"
            grep -A 10 "<rule-list>" "$file" | grep "<name>" | head -5 | while IFS= read -r line; do
                if [[ $line =~ \<name\>([^<]+)\</name\> ]]; then
                    rule_name="${BASH_REMATCH[1]}"
                    echo "   - $rule_name"
                fi
            done
        fi
        
        # Show command rules if present
        if grep -q "<cmdrule>" "$file" 2>/dev/null; then
            echo "   Command Rules: Present ✓"
        fi
        echo
    fi
done

echo "🔍 Testing Multiple Files Functionality"
echo "======================================="
echo

# Test 1: Load multiple files and show merge results
echo "1️⃣ Loading and merging all configuration files:"
echo "   Command: $NACM_VALIDATOR --config-dir $CONFIG_DIR --user alice --operation read --verbose"
echo
$NACM_VALIDATOR --config-dir "$CONFIG_DIR" --user alice --operation read --verbose
echo

# Test 2: Different users with different group memberships
echo "2️⃣ Testing different users across merged configuration:"
echo

users=("alice" "bob" "charlie" "unknown")
operations=("read" "create" "exec")

for user in "${users[@]}"; do
    echo "   Testing user: $user"
    for op in "${operations[@]}"; do
        echo -n "     $op: "
        if $NACM_VALIDATOR --config-dir "$CONFIG_DIR" --user "$user" --operation "$op" --format exit-code 2>/dev/null; then
            echo "✅ PERMIT"
        else
            echo "❌ DENY"
        fi
    done
    echo
done

# Test 3: Command-based access (Tail-f ACM extension)
echo "3️⃣ Testing command-based access control:"
echo

commands=("show status" "show config" "help" "reboot")
contexts=("cli" "webui")

for user in "alice" "charlie"; do
    echo "   User: $user"
    for context in "${contexts[@]}"; do
        for command in "${commands[@]}"; do
            echo -n "     $context '$command': "
            if $NACM_VALIDATOR --config-dir "$CONFIG_DIR" --user "$user" --operation read --context "$context" --command "$command" --format exit-code 2>/dev/null; then
                echo "✅ PERMIT"
            else
                echo "❌ DENY"
            fi
        done
    done
    echo
done

# Test 4: Compare single file vs multiple files
echo "4️⃣ Comparing single file vs multiple files approach:"
echo

echo "   Single file (01-base.xml only):"
echo -n "     alice read: "
if $NACM_VALIDATOR --config "$CONFIG_DIR/01-base.xml" --user alice --operation read --format exit-code 2>/dev/null; then
    echo "✅ PERMIT"
else
    echo "❌ DENY"
fi

echo -n "     bob read: "
if $NACM_VALIDATOR --config "$CONFIG_DIR/01-base.xml" --user bob --operation read --format exit-code 2>/dev/null; then
    echo "✅ PERMIT"
else
    echo "❌ DENY"
fi

echo "   Multiple files (merged configuration):"
echo -n "     alice read: "
if $NACM_VALIDATOR --config-dir "$CONFIG_DIR" --user alice --operation read --format exit-code 2>/dev/null; then
    echo "✅ PERMIT"
else
    echo "❌ DENY"
fi

echo -n "     bob read: "
if $NACM_VALIDATOR --config-dir "$CONFIG_DIR" --user bob --operation read --format exit-code 2>/dev/null; then
    echo "✅ PERMIT"
else
    echo "❌ DENY"
fi
echo

# Test 5: Error handling with invalid files
echo "5️⃣ Testing error handling with mixed valid/invalid files:"
echo "   (Note: Some files may fail to load, but valid ones should still work)"
echo
$NACM_VALIDATOR --config-dir "$CONFIG_DIR" --user alice --operation read --verbose 2>&1 | grep -E "(✓|✗|Warning:|groups loaded|rule lists loaded)"
echo

# Test 6: JSON output with merged configuration
echo "6️⃣ JSON output with merged configuration:"
echo
echo '{"user": "alice", "operation": "read", "context": "cli", "command": "show status"}' | \
    $NACM_VALIDATOR --config-dir "$CONFIG_DIR" --json-input --format json | jq .
echo

echo "🎯 Key Benefits of Multiple Files Approach:"
echo "============================================="
echo "✅ Modularity: Split configuration into logical components"
echo "✅ Team Collaboration: Different teams can manage separate files" 
echo "✅ Environment-Specific: Override settings per environment"
echo "✅ Maintenance: Easier to update specific parts of configuration"
echo "✅ Version Control: Better diff and merge capabilities"
echo "✅ Backward Compatible: Still supports single --config files"
echo "✅ Error Resilience: Invalid files don't break the entire configuration"
echo "✅ YANG Compliance: Implements proper YANG merge semantics"
echo

echo "📖 Usage Patterns:"
echo "=================="
echo "# Load from directory:"
echo "nacm-validator --config-dir /etc/nacm/configs.d --user alice --operation read"
echo
echo "# Traditional single file (still works):"  
echo "nacm-validator --config /etc/nacm/main.xml --user alice --operation read"
echo
echo "# Cannot use both (mutual exclusion):"
echo "nacm-validator --config main.xml --config-dir configs/ # ❌ ERROR"
echo

echo "🏁 Demo completed successfully!"
