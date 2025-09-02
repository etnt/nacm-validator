#!/bin/bash
# Multiple Files Configuration Demo
# This script demonstrates the new multiple files functionality in nacm-validator

set -e

echo "=== NACM Validator Multiple Files Demo ==="
echo

# Build the project first
echo "Building nacm-validator..."
cargo build --quiet
echo "✓ Build complete"
echo

# Set up variables
BINARY="../../target/debug/nacm-validator"
TEST_CONFIG_DIR="test-configs"

# Create test scenario function
run_test() {
    local description="$1"
    local user="$2"
    local operation="$3"
    local extra_args="$4"
    
    echo "--- $description ---"
    echo "Command: $BINARY --config-dir $TEST_CONFIG_DIR --user $user --operation $operation $extra_args"
    
    if $BINARY --config-dir "$TEST_CONFIG_DIR" --user "$user" --operation "$operation" $extra_args; then
        echo "✓ PERMIT - Access granted"
    else
        echo "✗ DENY - Access denied"
    fi
    echo
}

echo "Using configuration directory: $TEST_CONFIG_DIR"
echo "Files in directory:"
ls -1 "$TEST_CONFIG_DIR"/*.xml | sed 's|.*/||' | nl
echo

# Test scenarios
echo "=== Testing Different Users and Operations ==="
echo

run_test "Admin user reading data" "alice" "read" "--verbose"

run_test "Admin user executing RPC" "alice" "exec" "--rpc edit-config"

run_test "Operator user reading data (should be permitted)" "charlie" "read"

run_test "Operator user writing data (should be denied)" "charlie" "update"

run_test "Unknown user accessing data (should be denied)" "unknown-user" "read"

run_test "Command access via CLI context" "charlie" "read" "--context cli --command \"show status\""

echo "=== Comparing Single File vs Multiple Files ==="
echo

echo "--- Single file configuration ---"
echo "Command: $BINARY --config $TEST_CONFIG_DIR/01-base.xml --user alice --operation read --verbose"
$BINARY --config "$TEST_CONFIG_DIR/01-base.xml" --user alice --operation read --verbose
echo

echo "--- Multiple files configuration (same user/operation) ---"
echo "Command: $BINARY --config-dir $TEST_CONFIG_DIR --user alice --operation read --verbose"
$BINARY --config-dir "$TEST_CONFIG_DIR" --user alice --operation read --verbose
echo

echo "=== Configuration Merging Demonstration ==="
echo
echo "Notice how the multiple files configuration shows:"
echo "- More groups (merged from all files)"
echo "- More rule lists (combined from all files)" 
echo "- More total rules (accumulated from all files)"
echo
echo "This demonstrates the YANG merge semantics where:"
echo "- Global settings use last-wins strategy"
echo "- Groups and rules are merged additively"
echo "- Rule precedence is maintained across files"

echo
echo "=== Demo Complete ==="
echo "Try experimenting with different users, operations, and contexts!"
echo "Use --help to see all available options."
