#!/bin/bash
#
# SecureServer - Security Testing Script
# -------------------------------------
# This script tests the security configuration of the server
# It should be run after secureserver.sh to verify the setup

# Exit on error
set -e

# Base directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="/opt/.env"

# Source the shared functions
source "$SCRIPT_DIR/lib/functions.sh"

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    print_color "red" "This script must be run as root. Use sudo or switch to root user."
    exit 1
fi

print_section "Security Configuration Verification Tests"

# Load SSH port from .env file
SSH_PORT=$(grep -E "^SSH_PORT=" "$ENV_FILE" 2>/dev/null | cut -d= -f2)
if [ -z "$SSH_PORT" ]; then
    print_color "yellow" "Warning: SSH_PORT not found in $ENV_FILE"
    # Try to determine from current config
    SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=22
        print_color "yellow" "Assuming default SSH port 22"
    else
        print_color "blue" "Using SSH port $SSH_PORT from sshd_config"
    fi
fi

# Initialize pass counter
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0
TOTAL_TESTS=0

# Helper function to record test results
record_test() {
    local name=$1
    local result=$2
    local message=$3
    
    TOTAL_TESTS=$((TOTAL_TESTS+1))
    
    case $result in
        "PASS")
            print_color "green" "✓ PASS: $name"
            TESTS_PASSED=$((TESTS_PASSED+1))
            ;;
        "FAIL") 
            print_color "red" "✗ FAIL: $name - $message"
            TESTS_FAILED=$((TESTS_FAILED+1))
            ;;
        "WARN")
            print_color "yellow" "⚠ WARN: $name - $message" 
            TESTS_WARNED=$((TESTS_WARNED+1))
            ;;
        *)
            print_color "blue" "? UNKNOWN: $name - $message"
            ;;
    esac
}

# Test 1: SSH root login disabled
print_color "blue" "Checking if SSH root login is disabled..."
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
    record_test "SSH root login" "PASS" ""
else
    record_test "SSH root login" "FAIL" "Root login should be disabled"
fi

# Test 2: SSH password authentication
print_color "blue" "Checking SSH password authentication..."
if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    record_test "SSH password authentication" "PASS" ""
else
    record_test "SSH password authentication" "WARN" "Password authentication is enabled"
fi

# Test 3: SSH running on non-standard port
print_color "blue" "Checking SSH port configuration..."
if [ "$SSH_PORT" != "22" ]; then
    record_test "SSH non-standard port" "PASS" ""
else
    record_test "SSH non-standard port" "WARN" "SSH is using the default port 22"
fi

# Test 4: Firewall running
print_color "blue" "Checking if firewall is running..."
if systemctl is-active --quiet firewalld; then
    record_test "Firewall status" "PASS" ""
else
    record_test "Firewall status" "FAIL" "Firewall is not running"
fi

# Test 5: Firewall port 22 blocked
print_color "blue" "Checking if default SSH port is blocked in firewall..."
if ! (firewall-cmd --list-ports | grep -q "\b22/tcp\b") && ! (firewall-cmd --list-services | grep -q "ssh"); then
    record_test "Firewall blocks port 22" "PASS" ""
else
    record_test "Firewall blocks port 22" "WARN" "Default SSH port 22 is not blocked in firewall"
fi

# Test 6: Custom SSH port allowed in firewall
print_color "blue" "Checking if custom SSH port is allowed in firewall..."
if firewall-cmd --list-ports | grep -q "${SSH_PORT}/tcp"; then
    record_test "Firewall allows custom SSH port" "PASS" ""
else
    record_test "Firewall allows custom SSH port" "FAIL" "Custom SSH port $SSH_PORT is not allowed in firewall"
fi

# Test 7: SELinux status
print_color "blue" "Checking SELinux status..."
SELINUX_STATUS=$(getenforce)
if [ "$SELINUX_STATUS" = "Enforcing" ]; then
    record_test "SELinux status" "PASS" ""
elif [ "$SELINUX_STATUS" = "Permissive" ]; then
    record_test "SELinux status" "WARN" "SELinux is in permissive mode"
else
    record_test "SELinux status" "FAIL" "SELinux is disabled"
fi

# Test 8: SSH custom port in SELinux
print_color "blue" "Checking if custom SSH port is configured in SELinux..."
if command_exists semanage && semanage port -l | grep "ssh_port_t" | grep -q "${SSH_PORT}"; then
    record_test "SELinux SSH port configuration" "PASS" ""
else
    record_test "SELinux SSH port configuration" "WARN" "Custom SSH port may not be properly configured in SELinux"
fi


# Test 9: Fail2ban installed and running
print_color "blue" "Checking if Fail2ban is installed and running..."
if systemctl is-active --quiet fail2ban; then
    record_test "Fail2ban status" "PASS" ""
else
    record_test "Fail2ban status" "FAIL" "Fail2ban is not running"
fi

# Test 10: Automatic updates enabled
print_color "blue" "Checking if automatic updates are enabled..."
if systemctl is-enabled --quiet dnf-automatic.timer && grep -q "apply_updates = yes" /etc/dnf/automatic.conf; then
    record_test "Automatic updates" "PASS" ""
else
    record_test "Automatic updates" "WARN" "Automatic updates may not be properly configured"
fi

# Test 11: SSH timeout configured
print_color "blue" "Checking SSH timeout configuration..."
if [ -f "/etc/profile.d/timeout.sh" ] && grep -q "TMOUT=900" "/etc/profile.d/timeout.sh"; then
    record_test "SSH timeout" "PASS" ""
else
    record_test "SSH timeout" "WARN" "SSH timeout may not be properly configured"
fi

# Test 12: SSH session timeout configured
print_color "blue" "Checking SSH client alive settings..."
if grep -q "^ClientAliveInterval" /etc/ssh/sshd_config; then
    record_test "SSH client alive interval" "PASS" ""
else
    record_test "SSH client alive interval" "WARN" "SSH client alive interval not set"
fi

# Test 13: Audit daemon running
print_color "blue" "Checking if audit daemon is running..."
if systemctl is-active --quiet auditd; then
    record_test "Audit daemon" "PASS" ""
else
    record_test "Audit daemon" "FAIL" "Audit daemon is not running"
fi

# Print results summary
print_section "Security Test Results Summary"
print_color "green" "Tests passed: $TESTS_PASSED"
print_color "yellow" "Tests with warnings: $TESTS_WARNED"
print_color "red" "Tests failed: $TESTS_FAILED"
print_color "blue" "Total tests: $TOTAL_TESTS"

# Determine overall result
if [ $TESTS_FAILED -eq 0 ]; then
    if [ $TESTS_WARNED -eq 0 ]; then
        print_color "green" "All tests passed! Your server is configured securely."
    else
        print_color "yellow" "All critical tests passed, but there are some warnings to review."
    fi
    exit 0
else
    print_color "red" "Some security tests failed. Please review the results and fix the issues."
    exit 1
fi