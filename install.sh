#!/bin/bash
#
# SecureServer - Installation Script
# ---------------------------------
# This script installs SecureServer to /opt/setup/secureserver
# and can be used to quickly deploy SecureServer on a new system

# Exit on error
set -e

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\e[31mThis script must be run as root. Use sudo or switch to root user.\e[0m"
    exit 1
fi

echo -e "\e[34m===================================================================\e[0m"
echo -e "\e[34m  SecureServer Installation\e[0m"
echo -e "\e[34m===================================================================\e[0m"
echo

# Get current directory
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="/opt/setup/secureserver"

# Create target directory if it doesn't exist
echo -e "\e[34mCreating installation directory at $TARGET_DIR...\e[0m"
mkdir -p "$TARGET_DIR"

# Create necessary subdirectories
echo -e "\e[34mCreating subdirectories...\e[0m"
mkdir -p "$TARGET_DIR/lib"
mkdir -p "$TARGET_DIR/templates/sshd"
mkdir -p "$TARGET_DIR/templates/fail2ban"
mkdir -p "$TARGET_DIR/tests"

# Copy files
echo -e "\e[34mCopying files...\e[0m"
cp "$CURRENT_DIR/secureserver.sh" "$TARGET_DIR/"
cp "$CURRENT_DIR/README.md" "$TARGET_DIR/"

# Copy directories
echo -e "\e[34mCopying library files...\e[0m"
cp -r "$CURRENT_DIR/lib/"* "$TARGET_DIR/lib/" 2>/dev/null || true

echo -e "\e[34mCopying template files...\e[0m"
cp -r "$CURRENT_DIR/templates/sshd/"* "$TARGET_DIR/templates/sshd/" 2>/dev/null || true
cp -r "$CURRENT_DIR/templates/fail2ban/"* "$TARGET_DIR/templates/fail2ban/" 2>/dev/null || true

echo -e "\e[34mCopying test scripts...\e[0m"
cp -r "$CURRENT_DIR/tests/"* "$TARGET_DIR/tests/" 2>/dev/null || true

# Set permissions
echo -e "\e[34mSetting permissions...\e[0m"
chmod +x "$TARGET_DIR/secureserver.sh"
chmod +x "$TARGET_DIR/tests/test-security.sh" 2>/dev/null || true

echo -e "\e[32mSecureServer has been installed to $TARGET_DIR\e[0m"
echo
echo -e "\e[33mTo run SecureServer, use:\e[0m"
echo "  sudo $TARGET_DIR/secureserver.sh"
echo

# Ask if user wants to run the script now
echo -n "Would you like to run SecureServer now? (y/n): "
read -r run_now
if [[ "$run_now" =~ ^[Yy]$ ]]; then
    echo -e "\e[34mLaunching SecureServer...\e[0m"
    "$TARGET_DIR/secureserver.sh"
else
    echo -e "\e[32mInstallation complete. You can run SecureServer later using the command above.\e[0m"
fi