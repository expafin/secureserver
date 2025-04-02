#!/bin/bash
#
# SecureServer - AlmaLinux Server Security Hardening
# --------------------------------------------------
# This script implements security best practices for AlmaLinux servers.
# It handles both new server setup and existing server hardening,
# checking for existing configurations before making changes.
# Authors: SecureServer Project
# License: MIT

# Exit on error
set -e

# Base directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/opt/.env"

# Source helper functions
source "$SCRIPT_DIR/lib/functions.sh"

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    print_color "red" "This script must be run as root. Use sudo or switch to root user."
    exit 1
fi

print_section "SecureServer - AlmaLinux Server Security Hardening"

# Test network connectivity before starting
print_color "blue" "Testing network connectivity..."
if ! ping -c 1 google.com &>/dev/null; then
    print_color "yellow" "Warning: Internet connectivity issue detected. Some features may not work properly."
fi

# System update
print_section "Updating System Packages"
print_color "blue" "Running system update..."
dnf update -y
print_color "green" "System packages updated successfully."

# Install essential packages
print_color "blue" "Installing essential packages..."
dnf install nc -y
print_color "green" "Netcat (nc) installed successfully."

# Define template and configuration paths
TEMPLATES_DIR="$SCRIPT_DIR/templates"
SSH_TEMPLATE="$TEMPLATES_DIR/sshd/sshd_config"
FAIL2BAN_TEMPLATE="$TEMPLATES_DIR/fail2ban/jail.local"

# Check if templates exist
if [ ! -f "$SSH_TEMPLATE" ]; then
    print_color "red" "Error: SSH template not found at $SSH_TEMPLATE"
    print_color "red" "Please make sure the template files are in place before running this script."
    exit 1
fi

if [ ! -f "$FAIL2BAN_TEMPLATE" ]; then
    print_color "red" "Error: Fail2ban template not found at $FAIL2BAN_TEMPLATE"
    print_color "red" "Please make sure the template files are in place before running this script."
    exit 1
fi

# Set USERNAME to the user who executed sudo
USERNAME="$SUDO_USER"
if [ -z "$USERNAME" ]; then
    # Try to determine the user another way if SUDO_USER is not set
    USERNAME=$(logname 2>/dev/null || echo "")
    
    if [ -z "$USERNAME" ]; then
        print_color "yellow" "Warning: Could not determine the username automatically."
        read -p "Please enter the username for server administration: " USERNAME
        if [ -z "$USERNAME" ]; then
            print_color "red" "Error: Username is required."
            exit 1
        fi
    fi
fi

# Verify the user exists
if ! id "$USERNAME" &>/dev/null; then
    print_color "yellow" "User $USERNAME does not exist. Creating user..."
    useradd -m -s /bin/bash "$USERNAME"
    
    # Set password for the new user
    print_color "blue" "Setting password for $USERNAME"
    passwd "$USERNAME"
    
    # Add user to sudoers
    print_color "blue" "Adding $USERNAME to sudoers..."
    usermod -aG wheel "$USERNAME"
fi

# Save USERNAME to .env if not already there
print_color "blue" "Saving configuration to $ENV_FILE"
if ! grep -q "^USERNAME=" "$ENV_FILE" 2>/dev/null; then
    # Create the file if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        mkdir -p "$(dirname "$ENV_FILE")"
        echo "# SecureServer Environment Configuration" > "$ENV_FILE"
        echo "# Created on $(date '+%Y-%m-%d')" >> "$ENV_FILE"
        echo "" >> "$ENV_FILE"
    fi
    echo "USERNAME=$USERNAME" >> "$ENV_FILE"
fi

# Prompt for SSH_PORT if not defined and save it
SSH_PORT=$(grep -E "^SSH_PORT=" "$ENV_FILE" 2>/dev/null | cut -d= -f2)
if [ -z "$SSH_PORT" ]; then
    read -p "Enter custom SSH port (recommended between 1024-65535) [2200]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-2200}
    
    # Validate SSH port
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
        print_color "yellow" "Invalid port number. Using default port 2200."
        SSH_PORT=2200
    fi
    
    # Save to .env file
    if grep -q "^SSH_PORT=" "$ENV_FILE"; then
        # Update existing value
        sed -i "s/^SSH_PORT=.*/SSH_PORT=$SSH_PORT/" "$ENV_FILE"
    else
        # Add new value
        echo "SSH_PORT=$SSH_PORT" >> "$ENV_FILE"
    fi
    print_color "green" "SSH port saved to .env file"
fi

print_color "blue" "Using parameters - Username: $USERNAME, SSH Port: $SSH_PORT"

# User setup
print_section "User Account Setup"

# We already know the user exists since we verified above
print_color "green" "Using existing user: $USERNAME"

# SSH key setup
print_section "SSH Key Configuration"

# Set up SSH directory with proper permissions
SSH_DIR="/home/$USERNAME/.ssh"
if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR"
    print_color "green" "Created $SSH_DIR directory."
fi

# Check if user already has authorized_keys
if [ -f "$SSH_DIR/authorized_keys" ]; then
    print_color "green" "SSH authorized_keys already exists for $USERNAME. Keeping existing keys."
# Check if root has authorized_keys
elif [ -f "/root/.ssh/authorized_keys" ]; then
    print_color "blue" "Copying SSH keys from root to $USERNAME..."
    cp /root/.ssh/authorized_keys "$SSH_DIR/"
    chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$SSH_DIR/authorized_keys"
    print_color "green" "SSH keys copied and permissions set."
else
    print_color "yellow" "No authorized_keys found for root or $USERNAME."
    
    # Offer to create a key
    print_color "blue" "Would you like to create a new SSH key pair for $USERNAME?"
    if confirm "Generate a new SSH key pair?" "yes"; then
        print_color "blue" "Generating new SSH key pair for $USERNAME..."
        
        # Check which user to sudo as
        if [ "$(id -u)" -eq 0 ]; then
            # If running as root, sudo as the target user
            sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "/home/$USERNAME/.ssh/id_ed25519" -N ""
        else
            # If already the target user, just run the command
            ssh-keygen -t ed25519 -f "/home/$USERNAME/.ssh/id_ed25519" -N ""
        fi
        
        # Copy the public key to authorized_keys
        cat "/home/$USERNAME/.ssh/id_ed25519.pub" >> "$SSH_DIR/authorized_keys"
        chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        chmod 600 "$SSH_DIR/authorized_keys"
        
        print_color "green" "SSH key pair generated and added to authorized_keys."
        print_color "blue" "Important: Save this private key to your local machine for SSH access:"
        print_color "blue" "Private key is located at: /home/$USERNAME/.ssh/id_ed25519"
        cat "/home/$USERNAME/.ssh/id_ed25519"
        echo
        print_color "yellow" "WARNING: This is the only time this private key will be displayed!"
        print_color "yellow" "Copy it now to your local machine."
        echo
        read -p "Press Enter once you have copied the private key..." _
    else
        print_color "red" "WARNING: No SSH keys found! Password authentication will remain enabled."
        print_color "yellow" "You should manually set up SSH keys for $USERNAME before restricting SSH access."
        
        # Keep password authentication enabled
        KEEP_PASSWORD_AUTH=true
        
        read -p "Press Enter to continue..." _
    fi
fi

# Check if SSH is already configured securely
SSH_CONFIG_SECURE=true
SSH_ROOT_LOGIN=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config || echo "")
SSH_PASSWORD_AUTH=$(grep -E "^PasswordAuthentication" /etc/ssh/sshd_config || echo "")
SSH_PUBKEY_AUTH=$(grep -E "^PubkeyAuthentication" /etc/ssh/sshd_config || echo "")

if [ -z "$SSH_ROOT_LOGIN" ] || [[ "$SSH_ROOT_LOGIN" != *"no"* ]]; then
    SSH_CONFIG_SECURE=false
fi

if [ -z "$SSH_PASSWORD_AUTH" ] || [[ "$SSH_PASSWORD_AUTH" != *"no"* ]]; then
    SSH_CONFIG_SECURE=false
fi

if [ -z "$SSH_PUBKEY_AUTH" ] || [[ "$SSH_PUBKEY_AUTH" != *"yes"* ]]; then
    SSH_CONFIG_SECURE=false
fi

if [ "$SSH_CONFIG_SECURE" = true ]; then
    print_color "green" "SSH is already configured securely."
    
    # Update only the port if necessary
    CURRENT_SSH_PORT=$(grep -E "^Port [0-9]+" /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$CURRENT_SSH_PORT" != "$SSH_PORT" ]; then
        print_color "blue" "Updating SSH port from $CURRENT_SSH_PORT to $SSH_PORT..."
        sed -i "s/^Port $CURRENT_SSH_PORT/Port $SSH_PORT/" /etc/ssh/sshd_config
        print_color "green" "SSH port updated."
    else
        print_color "green" "SSH port is already set to $SSH_PORT. No changes needed."
    fi
else
    # Back up SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
    print_color "blue" "Backed up original SSH configuration."
    
    # Configure SSH for better security using the template
    print_color "blue" "Using SSH configuration template..."
    # Replace $SSH_PORT placeholder with actual port
    sed "s/\$SSH_PORT/$SSH_PORT/g" "$SSH_TEMPLATE" > /etc/ssh/sshd_config
    
    # If we decided to keep password authentication enabled
    if [ "$KEEP_PASSWORD_AUTH" = true ]; then
        print_color "yellow" "Keeping password authentication enabled as requested."
        sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
    fi
    
    print_color "green" "SSH configured to use port $SSH_PORT with secure settings."
fi

# Set up firewall
print_section "Firewall Configuration"

# Check if firewalld is installed and running
FIREWALLD_INSTALLED=false
FIREWALLD_RUNNING=false

if command -v firewall-cmd &> /dev/null; then
    FIREWALLD_INSTALLED=true
    if systemctl is-active --quiet firewalld; then
        FIREWALLD_RUNNING=true
    fi
fi

# Install firewalld if not installed
if [ "$FIREWALLD_INSTALLED" = false ]; then
    print_color "blue" "Installing firewalld..."
    dnf install firewalld -y
    FIREWALLD_INSTALLED=true
fi

# Start and enable firewalld if not running
if [ "$FIREWALLD_RUNNING" = false ]; then
    print_color "blue" "Starting and enabling firewalld..."
    systemctl enable firewalld
    systemctl start firewalld
    FIREWALLD_RUNNING=true
else
    print_color "green" "Firewalld is already running."
fi

# Check if SSH port is already allowed in firewall
SSH_PORT_ALLOWED=false
if firewall-cmd --list-ports | grep -q "${SSH_PORT}/tcp"; then
    SSH_PORT_ALLOWED=true
    print_color "green" "Firewall already allows port $SSH_PORT/tcp."
fi

# Configure firewall for new SSH port if not already allowed
if [ "$SSH_PORT_ALLOWED" = false ]; then
    print_color "blue" "Configuring firewall to allow port $SSH_PORT..."
    firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
    print_color "green" "Port $SSH_PORT added to firewall."
fi

# Add web server ports
print_color "blue" "Would you like to allow HTTP (80) and HTTPS (443) ports?"
if confirm "Allow HTTP and HTTPS ports?" "yes"; then
    print_color "blue" "Adding HTTP and HTTPS ports to firewall..."
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=443/tcp
    print_color "green" "Web server ports added to firewall."
else
    print_color "blue" "Skipping HTTP and HTTPS port configuration."
fi

# Explicitly remove port 22 from firewall (regardless of whether it's in use)
if firewall-cmd --list-ports | grep -q "22/tcp" || firewall-cmd --list-services | grep -q "ssh"; then
    print_color "blue" "Removing standard SSH port (22) from firewall configuration..."
    firewall-cmd --permanent --remove-service=ssh
    firewall-cmd --permanent --remove-port=22/tcp
    print_color "green" "Port 22 has been removed from firewall configuration."
    
    # Warning if port 22 is currently in use
    if ss -tuln | grep -q ":22 "; then
        print_color "yellow" "WARNING: Port 22 is currently in use but has been blocked in the firewall."
        print_color "yellow" "Make sure you can connect on the new port $SSH_PORT before ending this session!"
        print_color "yellow" "You may need to restart the SSH service for all changes to take effect."
    fi
else
    print_color "green" "Port 22 is not configured in the firewall."
fi

# Apply firewall changes
print_color "blue" "Applying firewall changes..."
firewall-cmd --reload
print_color "green" "Firewall configuration applied."

# Configure SELinux for the custom SSH port
print_section "Configuring SELinux for Custom SSH Port"

# Check if SELinux is enabled
if getenforce | grep -q -i "enforcing\|permissive"; then
    # Check if the necessary SELinux policy utilities are installed
    if ! command -v semanage &> /dev/null; then
        print_color "blue" "Installing SELinux policy management tools..."
        dnf install -y policycoreutils-python-utils
    fi

    # Check if the custom port is already defined for SSH in SELinux
    SELINUX_PORT_CONFIG=$(semanage port -l | grep "ssh_port_t" | grep -w "$SSH_PORT" || echo "")

    if [ -n "$SELINUX_PORT_CONFIG" ]; then
        print_color "green" "SELinux is already configured to allow SSH on port $SSH_PORT."
    else
        print_color "blue" "Adding port $SSH_PORT to SELinux SSH port configuration..."
        semanage port -a -t ssh_port_t -p tcp "$SSH_PORT"
        print_color "green" "SELinux configured to allow SSH on port $SSH_PORT."
    fi

    # Note about port 22 in SELinux
    print_color "yellow" "Note: Port 22 cannot be removed from SELinux as it's defined in the base policy."
    print_color "blue" "This is not a security concern as long as:"
    print_color "blue" "1. The firewall blocks port 22 (which we've configured)"
    print_color "blue" "2. SSH daemon doesn't listen on port 22 (which we've configured)"
else
    print_color "yellow" "SELinux is disabled on this system. Skipping SELinux configuration."
fi

# Install and configure fail2ban
print_section "Installing Fail2ban"

# Check if fail2ban is already installed
FAIL2BAN_INSTALLED=false
if command -v fail2ban-client &> /dev/null; then
    FAIL2BAN_INSTALLED=true
    print_color "green" "Fail2ban is already installed."
fi

if [ "$FAIL2BAN_INSTALLED" = false ]; then
    # Install EPEL repository
    print_color "blue" "Installing EPEL repository..."
    dnf install epel-release -y

    # Install fail2ban
    print_color "blue" "Installing fail2ban..."
    dnf install fail2ban -y
    print_color "green" "Fail2ban installed."
fi

# Configure fail2ban using template
print_color "blue" "Using fail2ban configuration template..."
# Create the jail.local file from template
mkdir -p /etc/fail2ban
# Replace $SSH_PORT placeholder with actual port
sed "s/\$SSH_PORT/$SSH_PORT/g" "$FAIL2BAN_TEMPLATE" > /etc/fail2ban/jail.local
print_color "green" "Fail2ban configuration created from template."

# Check if fail2ban is running
if systemctl is-active --quiet fail2ban; then
    print_color "green" "Fail2ban is already running."
    systemctl restart fail2ban
    print_color "green" "Fail2ban restarted to apply configuration changes."
else
    print_color "blue" "Starting and enabling Fail2ban..."
    systemctl enable fail2ban
    systemctl start fail2ban
    print_color "green" "Fail2ban started and enabled."
fi

# Set up automatic updates
print_section "Configuring Automatic Updates"

# Check if dnf-automatic is installed
if ! rpm -q dnf-automatic &>/dev/null; then
    print_color "blue" "Installing dnf-automatic..."
    dnf install dnf-automatic -y
else
    print_color "green" "dnf-automatic is already installed."
fi

# Check if automatic updates are already configured
if grep -q "apply_updates = yes" /etc/dnf/automatic.conf; then
    print_color "green" "Automatic updates are already configured."
else
    # Configure automatic updates
    print_color "blue" "Configuring automatic updates..."
    sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
    print_color "green" "Automatic updates configured to apply updates."
fi

# Check if the timer is enabled
if systemctl is-enabled --quiet dnf-automatic.timer; then
    print_color "green" "Automatic updates timer is already enabled."
else
    print_color "blue" "Enabling automatic updates timer..."
    systemctl enable dnf-automatic.timer
    systemctl start dnf-automatic.timer
    print_color "green" "Automatic updates timer enabled and started."
fi

# Configure SELinux
print_section "Configuring SELinux"

# Check SELinux current status
SELINUX_STATUS=$(getenforce)
SELINUX_CONFIG=$(grep "^SELINUX=" /etc/selinux/config | cut -d= -f2)

print_color "blue" "Current SELinux status: $SELINUX_STATUS"
print_color "blue" "SELinux configuration: $SELINUX_CONFIG"

if [ "$SELINUX_CONFIG" != "enforcing" ]; then
    print_color "blue" "Setting SELinux to enforcing mode in configuration (will apply on next reboot)..."
    sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    print_color "green" "SELinux set to enforcing mode in configuration."
else
    print_color "green" "SELinux is already configured for enforcing mode."
fi

# If SELinux is not in enforcing mode, recommend a reboot
if [ "$SELINUX_STATUS" != "Enforcing" ]; then
    print_color "yellow" "NOTE: SELinux is currently not in enforcing mode. A reboot is recommended."
fi

# Secure shared memory
print_section "Securing Shared Memory"

# Check if shared memory is already secured
if grep -q "/run/shm" /etc/fstab; then
    print_color "green" "Shared memory is already secured in /etc/fstab."
else
    print_color "blue" "Securing shared memory..."
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    print_color "green" "Shared memory secured in /etc/fstab."
fi

# Install system auditing
print_section "Installing System Auditing"

# Check if audit is already installed
if rpm -q audit &>/dev/null; then
    print_color "green" "System auditing (audit) is already installed."
else
    print_color "blue" "Installing system auditing..."
    dnf install audit -y
    print_color "green" "System auditing installed."
fi

# Check if auditd is enabled
if systemctl is-enabled --quiet auditd; then
    print_color "green" "Audit daemon (auditd) is already enabled."
else
    print_color "blue" "Enabling audit daemon..."
    systemctl enable auditd
    systemctl start auditd
    print_color "green" "Audit daemon enabled and started."
fi

# Install log monitoring
print_section "Installing Log Monitoring"

# Check if logwatch is already installed
if rpm -q logwatch &>/dev/null; then
    print_color "green" "Logwatch is already installed."
else
    print_color "blue" "Installing logwatch..."
    dnf install logwatch -y
    print_color "green" "Logwatch installed."
fi

# Disable unused services
print_section "Disabling Unnecessary Services"
SERVICES_TO_DISABLE=("bluetooth.service" "cups.service")

for SERVICE in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl list-unit-files | grep -q "$SERVICE"; then
        if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
            print_color "blue" "Disabling $SERVICE..."
            systemctl disable "$SERVICE"
            systemctl stop "$SERVICE"
            print_color "green" "Disabled $SERVICE"
        else
            print_color "green" "Service $SERVICE is already disabled."
        fi
    else
        print_color "yellow" "Service $SERVICE does not exist on this system."
    fi
done

# Set up SSH session timeout
print_section "Setting SSH Timeout"

# Check if timeout is already configured
if [ -f "/etc/profile.d/timeout.sh" ]; then
    print_color "green" "SSH timeout is already configured."
else
    print_color "blue" "Configuring SSH session timeout..."
    cat << EOF >> /etc/profile.d/timeout.sh
if [ -z "\${TMOUT+x}" ]; then
    readonly TMOUT=900
    export TMOUT
fi
EOF
    chmod +x /etc/profile.d/timeout.sh
    print_color "green" "SSH session timeout set to 15 minutes."
fi

# Add to .env file
print_color "blue" "Updating .env file with security settings..."
# Save security date to .env
if ! grep -q "^SECURITY_HARDENED=" "$ENV_FILE" 2>/dev/null; then
    echo "SECURITY_HARDENED=true" >> "$ENV_FILE"
    echo "SECURITY_DATE=\"$(date '+%Y-%m-%d')\"" >> "$ENV_FILE"
fi

# Restart sshd
print_section "Restarting SSH Service"
print_color "blue" "Restarting SSH service to apply changes..."
systemctl restart sshd
print_color "green" "SSH service restarted."

# Run verification tests
print_section "Running Security Verification Tests"

if [ -f "$SCRIPT_DIR/tests/test-security.sh" ]; then
    print_color "blue" "Running security verification tests..."
    bash "$SCRIPT_DIR/tests/test-security.sh"
    if [ $? -eq 0 ]; then
        print_color "green" "Security verification tests passed."
    else
        print_color "yellow" "Some security verification tests failed. Please review the output above."
    fi
else
    print_color "yellow" "Security verification test script not found. Skipping tests."
fi

# Wrap up
print_section "Security Hardening Complete"
print_color "green" "Server has been secured according to best practices."
echo
print_color "yellow" "IMPORTANT REMINDERS:"
echo "1. Your SSH port is now: $SSH_PORT"
echo "2. Only key-based authentication is allowed (unless otherwise configured)"
echo "3. Make sure you can log in as $USERNAME before logging out"
echo
print_color "blue" "To connect to this server in the future:"
echo "ssh $USERNAME@<server-ip> -p $SSH_PORT"
echo
print_color "green" "Testing your configuration:"
echo "- Firewall status: firewall-cmd --list-all"
echo "- Fail2ban status: fail2ban-client status"
echo "- SELinux port configuration: semanage port -l | grep ssh_port_t"
echo "- SSH config check: sshd -T | grep -E 'permitrootlogin|passwordauthentication|port'"
echo

print_color "blue" "Thank you for using SecureServer!"