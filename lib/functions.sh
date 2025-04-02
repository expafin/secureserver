#!/bin/bash
#
# SecureServer - Shared Functions
# ------------------------------
# Common functions used in the SecureServer script

# Function to print section headers
print_section() {
    echo
    echo "====================================================================="
    echo "  $1"
    echo "====================================================================="
    echo
}

# Function to print colorized text
print_color() {
    local color=$1
    local text=$2
    
    case $color in
        "red")    echo -e "\e[31m$text\e[0m" ;;
        "green")  echo -e "\e[32m$text\e[0m" ;;
        "yellow") echo -e "\e[33m$text\e[0m" ;;
        "blue")   echo -e "\e[34m$text\e[0m" ;;
        "purple") echo -e "\e[35m$text\e[0m" ;;
        "cyan")   echo -e "\e[36m$text\e[0m" ;;
        *) echo "$text" ;;
    esac
}

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to check if a service is running
service_running() {
    systemctl is-active --quiet "$1"
}

# Function to check if a service is enabled
service_enabled() {
    systemctl is-enabled --quiet "$1"
}

# Function to verify if a package is installed
package_installed() {
    rpm -q "$1" &>/dev/null
}

# Function to prompt user for confirmation
confirm() {
    local prompt="$1"
    local default="${2:-no}"
    
    local response
    if [ "$default" = "yes" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -p "$prompt" response
    response=${response:-$default}
    
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Function to prompt for a value with a default
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local variable_name="$3"
    
    read -p "$prompt [$default]: " input
    input=${input:-$default}
    
    # Export the variable
    export "$variable_name"="$input"
    
    # Return the value
    echo "$input"
}

# Function to generate a secure random password
generate_password() {
    local length=${1:-16}
    openssl rand -base64 $length | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+' | head -c $length
}

# Function to log a message
log_message() {
    local level="$1"
    local message="$2"
    local log_file="/var/log/secureserver.log"
    
    # Create log file if it doesn't exist
    if [ ! -f "$log_file" ]; then
        touch "$log_file"
        chmod 644 "$log_file"
    fi
    
    # Get timestamp
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Write to log file
    echo "[$timestamp] [$level] $message" >> "$log_file"
    
    # Also print to console if not silent
    if [ "${SILENT:-false}" != "true" ]; then
        case "$level" in
            ERROR)   print_color "red" "[$level] $message" ;;
            WARNING) print_color "yellow" "[$level] $message" ;;
            INFO)    print_color "green" "[$level] $message" ;;
            DEBUG)   print_color "blue" "[$level] $message" ;;
            *)       echo "[$level] $message" ;;
        esac
    fi
}

# Function to backup a file before modifying it
backup_file() {
    local file="$1"
    local backup_dir="/opt/secureserver-backups"
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$backup_dir" ]; then
        mkdir -p "$backup_dir"
    fi
    
    # Only backup if file exists
    if [ -f "$file" ]; then
        local backup_file="$backup_dir/$(basename "$file").$(date +%Y%m%d%H%M%S).bak"
        cp "$file" "$backup_file"
        log_message "INFO" "Backed up $file to $backup_file"
        return 0
    else
        log_message "WARNING" "Cannot backup $file: File does not exist"
        return 1
    fi
}

# Function to create a system status report
system_status() {
    print_section "System Status Report"
    
    # System info
    print_color "blue" "System Information:"
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p)"
    
    # Load averages
    print_color "blue" "Load Averages:"
    echo "$(uptime | sed 's/.*load average: //')"
    
    # Memory usage
    print_color "blue" "Memory Usage:"
    free -h
    
    # Disk usage
    print_color "blue" "Disk Usage:"
    df -h
    
    # Service status
    print_color "blue" "Service Status:"
    for service in sshd firewalld fail2ban; do
        if systemctl list-unit-files | grep -q "$service"; then
            status=$(systemctl is-active "$service" 2>/dev/null)
            enabled=$(systemctl is-enabled "$service" 2>/dev/null)
            echo "$service: $status (enabled: $enabled)"
        else
            echo "$service: not installed"
        fi
    done
    
    # SELinux status
    print_color "blue" "SELinux Status:"
    echo "$(getenforce)"
    
    # Firewall status
    print_color "blue" "Firewall Status:"
    if command_exists firewall-cmd; then
        echo "Active: $(firewall-cmd --state)"
        echo "Zones: $(firewall-cmd --get-active-zones)"
        echo "Open ports: $(firewall-cmd --list-ports)"
    else
        echo "Firewalld not installed"
    fi
    
    # Return success
    return 0
}

# Export all functions
export -f print_section
export -f print_color
export -f command_exists
export -f service_running
export -f service_enabled
export -f package_installed
export -f confirm
export -f prompt_with_default
export -f generate_password
export -f log_message
export -f backup_file
export -f system_status