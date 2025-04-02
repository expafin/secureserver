# SecureServer

SecureServer is a comprehensive security hardening script for AlmaLinux and RHEL-based servers. It automates the implementation of security best practices to help you quickly establish a robust security baseline for ypur Linux servers.

## ✨ Features

### 🔒 Core Security Hardening
- **SSH Hardening**: Uses key-based authentication, custom ports, secure ciphers, and disables root login
- **Firewall Configuration**: Sets up firewalld with secure defaults and custom rules
- **Fail2ban Implementation**: Protects against brute force attacks with intelligent jailing
- **SELinux Configuration**: Properly configures SELinux for enhanced security in enforcing mode
- **System Auditing**: Configures comprehensive system activity logging
 
### 🛡️ Additional Protections
- **Automatic Security Updates**: Ensures your system stays patched against known vulnerabilities
- **Session Security**: Implements timeouts and secure defaults to prevent idle session attacks
- **Secure Shared Memory**: Prevents shared memory exploits
- **Log Monitoring**: Installs and configures logwatch for security event monitoring

### 🧪 Verification & Testing
- **Automated Security Tests**: Runs a comprehensive suite of verification tests post-installation
- **Detailed Reports**: Provides clear pass/fail reporting for each security configuration

## 📋 Requirements

- AlmaLinux 9.x or compatible RHEL-based distribution (CentOS, Rocky Linux, etc.)
- Root access or sudo privileges
- Internet connectivity for package installation

## 🚀 Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/expafin/secureserver.git
   cd secureserver
   ```

2. Make the script executable:
   ```bash
   chmod +x install.sh
   ```

3. Run the script as root:
   ```bash
   sudo ./install.sh
   ```

### Installation Options

The script offers interactive configuration during installation:

- Custom SSH port selection (default: 2200)
- Web server port configuration (HTTP/HTTPS)
- Automatic SSH key generation if needed
- User account creation and configuration

## 📊 Security Verification

After installation, a verification test automatically runs to ensure all security measures were properly applied. Results display:

- ✅ **PASS**: Successfully applied security measure
- ⚠️ **WARN**: Non-critical issue that should be reviewed
- ❌ **FAIL**: Critical security issue that needs to be addressed

Run verification manually anytime:
```bash
sudo /opt/setup/secureserver/tests/test-security.sh
```

## 🔍 What SecureServer Configures

### System Security
- **System Updates**: Updates all packages to latest versions
- **User Configuration**: Configures a secure non-root user with sudo privileges
- **SELinux**: Sets to enforcing mode with proper contexts
- **Shared Memory**: Secures against shared memory-based attacks

### SSH Hardening
- **Custom Port**: Changes SSH port from default 22 to a custom port
- **Key-Based Authentication**: Disables password authentication
- **Root Login**: Disables direct root login
- **Secure Algorithms**: Configures strong ciphers and key exchange methods
- **Session Timeouts**: Implements automatic timeouts for idle sessions

### Firewall & Access Control
- **Firewalld**: Sets up and configures firewalld
- **Port Management**: Blocks default SSH port, opens custom SSH port
- **Fail2ban**: Configures protection against brute force attacks
- **Web Server Rules**: Optional HTTP/HTTPS port configuration

### Monitoring & Updates
- **Automatic Updates**: Configures dnf-automatic for security patches
- **Auditing**: Installs and configures the audit daemon
- **Log Monitoring**: Sets up logwatch for critical event notifications

## 🔌 Project Structure

```
secureserver/
├── lib/
│   └── functions.sh          # Shared utility functions
├── templates/
│   ├── sshd/
│   │   └── sshd_config       # Secure SSH configuration template
│   └── fail2ban/
│       └── jail.local        # Fail2ban configuration template
├── tests/
│   └── test-security.sh      # Security verification script
├── install.sh                # Easy installation script
└── secureserver.sh           # Main security hardening script
```

## 🔧 Customization

SecureServer can be customized through:

1. **Interactive Prompts**: The script asks for important settings during execution
2. **Template Modification**: Edit the template files to adjust security parameters
3. **Environment Variables**: Set variables in `/opt/.env` for persistence

## 📝 Common Usage Examples

### Basic Server Hardening
```bash
sudo ./secureserver.sh
```

### Installation to Standard Location
```bash
sudo ./install.sh
```

### Verification Only
```bash
sudo ./tests/test-security.sh
```

### System Status Check
```bash
source /opt/setup/secureserver/lib/functions.sh
system_status
```

## 🔄 What to Do After Installation

1. Verify you can log in through the new SSH port before closing your session
2. Test your firewall rules to ensure critical services are accessible
3. Review the verification test results and address any warnings
4. Document your new SSH port and access methods for future reference

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⚠️ Security Considerations

- Always maintain a backup of your SSH keys in a secure location
- Regularly run the verification script to ensure your security posture
- Consider running in a test environment before applying to production servers
- The script configures a secure baseline, but additional measures may be needed for compliance with specific standards (PCI-DSS, HIPAA, etc.)

## 🙏 Acknowledgements

- Special thanks to the AlmaLinux/RHEL community
- Inspired by various security benchmarks including CIS (Center for Internet Security)
