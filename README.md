# Linux Hardening Compliance Checker

A comprehensive Bash-based security compliance checker that validates Linux systems against industry-standard hardening benchmarks, including CIS (Center for Internet Security) recommendations.

## Description

This tool performs automated security audits on Linux systems by checking:

- **File Permissions** - Critical system files and their access controls
- **User Accounts** - Empty passwords, UID 0 users, password policies
- **SSH Configuration** - Secure SSH daemon settings
- **Kernel Parameters** - Network and security-related sysctl settings
- **Service Hardening** - Dangerous services that should be disabled
- **Logging & Auditing** - Audit daemon and logging configuration
- **Additional Security** - World-writable files, SUID/SGID binaries

## Installation

### Quick Install

```bash
# Clone or download the project
git clone <repository-url>
cd hardening-compliance-check

# Make scripts executable
chmod +x hardening-compliance-check.sh
chmod +x tests/test_runner.sh
```

### System Requirements

- Linux operating system (Ubuntu, Debian, CentOS, RHEL, Fedora, etc.)
- Bash 4.0 or higher
- Root privileges recommended for complete checks

### No Dependencies

This tool is written entirely in Bash and uses only standard Linux utilities:
- `stat`, `find`, `grep`, `sed`, `awk`
- `sysctl` for kernel parameters
- `systemctl` for service management (optional)

## Usage

### Basic Usage

```bash
# Run all security checks (requires root for full coverage)
sudo ./hardening-compliance-check.sh
```

### Command Line Options

```
Usage: hardening-compliance-check.sh [OPTIONS]

Options:
  -h, --help          Show help message
  -v, --version       Show version information
  -c, --category CAT  Run specific category only
  -o, --output FILE   Write results to output file
  -f, --format FMT    Output format: text, json, csv
  -q, --quiet         Suppress non-essential output
  --no-color          Disable colored output
  --list-categories   List available check categories
  --list-checks       List all available checks
```

### Examples

```bash
# Run all checks
sudo ./hardening-compliance-check.sh

# Run only SSH hardening checks
sudo ./hardening-compliance-check.sh -c ssh_hardening

# Run kernel parameter checks only
sudo ./hardening-compliance-check.sh -c kernel_hardening

# Output results to JSON file
sudo ./hardening-compliance-check.sh -f json -o results.json

# Run with quiet mode
sudo ./hardening-compliance-check.sh -q

# List all available categories
./hardening-compliance-check.sh --list-categories

# List all security checks
./hardening-compliance-check.sh --list-checks
```

### Check Categories

| Category | Description |
|----------|-------------|
| `file_permissions` | System file permission checks |
| `user_accounts` | User account security checks |
| `ssh_hardening` | SSH configuration checks |
| `kernel_hardening` | Kernel parameter checks |
| `service_hardening` | Service configuration checks |
| `logging_audit` | Logging and auditing checks |

## How It Works

### Architecture

```
hardening-compliance-check.sh    # Main entry point
├── lib/
│   ├── utils.sh                 # Utility functions
│   ├── config.sh                # Benchmark definitions
│   └── checks.sh                # Security check implementations
└── tests/
    └── test_runner.sh           # Test suite
```

### Check Process

1. **Initialization** - Load configuration and benchmark definitions
2. **Discovery** - Identify system type and available features
3. **Evaluation** - Compare current settings against benchmarks
4. **Reporting** - Generate compliance report with pass/fail status
5. **Scoring** - Calculate overall compliance percentage

### Benchmark Sources

The security benchmarks are aligned with:

- **CIS Benchmarks** - Center for Internet Security recommendations
- **STIG** - Security Technical Implementation Guides
- **NIST** - National Institute of Standards guidelines
- **Industry Best Practices** - Common hardening recommendations

### Security Checks Performed

#### SSH Hardening (18 checks)
- PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords
- X11Forwarding, MaxAuthTries, ClientAlive settings
- Cryptographic settings (Ciphers, MACs, KexAlgorithms)

#### Kernel Parameters (25+ checks)
- Network security (IP forwarding, redirects, source routing)
- Memory protection (ASLR, exec-shield)
- Information disclosure (dmesg_restrict, kptr_restrict)

#### File Permissions (20+ checks)
- /etc/passwd, /etc/shadow, /etc/group
- SSH configuration, cron directories
- Log files, bootloader configuration

#### User Account Security
- Empty password detection
- Non-root UID 0 user detection
- Password policy enforcement

## Output

### Text Output (Default)

```
============================================================
              LINUX HARDENING COMPLIANCE CHECK
============================================================

  Started: 2024-01-15 10:30:45
  Hostname: server01
  Distribution: ubuntu
  Kernel: 5.15.0-generic

============================================================
                    SSH HARDENING
============================================================

  [✓] SSH PermitRootLogin                                   
  [✓] SSH PasswordAuthentication                            
  [✗] SSH X11Forwarding           - Current: yes (expected: no)
  ...

============================================================
                  COMPLIANCE SUMMARY
============================================================

  Total checks:  65
  Passed:        58
  Failed:        5
  Skipped:       2

  Compliance score: 89%

  Status: PARTIALLY COMPLIANT
```

### JSON Output

```json
{
    "report": {
        "tool": "hardening-compliance-check",
        "version": "1.0.0",
        "timestamp": "2024-01-15T10:30:45+00:00",
        "hostname": "server01",
        "distribution": "ubuntu",
        "kernel": "5.15.0-generic"
    },
    "summary": {
        "total_checks": 65,
        "passed": 58,
        "failed": 5,
        "skipped": 2,
        "compliance_score": 89
    }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (compliant) |
| 1 | One or more checks failed (non-compliant) |
| 2 | Partial compliance (some checks skipped) |
| 3 | Checks were skipped |

## Running Tests

```bash
# Run the test suite
./tests/test_runner.sh

# Run with verbose output
./tests/test_runner.sh --verbose

# Show test help
./tests/test_runner.sh --help
```

## Remediation

When checks fail, consider these remediation steps:

### SSH Configuration
```bash
# Edit /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Apply changes
sudo systemctl restart sshd
```

### Kernel Parameters
```bash
# Add to /etc/sysctl.conf or /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2

# Apply changes
sudo sysctl -p
```

### File Permissions
```bash
# Fix permissions
sudo chmod 600 /etc/shadow
sudo chmod 644 /etc/passwd
```

## Limitations

- Some checks are distribution-specific and may be skipped
- Running as non-root will limit check coverage
- Some kernel parameters may not be available on all systems
- Service checks require systemd or init scripts

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite
5. Submit a pull request

## License

This project is provided as-is for educational and security auditing purposes.

## Disclaimer

This tool is designed for security auditing. Always:
- Test in a non-production environment first
- Understand the implications of security changes
- Backup configurations before making changes
- Follow your organization's change management process

## Version History

- **1.0.0** - Initial release with core security checks
