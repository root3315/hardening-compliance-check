#!/usr/bin/env bash
#
# config.sh - Configuration and benchmark definitions
# Contains security benchmark values and configuration settings
#

# Script version
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="hardening-compliance-check"

# Default configuration paths
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly LOGIN_CONFIG="/etc/login.defs"
readonly PAM_CONFIG="/etc/pam.d/common-password"
readonly SYSCTL_CONFIG="/etc/sysctl.conf"
readonly AUDIT_CONFIG="/etc/audit/auditd.conf"
readonly CRON_ALLOW="/etc/cron.allow"
readonly CRON_DENY="/etc/cron.deny"
readonly AT_ALLOW="/etc/at.allow"
readonly AT_DENY="/etc/at.deny"

# Cache configuration
readonly CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/hardening-compliance-check"
readonly CACHE_FILE="${CACHE_DIR}/check_results.cache"
readonly CACHE_VERSION="1"
DEFAULT_CACHE_TTL=3600  # 1 hour in seconds

# Benchmark severity levels
readonly SEVERITY_CRITICAL="critical"
readonly SEVERITY_HIGH="high"
readonly SEVERITY_MEDIUM="medium"
readonly SEVERITY_LOW="low"
readonly SEVERITY_INFO="info"

# Check categories
declare -A CATEGORIES=(
    ["file_permissions"]="File Permissions"
    ["user_accounts"]="User Accounts"
    ["ssh_hardening"]="SSH Configuration"
    ["kernel_hardening"]="Kernel Parameters"
    ["service_hardening"]="Service Configuration"
    ["logging_audit"]="Logging and Auditing"
    ["bootloader"]="Bootloader Security"
    ["network"]="Network Security"
)

# SSH hardening benchmarks (CIS Benchmark aligned)
declare -A SSH_BENCHMARKS=(
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["PermitEmptyPasswords"]="no"
    ["X11Forwarding"]="no"
    ["MaxAuthTries"]="4"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="3"
    ["Protocol"]="2"
    ["AllowAgentForwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["PermitUserEnvironment"]="no"
    ["Ciphers"]="aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr"
    ["MACs"]="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    ["KexAlgorithms"]="curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
    ["LoginGraceTime"]="60"
    ["MaxSessions"]="10"
    ["StrictModes"]="yes"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
)

# SSH benchmark severity levels
declare -A SSH_SEVERITY=(
    ["PermitRootLogin"]="$SEVERITY_CRITICAL"
    ["PasswordAuthentication"]="$SEVERITY_HIGH"
    ["PermitEmptyPasswords"]="$SEVERITY_CRITICAL"
    ["X11Forwarding"]="$SEVERITY_MEDIUM"
    ["MaxAuthTries"]="$SEVERITY_MEDIUM"
    ["ClientAliveInterval"]="$SEVERITY_LOW"
    ["ClientAliveCountMax"]="$SEVERITY_LOW"
    ["Protocol"]="$SEVERITY_HIGH"
    ["AllowAgentForwarding"]="$SEVERITY_LOW"
    ["AllowTcpForwarding"]="$SEVERITY_LOW"
    ["PermitUserEnvironment"]="$SEVERITY_MEDIUM"
    ["Ciphers"]="$SEVERITY_MEDIUM"
    ["MACs"]="$SEVERITY_MEDIUM"
    ["KexAlgorithms"]="$SEVERITY_MEDIUM"
    ["LoginGraceTime"]="$SEVERITY_LOW"
    ["MaxSessions"]="$SEVERITY_LOW"
    ["StrictModes"]="$SEVERITY_HIGH"
    ["IgnoreRhosts"]="$SEVERITY_HIGH"
    ["HostbasedAuthentication"]="$SEVERITY_HIGH"
)

# Kernel parameter benchmarks (sysctl)
declare -A KERNEL_BENCHMARKS=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.default.accept_source_route"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.secure_redirects"]="0"
    ["net.ipv4.conf.default.secure_redirects"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.conf.default.log_martians"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
    ["net.ipv4.conf.all.rp_filter"]="1"
    ["net.ipv4.conf.default.rp_filter"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.conf.all.ignore_icmp_broadcasts"]="1"
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.default.accept_redirects"]="0"
    ["kernel.randomize_va_space"]="2"
    ["kernel.exec-shield"]="1"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.kptr_restrict"]="2"
    ["kernel.unprivileged_bpf_disabled"]="1"
    ["user.max_user_namespaces"]="0"
)

# Kernel benchmark severity levels
declare -A KERNEL_SEVERITY=(
    ["net.ipv4.ip_forward"]="$SEVERITY_HIGH"
    ["net.ipv4.conf.all.send_redirects"]="$SEVERITY_MEDIUM"
    ["net.ipv4.conf.default.send_redirects"]="$SEVERITY_MEDIUM"
    ["net.ipv4.conf.all.accept_source_route"]="$SEVERITY_HIGH"
    ["net.ipv4.conf.default.accept_source_route"]="$SEVERITY_HIGH"
    ["net.ipv4.conf.all.accept_redirects"]="$SEVERITY_MEDIUM"
    ["net.ipv4.conf.default.accept_redirects"]="$SEVERITY_MEDIUM"
    ["net.ipv4.conf.all.secure_redirects"]="$SEVERITY_LOW"
    ["net.ipv4.conf.default.secure_redirects"]="$SEVERITY_LOW"
    ["net.ipv4.conf.all.log_martians"]="$SEVERITY_MEDIUM"
    ["net.ipv4.conf.default.log_martians"]="$SEVERITY_MEDIUM"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="$SEVERITY_MEDIUM"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="$SEVERITY_LOW"
    ["net.ipv4.conf.all.rp_filter"]="$SEVERITY_MEDIUM"
    ["net.ipv4.conf.default.rp_filter"]="$SEVERITY_MEDIUM"
    ["net.ipv4.tcp_syncookies"]="$SEVERITY_HIGH"
    ["net.ipv4.conf.all.ignore_icmp_broadcasts"]="$SEVERITY_MEDIUM"
    ["net.ipv6.conf.all.accept_redirects"]="$SEVERITY_MEDIUM"
    ["net.ipv6.conf.default.accept_redirects"]="$SEVERITY_MEDIUM"
    ["kernel.randomize_va_space"]="$SEVERITY_CRITICAL"
    ["kernel.exec-shield"]="$SEVERITY_HIGH"
    ["kernel.dmesg_restrict"]="$SEVERITY_MEDIUM"
    ["kernel.kptr_restrict"]="$SEVERITY_HIGH"
    ["kernel.unprivileged_bpf_disabled"]="$SEVERITY_HIGH"
    ["user.max_user_namespaces"]="$SEVERITY_MEDIUM"
)

# File permission benchmarks
declare -A FILE_PERM_BENCHMARKS=(
    ["/etc/passwd"]="644"
    ["/etc/shadow"]="600"
    ["/etc/group"]="644"
    ["/etc/gshadow"]="600"
    ["/etc/hosts"]="644"
    ["/etc/hosts.allow"]="644"
    ["/etc/hosts.deny"]="644"
    ["/etc/ssh/sshd_config"]="600"
    ["/etc/crontab"]="600"
    ["/etc/cron.hourly"]="700"
    ["/etc/cron.daily"]="700"
    ["/etc/cron.weekly"]="700"
    ["/etc/cron.monthly"]="700"
    ["/etc/cron.d"]="700"
    ["/var/log"]="755"
    ["/var/log/messages"]="640"
    ["/var/log/secure"]="600"
    ["/var/log/auth.log"]="640"
    ["/boot/grub/grub.cfg"]="600"
    ["/boot/grub2/grub.cfg"]="600"
)

# File permission severity levels
declare -A FILE_PERM_SEVERITY=(
    ["/etc/passwd"]="$SEVERITY_HIGH"
    ["/etc/shadow"]="$SEVERITY_CRITICAL"
    ["/etc/group"]="$SEVERITY_MEDIUM"
    ["/etc/gshadow"]="$SEVERITY_CRITICAL"
    ["/etc/hosts"]="$SEVERITY_LOW"
    ["/etc/hosts.allow"]="$SEVERITY_LOW"
    ["/etc/hosts.deny"]="$SEVERITY_LOW"
    ["/etc/ssh/sshd_config"]="$SEVERITY_HIGH"
    ["/etc/crontab"]="$SEVERITY_HIGH"
    ["/etc/cron.hourly"]="$SEVERITY_HIGH"
    ["/etc/cron.daily"]="$SEVERITY_HIGH"
    ["/etc/cron.weekly"]="$SEVERITY_HIGH"
    ["/etc/cron.monthly"]="$SEVERITY_HIGH"
    ["/etc/cron.d"]="$SEVERITY_HIGH"
    ["/var/log"]="$SEVERITY_MEDIUM"
    ["/var/log/messages"]="$SEVERITY_MEDIUM"
    ["/var/log/secure"]="$SEVERITY_HIGH"
    ["/var/log/auth.log"]="$SEVERITY_HIGH"
    ["/boot/grub/grub.cfg"]="$SEVERITY_HIGH"
    ["/boot/grub2/grub.cfg"]="$SEVERITY_HIGH"
)

# Services that should be disabled
DISABLED_SERVICES=(
    "avahi-daemon"
    "cups"
    "nfs"
    "rpcbind"
    "rsh"
    "rlogin"
    "telnet"
    "tftp"
    "ypbind"
    "xinetd"
)

# Services that should be enabled
ENABLED_SERVICES=(
    "sshd"
    "firewalld"
    "auditd"
)

# Dangerous filesystems that should be disabled
DISABLED_FILESYSTEMS=(
    "cramfs"
    "freevxfs"
    "jffs2"
    "hfs"
    "hfsplus"
    "squashfs"
    "udf"
    "vfat"
)

# UID range for regular users
readonly MIN_UID=1000
readonly MAX_UID=65533

# Password policy benchmarks
declare -A PASSWORD_BENCHMARKS=(
    ["PASS_MAX_DAYS"]="90"
    ["PASS_MIN_DAYS"]="7"
    ["PASS_WARN_AGE"]="14"
    ["LOGIN_RETRIES"]="3"
    ["LOGIN_TIMEOUT"]="60"
    ["UID_MIN"]="1000"
    ["GID_MIN"]="1000"
)

# Output format options
readonly FORMAT_TEXT="text"
readonly FORMAT_JSON="json"
readonly FORMAT_CSV="csv"

# Default output format
DEFAULT_FORMAT="$FORMAT_TEXT"

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EXIT_PARTIAL=2
readonly EXIT_SKIP=3
