#!/usr/bin/env bash
#
# checks.sh - Security check functions for hardening compliance
# Implements individual security checks against defined benchmarks
#

# Global cache control
USE_CACHE=false
CACHE_HIT_COUNT=0
CACHE_MISS_COUNT=0

# Enable caching
enable_cache() {
    USE_CACHE=true
}

# Disable caching
disable_cache() {
    USE_CACHE=false
}

# Get SSH parameter type for validation
get_ssh_param_type() {
    local param="$1"
    case "$param" in
        PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding|\
        AllowAgentForwarding|AllowTcpForwarding|PermitUserEnvironment|StrictModes|\
        IgnoreRhosts|HostbasedAuthentication)
            echo "boolean"
            ;;
        MaxAuthTries|ClientAliveInterval|ClientAliveCountMax|Protocol|LoginGraceTime|MaxSessions)
            echo "numeric"
            ;;
        Ciphers|MACs|KexAlgorithms)
            echo "crypto"
            ;;
        *)
            echo "string"
            ;;
    esac
}

# Check SSH configuration settings
check_ssh_config() {
    local pass_count=0
    local fail_count=0
    local skip_count=0
    local invalid_count=0

    print_subheader "SSH Configuration Checks"
    echo ""

    if [[ ! -f "$SSH_CONFIG" ]]; then
        log_warning "SSH config file not found: $SSH_CONFIG"
        store_cache_result "ssh_config" "skip" "Config not found"
        return $EXIT_SKIP
    fi

    for key in "${!SSH_BENCHMARKS[@]}"; do
        local expected="${SSH_BENCHMARKS[$key]}"
        local severity="${SSH_SEVERITY[$key]}"
        local current
        local param_type

        param_type=$(get_ssh_param_type "$key")
        current=$(get_config_value "$SSH_CONFIG" "$key" " ")

        # Sanitize the current value
        current=$(sanitize_config_value "$current")

        if [[ -z "$current" ]]; then
            # Key not present - check if it's a critical setting
            if [[ "$severity" == "$SEVERITY_CRITICAL" || "$severity" == "$SEVERITY_HIGH" ]]; then
                print_check_result "SSH $key" "fail" "Not configured (expected: $expected)"
                ((fail_count++)) || true
            else
                print_check_result "SSH $key" "warn" "Not configured"
                ((skip_count++)) || true
            fi
        elif ! validate_config_value "$key" "$current" "$param_type"; then
            # Invalid value format
            print_check_result "SSH $key" "fail" "Invalid format: '$current'"
            ((fail_count++)) || true
            ((invalid_count++)) || true
        elif [[ "$current" == "$expected" ]]; then
            print_check_result "SSH $key" "pass"
            ((pass_count++)) || true
        else
            print_check_result "SSH $key" "fail" "Current: $current (expected: $expected)"
            ((fail_count++)) || true
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "SSH checks: $pass_count passed, $fail_count failed, $skip_count skipped, $invalid_count invalid format"
    else
        log_info "SSH checks: $pass_count passed, $fail_count failed, $skip_count skipped"
    fi

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "ssh_config" "fail" "Failed: $fail_count"
    elif [[ $skip_count -gt 0 ]]; then
        store_cache_result "ssh_config" "skip" "Skipped: $skip_count"
    else
        store_cache_result "ssh_config" "pass" "Passed: $pass_count"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    elif [[ $skip_count -gt 0 ]]; then
        return $EXIT_PARTIAL
    fi
    return $EXIT_SUCCESS
}

# Check kernel parameters
check_kernel_params() {
    local pass_count=0
    local fail_count=0
    local skip_count=0
    local invalid_count=0

    print_subheader "Kernel Parameter Checks"
    echo ""

    if [[ ! -f "$SYSCTL_CONFIG" && ! -d /proc/sys ]]; then
        log_warning "No sysctl configuration found — kernel parameter checks skipped"
        echo ""
        store_cache_result "kernel_params" "skip" "No sysctl config found"
        return $EXIT_SKIP
    fi

    for param in "${!KERNEL_BENCHMARKS[@]}"; do
        local expected="${KERNEL_BENCHMARKS[$param]}"
        local severity="${KERNEL_SEVERITY[$param]}"
        local current

        current=$(get_sysctl "$param" 2>/dev/null)

        # Sanitize the current value
        current=$(sanitize_config_value "$current")

        if [[ -z "$current" ]]; then
            # Parameter not available - might be kernel/distro specific
            if [[ "$severity" == "$SEVERITY_CRITICAL" ]]; then
                print_check_result "Kernel $param" "fail" "Not set (expected: $expected)"
                ((fail_count++)) || true
            else
                print_check_result "Kernel $param" "skip" "Parameter not available"
                ((skip_count++)) || true
            fi
        elif ! validate_kernel_numeric "$current"; then
            # Invalid value format for kernel parameter
            print_check_result "Kernel $param" "fail" "Invalid format: '$current'"
            ((fail_count++)) || true
            ((invalid_count++)) || true
        elif [[ "$current" == "$expected" ]]; then
            print_check_result "Kernel $param" "pass"
            ((pass_count++)) || true
        else
            print_check_result "Kernel $param" "fail" "Current: $current (expected: $expected)"
            ((fail_count++)) || true
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "Kernel checks: $pass_count passed, $fail_count failed, $skip_count skipped, $invalid_count invalid format"
    else
        log_info "Kernel checks: $pass_count passed, $fail_count failed, $skip_count skipped"
    fi

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "kernel_params" "fail" "Failed: $fail_count"
    elif [[ $skip_count -gt 0 ]]; then
        store_cache_result "kernel_params" "skip" "Skipped: $skip_count"
    else
        store_cache_result "kernel_params" "pass" "Passed: $pass_count"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    elif [[ $skip_count -gt 0 ]]; then
        return $EXIT_PARTIAL
    fi
    return $EXIT_SUCCESS
}

# Check file permissions
check_file_permissions() {
    local pass_count=0
    local fail_count=0
    local skip_count=0
    local invalid_count=0

    print_subheader "File Permission Checks"
    echo ""

    for file in "${!FILE_PERM_BENCHMARKS[@]}"; do
        local expected="${FILE_PERM_BENCHMARKS[$file]}"
        local severity="${FILE_PERM_SEVERITY[$file]}"
        local current

        if [[ ! -e "$file" ]]; then
            print_check_result "File $file" "skip" "File does not exist"
            ((skip_count++)) || true
            continue
        fi

        # Validate file path before reading
        if ! validate_file_path "$file"; then
            print_check_result "File $file" "fail" "Invalid path format"
            ((fail_count++)) || true
            ((invalid_count++)) || true
            continue
        fi

        current=$(get_file_perms "$file")

        if [[ -z "$current" ]]; then
            print_check_result "File $file" "skip" "Cannot read permissions"
            ((skip_count++)) || true
        elif ! validate_file_permission "$current"; then
            # Invalid permission format
            print_check_result "File $file" "fail" "Invalid format: '$current'"
            ((fail_count++)) || true
            ((invalid_count++)) || true
        elif [[ "$current" == "$expected" ]]; then
            print_check_result "File $file" "pass"
            ((pass_count++)) || true
        else
            print_check_result "File $file" "fail" "Current: $current (expected: $expected)"
            ((fail_count++)) || true
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "Permission checks: $pass_count passed, $fail_count failed, $skip_count skipped, $invalid_count invalid format"
    else
        log_info "Permission checks: $pass_count passed, $fail_count failed, $skip_count skipped"
    fi

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "file_permissions" "fail" "Failed: $fail_count"
    elif [[ $skip_count -gt 0 ]]; then
        store_cache_result "file_permissions" "skip" "Skipped: $skip_count"
    else
        store_cache_result "file_permissions" "pass" "Passed: $pass_count"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    elif [[ $skip_count -gt 0 ]]; then
        return $EXIT_PARTIAL
    fi
    return $EXIT_SUCCESS
}

# Check for users with empty passwords
check_empty_passwords() {
    print_subheader "Empty Password Check"
    echo ""

    if [[ ! -f /etc/shadow ]]; then
        log_warning "/etc/shadow not found — skipping empty password check"
        echo ""
        store_cache_result "empty_passwords" "skip" "/etc/shadow not found"
        return $EXIT_SKIP
    fi

    if [[ ! -r /etc/shadow ]]; then
        log_warning "/etc/shadow not readable — skipping empty password check (run as root)"
        echo ""
        store_cache_result "empty_passwords" "skip" "/etc/shadow not readable"
        return $EXIT_SKIP
    fi

    local empty_pass_users=0

    while IFS=: read -r username password rest; do
        if [[ "$password" == "" || "$password" == "!" || "$password" == "*" ]]; then
            continue
        fi
        if [[ "$password" =~ ^!?$ ]]; then
            ((empty_pass_users++)) || true
            log_warning "User '$username' has empty or disabled password"
        fi
    done < /etc/shadow

    if [[ $empty_pass_users -eq 0 ]]; then
        print_check_result "No empty passwords" "pass"
        echo ""
        store_cache_result "empty_passwords" "pass" "No empty passwords found"
        return $EXIT_SUCCESS
    else
        print_check_result "Empty password users found" "fail" "Count: $empty_pass_users"
        echo ""
        store_cache_result "empty_passwords" "fail" "Found: $empty_pass_users"
        return $EXIT_FAILURE
    fi
}

# Check for users with UID 0 (other than root)
check_uid_zero_users() {
    print_subheader "UID 0 User Check"
    echo ""

    if [[ ! -f /etc/passwd ]]; then
        log_warning "/etc/passwd not found — skipping UID 0 user check"
        echo ""
        store_cache_result "uid_zero_users" "skip" "/etc/passwd not found"
        return $EXIT_SKIP
    fi

    if [[ ! -r /etc/passwd ]]; then
        log_warning "/etc/passwd not readable — skipping UID 0 user check"
        echo ""
        store_cache_result "uid_zero_users" "skip" "/etc/passwd not readable"
        return $EXIT_SKIP
    fi

    local uid_zero_users=()

    while IFS=: read -r username _ uid rest; do
        if [[ "$uid" == "0" && "$username" != "root" ]]; then
            uid_zero_users+=("$username")
        fi
    done < /etc/passwd

    if [[ ${#uid_zero_users[@]} -eq 0 ]]; then
        print_check_result "No non-root UID 0 users" "pass"
        echo ""
        store_cache_result "uid_zero_users" "pass" "No non-root UID 0 users"
        return $EXIT_SUCCESS
    else
        print_check_result "Non-root UID 0 users found" "fail" "Users: ${uid_zero_users[*]}"
        echo ""
        store_cache_result "uid_zero_users" "fail" "Found: ${uid_zero_users[*]}"
        return $EXIT_FAILURE
    fi
}

# Check password policy
check_password_policy() {
    local pass_count=0
    local fail_count=0
    local invalid_count=0

    print_subheader "Password Policy Checks"
    echo ""

    if [[ ! -f "$LOGIN_CONFIG" ]]; then
        log_warning "Login config not found: $LOGIN_CONFIG"
        store_cache_result "password_policy" "skip" "Config not found"
        return $EXIT_SKIP
    fi

    for key in "${!PASSWORD_BENCHMARKS[@]}"; do
        local expected="${PASSWORD_BENCHMARKS[$key]}"
        local current

        current=$(get_config_value "$LOGIN_CONFIG" "$key" " ")

        # Sanitize the current value
        current=$(sanitize_config_value "$current")

        if [[ -z "$current" ]]; then
            print_check_result "Password $key" "warn" "Not configured (recommended: $expected)"
            ((pass_count++)) || true
        elif ! validate_password_numeric "$current"; then
            # Invalid value format
            print_check_result "Password $key" "fail" "Invalid format: '$current'"
            ((fail_count++)) || true
            ((invalid_count++)) || true
        elif [[ "$key" == "PASS_MAX_DAYS" || "$key" == "PASS_MIN_DAYS" || "$key" == "LOGIN_RETRIES" ]]; then
            # For these, lower or equal is better
            if [[ "$current" -le "$expected" ]]; then
                print_check_result "Password $key" "pass" "Current: $current"
                ((pass_count++)) || true
            else
                print_check_result "Password $key" "fail" "Current: $current (max recommended: $expected)"
                ((fail_count++)) || true
            fi
        else
            if [[ "$current" == "$expected" ]]; then
                print_check_result "Password $key" "pass"
                ((pass_count++)) || true
            else
                print_check_result "Password $key" "fail" "Current: $current (expected: $expected)"
                ((fail_count++)) || true
            fi
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "Password policy: $pass_count passed, $fail_count failed, $invalid_count invalid format"
    else
        log_info "Password policy: $pass_count passed, $fail_count failed"
    fi

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "password_policy" "fail" "Failed: $fail_count"
    else
        store_cache_result "password_policy" "pass" "Passed: $pass_count"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    fi
    return $EXIT_SUCCESS
}

# Check for dangerous services
check_dangerous_services() {
    local pass_count=0
    local fail_count=0
    local skip_count=0

    print_subheader "Dangerous Service Checks"
    echo ""

    for service in "${DISABLED_SERVICES[@]}"; do
        if service_enabled "$service" || service_active "$service"; then
            print_check_result "Service $service disabled" "fail" "Service is active/enabled"
            ((fail_count++)) || true
        else
            print_check_result "Service $service disabled" "pass"
            ((pass_count++)) || true
        fi
    done

    echo ""
    log_info "Service checks: $pass_count passed, $fail_count failed"

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "dangerous_services" "fail" "Failed: $fail_count"
    else
        store_cache_result "dangerous_services" "pass" "Passed: $pass_count"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    fi
    return $EXIT_SUCCESS
}

# Check for required services
check_required_services() {
    local pass_count=0
    local fail_count=0

    print_subheader "Required Service Checks"
    echo ""

    for service in "${ENABLED_SERVICES[@]}"; do
        if command_exists systemctl; then
            if service_enabled "$service" || service_active "$service"; then
                print_check_result "Service $service enabled" "pass"
                ((pass_count++)) || true
            else
                print_check_result "Service $service enabled" "warn" "Service not active"
                ((fail_count++)) || true
            fi
        else
            print_check_result "Service $service" "skip" "systemctl not available"
        fi
    done

    echo ""
    log_info "Required services: $pass_count passed, $fail_count warnings"

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "required_services" "warn" "Warnings: $fail_count"
    else
        store_cache_result "required_services" "pass" "Passed: $pass_count"
    fi

    return $EXIT_SUCCESS
}

# Check cron/at restrictions
check_cron_at_restrictions() {
    local pass_count=0
    local fail_count=0

    print_subheader "Cron/At Access Control Checks"
    echo ""

    # Check cron.allow exists or cron.deny doesn't exist
    if [[ -f "$CRON_ALLOW" ]]; then
        print_check_result "Cron access restricted" "pass" "cron.allow exists"
        ((pass_count++)) || true
    elif [[ -f "$CRON_DENY" ]]; then
        print_check_result "Cron access restricted" "warn" "Using cron.deny instead of cron.allow"
        ((fail_count++)) || true
    else
        print_check_result "Cron access restricted" "fail" "No cron.allow file"
        ((fail_count++)) || true
    fi

    # Check at.allow exists or at.deny doesn't exist
    if [[ -f "$AT_ALLOW" ]]; then
        print_check_result "At access restricted" "pass" "at.allow exists"
        ((pass_count++)) || true
    elif [[ -f "$AT_DENY" ]]; then
        print_check_result "At access restricted" "warn" "Using at.deny instead of at.allow"
        ((fail_count++)) || true
    else
        print_check_result "At access restricted" "fail" "No at.allow file"
        ((fail_count++)) || true
    fi

    echo ""
    log_info "Access control: $pass_count passed, $fail_count failed"

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "cron_at_restrictions" "fail" "Failed: $fail_count"
    else
        store_cache_result "cron_at_restrictions" "pass" "Passed: $pass_count"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    fi
    return $EXIT_SUCCESS
}

# Check for world-writable files in system directories
check_world_writable() {
    local pass_count=0
    local fail_count=0
    local world_writable_files=()

    print_subheader "World-Writable File Checks"
    echo ""

    local system_dirs=("/etc" "/usr" "/bin" "/sbin" "/lib" "/boot")

    for dir in "${system_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                world_writable_files+=("$file")
            done < <(find "$dir" -type f -perm -0002 -print0 2>/dev/null | head -z -n 20)
        fi
    done

    if [[ ${#world_writable_files[@]} -eq 0 ]]; then
        print_check_result "No world-writable system files" "pass"
        ((pass_count++)) || true
    else
        print_check_result "World-writable files found" "fail" "Count: ${#world_writable_files[@]}"
        ((fail_count++)) || true
        for file in "${world_writable_files[@]:0:5}"; do
            echo "    - $file"
        done
        if [[ ${#world_writable_files[@]} -gt 5 ]]; then
            echo "    ... and $((${#world_writable_files[@]} - 5)) more"
        fi
    fi

    echo ""
    log_info "World-writable check: $pass_count passed, $fail_count failed"

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "world_writable" "fail" "Found: ${#world_writable_files[@]}"
    else
        store_cache_result "world_writable" "pass" "No world-writable files"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    fi
    return $EXIT_SUCCESS
}

# Check for unowned files
check_unowned_files() {
    local pass_count=0
    local fail_count=0
    local unowned_files=()

    print_subheader "Unowned File Checks"
    echo ""

    local check_dirs=("/etc" "/usr" "/bin" "/sbin")

    for dir in "${check_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                unowned_files+=("$file")
            done < <(find "$dir" -type f \( -nouser -o -nogroup \) -print0 2>/dev/null | head -z -n 20)
        fi
    done

    if [[ ${#unowned_files[@]} -eq 0 ]]; then
        print_check_result "No unowned system files" "pass"
        ((pass_count++)) || true
    else
        print_check_result "Unowned files found" "fail" "Count: ${#unowned_files[@]}"
        ((fail_count++)) || true
        for file in "${unowned_files[@]:0:5}"; do
            echo "    - $file"
        done
        if [[ ${#unowned_files[@]} -gt 5 ]]; then
            echo "    ... and $((${#unowned_files[@]} - 5)) more"
        fi
    fi

    echo ""
    log_info "Unowned file check: $pass_count passed, $fail_count failed"

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "unowned_files" "fail" "Found: ${#unowned_files[@]}"
    else
        store_cache_result "unowned_files" "pass" "No unowned files"
    fi

    if [[ $fail_count -gt 0 ]]; then
        return $EXIT_FAILURE
    fi
    return $EXIT_SUCCESS
}

# Check audit daemon status
check_audit_status() {
    print_subheader "Audit Daemon Check"
    echo ""

    if command_exists auditctl; then
        local status
        status=$(auditctl -s 2>/dev/null)

        if [[ -n "$status" ]]; then
            print_check_result "Audit daemon running" "pass"
            echo ""
            store_cache_result "audit_status" "pass" "Audit daemon running"
            return $EXIT_SUCCESS
        else
            print_check_result "Audit daemon running" "fail" "Not running"
            echo ""
            store_cache_result "audit_status" "fail" "Audit daemon not running"
            return $EXIT_FAILURE
        fi
    else
        print_check_result "Audit daemon" "skip" "auditctl not installed"
        echo ""
        store_cache_result "audit_status" "skip" "auditctl not installed"
        return $EXIT_SKIP
    fi
}

# Check for SUID/SGID binaries in non-standard locations
check_suid_sgid() {
    local pass_count=0
    local fail_count=0
    local suid_files=()

    print_subheader "SUID/SGID Binary Checks"
    echo ""

    local non_standard_dirs=("/tmp" "/var/tmp" "/home" "/opt")

    for dir in "${non_standard_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                suid_files+=("$file")
            done < <(find "$dir" -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null | head -z -n 20)
        fi
    done

    if [[ ${#suid_files[@]} -eq 0 ]]; then
        print_check_result "No SUID/SGID in non-standard dirs" "pass"
        ((pass_count++)) || true
    else
        print_check_result "SUID/SGID in non-standard locations" "warn" "Count: ${#suid_files[@]}"
        ((fail_count++)) || true
        for file in "${suid_files[@]:0:5}"; do
            echo "    - $file"
        done
        if [[ ${#suid_files[@]} -gt 5 ]]; then
            echo "    ... and $((${#suid_files[@]} - 5)) more"
        fi
    fi

    echo ""
    log_info "SUID/SGID check: $pass_count passed, $fail_count warnings"

    # Store cache result
    if [[ $fail_count -gt 0 ]]; then
        store_cache_result "suid_sgid" "warn" "Found: ${#suid_files[@]}"
    else
        store_cache_result "suid_sgid" "pass" "No SUID/SGID in non-standard locations"
    fi

    return $EXIT_SUCCESS
}

# Run all checks
run_all_checks() {
    local total_pass=0
    local total_fail=0
    local total_skip=0
    local result

    # Initialize cache if enabled
    if [[ "$USE_CACHE" == "true" ]]; then
        init_cache
        write_cache_header
    fi

    print_header "LINUX HARDENING COMPLIANCE CHECK"
    echo "  Started: $(timestamp)"
    echo "  Hostname: $(hostname)"
    echo "  Distribution: $(get_distribution) $(get_distribution_version)"
    echo "  Kernel: $(uname -r)"
    echo ""

    # File permissions
    print_header "FILE PERMISSIONS"
    check_file_permissions
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    # User accounts
    print_header "USER ACCOUNT SECURITY"
    check_empty_passwords
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_uid_zero_users
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_password_policy
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    # SSH hardening
    print_header "SSH HARDENING"
    check_ssh_config
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    # Kernel hardening
    print_header "KERNEL HARDENING"
    check_kernel_params
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    # Service hardening
    print_header "SERVICE HARDENING"
    check_dangerous_services
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_required_services
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_cron_at_restrictions
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    # Additional security checks
    print_header "ADDITIONAL SECURITY CHECKS"
    check_world_writable
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_unowned_files
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_suid_sgid
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    check_audit_status
    result=$?
    case $result in
        0) ((total_pass++)) || true ;;
        1) ((total_fail++)) || true ;;
        *) ((total_skip++)) || true ;;
    esac

    # Summary
    print_header "COMPLIANCE SUMMARY"
    local total=$((total_pass + total_fail + total_skip))
    local pass_pct=0
    if [[ $total -gt 0 ]]; then
        pass_pct=$(( (total_pass * 100) / total ))
    fi

    echo "  Total checks:  $total"
    print_color "$COLOR_GREEN" "  Passed:        $total_pass"
    print_color "$COLOR_RED" "  Failed:        $total_fail"
    print_color "$COLOR_CYAN" "  Skipped:       $total_skip"
    echo ""
    echo "  Compliance score: ${pass_pct}%"
    echo ""

    # Report cache statistics if caching was used
    if [[ "$USE_CACHE" == "true" ]]; then
        if [[ $CACHE_HIT_COUNT -gt 0 || $CACHE_MISS_COUNT -gt 0 ]]; then
            echo "  Cache hits:    $CACHE_HIT_COUNT"
            echo "  Cache misses:  $CACHE_MISS_COUNT"
            echo ""
        fi
    fi

    if [[ $total_fail -eq 0 ]]; then
        print_color "$COLOR_GREEN" "  Status: COMPLIANT"
        return $EXIT_SUCCESS
    elif [[ $pass_pct -ge 70 ]]; then
        print_color "$COLOR_YELLOW" "  Status: PARTIALLY COMPLIANT"
        return $EXIT_PARTIAL
    else
        print_color "$COLOR_RED" "  Status: NON-COMPLIANT"
        return $EXIT_FAILURE
    fi
}
