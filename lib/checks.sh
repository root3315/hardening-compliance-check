#!/usr/bin/env bash
#
# checks.sh - Security check functions for hardening compliance
# Implements individual security checks against defined benchmarks
#

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
                ((fail_count++))
            else
                print_check_result "SSH $key" "warn" "Not configured"
                ((skip_count++))
            fi
        elif ! validate_config_value "$key" "$current" "$param_type"; then
            # Invalid value format
            print_check_result "SSH $key" "fail" "Invalid format: '$current'"
            ((fail_count++))
            ((invalid_count++))
        elif [[ "$current" == "$expected" ]]; then
            print_check_result "SSH $key" "pass"
            ((pass_count++))
        else
            print_check_result "SSH $key" "fail" "Current: $current (expected: $expected)"
            ((fail_count++))
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "SSH checks: $pass_count passed, $fail_count failed, $skip_count skipped, $invalid_count invalid format"
    else
        log_info "SSH checks: $pass_count passed, $fail_count failed, $skip_count skipped"
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
                ((fail_count++))
            else
                print_check_result "Kernel $param" "skip" "Parameter not available"
                ((skip_count++))
            fi
        elif ! validate_kernel_numeric "$current"; then
            # Invalid value format for kernel parameter
            print_check_result "Kernel $param" "fail" "Invalid format: '$current'"
            ((fail_count++))
            ((invalid_count++))
        elif [[ "$current" == "$expected" ]]; then
            print_check_result "Kernel $param" "pass"
            ((pass_count++))
        else
            print_check_result "Kernel $param" "fail" "Current: $current (expected: $expected)"
            ((fail_count++))
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "Kernel checks: $pass_count passed, $fail_count failed, $skip_count skipped, $invalid_count invalid format"
    else
        log_info "Kernel checks: $pass_count passed, $fail_count failed, $skip_count skipped"
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
            ((skip_count++))
            continue
        fi

        # Validate file path before reading
        if ! validate_file_path "$file"; then
            print_check_result "File $file" "fail" "Invalid path format"
            ((fail_count++))
            ((invalid_count++))
            continue
        fi

        current=$(get_file_perms "$file")

        if [[ -z "$current" ]]; then
            print_check_result "File $file" "skip" "Cannot read permissions"
            ((skip_count++))
        elif ! validate_file_permission "$current"; then
            # Invalid permission format
            print_check_result "File $file" "fail" "Invalid format: '$current'"
            ((fail_count++))
            ((invalid_count++))
        elif [[ "$current" == "$expected" ]]; then
            print_check_result "File $file" "pass"
            ((pass_count++))
        else
            print_check_result "File $file" "fail" "Current: $current (expected: $expected)"
            ((fail_count++))
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "Permission checks: $pass_count passed, $fail_count failed, $skip_count skipped, $invalid_count invalid format"
    else
        log_info "Permission checks: $pass_count passed, $fail_count failed, $skip_count skipped"
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
    
    local empty_pass_users=0
    
    if [[ -f /etc/shadow ]]; then
        while IFS=: read -r username password rest; do
            if [[ "$password" == "" || "$password" == "!" || "$password" == "*" ]]; then
                continue
            fi
            if [[ "$password" =~ ^!?$ ]]; then
                ((empty_pass_users++))
                log_warning "User '$username' has empty or disabled password"
            fi
        done < /etc/shadow
    fi
    
    if [[ $empty_pass_users -eq 0 ]]; then
        print_check_result "No empty passwords" "pass"
        echo ""
        return $EXIT_SUCCESS
    else
        print_check_result "Empty password users found" "fail" "Count: $empty_pass_users"
        echo ""
        return $EXIT_FAILURE
    fi
}

# Check for users with UID 0 (other than root)
check_uid_zero_users() {
    print_subheader "UID 0 User Check"
    echo ""
    
    local uid_zero_users=()
    
    while IFS=: read -r username _ uid rest; do
        if [[ "$uid" == "0" && "$username" != "root" ]]; then
            uid_zero_users+=("$username")
        fi
    done < /etc/passwd
    
    if [[ ${#uid_zero_users[@]} -eq 0 ]]; then
        print_check_result "No non-root UID 0 users" "pass"
        echo ""
        return $EXIT_SUCCESS
    else
        print_check_result "Non-root UID 0 users found" "fail" "Users: ${uid_zero_users[*]}"
        echo ""
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
            ((pass_count++))
        elif ! validate_password_numeric "$current"; then
            # Invalid value format
            print_check_result "Password $key" "fail" "Invalid format: '$current'"
            ((fail_count++))
            ((invalid_count++))
        elif [[ "$key" == "PASS_MAX_DAYS" || "$key" == "PASS_MIN_DAYS" || "$key" == "LOGIN_RETRIES" ]]; then
            # For these, lower or equal is better
            if [[ "$current" -le "$expected" ]]; then
                print_check_result "Password $key" "pass" "Current: $current"
                ((pass_count++))
            else
                print_check_result "Password $key" "fail" "Current: $current (max recommended: $expected)"
                ((fail_count++))
            fi
        else
            if [[ "$current" == "$expected" ]]; then
                print_check_result "Password $key" "pass"
                ((pass_count++))
            else
                print_check_result "Password $key" "fail" "Current: $current (expected: $expected)"
                ((fail_count++))
            fi
        fi
    done

    echo ""
    if [[ $invalid_count -gt 0 ]]; then
        log_warning "Password policy: $pass_count passed, $fail_count failed, $invalid_count invalid format"
    else
        log_info "Password policy: $pass_count passed, $fail_count failed"
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
            ((fail_count++))
        else
            print_check_result "Service $service disabled" "pass"
            ((pass_count++))
        fi
    done
    
    echo ""
    log_info "Service checks: $pass_count passed, $fail_count failed"
    
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
                ((pass_count++))
            else
                print_check_result "Service $service enabled" "warn" "Service not active"
                ((fail_count++))
            fi
        else
            print_check_result "Service $service" "skip" "systemctl not available"
        fi
    done
    
    echo ""
    log_info "Required services: $pass_count passed, $fail_count warnings"
    
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
        ((pass_count++))
    elif [[ -f "$CRON_DENY" ]]; then
        print_check_result "Cron access restricted" "warn" "Using cron.deny instead of cron.allow"
        ((fail_count++))
    else
        print_check_result "Cron access restricted" "fail" "No cron.allow file"
        ((fail_count++))
    fi
    
    # Check at.allow exists or at.deny doesn't exist
    if [[ -f "$AT_ALLOW" ]]; then
        print_check_result "At access restricted" "pass" "at.allow exists"
        ((pass_count++))
    elif [[ -f "$AT_DENY" ]]; then
        print_check_result "At access restricted" "warn" "Using at.deny instead of at.allow"
        ((fail_count++))
    else
        print_check_result "At access restricted" "fail" "No at.allow file"
        ((fail_count++))
    fi
    
    echo ""
    log_info "Access control: $pass_count passed, $fail_count failed"
    
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
        ((pass_count++))
    else
        print_check_result "World-writable files found" "fail" "Count: ${#world_writable_files[@]}"
        ((fail_count++))
        for file in "${world_writable_files[@]:0:5}"; do
            echo "    - $file"
        done
        if [[ ${#world_writable_files[@]} -gt 5 ]]; then
            echo "    ... and $((${#world_writable_files[@]} - 5)) more"
        fi
    fi
    
    echo ""
    log_info "World-writable check: $pass_count passed, $fail_count failed"
    
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
        ((pass_count++))
    else
        print_check_result "Unowned files found" "fail" "Count: ${#unowned_files[@]}"
        ((fail_count++))
        for file in "${unowned_files[@]:0:5}"; do
            echo "    - $file"
        done
        if [[ ${#unowned_files[@]} -gt 5 ]]; then
            echo "    ... and $((${#unowned_files[@]} - 5)) more"
        fi
    fi
    
    echo ""
    log_info "Unowned file check: $pass_count passed, $fail_count failed"
    
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
            return $EXIT_SUCCESS
        else
            print_check_result "Audit daemon running" "fail" "Not running"
            echo ""
            return $EXIT_FAILURE
        fi
    else
        print_check_result "Audit daemon" "skip" "auditctl not installed"
        echo ""
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
        ((pass_count++))
    else
        print_check_result "SUID/SGID in non-standard locations" "warn" "Count: ${#suid_files[@]}"
        ((fail_count++))
        for file in "${suid_files[@]:0:5}"; do
            echo "    - $file"
        done
        if [[ ${#suid_files[@]} -gt 5 ]]; then
            echo "    ... and $((${#suid_files[@]} - 5)) more"
        fi
    fi
    
    echo ""
    log_info "SUID/SGID check: $pass_count passed, $fail_count warnings"
    
    return $EXIT_SUCCESS
}

# Run all checks
run_all_checks() {
    local total_pass=0
    local total_fail=0
    local total_skip=0
    local result
    
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
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    # User accounts
    print_header "USER ACCOUNT SECURITY"
    check_empty_passwords
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_uid_zero_users
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_password_policy
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    # SSH hardening
    print_header "SSH HARDENING"
    check_ssh_config
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    # Kernel hardening
    print_header "KERNEL HARDENING"
    check_kernel_params
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    # Service hardening
    print_header "SERVICE HARDENING"
    check_dangerous_services
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_required_services
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_cron_at_restrictions
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    # Additional security checks
    print_header "ADDITIONAL SECURITY CHECKS"
    check_world_writable
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_unowned_files
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_suid_sgid
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
    esac
    
    check_audit_status
    result=$?
    case $result in
        0) ((total_pass++)) ;;
        1) ((total_fail++)) ;;
        *) ((total_skip++)) ;;
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
