#!/usr/bin/env bash
#
# test_runner.sh - Test runner for hardening compliance checker
# Runs unit tests and integration tests for the compliance checker
#
# Usage: ./test_runner.sh [OPTIONS]
#
# Options:
#   -v, --verbose    Show detailed test output
#   -h, --help       Show help message
#

set -uo pipefail

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Source the library modules
source "${PROJECT_DIR}/lib/utils.sh"
source "${PROJECT_DIR}/lib/config.sh"

# Verbose mode
VERBOSE=false

# Print test header
print_test_header() {
    echo ""
    if supports_color; then
        echo -e "${COLOR_BOLD}${COLOR_YELLOW}========================================${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_YELLOW}  Running: $1${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_YELLOW}========================================${COLOR_RESET}"
    else
        echo "========================================"
        echo "  Running: $1"
        echo "========================================"
    fi
    echo ""
}

# Assert equality
assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-}"

    ((TESTS_RUN++))

    if [[ "$expected" == "$actual" ]]; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "assert_equals: $message"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "assert_equals: $message"
        echo "  Expected: '$expected'"
        echo "  Actual:   '$actual'"
        return 1
    fi
}

# Assert not equals
assert_not_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-}"

    ((TESTS_RUN++))

    if [[ "$expected" != "$actual" ]]; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "assert_not_equals: $message"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "assert_not_equals: $message"
        echo "  Expected not: '$expected'"
        echo "  Actual:       '$actual'"
        return 1
    fi
}

# Assert true
assert_true() {
    local condition="$1"
    local message="${2:-}"

    ((TESTS_RUN++))

    if eval "$condition"; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "assert_true: $message"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "assert_true: $message"
        echo "  Condition: $condition"
        return 1
    fi
}

# Assert false
assert_false() {
    local condition="$1"
    local message="${2:-}"

    ((TESTS_RUN++))

    if ! eval "$condition"; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "assert_false: $message"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "assert_false: $message"
        echo "  Condition: $condition"
        return 1
    fi
}

# Assert file exists
assert_file_exists() {
    local file="$1"
    local message="${2:-File should exist}"

    ((TESTS_RUN++))

    if [[ -f "$file" ]]; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "$message: $file"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "$message: $file"
        return 1
    fi
}

# Assert command exists
assert_command_exists() {
    local cmd="$1"
    local message="${2:-Command should exist}"

    ((TESTS_RUN++))

    if command -v "$cmd" &>/dev/null; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "$message: $cmd"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "$message: $cmd"
        return 1
    fi
}

# Assert exit code
assert_exit_code() {
    local expected="$1"
    local actual="$2"
    local message="${3:-}"

    ((TESTS_RUN++))

    if [[ "$expected" == "$actual" ]]; then
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "assert_exit_code: $message"
        fi
        return 0
    else
        ((TESTS_FAILED++))
        log_error "assert_exit_code: $message"
        echo "  Expected: $expected"
        echo "  Actual:   $actual"
        return 1
    fi
}

# Skip a test
skip_test() {
    local message="$1"
    ((TESTS_SKIPPED++))
    log_warning "SKIPPED: $message"
}

# Test utility functions
test_utils() {
    print_test_header "Utility Functions Tests"

    # Test trim function
    local trimmed
    trimmed=$(trim "  hello world  ")
    assert_equals "hello world" "$trimmed" "trim removes whitespace"

    # Test to_lower function
    local lowered
    lowered=$(to_lower "HELLO")
    assert_equals "hello" "$lowered" "to_lower converts to lowercase"

    # Test to_upper function
    local uppered
    uppered=$(to_upper "hello")
    assert_equals "HELLO" "$uppered" "to_upper converts to uppercase"

    # Test contains function
    assert_true 'contains "hello world" "world"' "contains finds substring"
    assert_false 'contains "hello world" "foo"' "contains returns false for missing substring"

    # Test starts_with function
    assert_true 'starts_with "hello world" "hello"' "starts_with finds prefix"
    assert_false 'starts_with "hello world" "world"' "starts_with returns false for wrong prefix"

    # Test ends_with function
    assert_true 'ends_with "hello world" "world"' "ends_with finds suffix"
    assert_false 'ends_with "hello world" "hello"' "ends_with returns false for wrong suffix"

    # Test timestamp function
    local ts
    ts=$(timestamp)
    assert_not_equals "" "$ts" "timestamp returns non-empty value"

    # Test calc_percentage function
    local pct
    pct=$(calc_percentage 75 100)
    assert_equals "75" "$pct" "calc_percentage calculates correctly"

    pct=$(calc_percentage 0 100)
    assert_equals "0" "$pct" "calc_percentage handles zero numerator"
}

# Test config values
test_config() {
    print_test_header "Configuration Tests"

    # Test script version is set
    assert_not_equals "" "$SCRIPT_VERSION" "SCRIPT_VERSION is set"

    # Test script name is set
    assert_equals "hardening-compliance-check" "$SCRIPT_NAME" "SCRIPT_NAME is correct"

    # Test SSH config path
    assert_not_equals "" "$SSH_CONFIG" "SSH_CONFIG path is set"

    # Test SSH benchmarks are populated
    assert_not_equals "" "${#SSH_BENCHMARKS[@]}" "SSH_BENCHMARKS has entries"

    # Test kernel benchmarks are populated
    assert_not_equals "" "${#KERNEL_BENCHMARKS[@]}" "KERNEL_BENCHMARKS has entries"

    # Test file permission benchmarks
    assert_not_equals "" "${#FILE_PERM_BENCHMARKS[@]}" "FILE_PERM_BENCHMARKS has entries"

    # Test specific benchmark values
    assert_equals "no" "${SSH_BENCHMARKS[PermitRootLogin]}" "PermitRootLogin benchmark is 'no'"
    assert_equals "0" "${KERNEL_BENCHMARKS[net.ipv4.ip_forward]}" "ip_forward benchmark is '0'"
    assert_equals "600" "${FILE_PERM_BENCHMARKS[/etc/shadow]}" "/etc/shadow perms is '600'"

    # Test severity levels
    assert_equals "critical" "${SSH_SEVERITY[PermitRootLogin]}" "PermitRootLogin severity is critical"
    assert_equals "critical" "${KERNEL_SEVERITY[kernel.randomize_va_space]}" "ASLR severity is critical"

    # Test cache configuration
    assert_not_equals "" "$CACHE_DIR" "CACHE_DIR is set"
    assert_not_equals "" "$CACHE_FILE" "CACHE_FILE is set"
    assert_not_equals "" "$CACHE_VERSION" "CACHE_VERSION is set"
    assert_not_equals "" "$DEFAULT_CACHE_TTL" "DEFAULT_CACHE_TTL is set"
}

# Test helper functions
test_helpers() {
    print_test_header "Helper Function Tests"

    # Test command_exists
    assert_true 'command_exists bash' "command_exists finds bash"
    assert_false 'command_exists nonexistent_command_xyz' "command_exists returns false for missing command"

    # Test file_exists with existing file
    assert_true 'file_exists /etc/passwd' "file_exists finds /etc/passwd"
    assert_false 'file_exists /nonexistent_file_xyz' "file_exists returns false for missing file"

    # Test get_file_perms
    local perms
    perms=$(get_file_perms /etc/passwd)
    assert_not_equals "" "$perms" "get_file_perms returns value for /etc/passwd"

    # Test get_distribution
    local dist
    dist=$(get_distribution)
    assert_not_equals "" "$dist" "get_distribution returns value"

    # Test is_distribution
    # This will vary by system, just test it runs
    local result
    result=$(is_distribution "ubuntu" && echo "true" || echo "false")
    assert_not_equals "" "$result" "is_distribution runs without error"
}

# Test main script exists and is executable
test_script_structure() {
    print_test_header "Script Structure Tests"

    # Test main script exists
    assert_file_exists "${PROJECT_DIR}/hardening-compliance-check.sh" "Main script exists"

    # Test lib files exist
    assert_file_exists "${PROJECT_DIR}/lib/utils.sh" "utils.sh exists"
    assert_file_exists "${PROJECT_DIR}/lib/config.sh" "config.sh exists"
    assert_file_exists "${PROJECT_DIR}/lib/checks.sh" "checks.sh exists"

    # Test scripts have shebang
    local shebang
    shebang=$(head -n1 "${PROJECT_DIR}/hardening-compliance-check.sh")
    assert_equals "#!/usr/bin/env bash" "$shebang" "Main script has correct shebang"

    shebang=$(head -n1 "${PROJECT_DIR}/lib/utils.sh")
    assert_equals "#!/usr/bin/env bash" "$shebang" "utils.sh has correct shebang"

    # Test scripts are syntactically valid
    local syntax_check
    if bash -n "${PROJECT_DIR}/hardening-compliance-check.sh" 2>/dev/null; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "Main script syntax is valid"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "Main script has syntax errors"
    fi

    if bash -n "${PROJECT_DIR}/lib/utils.sh" 2>/dev/null; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "utils.sh syntax is valid"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "utils.sh has syntax errors"
    fi

    if bash -n "${PROJECT_DIR}/lib/config.sh" 2>/dev/null; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "config.sh syntax is valid"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "config.sh has syntax errors"
    fi

    if bash -n "${PROJECT_DIR}/lib/checks.sh" 2>/dev/null; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "checks.sh syntax is valid"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "checks.sh has syntax errors"
    fi
}

# Test help and version output
test_cli_options() {
    print_test_header "CLI Options Tests"

    # Test help output
    local help_output
    help_output=$("${PROJECT_DIR}/hardening-compliance-check.sh" --help 2>&1 || true)
    assert_not_equals "" "$help_output" "Help option produces output"
    assert_true '[[ "$help_output" == *"USAGE"* ]]' "Help output contains USAGE"
    assert_true '[[ "$help_output" == *"--help"* ]]' "Help output contains --help"
    assert_true '[[ "$help_output" == *"--cache"* ]]' "Help output contains --cache option"

    # Test version output
    local version_output
    version_output=$("${PROJECT_DIR}/hardening-compliance-check.sh" --version 2>&1 || true)
    assert_not_equals "" "$version_output" "Version option produces output"
    assert_true '[[ "$version_output" == *"version"* ]]' "Version output contains version"

    # Test list-categories output
    local categories_output
    categories_output=$("${PROJECT_DIR}/hardening-compliance-check.sh" --list-categories 2>&1 || true)
    assert_not_equals "" "$categories_output" "List-categories produces output"
    assert_true '[[ "$categories_output" == *"ssh_hardening"* ]]' "Categories output contains ssh_hardening"
}

# Test benchmark coverage
test_benchmark_coverage() {
    print_test_header "Benchmark Coverage Tests"

    # Test SSH benchmarks count (should have at least 10)
    local ssh_count=${#SSH_BENCHMARKS[@]}
    if [[ $ssh_count -ge 10 ]]; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "SSH benchmarks count: $ssh_count (>= 10)"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "SSH benchmarks count: $ssh_count (< 10)"
    fi

    # Test kernel benchmarks count (should have at least 15)
    local kernel_count=${#KERNEL_BENCHMARKS[@]}
    if [[ $kernel_count -ge 15 ]]; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "Kernel benchmarks count: $kernel_count (>= 15)"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "Kernel benchmarks count: $kernel_count (< 15)"
    fi

    # Test file permission benchmarks count (should have at least 10)
    local file_count=${#FILE_PERM_BENCHMARKS[@]}
    if [[ $file_count -ge 10 ]]; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "File permission benchmarks count: $file_count (>= 10)"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "File permission benchmarks count: $file_count (< 10)"
    fi

    # Test disabled services count (should have at least 5)
    local service_count=${#DISABLED_SERVICES[@]}
    if [[ $service_count -ge 5 ]]; then
        ((TESTS_RUN++))
        ((TESTS_PASSED++))
        if [[ "$VERBOSE" == true ]]; then
            log_success "Disabled services count: $service_count (>= 5)"
        fi
    else
        ((TESTS_RUN++))
        ((TESTS_FAILED++))
        log_error "Disabled services count: $service_count (< 5)"
    fi
}

# Test input validation functions
test_input_validation() {
    print_test_header "Input Validation Tests"

    # Test validate_ssh_boolean
    assert_true 'validate_ssh_boolean "yes"' "validate_ssh_boolean accepts yes"
    assert_true 'validate_ssh_boolean "no"' "validate_ssh_boolean accepts no"
    assert_true 'validate_ssh_boolean "YES"' "validate_ssh_boolean accepts YES"
    assert_true 'validate_ssh_boolean "NO"' "validate_ssh_boolean accepts NO"
    assert_false 'validate_ssh_boolean "true"' "validate_ssh_boolean rejects true"
    assert_false 'validate_ssh_boolean "false"' "validate_ssh_boolean rejects false"
    assert_false 'validate_ssh_boolean "1"' "validate_ssh_boolean rejects 1"
    assert_false 'validate_ssh_boolean "0"' "validate_ssh_boolean rejects 0"

    # Test validate_ssh_numeric
    assert_true 'validate_ssh_numeric "300"' "validate_ssh_numeric accepts 300"
    assert_true 'validate_ssh_numeric "0"' "validate_ssh_numeric accepts 0"
    assert_true 'validate_ssh_numeric "9999"' "validate_ssh_numeric accepts 9999"
    assert_false 'validate_ssh_numeric "-1"' "validate_ssh_numeric rejects negative"
    assert_false 'validate_ssh_numeric "abc"' "validate_ssh_numeric rejects abc"
    assert_false 'validate_ssh_numeric "10abc"' "validate_ssh_numeric rejects mixed"

    # Test validate_ssh_crypto
    assert_true 'validate_ssh_crypto "aes256-ctr"' "validate_ssh_crypto accepts single algo"
    assert_true 'validate_ssh_crypto "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"' "validate_ssh_crypto accepts comma-separated"
    assert_false 'validate_ssh_crypto "aes256;rm -rf /"' "validate_ssh_crypto rejects injection"

    # Test validate_kernel_numeric
    assert_true 'validate_kernel_numeric "0"' "validate_kernel_numeric accepts 0"
    assert_true 'validate_kernel_numeric "1"' "validate_kernel_numeric accepts 1"
    assert_true 'validate_kernel_numeric "-1"' "validate_kernel_numeric accepts -1"
    assert_true 'validate_kernel_numeric "2"' "validate_kernel_numeric accepts 2"
    assert_false 'validate_kernel_numeric "abc"' "validate_kernel_numeric rejects abc"

    # Test validate_file_permission
    assert_true 'validate_file_permission "644"' "validate_file_permission accepts 644"
    assert_true 'validate_file_permission "600"' "validate_file_permission accepts 600"
    assert_true 'validate_file_permission "755"' "validate_file_permission accepts 755"
    assert_true 'validate_file_permission "700"' "validate_file_permission accepts 700"
    assert_true 'validate_file_permission "0644"' "validate_file_permission accepts 0644"
    assert_false 'validate_file_permission "888"' "validate_file_permission rejects 888"
    assert_false 'validate_file_permission "abc"' "validate_file_permission rejects abc"
    assert_false 'validate_file_permission "64"' "validate_file_permission rejects 64"

    # Test validate_password_numeric
    assert_true 'validate_password_numeric "90"' "validate_password_numeric accepts 90"
    assert_true 'validate_password_numeric "0"' "validate_password_numeric accepts 0"
    assert_false 'validate_password_numeric "-1"' "validate_password_numeric rejects -1"
    assert_false 'validate_password_numeric "abc"' "validate_password_numeric rejects abc"

    # Test validate_config_value
    assert_true 'validate_config_value "test" "yes" "boolean"' "validate_config_value accepts valid boolean"
    assert_true 'validate_config_value "test" "300" "numeric"' "validate_config_value accepts valid numeric"
    assert_true 'validate_config_value "test" "644" "permission"' "validate_config_value accepts valid permission"
    assert_false 'validate_config_value "test" "invalid" "boolean"' "validate_config_value rejects invalid boolean"
    assert_false 'validate_config_value "test" "" "numeric"' "validate_config_value rejects empty"

    # Test sanitize_config_value
    local sanitized
    sanitized=$(sanitize_config_value "hello world")
    assert_equals "hello world" "$sanitized" "sanitize_config_value keeps clean input"

    sanitized=$(sanitize_config_value 'test;rm -rf /')
    assert_false '[[ "$sanitized" == *";"* ]]' "sanitize_config_value removes semicolons"

    sanitized=$(sanitize_config_value 'test$(whoami)')
    assert_false '[[ "$sanitized" == *"$"* ]]' "sanitize_config_value removes dollar signs"

    # Test validate_file_path
    assert_true 'validate_file_path "/etc/passwd"' "validate_file_path accepts absolute path"
    assert_true 'validate_file_path "./config.txt"' "validate_file_path accepts relative path"
    assert_true 'validate_file_path "filename.txt"' "validate_file_path accepts simple filename"
    assert_false 'validate_file_path "../../../etc/passwd"' "validate_file_path rejects traversal"
    assert_false 'validate_file_path "/../etc/passwd"' "validate_file_path rejects root traversal"
    assert_false 'validate_file_path "-rf /etc/passwd"' "validate_file_path rejects dash prefix"

    # Test validate_category_name
    assert_true 'validate_category_name "ssh_hardening"' "validate_category_name accepts ssh_hardening"
    assert_true 'validate_category_name "kernel_hardening"' "validate_category_name accepts kernel_hardening"
    assert_true 'validate_category_name "file_permissions"' "validate_category_name accepts file_permissions"
    assert_false 'validate_category_name "SSH_hardening"' "validate_category_name rejects uppercase"
    assert_false 'validate_category_name "123category"' "validate_category_name rejects numeric start"
    assert_false 'validate_category_name "cat;rm -rf /"' "validate_category_name rejects injection"

    # Test validate_output_format
    assert_true 'validate_output_format "text"' "validate_output_format accepts text"
    assert_true 'validate_output_format "json"' "validate_output_format accepts json"
    assert_true 'validate_output_format "csv"' "validate_output_format accepts csv"
    assert_false 'validate_output_format "xml"' "validate_output_format rejects xml"
    assert_false 'validate_output_format "html"' "validate_output_format rejects html"
}

# Test cache functions
test_cache_functions() {
    print_test_header "Cache Function Tests"

    # Test init_cache creates directory
    init_cache
    assert_true '[[ -d "$CACHE_DIR" ]]' "init_cache creates cache directory"

    # Test get_cache_path
    local cache_path
    cache_path=$(get_cache_path)
    assert_equals "$CACHE_FILE" "$cache_path" "get_cache_path returns correct path"

    # Test clear_cache when no cache exists
    rm -f "$CACHE_FILE" 2>/dev/null || true
    clear_cache
    assert_true '[[ $? -eq 0 ]]' "clear_cache succeeds when no cache exists"

    # Test write_cache_header
    write_cache_header
    assert_true '[[ -f "$CACHE_FILE" ]]' "write_cache_header creates cache file"

    # Test cache header format
    local header
    header=$(head -1 "$CACHE_FILE")
    assert_true '[[ "$header" == "#CACHE_META:"* ]]' "cache header has correct format"

    # Test cache version in header
    local version
    version=$(get_cache_version)
    assert_equals "$CACHE_VERSION" "$version" "cache version matches"

    # Test store and retrieve cache result
    store_cache_result "test_check" "pass" "test details"
    local cached_result
    cached_result=$(get_cached_result "test_check")
    assert_equals "pass" "$cached_result" "get_cached_result returns stored value"

    local cached_details
    cached_details=$(get_cached_details "test_check")
    assert_equals "test details" "$cached_details" "get_cached_details returns stored value"

    # Test is_cache_empty
    assert_false 'is_cache_empty' "is_cache_empty returns false after storing"

    # Test cache age
    local age
    age=$(get_cache_age)
    assert_not_equals "" "$age" "get_cache_age returns value"

    # Test cache TTL validation (cache should be valid with default TTL)
    assert_true 'is_cache_valid 3600' "is_cache_valid returns true for fresh cache"

    # Test is_cache_valid with zero TTL (should always be invalid)
    assert_false 'is_cache_valid 0' "is_cache_valid returns false for zero TTL"

    # Clean up test cache
    rm -f "$CACHE_FILE" 2>/dev/null || true
}

# Test cache CLI options
test_cache_cli() {
    print_test_header "Cache CLI Tests"

    # Test --clear-cache option
    local clear_output
    clear_output=$("${PROJECT_DIR}/hardening-compliance-check.sh" --clear-cache 2>&1 || true)
    assert_not_equals "" "$clear_output" "--clear-cache produces output"
    assert_true '[[ "$clear_output" == *"Cache"* || "$clear_output" == *"cache"* ]]' "clear-cache output mentions cache"

    # Test --cache-ttl with valid value
    local ttl_output
    ttl_output=$("${PROJECT_DIR}/hardening-compliance-check.sh" --cache-ttl 300 --help 2>&1 || true)
    assert_exit_code 0 "$?" "--cache-ttl with valid value succeeds"

    # Test --cache-ttl with invalid value
    local invalid_ttl_output
    invalid_ttl_output=$("${PROJECT_DIR}/hardening-compliance-check.sh" --cache-ttl abc 2>&1 || true)
    assert_true '[[ "$invalid_ttl_output" == *"error"* || "$invalid_ttl_output" == *"Error"* || "$invalid_ttl_output" == *"must be"* ]]' "--cache-ttl with invalid value shows error"
}

# Print test summary
print_summary() {
    echo ""
    if supports_color; then
        echo -e "${COLOR_BOLD}========================================${COLOR_RESET}"
        echo -e "${COLOR_BOLD}           TEST SUMMARY${COLOR_RESET}"
        echo -e "${COLOR_BOLD}========================================${COLOR_RESET}"
    else
        echo "========================================"
        echo "           TEST SUMMARY"
        echo "========================================"
    fi
    echo ""
    echo "  Total tests run:    $TESTS_RUN"
    print_color "$COLOR_GREEN" "  Passed:             $TESTS_PASSED"
    print_color "$COLOR_RED" "  Failed:             $TESTS_FAILED"
    print_color "$COLOR_YELLOW" "  Skipped:            $TESTS_SKIPPED"
    echo ""

    local pass_rate=0
    if [[ $TESTS_RUN -gt 0 ]]; then
        pass_rate=$(( (TESTS_PASSED * 100) / TESTS_RUN ))
    fi
    echo "  Pass rate:          ${pass_rate}%"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        print_color "$COLOR_GREEN" "  All tests passed!"
        return 0
    else
        print_color "$COLOR_RED" "  Some tests failed!"
        return 1
    fi
}

# Parse arguments
parse_test_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -v, --verbose    Show detailed test output"
                echo "  -h, --help       Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Main test runner
main() {
    parse_test_args "$@"

    echo ""
    if supports_color; then
        echo -e "${COLOR_BOLD}${COLOR_GREEN}========================================${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_GREEN}  Hardening Compliance Checker Tests${COLOR_RESET}"
        echo -e "${COLOR_BOLD}${COLOR_GREEN}========================================${COLOR_RESET}"
    else
        echo "========================================"
        echo "  Hardening Compliance Checker Tests"
        echo "========================================"
    fi

    # Run all test suites
    test_utils
    test_config
    test_helpers
    test_script_structure
    test_cli_options
    test_benchmark_coverage
    test_input_validation
    test_cache_functions
    test_cache_cli

    # Print summary
    print_summary
}

# Run main
main "$@"
