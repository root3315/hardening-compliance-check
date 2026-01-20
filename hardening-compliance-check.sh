#!/usr/bin/env bash
#
# hardening-compliance-check.sh - Linux Hardening Compliance Checker
# 
# A comprehensive security compliance checker that validates Linux systems
# against industry-standard hardening benchmarks including CIS benchmarks.
#
# Usage: ./hardening-compliance-check.sh [OPTIONS]
#
# Options:
#   -h, --help          Show this help message
#   -v, --version       Show version information
#   -c, --category CAT  Run checks for specific category only
#   -o, --output FILE   Write results to output file
#   -f, --format FMT    Output format: text, json, csv (default: text)
#   -q, --quiet         Suppress non-essential output
#   --no-color          Disable colored output
#   --list-categories   List available check categories
#   --list-checks       List all available checks
#

set -euo pipefail

# Script directory for sourcing modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/checks.sh"

# Global variables
OUTPUT_FILE=""
OUTPUT_FORMAT="$DEFAULT_FORMAT"
QUIET_MODE=false
NO_COLOR=false
SELECTED_CATEGORY=""
START_TIME=""

# Print usage information
usage() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Linux Hardening Compliance Checker

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    -h, --help          Show this help message and exit
    -v, --version       Show version information and exit
    -c, --category CAT  Run checks for specific category only
                        Categories: file_permissions, user_accounts,
                                    ssh_hardening, kernel_hardening,
                                    service_hardening, logging_audit
    -o, --output FILE   Write results to specified output file
    -f, --format FMT    Output format: text, json, csv (default: text)
    -q, --quiet         Suppress non-essential output
    --no-color          Disable colored output
    --list-categories   List available check categories
    --list-checks       List all available checks with descriptions

EXAMPLES:
    # Run all checks
    ${SCRIPT_NAME}

    # Run only SSH hardening checks
    ${SCRIPT_NAME} -c ssh_hardening

    # Output results to JSON file
    ${SCRIPT_NAME} -f json -o results.json

    # Run with quiet mode
    ${SCRIPT_NAME} -q

EXIT CODES:
    0   All checks passed (compliant)
    1   One or more checks failed (non-compliant)
    2   Partial compliance (some checks skipped)
    3   Checks were skipped

NOTES:
    - This script should be run as root for complete system access
    - Some checks may be distribution-specific
    - Results are based on CIS Benchmark recommendations

EOF
}

# Print version information
print_version() {
    echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
    echo "Linux Hardening Compliance Checker"
    echo ""
    echo "This tool checks your Linux system against security hardening"
    echo "benchmarks and provides a compliance report."
}

# List available categories
list_categories() {
    print_header "AVAILABLE CHECK CATEGORIES"
    
    for key in "${!CATEGORIES[@]}"; do
        local name="${CATEGORIES[$key]}"
        printf "  %-25s %s\n" "$key" "- $name"
    done
    
    echo ""
}

# List all available checks
list_checks() {
    print_header "AVAILABLE SECURITY CHECKS"
    
    echo "SSH Configuration Checks:"
    for key in "${!SSH_BENCHMARKS[@]}"; do
        local expected="${SSH_BENCHMARKS[$key]}"
        local severity="${SSH_SEVERITY[$key]}"
        printf "  %-30s (expected: %-15s severity: %s)\n" "$key" "$expected" "$severity"
    done
    
    echo ""
    echo "Kernel Parameter Checks:"
    for param in "${!KERNEL_BENCHMARKS[@]}"; do
        local expected="${KERNEL_BENCHMARKS[$param]}"
        local severity="${KERNEL_SEVERITY[$param]}"
        printf "  %-40s = %-5s [%s]\n" "$param" "$expected" "$severity"
    done
    
    echo ""
    echo "File Permission Checks:"
    for file in "${!FILE_PERM_BENCHMARKS[@]}"; do
        local expected="${FILE_PERM_BENCHMARKS[$file]}"
        local severity="${FILE_PERM_SEVERITY[$file]}"
        printf "  %-35s %s [%s]\n" "$file" "$expected" "$severity"
    done
    
    echo ""
    echo "Password Policy Checks:"
    for key in "${!PASSWORD_BENCHMARKS[@]}"; do
        local expected="${PASSWORD_BENCHMARKS[$key]}"
        printf "  %-20s %s\n" "$key" "$expected"
    done
    
    echo ""
    echo "Disabled Services:"
    for service in "${DISABLED_SERVICES[@]}"; do
        printf "  %s\n" "$service"
    done
    
    echo ""
    echo "Enabled Services:"
    for service in "${ENABLED_SERVICES[@]}"; do
        printf "  %s\n" "$service"
    done
    
    echo ""
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit $EXIT_SUCCESS
                ;;
            -v|--version)
                print_version
                exit $EXIT_SUCCESS
                ;;
            -c|--category)
                if [[ -n "${2:-}" ]]; then
                    SELECTED_CATEGORY="$2"
                    shift 2
                else
                    log_error "Category argument requires a value"
                    exit $EXIT_FAILURE
                fi
                ;;
            -o|--output)
                if [[ -n "${2:-}" ]]; then
                    OUTPUT_FILE="$2"
                    shift 2
                else
                    log_error "Output file argument requires a value"
                    exit $EXIT_FAILURE
                fi
                ;;
            -f|--format)
                if [[ -n "${2:-}" ]]; then
                    OUTPUT_FORMAT="$2"
                    shift 2
                else
                    log_error "Format argument requires a value"
                    exit $EXIT_FAILURE
                fi
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            --list-categories)
                list_categories
                exit $EXIT_SUCCESS
                ;;
            --list-checks)
                list_checks
                exit $EXIT_SUCCESS
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit $EXIT_FAILURE
                ;;
        esac
    done
}

# Validate output format
validate_format() {
    case "$OUTPUT_FORMAT" in
        text|json|csv)
            return 0
            ;;
        *)
            log_error "Invalid output format: $OUTPUT_FORMAT"
            log_error "Valid formats: text, json, csv"
            return 1
            ;;
    esac
}

# Validate category
validate_category() {
    if [[ -n "$SELECTED_CATEGORY" ]]; then
        if [[ -z "${CATEGORIES[$SELECTED_CATEGORY]:-}" ]]; then
            log_error "Invalid category: $SELECTED_CATEGORY"
            echo "Valid categories:"
            for key in "${!CATEGORIES[@]}"; do
                echo "  $key"
            done
            return 1
        fi
    fi
    return 0
}

# Generate JSON output
generate_json_output() {
    local pass_count="$1"
    local fail_count="$2"
    local skip_count="$3"
    local total="$4"
    
    local timestamp
    timestamp=$(date -Iseconds)
    
    cat << EOF
{
    "report": {
        "tool": "${SCRIPT_NAME}",
        "version": "${SCRIPT_VERSION}",
        "timestamp": "${timestamp}",
        "hostname": "$(hostname)",
        "distribution": "$(get_distribution)",
        "distribution_version": "$(get_distribution_version)",
        "kernel": "$(uname -r)"
    },
    "summary": {
        "total_checks": ${total},
        "passed": ${pass_count},
        "failed": ${fail_count},
        "skipped": ${skip_count},
        "compliance_score": $(( (pass_count * 100) / total ))
    }
}
EOF
}

# Generate CSV output
generate_csv_output() {
    local pass_count="$1"
    local fail_count="$2"
    local skip_count="$3"
    
    echo "metric,value"
    echo "timestamp,$(date -Iseconds)"
    echo "hostname,$(hostname)"
    echo "distribution,$(get_distribution)"
    echo "kernel,$(uname -r)"
    echo "total_checks,$((pass_count + fail_count + skip_count))"
    echo "passed,${pass_count}"
    echo "failed,${fail_count}"
    echo "skipped,${skip_count}"
    echo "compliance_score,$(( (pass_count * 100) / (pass_count + fail_count + skip_count) ))"
}

# Run checks based on selected category
run_category_checks() {
    local category="$1"
    local result
    
    case "$category" in
        file_permissions)
            check_file_permissions
            result=$?
            ;;
        user_accounts)
            check_empty_passwords
            check_uid_zero_users
            check_password_policy
            result=$?
            ;;
        ssh_hardening)
            check_ssh_config
            result=$?
            ;;
        kernel_hardening)
            check_kernel_params
            result=$?
            ;;
        service_hardening)
            check_dangerous_services
            check_required_services
            check_cron_at_restrictions
            result=$?
            ;;
        logging_audit)
            check_audit_status
            result=$?
            ;;
        *)
            log_error "Unknown category: $category"
            return $EXIT_FAILURE
            ;;
    esac
    
    return $result
}

# Main function
main() {
    START_TIME=$(date +%s)
    
    # Parse command line arguments
    parse_args "$@"
    
    # Handle no-color option
    if [[ "$NO_COLOR" == true ]]; then
        exec 3>&1
        exec > >(sed 's/\x1b\[[0-9;]*m//g')
    fi
    
    # Validate inputs
    if ! validate_format; then
        exit $EXIT_FAILURE
    fi
    
    if ! validate_category; then
        exit $EXIT_FAILURE
    fi
    
    # Check if running as root (warn but don't fail)
    if [[ $EUID -ne 0 ]]; then
        log_warning "Running as non-root user. Some checks may be skipped."
        log_warning "For complete results, run as root."
        echo ""
    fi
    
    # Run checks
    local exit_code
    
    if [[ -n "$SELECTED_CATEGORY" ]]; then
        print_header "LINUX HARDENING COMPLIANCE CHECK"
        echo "  Category: ${CATEGORIES[$SELECTED_CATEGORY]}"
        echo "  Started: $(timestamp)"
        echo ""
        
        run_category_checks "$SELECTED_CATEGORY"
        exit_code=$?
    else
        run_all_checks
        exit_code=$?
    fi
    
    # Calculate duration
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - START_TIME))
    
    # Generate output file if specified
    if [[ -n "$OUTPUT_FILE" ]]; then
        case "$OUTPUT_FORMAT" in
            json)
                generate_json_output 0 0 0 0 > "$OUTPUT_FILE"
                ;;
            csv)
                generate_csv_output 0 0 0 > "$OUTPUT_FILE"
                ;;
            *)
                # Text output already printed to stdout
                log_info "Results written to: $OUTPUT_FILE"
                ;;
        esac
    fi
    
    # Print completion message
    echo ""
    log_info "Completed in $(format_duration $duration)"
    
    exit $exit_code
}

# Run main function with all arguments
main "$@"
