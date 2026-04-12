#!/usr/bin/env bash
#
# utils.sh - Utility functions for hardening compliance checker
# Provides logging, formatting, and common helper functions
#

# Color codes for terminal output
readonly COLOR_RESET='\033[0m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_BOLD='\033[1m'

# Check if output supports colors
supports_color() {
    if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
        case "${COLORTERM:-}" in
            truecolor|24bit) return 0 ;;
        esac
        case "${TERM:-}" in
            xterm-kitty|xterm-256color|screen-256color) return 0 ;;
        esac
        [[ "${TERM:-}" =~ ^xterm ]] && return 0
    fi
    return 1
}

# Strip color codes from a string
strip_colors() {
    local str="$1"
    echo -e "$str" | sed 's/\x1b\[[0-9;]*m//g'
}

# Print a message with color
print_color() {
    local color="$1"
    local message="$2"
    if supports_color; then
        echo -e "${color}${message}${COLOR_RESET}"
    else
        echo -e "$message"
    fi
}

# Print info message
log_info() {
    print_color "$COLOR_BLUE" "[INFO] $*"
}

# Print success message
log_success() {
    print_color "$COLOR_GREEN" "[PASS] $*"
}

# Print warning message
log_warning() {
    print_color "$COLOR_YELLOW" "[WARN] $*"
}

# Print error message
log_error() {
    print_color "$COLOR_RED" "[FAIL] $*" >&2
}

# Print check result with status
print_check_result() {
    local check_name="$1"
    local status="$2"
    local details="${3:-}"

    local status_color status_icon
    case "$status" in
        pass)
            status_color="$COLOR_GREEN"
            status_icon="✓"
            ;;
        fail)
            status_color="$COLOR_RED"
            status_icon="✗"
            ;;
        warn)
            status_color="$COLOR_YELLOW"
            status_icon="!"
            ;;
        skip)
            status_color="$COLOR_CYAN"
            status_icon="○"
            ;;
        *)
            status_color="$COLOR_RESET"
            status_icon="?"
            ;;
    esac

    if supports_color; then
        printf "  ${status_color}[%s]${COLOR_RESET} %-50s" "$status_icon" "$check_name"
    else
        printf "  [%s] %-50s" "$status_icon" "$check_name"
    fi

    if [[ -n "$details" ]]; then
        echo " - $details"
    else
        echo ""
    fi
}

# Print section header
print_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    local line=""

    for ((i=0; i<width; i++)); do
        line+="="
    done

    echo ""
    if supports_color; then
        echo -e "${COLOR_BOLD}${COLOR_CYAN}${line}${COLOR_RESET}"
        printf "  ${COLOR_BOLD}${COLOR_CYAN}%*s%s%*s${COLOR_RESET}\n" "$padding" "" "$title" "$padding" ""
        echo -e "${COLOR_BOLD}${COLOR_CYAN}${line}${COLOR_RESET}"
    else
        echo "$line"
        printf "  %*s%s%*s\n" "$padding" "" "$title" "$padding" ""
        echo "$line"
    fi
    echo ""
}

# Print sub-header
print_subheader() {
    local title="$1"
    if supports_color; then
        echo -e "${COLOR_BOLD}${title}${COLOR_RESET}"
    else
        echo "$title"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        return 1
    fi
    return 0
}

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Check if a file exists and is readable
file_exists() {
    [[ -f "$1" && -r "$1" ]]
}

# Check if a directory exists
dir_exists() {
    [[ -d "$1" ]]
}

# Get file permission in octal format
get_file_perms() {
    local file="$1"
    if [[ -e "$file" ]]; then
        stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null
    else
        echo ""
    fi
}

# Get file owner
get_file_owner() {
    local file="$1"
    if [[ -e "$file" ]]; then
        stat -c '%U' "$file" 2>/dev/null || stat -f '%Su' "$file" 2>/dev/null
    else
        echo ""
    fi
}

# Get file group
get_file_group() {
    local file="$1"
    if [[ -e "$file" ]]; then
        stat -c '%G' "$file" 2>/dev/null || stat -f '%Sg' "$file" 2>/dev/null
    else
        echo ""
    fi
}

# Check if a service is active
service_active() {
    local service="$1"
    if command_exists systemctl; then
        systemctl is-active --quiet "$service" 2>/dev/null
        return $?
    elif command_exists service; then
        service "$service" status &>/dev/null
        return $?
    fi
    return 1
}

# Check if a service is enabled
service_enabled() {
    local service="$1"
    if command_exists systemctl; then
        systemctl is-enabled --quiet "$service" 2>/dev/null
        return $?
    fi
    return 1
}

# Get kernel parameter value
get_sysctl() {
    local param="$1"
    sysctl -n "$param" 2>/dev/null
}

# Check kernel parameter value
check_sysctl() {
    local param="$1"
    local expected="$2"
    local current
    current=$(get_sysctl "$param")

    if [[ "$current" == "$expected" ]]; then
        return 0
    fi
    return 1
}

# Get config value from file
get_config_value() {
    local file="$1"
    local key="$2"
    local separator="${3:- }"

    if [[ -f "$file" ]]; then
        grep -E "^[[:space:]]*${key}${separator}" "$file" 2>/dev/null | \
            sed -E "s/^[[:space:]]*${key}${separator}//" | \
            tr -d '"' | tr -d "'" | xargs
    fi
}

# Check if config has specific value
config_has_value() {
    local file="$1"
    local key="$2"
    local value="$3"
    local separator="${4:- }"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    local current
    current=$(get_config_value "$file" "$key" "$separator")
    [[ "$current" == "$value" ]]
}

# Check if config key exists
config_key_exists() {
    local file="$1"
    local key="$2"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    grep -qE "^[[:space:]]*${key}[[:space:]]" "$file" 2>/dev/null
}

# Trim whitespace from string
trim() {
    local var="$1"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo "$var"
}

# Convert string to lowercase
to_lower() {
    local str="${1:-}"
    echo "$str" | tr '[:upper:]' '[:lower:]'
}

# Convert string to uppercase
to_upper() {
    local str="${1:-}"
    echo "$str" | tr '[:lower:]' '[:upper:]'
}

# Check if string contains substring
contains() {
    [[ "$1" == *"$2"* ]]
}

# Check if string starts with prefix
starts_with() {
    [[ "$1" == "$2"* ]]
}

# Check if string ends with suffix
ends_with() {
    [[ "$1" == *"$2" ]]
}

# Get current timestamp
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Get current timestamp in seconds since epoch
timestamp_epoch() {
    date '+%s'
}

# Get distribution info
get_distribution() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        echo "$DISTRIB_ID"
    elif command_exists lsb_release; then
        lsb_release -is
    else
        echo "unknown"
    fi
}

# Get distribution version
get_distribution_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$VERSION_ID"
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        echo "$DISTRIB_RELEASE"
    elif command_exists lsb_release; then
        lsb_release -rs
    else
        echo "unknown"
    fi
}

# Check if distribution matches
is_distribution() {
    local dist="$1"
    local current
    current=$(get_distribution | to_lower)
    [[ "$current" == *"$dist"* ]]
}

# Calculate percentage
calc_percentage() {
    local numerator="$1"
    local denominator="$2"
    if [[ "$denominator" -eq 0 ]]; then
        echo "0"
    else
        echo $(( (numerator * 100) / denominator ))
    fi
}

# Format duration in seconds
format_duration() {
    local seconds="$1"
    local minutes=$((seconds / 60))
    local remaining_seconds=$((seconds % 60))

    if [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${remaining_seconds}s"
    else
        echo "${remaining_seconds}s"
    fi
}

# ============================================================================
# Input Validation Functions
# ============================================================================

# Validate SSH boolean parameter value
# Returns 0 if valid (yes/no), 1 otherwise
validate_ssh_boolean() {
    local value="$1"
    case "$(to_lower "$value")" in
        yes|no) return 0 ;;
        *) return 1 ;;
    esac
}

# Validate SSH numeric parameter value
# Returns 0 if valid positive integer, 1 otherwise
validate_ssh_numeric() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]]
}

# Validate SSH cipher/MAC/Kex algorithm string
# Returns 0 if valid format, 1 otherwise
validate_ssh_crypto() {
    local value="$1"
    # Allow comma-separated list of algorithm names
    [[ "$value" =~ ^[a-zA-Z0-9@._+-]+(,[a-zA-Z0-9@._+-]+)*$ ]]
}

# Validate kernel parameter value (numeric)
# Returns 0 if valid, 1 otherwise
validate_kernel_numeric() {
    local value="$1"
    [[ "$value" =~ ^-?[0-9]+$ ]]
}

# Validate file permission value (octal)
# Returns 0 if valid octal permission, 1 otherwise
validate_file_permission() {
    local value="$1"
    [[ "$value" =~ ^[0-7]{3,4}$ ]]
}

# Validate password policy numeric value
# Returns 0 if valid non-negative integer, 1 otherwise
validate_password_numeric() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]]
}

# Validate config value based on parameter type
# Args: param_name, value, param_type (boolean|numeric|permission|crypto)
# Returns 0 if valid, 1 otherwise
validate_config_value() {
    local param_name="$1"
    local value="$2"
    local param_type="$3"

    if [[ -z "$value" ]]; then
        return 1
    fi

    case "$param_type" in
        boolean)
            validate_ssh_boolean "$value"
            ;;
        numeric)
            validate_ssh_numeric "$value"
            ;;
        permission)
            validate_file_permission "$value"
            ;;
        crypto)
            validate_ssh_crypto "$value"
            ;;
        *)
            # Unknown type, accept any non-empty value
            [[ -n "$value" ]]
            ;;
    esac
}

# Sanitize config value (remove dangerous characters)
# Returns sanitized value
sanitize_config_value() {
    local value="$1"
    # Remove command injection characters
    value="${value//\$/}"
    value="${value//\`/}"
    value="${value//;/}"
    value="${value//|/}"
    value="${value//&/}"
    # Remove newlines and carriage returns
    value="${value//$'\n'/}"
    value="${value//$'\r'/}"
    # Trim whitespace
    trim "$value"
}

# Validate file path (prevent path traversal)
# Returns 0 if safe, 1 if dangerous
validate_file_path() {
    local path="$1"

    # Reject empty paths
    if [[ -z "$path" ]]; then
        return 1
    fi

    # Reject paths starting with dash (option injection)
    if [[ "$path" == -* ]]; then
        return 1
    fi

    # Reject path traversal attempts
    if [[ "$path" == *"/../"* || "$path" == "../"* || "$path" == *"/.." ]]; then
        return 1
    fi

    # Accept absolute paths
    if [[ "$path" == /* ]]; then
        return 0
    fi

    # Accept relative paths starting with ./
    if [[ "$path" == ./* ]]; then
        return 0
    fi

    # Accept simple filenames (no directory separators)
    if [[ "$path" != */* ]]; then
        return 0
    fi

    # Reject other patterns
    return 1
}

# Validate category name (alphanumeric and underscore only)
# Returns 0 if valid, 1 otherwise
validate_category_name() {
    local category="$1"
    [[ "$category" =~ ^[a-z][a-z0-9_]*$ ]]
}

# Validate output format
# Returns 0 if valid, 1 otherwise
validate_output_format() {
    local format="$1"
    case "$format" in
        text|json|csv) return 0 ;;
        *) return 1 ;;
    esac
}

# Log validation error
log_validation_error() {
    local param="$1"
    local value="$2"
    local reason="${3:-invalid value}"
    log_warning "Validation failed for '$param': $reason (got: '$value')"
}

# ============================================================================
# Cache Functions
# ============================================================================

# Initialize cache directory
# Returns 0 on success, 1 on failure
init_cache() {
    if [[ ! -d "$CACHE_DIR" ]]; then
        mkdir -p "$CACHE_DIR" 2>/dev/null
        if [[ $? -ne 0 ]]; then
            log_warning "Failed to create cache directory: $CACHE_DIR"
            return 1
        fi
    fi
    return 0
}

# Check if cache is enabled and valid
# Returns 0 if cache should be used, 1 otherwise
is_cache_valid() {
    # Check if caching is enabled (default to false if not set)
    if [[ "${USE_CACHE:-false}" != "true" ]]; then
        return 1
    fi

    # Initialize cache directory if needed
    if ! init_cache; then
        return 1
    fi

    if [[ ! -f "$CACHE_FILE" ]]; then
        return 1
    fi

    local cache_age
    local current_time
    current_time=$(timestamp_epoch)
    cache_age=$(get_cache_age)

    if [[ -z "$cache_age" ]]; then
        return 1
    fi

    local age=$((current_time - cache_age))
    if [[ $age -lt ${CACHE_TTL:-3600} ]]; then
        return 0
    fi

    return 1
}

# Get cache age in seconds since epoch
# Returns empty string if cache doesn't exist or is invalid
get_cache_age() {
    if [[ ! -f "$CACHE_FILE" ]]; then
        echo ""
        return
    fi

    local meta_line
    meta_line=$(grep "^#CACHE_META:" "$CACHE_FILE" 2>/dev/null | head -1)
    if [[ -z "$meta_line" ]]; then
        echo ""
        return
    fi

    echo "$meta_line" | sed 's/^#CACHE_META://' | cut -d'|' -f1
}

# Get cache version
get_cache_version() {
    if [[ ! -f "$CACHE_FILE" ]]; then
        echo ""
        return
    fi

    local meta_line
    meta_line=$(grep "^#CACHE_META:" "$CACHE_FILE" 2>/dev/null | head -1)
    if [[ -z "$meta_line" ]]; then
        echo ""
        return
    fi

    echo "$meta_line" | sed 's/^#CACHE_META://' | cut -d'|' -f2
}

# Get cached result for a specific check
# Args: check_name
# Returns: cached result (pass|fail|skip|warn) or empty if not found
get_cached_result() {
    local check_name="$1"

    if [[ ! -f "$CACHE_FILE" ]]; then
        echo ""
        return
    fi

    local result_line
    result_line=$(grep "^${check_name}|" "$CACHE_FILE" 2>/dev/null | head -1)
    if [[ -z "$result_line" ]]; then
        echo ""
        return
    fi

    echo "$result_line" | cut -d'|' -f2
}

# Get cached details for a specific check
# Args: check_name
# Returns: cached details or empty if not found
get_cached_details() {
    local check_name="$1"

    if [[ ! -f "$CACHE_FILE" ]]; then
        echo ""
        return
    fi

    local result_line
    result_line=$(grep "^${check_name}|" "$CACHE_FILE" 2>/dev/null | head -1)
    if [[ -z "$result_line" ]]; then
        echo ""
        return
    fi

    echo "$result_line" | cut -d'|' -f3-
}

# Store result in cache
# Args: check_name, status, details
store_cache_result() {
    local check_name="$1"
    local status="$2"
    local details="${3:-}"

    # Check if caching is enabled (default to false if not set)
    if [[ "${USE_CACHE:-false}" != "true" ]]; then
        return 1
    fi

    if [[ ! -d "$CACHE_DIR" ]]; then
        init_cache || return 1
    fi

    # Remove old entry for this check if exists
    if [[ -f "$CACHE_FILE" ]]; then
        local temp_file="${CACHE_FILE}.tmp"
        grep -v "^${check_name}|" "$CACHE_FILE" > "$temp_file" 2>/dev/null || true
        mv "$temp_file" "$CACHE_FILE" 2>/dev/null || true
    fi

    # Append new entry
    echo "${check_name}|${status}|${details}" >> "$CACHE_FILE" 2>/dev/null
}

# Write cache metadata header
# Should be called before storing results
write_cache_header() {
    local current_time
    current_time=$(timestamp_epoch)

    # Check if caching is enabled (default to false if not set)
    if [[ "${USE_CACHE:-false}" != "true" ]]; then
        return 1
    fi

    if [[ ! -d "$CACHE_DIR" ]]; then
        init_cache || return 1
    fi

    # Create new cache file with header
    echo "#CACHE_META:${current_time}|${CACHE_VERSION}" > "$CACHE_FILE" 2>/dev/null
    echo "# Generated: $(timestamp)" >> "$CACHE_FILE" 2>/dev/null
    echo "# Hostname: $(hostname)" >> "$CACHE_FILE" 2>/dev/null
    echo "# Distribution: $(get_distribution) $(get_distribution_version)" >> "$CACHE_FILE" 2>/dev/null
    echo "# Kernel: $(uname -r)" >> "$CACHE_FILE" 2>/dev/null
    echo "" >> "$CACHE_FILE" 2>/dev/null
}

# Clear the cache
clear_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        rm -f "$CACHE_FILE" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_info "Cache cleared"
            return 0
        else
            log_error "Failed to clear cache"
            return 1
        fi
    else
        log_info "No cache to clear"
        return 0
    fi
}

# Get cache file path
get_cache_path() {
    echo "$CACHE_FILE"
}

# Check if cache is empty (only has header)
is_cache_empty() {
    if [[ ! -f "$CACHE_FILE" ]]; then
        return 0
    fi

    local data_lines
    data_lines=$(grep -v "^#" "$CACHE_FILE" 2>/dev/null | grep -v "^$" | wc -l)
    if [[ $data_lines -eq 0 ]]; then
        return 0
    fi
    return 1
}
