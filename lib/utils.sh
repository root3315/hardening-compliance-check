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
