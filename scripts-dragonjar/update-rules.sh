#!/usr/bin/env bash

################################################################################
# Update MASTG Semgrep Rules
# Description: Syncs upstream OWASP/MASTG rules via git submodule or direct fetch
# Usage: bash update-rules.sh [--submodule|--fetch]
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/colors.sh"
RULES_DIR="$SCRIPT_DIR/semgrep-rules"
MASTG_RULES_FILE="$RULES_DIR/MASTG-rules.yaml"

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[✓]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; }

show_help() {
    cat << EOF
${BOLD}Update MASTG Semgrep Rules${NC}

${BOLD}USAGE:${NC}
    $0 [--submodule|--fetch]

${BOLD}OPTIONS:${NC}
    --submodule   Pull latest rules from git submodule (if configured)
    --fetch       Download latest rules directly from OWASP/MASTG
    --help, -h    Show this help

${BOLD}DESCRIPTION:${NC}
    This script updates the semgrep rules bundle from upstream sources.

    --submodule: Uses git to pull latest from configured submodule
    --fetch:     Downloads directly from GitHub (requires network)

${BOLD}EXAMPLES:${NC}
    $0 --submodule
    $0 --fetch

EOF
    exit 0
}

# Count current rules
count_rules() {
    if [ -f "$MASTG_RULES_FILE" ]; then
        grep -c "^  - id:" "$MASTG_RULES_FILE" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Update via git submodule
update_submodule() {
    log_info "Updating via git submodule..."

    if [ ! -f "$SCRIPT_DIR/.gitmodules" ]; then
        log_error ".gitmodules not configured. Use --fetch instead."
        return 1
    fi

    git submodule update --init --recursive "$RULES_DIR" 2>/dev/null || {
        log_warning "Submodule update failed"
        return 1
    }

    log_success "Submodule updated"
}

# Update via direct fetch
update_fetch() {
    log_info "Fetching latest rules from OWASP/MASTG..."

    local temp_dir
    temp_dir=$(mktemp -d)

    trap "rm -rf $temp_dir" EXIT

    # Download MASTG rules
    local maastg_url="https://raw.githubusercontent.com/OWASP/owasp-mastg/master/CRYPTO/_rules/semgrep-rules.yaml"

    if command -v curl &>/dev/null; then
        curl -sL "$maastg_url" -o "$temp_dir/MASTG-rules.yaml" 2>/dev/null || {
            log_warning "Could not download from MASTG repo, using bundled rules"
            return 1
        }
    elif command -v wget &>/dev/null; then
        wget -q "$maastg_url" -O "$temp_dir/MASTG-rules.yaml" 2>/dev/null || {
            log_warning "Could not download from MASTG repo, using bundled rules"
            return 1
        }
    else
        log_error "Neither curl nor wget available"
        return 1
    fi

    # Backup existing custom rules
    local backup_file="$RULES_DIR/MASTG-rules.yaml.backup"
    if [ -f "$MASTG_RULES_FILE" ]; then
        cp "$MASTG_RULES_FILE" "$backup_file"
        log_info "Backed up existing rules to $backup_file"
    fi

    # Merge (preserve custom rules by appending backup)
    cat "$temp_dir/MASTG-rules.yaml" "$backup_file" > "$MASTG_RULES_FILE" 2>/dev/null || {
        cp "$temp_dir/MASTG-rules.yaml" "$MASTG_RULES_FILE"
    }

    log_success "Rules updated from upstream"
}

# Main
main() {
    local mode="submodule"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --submodule)
                mode="submodule"
                shift
                ;;
            --fetch)
                mode="fetch"
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                ;;
        esac
    done

    log_section "Updating MASTG Semgrep Rules"

    local before_count
    before_count=$(count_rules)
    log_info "Current rules count: $before_count"

    case $mode in
        submodule)
            update_submodule || log_warning "Using bundled rules"
            ;;
        fetch)
            update_fetch || log_warning "Keeping existing rules"
            ;;
    esac

    local after_count
    after_count=$(count_rules)
    log_success "Updated $before_count rules -> $after_count rules"

    local diff=$((after_count - before_count))
    if [ $diff -ne 0 ]; then
        log_info "Net change: $([ $diff -gt 0 ] && echo "+" || echo "")$diff rules"
    fi
}

log_section() { echo -e "\n=== $* ===\n"; }

main "$@"
