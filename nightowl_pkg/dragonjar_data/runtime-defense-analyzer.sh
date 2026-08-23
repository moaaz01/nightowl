#!/usr/bin/env bash

################################################################################
# Runtime Defense Analyzer (RDA)
# Description: Phase 4 entry point for Frida-based RASP detector framework
# Author: android-apk-audit skill
# Usage: bash runtime-defense-analyzer.sh <apk-file> <package-name> [--active-mode --authorized-lab]
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTOR_CATALOG="$SCRIPT_DIR/detector-catalog.json"
FINDINGS_SCHEMA="$SCRIPT_DIR/findings-schema.json"
OUTPUT_FILE=""

source "$SCRIPT_DIR/../lib/colors.sh"

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[✓]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; }
log_section() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}\n"; }

show_help() {
    cat << EOF
${BOLD}Runtime Defense Analyzer (RDA)${NC}

${BOLD}USAGE:${NC}
    $0 <apk-file> <package-name> [--active-mode --authorized-lab]

${BOLD}ARGUMENTS:${NC}
    apk-file        Path to the APK file (required for info)
    package-name    Target package name (required)

${BOLD}OPTIONS:${NC}
    --active-mode   Enable active probing (bypass techniques)
    --authorized-lab Required flag when using --active-mode (fail-closed otherwise)
    --help, -h      Show this help message
    --list          List available detectors
    --output        Output JSON file path (default: findings-rda.json)

${BOLD}OUTPUT:${NC}
    JSON output with structure:
    {
        "mode": "passive|active",
        "findings": [...],
        "summary": {...}
    }

${BOLD}SECURITY:${NC}
    Passive mode (default): No active probes, read-only detection
    Active mode: Bypass techniques - REQUIRES --authorized-lab flag

${BOLD}EXAMPLES:${NC}
    $0 app.apk com.example.app
    $0 app.apk com.example.app --active-mode --authorized-lab
    $0 --list

EOF
    exit 0
}

# Check if Frida is available
check_frida() {
    if ! command -v frida &>/dev/null; then
        log_error "Frida not found. Install with: pip install frida frida-tools"
        return 1
    fi

    if ! command -v frida-ps &>/dev/null; then
        log_error "frida-tools not found. Install with: pip install frida-tools"
        return 1
    fi

    log_info "Frida available"
    return 0
}

# List available detectors
list_detectors() {
    if [ ! -f "$DETECTOR_CATALOG" ]; then
        log_error "Detector catalog not found: $DETECTOR_CATALOG"
        return 1
    fi

    log_section "Available RASP Detectors"

    local detector_count
    detector_count=$(python3 -c "import json; print(len(json.load(open('$DETECTOR_CATALOG'))['detectors']))" 2>/dev/null || echo "0")

    log_info "Total detectors: $detector_count"
    echo ""

    python3 -c "
import json
with open('$DETECTOR_CATALOG') as f:
    catalog = json.load(f)
    for det in catalog['detectors']:
        print(f\"  {det['name']:20s} - {det['description']}\")
        print(f\"    Category: {det['category']}, Bypass: {'Yes' if det.get('bypass_available') else 'No'}\")
        print(f\"    Vendor: {det.get('vendor', 'N/A')}, Platform: {det.get('platform', 'N/A')}\")
        print()
" 2>/dev/null || {
        echo "Detectors:"
        jq -r '.detectors[] | "\(.name) - \(.description)"' "$DETECTOR_CATALOG" 2>/dev/null || log_warning "Install jq or python3 for catalog listing"
    }
}

# Load detector catalog
load_catalog() {
    if [ ! -f "$DETECTOR_CATALOG" ]; then
        log_error "Detector catalog not found: $DETECTOR_CATALOG"
        exit 1
    fi

    log_info "Loading detector catalog..."

    # Validate JSON
    if ! python3 -c "import json; json.load(open('$DETECTOR_CATALOG'))" 2>/dev/null; then
        log_error "Invalid JSON in detector catalog"
        exit 1
    fi

    log_success "Catalog loaded"
}

# Run a single detector (passive mode - no bypass)
run_detector_passive() {
    local detector_name="$1"
    local package_name="$2"
    local output_file="$3"

    local detector_file="$SCRIPT_DIR/rasp-detectors/${detector_name}.js"

    if [ ! -f "$detector_file" ]; then
        log_warning "Detector script not found: $detector_file"
        return 1
    fi

    log_info "Running detector: $detector_name"

    # Passive mode: spawn app and run detector without bypass
    local result
    result=$(frida -U -f "$package_name" -l "$detector_file" 2>/dev/null || true)

    if [ -n "$result" ]; then
        echo "$result" >> "$output_file"
        log_success "Detector $detector_name completed"
        return 0
    else
        log_warning "Detector $detector_name returned no output"
        return 1
    fi
}

# Run a single detector (active mode - with bypass)
run_detector_active() {
    local detector_name="$1"
    local package_name="$2"
    local output_file="$3"

    local detector_file="$SCRIPT_DIR/rasp-detectors/${detector_name}.js"

    if [ ! -f "$detector_file" ]; then
        log_warning "Detector script not found: $detector_file"
        return 1
    fi

    log_info "Running detector (ACTIVE): $detector_name"

    # Active mode: run with bypass flags
    local result
    result=$(frida -U -f "$package_name" -l "$detector_file" -e "Session.enableJit()" 2>/dev/null || true)

    if [ -n "$result" ]; then
        echo "$result" >> "$output_file"
        log_success "Detector $detector_name completed (active)"
        return 0
    else
        log_warning "Detector $detector_name returned no output"
        return 1
    fi
}

# Output JSON results
output_json() {
    local output_file="$1"
    local mode="$2"
    local findings_count="$3"
    local triggered_count="$4"

    local json_output
    json_output=$(python3 -c "
import json
import sys

# Build findings array from output file
findings = []
if [ -f '$output_file' ] && [ \$(wc -l < '$output_file') -gt 0 ]; then
    try:
        with open('$output_file') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except:
                        pass
    except:
        pass

# Build summary
summary = {
    'total_detectors_run': $findings_count,
    'detectors_triggered': $triggered_count,
    'mode': '$mode',
    'scan_complete': True
}

# Build final output
output = {
    'mode': '$mode',
    'findings': findings,
    'summary': summary
}

print(json.dumps(output, indent=2))
" 2>/dev/null || echo "{\"mode\":\"$mode\",\"findings\":[],\"summary\":{\"error\":\"JSON generation failed\"}}")

    echo "$json_output"
}

# Main execution
main() {
    local apk_file=""
    local package_name=""
    local active_mode=false
    local authorized_lab=false
    local list_only=false
    local output_file="findings-rda.json"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                ;;
            --active-mode)
                active_mode=true
                shift
                ;;
            --authorized-lab)
                authorized_lab=true
                shift
                ;;
            --list)
                list_only=true
                shift
                ;;
            --output)
                output_file="$2"
                shift 2
                ;;
            --*)
                log_error "Unknown option: $1"
                show_help
                ;;
            *)
                if [ -z "$apk_file" ]; then
                    apk_file="$1"
                elif [ -z "$package_name" ]; then
                    package_name="$1"
                fi
                shift
                ;;
        esac
    done

    # Security check: active mode requires authorized-lab
    if [ "$active_mode" = true ] && [ "$authorized_lab" = false ]; then
        log_error "ACTIVE MODE REQUIRES --authorized-lab FLAG"
        log_error "Active probing can cause instability. Provide --authorized-lab to acknowledge."
        exit 1
    fi

    if [ "$list_only" = true ]; then
        list_detectors
        exit 0
    fi

    if [ -z "$package_name" ]; then
        log_error "Package name is required"
        show_help
    fi

    check_frida || exit 1
    load_catalog

    log_section "Runtime Defense Analysis"
    log_info "Package: $package_name"
    log_info "Mode: $([ "$active_mode" = true ] && echo "ACTIVE (bypass enabled)" || echo "PASSIVE (read-only)")"

    # Initialize output file
    echo "" > "$output_file"

    local findings_count=0

    # Run each detector
    local detectors
    detectors=$(python3 -c "
import json
with open('$DETECTOR_CATALOG') as f:
    catalog = json.load(f)
    for det in catalog['detectors']:
        detector_file = det.get('file')
        if detector_file and detector_file != 'none':
            print(detector_file)
" 2>/dev/null || echo "")

    for detector_file in $detectors; do
        local detector_name="${detector_file%.js}"
        if [ "$active_mode" = true ]; then
            if run_detector_active "$detector_name" "$package_name" "$output_file"; then
                findings_count=$((findings_count + 1))
            fi
        else
            if run_detector_passive "$detector_name" "$package_name" "$output_file"; then
                findings_count=$((findings_count + 1))
            fi
        fi
    done

    log_section "RDA Complete"
    log_success "Executed $findings_count detectors"

    # Count triggered detectors
    local triggered_count=0
    if [ -f "$output_file" ] && [ "$(wc -l < "$output_file")" -gt 0 ]; then
        triggered_count=$(grep -c '"triggered": true' "$output_file" 2>/dev/null || echo "0")
        log_info "Detectors triggered: $triggered_count"
    fi

    # Output JSON results
    local mode="passive"
    if [ "$active_mode" = true ]; then
        mode="active"
    fi

    log_section "JSON Output"
    output_json "$output_file" "$mode" "$findings_count" "$triggered_count" > "${output_file%.json}-report.json"
    log_success "Report: ${output_file%.json}-report.json"

    # Move JSON output to final location
    mv "${output_file%.json}-report.json" "$output_file" 2>/dev/null || true
    log_success "Final output: $output_file"
}

main "$@"