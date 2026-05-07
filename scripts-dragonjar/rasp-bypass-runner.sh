#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROFILE_FILE="$SCRIPT_DIR/bypass-profiles.json"
source "$PROJECT_ROOT/scripts/lib/colors.sh"

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; }

usage() {
    cat <<'USAGE'
RASP Bypass Runner

USAGE:
    rasp-bypass-runner.sh --package <package.name> --detectors <name[,name...]> [--print-command]
    rasp-bypass-runner.sh --package <package.name> --from-rda findings-rda.json [--print-command]
    rasp-bypass-runner.sh --list-profiles
    rasp-bypass-runner.sh --profile <name>

OPTIONS:
    --package        Android package name to spawn with Frida.
    --detectors      Comma-separated detector/profile names, e.g. rootbeer,frida_detect,talsec.
    --from-rda       RDA JSON report. Triggered finding names are mapped to bypass profiles.
    --run            Execute Frida. Requires --authorized-lab.
    --authorized-lab Required with --run to acknowledge authorized test scope.
    --print-command  Print final Frida command (default when --run is absent).
    --list-profiles  List available bypass profiles.
    --profile        Show one profile's scripts, coverage, and limits.
    --help, -h       Show this help.

SAFETY:
    Authorized lab validation only. This runner does not forge server-side
    attestation verdicts. For Approov/Play Integrity/SafetyNet, validate server
    behavior with an authorized test tenant, backend allowlist, or mock verifier.
USAGE
}

require_python() {
    command -v python3 >/dev/null 2>&1 || { log_error "python3 is required"; exit 2; }
}

profile_tool() {
    require_python
    python3 - "$PROFILE_FILE" "$PROJECT_ROOT" "$@" <<'PY_SCRIPT'
import json, shlex, sys
from pathlib import Path
profile_file, project_root, mode, *args = sys.argv[1:]
data = json.load(open(profile_file))
profiles = data["profiles"]

if mode == "list":
    for name, profile in sorted(profiles.items()):
        print(f"{name:16s} {profile['category']:28s} scripts={len(profile['scripts'])}")
    sys.exit(0)

if mode == "show":
    name = args[0]
    if name not in profiles:
        print(f"Profile not found: {name}", file=sys.stderr)
        sys.exit(1)
    profile = profiles[name]
    print(f"Profile: {name}")
    print(f"Category: {profile['category']}")
    print("Scripts:")
    for script in profile["scripts"]:
        print(f"  - {script}")
    print("Validates:")
    for item in profile.get("validates", []):
        print(f"  - {item}")
    print(f"Limits: {profile.get('limits', 'None documented')}")
    sys.exit(0)

if mode == "build":
    package_name, detectors_csv, rda_file = args
    requested = []
    if detectors_csv:
        requested.extend(x.strip() for x in detectors_csv.split(',') if x.strip())
    if rda_file:
        report = json.load(open(rda_file))
        for finding in report.get("findings", []):
            if finding.get("triggered") is True:
                for key in ("detector", "name", "id"):
                    value = finding.get(key)
                    if value:
                        requested.append(str(value))
                        break
    selected_profiles, warnings = [], []
    scripts, script_seen = [], set()
    for raw_name in requested:
        name = raw_name.replace('-', '_')
        if name not in profiles:
            warnings.append(f"No bypass profile for detector '{raw_name}'")
            continue
        selected_profiles.append(name)
        for script in profiles[name]["scripts"]:
            path = Path(project_root) / script
            if not path.is_file():
                warnings.append(f"Missing bypass script for {name}: {script}")
                continue
            if script not in script_seen:
                script_seen.add(script)
                scripts.append(script)
    command = ["frida", "-U", "-f", package_name]
    for script in scripts:
        command.extend(["-l", str(Path(project_root) / script)])
    output = {
        "profiles": selected_profiles,
        "scripts": scripts,
        "warnings": warnings,
        "command": " ".join(shlex.quote(part) for part in command),
    }
    print(json.dumps(output, indent=2))
    sys.exit(0)

print(f"Unknown mode: {mode}", file=sys.stderr)
sys.exit(2)
PY_SCRIPT
}

main() {
    local package_name=""
    local detectors_csv=""
    local rda_file=""
    local run=false
    local authorized_lab=false
    local profile_name=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h) usage; exit 0 ;;
            --package) package_name="${2:-}"; shift 2 ;;
            --detectors) detectors_csv="${2:-}"; shift 2 ;;
            --from-rda) rda_file="${2:-}"; shift 2 ;;
            --run) run=true; shift ;;
            --authorized-lab) authorized_lab=true; shift ;;
            --print-command) shift ;;
            --list-profiles) profile_tool list; exit 0 ;;
            --profile) profile_name="${2:-}"; shift 2 ;;
            *) log_error "Unknown argument: $1"; usage; exit 2 ;;
        esac
    done

    if [ -n "$profile_name" ]; then
        profile_tool show "$profile_name"
        exit 0
    fi
    if [ -z "$package_name" ]; then
        log_error "--package is required unless using --list-profiles or --profile"
        usage
        exit 2
    fi
    if [ -z "$detectors_csv" ] && [ -z "$rda_file" ]; then
        log_error "Provide --detectors or --from-rda"
        usage
        exit 2
    fi
    if [ -n "$rda_file" ] && [ ! -f "$rda_file" ]; then
        log_error "RDA report not found: $rda_file"
        exit 1
    fi
    if [ "$run" = true ] && [ "$authorized_lab" = false ]; then
        log_error "--run requires --authorized-lab"
        exit 1
    fi

    local stack_json
    stack_json="$(profile_tool build "$package_name" "$detectors_csv" "$rda_file")"
    echo "$stack_json" | python3 -c 'import json,sys; data=json.load(sys.stdin); [print("[!] "+w, file=sys.stderr) for w in data["warnings"]]'

    local command
    command="$(echo "$stack_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["command"])')"
    local scripts_count
    scripts_count="$(echo "$stack_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["scripts"]))')"
    if [ "$scripts_count" -eq 0 ]; then
        log_error "No bypass scripts selected"
        exit 1
    fi

    log_info "Selected profiles: $(echo "$stack_json" | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["profiles"]))')"
    printf '%s\n' "$command"

    if [ "$run" = true ]; then
        command -v frida >/dev/null 2>&1 || { log_error "frida is required to run"; exit 2; }
        log_warning "Running bypass stack in authorized-lab mode"
        eval "$command"
    fi
}

main "$@"
