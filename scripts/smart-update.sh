#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# NightOwl Smart Update v4.0 — Incremental Installer
# Only installs missing dependencies. Skips what's already present.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS="$ROOT/tools"
VENV="$ROOT/.venv"

# ─── Colors ───────────────────────────────────────────────────────────
R='\033[0;31m'  G='\033[0;32m'  Y='\033[1;33m'
C='\033[0;36m'  B='\033[1m'     D='\033[0;37m'  N='\033[0m'

ok()   { echo -e "  ${G}✓${N} $1"; }
skip() { echo -e "  ${D}⊘ $1 (already installed)${N}"; }
warn() { echo -e "  ${Y}⚠ $1${N}"; }
fail() { echo -e "  ${R}✗ $1${N}"; }
hdr()  { echo -e "\n${C}━━━ $1 ━━━${N}"; }

# ─── Counters ─────────────────────────────────────────────────────────
INSTALLED=0
SKIPPED=0
FAILED=0
TOTAL_START=$(date +%s)

banner() {
    echo -e "${C}"
    echo "  +--------------------------------------------------+"
    echo "  |  NightOwl Smart Update v4.0                      |"
    echo "  |  Incremental Dependency Installer                 |"
    echo "  +--------------------------------------------------+"
    echo -e "${N}"
}

# ═══════════════════════════════════════════════════════════════════════
# CHECK HELPERS
# ═══════════════════════════════════════════════════════════════════════

has_cmd() { command -v "$1" &>/dev/null; }
has_pip() { python3 -c "import $1" 2>/dev/null; }
has_apt() { dpkg -l "$1" 2>/dev/null | grep -q "^ii"; }

need_cmd() {
    local name="$1" install_fn="$2"
    if has_cmd "$name"; then
        skip "$name"
        ((SKIPPED++))
    else
        $install_fn && ok "$name installed" && ((INSTALLED++)) || { fail "$name"; ((FAILED++)); }
    fi
}

need_pip() {
    local pkg="$1" import_name="${2:-$1}"
    if has_pip "$import_name"; then
        skip "pip: $pkg"
        ((SKIPPED++))
    else
        pip install -q "$pkg" && ok "pip: $pkg" && ((INSTALLED++)) || { fail "pip: $pkg"; ((FAILED++)); }
    fi
}

need_apt() {
    local pkg="$1"
    if has_apt "$pkg"; then
        skip "apt: $pkg"
        ((SKIPPED++))
    else
        sudo apt-get install -y -qq "$pkg" >/dev/null 2>&1 && ok "apt: $pkg" && ((INSTALLED++)) || { fail "apt: $pkg"; ((FAILED++)); }
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 1 — SYSTEM PACKAGES
# ═══════════════════════════════════════════════════════════════════════

install_system() {
    hdr "Phase 1: System Packages"
    sudo apt-get update -qq >/dev/null 2>&1 || warn "apt update failed (continuing)"

    local pkgs=(
        python3 python3-pip python3-venv
        default-jdk
        git wget curl unzip
        build-essential
        android-sdk
        adb
        apktool
        smali
        zipalign
    )
    for pkg in "${pkgs[@]}"; do
        need_apt "$pkg"
    done
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 2 — PYTHON VENV & PACKAGES
# ═══════════════════════════════════════════════════════════════════════

install_python() {
    hdr "Phase 2: Python Environment"

    # Create venv if missing
    if [ ! -d "$VENV" ]; then
        python3 -m venv "$VENV"
        ok "Virtual environment created"
        ((INSTALLED++))
    else
        skip "Virtual environment"
        ((SKIPPED++))
    fi

    # Activate venv
    source "$VENV/bin/activate"
    pip install --upgrade pip -q 2>/dev/null

    # Python packages (name, import_name)
    local packages=(
        "androguard:androguard"
        "frida-tools:frida"
        "objection:objection"
        "r2pipe:r2pipe"
        "rich:rich"
        "tabulate:tabulate"
        "lxml:lxml"
        "xmltodict:xmltodict"
        "requests:requests"
        "cryptography:cryptography"
        "pyelftools:elftools"
        "oletools:oletools"
        "colorama:colorama"
        "pyyaml:yaml"
    )
    for entry in "${packages[@]}"; do
        IFS=':' read -r pkg imp <<< "$entry"
        need_pip "$pkg" "$imp"
    done
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 3 — BINARY TOOLS
# ═══════════════════════════════════════════════════════════════════════

install_jadx() {
    local JADX_DIR="$TOOLS/jadx"
    if [ -f "$JADX_DIR/bin/jadx" ]; then
        skip "jadx"
        ((SKIPPED++))
        return
    fi
    mkdir -p "$JADX_DIR"
    local VER="1.5.1"
    wget -qO /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${VER}/jadx-${VER}.zip"
    unzip -qo /tmp/jadx.zip -d "$JADX_DIR" && rm -f /tmp/jadx.zip
    chmod +x "$JADX_DIR/bin/jadx" "$JADX_DIR/bin/jadx-gui" 2>/dev/null || true
    ok "jadx $VER"
    ((INSTALLED++))
}

install_ghidra() {
    local GHIDRA_DIR="$TOOLS/ghidra"
    if [ -d "$GHIDRA_DIR" ] && ls "$GHIDRA_DIR"/ghidra*/ghidraRun 2>/dev/null; then
        skip "Ghidra"
        ((SKIPPED++))
        return
    fi
    mkdir -p "$GHIDRA_DIR"
    local VER="11.3.1" DATE="20250219"
    local URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${VER}_build/ghidra_${VER}_PUBLIC_${DATE}.zip"
    wget -qO /tmp/ghidra.zip "$URL"
    unzip -qo /tmp/ghidra.zip -d "$GHIDRA_DIR" && rm -f /tmp/ghidra.zip
    ok "Ghidra $VER"
    ((INSTALLED++))
}

install_r2() {
    if has_cmd "r2"; then
        skip "radare2"
        ((SKIPPED++))
        return
    fi
    if has_cmd "git"; then
        git clone --depth 1 https://github.com/radareorg/radare2 /tmp/radare2 2>/dev/null
        (cd /tmp/radare2 && sys/install.sh >/dev/null 2>&1) && ok "radare2" && ((INSTALLED++)) || { fail "radare2"; ((FAILED++)); }
        rm -rf /tmp/radare2
    else
        fail "radare2 (git not available)"
        ((FAILED++))
    fi
}

install_dex2jar() {
    local D2J="$TOOLS/dex2jar"
    if [ -f "$D2J/d2j-dex2jar.sh" ]; then
        skip "dex2jar"
        ((SKIPPED++))
        return
    fi
    mkdir -p "$D2J"
    local VER="2.4"
    wget -qO /tmp/d2j.zip "https://github.com/pxb1988/dex2jar/releases/download/v${VER}/dex-tools-v${VER}.zip"
    unzip -qo /tmp/d2j.zip -d /tmp/d2j-tmp && rm -f /tmp/d2j.zip
    mv /tmp/d2j-tmp/dex-tools-*/* "$D2J/" 2>/dev/null || mv /tmp/d2j-tmp/* "$D2J/" 2>/dev/null
    chmod +x "$D2J"/*.sh 2>/dev/null || true
    rm -rf /tmp/d2j-tmp
    ok "dex2jar $VER"
    ((INSTALLED++))
}

install_nuclei() {
    if has_cmd "nuclei"; then
        skip "nuclei"
        ((SKIPPED++))
        return
    fi
    if has_cmd "go"; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null \
            && ok "nuclei" && ((INSTALLED++)) || { fail "nuclei"; ((FAILED++)); }
    else
        warn "nuclei skipped (Go not installed)"
        ((SKIPPED++))
    fi
}

install_mitmproxy() {
    if has_cmd "mitmproxy"; then
        skip "mitmproxy"
        ((SKIPPED++))
        return
    fi
    pip install mitmproxy -q 2>/dev/null && ok "mitmproxy" && ((INSTALLED++)) || { fail "mitmproxy"; ((FAILED++)); }
}

install_binaries() {
    hdr "Phase 3: Binary Tools"
    mkdir -p "$TOOLS"
    install_jadx
    install_ghidra
    install_r2
    install_dex2jar
    install_nuclei
    install_mitmproxy
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 4 — DIRECTORY STRUCTURE
# ═══════════════════════════════════════════════════════════════════════

setup_dirs() {
    hdr "Phase 4: Directory Structure"
    local dirs=(
        "$ROOT/targets"
        "$ROOT/workspace/reports"
        "$ROOT/workspace/decompiled"
        "$ROOT/workspace/logs"
        "$ROOT/frida-scripts"
        "$ROOT/androguard-scripts"
        "$ROOT/scripts"
    )
    for d in "${dirs[@]}"; do
        if [ -d "$d" ]; then
            skip "$(basename "$d")/"
            ((SKIPPED++))
        else
            mkdir -p "$d"
            ok "Created $(basename "$d")/"
            ((INSTALLED++))
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 5 — ENV SETUP
# ═══════════════════════════════════════════════════════════════════════

setup_env() {
    hdr "Phase 5: Environment"
    local ENV_FILE="$ROOT/env.sh"
    if [ -f "$ENV_FILE" ] && grep -q "NIGHTOWL_ROOT" "$ENV_FILE"; then
        skip "env.sh"
        ((SKIPPED++))
    else
        cat > "$ENV_FILE" << 'ENVEOF'
#!/usr/bin/env bash
# NightOwl v4.0 Environment
export NIGHTOWL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$NIGHTOWL_ROOT:$NIGHTOWL_ROOT/tools/jadx/bin:$NIGHTOWL_ROOT/tools/dex2jar:$PATH"

# Activate venv
[ -d "$NIGHTOWL_ROOT/.venv" ] && source "$NIGHTOWL_ROOT/.venv/bin/activate"

# Aliases
alias nightowl="python3 $NIGHTOWL_ROOT/nightowl.py"
alias nightowl-full="python3 $NIGHTOWL_ROOT/nightowl.py full"
alias nightowl-scan="python3 $NIGHTOWL_ROOT/nightowl.py scan"

# Frida helpers
alias frida-deploy='adb push $NIGHTOWL_ROOT/tools/frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"'
alias frida-intercept='frida -U -f'

# Objection
obj() { objection -g "$1" explore; }

echo "🦉 NightOwl environment loaded — type 'nightowl guide' for help"
ENVEOF
        chmod +x "$ENV_FILE"
        ok "env.sh generated"
        ((INSTALLED++))
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 6 — VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

verify() {
    hdr "Phase 6: Verification"
    local checks=0 passed=0

    verify_one() {
        local label="$1" cmd="$2"
        ((checks++))
        if eval "$cmd" >/dev/null 2>&1; then
            ok "$label"
            ((passed++))
        else
            fail "$label"
        fi
    }

    verify_one "Python 3"       "python3 --version"
    verify_one "pip"             "pip --version"
    verify_one "androguard"      "python3 -c 'import androguard'"
    verify_one "frida"           "python3 -c 'import frida'"
    verify_one "rich"            "python3 -c 'import rich'"
    verify_one "r2pipe"          "python3 -c 'import r2pipe'"
    verify_one "adb"             "adb version"
    verify_one "jadx"            "test -f $TOOLS/jadx/bin/jadx"
    verify_one "nightowl.py"     "python3 -c \"import py_compile; py_compile.compile('$ROOT/nightowl.py', doraise=True)\""
    verify_one "targets/ dir"    "test -d $ROOT/targets"
    verify_one "reports/ dir"    "test -d $ROOT/workspace/reports"

    echo ""
    echo -e "  ${B}Verification: $passed/$checks passed${N}"
}

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

main() {
    banner

    echo -e "  ${D}Root: $ROOT${N}"
    echo -e "  ${D}Date: $(date '+%Y-%m-%d %H:%M:%S')${N}"
    echo ""

    install_system
    install_python
    install_binaries
    setup_dirs
    setup_env
    verify

    local TOTAL_END=$(date +%s)
    local ELAPSED=$((TOTAL_END - TOTAL_START))

    hdr "Summary"
    echo -e "  ${G}Installed:${N}  $INSTALLED"
    echo -e "  ${D}Skipped:${N}   $SKIPPED"
    echo -e "  ${R}Failed:${N}    $FAILED"
    echo -e "  ${D}Time:${N}      ${ELAPSED}s"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "  ${G}${B}🦉 NightOwl environment is ready!${N}"
    else
        echo -e "  ${Y}⚠ Some packages failed — check above for details${N}"
    fi

    echo -e "  ${D}Run: source env.sh && nightowl guide${N}"
    echo ""
}

main "$@"
