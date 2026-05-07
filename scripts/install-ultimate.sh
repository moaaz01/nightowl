#!/usr/bin/env bash

###############################################################################
# NightOwl — Ultimate Android Security Environment
# ONE-COMMAND INSTALLER v3.0
#
# Usage:
#   chmod +x install-ultimate.sh && ./install-ultimate.sh
#   or:
#   bash install-ultimate.sh
###############################################################################

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
B='\033[0;34m'; C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'
ok()  { echo -e "  ${G}[✓]${N} $*"; }
nok() { echo -e "  ${R}[✗]${N} $*"; }
inf() { echo -e "  ${B}[▸]${N} $*"; }
wrn() { echo -e "  ${Y}[!]${N} $*"; }
hdr() { echo -e "\n${C}${W}── $* ──${N}"; }

# ─── Dirs ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS="$ROOT/tools"
WS="$ROOT/workspace"
mkdir -p "$TOOLS" "$WS/apps" "$WS/decompiled" "$WS/analysis" "$WS/reports"

# ─── OS Detection ─────────────────────────────────────────────────────────────
detect_os() {
    if   [[ "$OSTYPE" == linux-gnu* ]]; then OS=linux
    elif [[ "$OSTYPE" == darwin* ]];    then OS=macos
    elif grep -qi microsoft /proc/version 2>/dev/null; then OS=wsl
    else OS=unknown; fi
    inf "Detected OS: $OS"
}

# ─── System Dependencies ──────────────────────────────────────────────────────
install_system_deps() {
    hdr "System Dependencies"
    if [[ "$OS" == linux || "$OS" == wsl ]]; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
                openjdk-17-jdk git curl wget unzip python3 python3-pip \
                python3-venv python3-dev build-essential libssl-dev \
                adb android-tools-adb golang-go radare2 \
                2>/dev/null || true
        elif command -v pacman &>/dev/null; then
            sudo pacman -Syu --noconfirm jdk17-openjdk git curl wget \
                unzip python python-pip base-devel radare2 android-tools go
        fi
    elif [[ "$OS" == macos ]]; then
        command -v brew &>/dev/null || { nok "Homebrew required: https://brew.sh"; exit 1; }
        brew update -q
        brew install openjdk@17 git curl wget python3 radare2 go android-platform-tools 2>/dev/null || true
        brew install --cask ghidra 2>/dev/null || wrn "Ghidra Cask failed — will download manually"
    fi
    ok "System dependencies ready"
}

# ─── Python Virtual Environment ───────────────────────────────────────────────
setup_python_env() {
    hdr "Python Environment"
    if [[ ! -d "$ROOT/.venv" ]]; then
        inf "Creating virtual environment…"
        python3 -m venv "$ROOT/.venv"
    fi
    source "$ROOT/.venv/bin/activate"
    pip install --upgrade pip setuptools wheel -q
    ok "Python venv active: $ROOT/.venv"
}

# ─── Python Packages ──────────────────────────────────────────────────────────
install_python_packages() {
    hdr "Python Security Packages"
    source "$ROOT/.venv/bin/activate" 2>/dev/null || true

    PACKAGES=(
        "androguard==4.1.3"
        "frida-tools"
        "frida"
        "objection"
        "apkid"
        "quark-engine"
        "lief"
        "capstone"
        "unicorn"
        "r2pipe"
        "pycryptodome"
        "requests"
        "colorama"
        "pyyaml"
        "rich"
        "tabulate"
        "paramiko"
        "xmltodict"
        "pyelftools"
        "oletools"
    )

    for pkg in "${PACKAGES[@]}"; do
        inf "Installing $pkg…"
        pip install "$pkg" -q 2>&1 | tail -1 || wrn "Failed: $pkg"
    done
    ok "All Python packages installed"
}

# ─── Java Tools ───────────────────────────────────────────────────────────────
download_java_tools() {
    hdr "Java Tools (JADX / Apktool / dex2jar)"
    cd "$TOOLS"

    # JADX
    if [[ ! -d jadx ]]; then
        inf "Downloading JADX…"
        JADX_VER="1.5.0"
        wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" \
             -O jadx.zip && unzip -q jadx.zip -d jadx && rm jadx.zip
        chmod +x jadx/bin/jadx jadx/bin/jadx-gui 2>/dev/null || true
        ok "JADX $JADX_VER"
    else ok "JADX already installed"; fi

    # Apktool
    if [[ ! -f apktool.jar ]]; then
        inf "Downloading Apktool…"
        APKT_VER="3.0.1"
        wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKT_VER}/apktool_${APKT_VER}.jar" \
             -O apktool.jar
        # wrapper script
        cat > "$TOOLS/apktool" <<'WRAP'
#!/bin/bash
java -jar "$(dirname "$0")/apktool.jar" "$@"
WRAP
        chmod +x "$TOOLS/apktool"
        ok "Apktool $APKT_VER"
    else ok "Apktool already installed"; fi

    # dex2jar
    if [[ ! -d dex2jar ]]; then
        inf "Downloading dex2jar…"
        wget -q "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip" \
             -O d2j.zip && unzip -q d2j.zip && mv dex-tools-v2.4 dex2jar && rm d2j.zip
        chmod +x dex2jar/bin/d2j-dex2jar.sh 2>/dev/null || true
        ok "dex2jar 2.4"
    else ok "dex2jar already installed"; fi

    # Ghidra
    if [[ ! -d ghidra ]]; then
        inf "Downloading Ghidra…"
        GHIDRA_VER="11.3.1"
        GHIDRA_TAG="${GHIDRA_VER}_PUBLIC"
        GHIDRA_DATE="20250219"
        GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_TAG}_${GHIDRA_DATE}.zip"
        wget -q "$GHIDRA_URL" -O ghidra.zip \
            && unzip -q ghidra.zip \
            && mv ghidra_* ghidra \
            && rm ghidra.zip \
            && chmod +x ghidra/ghidraRun.sh 2>/dev/null || true
        ok "Ghidra $GHIDRA_VER"
    else ok "Ghidra already installed"; fi
}

# ─── Binary Tools ─────────────────────────────────────────────────────────────
install_binary_tools() {
    hdr "Binary Tools (radare2 / Nuclei)"

    # radare2 — already installed via apt above
    if command -v radare2 &>/dev/null; then
        ok "radare2 $(radare2 -v 2>/dev/null | head -1 | cut -d' ' -f2)"
    else
        inf "Building radare2 from source…"
        cd /tmp && git clone -q --depth 1 https://github.com/radareorg/radare2 radare2-src
        cd radare2-src && ./sys/install.sh -q
        ok "radare2 installed from source"
    fi

    # Nuclei
    if ! command -v nuclei &>/dev/null; then
        if command -v go &>/dev/null; then
            inf "Installing Nuclei…"
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
            export PATH="$HOME/go/bin:$PATH"
            ok "Nuclei installed"
        else
            wrn "Go not found — Nuclei skipped. Install Go then run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        fi
    else
        ok "Nuclei $(nuclei -version 2>/dev/null | head -1)"
    fi
}

# ─── Frida Server (download binaries) ─────────────────────────────────────────
download_frida_server() {
    hdr "Frida Server Binaries"
    mkdir -p "$TOOLS/frida-server"
    cd "$TOOLS/frida-server"

    FRIDA_VER=$(pip show frida 2>/dev/null | grep ^Version | cut -d' ' -f2)
    [[ -z "$FRIDA_VER" ]] && FRIDA_VER="17.2.0"
    inf "Frida version: $FRIDA_VER"

    ARCHS=("android-arm64" "android-arm" "android-x86_64" "android-x86")
    for arch in "${ARCHS[@]}"; do
        fname="frida-server-${FRIDA_VER}-${arch}"
        if [[ ! -f "${fname}.xz" && ! -f "${fname}" ]]; then
            inf "Downloading frida-server for $arch…"
            wget -q \
                "https://github.com/frida/frida/releases/download/${FRIDA_VER}/${fname}.xz" \
                -O "${fname}.xz" && xz -d "${fname}.xz" 2>/dev/null \
                && chmod +x "$fname" \
                && ok "  $arch" \
                || wrn "  Failed: $fname"
        else
            ok "  $arch (cached)"
        fi
    done
}

# ─── Aliases & Environment File ───────────────────────────────────────────────
write_env() {
    hdr "Environment & Aliases"

    cat > "$ROOT/env.sh" <<ENVEOF
#!/usr/bin/env bash
# NightOwl — Android RE Toolkit Environment
# Source this file: source env.sh

export NIGHTOWL_ROOT="$ROOT"
export TOOLS_DIR="$TOOLS"
export WORKSPACE="$WS"

# Activate Python venv
source "$ROOT/.venv/bin/activate" 2>/dev/null || true

# Add tool paths
export PATH="$TOOLS/jadx/bin:$TOOLS:$HOME/go/bin:\$PATH"

# ─── Convenient Aliases ─────────────────────────────────────────────────
alias jadx-gui="$TOOLS/jadx/bin/jadx-gui"
alias jadx="$TOOLS/jadx/bin/jadx"
alias apktool="java -jar $TOOLS/apktool.jar"
alias d2j="$TOOLS/dex2jar/bin/d2j-dex2jar.sh"
alias ghidra="$TOOLS/ghidra/ghidraRun.sh &"

# Quick analysis (main tool)
alias nightowl="python3 $ROOT/nightowl.py"

# Frida helpers
alias frida-list="frida-ps -H 127.0.0.1:27042 2>/dev/null || frida-ps -U"
alias frida-intercept="frida -H 127.0.0.1:27042 -f"
alias frida-attach="frida -H 127.0.0.1:27042 -n"
alias frida-hook="frida -H 127.0.0.1:27042 -f"

# objection shortcut
obj() { objection -H 127.0.0.1:27042 -g "\$1" explore; }

# Push and start frida-server on connected device (ARM64)
frida-deploy() {
    local srv="$TOOLS/frida-server/frida-server-*-android-arm64"
    adb push \$srv /data/local/tmp/frida-server
    adb shell chmod 755 /data/local/tmp/frida-server
    adb shell nohup /data/local/tmp/frida-server &>/dev/null &
    adb forward tcp:27042 tcp:27042
    echo "[+] frida-server deployed and port 27042 forwarded"
}

echo ""
echo "  NightOwl Ultimate RE Toolkit loaded"
echo "  Type 'nightowl app.apk' to start analysis"
echo ""
ENVEOF
    chmod +x "$ROOT/env.sh"
    ok "env.sh written → source $ROOT/env.sh"
}

# ─── Verification ─────────────────────────────────────────────────────────────
verify() {
    hdr "Installation Verification"

    source "$ROOT/.venv/bin/activate" 2>/dev/null || true
    export PATH="$TOOLS/jadx/bin:$TOOLS:$HOME/go/bin:$PATH"

    check() {
        local name="$1" cmd="$2"
        if eval "$cmd" &>/dev/null; then ok "$name"
        else nok "$name"; fi
    }

    # Python packages
    check "androguard"    "python3 -c 'import androguard'"
    check "frida-tools"   "python3 -c 'import frida'"
    check "objection"     "python3 -c 'import objection'"
    check "apkid"         "python3 -c 'import apkid'"
    check "quark-engine"  "python3 -c 'import quark'"
    check "capstone"      "python3 -c 'import capstone'"
    check "lief"          "python3 -c 'import lief'"
    check "unicorn"       "python3 -c 'import unicorn'"
    check "r2pipe"        "python3 -c 'import r2pipe'"
    check "rich"          "python3 -c 'import rich'"
    check "tabulate"      "python3 -c 'import tabulate'"

    # Binaries
    check "JADX"          "[[ -f $TOOLS/jadx/bin/jadx ]]"
    check "Apktool"       "[[ -f $TOOLS/apktool.jar ]]"
    check "dex2jar"       "[[ -d $TOOLS/dex2jar ]]"
    check "Ghidra"        "[[ -f $TOOLS/ghidra/ghidraRun.sh ]]"
    check "radare2"       "command -v radare2"
    check "Nuclei"        "command -v nuclei || [[ -f $HOME/go/bin/nuclei ]]"

    # Frida server
    check "frida-server (arm64)" "[[ -f $TOOLS/frida-server/frida-server-*-android-arm64 ]]"

    # NightOwl analyzer
    check "nightowl.py"   "[[ -f $ROOT/nightowl.py ]]"
}

# ─── Final Banner ─────────────────────────────────────────────────────────────
final_banner() {
    echo ""
    echo -e "${G}╔════════════════════════════════════════════════════╗"
    echo -e "║   NightOwl Ultimate RE Toolkit v3.0 — READY!      ║"
    echo -e "╚════════════════════════════════════════════════════╝${N}"
    echo ""
    echo -e "  ${W}To activate the environment in any terminal:${N}"
    echo -e "    ${Y}source $ROOT/env.sh${N}"
    echo ""
    echo -e "  ${W}Quick analysis:${N}"
    echo -e "    ${Y}source $ROOT/env.sh${N}"
    echo -e "    ${Y}nightowl app.apk${N}"
    echo ""
    echo -e "  ${W}Subcommands:${N}"
    echo -e "    ${Y}nightowl full   app.apk${N}   # Full 8-section report"
    echo -e "    ${Y}nightowl info   app.apk${N}   # Basic info only"
    echo -e "    ${Y}nightowl perms  app.apk${N}   # Permissions analysis"
    echo -e "    ${Y}nightowl urls   app.apk${N}   # URLs & API endpoints"
    echo -e "    ${Y}nightowl secrets app.apk${N}  # Secret detection"
    echo -e "    ${Y}nightowl arch   app.apk${N}   # Architecture analysis"
    echo -e "    ${Y}nightowl vulns  app.apk${N}   # Vulnerability scan"
    echo ""
    echo -e "  ${W}Dynamic analysis:${N}"
    echo -e "    ${Y}frida-deploy                              ${C}# push server${N}"
    echo -e "    ${Y}frida-intercept com.example.app -l $ROOT/frida-scripts/api-interceptor.js${N}"
    echo ""
    echo -e "  ${W}Tools directory:${N}   $TOOLS"
    echo -e "  ${W}Workspace:${N}         $WS"
    echo -e "  ${W}Reports will be:${N}   $WS/reports"
    echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo -e "${C}${W}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║    NightOwl — Ultimate Android RE Toolkit Installer     ║"
    echo "║    One-command setup for the world's best mobile RE env ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${N}"

    detect_os
    install_system_deps
    setup_python_env
    install_python_packages
    download_java_tools
    install_binary_tools
    download_frida_server
    write_env
    verify
    final_banner
}

main "$@"
