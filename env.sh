#!/usr/bin/env bash
# NightOwl — Android RE Toolkit Environment
# Source this file: source env.sh

NIGHTOWL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NIGHTOWL_ROOT
export TOOLS_DIR="$NIGHTOWL_ROOT/tools"
export WORKSPACE="$NIGHTOWL_ROOT/workspace"

# Activate Python venv
source "$NIGHTOWL_ROOT/.venv/bin/activate" 2>/dev/null || true

# Add tool paths
export PATH="$TOOLS_DIR/jadx/bin:$TOOLS_DIR:$HOME/go/bin:$PATH"

# ─── Convenient Aliases ─────────────────────────────────────────────────
alias jadx-gui="$TOOLS_DIR/jadx/bin/jadx-gui"
alias jadx="$TOOLS_DIR/jadx/bin/jadx"
alias apktool="java -jar $TOOLS_DIR/apktool.jar"
alias d2j="$TOOLS_DIR/dex2jar/bin/d2j-dex2jar.sh"
alias ghidra="$TOOLS_DIR/ghidra/ghidraRun.sh &"

# Quick analysis (main tool)
alias nightowl="python3 $NIGHTOWL_ROOT/nightowl.py"

# Frida helpers
alias frida-list="frida-ps -H 127.0.0.1:27042 2>/dev/null || frida-ps -U"
alias frida-intercept="frida -H 127.0.0.1:27042 -f"
alias frida-attach="frida -H 127.0.0.1:27042 -n"
alias frida-hook="frida -H 127.0.0.1:27042 -f"

# objection shortcut
obj() { objection -H 127.0.0.1:27042 -g "$1" explore; }

# Push and start frida-server on connected device (ARM64)
frida-deploy() {
    local srv="$TOOLS_DIR/frida-server/frida-server-*-android-arm64"
    adb push $srv /data/local/tmp/frida-server
    adb shell chmod 755 /data/local/tmp/frida-server
    adb shell nohup /data/local/tmp/frida-server &>/dev/null &
    adb forward tcp:27042 tcp:27042
    echo "[+] frida-server deployed and port 27042 forwarded"
}

echo ""
echo "  NightOwl Ultimate RE Toolkit loaded"
echo "  Type 'nightowl app.apk' to start analysis"
echo ""