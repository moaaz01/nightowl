#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# NightOwl v4.0 — Network Analysis Setup
# Configures mitmproxy, Burp Suite bridge, and device proxy
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

R='\033[0;31m'  G='\033[0;32m'  Y='\033[1;33m'
C='\033[0;36m'  B='\033[1m'     D='\033[0;37m'  N='\033[0m'

ok()   { echo -e "  ${G}✓${N} $1"; }
fail() { echo -e "  ${R}✗${N} $1"; }
warn() { echo -e "  ${Y}⚠${N} $1"; }
info() { echo -e "  ${C}ℹ${N} $1"; }

banner() {
    echo -e "${C}"
    echo "  +--------------------------------------------------+"
    echo "  |  NightOwl -- Network Analysis Setup              |"
    echo "  |  mitmproxy / Burp Suite / Device Proxy           |"
    echo "  +--------------------------------------------------+"
    echo -e "${N}"
}

# ─── Get host IP ──────────────────────────────────────────────────────
get_host_ip() {
    local ip
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [ -z "$ip" ]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    echo "${ip:-127.0.0.1}"
}

HOST_IP=$(get_host_ip)
PROXY_PORT="${NIGHTOWL_PROXY_PORT:-8080}"
CERT_DIR="$ROOT/workspace/certs"

# ═══════════════════════════════════════════════════════════════════════
# MITMPROXY
# ═══════════════════════════════════════════════════════════════════════

setup_mitmproxy() {
    echo -e "\n${C}--- mitmproxy Setup ---${N}"

    if ! command -v mitmproxy &>/dev/null; then
        info "Installing mitmproxy..."
        pip install mitmproxy -q 2>/dev/null && ok "mitmproxy installed" || { fail "mitmproxy install failed"; return 1; }
    else
        ok "mitmproxy already installed ($(mitmproxy --version 2>/dev/null | head -1))"
    fi

    # Generate CA if not exists
    mkdir -p "$CERT_DIR"
    if [ ! -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]; then
        info "Generating mitmproxy CA certificate..."
        timeout 3 mitmproxy --listen-port 0 2>/dev/null || true
    fi

    if [ -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]; then
        cp "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" "$CERT_DIR/mitmproxy-ca.pem" 2>/dev/null
        ok "CA certificate copied to $CERT_DIR/"
    fi

    echo ""
    info "To start mitmproxy:"
    echo -e "    ${Y}mitmproxy --listen-port $PROXY_PORT${N}"
    echo -e "    ${Y}mitmweb --listen-port $PROXY_PORT --web-port 8081${N}  ${D}(web UI)${N}"
    echo -e "    ${Y}mitmdump --listen-port $PROXY_PORT -w traffic.flow${N}  ${D}(dump to file)${N}"
}

# ═══════════════════════════════════════════════════════════════════════
# BURP SUITE BRIDGE
# ═══════════════════════════════════════════════════════════════════════

setup_burp() {
    echo -e "\n${C}--- Burp Suite Bridge ---${N}"

    info "Burp Suite manual configuration:"
    echo ""
    echo -e "  ${B}Step 1:${N} Open Burp Suite → Proxy → Proxy Settings"
    echo -e "  ${B}Step 2:${N} Add listener → Bind to: ${Y}0.0.0.0:$PROXY_PORT${N}"
    echo -e "  ${B}Step 3:${N} Export CA: Proxy → Options → Import/Export CA"
    echo -e "  ${B}Step 4:${N} Save DER cert as ${Y}$CERT_DIR/burp-ca.der${N}"
    echo ""
    echo -e "  ${D}Convert to PEM:${N}"
    echo -e "    ${Y}openssl x509 -inform DER -in $CERT_DIR/burp-ca.der -out $CERT_DIR/burp-ca.pem${N}"

    # Provide chain through mitmproxy to Burp (upstream proxy)
    echo ""
    info "Chain mitmproxy → Burp (captures in both):"
    echo -e "    ${Y}mitmproxy --listen-port 8081 --mode upstream:http://127.0.0.1:$PROXY_PORT${N}"
}

# ═══════════════════════════════════════════════════════════════════════
# DEVICE PROXY
# ═══════════════════════════════════════════════════════════════════════

setup_device_proxy() {
    echo -e "\n${C}--- Device Proxy ---${N}"

    if ! command -v adb &>/dev/null; then
        fail "adb not found — install android-sdk"
        return 1
    fi

    # Check device connection
    local devices
    devices=$(adb devices 2>/dev/null | grep -c "device$")
    if [ "$devices" -eq 0 ]; then
        warn "No Android device connected"
        info "Connect via USB or: ${Y}adb connect DEVICE_IP:5555${N}"
        echo ""
    else
        ok "$devices device(s) connected"
    fi

    echo ""
    info "Set proxy on device:"
    echo -e "    ${Y}adb shell settings put global http_proxy $HOST_IP:$PROXY_PORT${N}"
    echo ""
    info "Clear proxy:"
    echo -e "    ${Y}adb shell settings put global http_proxy :0${N}"
    echo ""

    echo -e "  ${B}Apply now? (y/N):${N} "
    read -r choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        adb shell settings put global http_proxy "$HOST_IP:$PROXY_PORT" 2>/dev/null \
            && ok "Proxy set to $HOST_IP:$PROXY_PORT" \
            || fail "Failed to set proxy"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# INSTALL CA TO DEVICE
# ═══════════════════════════════════════════════════════════════════════

install_ca_cert() {
    echo -e "\n${C}--- Install CA Certificate on Device ---${N}"

    local cert=""
    if [ -f "$CERT_DIR/mitmproxy-ca.pem" ]; then
        cert="$CERT_DIR/mitmproxy-ca.pem"
        info "Using mitmproxy CA"
    elif [ -f "$CERT_DIR/burp-ca.pem" ]; then
        cert="$CERT_DIR/burp-ca.pem"
        info "Using Burp Suite CA"
    elif [ -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]; then
        cert="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
        info "Using default mitmproxy CA"
    fi

    if [ -z "$cert" ]; then
        warn "No CA certificate found. Run mitmproxy first or export from Burp."
        return 1
    fi

    echo ""
    info "Method 1 — User certificate (non-root):"
    echo -e "    ${Y}adb push $cert /sdcard/ca-cert.pem${N}"
    echo -e "    Then: Settings → Security → Install from storage"
    echo ""

    info "Method 2 — System certificate (root required):"
    local hash
    hash=$(openssl x509 -inform PEM -subject_hash_old -in "$cert" 2>/dev/null | head -1)
    if [ -n "$hash" ]; then
        echo -e "    ${Y}# Convert and push as system cert${N}"
        echo -e "    ${Y}openssl x509 -inform PEM -in $cert -out /tmp/${hash}.0${N}"
        echo -e "    ${Y}adb root${N}"
        echo -e "    ${Y}adb remount${N}"
        echo -e "    ${Y}adb push /tmp/${hash}.0 /system/etc/security/cacerts/${N}"
        echo -e "    ${Y}adb shell chmod 644 /system/etc/security/cacerts/${hash}.0${N}"
        echo -e "    ${Y}adb reboot${N}"
    else
        echo -e "    ${D}(could not compute cert hash — openssl may be missing)${N}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════════════════════════════════

show_status() {
    echo -e "\n${C}--- Network Status ---${N}"

    echo -e "  ${B}Host IP:${N}     $HOST_IP"
    echo -e "  ${B}Proxy Port:${N}  $PROXY_PORT"
    echo ""

    # Check mitmproxy
    if command -v mitmproxy &>/dev/null; then
        ok "mitmproxy installed"
    else
        fail "mitmproxy not installed"
    fi

    # Check adb
    if command -v adb &>/dev/null; then
        local devs
        devs=$(adb devices 2>/dev/null | grep -c "device$")
        ok "adb available ($devs device(s))"
    else
        fail "adb not available"
    fi

    # Check if proxy listener is active
    if ss -tlnp 2>/dev/null | grep -q ":$PROXY_PORT "; then
        ok "Port $PROXY_PORT is listening"
    else
        warn "Port $PROXY_PORT not listening (proxy not running)"
    fi

    # Check cert
    if [ -f "$CERT_DIR/mitmproxy-ca.pem" ] || [ -f "$CERT_DIR/burp-ca.pem" ]; then
        ok "CA certificate available in $CERT_DIR/"
    else
        warn "No CA certificate — run setup first"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════
# TEARDOWN
# ═══════════════════════════════════════════════════════════════════════

teardown() {
    echo -e "\n${C}--- Teardown ---${N}"

    # Clear device proxy
    if command -v adb &>/dev/null; then
        adb shell settings put global http_proxy :0 2>/dev/null \
            && ok "Device proxy cleared" || warn "Could not clear device proxy"
    fi

    # Kill mitmproxy if running
    pkill -f mitmproxy 2>/dev/null && ok "mitmproxy stopped" || info "mitmproxy was not running"
    pkill -f mitmdump  2>/dev/null && ok "mitmdump stopped"  || true

    echo ""
    ok "Network teardown complete"
}

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  setup       Full setup (mitmproxy + burp bridge + device)"
    echo "  mitmproxy   Setup mitmproxy only"
    echo "  burp        Burp Suite bridge instructions"
    echo "  device      Configure device proxy"
    echo "  cert        Install CA certificate on device"
    echo "  status      Show network analysis status"
    echo "  teardown    Stop proxies and clear device settings"
    echo "  help        Show this message"
}

main() {
    banner

    case "${1:-setup}" in
        setup)
            setup_mitmproxy
            setup_burp
            setup_device_proxy
            install_ca_cert
            show_status
            ;;
        mitmproxy)  setup_mitmproxy ;;
        burp)       setup_burp ;;
        device)     setup_device_proxy ;;
        cert)       install_ca_cert ;;
        status)     show_status ;;
        teardown)   teardown ;;
        help|--help|-h) usage ;;
        *)
            fail "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
