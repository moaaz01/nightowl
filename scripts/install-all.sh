#!/bin/bash

###############################################################################
# Android Reverse Engineering Toolkit - Installation Script (Linux/macOS)
# Version: 1.0
# Purpose: Automated setup of all Android security testing tools
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_ROOT/tools"
WORKSPACE_DIR="$PROJECT_ROOT/workspace"

# Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        DISTRO=$(lsb_release -si 2>/dev/null || echo "unknown")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
}

install_system_deps() {
    log_info "Installing system dependencies..."

    if [ "$OS" = "linux" ]; then
        if command -v apt-get &> /dev/null; then
            log_info "Detected Debian/Ubuntu - using apt"
            sudo apt-get update
            sudo apt-get install -y \
                openjdk-11-jdk \
                openjdk-11-jdk-headless \
                git \
                python3 \
                python3-pip \
                python3-dev \
                build-essential \
                curl \
                wget \
                unzip \
                default-jdk \
                gcc \
                g++
        elif command -v pacman &> /dev/null; then
            log_info "Detected Arch Linux - using pacman"
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm \
                jdk11-openjdk \
                git \
                python \
                base-devel \
                curl \
                wget \
                unzip
        else
            log_warning "Unsupported Linux distribution. Please install dependencies manually."
        fi
    elif [ "$OS" = "macos" ]; then
        log_info "Detected macOS - using Homebrew"
        if ! command -v brew &> /dev/null; then
            log_error "Homebrew not found. Please install from https://brew.sh"
            exit 1
        fi
        brew update
        brew install \
            openjdk@11 \
            git \
            python3 \
            curl \
            wget \
            unzip
    fi

    log_success "System dependencies installed"
}

install_python_tools() {
    log_info "Installing Python tools..."

    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found. Please install Python 3."
        exit 1
    fi

    python3 -m pip install --upgrade pip setuptools wheel
    python3 -m pip install -r "$PROJECT_ROOT/requirements-python.txt"

    log_success "Python tools installed"
}

download_java_tools() {
    log_info "Downloading Java-based tools..."

    mkdir -p "$TOOLS_DIR"

    # JADX
    log_info "Downloading JADX..."
    JADX_URL="https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip"
    if [ ! -d "$TOOLS_DIR/jadx" ]; then
        cd "$TOOLS_DIR"
        wget -q "$JADX_URL" -O jadx.zip && unzip -q jadx.zip -d jadx && rm jadx.zip
        chmod +x jadx/bin/jadx jadx/bin/jadx-gui
        log_success "JADX downloaded"
    else
        log_warning "JADX already exists"
    fi

    # Apktool
    log_info "Downloading Apktool..."
    APKTOOL_URL="https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar"
    if [ ! -f "$TOOLS_DIR/apktool.jar" ]; then
        cd "$TOOLS_DIR"
        wget -q "$APKTOOL_URL" -O apktool.jar
        chmod +x apktool.jar
        log_success "Apktool downloaded"
    else
        log_warning "Apktool already exists"
    fi

    # dex2jar
    log_info "Downloading dex2jar..."
    DEX2JAR_URL="https://github.com/pxb1988/dex2jar/releases/download/2.1-SNAPSHOT/dex2jar-2.1-SNAPSHOT-dist.zip"
    if [ ! -d "$TOOLS_DIR/dex2jar" ]; then
        cd "$TOOLS_DIR"
        wget -q "$DEX2JAR_URL" -O dex2jar.zip && unzip -q dex2jar.zip && rm dex2jar.zip
        chmod +x dex2jar*/bin/d2j-dex2jar.sh
        log_success "dex2jar downloaded"
    else
        log_warning "dex2jar already exists"
    fi

    # Ghidra
    log_info "Downloading Ghidra..."
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4_build/ghidra_11.4_PUBLIC_20240917.zip"
    if [ ! -d "$TOOLS_DIR/ghidra" ]; then
        cd "$TOOLS_DIR"
        wget -q "$GHIDRA_URL" -O ghidra.zip && unzip -q ghidra.zip && rm ghidra.zip
        chmod +x ghidra*/ghidraRun.sh
        log_success "Ghidra downloaded"
    else
        log_warning "Ghidra already exists"
    fi

    log_success "Java tools downloaded"
}

install_binary_tools() {
    log_info "Installing binary analysis tools..."

    # radare2
    if ! command -v radare2 &> /dev/null; then
        log_info "Installing radare2..."
        if [ "$OS" = "linux" ]; then
            if [ "$DISTRO" = "Ubuntu" ] || [ "$DISTRO" = "Debian" ]; then
                sudo apt-get install -y radare2
            else
                log_warning "Please install radare2 manually: https://radare2.com/"
            fi
        elif [ "$OS" = "macos" ]; then
            brew install radare2
        fi
        log_success "radare2 installed"
    else
        log_warning "radare2 already installed"
    fi

    # Nuclei (Go-based)
    if ! command -v nuclei &> /dev/null; then
        log_info "Installing Nuclei..."
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            log_success "Nuclei installed"
        else
            log_warning "Go not installed. Skipping Nuclei. Install from: https://github.com/projectdiscovery/nuclei"
        fi
    else
        log_warning "Nuclei already installed"
    fi
}

setup_environment() {
    log_info "Setting up environment..."

    # Create workspace directories
    mkdir -p "$WORKSPACE_DIR"/{apps,decompiled,analysis,reports}

    # Create .env file
    cat > "$PROJECT_ROOT/.env.local" <<'EOF'
# Android RE Toolkit Environment Variables

# Tool paths
export JADX_HOME="$PROJECT_ROOT/tools/jadx"
export TOOLS_DIR="$PROJECT_ROOT/tools"
export WORKSPACE_DIR="$PROJECT_ROOT/workspace"

# Python path
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Add tools to PATH
export PATH="$JADX_HOME/bin:$TOOLS_DIR:$PATH"

# Frida configuration
export FRIDA_PAYLOAD_TIMEOUT=30000
export FRIDA_SERVER_PORT=27042
EOF

    log_success "Environment setup complete"
}

create_alias_script() {
    log_info "Creating convenience aliases..."

    cat > "$PROJECT_ROOT/aliases.sh" <<'EOF'
#!/bin/bash
# Convenience aliases for Android RE Toolkit

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$PROJECT_ROOT/tools"

# JADX
alias jadx="$TOOLS_DIR/jadx/bin/jadx"
alias jadx-gui="$TOOLS_DIR/jadx/bin/jadx-gui &"

# Apktool
alias apktool="java -jar $TOOLS_DIR/apktool.jar"

# dex2jar
alias dex2jar="$TOOLS_DIR/dex2jar/bin/d2j-dex2jar.sh"

# Quick analysis commands
alias analyze-apk="python3 $PROJECT_ROOT/androguard-scripts/analyze.py"
alias extract-strings="python3 $PROJECT_ROOT/androguard-scripts/extract-strings.py"
alias check-permissions="python3 $PROJECT_ROOT/androguard-scripts/find-permissions.py"

echo "[✓] Android RE aliases loaded"
EOF

    chmod +x "$PROJECT_ROOT/aliases.sh"
    log_success "Aliases created in: $PROJECT_ROOT/aliases.sh"
}

verify_installation() {
    log_info "Verifying installation..."

    echo ""
    echo -e "${BLUE}Tool Verification:${NC}"

    # Python tools
    python3 -c "import frida; print('  ✓ Frida:', frida.__version__)" 2>/dev/null || echo "  ✗ Frida: NOT INSTALLED"
    python3 -c "import androguard; print('  ✓ Androguard: available')" 2>/dev/null || echo "  ✗ Androguard: NOT INSTALLED"
    python3 -c "import quark; print('  ✓ Quark Engine: available')" 2>/dev/null || echo "  ✗ Quark Engine: NOT INSTALLED"
    python3 -c "import objection; print('  ✓ objection: available')" 2>/dev/null || echo "  ✗ objection: NOT INSTALLED"

    # Java tools
    if [ -f "$TOOLS_DIR/jadx/bin/jadx" ]; then
        echo "  ✓ JADX: installed"
    else
        echo "  ✗ JADX: NOT INSTALLED"
    fi

    if [ -f "$TOOLS_DIR/apktool.jar" ]; then
        echo "  ✓ Apktool: installed"
    else
        echo "  ✗ Apktool: NOT INSTALLED"
    fi

    # Binary tools
    command -v radare2 &> /dev/null && echo "  ✓ radare2: installed" || echo "  ✗ radare2: NOT INSTALLED"
    command -v nuclei &> /dev/null && echo "  ✓ Nuclei: installed" || echo "  ✗ Nuclei: NOT INSTALLED"

    echo ""
}

main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════╗"
    echo "║  Android RE Toolkit - Installation Script  ║"
    echo "║           Version 1.0 - 2026                ║"
    echo "╚════════════════════════════════════════════╝"
    echo -e "${NC}"

    detect_os
    log_info "Detected OS: $OS"

    install_system_deps
    install_python_tools
    download_java_tools
    install_binary_tools
    setup_environment
    create_alias_script
    verify_installation

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    Installation Complete! 🎉               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "To use the tools, source the aliases:"
    echo -e "  ${YELLOW}source $PROJECT_ROOT/aliases.sh${NC}"
    echo ""
    echo -e "Project directory: ${YELLOW}$PROJECT_ROOT${NC}"
    echo -e "Tools directory:   ${YELLOW}$TOOLS_DIR${NC}"
    echo -e "Workspace:         ${YELLOW}$WORKSPACE_DIR${NC}"
    echo ""
    echo -e "Next steps:"
    echo -e "  1. ${YELLOW}source $PROJECT_ROOT/aliases.sh${NC}"
    echo -e "  2. ${YELLOW}cd $WORKSPACE_DIR/apps${NC}"
    echo -e "  3. ${YELLOW}jadx-gui app.apk${NC}"
    echo ""
}

main "$@"
