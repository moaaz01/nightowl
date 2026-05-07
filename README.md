<div align="center">

# 🦉 NightOwl

### Unified Android Security Analysis Platform

**Static Analysis · Framework Detection · RASP Assessment · Automated Bypass · Agent-Ready**

[![Release](https://img.shields.io/github/v/release/moaaz01/nightowl?label=release&color=blue)](https://github.com/moaaz01/nightowl/releases)
[![Python](https://img.shields.io/badge/python-3.12+-green.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![All Tools](https://img.shields.io/badge/tools-24%20commands-8A2BE2.svg)](https://github.com/moaaz01/nightowl#-usage)

</div>

---

**NightOwl** is a unified Android security analysis platform that combines deep static analysis, framework detection, runtime defense assessment, and automated bypass generation into a single command-line interface. Designed for security researchers, penetration testers, and AI agents.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **9-Section APK Analysis** | Info, Permissions, URLs, Secrets, Architecture, Vulnerabilities, Manifest, APIs, Decompilation |
| **DragonJAR Static Audit** | Full static analysis pipeline with jadx, apktool, ripgrep, and strings |
| **Framework Detection** | Automatic Flutter, React Native, Cordova, and Unity analysis |
| **RASP Defense Detection** | Identifies RootBeer, Frida Detection, SafetyNet, Talsec, and 10+ runtime defense mechanisms |
| **Frida Bypass Generation** | Auto-generates optimized bypass scripts per detection profile |
| **Semgrep MASTG Scanning** | OWASP MASVS-aligned rules for automated compliance scanning |
| **CVSS v3.1 Scoring** | Automated severity scoring with grade assignment |
| **55+ Secret Patterns** | AWS, GCP, Stripe, PayPal, Telegram, JWT, Firebase, SSH keys, and more |
| **Shannon Entropy Filter** | Entropy-based false positive elimination from binary noise |
| **Native .so Extraction** | String extraction from libapp.so, libflutter.so, and other native libraries |
| **Security Scoring** | Weighted category scoring with letter grades (A+ through F) |
| **HTML + MD + JSON Reports** | Interactive tabbed HTML, Markdown, and machine-readable JSON |
| **Interactive Wizard** | Guided mode with 12 scan types when run without arguments |
| **Preflight Check** | Validates 15 system tools and 4 Python packages |
| **Batch Scanning** | Scan entire directories of APKs at once |
| **Agent Integration** | Full SKILL.md for AI agent use with structured JSON output |

---

## Installation

### Quick Start

```bash
git clone https://github.com/moaaz01/nightowl.git
cd nightowl
bash scripts/install-ultimate.sh
source env.sh
```

### Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
bash scripts/install-ultimate.sh
```

### Requirements

- **Python 3.12+**
- **Java JDK 8+** (for jadx, apktool)
- **Android SDK** (adb)
- See [requirements.txt](requirements.txt) for full Python dependencies

---

## Usage

### Quick Start

```bash
# Interactive wizard — guided menu
./nightowl

# Full security scan
./nightowl full app.apk

# Preflight dependency check
./nightowl preflight
```

### Full Command Reference

#### Core APK Analysis

```bash
./nightowl full app.apk          # Complete 8-section analysis
./nightowl quick app.apk         # Fast scan (analysis only, minimal rendering)
./nightowl info app.apk          # Package info, version, SDK levels, hashes
./nightowl perms app.apk         # Permission risk analysis
./nightowl urls app.apk          # URLs, endpoints, server domains, IPs
./nightowl secrets app.apk       # API keys, tokens, passwords, private keys
./nightowl vulns app.apk         # Security score and vulnerability assessment
./nightowl manifest app.apk      # Activities, services, receivers, providers
./nightowl apis app.apk          # Fast API endpoint extraction
./nightowl decompile app.apk     # Full decompilation (jadx + apktool)
./nightowl scan [directory]      # Batch scan all APKs in a directory
```

#### DragonJAR Security Modules

```bash
./nightowl static-audit app.apk          # Full DragonJAR static audit
./nightowl static-audit app.apk --reuse-jadx /path  # Reuse existing decompilation
./nightowl semgrep app.apk               # OWASP MASTG compliance scanning
./nightowl semgrep app.apk --reuse-jadx /path       # Reuse decompilation
./nightowl rasp app.apk [package]        # Runtime Application Self-Protection detection
./nightowl bypass <package> [detector_ids]           # Generate Frida bypass scripts
./nightowl preflight                     # Validate all system dependencies
```

#### Framework-Specific Analysis

```bash
./nightowl flutter app.apk         # Flutter security analysis
./nightowl react-native app.apk    # React Native security analysis
./nightowl cordova app.apk         # Cordova security analysis
./nightowl unity app.apk           # Unity security analysis
```

#### Utilities

```bash
./nightowl cvss findings.json      # CVSS v3.1 severity scoring
./nightowl guide                   # Full usage documentation
./nightowl proxy                   # Network proxy configuration
```

### Output Flags

```bash
./nightowl full app.apk --json           # Machine-readable JSON (agent-ready)
./nightowl full app.apk --save           # Save HTML + MD + JSON reports
./nightowl full app.apk --lang ar        # Arabic report translations
./nightowl full app.apk --report-dir ./output  # Custom output directory
```

### Dynamic Analysis (requires rooted Android device)

```bash
source env.sh

frida-deploy                              # Deploy Frida server to device
frida-intercept com.app -l frida-scripts/api-interceptor.js    # API traffic capture
frida -f com.app -l frida-scripts/ssl-bypass.js --no-pause     # SSL pinning bypass
frida -f com.app -l frida-scripts/memory-dump.js --no-pause    # Memory analysis
obj com.app                               # Objection interactive shell
```

---

## Analysis Capabilities

### Core APK Analysis (9 Sections)

| # | Section | Detects |
|---|---------|---------|
| 1 | Info | Package name, version, SDK levels, hashes, file metadata |
| 2 | Permissions | Dangerous/normal permissions with risk assessment |
| 3 | URLs | All URLs, API endpoints, server domains, IP addresses, emails |
| 4 | Secrets | 55+ patterns: API keys, tokens, credentials, private keys |
| 5 | Architecture | Frameworks (Flutter, React Native, Unity), native libraries, packers |
| 6 | Vulnerabilities | Security score, debug flags, backup, cleartext traffic |
| 7 | Manifest | Activities, services, receivers, providers, exported components |
| 8 | APIs | Retrofit/OkHttp/Volley endpoints, URL patterns, HTTP methods |
| 9 | Decompile | jadx source, apktool resources, native .so string extraction |

### DragonJAR Security Audit

| Module | Function |
|--------|----------|
| Static Audit | Full static analysis using jadx decompilation, apktool resource extraction, ripgrep pattern matching, and strings analysis |
| Framework Analysis | Automated detection and analysis of Flutter, React Native, Cordova, and Unity applications |
| RASP Detection | Identifies 10+ runtime defense mechanisms: RootBeer, Frida hooks, SafetyNet, Talsec, DexGuard, emulator checks, debug detection, SSL pinning |
| Bypass Generation | Generates optimized Frida scripts per detection profile with combined bypass option |
| Semgrep Scanner | Runs OWASP MASTG-aligned rules against decompiled source for compliance validation |
| CVSS Scoring | Automated CVSS v3.1 base score calculation with severity grade assignment |

### Secret Detection (55+ Patterns)

| Category | Examples |
|----------|---------|
| Cloud | AWS Access Key (AKIA), GCP API Key, Azure Credential |
| Payments | Stripe (sk_live_, pk_live_), PayPal, Square |
| Messaging | Telegram Bot Token, Discord Bot Token, Slack Webhook |
| Auth | JWT (eyJ), Bearer Token, Basic Auth |
| Database | PostgreSQL, MySQL, MongoDB URIs, Redis URL |
| DevOps | GitHub Token (ghp_), GitLab Token, Heroku API Key |
| Social | Twitter, Facebook, LinkedIn API keys |
| SSH | Private keys (-----BEGIN RSA), SSH config patterns |
| Mobile | Firebase (AIzaSy), SendGrid, Twilio SID |

Each pattern includes description, risk level (critical/high/medium/low), and entropy validation to minimize false positives.

---

## Project Structure

```
nightowl/
├── nightowl                  # Unified entry point (24 commands + wizard)
├── nightowl.py               # Core analysis engine
├── nwcore.py                 # Legacy nwcore package (compatibility)
├── nightowl_pkg/             # Modular analysis package
│   ├── core.py              # NightOwl engine — re-exports original analyzer
│   ├── dragonjar.py         # StaticAuditor, SemgrepScanner, CVSScorer
│   ├── frameworks.py        # Flutter, React Native, Cordova, Unity analyzers
│   ├── runtime.py           # RASPAnalyzer, BypassRunner (Frida scripts)
│   ├── preflight.py         # PreflightChecker (15 tools + 4 packages)
│   └── wizard.py            # Interactive wizard (12 scan modes)
├── scripts-dragonjar/       # DragonJAR reference scripts and rules
│   ├── semgrep-rules/       # OWASP MASTG compliance rules
│   ├── bypass-profiles.json # Frida bypass profile definitions
│   ├── detector-catalog.json # RASP detector catalog
│   └── masvs-mapping.json   # OWASP MASTG control mappings
├── frida-scripts/           # Ready-to-use Frida scripts
│   ├── api-interceptor.js
│   ├── ssl-bypass.js
│   ├── memory-dump.js
│   └── hooks.js
├── androguard-scripts/      # Androguard CLI wrappers
├── scripts/                 # Setup and utility scripts
├── skills/nightowl/         # AI agent skill definition
├── tests/                   # Unit tests
└── tools/                   # Binary tools (installed by scripts)
    ├── jadx/
    ├── dex2jar/
    └── ghidra/
```

---

## AI Agent Integration

NightOwl provides structured JSON output designed for AI agent consumption. See [SKILL.md](skills/nightowl/SKILL.md) and [AGENTS.md](AGENTS.md) for complete integration guides.

```bash
# Structured JSON output
./nightowl full app.apk --json

# Query specific findings
./nightowl secrets app.apk --json | jq '.secrets.critical[]'

# Batch analysis
./nightowl scan --json | jq '.[] | select(.grade == "F")'

# Dependency validation
./nightowl preflight --json
```

---

## Testing

```bash
python -m pytest tests/ -v
```

Tests cover: APK validation, secret pattern detection, analyzer logic, security scoring, report generation, and configuration constants.

---

## License

[MIT License](LICENSE) — Free for authorized security testing and research.

> For authorized security testing only

---

<div align="center">

**Built for security researchers who demand depth.**

</div>
