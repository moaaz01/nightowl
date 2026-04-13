<div align="center">

# 🦉 NightOwl

### Advanced Android APK Security Analyzer

**Static + Dynamic Analysis · OWASP MSTG Aligned · Agent-Ready**

[![Version](https://img.shields.io/badge/version-4.0-blue.svg)](https://github.com/moaaz01/nightowl)
[![Python](https://img.shields.io/badge/python-3.12+-green.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-49%20passing-brightgreen.svg)](tests/)

</div>

---

**NightOwl** is a comprehensive Android APK security analyzer that performs deep static analysis across 9 sections and integrates with dynamic analysis tools (Frida, Objection). Designed for security researchers, penetration testers, and AI agents.

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **9-Section Analysis** | Info, Permissions, URLs, Secrets, Architecture, Vulnerabilities, Manifest, APIs, Decompilation |
| **Native .so Scanning** | Extracts strings from `libapp.so`, `libflutter.so`, and other native libs (Flutter/RN support) |
| **55+ Secret Patterns** | AWS, GCP, Stripe, PayPal, Telegram, JWT, Firebase, SSH keys, and more |
| **Shannon Entropy Filter** | Real entropy calculation to eliminate binary noise false positives |
| **Security Scoring** | Weighted category scoring with letter grades (A+ → F) and OWASP-aligned risk levels |
| **Deep Link Analysis** | Detects unverified App Links, HTTP deep links, and autoVerify status |
| **Certificate Inspection** | Signing certificate details, expiry warnings, key strength checks |
| **HTML + MD + JSON Reports** | Interactive tabbed HTML, Markdown, and machine-readable JSON output |
| **Frida Scripts** | 4 ready-made scripts: API interceptor, SSL bypass, memory dump, hooks |
| **Batch Scanning** | Scan entire directories of APKs at once |
| **Agent Integration** | Full SKILL.md for AI agent use — structured JSON output, jq examples |

## 📦 Installation

### Quick Install

```bash
git clone https://github.com/moaaz01/nightowl.git
cd nightowl
bash scripts/install-ultimate.sh
source env.sh
```

### Manual Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install binary tools (jadx, dex2jar, radare2)
bash scripts/install-ultimate.sh
```

### Requirements

- **Python 3.12+**
- **Java JDK 8+** (for jadx/apktool)
- **Android SDK** (adb)
- See [requirements.txt](requirements.txt) for Python packages

## 🚀 Usage

### Static Analysis Commands

```bash
# Full 9-section analysis (recommended)
nightowl full app.apk

# Individual sections
nightowl info app.apk          # Basic info & hashes
nightowl perms app.apk        # Permission risk analysis
nightowl urls app.apk         # URLs, endpoints, servers
nightowl secrets app.apk      # API keys, tokens, passwords
nightowl arch app.apk         # Frameworks & libraries
nightowl vulns app.apk        # Security score & vulnerabilities
nightowl manifest app.apk     # Components & activities
nightowl apis app.apk         # Fast API/endpoint extraction
nightowl decompile app.apk    # Full decompile: jadx + apktool + native

# Batch scan all APKs in targets/
nightowl scan

# Usage guide
nightowl guide
```

### Output Flags

```bash
nightowl full app.apk --json          # JSON only (for scripting & agents)
nightowl full app.apk --save         # Save HTML + MD + JSON reports
nightowl full app.apk --lang ar      # Arabic report translations
nightowl full app.apk --report-dir ./output  # Custom output directory
```

### Dynamic Analysis (requires rooted device)

```bash
# 1. Load environment
source env.sh

# 2. Deploy Frida server to device
frida-deploy

# 3. Intercept API traffic + SSL bypass
frida-intercept com.app -l frida-scripts/api-interceptor.js

# 4. Dedicated SSL pinning bypass
frida -f com.app -l frida-scripts/ssl-bypass.js --no-pause

# 5. Memory analysis & secret scanning
frida -f com.app -l frida-scripts/memory-dump.js --no-pause

# 6. Interactive objection shell
obj com.app
```

## 📊 Analysis Sections

| # | Section | What It Detects |
|---|---------|----------------|
| 1 | **Info** | Package name, version, SDK levels, hashes (MD5/SHA1/SHA256), file size |
| 2 | **Permissions** | Dangerous/normal permissions with risk levels and descriptions |
| 3 | **URLs** | All URLs, API endpoints, server domains, IP addresses |
| 4 | **Secrets** | 55+ patterns: API keys, tokens, passwords, private keys, cloud credentials |
| 5 | **Architecture** | Frameworks (Flutter, React Native, Unity), native libraries, packer detection |
| 6 | **Vulnerabilities** | Security score with category weights, debug flags, backup enabled, cleartext traffic |
| 7 | **Manifest** | Activities, services, receivers, providers, exported components, deep links |
| 8 | **APIs** | Retrofit/OkHttp/Volley endpoints, URL path patterns, HTTP methods |
| 9 | **Decompile** | jadx source + apktool resources + native .so string extraction |

## 🔐 Secret Detection Patterns

NightOwl detects **55+ secret patterns** across these categories:

| Category | Examples |
|----------|---------|
| **Cloud** | AWS Access Key (`AKIA...`), GCP API Key, Azure Credential |
| **Payments** | Stripe (`sk_live_`, `pk_live_`), PayPal, Square |
| **Messaging** | Telegram Bot Token, Discord Bot Token, Slack Webhook |
| **Auth** | JWT (`eyJ...`), Bearer Token, Basic Auth |
| **Database** | PostgreSQL/MySQL/MongoDB URIs, Redis URL |
| **DevOps** | GitHub Token (`ghp_`), GitLab Token, Heroku API Key |
| **Social** | Twitter/Facebook/LinkedIn API keys |
| **SSH** | Private keys (`-----BEGIN RSA`), SSH config patterns |
| **Mobile** | Firebase (`AIzaSy...`), SendGrid, Twilio SID |

Each pattern includes a **description**, **risk level** (critical/high/medium/low), and **entropy validation** to reduce false positives.

## 📁 Project Structure

```
nightowl/
├── nightowl.py              # Main analyzer (single-file, portable)
├── env.sh                   # Environment setup (auto-generated)
├── requirements.txt          # Python dependencies
├── requirements-python.txt  # Detailed Python packages (pinned)
├── LICENSE                  # MIT License
├── AGENTS.md                # AI agent integration guide
├── README.md                # This file
├── frida-scripts/
│   ├── api-interceptor.js   # HTTP/HTTPS traffic capture
│   ├── ssl-bypass.js        # SSL pinning bypass
│   ├── memory-dump.js       # Memory scanning & secrets
│   └── hooks.js             # Crypto, auth, root detection hooks
├── androguard-scripts/
│   ├── analyze.py            # Androguard CLI wrapper
│   ├── extract-strings.py   # String extraction
│   └── find-permissions.py  # Permission finder
├── scripts/
│   ├── install-ultimate.sh  # Full dependency installer
│   ├── install-all.sh        # Alternative installer
│   ├── smart-update.sh      # Incremental update script
│   └── network-setup.sh    # Network/proxy configuration
├── skills/nightowl/
│   └── SKILL.md             # AI agent skill definition
├── tests/
│   ├── test_nightowl.py     # 49 unit tests
│   ├── create_test_apk.py   # Test APK generator
│   └── __init__.py
└── tools/                   # Binary tools (installed by scripts)
    ├── jadx/                # Java decompiler
    ├── dex2jar/             # DEX to JAR converter
    └── ghidra/              # Reverse engineering suite
```

## 🤖 AI Agent Integration

NightOwl is designed for agent-driven security analysis. The [SKILL.md](skills/nightowl/SKILL.md) and [AGENTS.md](AGENTS.md) provide complete integration guides.

```bash
# JSON output for agents
nightowl full app.apk --json

# Parse with jq
nightowl secrets app.apk --json | jq '.secrets.critical[]'

# Batch process
nightowl scan --json | jq '.[] | select(.grade == "F")'
```

## 🧪 Testing

```bash
# Run all 49 tests
python -m pytest tests/ -v

# Or directly
python tests/test_nightowl.py
```

Tests cover: validation, secret patterns, analyzer logic, scoring, report generation, and constants.

## 📜 License

[MIT License](LICENSE) — Free for authorized security testing and research.

---

<div align="center">

**🦉 Built for security researchers who demand depth.**

</div>