---
name: nightowl
description: |
  Android APK Security Analyzer — Static + Dynamic with Frida, RASP bypass, Source-to-Sink tracing,
  CVSS 4.0 scoring, and MASVS compliance. Use when user wants to analyze an APK for security issues,
  extract secrets/endpoints, bypass SSL pinning, bypass root detection, trace data flows, generate
  professional reports, or audit Android apps against OWASP MASVS/MSTG standards.
category: mobile-security
version: 5.0-merged
tools_required:
  - python3.12
  - androguard>=4.1.3
  - cryptography>=46.0.5
  - rich>=13.7.1
  - frida>=17.9
  - apktool>=3.0.1
  - jadx
  - apksigner
  - apkid

file: nightowl.py
---

# NightOwl v5.0 — Merged Android Security Suite
## (NightOwl + DragonJAR Android-Pentesting-Skill)

Static + Dynamic Android APK security analyzer. Combines NightOwl's ease-of-use and Arabic reports with DragonJAR's source-to-sink tracing, CVSS 4.0 scoring, and 40+ Frida scripts.

## When to Use

- General APK security analysis
- Extract API endpoints, hardcoded secrets, vulnerabilities
- Bypass SSL pinning, root detection, RASP defenses, Frida detection
- Trace source-to-sink data flows
- Deep link / intent injection testing
- Flutter, React Native, Cordova, Xamarin framework detection
- APK repackaging and smali patching
- CVSS 4.0 / MASVS compliance scoring
- OWASP MASVS/MSTG audit
- Malware analysis

## Activation Phrases

```
"فحص أمني", "حلل APK", "NightOwl", "analyze APK", "SSL pinning bypass"
"root detection bypass", "trace data flow", "OWASP audit"
"MASVS scoring", "CVSS 4.0", "Flutter traffic"
```

## Commands

```bash
# === NightOwl Commands ===
source ~/shamcash/venv/bin/activate
python3 nightowl.py full <apk> [--json|--save] [--lang ar]
python3 nightowl.py apis <apk>
python3 nightowl.py secrets <apk>
python3 nightowl.py vulns <apk>
python3 nightowl.py manifest <apk>
python3 nightowl.py scan <dir>
python3 nightowl.py proxy

# === DragonJAR Phase Commands ===
bash scripts/auto-audit-static.sh <apk> [--semgrep]
bash scripts/02-rasp/runtime-defense-analyzer.sh <apk> <package>
bash scripts/02-rasp/rasp-bypass-runner.sh --package <pkg> --from-rda <rda.json> --print-command
bash scripts/02-rasp/rasp-bypass-runner.sh --package <pkg> --from-rda <rda.json> --run --authorized-lab

# === Frida Script Direct Execution ===
frida -U -l frida-scripts/<script.js> -f <package> [--no-pause>
```

## Frida Scripts Available (40+)

| Script | Purpose |
|--------|---------|
| `ssl-pinning-bypass.js` | Bypass OkHttp3 CertificatePinner |
| `network-security-bypass.js` | Bypass Network Security Config |
| `root-detection-bypass.js` | Bypass root/rootbeer detection |
| `anti-frida-bypass.js` | Bypass Frida detection |
| `rasp-bypass.js` | Universal RASP bypass |
| `flutter-channel-hook.js` | Flutter method channel interception |
| `native-hook.js` | Hook native .so functions |
| `crypto-intercept.js` | Hook crypto operations |
| `jwt-token-monitor.js` | Monitor JWT creation/validation |
| `webview-monitor.js` | Monitor WebView loadUrl/evaluateJavascript |
| `intent-logger.js` | Log intent handling |
| `ipc-abuse-helper.js` | IPC component abuse |
| `jni-tracer.js` | JNI method tracing |
| `network-interceptor-enhanced.js` | Full traffic interception |
| `biometric-bypass.js` | Biometric authentication bypass |
| `packer-unpacker.js` | APK unpacker/packer |
| `memory-dump.js` | Dump app memory |
| `shared-prefs-dumper.js` | Export SharedPreferences |

**Full list:** `ls ~/shamcash/frida-scripts/`

## CVSS 4.0 Scoring

DragonJAR's scoring module generates CVSS 4.0 compliant scores:

```bash
# Calculate CVSS 4.0
python3 scripts/05-scoring/cvss4-calculator.py --input findings.json
```

Report format includes:
- CVSS 4.0 vector string
- MASVS compliance score (e.g., 72.6/100)
- Executive risk context

## Source-to-Sink Tracing (Phase 3)

DragonJAR methodology for tracing data flows:

| Source | Method | Sink | Impact |
|--------|--------|------|--------|
| `getIntent()` | Intent data | `Runtime.exec()` | RCE |
| Deep links | URL params | `loadUrl()` | XSS |
| `getParcelableExtra()` | Nested intent | `startActivity()` | Intent injection |
| SharedPreferences | User input | `FileOutputStream` | Path traversal |
| `query()` | Content provider | `execSQL()` | SQL injection |

## Audit Modes

| Mode | Description |
|-----|-------------|
| `quick` | Triage — decode, manifest, focused checks |
| `static` | No device — static only |
| `full` | Static + Dynamic + MASVS + CVSS 4.0 |
| `protected-app` | RASP/packing detection + bypass |
| `reporting-only` | Score existing findings |

## Framework Detection

Automatically detects:

- **Flutter** — `libflutter.so`, `flutter_assets/`
- **React Native** — `libhermes.so`, `index.android.bundle`
- **Cordova/Ionic** — `org.apache.cordova`, `assets/www/`
- **Xamarin** — `libmonodroid.so`

## Workflow Example

```bash
# 1. Full static scan with NightOwl
source venv/bin/activate
python3 nightowl.py full targets/app.apk --json --save --lang ar

# 2. RASP detection with DragonJAR
bash scripts/02-rasp/runtime-defense-analyzer.sh targets/app.apk com.target.app --output rda.json

# 3. Generate Frida bypass command
bash scripts/02-rasp/rasp-bypass-runner.sh --package com.target.app --from-rda rda.json --print-command

# 4. Run with authorized device
bash scripts/02-rasp/rasp-bypass-runner.sh --package com.target.app --from-rda rda.json --run --authorized-lab

# 5. Intercept Flutter traffic
frida -U -l frida-scripts/flutter-channel-hook.js -f com.target.app

# 6. CVSS 4.0 scoring
python3 scripts/05-scoring/cvss4-calculator.py --input findings.json
```

## Key References (77 files)

- `references-dragonjar/cvss-scoring-guide.md` — CVSS 4.0 guide
- `references-dragonjar/android-manifest-checklist.md` — 50+ manifest checks
- `references-dragonjar/attack-patterns.md` — Modern attack vectors
- `references-dragonjar/flutter-blutter-analysis.md` — Flutter traffic analysis
- `references-dragonjar/deep-link-exploitation.md` — Deep link abuse
- `references-dragonjar/intent-injection.md` — Intent injection patterns
- `references-dragonjar/biometric-testing-comprehensive.md` — Biometric bypass
- `references-dragonjar/apk-modification-guide.md` — Repackaging guide

## NightOwl JSON Schema

```
.security.score          # 0-100 score
.security.issues[]       # List of issues
.secrets[]               # Found secrets
.endpoints.servers[]     # Backend servers
.endpoints.api[]          # API paths
.vulns[]                 # Vulnerabilities
.info.package            # Package name
.info.min_sdk            # Minimum SDK
.arch.frameworks[]        # Detected frameworks
```

## MASVS Scoring

- 100 = clean, 0 = critical
- CRITICAL = -20, HIGH = -10, MEDIUM = -5, LOW = -2
- >= 80: SAFE | >= 60: MODERATE | < 60: HIGH RISK
