---
name: nightowl
description: Android APK static security analyzer — extracts secrets, endpoints, vulnerabilities, and generates interactive HTML reports. Use when the user wants to analyze an APK file, check for security issues, extract API endpoints, find hardcoded secrets, or generate security reports.
category: devops
version: 4.0
tools_required:
  - python3.12
  - androguard>=4.1.3
  - cryptography>=46.0.5
  - rich>=13.7.1
file: nightowl.py
---

# NightOwl v4.0 — Android APK Security Analyzer

Static security analyzer for Android APK files. Designed for both human use and AI agent orchestration.

## When to Use

- User wants to analyze an APK file for security issues
- User asks "is this app safe?" or "what does this app do?"
- User wants to extract API endpoints from an APK
- User wants to find hardcoded secrets/keys in an APK
- User wants a security report for an APK
- User wants to decompile an APK for source review

## Invocation

```bash
# Activate venv first
source venv/bin/activate

# Or use venv python directly
./venv/bin/python3 nightowl.py <command> <apk_path> [flags]
```

## Commands

| Command | Use When |
|---------|----------|
| `full <apk>` | General security analysis (default choice) |
| `apis <apk>` | Only need API endpoints |
| `secrets <apk>` | Only need hardcoded secrets |
| `vulns <apk>` | Only need vulnerability list |
| `manifest <apk>` | Only need component list |
| `info <apk>` | Only need basic APK info |
| `decompile <apk>` | Need source code review |
| `scan [dir]` | Batch analyze multiple APKs |
| `guide` | Show usage help |
| `proxy` | Network proxy setup |

## Flags

| Flag | Purpose |
|------|---------|
| `--json` | Machine-readable JSON (for agent parsing) |
| `--save` | Save HTML/MD/JSON report files |
| `--report-dir D` | Custom output directory |
| `--lang ar` | Arabic report sections |

## Output Locations

- Reports: `workspace/reports/` (or `--report-dir`)
- Decompiled: `workspace/decompiled/<apk_name>/`
- APKs: `targets/` directory

## Agent Usage Patterns

### Full Security Assessment
```bash
python3 nightowl.py full targets/app.apk --json
```
Parse JSON for `security.score`, `secrets`, `vulns`, `endpoints`.

### Extract Critical Secrets Only
```bash
python3 nightowl.py secrets targets/app.apk --json | jq '[.secrets[] | select(.risk == "CRITICAL")]'
```

### Get All API Servers
```bash
python3 nightowl.py apis targets/app.apk --json | jq '.endpoints.servers'
```

### Generate Shareable Report
```bash
python3 nightowl.py full targets/app.apk --save --lang ar
# Returns path to HTML report
```

### Batch Scan
```bash
python3 nightowl.py scan targets/ --json
```

## JSON Schema (Key Paths)

```
.security.score          # 0-100 score
.security.issues[]       # List of issues
.secrets[]               # Found secrets (type, value, risk)
.endpoints.servers[]     # Backend servers
.endpoints.api[]         # API paths
.vulns[]                 # Vulnerabilities (id, title, risk, rec)
.info.package            # Package name
.info.min_sdk            # Minimum SDK
.arch.frameworks[]       # Detected frameworks (Flutter, React Native, etc.)
```

## Scoring

- 100 = clean, 0 = critical issues
- CRITICAL finding = -20, HIGH = -10, MEDIUM = -5, LOW = -2
- Flutter apps: reduced penalties for framework noise
- >= 80: SAFE | >= 60: MODERATE | < 60: HIGH RISK

## Pitfalls

1. **Flutter apps**: DEX scanning alone misses everything. NightOwl handles this by scanning native `.so` files automatically.
2. **Large APKs**: >100MB may timeout. Use `apis` command for faster partial analysis.
3. **jadx/apktool optional**: If not installed, decompile reports SKIPPED. Other commands work without them.
4. **Paths**: Always use relative to project root or absolute paths. `targets/` is the default APK drop folder.

## Example Agent Conversation

```
User: Analyze this APK for security issues
Agent: python3 nightowl.py full targets/app.apk --json
Agent: [parses JSON, reports score, critical findings, endpoints]

User: Is it safe?
Agent: Score is 65/100 (MODERATE). Found 2 CRITICAL secrets and 3 HIGH vulnerabilities.

User: Give me a report in Arabic
Agent: python3 nightowl.py full targets/app.apk --save --lang ar
Agent: Report saved to workspace/reports/app_20260413_120000.html
```
