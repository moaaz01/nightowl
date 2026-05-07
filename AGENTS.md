# AGENTS.md — NightOwl Agent Integration Guide

Instructions for AI agents (Hermes, Claude, GPT, etc.) using NightOwl programmatically.

## Identity

| Field | Value |
|-------|-------|
| Tool | NightOwl v4.0 |
| Type | Android APK static security analyzer |
| Entry | `nightowl.py` (single-file, no install needed) |
| Runtime | Python 3.12+ |
| Deps | androguard, cryptography, rich |

## Environment

```bash
# Activate venv before any invocation
source venv/bin/activate

# Or use venv python directly
./venv/bin/python3 nightowl.py <cmd> <apk>
```

## Smart Path Resolution

NightOwl auto-resolves APK paths:
- `nightowl full app.apk` → tries `./app.apk`, then `targets/app.apk`
- `nightowl full targets/app.apk` → direct path

## Commands for Agents

### Full Analysis (recommended starting point)
```bash
python3 nightowl.py full <apk> --json
```
Returns complete JSON with all analysis sections.

### Targeted Extractions
```bash
python3 nightowl.py apis <apk> --json      # Endpoints only
python3 nightowl.py secrets <apk> --json   # Secrets only
python3 nightowl.py vulns <apk> --json     # Vulnerabilities only
python3 nightowl.py manifest <apk> --json  # Components only
python3 nightowl.py info <apk> --json      # Basic info only
```

### Decompile (for source-level review)
```bash
python3 nightowl.py decompile <apk> --out ./output
# Then: grep -r 'password\|secret\|key' ./output/jadx-src/
```

### Batch Scan
```bash
python3 nightowl.py scan ./targets/ --json
```

## JSON Output Schema

```json
{
  "tool": "NightOwl v4.0",
  "ts": "2026-04-13T12:00:00",
  "apk": "/path/to/app.apk",
  "info": {
    "package": "com.example.app",
    "version_name": "1.0.0",
    "min_sdk": "23",
    "target_sdk": "34",
    "signing": "v2",
    "hashes": { "md5": "...", "sha1": "...", "sha256": "..." }
  },
  "perms": { "all": [], "dangerous": [], "normal": [] },
  "endpoints": {
    "urls": [],
    "api": [],
    "servers": [],
    "domains": [],
    "ips": [],
    "emails": [],
    "auth_patterns": []
  },
  "secrets": [
    { "type": "AWS Key", "value": "AKIA***", "risk": "CRITICAL" }
  ],
  "security": {
    "score": 69,
    "issues": []
  },
  "arch": {
    "frameworks": ["Flutter"],
    "libraries": ["Firebase"],
    "native": ["libflutter.so"]
  },
  "vulns": [
    { "id": "V-001", "title": "...", "risk": "HIGH", "rec": "..." }
  ],
  "manifest": {
    "activities": [],
    "services": [],
    "receivers": [],
    "providers": []
  }
}
```

## Scoring System

- Starts at 100, deducts per finding
- CRITICAL: -20, HIGH: -10, MEDIUM: -5, LOW: -2
- Flutter-aware: reduced penalties for framework artifacts
- Cap: max 25 total secrets penalty (15 for Flutter)
- Score >= 80: SAFE, >= 60: MODERATE, < 60: HIGH RISK

## Agent Task Patterns

### "Is this APK safe?"
```bash
python3 nightowl.py full app.apk --json | jq '.security.score'
# Score >= 80 = likely safe
```

### "What APIs does this app call?"
```bash
python3 nightowl.py apis app.apk --json | jq '.endpoints.servers'
```

### "Find all hardcoded credentials"
```bash
python3 nightowl.py secrets app.apk --json | jq '[.secrets[] | select(.risk == "CRITICAL" or .risk == "HIGH")]'
```

### "What permissions does it request?"
```bash
python3 nightowl.py info app.apk --json | jq '.perms.dangerous'
```

### "Generate Arabic security report"
```bash
python3 nightowl.py full app.apk --save --lang ar
# Output: workspace/reports/app_<timestamp>.html
```

### "Compare two APKs"
```bash
python3 nightowl.py full app_v1.apk --json > v1.json
python3 nightowl.py full app_v2.apk --json > v2.json
python3 -c "
import json
v1 = json.load(open('v1.json'))
v2 = json.load(open('v2.json'))
print(f'v1 score: {v1[\"security\"][\"score\"]}')
print(f'v2 score: {v2[\"security\"][\"score\"]}')
print(f'New endpoints: {set(v2[\"endpoints\"][\"servers\"]) - set(v1[\"endpoints\"][\"servers\"])}')
"
```

## Error Handling

- Missing APK: returns exit code 1 with error message
- Tool not found (jadx/apktool): gracefully skips, reports SKIPPED
- Timeout: 300s for decompilation, 180s for apktool
- Malformed APK: androguard raises, caught and reported

## Known Limitations

1. **Static only** — no runtime/dynamic analysis (use Frida scripts manually)
2. **Flutter detection** — binary string extraction, not full Dart decompilation
3. **Obfuscated code** — jadx `--deobf` helps but can't fully deobfuscate
4. **Large APKs** — analysis time scales with APK size (>100MB may timeout)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (APK not found, analysis failed) |
| 2 | Invalid arguments |
