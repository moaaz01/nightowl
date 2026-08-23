---
name: nightowl
description: >-
  Drive NightOwl v8, a unified Android security analysis platform, from any AI
  agent (OpenClaw, Hermes, Claude Code, Codex, OpenCode). Use when the user
  asks to analyze, scan, or pentest an APK; find hardcoded secrets, login/auth
  flows, API access points, subscription/premium enforcement weaknesses;
  decompile an app; capture traffic through a proxy; or generate Frida
  verification hooks. All commands emit machine-readable JSON with validated,
  confidence-scored findings.
---

# NightOwl v8 — Agent Skill

Unified Android security analysis for agents. Every command supports `--json`
(stable schema), streams human progress to **stderr**, and exits 0/1/2
(success/failure/usage). Never parse the pretty output — always pass `--json`.

## Quick decision table

| User intent | Command |
|---|---|
| "Is this APK safe?" / full audit | `nightowl full <apk> --json` |
| Friendly walkthrough + summary | `nightowl start <apk>` (add `--save`) |
| Find hardcoded keys/tokens | `nightowl secrets <apk> --json` |
| Map login & token flows | `nightowl authmap <apk> --json` |
| Can premium be unlocked client-side? | `nightowl billing <apk> --json` |
| Deep-link/WebView/crypto/intent issues | `nightowl deepscan <apk> --json` |
| Is it packed/obfuscated? (APKiD-style) | `nightowl hardening <apk> --json` |
| Which trackers/privacy SDKs? | `nightowl privacy <apk> --json` |
| Vulnerable libraries / SBOM | `nightowl sca <apk> --json [--save-sbom sbom.json]` |
| List API endpoints | `nightowl endpoints <apk> --json` |
| Get source code | `nightowl decompile <apk>` |
| Intercept HTTPS traffic | `nightowl proxy setup --burp` + `nightowl capture` |
| Runtime lab (adb/frida/objection) | `nightowl lab devices`, `lab ssl <pkg>`, ... |
| Compare two builds | `nightowl diff old.json new.json [--json]` |
| Flutter/Dart deep intel | `nightowl dart <apk> --json` |
| Who uses weak crypto - app or libs? | `nightowl cryptoscope <apk> --json` |
| Exported surface + adb recipes | `nightowl surface <apk> --json` |
| Secrets in decompiled sources | `nightowl secrets-src <apk> --json` |
| Re-render saved JSON as report | `nightowl report saved.json` |

## Invocation

```bash
# from a git clone
./nightowl <command> <apk> --json

# or after `pipx install nightowl-security`
nightowl <command> <apk> --json
export NIGHTOWL_HOME=~/.nightowl   # where reports/artifacts are written
```

APK paths auto-resolve against `./targets/`. Python 3.12+; heavy deps optional
(androguard, rich); external tools (jadx/apktool/semgrep/adb/frida) detected by
`./nightowl preflight`. Set `NIGHTOWL_STATIC_ONLY=1` when handling untrusted
samples to block every command that executes parsers or touches devices.

## JSON contracts

### full → top-level object

```jsonc
{
  "info":   { "package": "...", "version_name": "...", "min_sdk": "...", "sha256": "..." },
  "perms":  { "dangerous": [ { "name": "...", "risk": "CRITICAL", "desc_en": "..." } ] },
  "endpoints": { "urls": [], "api": [], "servers": [], "domains": [], "ips": [] },
  "secrets": [ /* validated findings, see below */ ],
  "secrets_filtered": [ ],       // rejected candidates + why (audit trail)
  "secrets_stats": { "raw_candidates": 0, "reported": 0, "filtered": 0,
                     "confirmed": 0, "likely": 0, "suspected": 0 },
  "security": { "score": 0-100, "grade": "A+..F", "issues": [], "categories": {} },
  "vulns":   [ { "id": "V-001", "title": "", "risk": "", "rec": "", "cat": "" } ],
  "authmap": { "flows": [...], "token_lifecycle": {}, "weaknesses": [...] },
  "billing": { "enforcement_model": "local-only|server-backed|sdk-managed",
               "findings": [...], "verification_script": "path.js" },
  "deepscan":{ "attack_surface": {}, "uri_schemes": [], "findings": [...] },
  "hardening":{ "packers_protectors": {}, "anti_analysis": {} },
  "privacy": { "trackers": {}, "data_collection_permissions": [] },
  "sca":     { "vulnerable": [], "sbom": {} }
}
```

### secrets finding (validated)

```jsonc
{
  "type": "AWS Access Key",
  "value": "FULL VALUE — handle as sensitive",
  "risk": "MEDIUM",              // adjusted risk after validation
  "raw_risk": "CRITICAL",        // pattern-level risk before validation
  "confidence": 90.0,            // 0..100
  "verdict": "CONFIRMED",        // CONFIRMED | LIKELY | SUSPECTED | FILTERED
  "validation": ["well-formed AWS key ID", "high entropy (4.28 b/c)"],
  "context": "±120 chars around the match"
}
```

**Verdict semantics**
- `CONFIRMED` ≥75 — structure valid + positive context. Report as real.
- `LIKELY` 55–74 — plausible. Report with caveat.
- `SUSPECTED` 35–54 — weak evidence. Only mention if user asks broadly.
- `FILTERED` <35 — documentation key / placeholder / public-by-design.
  Excluded from reports and from `vulns`; kept in `secrets_filtered`.

Filter server-side with jq:
```bash
./nightowl secrets app.apk --json | jq '[.secrets[] | select(.confidence >= 75)]'
```

### authmap highlights

- `flows[]`: `{type: login|registration|token|mfa|logout, endpoint, http_method,
  credential_params[], grant_types[], transport}` — credential endpoints and
  the parameters they transmit.
- `token_lifecycle`: storage mechanism, request attachment style, JWT handling.
- `weaknesses[]`: cleartext login (CRITICAL), token-in-URL, unencrypted token
  storage, missing pinning — each MASVS-tagged.

### billing highlights

- `enforcement_model`: `local-only` = premium flags cached on device without
  visible server validation → highest bypass likelihood; `server-backed`;
  `sdk-managed`.
- `verification_script`: generated Frida hook path for runtime confirmation.

### v8 module contracts (compact)

- `hardening`: `packers_protectors{name:{category,evidence}}`,
  `anti_analysis{family:{evidence,count}}`, `obfuscation[]`,
  signing findings incl. Janus (`CVE-2017-13156`) when v1-only.
- `privacy`: `trackers{sdk:evidence}`, `tracker_count`, `ad_sdk_count`,
  `data_collection_permissions[{permission,exposes,category,risk}]`.
- `sca`: `vulnerable[{component,version,advisory,detail}]`,
  `needs_manual_review[]`, `sbom` = CycloneDX 1.5 JSON.
- `diff` result: `score.delta`, `verdict`
  (`IMPROVED|REGRESSED|SCORE_DROP|MIXED`),
  `secrets.added/removed` (values masked), per-layer added/resolved lists.

### Reports (--save / nightowl start --save)

Single-file HTML: dark/light toggle, severity filter chips + live search,
click-to-reveal secret values (base64-encoded at rest — raw values are NOT in
the file), confidence bars, filtered-candidates audit trail, SBOM download.
Markdown mirrors all sections with masked values.

## Recommended agent workflows

### 1. Triage then drill-down
```bash
./nightowl full app.apk --json > /tmp/full.json     # one pass, all layers
jq '.security.grade, .secrets_stats' /tmp/full.json
# then re-run targeted commands only where needed
```

### 2. Subscription enforcement assessment (authorized testing)
```bash
./nightowl billing app.apk --json                   # static model + weaknesses
./nightowl bypass-premium app.apk                   # emits workspace/bypass/<pkg>-premium-verify.js
frida -U -f <package> -l workspace/bypass/<pkg>-premium-verify.js --no-pause
```
Only run hooks against apps you own or are licensed to test. The script forces
entitlement flags true to *prove* client-side enforcement weakness; it is
evidence for the report, not a piracy feature.

### 3. Traffic capture through any proxy
```bash
./nightowl proxy setup --burp            # or --mitm | --charles | --target H:P
./nightowl proxy ca burpca.pem           # prints exact CA install commands
./nightowl capture                       # writes mitmproxy addon -> JSONL flows
mitmdump -s workspace/capture/nightowl_capture_addon.py -p 8080
NIGHTOWL_CAPTURE_HOSTS=api.target.com mitmdump -s ... # scope to target hosts
```
Works with Burp Suite, Charles, HTTP Toolkit, Reqable, or a bare HTTP CONNECT
proxy — anything that speaks HTTP(S) interception on host:port.

### 4. MCP integration (preferred for MCP-capable hosts)

```bash
claude mcp add nightowl -- ~/nightowl_new/nightowl mcp
```
Tools: `nightowl_full`, `nightowl_secrets`, `nightowl_authmap`,
`nightowl_billing`, `nightowl_deepscan`, `nightowl_hardening`,
`nightowl_privacy`, `nightowl_sca`, `nightowl_diff`, `nightowl_endpoints`,
`nightowl_decompile`, `nightowl_preflight`. Stdout carries only JSON-RPC —
safe for strict hosts.

Non-MCP agents: shell out via bash with `--json`; stderr shows progress.

## Output hygiene rules for agents

1. Always add `--json`; pipe stderr away (`2>/dev/null`) when capturing stdout.
2. Exit codes: 0 ok · 1 analysis failure · 2 usage error.
3. Mask secret values before echoing them into chat logs:
   show first 6 + last 4 chars only.
4. `secrets_filtered` exists so you can *explain* rejections — never treat it
   as findings.
5. Long scans: `full` on a 100MB APK can take minutes; use timeouts ≥300s.

## Safety & authorization

NightOwl is for **authorized security testing and research only**. Bypass
generation (`bypass-premium`, RASP `bypass`) produces verification scripts for
demonstrating weaknesses in apps you are permitted to test. Do not use against
third-party apps without explicit permission.
