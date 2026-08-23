<div align="center">

```
   ,_         _,
   | \.___./" |
   '.  o o  .'      N I G H T O W L   v8
    '--.-.--'       Ultimate Android Security Platform
   .--' '-.
  /       \
 |         |
```

# 🦉 NightOwl

### Unified Android Security Analysis Platform

**Validated Secrets · Auth Mapping · Subscription Enforcement · Packers ·
Privacy · SCA/SBOM · Dynamic Lab · Report Diffing · MCP Agent Bridge**

[![Python](https://img.shields.io/badge/python-3.12%2B-green)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-103%20passing-brightgreen)](#testing)
[![MCP](https://img.shields.io/badge/MCP-compatible-blue)](#ai-agent-integration)
[![OWASP](https://img.shields.io/badge/MASVS%2FMASTG-aligned-orange)](#masvs-alignment)

*For authorized security testing and research only.*

</div>

---

NightOwl is a single-command Android security analysis platform for penetration
testers, security researchers, and AI agents. It fuses deep static analysis, a
false-positive elimination engine, authentication-flow mapping,
subscription-enforcement assessment, packer fingerprinting, supply-chain
scanning, a dynamic-analysis lab, and an interactive reporting engine into one
dependency-light CLI.

## Why NightOwl

Most scanners stop at pattern matching: any string that *looks* like an API key
becomes a CRITICAL alarm, drowning real findings in noise. NightOwl treats every
regex hit as a **candidate** that must survive structural validation, entropy
floors, context analysis, and a public-documentation denylist before it is
reported. Every finding carries a **confidence score**, a **verdict**, and
**human-readable reasons** — so you act on results instead of triaging them.

| Verdict | Confidence | Meaning |
|---|---|---|
| `CONFIRMED` | ≥ 75 | Structure valid + positive context. Report as real. |
| `LIKELY` | 55–74 | Plausible. Report with caveat. |
| `SUSPECTED` | 35–54 | Weak evidence. Downgraded automatically. |
| `FILTERED` | < 35 | Docs example / placeholder / public-by-design. Hidden but auditable. |

Rejected candidates are never silently dropped — they are preserved in a
`secrets_filtered` audit trail with rejection reasons.

## Capabilities

| Module | Command | What it does |
|---|---|---|
| Core analysis | `full`, `quick` | Package info, permission risk, URLs/endpoints, certificates, manifest components, architecture, score & grade (A–F) |
| Secrets validation | `secrets` | 55+ provider patterns → validated findings with confidence, verdicts and audit trail (`--strict`, `--min-confidence`, `--show-filtered`) |
| Authentication map | `authmap` | Login/register/token/MFA endpoints with HTTP methods & credential params, token storage lifecycle, transport weaknesses (cleartext login, token-in-URL, missing pinning) |
| Subscription enforcement | `billing` | Play Billing / RevenueCat / Adapty / Superwall detection, local entitlement flags, missing receipt validation → enforcement model (`local-only` / `server-backed` / `sdk-managed`) + Frida verification script generation |
| Deep static layers | `deepscan` | Exported attack surface, deep-link hijacks, WebView hardening, crypto misuse (ECB, static IVs), intent redirection — MASVS-mapped with CVSS vectors |
| Hardening fingerprint | `hardening` | APKiD-style packer/protector/obfuscator detection (360 Jiagu, Bangcle, Ijiami, DexGuard, DashO…), anti-analysis families, Janus v1-only signing (CVE-2017-13156) |
| Privacy audit | `privacy` | Exodus-style tracker catalog (~50 SDKs) + data-collection permission map grouped by data category |
| Supply chain | `sca` | Version-aware vulnerable-library scan with advisories (CVE-2021-0341, CVE-2023-4863…) + CycloneDX 1.5 SBOM generation |
| Decompilation | `decompile` | jadx + apktool pipeline with workspace caching |
| Frameworks | `flutter`, `react-native`, `cordova`, `unity` | Framework-specific analysis paths |
| RASP & bypass | `rasp`, `bypass` | Runtime-defense detection (RootBeer, Frida checks, SafetyNet, Talsec…) and per-profile Frida bypass script generation |
| Traffic capture | `proxy`, `capture` | Device proxy setup for Burp/mitmproxy/Charles/any target, CA-install helper, APK network-config patcher, mitmproxy addon streaming JSONL flows |
| Dynamic lab | `lab` | adb/frida/objection workflow: device inventory, install/launch, NDJSON logcat, dumpsys, private-storage listing, backup capture, SSL-unpinning, screenshots, cleanup |
| Regression diffing | `diff` | Compare two saved scans: score delta, IMPROVED/REGRESSED verdict, added/resolved secrets & weaknesses per layer |
| Reporting | `--save`, `report` | Interactive single-file HTML + Markdown + JSON (see [Reports](#reports)) |

## Installation

**From source:**
```bash
git clone https://github.com/moaaz01/nightowl.git
cd nightowl
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[full]"
nightowl preflight                    # verify environment
```

**Or install as a CLI tool (pipx/pip):**
```bash
pipx install nightowl-security         # then just: nightowl <command>
export NIGHTOWL_HOME=~/.nightowl       # where reports/artifacts go
```

**Or Docker (jadx/apktool baked in):**
```bash
docker build -t nightowl .
docker run --rm -v "$PWD:/data" nightowl full /data/app.apk --json
```

Deep documentation: [architecture](docs/architecture.md) ·
[JSON contract](docs/json-contract.md) ·
[MCP server](docs/mcp.md)

**Requirements:** Python 3.12+. Optional but recommended:
[jadx](https://github.com/skylot/jadx),
[apktool](https://ibotpeaches.github.io/Apktool/),
[semgrep](https://semgrep.dev),
[adb](https://developer.android.com/tools/adb),
[Frida](https://frida.re) for dynamic work.
Heavy Python deps (androguard, rich) are optional — core string-based scans run
on a bare interpreter.

**Hostile-input mode:** scanning untrusted samples? Use `--static-only`
(or `NIGHTOWL_STATIC_ONLY=1`) to disable every command that executes external
parsers or touches devices. See [SECURITY.md](SECURITY.md).

## Quick Start

```bash
./nightowl                              # interactive wizard
./nightowl start app.apk --save         # one-shot pipeline: progress +
                                        # executive summary card + reports
./nightowl full app.apk --json          # everything, machine-readable
```

## Command Reference

### Analysis

```bash
./nightowl start <apk> [--save]     # guided pipeline + executive summary card
./nightowl full <apk>               # all layers, merged JSON
./nightowl quick <apk>              # fast scan
./nightowl info|perms|urls|vulns|manifest <apk>
./nightowl secrets <apk> --strict [--show-filtered]
./nightowl authmap <apk>
./nightowl billing <apk>
./nightowl deepscan <apk>
./nightowl hardening <apk>
./nightowl privacy <apk>
./nightowl sca <apk> [--save-sbom sbom.json]
./nightowl endpoints <apk>          # API access points only
./nightowl decompile <apk>          # jadx + apktool -> workspace/decompiled/
./nightowl scan ./targets/          # batch directory
```

### Subscription enforcement testing *(authorized targets only)*

```bash
./nightowl billing app.apk          # enforcement model + weaknesses
./nightowl bypass-premium app.apk   # -> workspace/bypass/<pkg>-premium-verify.js
frida -U -f <package> -l workspace/bypass/<pkg>-premium-verify.js --no-pause
```

### Network interception

```bash
./nightowl proxy setup --burp|--mitm|--charles|--target HOST:PORT [--serial S]
./nightowl proxy ca proxyca.pem     # exact CA install commands (user/system store)
./nightowl proxy netconfig app.apk  # user-CA trust config + apktool patch steps
./nightowl capture                  # write mitmproxy addon -> JSONL flow capture
mitmdump -s workspace/capture/nightowl_capture_addon.py -p 8080
NIGHTOWL_CAPTURE_HOSTS=api.target.com mitmdump -s ...   # scope to target hosts
./nightowl proxy clear && ./nightowl lab clean          # cleanup when done
```

### Dynamic lab *(your own rooted device/emulator)*

```bash
./nightowl lab devices                          # inventory: root + frida status
./nightowl lab install app.apk -r
./nightowl lab launch <pkg>                     # / stop <pkg>
./nightowl lab logcat --pkg <pkg> --json        # NDJSON stream for agents
./nightowl lab dumpsys <pkg>                    # package/activity view
./nightowl lab prefs <pkg> [--pull DIR]         # private storage listing
./nightowl lab backup <pkg>                     # adb backup capture (.ab)
./nightowl lab frida                            # push/start frida-server
./nightowl lab objection <pkg>                  # ready-made REPL commands
./nightowl lab ssl <pkg>                        # unpinning one-liners
./nightowl lab screenshot out.png
```

### Reports & regression tracking

```bash
./nightowl full app.apk --save                 # JSON + MD + interactive HTML
./nightowl report saved-scan.json              # re-render old JSON in new format
./nightowl diff old.json new.json [--json]     # IMPROVED / REGRESSED / MIXED
```

### DragonJAR modules

```bash
./nightowl static-audit app.apk    [--reuse-jadx DIR]
./nightowl semgrep app.apk         # OWASP MASTG compliance rules
./nightowl rasp app.apk [package]  # runtime defense detection
./nightowl bypass <package> [detector_ids] [--output DIR]
./nightowl cvss findings.json      # CVSS v3.1 scoring
```

### Global flags

| Flag | Effect |
|---|---|
| `--json` | Machine output on stdout; human progress on stderr |
| `--save` | Write JSON + Markdown + HTML reports |
| `--lang ar` | Arabic translations in exported reports |
| `--min-confidence N` / `--strict` | Secret confidence threshold (default 55 / strict 75) |
| `--show-filtered` | Print rejected candidates and why |
| `--serial DEVICE` | Target a specific adb device |
| `-v` | Verbose errors with traceback |

**Exit codes:** `0` success · `1` analysis failure · `2` usage error.

## Reports

`--save` produces three formats in `workspace/reports/`:

- **HTML (interactive, single file)** — dark/light themes, sticky navigation,
  live search, severity filter chips, click-to-reveal masked secrets (raw
  values are base64-encoded at rest — never plaintext in the file), confidence
  bars, filtered-candidates audit trail, embedded SBOM download, print-friendly
  CSS. Zero external assets: safe to email or archive.
- **Markdown** — mirrors every section with masked values for wikis and PRs.
- **JSON** — complete machine-readable state of every module.

Older saved scans can be upgraded anytime: `./nightowl report old-scan.json`.

## JSON Contract

```jsonc
{
  "info":   { "package": "...", "version_name": "...", "sha256": "..." },
  "perms":  { "dangerous": [{ "name": "...", "risk": "HIGH" }] },
  "endpoints": { "urls": [], "servers": [], "ips": [] },
  "secrets": [{
      "type": "AWS Access Key", "risk": "HIGH",
      "confidence": 90, "verdict": "CONFIRMED",
      "validation": ["well-formed AWS key ID"]
  }],
  "secrets_filtered": [],
  "security": { "score": 62, "grade": "C", "issues": [] },
  "authmap":  { "flows": [], "token_lifecycle": {}, "weaknesses": [] },
  "billing":  { "enforcement_model": "local-only", "findings": [] },
  "deepscan": { "findings": [] },
  "hardening": { "packers_protectors": {}, "anti_analysis": {} },
  "privacy":  { "trackers": {}, "data_collection_permissions": [] },
  "sca":      { "vulnerable": [], "sbom": { "bomFormat": "CycloneDX" } }
}
```

## AI Agent Integration

NightOwl speaks native agent:

- **MCP server** — 12 tools for OpenClaw, Hermes, Claude Code/Desktop, Codex,
  OpenCode, Cursor and any MCP-capable host:
  ```bash
  claude mcp add nightowl -- /path/to/nightowl mcp
  ```
  Tools: `nightowl_full`, `nightowl_secrets`, `nightowl_authmap`,
  `nightowl_billing`, `nightowl_deepscan`, `nightowl_hardening`,
  `nightowl_privacy`, `nightowl_sca`, `nightowl_diff`, `nightowl_endpoints`,
  `nightowl_decompile`, `nightowl_preflight`.
- **SKILL.md** — [`skills/nightowl/SKILL.md`](skills/nightowl/SKILL.md):
  decision tables, jq recipes, JSON contracts, safety rules.
- **AGENTS.md** — quick reference for repository agents.
- **NDJSON streams** — `lab logcat --json` for runtime telemetry.

## MASVS Alignment

Findings across modules carry MASVS mappings (e.g. `MASVS-NETWORK-1` for
cleartext auth transport, `MASVS-STORAGE-1` for unencrypted token storage,
`MASVS-RESILIENCE-2` for client-side-only entitlement enforcement) and key
deep-scan findings include CVSS v3.1 vectors. The Semgrep module runs
MASTG-aligned rules for compliance validation. This makes NightOwl output
directly usable in MASVS-scoped engagement reports.

## Project Structure

```
nightowl/
├── nightowl                    # Unified CLI entry point (v8)
├── nightowl.py                 # Core analysis engine (9 sections + scoring)
├── nightowl_pkg/
│   ├── core.py                 # Engine re-exports + decompilation helpers
│   ├── validators.py           # False-positive reduction engine
│   ├── authmap.py              # Authentication flow mapper
│   ├── billing.py              # Subscription enforcement analyzer
│   ├── deepscan.py             # Advanced static layers (MASVS/CVSS)
│   ├── hardening.py            # Packer/protector fingerprinting
│   ├── privacy.py              # Tracker & data-collection audit
│   ├── sca.py                  # Vulnerable libraries + CycloneDX SBOM
│   ├── lab.py                  # Dynamic analysis orchestrator
│   ├── diff.py                 # Report differ (regression tracking)
│   ├── report.py               # Interactive HTML/MD report engine
│   ├── proxy.py                # Universal proxy/capture integration
│   ├── mcp_server.py           # MCP stdio server (12 tools)
│   ├── dragonjar.py            # Static audit, Semgrep, CVSS scoring
│   ├── frameworks.py           # Flutter/RN/Cordova/Unity analyzers
│   ├── runtime.py              # RASP detection + bypass generation
│   ├── preflight.py            # Dependency validation
│   └── wizard.py               # Interactive menu
├── frida-scripts/              # api-interceptor, ssl-bypass, memory-dump…
├── scripts-dragonjar/          # Semgrep rules, detector catalog, profiles
├── skills/nightowl/SKILL.md    # AI-agent skill definition
└── tests/                      # 103 tests (unit + integration)
```

## Testing

```bash
python -m pytest tests/ -q
# 103 passing — validators, billing, authmap, deepscan, hardening, privacy,
# SCA, diff, report engine, MCP protocol, legacy engine compatibility
```

## Security & Responsible Use

NightOwl is a defensive-security testing tool. Bypass and verification script
generation (`bypass-premium`, `lab`, `rasp bypass`) exists to *demonstrate*
weaknesses on applications you own or are explicitly licensed to test.
See [SECURITY.md](SECURITY.md) for the project security policy. Do not use
NightOwl against third-party applications without authorization.

## Roadmap

- [ ] iOS (IPA) parity for core modules
- [ ] AAB support alongside APK
- [ ] CI/CD GitHub Action wrapper with SARIF output
- [ ] Live secret verification behind explicit opt-in flag
- [ ] Cross-build trend dashboards from `diff` history

## License

[MIT](LICENSE) — free for authorized security testing and research.

<div align="center">
<i>Built for security researchers who demand depth — and truth in results.</i>
</div>
