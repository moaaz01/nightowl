# 🦉 NightOwl v8 — Ultimate Android Security Analysis Platform

```
   ,_         _,
   | \.___./" |
   '.  o o  .'      N I G H T O W L   v8.0.0
    '--.-.--'       Ultimate Android Security Platform
   .--' '-.
  /       \        Validated Secrets - AuthMap - Subscription Lab
 |         |       DeepScan - Packers - Privacy - SCA - MCP Bridge
```

**Static Analysis · Validated Secrets · Authentication Mapping · Subscription
Enforcement Testing · Advanced Static Layers · Packer Fingerprinting · Privacy
Audit · SCA/SBOM · Dynamic Lab · Universal Proxy Capture · Report Diffing ·
MCP Agent Bridge**

For **authorized security testing** and research. MIT-licensed.

---

## What's new in v8 (vs v7)

| Area | v7 | v8 |
|---|---|---|
| Packers/protectors | — | **`hardening`**: APKiD-style fingerprinting (360 Jiagu, Bangcle, Ijiami, Tencent Legu, DexGuard, DashO...), anti-analysis families, Janus (v1-only signing) detection with CVE-2017-13156 |
| Privacy | — | **`privacy`**: Exodus-style tracker catalog (~50 SDKs), data-collection permission map by category |
| Supply chain | — | **`sca`**: vulnerable-library scan with advisories (CVE-2021-0341, CVE-2023-4863...) + CycloneDX 1.5 SBOM generation (`--save-sbom`) |
| Dynamic lab | manual frida cmds | **`lab`**: full adb/frida/objection workflow — devices inventory (root+frida status), install/launch/logcat(NDJSON)/dumpsys/prefs/pull/backup/ssl-unpinning/screenshot/clean |
| Regression tracking | — | **`diff old.json new.json`**: score delta, verdict IMPROVED/REGRESSED, added/resolved secrets & weaknesses per layer |
| Reports | legacy 6-section HTML | **v8 report engine**: single-file interactive HTML (dark/light, severity filter chips, live search, click-to-reveal masked secrets, confidence bars, filtered-candidates audit trail, SBOM download) + comprehensive Markdown. `nightowl report <json>` re-renders anytime |
| UX | many commands | **`start <apk>`**: one-shot guided pipeline with progress steps + executive summary card; grouped `help` |

---

## What's new in v7 (vs v6)

| Area | v6 behavior | v7 behavior |
|---|---|---|
| Secrets accuracy | Regex hit = alarm; Firebase `AIza` keys and doc examples reported CRITICAL; Flutter "noise" filter silently dropped real findings | **Validation engine**: every candidate gets structural checks, entropy floors, context scoring, public-example denylist → verdict `CONFIRMED/LIKELY/SUSPECTED/FILTERED` with confidence 0–100 and reasons. FILTERED items hidden but auditable |
| Partial tokens | Any fragment of a token shape = vulnerability flagged | Malformed/partial tokens can never reach CONFIRMED (length, segment, checksum-style validation) |
| Subscription testing | none | **`billing`**: detects Play Billing/RevenueCat/Adapty/Superwall/Qonversion, local entitlement flags, missing receipt validation, debug unlock switches → enforcement model + weaknesses. **`bypass-premium`**: generates tailored Frida hooks to *verify* client-side unlock at runtime (authorized tests) |
| Authentication analysis | URL grep | **`authmap`**: login/register/token/MFA endpoints with HTTP methods & credential params, token storage & attachment lifecycle, weaknesses (cleartext login, token-in-URL, no pinning, OAuth client secrets) |
| Advanced static layers | 9 fixed sections | **`deepscan`**: exported attack surface, deep-link hijack candidates, WebView hardening, crypto misuse (ECB/static IV/hardcoded keys), intent redirection, log/clipboard leakage — MASVS-mapped, CVSS vectors on key findings |
| Proxy support | printed adb tips | **Universal interception**: device/emulator proxy setup for Burp/mitmproxy/Charles/any target, CA-hash install helper, `netconfig` generator to patch user-CA trust into any APK, mitmproxy JSONL addon capturing flows for agent post-processing |
| AI agents | SKILL.md + JSON | **MCP stdio server** (`nightowl mcp`) exposing 8 tools to OpenClaw/Hermes/Claude Code/Codex/OpenCode/Cursor; JSON-first CLI with stderr progress and stable exit codes |

---

## Install

```bash
git clone https://github.com/moaaz01/nightowl.git
cd nightowl
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # rich, androguard, loguru...
bash scripts/install-ultimate.sh       # jadx/apktool/semgrep helpers
./nightowl preflight                   # verify environment
```

## Usage

```bash
./nightowl                             # interactive wizard
./nightowl full app.apk                # everything: core + validation +
                                       # authmap + billing + deepscan
./nightowl full app.apk --json > r.json
```

### Core (v6-compatible)
```bash
./nightowl info|perms|urls|secrets|vulns|manifest <apk>
./nightowl apis <apk>            ./nightowl decompile <apk>
./nightowl scan [dir]            ./nightowl static-audit|semgrep|rasp|bypass|cvss ...
./nightowl flutter|react-native|cordova|unity <apk>
```

### v7/v8 commands
```bash
# Friendly one-shot pipeline (progress + executive summary card)
./nightowl start app.apk --save

# Validated secrets (false-positive reduction)
./nightowl secrets app.apk --show-filtered
./nightowl secrets app.apk --min-confidence 75 --json

# Authentication mapping & API access points
./nightowl authmap app.apk --json

# Subscription / premium enforcement assessment
./nightowl billing app.apk
./nightowl bypass-premium app.apk     # -> workspace/bypass/<pkg>-premium-verify.js

# Advanced static layers
./nightowl deepscan app.apk --json

# v8: hardening / privacy / supply chain
./nightowl hardening app.apk          # packers, anti-analysis, Janus signing
./nightowl privacy app.apk            # trackers + data-collection map
./nightowl sca app.apk --save-sbom sbom.json

# Dynamic analysis lab (your own device/emulator)
./nightowl lab devices                # root + frida status
./nightowl lab install app.apk -r && ./nightowl lab launch <pkg>
./nightowl lab ssl <pkg>              # unpinning one-liners
./nightowl lab logcat --pkg <pkg> --json   # NDJSON stream for agents
./nightowl lab clean                  # clear proxy/reverses when done

# Reports & regression tracking
./nightowl diff old.json new.json     # verdict: IMPROVED / REGRESSED / MIXED
./nightowl report saved-scan.json     # re-render interactive HTML+MD

# Universal traffic capture
./nightowl proxy status|setup --burp|--mitm|--charles|--target H:P|clear
./nightowl proxy ca proxyca.pem       # exact CA install commands
./nightowl proxy netconfig app.apk    # user-CA trust config + apktool steps
./nightowl capture                    # mitmproxy addon -> JSONL flows

# MCP server for agent hosts
claude mcp add nightowl -- $(pwd)/nightowl mcp
```

### Flags
`--json` (machine output; progress → stderr) · `--save` (HTML+MD+JSON) ·
`--lang ar` · `--min-confidence N` · `--strict` (=75) · `--show-filtered` ·
`--serial DEVICE` (adb) · `-v`

Exit codes: `0` success · `1` analysis failure · `2` usage error.

---

## The validation engine (why v7 findings are trustworthy)

Each raw regex hit is only a *candidate*. The engine then applies:

1. **Public-example denylist** — AWS docs keys (`AKIAIOSFODNN7EXAMPLE`),
   Telegram docs bot token, jwt.io demo token, etc. → `FILTERED`.
2. **Structural validators per provider** — AWS key ID length/charset,
   Telegram bot-token segments & entropy, GitHub PAT shapes, Slack segments,
   SendGrid body, JWT base64/JSON decode with `alg` and `exp` analysis,
   Stripe live-vs-test semantics, DB URIs checked for embedded credentials.
3. **Public-by-design downgrades** — Firebase `AIza` keys ship in every app;
   reported MEDIUM with "verify API restrictions", never CRITICAL noise.
4. **Context scoring** — ±120 chars scanned for `test/example/mock/sandbox`
   vs `prod/live/release/authorization` markers.
5. **Placeholder detection inside the value itself** — catches partial tokens
   and template strings like `sk_live_test1234...`.
6. **Entropy floors & corpus repetition** — SDK constants repeated many times
   are demoted.

Result: fewer false alarms, zero silent drops (everything rejected is listed
in `secrets_filtered` with reasons).

## Subscription enforcement methodology

Maps how paid features are enforced: billing SDK inventory → local entitlement
storage patterns → server-side validation endpoint search → debug switch
detection → paywall UI resources. Produces an enforcement model
(`local-only`, `server-backed`, `sdk-managed`) plus severity-ranked findings,
then generates a Frida script that forces entitlements true so the tester can
*prove* the weakness at runtime. Aligned with OWASP MASTG resilience testing.

## Agent integration

- **SKILL.md** at [`skills/nightowl/SKILL.md`](skills/nightowl/SKILL.md) —
  decision tables, JSON contracts, jq recipes, safety rules.
- **AGENTS.md** — quick reference for repo agents.
- **MCP**: `nightowl mcp` serves tools over stdio JSON-RPC.

## Tests

```bash
python -m pytest tests/ -q      # 84+ tests: validators, billing, authmap,
                                # deepscan, MCP protocol, legacy engine
```

## License

MIT — see [LICENSE](LICENSE). For authorized security testing only.

**Built for security researchers who demand depth — and truth in results.**
