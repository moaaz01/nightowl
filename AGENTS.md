# AGENTS.md — NightOwl v8 Agent Integration Guide

Instructions for AI agents (OpenClaw, Hermes, Claude Code, Codex, OpenCode...)
using NightOwl programmatically. Full contracts: [`skills/nightowl/SKILL.md`](skills/nightowl/SKILL.md).

## Identity

| Field | Value |
|-------|-------|
| Tool | NightOwl v8 — Ultimate Android Security Platform |
| Entry | `./nightowl` (CLI) or `./nightowl mcp` (MCP stdio server) |
| Runtime | Python 3.12+ |
| Core deps | androguard, rich (optional but recommended) |

## Golden rules

1. Always pass `--json`; progress goes to stderr, data to stdout.
2. Exit codes: `0` ok · `1` analysis failed · `2` usage error.
3. APK paths resolve against `./targets/` automatically.
4. Never echo full secret values into logs — mask to first 6 / last 4 chars.
5. Trust verdicts: report only `CONFIRMED`/`LIKELY`; `SUSPECTED` with caveat;
   ignore `FILTERED` (audit trail lives in `.secrets_filtered[]`).

## Command map

```bash
./nightowl full <apk> --json        # everything (core+validation+authmap+billing+deepscan)
./nightowl secrets <apk> --json     # validated secrets w/ confidence
./nightowl authmap <apk> --json     # login flows, token lifecycle, weaknesses
./nightowl billing <apk> --json     # subscription enforcement model + findings
./nightowl deepscan <apk> --json    # exported surface, webview, crypto, intents
./nightowl endpoints <apk> --json   # API access points
./nightowl decompile <apk>          # jadx+apktool -> workspace/decompiled/
./nightowl bypass-premium <apk>     # Frida entitlement verification script
./nightowl capture                  # mitmproxy addon -> JSONL flows
./nightowl proxy setup --burp       # device -> your interception proxy
./nightowl preflight                # dependency check
```

## jq recipes

```bash
# only high-confidence secrets
./nightowl secrets app.apk --json | jq '[.secrets[] | select(.confidence >= 75)]'

# cleartext auth weaknesses
./nightowl authmap app.apk --json | jq '[.weaknesses[] | select(.severity == "CRITICAL")]'

# can premium be unlocked client-side?
./nightowl billing app.apk --json | jq '.enforcement_model'

# grade + score
./nightowl full app.apk --json | jq '.security.grade, .security.score'
```

## MCP

```bash
claude mcp add nightowl -- ~/nightowl_new/nightowl mcp
```
Tools: `nightowl_full`, `nightowl_secrets`, `nightowl_authmap`,
`nightowl_billing`, `nightowl_deepscan`, `nightowl_hardening`,
`nightowl_privacy`, `nightowl_sca`, `nightowl_diff`, `nightowl_endpoints`,
`nightowl_decompile`, `nightowl_preflight`. Stdout carries only JSON-RPC —
safe for strict hosts.

## Timeouts

- strings-based scans (`secrets/authmap/billing/endpoints/deepscan`): 120s
- `full`: 300s for ≤100MB APKs
- `decompile`: 300s

## Safety

Authorized security testing only. Bypass/verification scripts are evidence
tools for apps you own or are licensed to test.
