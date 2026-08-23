# NightOwl MCP Server

NightOwl ships a native Model Context Protocol server so agent hosts
(Claude Code/Desktop, OpenClaw, Hermes, Codex, OpenCode, Cursor, …) can run
scans as tools instead of shelling out.

Protocol: JSON-RPC 2.0 over stdio, methods `initialize`, `ping`,
`tools/list`, `tools/call` (MCP `2024-11-05` compatible subset). Stdout is
reserved for protocol frames — library chatter is suppressed and scan
progress is redirected to stderr.

## Registration

```bash
# Claude Code / Claude Desktop style hosts
claude mcp add nightowl -- /path/to/nightowl mcp

# Generic: the command to spawn is simply
/path/to/nightowl mcp
```

When installed via pip the binary is on PATH:

```bash
claude mcp add nightowl -- nightowl mcp
```

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `nightowl_full` | `apk`, `min_confidence?` | merged report: info/perms/endpoints/secrets/security/vulns/authmap/billing/deepscan |
| `nightowl_secrets` | `apk` | validated secrets + stats + filtered count |
| `nightowl_authmap` | `apk` | flows, token lifecycle, weaknesses |
| `nightowl_billing` | `apk` | enforcement model, findings, verification script path |
| `nightowl_deepscan` | `apk` | attack surface + advanced findings |
| `nightowl_hardening` | `apk` | packers, anti-analysis families |
| `nightowl_privacy` | `apk` | trackers, data-collection permissions |
| `nightowl_sca` | `apk` | vulnerable components + CycloneDX SBOM |
| `nightowl_endpoints` | `apk` | URLs/annotated calls/servers |
| `nightowl_diff` | `old_json`, `new_json` | score delta, verdict, per-layer deltas |
| `nightowl_decompile` | `apk` | jadx/apktool output dirs |
| `nightowl_preflight` | — | dependency inventory |

Tool results carry up to ~400KB of text per call; large scans are truncated —
prefer targeted tools (`secrets`, `authmap`, …) over `full` inside agents.

## Path confinement

Agent-supplied paths are untrusted by default in enterprise settings.
Constrain every tool call with:

```bash
NIGHTOWL_WORKSPACE=/srv/engagements/clientA:/home/analyst/targets nightowl mcp
```

Behavior:
- unset → unrestricted (local single-user default; unchanged from CLI use)
- set → every `apk` / `old_json` / `new_json` path must resolve under one of
  the colon-separated roots or the tool returns an error result
- `NIGHTOWL_ALLOW_ANYWHERE=1` overrides confinement explicitly

## Timeouts & hygiene

- Engine subprocess budgets are enforced centrally (`NIGHTOWL_TIMEOUT`,
  default 120s) so a hung parser can never wedge the agent host.
- SIGINT cleanly cancels; partial state is flushed to
  `$NIGHTOWL_HOME/workspace/reports/partial-*.json`.
- Set `NIGHTOWL_HOME` to keep reports/bypass scripts out of read-only
  installs (Docker images mount `/data` for this).

## Example session

```
host : initialize            → serverInfo { name: "nightowl", version }
host : tools/list            → 12 tool schemas
host : tools/call nightowl_secrets { "apk": "/data/app.apk" }
tool : content[0].text = "{ ...validated findings... }"
```
