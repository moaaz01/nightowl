# NightOwl Architecture

Single source of truth: `nightowl_pkg/engine.py`. Everything else is a facade,
a scan layer, or a delivery surface.

```
                        ┌────────────────────────────┐
  APK ─────────────────►│  engine.py (NightOwlAnalyzer)│
                        │  strings · perms · endpoints │
                        │  secrets → validators        │
                        │  security score · vulns      │
                        └───────────┬────────────────┘
                                    │ az.txt / az.d
              ┌─────────────────────┼──────────────────────┐
              ▼                     ▼                      ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐
   │ authmap.py       │  │ billing.py       │  │ deepscan.py        │
   │ hardening.py     │  │ privacy.py       │  │ sca.py             │
   │ scan layers (read az.txt, write sub-reports into az.d)          │
   └──────────────────┘  └──────────────────┘  └────────────────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                ▼
            report.py (HTML/MD)  diff.py        mcp_server.py
            console summary      regression      12 tools for
                                 tracking        agent hosts
```

## Layers

| Layer | Files | Reads | Writes |
|---|---|---|---|
| Extraction | `engine.extract_strings` | APK zip (DEX/assets/XML/.so) | `az.strings`, `az.txt` |
| Core sections | `engine.analyze_*` | `az.txt` + androguard | `az.d[info/perms/endpoints/security/arch/manifest/cert]` |
| Secret validation | `validators.triage_findings` | raw regex candidates from `analyze_secrets` | verdict/confidence per finding + `secrets_filtered` |
| Scan layers | `authmap/billing/deepscan/hardening/privacy/sca` | `az.txt` (+ manifest, cert) | `az.d[authmap/billing/deepscan/hardening/privacy/sca]` |
| Delivery | `cli`, `report`, `diff`, `mcp_server` | `az.d` or saved JSON | stdout, HTML/MD files, JSON-RPC |

## Key invariants

1. **No silent drops** — every rejected secret candidate appears in
   `secrets_filtered[]` with reasons. Validators decide; nothing upstream
   filters.
2. **stdout purity** — under `--json` (and always in MCP mode) stdout carries
   data only; human progress goes to stderr. Enforced via
   `contextlib.redirect_stdout(sys.stderr)` around engine calls.
3. **Masking at rest** — reports never contain plaintext secret values;
   reveal buttons decode base64 blobs client-side. Attribute positions are
   escaped (`html.escape(..., quote=True)`) so hostile APK content can never
   break out into markup (enforced by `tests/test_security_invariants.py`).
4. **Mandatory subprocess timeouts** — all external tools run with explicit
   budgets (`nwproc.DEFAULT_TIMEOUT`, env `NIGHTOWL_TIMEOUT`). No call site
   may omit a timeout.
5. **Path confinement at the agent boundary** — MCP tool arguments pass
   through `_confine()`; set `NIGHTOWL_WORKSPACE` to restrict reads/writes to
   approved roots.

## Entry points

- `nightowl` (repo file) → `nightowl_pkg.cli:main`
- `pip install nightowl-security` installs the same console script
- `python -m nightowl_pkg.cli` equivalent
- `nightowl mcp` starts the MCP stdio server (JSON-RPC 2024-11-05 subset)

## Runtime artifacts

All writable state lives under one root:

- default: `<repo>/workspace/` (reports, decompiled, bypass, capture, netconfig)
- pip/Docker: `$NIGHTOWL_HOME/workspace/`

Tool binaries (jadx/apktool/adb/semgrep/frida) are discovered on PATH plus
known hints; `nightowl preflight` validates versions and flags tools below the
pinned minimums (see `PreflightChecker.MIN_VERSIONS`).

## Extension points

Add a static scan layer in three steps:

1. Create `nightowl_pkg/mymodule.py` exposing `analyze(txt, ...) -> dict`
   with a `module` key and a `findings[]` list of
   `{severity, title, evidence?, masvs?}` items.
2. Append it inside `cli._attach_advanced_layers()` guarded by try/except.
3. Add a section renderer in `report.py` and a jq-friendly block in
   `docs/json-contract.md`.

Dynamic capabilities belong in `lab.py`; runtime instrumentation scripts in
`frida-scripts/`.
