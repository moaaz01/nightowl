# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 8.0.x   | :white_check_mark: |
| < 8.0   | :x:                |

## Reporting a Vulnerability

Report vulnerabilities in NightOwl itself via
[GitHub Security Advisories](https://github.com/moaaz01/nightowl/security/advisories/new)
or by contacting the maintainer directly. Expect an initial response within
72 hours. Please do not open public issues for exploitable conditions.

## Trust Boundary: APKs Are Hostile Input

Every APK handed to NightOwl is **untrusted attacker-controllable input**.
Parsing it invokes third-party tools (jadx, apktool, androguard, semgrep) that
have had real parser CVEs. NightOwl treats this as a first-class constraint:

1. **Mandatory timeouts** — all external tool invocations carry explicit
   budgets (`NIGHTOWL_TIMEOUT`, default 120s). A hung parser cannot wedge a
   scan or an MCP-connected agent host.
2. **Version pinning** — `nightowl preflight` flags external parsers below
   pinned minimums (`PreflightChecker.MIN_VERSIONS`: jadx >= 1.4.0,
   apktool >= 2.7.0). Keep them updated; run NightOwl in the official Docker
   image to get vetted versions automatically.
3. **Static-only mode** — when scanning untrusted samples, run
   `nightowl --static-only ...` (or export `NIGHTOWL_STATIC_ONLY=1`) to
   disable every command that executes external parsers or touches devices.
4. **Report hygiene** — APK-derived strings are HTML-escaped everywhere they
   appear in generated reports; secret values are base64-encoded at rest with
   escaped attributes and click-to-reveal decoding. Invariants are enforced in
   `tests/test_security_invariants.py`.
5. **Agent path confinement** — when exposing NightOwl over MCP, set
   `NIGHTOWL_WORKSPACE` so agent-supplied paths are rejected outside approved
   roots (see `docs/mcp.md`).

## Authorized Testing Only

NightOwl's bypass and verification capabilities exist to demonstrate
weaknesses during authorized engagements. Using the tool against applications
you do not own or are not licensed to test may be illegal in your
jurisdiction.
