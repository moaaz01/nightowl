# mcp_server.py -- NightOwl v7 Model Context Protocol (stdio) server
#
# Exposes NightOwl scans as MCP tools. Works with any MCP-capable host:
# OpenClaw, Hermes, Claude Code / Claude Desktop, Codex, OpenCode, Cursor...
#
# Register (example for claude-based hosts):
#   claude mcp add nightowl -- /home/ali/nightowl_new/nightowl mcp
#
# Protocol: JSON-RPC 2.0 over stdio (MCP 2024-11-05 compatible subset):
#   initialize / tools/list / tools/call (+ ping)

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROTOCOL_VERSION = "2024-11-05"


def _confine(path):
    """H-04: confine agent-supplied paths to NIGHTOWL_WORKSPACE.

    - No NIGHTOWL_WORKSPACE set  -> unconstrained (local CLI owners trust
      themselves; behavior unchanged for existing users).
    - NIGHTOWL_WORKSPACE set     -> colon-separated allowlist of roots; every
      path passed by an MCP tool call must resolve inside one of them.
    - NIGHTOWL_ALLOW_ANYWHERE=1  -> explicit escape hatch, wins over roots.
    """
    rp = Path(str(path)).expanduser().resolve()
    if os.environ.get("NIGHTOWL_ALLOW_ANYWHERE") == "1":
        return str(rp)
    raw = os.environ.get("NIGHTOWL_WORKSPACE", "").strip()
    if not raw:
        return str(rp)
    sep = ";" if os.name == "nt" else ":"
    for root in raw.split(sep):
        root = Path(root).expanduser().resolve()
        try:
            rp.relative_to(root)
            return str(rp)
        except ValueError:
            continue
    raise PermissionError(
        f"path outside NIGHTOWL_WORKSPACE: {rp} "
        f"(allowed roots: {raw}; set NIGHTOWL_ALLOW_ANYWHERE=1 to override)")


def _tool(name, desc, props, required=None):
    return {
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": required or [],
        },
    }


APK_PATH_PROP = {
    "apk": {"type": "string", "description": "Path to the APK file to analyze"},
}

TOOLS = [
    _tool("nightowl_full",
          "Complete 9-section APK security scan + validation engine. "
          "Returns JSON with info, permissions, endpoints, validated secrets, "
          "security score/grade, vulnerabilities, architecture.",
          {**APK_PATH_PROP,
           "min_confidence": {"type": "integer", "description":
                              "Only report secrets with confidence >= this (0-100)"}},
          ["apk"]),
    _tool("nightowl_secrets",
          "Hardcoded secret detection with false-positive reduction. Every "
          "finding carries verdict CONFIRMED/LIKELY/SUSPECTED and a "
          "confidence score with human-readable reasons.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_authmap",
          "Extract the authentication architecture: login/token/MFA "
          "endpoints, HTTP methods, credential parameters, token storage and "
          "transport weaknesses (cleartext login, tokens in URLs...).",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_billing",
          "Subscription/premium enforcement assessment: billing SDKs, "
          "client-side entitlement storage, missing receipt validation; also "
          "generates a Frida verification script (authorized testing only).",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_deepscan",
          "Advanced static layers: exported attack surface, deep-link "
          "hijacking, WebView hardening, crypto misuse, intent redirection, "
          "log leakage. MASVS-mapped findings.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_hardening",
          "Packers/protectors fingerprint (360 Jiagu, Bangcle, Ijiami, "
          "DexGuard...), anti-analysis families, signing-scheme weaknesses.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_privacy",
          "Tracker/SDK privacy audit (Exodus-style catalog) plus "
          "data-collection permission map.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_sca",
          "Software composition analysis: vulnerable-library scan with CVE "
          "advisories + CycloneDX SBOM inventory.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_diff",
          "Compare two saved scan JSONs; reports score delta and added/"
          "resolved secrets, vulns, auth weaknesses, servers.",
          {"old_json": {"type": "string",
                        "description": "Path to the older scan JSON"},
           "new_json": {"type": "string",
                        "description": "Path to the newer scan JSON"}},
          ["old_json", "new_json"]),
    _tool("nightowl_endpoints",
          "All API access points: absolute URLs, Retrofit-annotated calls, "
          "servers, domains, IPs.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_decompile",
          "Decompile an APK with jadx + apktool into workspace/decompiled/.",
          APK_PATH_PROP, ["apk"]),
    _tool("nightowl_preflight",
          "Validate all system dependencies (jadx, apktool, semgrep, adb, "
          "python packages).",
          {}),
]


def _run_scan(kind, apk, extra=None):
    """Execute one scan in-process and return compact JSON."""
    import contextlib
    from nightowl_pkg import core as nw

    def _cap(kind, az):
        if kind == "full":
            with contextlib.redirect_stdout(sys.stderr):
                az.run_full()
            try:
                from nightowl_pkg.billing import analyze_billing, generate_bypass_script
                rep = analyze_billing(az.txt, az.d.get("info"))
                pkg = az.d.get("info", {}).get("package") or "com.target.app"
                rep["package"] = pkg
                script = generate_bypass_script(
                    pkg, rep,
                    ROOT / "workspace" / "bypass" / f"{pkg}-premium-verify.js")
                rep["verification_script"] = str(script)
                az.d["billing"] = rep
            except Exception:
                pass
            try:
                from nightowl_pkg.authmap import map_authentication
                az.d["authmap"] = map_authentication(az.txt)
            except Exception:
                pass
            try:
                from nightowl_pkg.deepscan import analyze_deep, attach_cvss
                az.d["deepscan"] = attach_cvss(
                    analyze_deep(az.txt, az.d.get("manifest") or {}))
            except Exception:
                pass
            return {k: v for k, v in az.d.items()
                    if k not in ("desc", "_native_strings_count")}
        if kind == "secrets":
            az.extract_strings()
            az.analyze_secrets()
            return {"secrets": az.d["secrets"],
                    "stats": az.d.get("secrets_stats"),
                    "filtered_hidden": len(az.d.get("secrets_filtered", []))}
        if kind == "authmap":
            from nightowl_pkg import authmap as am
            az.extract_strings()
            az.analyze_endpoints()
            access = am.extract_access_points(az.txt)
            out = am.map_authentication(az.txt)
            out["access_points"] = access
            return out
        if kind == "billing":
            from nightowl_pkg.billing import analyze_billing, generate_bypass_script
            az.extract_strings()
            rep = analyze_billing(az.txt, az.d.get("info"))
            pkg = az.d.get("info", {}).get("package") or "com.target.app"
            rep["package"] = pkg
            script = generate_bypass_script(
                pkg, rep, ROOT / "workspace" / "bypass" / f"{pkg}-premium-verify.js")
            rep["verification_script"] = str(script)
            return rep
        if kind == "deepscan":
            from nightowl_pkg.deepscan import analyze_deep, attach_cvss
            az.extract_strings()
            az.analyze_manifest()
            az.analyze_components()
            return attach_cvss(analyze_deep(az.txt, az.d.get("manifest") or {}))
        if kind == "endpoints":
            az.extract_strings()
            az.analyze_endpoints()
            az.analyze_apis()
            return az.d["endpoints"]
        return None

    az = nw.NightOwlAnalyzer(apk)
    out = _cap(kind, az)
    if out is None:
        raise RuntimeError(f"unknown scan kind: {kind}")
    min_conf = int((extra or {}).get("min_confidence") or 0)
    if min_conf and isinstance(out, dict) and "secrets" in out:
        out["secrets"] = [s for s in out["secrets"]
                          if s.get("confidence", 100) >= min_conf]
    return out


def handle(msg):
    method = msg.get("method")
    mid = msg.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "nightowl", "version": "7.0.0"},
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        args = params.get("arguments") or {}
        try:
            # H-04: confine every agent-supplied filesystem path
            for key in ("apk", "old_json", "new_json"):
                if key in args:
                    args[key] = _confine(args[key])
            mapping = {
                "nightowl_full": "full", "nightowl_secrets": "secrets",
                "nightowl_authmap": "authmap", "nightowl_billing": "billing",
                "nightowl_deepscan": "deepscan", "nightowl_endpoints": "endpoints",
            }
            if name == "nightowl_decompile":
                from nightowl_pkg.core import decompile_apk
                jadx, apktool = decompile_apk(args["apk"])
                data = {"jadx_output": jadx, "apktool_output": apktool}
            elif name == "nightowl_preflight":
                from nightowl_pkg.preflight import PreflightChecker
                data = PreflightChecker().run_all() \
                    if hasattr(PreflightChecker, "run_all") else \
                    {"note": "see nightowl preflight CLI"}
            elif name == "nightowl_diff":
                from nightowl_pkg.diff import diff_reports
                old = json.loads(Path(args["old_json"]).read_text())
                new = json.loads(Path(args["new_json"]).read_text())
                data = diff_reports(old, new)
            elif name in ("nightowl_hardening", "nightowl_privacy",
                          "nightowl_sca"):
                from nightowl_pkg import core as nw2
                az2 = nw2.NightOwlAnalyzer(args["apk"])
                az2.extract_strings()
                kind = name.split("_")[1]
                if kind == "hardening":
                    az2.analyze_info(); az2.analyze_cert()
                    from nightowl_pkg.hardening import analyze_hardening
                    data = analyze_hardening(
                        az2.txt,
                        az2.d.get("info", {}).get("native_libs"),
                        az2.d.get("cert"))
                elif kind == "privacy":
                    az2.analyze_perms()
                    from nightowl_pkg.privacy import analyze_privacy
                    data = analyze_privacy(az2.txt,
                                           az2.d["perms"].get("dangerous"))
                else:
                    from nightowl_pkg.sca import analyze_sca
                    data = analyze_sca(az2.txt)
            elif name in mapping:
                data = _run_scan(mapping[name], args["apk"], args)
            else:
                raise ValueError(f"unknown tool {name}")

            payload = json.dumps(data, ensure_ascii=False, default=str)
            # MCP tool results are content items; large payloads truncated
            trunc = payload[:400000]
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": trunc}],
                "isError": False,
            }}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"error: {e}"}],
                "isError": True,
            }}
    if method is not None and method.startswith("notifications/"):
        return None
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def serve():
    """Blocking stdio loop."""
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as e:
            resp = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": f"parse error: {e}"}}
        else:
            try:
                resp = handle(msg)
            except Exception as e:  # never crash the loop
                resp = {"jsonrpc": "2.0", "id": msg.get("id"),
                        "error": {"code": -32603, "message": str(e)}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve()
