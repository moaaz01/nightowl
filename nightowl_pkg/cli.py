#!/usr/bin/env python3
# cli.py -- NightOwl v8 Unified CLI
#
# Ultimate Android Security Analysis Platform
# Static - Secrets(validation) - AuthMap - Billing Enforcement - DeepScan
# Universal Proxy Capture - MCP Agent Bridge (OpenClaw/Hermes/Claude/Codex/OpenCode)
#
# AUTHORIZED SECURITY TESTING ONLY.

# cli.py -- NightOwl v8 command-line interface.
#
# Installed as a console-script via pyproject (`nightowl` on PATH) and also
# reachable as `python -m nightowl_pkg.cli`. The top-level ./nightowl file is
# a thin shim into this module.

import os
import sys
import json
import logging
import contextlib
import signal
from datetime import datetime

logging.disable(logging.CRITICAL)

from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_SCRIPT_DIR = Path(__file__).resolve().parent.parent

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.disable("androguard")
except ImportError:
    pass

from nightowl_pkg import core as nw
from nightowl_pkg import dragonjar as dj
from nightowl_pkg import frameworks as fw
from nightowl_pkg import runtime as rt
from nightowl_pkg import preflight as pf
from nightowl_pkg import wizard as wz

nw.show_banner = lambda: None

RICH = nw.RICH
con = nw.con if RICH else None

VERSION = "8.3.0"

LOGO = r"""
   ,_         _,
   | \.___./" |
   '.  o o  .'      N I G H T O W L   v{version}
    '--.-.--'       Ultimate Android Security Platform
   .--' '-.
  /       \        Validated Secrets - AuthMap - Subscription Lab
 |         |       DeepScan - Packers - Privacy - SCA - MCP Bridge
"""

BANNER_SHOWN = False


def show_banner():
    global BANNER_SHOWN
    if BANNER_SHOWN or "--json" in sys.argv or os.environ.get("NIGHTOWL_QUIET"):
        return
    BANNER_SHOWN = True
    text = LOGO.format(version=VERSION)
    if RICH:
        con.print(f"[bold cyan]{text}[/]")
    else:
        print(text)


USAGE = f"""NightOwl v{VERSION} - command reference

QUICK START
  start <apk>           Friendly one-shot pipeline: scans everything with a
                        progress view and prints an executive summary card.
                        Add --save for JSON+HTML+MD reports.

CORE APK ANALYSIS
  full <apk>            Complete analysis (all layers, machine output)
  quick <apk>           Fast static scan
  info|perms|urls|secrets|vulns|manifest <apk>
                        Individual sections
  apis|endpoints <apk>  API access points extraction
  decompile <apk>       jadx + apktool decompilation
  scan [dir]            Batch scan directory of APKs

VALIDATED SECRETS (false-positive reduction engine)
  secrets <apk> --min-confidence 75 [--show-filtered] [--strict]

AUTHENTICATION & NETWORK
  authmap <apk>         Login/register/token/MFA flow map, credential params,
                        token storage & transport weaknesses, access points
  deepscan <apk>        Advanced static layers (exported surface, deep links,
                        WebView hardening, crypto misuse, intent redirection)
  proxy status|setup|clear|ca|netconfig|capture|env
                        Universal interception: mitmproxy/Burp/Charles/env

SUBSCRIPTION ENFORCEMENT (authorized testing)
  billing <apk>         Detect paid-feature enforcement model & weaknesses
  bypass-premium <apk>  Generate tailored Frida entitlement-verification hooks

ELITE REVERSE ENGINEERING (v8.1)
  dart <apk>            Flutter/Dart AOT intelligence: package imports, API
                        routes, RSA padding audit (PKCS1v15 vs OAEP), entity-
                        table detection that defuses fake PEM fragments
  cryptoscope <apk>     Source-aware crypto audit over jadx tree: provenance
                        classification (APP CODE vs LIBRARY vs OBFUSCATED),
                        mode/padding inventory, hardcoded key literals
  surface <apk>         Exported-component exploitation map with adb recipes
  secrets-src <apk>     Secret scan across decompiled sources w/ file:line

API INFRASTRUCTURE ASSESSMENT
  apimap <base-url>     Server fingerprint, security headers audit,
                        error-handling leakage, TLS config, route probes
                        [--routes /a,/b,/c]

HARDENING / PRIVACY / SUPPLY CHAIN
  hardening <apk>       Packers/protectors fingerprint, anti-analysis families,
                        Janus signing-scheme weaknesses
  privacy <apk>         Tracker SDK audit + data-collection permission map
  sca <apk>             Vulnerable-library scan + CycloneDX SBOM
                        (--save-sbom FILE.json)

DYNAMIC LAB (requires your own device/emulator)
  lab devices|install|uninstall|launch|stop|logcat|dumpsys|prefs|pull|
      backup|frida|objection|ssl|screenshot|clean
                        Runtime-phase workflow over adb/frida/objection

REPORTS
  diff <old.json> <new.json>   Compare two saved scans (regression tracking)
  report <saved.json>          Re-render a saved JSON into HTML+MD

DRAGONJAR MODULES
  static-audit|semgrep|rasp|bypass|cvss <args>

FRAMEWORKS
  flutter|react-native|cordova|unity <apk>

AGENT INTEGRATION
  mcp                   Start MCP stdio server (OpenClaw/Hermes/Claude Code/
                        Codex/OpenCode MCP hosts)
  preflight             Dependency check

FLAGS (global): --json  --save  --lang ar  -v/--verbose
Exit codes: 0 success | 1 analysis failure | 2 usage error
"""


# Commands that execute external parsers/binaries or touch devices.
# Blocked under --static-only / NIGHTOWL_STATIC_ONLY=1 (hostile-input mode).
DYNAMIC_COMMANDS = {"lab", "proxy", "capture", "decompile", "rasp", "bypass",
                    "bypass-premium", "static-audit", "semgrep"}


def _static_only(argv):
    return ("--static-only" in argv
            or os.environ.get("NIGHTOWL_STATIC_ONLY") == "1")


def _guard_static_only(cmd, argv=None):
    # v8.0.1 regression fix: the guard must only fire when static-only mode
    # is actually active — previously it blocked dynamic commands ALWAYS.
    argv = sys.argv[1:] if argv is None else argv
    if _static_only(argv) and cmd in DYNAMIC_COMMANDS:
        print(f"[!] '{cmd}' executes external tools/devices — blocked in "
              "static-only mode (APKs are hostile input).\n"
              "    Remove --static-only / NIGHTOWL_STATIC_ONLY to enable.")
        return True
    return False


# ── M-05: clean cancellation with partial-report flush ────────────────
_CURRENT_ANALYZER = None


def _flush_partial_report(signum=None, frame=None):
    az = _CURRENT_ANALYZER
    if az is not None and getattr(az, "d", None):
        try:
            out = Path(os.environ.get("NIGHTOWL_HOME") or Path.cwd())                 / "workspace" / "reports"
            out.mkdir(parents=True, exist_ok=True)
            f = out / f"partial-{Path(az.path).stem}-{datetime.now():%Y%m%d-%H%M%S}.json"
            f.write_text(json.dumps(az.d, indent=2, ensure_ascii=False,
                                    default=str))
            print(f"\n[!] Interrupted — partial report flushed: {f}")
        except Exception:
            print("\n[!] Interrupted.")
    else:
        print("\nInterrupted.")
    sys.exit(130)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    signal.signal(signal.SIGINT, _flush_partial_report)

    if not argv or argv[0] in ("interactive", "wizard", "menu", "-i"):
        show_banner()
        wz.interactive_wizard()
        return 0

    if argv[0] in ("guide", "help", "--help", "-h", "usage"):
        show_banner()
        print(USAGE)
        return 0

    if argv[0] in ("version", "--version"):
        print(f"NightOwl v{VERSION}")
        return 0

    cmd = argv[0]
    args = argv[1:]
    apk_arg = next((a for a in args if a.lower().endswith(".apk")
                    or Path(a).exists()), None)

    # ── Friendly one-shot pipeline ────────────────────────────────────────
    if cmd == "start":
        if not apk_arg:
            print("Usage: nightowl start <apk> [--save]")
            return 2
        target = _resolve_apk(apk_arg)
        show_banner()
        az = nw.NightOwlAnalyzer(target, lang="en")

        def step(msg):
            print(f"  [..] {msg}", flush=True)

        step("extracting strings & resources")
        az.extract_strings()
        step("core sections (info/perms/endpoints/security/arch)")
        with contextlib.redirect_stdout(sys.stderr):
            az.analyze_info(); az.analyze_perms(); az.analyze_endpoints()
            az.analyze_security(); az.analyze_arch(); az.analyze_cert()
        step("validating secrets (false-positive engine)")
        with contextlib.redirect_stdout(sys.stderr):
            az.analyze_secrets(); az.analyze_vulns()
        step("mapping authentication flows")
        # v8.0.2: manifest must exist or deepscan loses the exported-surface
        # layer entirely (full always had it; start was silently thinner)
        az.analyze_manifest()
        az.analyze_components()
        _attach_advanced_layers(az)
        step("fingerprinting packers & hardening")
        try:
            from nightowl_pkg.hardening import analyze_hardening
            az.d["hardening"] = analyze_hardening(
                az.txt, az.d.get("info", {}).get("native_libs"), az.d.get("cert"))
        except Exception:
            pass
        step("auditing trackers & privacy surface")
        try:
            from nightowl_pkg.privacy import analyze_privacy
            az.d["privacy"] = analyze_privacy(az.txt,
                                              az.d["perms"].get("dangerous"))
        except Exception:
            pass
        step("scanning supply chain (SCA)")
        try:
            from nightowl_pkg.sca import analyze_sca
            az.d["sca"] = analyze_sca(az.txt)
        except Exception:
            pass

        from nightowl_pkg.report import render_console_summary
        render_console_summary(az.d)

        if "--save" in args or "--json" in args:
            hp = az.save()
            if "--json" in args:
                print(json.dumps(az.d, indent=2, ensure_ascii=False))
            else:
                print(f"  HTML report: {hp}")
        return 0

    # ── Report re-render ─────────────────────────────────────────────────
    if cmd == "report":
        if not args or not Path(args[0]).exists():
            print("Usage: nightowl report <saved-scan.json> [--out DIR]")
            return 2
        data = json.loads(Path(args[0]).read_text())
        from nightowl_pkg.report import build_html, build_md
        outdir = Path(args[args.index("--out") + 1]) if "--out" in args \
            else (_data_dir() / "workspace" / "reports")
        outdir.mkdir(parents=True, exist_ok=True)
        stem = Path(data.get("apk", "report")).stem + "-v8"
        hp = outdir / f"{stem}.html"
        mp = outdir / f"{stem}.md"
        hp.write_text(build_html(data))
        mp.write_text(build_md(data))
        print(f"[+] HTML: {hp}\n[+] MD  : {mp}")
        return 0

    # ── Diff two reports ─────────────────────────────────────────────────
    if cmd == "diff":
        if len(args) < 2:
            print("Usage: nightowl diff <old.json> <new.json> [--json]")
            return 2
        from nightowl_pkg.diff import cmd_diff
        return cmd_diff(args[0], args[1], json_out="--json" in args)

    # ── Lab ──────────────────────────────────────────────────────────────
    if cmd == "lab":
        if _static_only(argv):
            _guard_static_only(cmd)
            return 2
        show_banner()
        from nightowl_pkg.lab import cmd_lab
        return cmd_lab(args)

    # ── v8.1 Elite RE modules ────────────────────────────────────────────
    if cmd in ("dart", "cryptoscope", "surface", "secrets-src"):
        show_banner()
        if not apk_arg:
            print(f"Usage: nightowl {cmd} <apk-or-dir> [--json]")
            return 2
        target = _resolve_apk(apk_arg)
        json_mode = "--json" in args

        if cmd == "dart":
            from nightowl_pkg.dart import analyze_dart
            rep = analyze_dart(target)
            print(json.dumps(rep, indent=2) if json_mode else _pretty_dart(rep))
            return 0
        if cmd == "cryptoscope":
            from nightowl_pkg.cryptoscope import cmd_cryptoscope
            cmd_cryptoscope(target, json_out=json_mode)
            return 0
        if cmd == "surface":
            from nightowl_pkg.surface import cmd_surface
            cmd_surface(target, json_out=json_mode)
            return 0
        if cmd == "secrets-src":
            src_dir = Path(target)
            if not src_dir.is_dir():
                base = _data_dir() / "workspace" / "decompiled" / Path(target).stem
                src_dir = base / "jadx-src"
            if not src_dir.exists():
                print("[!] Decompile first: nightowl decompile <apk>")
                return 2
            from nightowl_pkg.secretsrc import scan_source_secrets
            rep = scan_source_secrets(src_dir,
                                      min_conf=int(os.environ.get(
                                          "NIGHTOWL_MIN_CONF", "55")))
            kept = rep["findings"]
            print(json.dumps(rep, indent=2) if json_mode else
                  "\n".join(f"[{f['verdict']:9} {f['confidence']:5}] "
                            f"{f['risk']:8} {f['type']}: {f['value'][:40]}"
                            f"  @{f['site']}" for f in kept[:60]))
            print(f"\n{rep['stats']['reported']} reported / "
                  f"{rep['stats']['filtered']} filtered "
                  f"(scanned {rep['stats']['files_scanned']} files)")
            return 0

    # ── API Infrastructure Assessment ────────────────────────────────
    if cmd == "apimap":
        show_banner()
        if not args or args[0].startswith("--"):
            print("Usage: nightowl apimap <base-url> [--routes r1,r2,...] [--json]")
            return 2
        from nightowl_pkg.apimap import cmd_apimap
        base = args[0]
        routes = None
        if "--routes" in args:
            i = args.index("--routes")
            routes = args[i + 1] if i + 1 < len(args) else None
        cmd_apimap(base, routes=routes, json_out="--json" in args)
        return 0

    # ── Hardening / Privacy / SCA ────────────────────────────────────────
    if cmd in ("hardening", "privacy", "sca"):
        show_banner()
        if not apk_arg:
            print(f"Usage: nightowl {cmd} <apk> [--json]")
            return 2
        mod = {"hardening": "hardening", "privacy": "privacy", "sca": "sca"}[cmd]
        kwargs = {"json_out": "--json" in args}
        if cmd == "sca" and "--save-sbom" in args:
            i = args.index("--save-sbom")
            kwargs["save_sbom"] = args[i + 1] if i + 1 < len(args) else None
        getattr(__import__("nightowl_pkg." + mod, fromlist=[mod]),
                f"cmd_{mod}")(_resolve_apk(apk_arg), **kwargs)
        return 0

    # ── MCP server ───────────────────────────────────────────────────────
    if cmd == "mcp":
        from nightowl_pkg.mcp_server import serve
        serve()
        return 0

    # ── No-APK commands ──────────────────────────────────────────────────
    if cmd == "preflight":
        show_banner()
        pf.cmd_preflight()
        return 0

    if cmd == "proxy":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        from nightowl_pkg import proxy as px
        return px.cmd_proxy(args) or 0

    if cmd == "capture":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        from nightowl_pkg.proxy import cmd_capture_wrapper
        return cmd_capture_wrapper(args) or 0

    if cmd == "cvss":
        show_banner()
        if not args:
            print("Usage: nightowl cvss <findings.json>")
            return 2
        result = dj.cmd_cvss(args[0])
        print(json.dumps(result, indent=2))
        return 0

    if cmd in ("flutter", "react-native", "cordova", "unity"):
        show_banner()
        if not apk_arg:
            print(f"Usage: nightowl {cmd} <apk>")
            return 2
        result = fw.cmd_framework(_resolve_apk(apk_arg), cmd)
        print(json.dumps(result, indent=2) if isinstance(result, dict) else str(result))
        return 0

    if cmd == "static-audit":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        if not apk_arg:
            print("Usage: nightowl static-audit <apk> [--reuse-jadx <dir>]")
            return 2
        reuse = None
        if "--reuse-jadx" in args:
            i = args.index("--reuse-jadx")
            reuse = args[i + 1] if i + 1 < len(args) else None
        dj.cmd_static_audit(_resolve_apk(apk_arg), reuse_jadx=reuse)
        return 0

    if cmd == "semgrep":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        if not apk_arg:
            print("Usage: nightowl semgrep <apk_or_dir>")
            return 2
        reuse = None
        if "--reuse-jadx" in args:
            i = args.index("--reuse-jadx")
            reuse = args[i + 1] if i + 1 < len(args) else None
        target = _resolve_apk(apk_arg)
        result = dj.cmd_semgrep(target, reuse_jadx=reuse)
        print("---BEGIN_JSON---")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print("---END_JSON---")
        rp = _data_dir() / "workspace" / "reports"
        rp.mkdir(parents=True, exist_ok=True)
        (rp / f"semgrep-{Path(target).stem}.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if cmd == "rasp":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        if not apk_arg:
            print("Usage: nightowl rasp <apk> [package]")
            return 2
        pkg = None
        positional = [a for a in args if not a.startswith("--")]
        if len(positional) > 1:
            pkg = positional[1]
        result = rt.cmd_rasp(_resolve_apk(apk_arg), pkg)
        print(json.dumps(result, indent=2, ensure_ascii=False)
              if isinstance(result, dict) else str(result))
        return 0

    if cmd == "bypass":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        if not args:
            print("Usage: nightowl bypass <package_name> [detector_ids...] [--output DIR]")
            return 2
        detectors = [a for a in args[1:] if not a.startswith("--")]
        output_dir = None
        if "--output" in args:
            i = args.index("--output")
            output_dir = args[i + 1] if i + 1 < len(args) else None
        rt.cmd_bypass(args[0], detector_ids=detectors or
                      ["rootbeer", "frida_detect", "safety_net", "debug_detect"],
                      output_dir=output_dir)
        return 0

    # ── Subscription enforcement ─────────────────────────────────────────
    if cmd == "billing":
        show_banner()
        if not apk_arg:
            print("Usage: nightowl billing <apk> [--json]")
            return 2
        from nightowl_pkg.billing import cmd_billing
        cmd_billing(_resolve_apk(apk_arg), json_out="--json" in args)
        return 0

    if cmd == "bypass-premium":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        if not args:
            print("Usage: nightowl bypass-premium <apk-or-package> [--json]\n"
                  "AUTHORIZED TESTING ONLY - generates Frida hooks to VERIFY "
                  "client-side entitlement weaknesses found by `nightowl billing`.")
            return 2
        from nightowl_pkg.billing import analyze_billing, generate_bypass_script
        target = args[0]
        package = target
        report = {"billing_sdks": [], "enforcement_model": "unknown"}
        if target.lower().endswith(".apk") and Path(target).exists():
            az = nw.NightOwlAnalyzer(_resolve_apk(target))
            az.extract_strings()
            az.analyze_info()
            report = analyze_billing(az.txt, az.d.get("info"))
            package = az.d.get("info", {}).get("package") or package
        out = _data_dir() / "workspace" / "bypass" / f"{package}-premium-verify.js"
        generate_bypass_script(package, report, out)
        msg = (f"[+] Frida verification script written: {out}\n"
               f"[+] Run:\n"
               f"    frida -U -f {package} -l {out} --no-pause\n"
               f"[!] For AUTHORIZED security testing only.")
        if "--json" in args:
            print(json.dumps({"script": str(out), "package": package}, indent=2))
        else:
            print(msg)
        return 0

    # ── Auth map ─────────────────────────────────────────────────────────
    if cmd == "authmap":
        show_banner()
        if not apk_arg:
            print("Usage: nightowl authmap <apk> [--json]")
            return 2
        from nightowl_pkg.authmap import cmd_authmap
        cmd_authmap(_resolve_apk(apk_arg), json_out="--json" in args)
        return 0

    # ── Deep scan ────────────────────────────────────────────────────────
    if cmd == "deepscan":
        show_banner()
        if not apk_arg:
            print("Usage: nightowl deepscan <apk> [--json]")
            return 2
        from nightowl_pkg.deepscan import cmd_deepscan
        cmd_deepscan(_resolve_apk(apk_arg), json_out="--json" in args)
        return 0

    # ── Core engine commands ─────────────────────────────────────────────
    core_cmds = {"full", "quick", "info", "perms", "urls", "secrets",
                 "vulns", "manifest", "apis", "endpoints"}

    if cmd in core_cmds:
        if not apk_arg:
            print(f"Usage: nightowl {cmd} <apk_path>")
            return 2

        json_mode = "--json" in args
        save_mode = "--save" in args
        min_conf = 55
        if "--min-confidence" in args:
            try:
                min_conf = int(args[args.index("--min-confidence") + 1])
            except (IndexError, ValueError):
                pass
        elif "--strict" in args:
            min_conf = 75

        show_banner()
        global _CURRENT_ANALYZER
        az = nw.NightOwlAnalyzer(_resolve_apk(apk_arg), lang="en")
        _CURRENT_ANALYZER = az
        quiet = contextlib.redirect_stdout(sys.stderr) if json_mode \
            else contextlib.nullcontext()

        section_map = {"info": "info", "perms": "perms", "urls": "urls",
                       "secrets": "secrets", "vulns": "vulns",
                       "manifest": "manifest"}
        if cmd in ("full", "quick"):
            with quiet:
                ok = az.run_full()
                if cmd == "full":
                    _attach_advanced_layers(az, save_mode=json_mode)
                    _apply_min_confidence(az, max(min_conf, 35))
        elif cmd in ("apis", "endpoints"):
            with quiet:
                az.extract_strings()
                az.analyze_endpoints()
                az.analyze_apis()
            ok = True
            if json_mode:
                print(json.dumps(az.d["endpoints"], indent=2, ensure_ascii=False))
            else:
                ep = az.d["endpoints"]
                print(f"urls={len(ep['urls'])} api={len(ep['api'])} "
                      f"servers={len(ep['servers'])} domains={len(ep['domains'])} "
                      f"ips={len(ep['ips'])}")
            if save_mode:
                _save_report(az, cmd, apk_arg)
            return 0
        else:
            with quiet:
                ok = az.run_section(section_map[cmd])
                if cmd == "secrets" and min_conf > 55:
                    _apply_min_confidence(az, min_conf)

        if cmd == "secrets":
            stats = az.d.get("secrets_stats", {})
            if not json_mode:
                print(f"\nSecrets validation: {stats.get('raw_candidates', '?')} raw "
                      f"-> {stats.get('reported', '?')} reported "
                      f"({stats.get('filtered', 0)} filtered as false positives)")
                if "--show-filtered" in args:
                    for s in az.d.get("secrets_filtered", [])[:20]:
                        print(f"  FILTERED [{s['confidence']:.0f}%] {s['type']}: "
                              f"{s['value'][:50]} ({'; '.join(s['validation'][:2])})")

        if json_mode and cmd != "apis":
            print(json.dumps(az.d, indent=2, ensure_ascii=False))
        else:
            az.render("full" if cmd not in section_map else cmd)

        if save_mode:
            _save_report(az, cmd, apk_arg)
        return 0 if ok else 1

    if cmd == "decompile":
        if _guard_static_only(cmd):
            return 2
        show_banner()
        if not apk_arg:
            print("Usage: nightowl decompile <apk_path>")
            return 2
        nw.cmd_decompile(_resolve_apk(apk_arg))
        return 0

    if cmd == "scan":
        show_banner()
        nw.cmd_scan(args[0] if args and not args[0].startswith("-") else None)
        return 0

    if cmd.endswith(".apk") and Path(cmd).exists():
        show_banner()
        az = nw.NightOwlAnalyzer(str(Path(cmd).resolve()))
        ok = az.run_full()
        _attach_advanced_layers(az, save_mode=True)
        return 0 if ok else 1

    print(f"Unknown command: {cmd}\nTry 'nightowl help'")
    return 2


def _pretty_dart(rep):
    if not rep.get("is_flutter"):
        return "No Dart snapshot found (not a Flutter app)."
    lines = ["\n=== Flutter/Dart AOT Analysis ===",
             f"architectures : {', '.join(rep['architectures'])}",
             f"packages      : {rep['package_count']} total, "
             f"{len(rep['packages'])} crypto/security-relevant"]
    for name, meta in rep["packages"].items():
        lines.append(f"  - {name}: {meta['kind']} {meta['note']}")
    if rep["api_base_urls"]:
        lines.append(f"API URLs      : {rep['api_base_urls'][:6]}")
    if rep["dart_routes"]:
        lines.append(f"Dart routes   : {rep['dart_routes'][:10]}")
    if rep["rsa_padding"]:
        lines.append("RSA padding   : " + str({k: v['assessment']
                                                for k, v in rep['rsa_padding'].items()}))
    if rep["sensitive_functions"]:
        lines.append(f"sensitive fn  : {rep['sensitive_functions'][:8]}")
    for f in rep["findings"]:
        lines.append(f"  [{f['severity']:6}] {f['title']}")
        if f.get("detail"):
            lines.append(f"           {f['detail']}")
    return "\n".join(lines)


def _data_dir():
    from nightowl_pkg import core as _c
    return getattr(_c, "DATA_DIR", Path.cwd())


def _attach_advanced_layers(az, save_mode=False):
    """Run all advanced layers and merge into az.d for `full` scans."""
    try:
        from nightowl_pkg.billing import analyze_billing, generate_bypass_script
        rep = analyze_billing(az.txt, az.d.get("info"))
        pkg = az.d.get("info", {}).get("package") or "com.target.app"
        rep["package"] = pkg
        script = generate_bypass_script(
            pkg, rep, _data_dir() / "workspace" / "bypass" / f"{pkg}-premium-verify.js")
        rep["verification_script"] = str(script)
        az.d["billing"] = rep
    except Exception:
        pass
    try:
        from nightowl_pkg.authmap import extract_access_points, map_authentication
        amap = map_authentication(az.txt)
        az.d["authmap"] = amap
    except Exception:
        pass
    try:
        from nightowl_pkg.deepscan import analyze_deep, attach_cvss
        az.d["deepscan"] = attach_cvss(analyze_deep(
                az.txt, az.d.get("manifest"), az.d.get("components")))
    except Exception:
        pass
    try:
        from nightowl_pkg.hardening import analyze_hardening
        az.d["hardening"] = analyze_hardening(
            az.txt, az.d.get("info", {}).get("native_libs"), az.d.get("cert"))
    except Exception:
        pass
    try:
        from nightowl_pkg.privacy import analyze_privacy
        az.d["privacy"] = analyze_privacy(az.txt,
                                          az.d["perms"].get("dangerous"))
    except Exception:
        pass
    try:
        from nightowl_pkg.sca import analyze_sca
        az.d["sca"] = analyze_sca(az.txt)
    except Exception:
        pass
    # v8.1: elite RE layers - dart always; source layers when a decompiled
    # tree is available from a previous `decompile` run
    try:
        from nightowl_pkg.dart import analyze_dart
        az.d["dart"] = analyze_dart(str(az.path))
    except Exception:
        pass
    stem = az.path.stem
    jadx = _data_dir() / "workspace" / "decompiled" / stem / "jadx-src"
    apktool_dir = _data_dir() / "workspace" / "decompiled" / stem / "apktool"
    if jadx.exists():
        try:
            from nightowl_pkg.cryptoscope import analyze_crypto_scope
            az.d["cryptoscope"] = analyze_crypto_scope(jadx)
        except Exception:
            pass
        try:
            from nightowl_pkg.secretsrc import scan_source_secrets
            az.d["secrets_src"] = scan_source_secrets(jadx)
        except Exception:
            pass
    if apktool_dir.exists():
        try:
            from nightowl_pkg.surface import analyze_surface
            mf = apktool_dir / "AndroidManifest.xml"
            if mf.exists():
                az.d["surface_map"] = analyze_surface(mf, jadx_src=jadx)
        except Exception:
            pass


def _apply_min_confidence(az, min_conf):
    kept = [s for s in az.d.get("secrets", [])
            if s.get("confidence", 100) >= min_conf]
    demoted = [s for s in az.d.get("secrets", [])
               if s.get("confidence", 100) < min_conf]
    az.d["secrets_filtered"] = (az.d.get("secrets_filtered", []) + demoted)[:80]
    az.d["secrets"] = kept
    st = az.d.setdefault("secrets_stats", {})
    st["reported"] = len(kept)


def _resolve_apk(path):
    p = Path(path)
    if p.exists():
        return str(p.resolve())
    targets = _SCRIPT_DIR / "targets"
    for ext in ("", ".apk"):
        cand = targets / (path + ext)
        if cand.exists():
            return str(cand.resolve())
    if targets.exists():
        apks = sorted(targets.glob("*.apk"))
        if apks:
            return str(apks[0].resolve())
    return path


def _save_report(az, cmd, apk_path):
    reports_dir = _data_dir() / "workspace" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    name = Path(apk_path).stem
    ts = __import__("datetime").datetime.now().strftime("%Y%m%d-%H%M%S")
    f = reports_dir / f"{name}-{cmd}-{ts}.json"
    f.write_text(json.dumps(az.d, indent=2, ensure_ascii=False))
    if RICH:
        con.print(f"[dim]Report saved: {f}[/]")
    else:
        print(f"Report saved: {f}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        if RICH and con:
            con.print(f"[red]Error:[/] {e}")
        else:
            print(f"Error: {e}")
        if "-v" in sys.argv or "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
