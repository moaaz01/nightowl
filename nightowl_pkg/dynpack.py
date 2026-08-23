# dynpack.py -- NightOwl v8.2.2 Dynamic Verification Pack
#
# Bridges static findings to CONFIRMED runtime facts when the analyst's
# device/emulator is NOT attached to this machine (e.g. Android Studio on
# the analyst's Windows PC):
#
#   nightowl lab pack targets/App.apk        -> writes dynamic_pack.sh
#   (analyst runs it where adb lives; bash or PowerShell-wrapped)
#   nightowl lab ingest results.json         -> merges verified verdicts
#
# The pack embeds every claim NightOwl made statically (exported activities,
# providers-not-exported, debuggable=false, backup=false...) as live checks,
# executes them against the connected device, and emits structured JSON so
# the report can flip each claim to VERIFIED / REFUTED with evidence.

import json
import re
import shlex
from pathlib import Path


def _sh(s):
    return shlex.quote(str(s))


def generate_pack(apk_path, package=None, components=None, providers=None,
                  deeplinks=None, out_path=None, powershell=False):
    """Build a self-contained verification script for a device with adb."""
    pkg = package or "?"
    apk_name = Path(apk_path).name

    lines = []
    ps = powershell
    shebang = ("# Run on the machine where your emulator/device is connected:"
               if not ps else
               "# PowerShell - run on the machine where adb sees your device:")
    lines.append(shebang)
    lines.append("# NightOwl Dynamic Verification Pack v1")
    lines.append(f"# target: {apk_name}  package: {pkg}")
    lines.append("# Requires: adb + the APK file next to this script")
    if not ps:
        lines.append("#!/usr/bin/env bash")
    lines.append("")

    def emit(cmd, json_key, expect_note=""):
        """Append one check: runs cmd, stores output under key."""
        if ps:
            lines.append(f'Write-Output "###CHECK {json_key}###"')
            lines.append(f"try {{ {cmd} }} catch {{ Write-Output $_.Exception.Message }}")
        else:
            lines.append(f'echo "###CHECK {json_key}###"')
            lines.append(cmd)

    pre = "adb " if not ps else "adb "
    # 0) environment
    emit(pre + "devices -l", "devices")
    # 1) install
    apk_arg = f'"{apk_name}"'
    emit(pre + f"install -r {apk_arg}", "install")
    # 2) debuggable ground truth at runtime
    emit(pre + f'shell "run-as {pkg} id 2>&1"', "runas_access",
         "success=debuggable")
    emit(pre + f'shell dumpsys package {pkg} | grep -E '
         f'"pkgFlags|debuggable|allowBackup|PRIVATE_FLAG"', "pkg_flags")
    # 3) exported activity launches (from surface map)
    for comp in (components or [])[:6]:
        comp_name = comp if isinstance(comp, str) else \
            comp.get("component") or comp.get("name")
        if not comp_name:
            continue
        act = comp.split(":")[-1] if ":" in str(comp) else comp_name
        emit(pre + f'shell am start -n "{pkg}/{act}"', f"launch:{act}")
        emit(pre + "shell sleep 2", f"launch_wait:{act}")
    # 4) deeplink probes
    for dl in (deeplinks or [])[:6]:
        emit(pre + f'shell am start -a android.intent.action.VIEW -d "{dl}"',
             f"deeplink:{dl}")
    # 5) provider probes (expect SecurityException when NOT exported)
    for prov in (providers or [])[:8]:
        name = prov if isinstance(prov, str) else \
            prov.get("component") or prov.get("name")
        if not name:
            continue
        authority = name
        emit(pre + f'shell content query --uri content://{authority}/ 2>&1',
             f"provider_query:{name}")
    # 6) logcat leakage window while app foregrounded
    emit(pre + "logcat -c", "logcat_clear")
    emit(pre + f"shell monkey -p {pkg} -c "
         f"android.intent.category.LAUNCHER 1", "relaunch_for_logcat")
    if not ps:
        lines.append("sleep 6")
    else:
        lines.append("Start-Sleep -Seconds 6")
    emit(pre + 'logcat -d -v brief', "logcat_dump")
    # 7) uninstall prompt (commented)
    lines.append("")
    lines.append("# optional cleanup: adb uninstall " + pkg)

    # ---- JSON assembly tail ----
    if not ps:
        lines.append("""
echo "###RESULTS_JSON###"
python3 - "$0" <<'PYEOF'
import json, sys, re, subprocess
raw = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
checks = {}
parts = re.split(r'###CHECK ([^#]+)###\\n?', raw)
for i in range(1, len(parts), 2):
    checks[parts[i]] = parts[i+1].strip()[:20000]
out = {"pack_version": 1, "checks": checks}
print(json.dumps(out))
PYEOF""")
    return "\n".join(lines)


def build_pack(apk_path, full_report=None, powershell=False, out_dir=None):
    """Compose pack from a saved/full report dict."""
    d = full_report or {}
    pkg = (d.get("info") or {}).get("package")
    comps = []
    sm = d.get("surface_map") or {}
    for c in sm.get("components", []):
        if c.get("type") == "activity":
            comps.append(c.get("name"))
    if not comps and d.get("components", {}).get("exported_no_perm"):
        comps = [c["component"] for c in d["components"]["exported_no_perm"]
                 if c.get("type") == "activity"]
    providers = [c["component"] for c in
                 (d.get("components", {}).get("provider_issues") or [])]
    if not providers and d.get("manifest"):
        providers = d["manifest"].get("providers", [])[:6]
    deeplinks = list(sm.get("components", []) and [
        dl for c in sm.get("components", []) for dl in c.get("deeplinks", [])
    ]) or []

    script = generate_pack(apk_path, package=pkg, components=comps,
                           providers=providers, deeplinks=deeplinks,
                           powershell=powershell)
    ext = "ps1" if powershell else "sh"
    out_dir = Path(out_dir or (Path.cwd() / "workspace" / "dynpack"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"dynamic_pack_{Path(apk_path).stem}.{ext}"
    out.write_text(script)
    return out


def _load_checks(path):
    """Accept either our bash-JSON format or raw sectioned text
    (PowerShell redirect output)."""
    raw = Path(path).read_text(encoding="utf-8", errors="ignore")
    if raw.lstrip().startswith("{"):
        data = json.loads(raw)
        return data.get("checks", {})
    checks = {}
    parts = re.split(r"###CHECK ([^#\n]+)###\n?", raw)
    for i in range(1, len(parts), 2):
        checks[parts[i]] = parts[i + 1].strip()[:20000]
    return checks


def ingest(results_json_path, base_report_path=None, out_path=None):
    """Merge returned pack results into verdicts; optionally patch report."""
    checks = _load_checks(results_json_path)
    verdicts = []

    def add(claim, status, evidence):
        verdicts.append({"claim": claim, "status": status,
                         "evidence": str(evidence)[:400]})

    for key, out in checks.items():
        low = str(out).lower()
        if key.startswith("launch:") or key.startswith("deeplink:"):
            ok = "starting:" in low or "activity manager" in low or \
                "warning" not in low[:60]
            blocked = "permission denial" in low or "securityexception" in low
            add(key, "VERIFIED-LAUNCHABLE" if ok and not blocked else
                ("BLOCKED" if blocked else "FAILED"), out[:160])
        elif key.startswith("provider_query:"):
            blocked = "permission denial" in low or "securityexception" in low \
                or "not exported" in low or "does not exist" in low
            leaked = "row " in low or '"="' in low or low.strip().startswith(
                "result")
            if leaked:
                add(key, "REFUTED-LEAKS-DATA!", out[:200])
            elif blocked:
                add(key, "CONFIRMED-NOT-EXPORTED", out[:160])
            else:
                add(key, "UNKNOWN", out[:120])
        elif key == "runas_access":
            dbg = "uid=" in low and "exception" not in low and "not debuggable" not in low
            add("app-is-debuggable(run-as)", "VERIFIED-DEBUGGABLE" if dbg
                else "CONFIRMED-NOT-DEBUGGABLE", out[:160])
        elif key == "pkg_flags":
            add("pkg-flags", "INFO", out[:300])
        elif key == "logcat_dump":
            import re as _re
            leaks = _re.findall(
                r"(?i)(?:password|token|secret|apikey|api_key|bearer)"
                r"[^=\n]{0,10}[=:]\s*[^\s]{6,}", str(out))
            add("logcat-secret-leak-scan",
                f"{len(leaks)} potential leak(s)" if leaks else "CLEAN",
                leaks[:6])
        elif key == "install":
            add("install", "Success" if "success" in low else out[:100],
                out[:100])

    summary = {
        "module": "dynamic-verification",
        "source": str(results_json_path),
        "verdicts": verdicts,
        "counts": {
            "verified": sum(1 for v in verdicts
                            if "VERIFIED" in v["status"] or
                            v["status"] == "Success"),
            "refuted_or_blocked": sum(1 for v in verdicts
                                      if "REFUTED" in v["status"] or
                                      v["status"] == "BLOCKED" or
                                      "NOT-EXPORTED" in v["status"]),
            "leaks": sum(1 for v in verdicts if "leak(s)" in v["status"]),
        },
    }
    if out_path:
        Path(out_path).write_text(json.dumps(summary, indent=2,
                                             ensure_ascii=False))
    return summary
