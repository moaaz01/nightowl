# surface.py -- NightOwl v8.1 Attack-Surface Exploitation Map
#
# Parses apktool's decoded AndroidManifest.xml directly and produces an
# actionable pentest map: every exported component, its protections, deep
# links, and ready-to-run adb recipes for manual verification.
#
# AUTHORIZED TESTING ONLY - the recipes target a device/emulator you own.

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"

# v8.1.1: exports that exist BY DESIGN of the vendor SDK - flagging them
# HIGH every scan erodes analyst trust.
KNOWN_BY_DESIGN_PREFIXES = (
    "com.google.android.play.core.",
    "androidx.profileinstaller.",
)


def _trivial_activity_note(jadx_src: Path | None, class_name: str):
    """If decompiled activity is a bare Flutter/empty subclass with no
    getIntent/extras handling, an exported status is cosmetic."""
    if not jadx_src or not jadx_src.exists():
        return None
    for prefix in ("sources/", "", "app/"):
        jf = jadx_src / (prefix + class_name.replace(".", "/") + ".java")
        if jf.exists():
            break
    else:
        return None
    try:
        code = jf.read_text(errors="ignore")
    except Exception:
        return None
    body_lines = [l for l in code.splitlines()
                  if l.strip() and not l.strip().startswith(("//", "*", "/*",
                                                              "import ",
                                                              "package "))]
    sensitive = re.search(r"getIntent|getParcelableExtra|getStringExtra|"
                          r"getData\(\)|onNewIntent", code)
    if len(body_lines) <= 14 and not sensitive:
        return ("trivial launcher subclass - no intent data handling found; "
                "exported surface is cosmetic")
    return None
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _find_manifest(apktool_dir: Path):
    for cand in (apktool_dir / "AndroidManifest.xml",):
        if cand.exists():
            return cand
    for p in apktool_dir.rglob("AndroidManifest.xml"):
        return p
    return None


def analyze_surface(manifest_xml_path, jadx_src=None):
    """Parse decoded manifest -> exported component map + adb recipes."""
    path = Path(manifest_xml_path)
    if not path.exists():
        return {"module": "attack-surface-map",
                "error": f"manifest not found: {path}", "components": [],
                "adb_recipes": [], "findings": []}

    root = ET.parse(path).getroot()
    pkg = root.get("package", "?")  # plain attribute, no android ns
    components = []

    def _intent_filters(el):
        out = []
        for f in el.findall("intent-filter"):
            entry = {"actions": [], "categories": [], "data": []}
            for a in f.findall("action"):
                entry["actions"].append(a.get(ANDROID + "name", ""))
            for c in f.findall("category"):
                entry["categories"].append(c.get(ANDROID + "name", ""))
            for d in f.findall("data"):
                dd = {k.split("}")[1]: v for k, v in d.attrib.items()}
                if dd:
                    entry["data"].append(dd)
            out.append(entry)
        return out

    for tag in ("activity", "activity-alias", "service", "receiver",
                "provider"):
        for el in root.iter(tag):
            name = el.get(ANDROID + "name", "?")
            exported = el.get(ANDROID + "exported")
            filters = _intent_filters(el)
            # pre-API31 semantics: intent-filter implies exported unless
            # explicitly disabled
            is_exported = (exported == "true") or (
                exported is None and bool(filters))
            if not is_exported:
                continue
            comp = {
                "type": tag,
                "name": name,
                "permission": el.get(ANDROID + "permission"),
                "grantUriPermissions": el.get(
                    ANDROID + "grantUriPermissions"),
                "exported": exported or "implicit(intent-filter)",
                "intent_filters": filters,
                "deeplinks": [],
            }
            for f in filters:
                for d in f["data"]:
                    sch = d.get("scheme")
                    host = d.get("host", "*")
                    if sch:
                        comp["deeplinks"].append(f"{sch}://{host}")
            components.append(comp)

    # severity classification
    findings = []
    for c in components:
        unprotected = not c["permission"]
        if c["type"] == "provider":
            sev = "HIGH" if unprotected else "INFO"
            findings.append({
                "severity": sev,
                "title": f"Exported provider: {c['name']}",
                "detail": ("No permission required - queryable/injectable "
                           "by any app" if unprotected else
                           f"protected by {c['permission']}"),
                "evidence": [c["grantUriPermissions"] or ""],
            })
        elif c["type"] in ("activity", "activity-alias") and \
                unprotected and c["deeplinks"]:
            sev = "MEDIUM"
            findings.append({
                "severity": sev,
                "title": f"Deep-link entry: {', '.join(c['deeplinks'])}",
                "detail": f"{c['name']} accepts external links; verify host "
                          f"validation inside the handler.",
                "evidence": [f'am start -a android.intent.action.VIEW -d '
                             f'"{c["deeplinks"][0]}"'],
            })
        elif c["type"] in ("activity",) and unprotected:
            trivial = _trivial_activity_note(jadx_src, c["name"])
            if any(c["name"].startswith(pref) for pref
                   in KNOWN_BY_DESIGN_PREFIXES):
                sev, extra = "INFO", "vendor by-design export."
            elif trivial:
                sev, extra = "LOW", trivial
            else:
                sev, extra = "LOW", ""
            findings.append({
                "severity": sev,
                "title": f"Exported activity: {c['name']}",
                "detail": ("Launchable by other apps; confirm it never "
                           "renders sensitive fragments on intent extras."
                           + (f" {extra}" if extra else "")),
            })
        elif c["type"] == "service" and unprotected:
            if any(c["name"].startswith(pref) for pref
                   in KNOWN_BY_DESIGN_PREFIXES):
                findings.append({
                    "severity": "INFO",
                    "title": f"Vendor by-design service export: "
                             f"{c['name'].split('.')[-1]}",
                    "detail": "Play Core asset-delivery pattern; expected.",
                })

    # adb recipes (authorized lab only)
    recipes = []
    for c in components:
        if c["type"] in ("activity", "activity-alias"):
            recipes.append(
                f"adb shell am start -n {pkg}/{c['name']}" +
                (f"  # deeplink: {c['deeplinks'][0]}"
                 if c["deeplinks"] else ""))
        elif c["type"] == "provider":
            authority_hint = re.sub(r".*\.([A-Za-z0-9_]+)$", r"\1",
                                    c["name"])
            recipes.append(
                f"# provider probe (needs readable table names): "
                f"adb shell content query --uri content://{authority_hint}/")

    sev_rank = {k: i for i, k in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    return {
        "module": "attack-surface-map",
        "package": pkg,
        "manifest": str(path),
        "exported_count": len(components),
        "components": components,
        "findings": findings,
        "adb_recipes": recipes[:25],
    }


def cmd_surface(apk_or_dir: str, json_out=False):
    """CLI handler: nightowl surface <apk>  (uses apktool output if present)"""
    from . import core as nw
    p = Path(apk_or_dir)
    base = p if p.is_dir() else \
        nw.DATA_DIR / "workspace" / "decompiled" / p.stem / "apktool"
    manifest = _find_manifest(base)
    if not manifest:
        print("[!] Decoded manifest not found. Run first:")
        print(f"    nightowl decompile {apk_or_dir}")
        return {"error": "no manifest"}
    jadx_dir = base.parent / "jadx-src" if base.name == "apktool" else None
    rep = analyze_surface(manifest, jadx_src=jadx_dir)
    if json_out:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return rep
    print("\n=== Attack-Surface Exploitation Map ===")
    print(f"package: {rep.get('package')} | exported: {rep['exported_count']}")
    for c in rep["components"]:
        prot = c["permission"] or "UNPROTECTED"
        dl = f" deeplink={','.join(c['deeplinks'])}" if c["deeplinks"] else ""
        print(f"  [{c['type']:14}] {c['name'][:60]} [{prot}]{dl}")
    print("\n-- Findings --")
    for f in rep["findings"]:
        print(f"  [{f['severity']:8}] {f['title']}")
        if f.get("detail"):
            print(f"             {f['detail']}")
    print("\n-- adb verification recipes (your own device!) --")
    for r in rep["adb_recipes"][:10]:
        print("  " + r)
    return rep


if __name__ == "__main__":  # pragma: no cover
    pass
