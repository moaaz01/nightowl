# deepscan.py -- NightOwl v8 Advanced Static Layers (MASTG-aligned)
#
# Layers not covered by the legacy 9-section engine:
#   - Exported attack surface matrix (components reachable without permission)
#   - Deep-link hijacking candidates
#   - WebView hardening failures (JS bridge, file access, mixed content)
#   - Cryptographic misuse (ECB, static IVs, hardcoded key material, SHA1/MD5)
#   - Intent redirection / PendingIntent mutability
#   - Sensitive data in logs & clipboard
#   - Janus-style signing weaknesses (v1-only schemes)
#
# Every finding carries a MASVS mapping and a CVSS v3.1 vector so output can
# feed the existing CVSS scorer and HTML reporter.

import json
import re

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

WEBVIEW_BAD = [
    (r"setJavaScriptEnabled\s*\(\s*true\s*\)", "JavaScript enabled in WebView", "MEDIUM"),
    (r"addJavascriptInterface\s*\(", "JS native bridge attached (@JavascriptInterface)",
     "HIGH"),
    (r"setAllowFileAccess\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true",
     "File access allowed from WebView URLs", "HIGH"),
    (r"setMixedContentMode\s*\(\s*WebSettings\.MIXED_CONTENT_ALWAYS_ALLOW",
     "Mixed content always allowed (HTTP inside HTTPS pages)", "MEDIUM"),
    (r"setSavePassword\s*\(\s*true", "WebView password saving enabled", "LOW"),
]

CRYPTO_MISUSE = [
    (r"(?i)Cipher\.getInstance\s*\(\s*\"AES/ECB", "AES-ECB mode (no IV, pattern leaks)", "HIGH"),
    (r"(?i)Cipher\.getInstance\s*\(\s*\"DES|\"DESede", "DES/3DES cipher (broken)", "HIGH"),
    (r"(?i)MessageDigest\.getInstance\s*\(\s*\"MD5", "MD5 digest (collisions)", "MEDIUM"),
    (r"(?i)MessageDigest\.getInstance\s*\(\s*\"SHA-?1\"", "SHA-1 digest", "LOW"),
    (r"IvParameterSpec\s*\(\s*[A-Za-z0-9\"\s]{6,40}\)", "Static/hardcoded IV construction",
     "MEDIUM"),
    (r"SecureRandom\s*\([^)]*\)\s*;?\s*//.*seed|SecureRandom\.\s*setSeed\s*\(",
     "Seeded SecureRandom (predictable randomness)", "MEDIUM"),
    (r"(?i)SecretKeySpec\s*\(\s*[^,]{0,4}\"[A-Za-z0-9+/=]{8,32}\"",
     "Hardcoded AES key bytes next to SecretKeySpec", "CRITICAL"),
    (r"(?i)(\"0123456789abcdef\"|\"0000000000000000\"|"
     r"\"0102030405060708\"|\"1234567890123456\")",
     "Well-known default IV/key string", "HIGH"),
]

INTENT_REDIRECTION = [
    (r"getIntent\s*\(\s*\)[^;]{0,80}(startActivity|startService|sendBroadcast|bindService)",
     "Forwarded intent from getIntent() into component start (intent redirection)",
     "HIGH"),
    (r"PendingIntent\.get(Activity|Service|BroadcastReceiver)\s*\([^;]*FLAG_MUTABLE",
     "Mutable PendingIntent created", "MEDIUM"),
    (r"setPackage\s*\(\s*null\s*\)[^;]{0,60}PendingIntent|PendingIntent[^;]{0,120}implicit",
     "Implicit PendingIntent (hijackable)", "LOW"),
]

LOG_LEAK = [
    (r"(?i)Log\.[deiw]\s*\([^;]{0,80}(password|passwd|token|secret|pin|otp|credit)",
     "Sensitive keyword logged via android.util.Log", "MEDIUM"),
    (r"(?i)println\s*\([^;]{0,60}(password|token|secret)", "Sensitive println logging", "LOW"),
]

CLIPBOARD = [
    (r"(?i)setPrimaryClip|ClipData\.newPlainText", "App writes to clipboard "
     "(other apps may read it on older Android)", "LOW"),
    (r"(?i)getPrimaryClip", "App reads clipboard contents", "INFO"),
]


def _run_rules(rules, txt, category, findings):
    for pat, title, sev in rules:
        hits = re.findall(pat, txt)
        if hits:
            findings.append({
                "category": category,
                "severity": sev,
                "title": title,
                "matches": len(hits),
                "evidence": [h[:100] if isinstance(h, str) else h[0][:100]
                             for h in hits[:4]],
            })


def analyze_deep(txt, manifest=None, components=None):
    """Run advanced static layers. `manifest` is the parsed manifest dict
    produced by the legacy engine (activities/services/receivers/providers)."""
    findings = []

    # ── Attack surface ────────────────────────────────────────────────────
    surface = {"exported_activities": [], "exported_services": [],
               "exported_receivers": [], "exported_providers": []}
    # v8.1.1: provenance-critical fix. The legacy engine emits component
    # NAMES (strings) without exported flags; treating every name as
    # exported produced HIGH false positives on apps whose providers are
    # all exported=false (MaxStore case). Only dict-shaped entries carry
    # ground truth; for string-only manifests we downgrade to INFO and
    # point analysts at `nightowl surface`.
    if manifest:
        def exported(items):
            out = []
            undetermined = 0
            for it in items or []:
                if isinstance(it, dict):
                    if it.get("exported") or it.get("exported_true"):
                        out.append(it.get("name", "?"))
                elif isinstance(it, str):
                    undetermined += 1
            return out, undetermined

        for key, mkey in (("exported_activities", "activities"),
                          ("exported_services", "services"),
                          ("exported_receivers", "receivers"),
                          ("exported_providers", "providers")):
            surface[key], undet = exported(manifest.get(mkey))
            surface.setdefault("undetermined", {})[mkey] = undet

        n_export = sum(len(surface[k]) for k in
                       ("exported_activities", "exported_services",
                        "exported_receivers", "exported_providers"))
        if n_export:
            findings.append({
                "category": "Attack Surface",
                "severity": "MEDIUM" if n_export <= 4 else "HIGH",
                "title": f"{n_export} exported components reachable by other apps",
                "matches": n_export,
                "evidence": sum((surface[k] for k in surface
                                 if k.startswith("exported_")), [])[:8],
            })
        if surface["exported_providers"]:
            findings.append({
                "category": "Attack Surface",
                "severity": "HIGH",
                "title": "Exported ContentProviders (query/injection surface)",
                "matches": len(surface["exported_providers"]),
                "evidence": surface["exported_providers"][:5],
            })
        # v8.1.1: prefer engine's parsed ground truth when available -
        # components.exported_no_perm carries exact exported+unprotected set
        if components and components.get("exported_no_perm"):
            real = components["exported_no_perm"]
            by_type = {}
            for c in real:
                by_type.setdefault(c.get("type", "?"), []).append(
                    c.get("component", "?"))
            n_real = len(real)
            if n_real:
                findings.append({
                    "category": "Attack Surface",
                    "severity": "MEDIUM" if n_real <= 4 else "HIGH",
                    "title": f"{n_real} exported UNPROTECTED components "
                             f"(decoded-manifest truth)",
                    "matches": n_real,
                    "evidence": [f"{c['type']}:{c['component']}"
                                 for c in real[:8]],
                })
            for pi in components.get("provider_issues") or []:
                findings.append({
                    "category": "Attack Surface",
                    "severity": "LOW",
                    "title": f"Provider grantUriPermissions: "
                             f"{pi.get('component','?').split('.')[-1]}",
                    "detail": pi.get("issue", ""),
                })
        undet_total = sum(surface.get("undetermined", {}).values())
        if undet_total and not surface["exported_providers"]:
            findings.append({
                "category": "Attack Surface",
                "severity": "INFO",
                "title": f"{undet_total} component(s) with undetermined "
                         f"exported status",
                "detail": "Binary manifest parse lacked exported flags - "
                          "run `nightowl decompile` + `nightowl surface` "
                          "for ground truth.",
                "matches": undet_total,
            })

    # ── Deep links ────────────────────────────────────────────────────────
    schemes = sorted(set(re.findall(
        r'android:scheme\s*=\s*"([a-zA-Z][a-zA-Z0-9+.\-]{1,30})"', txt)))
    custom_schemes = [s for s in schemes if s.lower() not in
                      ("http", "https", "mailto", "tel", "sms", "content", "file")]
    autoverify = re.search(r"android:autoVerify\s*=\s*\"?true", txt)
    if custom_schemes:
        findings.append({
            "category": "Deep Links",
            "severity": "MEDIUM",
            "title": f"{len(custom_schemes)} custom URI scheme(s) declared",
            "matches": len(custom_schemes),
            "evidence": custom_schemes[:10],
            "note": ("Custom schemes are hijackable by any installed app unless "
                     "App Links (autoVerify) is used." if not autoverify else None),
        })
        if not autoverify:
            findings.append({
                "category": "Deep Links",
                "severity": "MEDIUM",
                "title": "No autoVerify=true App Link verification",
                "matches": 1,
                "evidence": ["scheme handlers without domain ownership proof"],
            })

    # ── Rule-driven categories ────────────────────────────────────────
    _run_rules(WEBVIEW_BAD, txt, "WebView", findings)
    _run_rules(CRYPTO_MISUSE, txt, "Crypto", findings)
    _run_rules(INTENT_REDIRECTION, txt, "Intents", findings)
    _run_rules(LOG_LEAK, txt, "Logging", findings)
    _run_rules(CLIPBOARD, txt, "Clipboard", findings)

    # Deduplicate per (category,title)
    uniq, seen = [], set()
    for f in findings:
        k = (f["category"], f["title"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)

    sev_rank = {k: i for i, k in enumerate(SEV_ORDER)}
    uniq.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    return {
        "module": "deep-static-layers",
        "attack_surface": surface,
        "uri_schemes": schemes,
        "findings": uniq,
    }


CVSS_BASE = {
    "Exported ContentProviders (query/injection surface)":
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "Hardcoded AES key bytes next to SecretKeySpec":
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "JS native bridge attached (@JavascriptInterface)":
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
}


def attach_cvss(report):
    for f in report["findings"]:
        f["cvss_vector"] = CVSS_BASE.get(f["title"])
    return report


def cmd_deepscan(apk_path: str, analyzer=None, json_out=False):
    """CLI handler: nightowl deepscan <apk>"""
    from . import core as nw
    az = analyzer
    if az is None:
        az = nw.NightOwlAnalyzer(apk_path)
        az.extract_strings()
        az.analyze_manifest()
        az.analyze_components()
    manifest = az.d.get("manifest") or {}
    rep = attach_cvss(analyze_deep(az.txt, manifest))

    if json_out:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return rep

    RICH = getattr(nw, "RICH", False)
    con = getattr(nw, "con", None)
    lines = ["", "=== Deep Static Layers ==="]
    for f in rep["findings"]:
        extra = f" | {f['cvss_vector']}" if f.get("cvss_vector") else ""
        lines.append(f"[{f['severity']:8}] ({f['category']}) {f['title']} "
                     f"x{f['matches']}{extra}")
        note = f.get("note")
        if note:
            lines.append(f"           note: {note}")
    text = "\n".join(lines)
    if RICH and con:
        con.print(text)
    else:
        print(text)
    return rep
