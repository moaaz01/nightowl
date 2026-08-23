# sca.py -- NightOwl v8 Software Composition Analysis + CycloneDX SBOM
#
# Curated vulnerable-library intelligence for the Android ecosystem
# (OWASP Mobile Top 10 M2 - Insecure Data/Supply Chain) plus a CycloneDX 1.5
# component inventory generated from detected SDKs and native libraries.
#
# Detection is version-aware where evidence exists (POM properties in apktool
# resources, version strings in DEX); otherwise components are listed without
# a vulnerable/not-vulnerable verdict to stay honest.

import re
from datetime import datetime, timezone

# Advisory entries:
#   package key -> {title, cve/advisory, affected: callable(version)->bool,
#                   fix, severity, reference}
def _lt(v, bound):
    """Naive dotted-version compare: v < bound."""
    try:
        a = [int(x) for x in re.split(r"[.\-_+]", v)[:3] if x.isdigit()]
        b = [int(x) for x in bound.split(".")[:3]]
        while len(a) < 3:
            a.append(0)
        return a < b
    except Exception:
        return False


VULN_DB = {
    "okhttp": {
        "title": "OkHttp hostname verification flaw (cert pinning bypass family)",
        "advisory": "CVE-2021-0341",
        "affected": lambda v: _lt(v, "4.9.2"),
        "fix": ">= 4.9.2",
        "severity": "HIGH",
        "reference": "https://github.com/square/okhttp/security/advisories",
    },
    "libwebp": {
        "title": "libwebp heap buffer overflow (image parsing)",
        "advisory": "CVE-2023-4863",
        "affected": lambda v: _lt(v, "1.3.2"),
        "fix": ">= 1.3.2",
        "severity": "CRITICAL",
        "reference": "https://chromereleases.googleblog.com/2023/09/",
    },
    "bcprov (Bouncy Castle)": {
        "title": "Bouncy Castle information disclosure / weak PRNG era",
        "advisory": "CVE-2015-6644 / CVE-2016-1000338+",
        "affected": lambda v: _lt(v, "1.56"),
        "fix": ">= 1.60",
        "severity": "MEDIUM",
        "reference": "https://www.bouncycastle.org/releasenotes.html",
    },
    "jackson-databind": {
        "title": "Jackson-databind polymorphic deserialization gadget chain",
        "advisory": "CVE-2017-7525",
        "affected": lambda v: _lt(v, "2.8.9") or _lt(v, "2.9.0"),
        "fix": ">= 2.9.9.1 / enable default-typing guards",
        "severity": "HIGH",
        "reference": "https://github.com/FasterXML/jackson-databind/issues",
    },
    "guava": {
        "title": "Guava AtomicDoubleArray / unsafe deserialization",
        "advisory": "CVE-2018-10237",
        "affected": lambda v: _lt(v, "24.1.1"),
        "fix": ">= 24.1.1",
        "severity": "MEDIUM",
        "reference": "https://github.com/google/guava/releases",
    },
    "glide": {
        "title": "Glide bitmap decoding DoS window",
        "advisory": "GHSA glide-2021",
        "affected": lambda v: _lt(v, "4.12.0"),
        "fix": ">= 4.12.0",
        "severity": "LOW",
        "reference": "https://github.com/bumptech/glide/releases",
    },
}

# Component markers -> canonical component names for SBOM
COMPONENT_MARKERS = {
    "okhttp": ["okhttp3", "com.squareup.okhttp"],
    "retrofit": ["retrofit2", "com.squareup.retrofit"],
    "gson": ["com.google.gson"],
    "moshi": ["com.squareup.moshi"],
    "jackson-databind": ["com.fasterxml.jackson"],
    "glide": ["com.bumptech.glide"],
    "picasso": ["com.squareup.picasso"],
    "coil": ["io.coil", "coil.compose"],
    "volley": ["com.android.volley"],
    "ktor": ["io.ktor"],
    "bouncycastle (bcprov)": ["org.bouncycastle", "bcprov"],
    "spongycastle": ["org.spongycastle"],
    "conscrypt": ["org.conscrypt"],
    "guava": ["com.google.common.collect", "com.google.common.base"],
    "kotlinx-coroutines": ["kotlinx.coroutines"],
    "react-native": ["com.facebook.react"],
    "flutter-engine": ["libflutter.so", "io.flutter"],
    "unity-engine": ["libunity.so", "com.unity3d"],
    "webview-assets (libwebp)": ["libwebp.so"],
    "sqlite-android": ["android.database.sqlite"],
    "room": ["androidx.room"],
    "realm": ["io.realm"],
}

VERSION_RES = [
    # POM properties / gradle leftovers inside apktool res/values/*.xml
    r"(?i)(?P<comp>okhttp|retrofit|glide|gson|guava|coil|ktor)[_\-]?version[\"']?\s*"
    r"(?:[:=]\s*|\s+value\s*=\s*)[\"']?(?P<ver>\d+\.\d+(?:\.\d+)?)",
    r"(?i)(?P<comp>okhttp|glide)\s*[/\\]?\s*v?(?P<ver>\d\.\d+\.\d+)",
]


def _detect_versions(txt):
    versions = {}
    for pat in VERSION_RES:
        for m in re.finditer(pat, txt):
            comp = m.group("comp").lower()
            ver = m.group("ver")
            if comp not in versions or _lt(versions[comp], ver):
                versions[comp] = ver
    return versions


def analyze_sca(txt, arch=None):
    """Return vulnerable-component findings + full CycloneDX-style inventory."""
    markers_present = {}
    low = txt.lower()
    for comp, marks in COMPONENT_MARKERS.items():
        hits = sorted({m for m in marks if m.lower() in low})
        if hits:
            markers_present[comp] = hits

    versions = _detect_versions(txt)

    findings = []
    for comp, info in VULN_DB.items():
        marker_key = next((k for k in markers_present if k.startswith(
            comp.split(" ")[0].lower())), None)
        if not marker_key and not any(comp.lower().startswith(k.split(" ")[0])
                                      for k in markers_present):
            continue
        ver = versions.get(comp.split(" ")[0].lower())
        if ver is None:
            findings.append({
                "component": comp,
                "severity": "INFO",
                "title": f"{comp} present - version NOT determinable",
                "advisory": info["advisory"],
                "detail": f"Manual check advised against fix {info['fix']} "
                          f"({info['title']}).",
                "version": None,
            })
            continue
        if info["affected"](ver):
            findings.append({
                "component": comp,
                "severity": info["severity"],
                "title": f"Vulnerable dependency: {comp} {ver} "
                         f"({info['advisory']})",
                "advisory": info["advisory"],
                "detail": f'{info["title"]}. Fix: upgrade to {info["fix"]}. '
                          f'Reference: {info["reference"]}',
                "version": ver,
            })

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_rank.get(f.get("severity"), 9))

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": [{"vendor": "NightOwl", "name": "nightowl-sca",
                       "version": "8.0"}],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "properties": [{"name": "generated-from",
                            "value": "static APK analysis"}],
        },
        "components": [
            {"type": "library", "name": comp,
             "evidence": hits[:3],
             "version": versions.get(comp.split(" ")[0].lower())}
            for comp, hits in sorted(markers_present.items())
        ],
    }

    return {
        "module": "sca-supply-chain",
        "components_found": sorted(markers_present.keys()),
        "versions_detected": versions,
        "vulnerable": [f for f in findings
                       if f["severity"] != "INFO"],
        "needs_manual_review": [f for f in findings
                                if f["severity"] == "INFO"],
        "findings": findings,
        "sbom": sbom,
    }


def cmd_sca(apk_path: str, analyzer=None, json_out=False, save_sbom=None):
    """CLI handler: nightowl sca <apk>"""
    from . import core as nw
    az = analyzer
    if az is None:
        az = nw.NightOwlAnalyzer(apk_path)
        az.extract_strings()
        az.analyze_arch()
    rep = analyze_sca(az.txt, az.d.get("arch"))
    if save_sbom:
        from pathlib import Path
        import json as _json
        p = Path(save_sbom)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_json.dumps(rep["sbom"], indent=2))
    if json_out:
        import json as _json
        print(_json.dumps(rep, indent=2, ensure_ascii=False))
        return rep

    print("\n=== Software Composition Analysis ===")
    print(f"Components detected : {len(rep['components_found'])}")
    print(f"Versions extracted  : {rep['versions_detected'] or '-'}")
    for f in rep["vulnerable"]:
        print(f"  [{f['severity']:8}] {f['title']}")
        print(f"             {f['detail']}")
    if rep["needs_manual_review"]:
        print("Manual review:")
        for f in rep["needs_manual_review"]:
            print(f"  [-] {f['title']}")
    return rep
