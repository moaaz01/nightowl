# hardening.py -- NightOwl v8 Hardening & Anti-Analysis Fingerprinter
#
# APKiD-inspired (no external dependency): identifies packers, protectors,
# obfuscators and compilers from binary signatures, plus signing-scheme
# weaknesses (Janus / v1-only) surfaced from certificate metadata.
# Complements nightowl_pkg.runtime (RASP detectors) without duplicating it.

import re

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# name -> (category, evidence markers). Categories mirror APKiD vocabulary.
PACKERS = {
    "360 Jiagu (Qihoo)": ("packer", ["libjiagu.so", "libjiagu_art.so",
                                    "libjiagu_x86.so", "com.qihoo.util",
                                    "libjiagu_pro.so"]),
    "Bangcle / SecNeo": ("packer", ["libexecmain.so", "com.secneo.apkwrapper",
                                    "libDexHelper.so", "libSecShell.so"]),
    "Ijiami": ("packer", ["ijiami.dat", "ijiami.ajm", "com.shell.SuperApplication",
                          "libexec.so"]),
    "Tencent Legu": ("packer", ["libshella-", "libshellx-", "com.tencent.StubShell",
                                "tx_shell.lib"]),
    "Baidu Protect": ("packer", ["libbaiduprotect.so", "libbaiduprotect_x86.so"]),
    "Alibaba Mobile Sec": ("packer", ["libmobisec.so", "libmobisecpro.so",
                                      "aliprotect"]),
    "APKProtect": ("packer", ["libapkprotect.so"]),
    "AEGT": ("packer", ["libchaosvmp.so", "libddog.so", "libfdog.so"]),
    "NQ Shield": ("packer", ["libnqshield.so"]),
    "Vkey": ("packer", ["libvkey.so"]),
    "DexProtector": ("protector", ["DexProtector", "dexprotector"]),
    "Appdome": ("protector", ["com.appdome", "libappdome"]),
    "Arxan": ("protector", ["arxan", "libarxan"]),
    "Promon SHIELD": ("protector", ["promon", "libshield.so"]),
    "DexGuard": ("obfuscator", ["dexguard", "DexGuard"]),
    "Allatori": ("obfuscator", ["allatori"]),
    "DashO": ("obfuscator", ["dasho", "DashO"]),
    "Zelix KlassMaster": ("obfuscator", ["ZKM", "zelux"]),
}

COMPILERS = {
    "R8/D8 (Android default)": ["r8", "R8$"],
    "Kotlin Compiler": ["kotlin.jvm.internal", "Lkotlin/Metadata"],
}

ANTI_ANALYSIS_HINTS = {
    "anti-frida": ["frida-server", "frida-agent", "gum-js-loop", "linjector",
                   "/proc/self/maps frida", "27042"],
    "anti-xposed": ["de.robv.android.xposed", "XposedBridge"],
    "anti-magisk": ["magisk", "/sbin/.magisk", "zygisk"],
    "emulator-detect": ["goldfish", "ranchu", "genymotion", "qemu.hw.mainkeys",
                        "init.svc.qemu-props"],
    "root-detect": ["/system/bin/su", "/system/xbin/su", "Superuser.apk",
                    "eu.chainfire", "com.topjohnwu.magisk"],
}


def _detect(txt, native_libs):
    """Match signatures against text corpus and native library names."""
    libs = " ".join(native_libs or [])
    corpus = txt + "\n" + libs

    found_packers = {}
    for name, (cat, markers) in PACKERS.items():
        hits = sorted({m for m in markers if m.lower() in corpus.lower()})
        if hits:
            found_packers[name] = {"category": cat, "evidence": hits[:5]}

    compilers = sorted(name for name, marks in COMPILERS.items()
                       if any(m in txt for m in marks))

    anti = {}
    low = corpus.lower()
    for fam, markers in ANTI_ANALYSIS_HINTS.items():
        hits = sorted({m for m in markers if m.lower() in low})
        if hits:
            anti[fam] = {"evidence": hits[:4], "count": len(hits)}

    obfuscation = []
    if re.search(r"\bclass [a-z]\b", txt) or re.search(r"L[a-z]{1,3}/[a-z]{1,3}/[a-z]", txt):
        obfuscation.append("identifier renaming (single-letter classes)")
    if "SourceFile" in txt and re.search(r"\b[a-z]\.java\b", txt):
        obfuscation.append("stripped debug info")
    return found_packers, compilers, anti, obfuscation


def _signing_weaknesses(cert_info, manifest=None):
    """From legacy cert analysis: flag v1-only schemes (Janus, CVE-2017-13156)."""
    out = []
    schemes = []
    raw = str(cert_info or {})
    for s in ("v1", "v2", "v3"):
        if f"'{s}" in raw or f'"{s}' in raw or f"{s}:" in raw:
            schemes.append(s)
    if not schemes:
        schemes = None
    if schemes and "v2" not in schemes and "v3" not in schemes:
        out.append({
            "severity": "HIGH",
            "title": "Signed with v1 scheme only (Janus exposure)",
            "detail": "APK Signature Scheme v2/v3 missing -> vulnerable to "
                      "Janus artifact injection on Android 5.0-8.0 "
                      "(CVE-2017-13156). Re-sign with apksigner (--v2/--v3).",
            "masvs": "MASVS-RESILIENCE-3",
            "cve": "CVE-2017-13156",
        })
    return out


def analyze_hardening(txt, native_libs=None, cert_info=None, arch=None):
    packers, compilers, anti, obfuscation = _detect(txt, native_libs)

    findings = []
    for name, info in packers.items():
        sev = "INFO" if info["category"] == "compiler" else \
              ("LOW" if info["category"] == "obfuscator" else "MEDIUM")
        findings.append({
            "severity": sev,
            "title": f'{info["category"].title()} detected: {name}',
            "evidence": info["evidence"],
            "note": ("Packers complicate decompilation and often hide "
                     "malicious behavior; unpack before deep review."
                     if info["category"] == "packer" else None),
        })
    for fam, info in anti.items():
        findings.append({
            "severity": "INFO",
            "title": f"Anti-analysis family present: {fam}",
            "evidence": info["evidence"],
        })

    findings.extend(_signing_weaknesses(cert_info))

    sev_rank = {k: i for i, k in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    return {
        "module": "hardening-fingerprint",
        "packers_protectors": {k: v for k, v in packers.items()},
        "compilers": compilers,
        "anti_analysis": anti,
        "obfuscation": obfuscation,
        "findings": findings,
        "summary": {
            "packed": bool(packers),
            "obfuscated": bool(obfuscation) or any(
                p["category"] == "obfuscator" for p in packers.values()),
            "protected": bool(packers),
        },
    }


def cmd_hardening(apk_path: str, analyzer=None, json_out=False):
    """CLI handler: nightowl hardening <apk>"""
    from . import core as nw
    az = analyzer
    if az is None:
        az = nw.NightOwlAnalyzer(apk_path)
        az.extract_strings()
        az.analyze_info()
        az.analyze_cert()
    rep = analyze_hardening(
        az.txt,
        az.d.get("info", {}).get("native_libs"),
        az.d.get("cert"),
    )
    if json_out:
        import json as _json
        print(_json.dumps(rep, indent=2, ensure_ascii=False))
        return rep

    print("\n=== Hardening & Anti-Analysis Fingerprint ===")
    s = rep["summary"]
    print(f"Packed: {'YES' if s['packed'] else 'no'} | "
          f"Obfuscated: {'YES' if s['obfuscated'] else 'no'} | "
          f"Compilers: {', '.join(rep['compilers']) or '-'}")
    for name, info in rep["packers_protectors"].items():
        print(f"  [{info['category']:10}] {name}: {', '.join(info['evidence'][:3])}")
    for fam, info in rep["anti_analysis"].items():
        print(f"  [anti      ] {fam}: {len(info['evidence'])} marker(s)")
    for f in rep["findings"]:
        if f["severity"] in ("HIGH", "CRITICAL"):
            print(f"  [{f['severity']}] {f['title']}")
            if f.get("detail"):
                print(f"           {f['detail']}")
    return rep
