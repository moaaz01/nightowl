# cryptoscope.py -- NightOwl v8.1 Source-Aware Cryptographic Scope
#
# Runs over a jadx decompiled tree and answers the question binary strings
# never can: *who* uses weak crypto - the application or its libraries?
#
# ShamCash lesson: AES/ECB/NoPadding + AES-SIV hits were Google Tink
# internals (strong crypto), while the real issue lived in Dart
# (fast_rsa PKCS1v15). Provenance is everything.
#
# Output: findings with file:line evidence, classified as
#   APP CODE      - developer-authored package (not a known library)
#   LIBRARY       - known crypto/SDK namespace (Tink, BouncyCastle, Conscrypt)

import re
from pathlib import Path

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Namespace fragments identifying bundled libraries / generated code.
LIBRARY_NS = [
    "com/google/crypto/tink", "p199l2", "p274y2",          # tink obfuscated
    "org/bouncycastle", "org/spongycastle", "org/conscrypt",
    "com/google/android/gms", "androidx/", "android/support",
    "kotlin/", "kotlinx/", "io/grpc", "okhttp3/", "okio/",
    "com/google/firebase", "fluttersecurestorage",
]

CIPHER_SITES = re.compile(
    r'Cipher\.getInstance\(\s*"([^"]+)"')
KEYSPEC_RE = re.compile(
    r'new\s+SecretKeySpec\(\s*([^,()]+),\s*"([A-Za-z0-9]+)"\)')
IVSPEC_RE = re.compile(r"new\s+IvParameterSpec\(([^;]{0,80})\)")
STATIC_KEY_LIT = re.compile(
    r'"([A-Za-z0-9+/=]{16,44})"\s*\.getBytes\(\)|'
    r'Base64\.decode\(\s*"([A-Za-z0-9+/=]{16,44})"')

MODES = {
    "ECB": ("HIGH", "ECB mode - identical plaintext blocks leak patterns"),
    "CBC": ("LOW", "CBC without MAC - padding-oracle risk unless ETM"),
    "CTR": ("LOW", "CTR requires unique nonces per message"),
    "GCM": (None, "GCM AEAD - good"),
    "CTR/NoPadding": (None, None),
}


def _classify(path: str) -> str:
    p = path.replace("\\", "/")
    if any(ns in p for ns in LIBRARY_NS):
        return "LIBRARY"
    # jadx obfuscated short packages (p205m2 etc.) are usually libs too,
    # but we cannot prove it -> mark UNKNOWN so analysts look manually.
    if re.search(r"/sources/p\d+[a-zA-Z]\d*/", p):
        return "OBFUSCATED"
    return "APP CODE"


def scan_source_tree(src_dir: Path):
    """Yield (relpath, lineno, line, category) for interesting crypto sites."""
    java_files = list(Path(src_dir).rglob("*.java"))
    for jf in java_files:
        try:
            text = jf.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(jf.relative_to(src_dir))
        cat = _classify(rel)
        for m in CIPHER_SITES.finditer(text):
            ln = text[:m.start()].count("\n") + 1
            yield rel, ln, f"Cipher.getInstance(\"{m.group(1)}\")", cat, \
                m.group(1)
        for m in STATIC_KEY_LIT.finditer(text):
            ln = text[:m.start()].count("\n") + 1
            lit = m.group(1) or m.group(2)
            yield rel, ln, f"hardcoded key material getBytes/Base64({lit[:12]}...)", \
                cat, "HARDcoded-key"


def analyze_crypto_scope(src_dir):
    src_dir = Path(src_dir)
    if not src_dir.exists():
        return {"module": "cryptoscope", "error": "source dir not found",
                "findings": []}

    cipher_modes = {}
    rsa_padding = {}
    hardcoded_keys = []
    total_sites = 0

    for rel, ln, desc, cat, extra in scan_source_tree(src_dir):
        total_sites += 1
        if desc.startswith("Cipher.getInstance"):
            algo = extra.split("/")[0]
            mode = extra.split("/")[1] if "/" in extra else "?"
            pad = extra.split("/")[2] if extra.count("/") >= 2 else ""
            if algo == "RSA":
                # RSA has no block-chaining mode; "ECB" in JCE names is
                # vestigial. Audit the PADDING instead - that is where
                # Bleichenbacher lives.
                rsa_padding[pad or "None"] = \
                    rsa_padding.get(pad or "None", 0) + 1
                continue
            key = mode if mode != "?" else extra
            entry = cipher_modes.setdefault(key, {
                "count": 0, "padding": set(), "app_code": 0,
                "library": 0, "obfuscated": 0, "evidence": []})
            entry["count"] += 1
            entry["padding"].add(pad)
            bucket = {"APP CODE": "app_code", "LIBRARY": "library",
                      "OBFUSCATED": "obfuscated"}.get(cat, "library")
            entry[bucket] += 1
            site_tag = f"{rel}:{ln}"
            if len(entry["evidence"]) < 3 and site_tag not in entry["evidence"]:
                entry["evidence"].append(site_tag)
            if mode == "ECB" and cat == "APP CODE":
                entry.setdefault("app_ecb_sites", []).append(f"{rel}:{ln}")
        elif desc.startswith("hardcoded key material"):
            hardcoded_keys.append({"site": f"{rel}:{ln}",
                                   "category": cat,
                                   "preview": extra})

    findings = []
    for mode, meta in cipher_modes.items():
        if mode.upper() == "ECB":
            sev = "HIGH" if meta.get("app_code") else (
                "INFO" if meta.get("app_code") == 0 and
                (meta.get("library") or meta.get("obfuscated")) else "MEDIUM")
            findings.append({
                "severity": sev,
                "title": f"AES/{mode} usage ({meta['count']} site(s))",
                "detail": (
                    f"provenance: app_code={meta.get('app_code', 0)}, "
                    f"library={meta.get('library', 0)}, "
                    f"obfuscated={meta.get('obfuscated', 0)}. "
                    + ("Library-internal ECB (e.g. Tink keystore wrapping) "
                       "is not directly exploitable." if meta.get("app_code", 0) == 0
                       else "APPLICATION code uses ECB - pattern leakage.")),
                "evidence": meta["evidence"],
            })
        elif mode == "CBC":
            findings.append({
                "severity": "LOW",
                "title": f"AES/CBC usage ({meta['count']} site(s))",
                "detail": "Ensure HMAC/AEAD composition (Encrypt-then-MAC).",
                "evidence": meta["evidence"],
            })

    if hardcoded_keys:
        findings.append({
            "severity": "CRITICAL",
            "title": f"{len(hardcoded_keys)} hardcoded key-material "
                     f"literal(s) in source",
            "detail": "Key bytes embedded in code - extractable by design.",
            "evidence": [h["site"] + " [" + h["preview"] + "]"
                         for h in hardcoded_keys[:5]],
        })

    sev_rank = {k: i for i, k in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    if rsa_padding:
        pkcs1 = rsa_padding.get("PKCS1Padding", 0)
        oaep = sum(v for k, v in rsa_padding.items() if "OAEP" in k)
        if pkcs1:
            findings.append({
                "severity": "MEDIUM" if oaep else "HIGH",
                "title": f"RSA PKCS#1 v1.5 padding ({pkcs1} site(s))"
                         + (f" alongside OAEP ({oaep})" if oaep else
                            " with NO OAEP anywhere"),
                "detail": "Bleichenbacher-class risk profile; prefer "
                          "RSA-OAEP-256 for encryption.",
                "evidence": [f"padding={k}: {v}" for k, v in
                             sorted(rsa_padding.items())],
            })

    return {
        "module": "cryptoscope",
        "source_root": str(src_dir),
        "total_cipher_sites": total_sites,
        "rsa_padding": rsa_padding,
        "cipher_modes": {k: {**v, "padding": sorted(v["padding"])}
                         for k, v in cipher_modes.items()},
        "hardcoded_keys": hardcoded_keys,
        "findings": findings,
    }


def cmd_cryptoscope(apk_path: str, json_out=False):
    """CLI handler: nightowl cryptoscope <apk-or-jadx-dir>"""
    from . import core as nw
    p = Path(apk_path)
    if p.is_dir():
        src = p
    else:
        base = nw.DATA_DIR / "workspace" / "decompiled" / p.stem
        src = base / "jadx-src"
        if not src.exists():
            print("[!] No decompiled tree found. Run first:")
            print(f"    nightowl decompile {apk_path}")
            return {"error": "no source"}
    rep = analyze_crypto_scope(src)
    import json as _json
    if json_out:
        print(_json.dumps(rep, indent=2, ensure_ascii=False))
        return rep
    print("\n=== CryptoScope (source-aware) ===")
    print(f"cipher sites: {rep.get('total_cipher_sites')}")
    for mode, meta in (rep.get("cipher_modes") or {}).items():
        print(f"  {mode}: n={meta['count']} padding={'+'.join(meta['padding'])}"
              f" app={meta['app_code']} lib={meta['library']}"
              f" obf={meta['obfuscated']}")
    for f in rep.get("findings", []):
        print(f"  [{f['severity']:8}] {f['title']}")
        if f.get("detail"):
            print(f"             {f['detail']}")
        for e in (f.get("evidence") or [])[:3]:
            print(f"               · {e}")
    return rep


if __name__ == "__main__":  # pragma: no cover
    pass
