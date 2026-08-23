# secretsrc.py -- NightOwl v8.1 Source-Tree Secret Scanner
#
# Runs the validation engine over the *decompiled source tree* with real
# file:line provenance and code context - the accuracy that binary-string
# scanning can never reach (context is actual code, not blob fragments).
#
# Proven patterns this catches that binary scans miss:
#   - keys assigned in code:  String API_KEY = "AIza...";
#   - config objects:         "api_key": "sk_live_..."
#   - Dart/JS bundles inside assets/www

import re
from pathlib import Path

from .validators import assess, RANK

PATTERN_SET = {
    # label: regex (group1 = value when present)
    "AWS Access Key": r"\b(AKIA[0-9A-Z]{16})\b",
    "GCP API Key": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
    "Stripe Live Key": r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
    "GitHub Token": r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
    "Slack Token": r"\b(xox[abprs]-[0-9a-zA-Z\-]{10,48})\b",
    "Telegram Bot Token": r'\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b',
    "SendGrid Key": r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
    "MongoDB URI": r"(mongodb(?:\+srv)?://[^\s\"'<>]{10,})",
    "PostgreSQL URI": r"(postgres(?:ql)?://[^\s\"'<>]{10,})",
    "Bearer Token": r"(?i)\bbearer\s+([a-zA-Z0-9_\-.]{20,})",
    "Password": r"""(?i)\bpassword\b\s*[:=]\s*["']([^"'<>{}$]{8,64})["']""",
    "API Key (assigned)": r"""(?i)\bapi[_\-]?key\b\s*[:=]\s*["']([A-Za-z0-9_\-]{16,80})["']""",
    "Secret Key (assigned)": r"""(?i)\bsecret[_\-]?key\b\s*[:=]\s*["']([A-Za-z0-9_/+=\-]{16,80})["']""",
    "Auth Token (assigned)": r"""(?i)\b(auth|access)[_\-]?token\b\s*[:=]\s*["']([A-Za-z0-9_\-.]{16,120})["']""",
    "RSA Private Key": r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    "Public Key Block": r"(-----BEGIN PUBLIC KEY-----)",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "kotlin-builtin"}
SKIP_SUFFIX = (".png", ".jpg", ".webp", ".gif", ".ttf", ".otf", ".woff",
               ".woff2", ".mp3", ".mp4", ".zip", ".so")
MAX_FILE_BYTES = 3_000_000

# file types worth scanning
SCAN_SUFFIX = (".java", ".kt", ".xml", ".json", ".js", ".ts", ".dart",
               ".properties", ".yml", ".yaml", ".txt", ".html", ".smali",
               ".env", ".cfg", ".ini", "")


def scan_source_secrets(src_dir, min_conf=55):
    src_dir = Path(src_dir)
    findings = []
    filtered_count = 0
    files_scanned = 0

    for jf in src_dir.rglob("*"):
        if not jf.is_file():
            continue
        if any(part in SKIP_DIRS for part in jf.parts):
            continue
        if jf.suffix.lower() in SKIP_SUFFIX:
            continue
        if jf.suffix.lower() not in SCAN_SUFFIX:
            continue
        try:
            if jf.stat().st_size > MAX_FILE_BYTES:
                continue
            text = jf.read_text(errors="ignore")
        except Exception:
            continue
        files_scanned += 1
        rel = str(jf.relative_to(src_dir))

        for label, pat in PATTERN_SET.items():
            for m in re.finditer(pat, text):
                val = (m.group(1) or m.group(0)).strip().strip("\"'")
                if len(val) < 8:
                    continue
                line_no = text[:m.start()].count("\n") + 1
                ctx = text[max(0, m.start() - 160):m.end() + 160]
                res = assess(label, val, ctx, base_risk="HIGH")

                entry = {
                    "site": f"{rel}:{line_no}",
                    "type": label,
                    "value": val,
                    "risk": res["adjusted_risk"],
                    "confidence": res["confidence"],
                    "verdict": res["verdict"],
                    "validation": res["reasons"],
                }
                if res["verdict"] == "FILTERED" or \
                        res["confidence"] < min_conf:
                    filtered_count += 1
                    continue
                findings.append(entry)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: (order.get(x["risk"], 9),
                                 -x["confidence"]))
    return {
        "module": "secrets-source-scan",
        "source_root": str(src_dir),
        "stats": {"files_scanned": files_scanned,
                  "reported": len(findings),
                  "filtered": filtered_count},
        "findings": findings[:200],
    }


if __name__ == "__main__":  # pragma: no cover
    pass
