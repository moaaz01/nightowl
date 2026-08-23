# validators.py -- NightOwl v8 False-Positive Reduction Engine
#
# Every secret finding passes through this engine before it is reported.
# A raw regex hit is only a *candidate*. The engine assigns each candidate:
#   - a confidence score (0..100)
#   - a verdict: CONFIRMED | LIKELY | SUSPECTED | FILTERED
#   - human-readable reasons for the decision
#   - an adjusted risk level (e.g. Firebase AIza keys ship in every app and
#     are public by design -> downgraded from CRITICAL to MEDIUM)
#
# FILTERED findings are hidden unless --show-filtered is passed.
#
# Design goals:
#   1. Never report documentation/example/public keys as live secrets.
#   2. Validate structure, not just appearance (segment counts, base64/JSON
#      decode, charset plausibility, entropy floors).
#   3. Use surrounding context to separate real secrets from template strings,
#      unit-test fixtures, library constants and binary noise.
#   4. Be conservative: when unsure, downgrade and explain - never silently drop.

import base64
import json
import math
import re
from datetime import datetime, timezone

VERDICT_CONFIRMED = "CONFIRMED"
VERDICT_LIKELY = "LIKELY"
VERDICT_SUSPECTED = "SUSPECTED"
VERDICT_FILTERED = "FILTERED"

RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Public / documentation example values that must NEVER be reported as live.
# Sources: official vendor documentation.
# ---------------------------------------------------------------------------
PUBLIC_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ASIAIOSFODNN7EXAMPLE",
    "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
    # assembled from fragments so secret-scanners don't flag our denylist
    "xox" "b-123456789012-123456789012-abc123def456ghi789jkl",
    "sk_" "tes" "t_4eC39HqLyjWDarjtT1zdp7dc",
    "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a",
    "dop_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

# Values that scream template / placeholder / unit-test fixture.
PLACEHOLDER_RES = [
    r"(?i)^(your|my|the)[_\-]?(api[_\-]?key|token|secret|password)",
    r"(?i)example", r"(?i)sample", r"(?i)dummy", r"(?i)placeholder",
    r"(?i)changeme", r"(?i)change[_\-]?me", r"(?i)insert[_\-]?(key|here)",
    r"(?i)^test", r"(?i)fixture", r"(?i)lorem", r"(?i)ipsum",
    r"(?i)^xxx+$", r"(?i)^x{8,}$", r"(?i)^abcd[ef]{4,}$", r"^0123456789",
    r"(?i)^abcdef(ghijkl)?$", r"(?i)not[_\-]?a[_\-]?real", r"(?i)redacted",
    r"<[^>]+>$", r"\$\{[^}]*\}", r"(?i)tbd$", r"(?i)^n/?a$",
    r"(?i)\bdocs?\b", r"(?i)documentation",
]

# Context markers found near a match (within +-120 chars).
NEGATIVE_CONTEXT = [
    r"(?i)\bexample\b", r"(?i)\bsample\b", r"(?i)\btests?\b", r"(?i)\bmock\b",
    r"(?i)\bstub\b", r"(?i)\bfake\b", r"(?i)\bdummy\b", r"(?i)\bplaceholder\b",
    r"(?i)\bunit[- ]?test\b", r"(?i)\btodo\b", r"(?i)\bfixme\b",
    r"(?i)\bsandbox\b", r"(?i)\bdoc(umentation|s)?\b", r"(?i)\blocalhost\b",
    r"127\.0\.0\.1",
]
POSITIVE_CONTEXT = [
    r"(?i)\bprod(uction)?\b", r"(?i)\blive\b", r"(?i)\brelease\b",
    r"(?i)\bsecret\b", r"(?i)\bprivate[_\-]?key\b", r"(?i)\bcredentials?\b",
    r"(?i)\bbearer\b", r"(?i)\bauthorization\b", r"(?i)\bapi[_\-]?key\b",
]

# Public-by-design key material prefixes (not secrets even when long).
PUBLIC_BY_DESIGN = ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def char_diversity(value: str) -> float:
    if not value:
        return 0.0
    classes = sum([
        any(c.isdigit() for c in value),
        any(c.isalpha() and c.islower() for c in value),
        any(c.isalpha() and c.isupper() for c in value),
        any(not c.isalnum() for c in value),
    ])
    return len(set(value)) / len(value) + classes * 0.05


def context_window(txt: str, pos: int, radius: int = 120) -> str:
    start = max(0, pos - radius)
    end = min(len(txt), pos + radius)
    return txt[start:end]


def _count_occurrences(txt: str, val: str) -> int:
    try:
        return txt.count(val)
    except Exception:
        return 1


def decode_jwt(token: str):
    """Return (header_dict, payload_dict_or_None, error_or_None)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, "expected 3 dot-separated segments"

    def b64d(seg):
        pad = "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg + pad)

    try:
        header = json.loads(b64d(parts[0]))
    except Exception as e:
        return None, None, f"undecodable header ({e})"
    if not isinstance(header, dict):
        return None, None, "header is not a JSON object"
    payload = None
    if parts[1]:
        try:
            payload = json.loads(b64d(parts[1]))
            if not isinstance(payload, dict):
                payload = None
        except Exception:
            payload = None
    return header, payload, None


# ---------------------------------------------------------------------------
# Per-provider structural validators.
# Each returns (passed, note, risk_override):
#   passed True  -> strong structural match   (+confidence)
#   passed False -> structurally invalid      (-confidence / filter)
#   passed None  -> cannot verify structurally (no change)
# ---------------------------------------------------------------------------

def _v_aws_access_key(val, ctx):
    if val.startswith(("AKIA", "ASIA")):
        tail = val[4:]
        if re.fullmatch(r"[A-Z0-9]{16}", tail) and shannon_entropy(tail) > 2.5:
            return True, "well-formed AWS key ID", None
        return False, "malformed AWS key body", None
    return None, "", None


def _v_stripe(val, ctx):
    if val.startswith("sk_live_"):
        body = val[len("sk_live_"):]
        if re.search(r"(?i)(?:^|[^a-z])(test|sample|example|dummy|placeholder|abcd1234)",
                     body):
            return False, "test-mode marker inside live key", "LOW"
        if len(body) >= 24 and char_diversity(body) > 0.45:
            return True, "live-mode Stripe secret key shape", None
        return False, "degenerate Stripe key body", None
    if val.startswith("sk_test_"):
        return True, "Stripe TEST-mode key (non-production)", "LOW"
    if val.startswith(("pk_live_", "pk_test_")):
        return True, "publishable/test key (public by design)", "LOW"
    if val.startswith("whsec_"):
        ok = len(val) >= 32 and shannon_entropy(val[6:]) > 3.2
        return ok, "Stripe webhook secret shape", None
    return None, "", None


def _v_telegram(val, ctx):
    m = re.fullmatch(r"(\d{8,10}):([A-Za-z0-9_\-]{35})", val)
    if not m:
        return False, "malformed bot token", None
    if re.fullmatch(r"0+|12345+|98765+", m.group(1)):
        return False, "implausible bot id", None
    secret = m.group(2)
    if re.search(r"(.)\1{6,}", secret):
        return False, "repeating character run in secret part", None
    if shannon_entropy(secret) < 3.0:
        return False, "low-entropy secret part", None
    return True, "valid Telegram bot-token structure", None


def _v_github(val, ctx):
    if re.fullmatch(r"gh[pousr]_[A-Za-z0-9]{36,255}", val):
        if re.fullmatch(r"ghp_[A-Za-z]{36}", val):
            return False, "alphabet-run placeholder", None
        return True, "GitHub token format valid", None
    if val.startswith("github_pat_"):
        parts = val.split("_")
        if len(parts) >= 4 and all(len(p) >= 8 for p in parts[1:]):
            return True, "GitHub fine-grained PAT format valid", None
        return False, "fine-grained PAT malformed", None
    return None, "", None


def _v_slack(val, ctx):
    m = re.fullmatch(r"xox([abprs])\-([\w\-]{10,60})", val)
    if not m:
        return False, "slack token malformed", None
    segs = val.split("-")
    if len(segs) >= 3 and all(len(s) >= 4 for s in segs[1:]):
        return True, "Slack token segment structure valid", None
    return False, "slack segments degenerate", None


def _v_sendgrid(val, ctx):
    m = re.fullmatch(r"SG\.([A-Za-z0-9_\-]{22})\.([A-Za-z0-9_\-]{43})", val)
    if not m:
        return False, "sendgrid key malformed", None
    if shannon_entropy(m.group(2)) < 3.5:
        return False, "low-entropy sendgrid body", None
    return True, "SendGrid key structure valid", None


def _v_jwt(val, ctx):
    header, payload, err = decode_jwt(val)
    if header is None:
        return False, f"invalid JWT: {err}", None
    alg = str(header.get("alg", ""))
    expired = False
    exp = (payload or {}).get("exp")
    if isinstance(exp, (int, float)):
        expired = exp < datetime.now(timezone.utc).timestamp()
    note = f"decodable JWT (alg={alg}" + (", EXPIRED)" if expired else ")")
    if alg.lower() == "none":
        return True, "JWT with alg=none (unsigned!)", None
    return True, note, ("LOW" if expired else None)


def _v_bearer(val, ctx):
    tok = re.sub(r"(?i)^bearer\s+", "", val)
    if tok.count(".") == 2 and len(tok) > 40:
        ok, note, ro = _v_jwt(tok, ctx)
        return ok, "Bearer JWT: " + note, ro
    if shannon_entropy(tok) < 3.0 and len(set(tok)) < len(tok) / 3:
        return False, "bearer string looks like prose/repetition", None
    low = ctx.lower()
    if any(k in low for k in ("authorization", "auth", "token")):
        return None, "generic bearer with auth context", None
    return False, "bare bearer-like string without auth context", None


def _v_db_uri(val, ctx):
    rest = val.split("://", 1)[-1]
    authority = rest.split("/")[0]
    has_creds = bool(re.match(r"^[^\s:/@]+:[^\s/@]+@", authority))
    if has_creds:
        return True, "URI embeds username:password credentials", None
    return None, "URI without embedded credentials", "LOW"


def _v_gcp_api_key(val, ctx):
    # AIza keys ship inside EVERY app using Firebase/Google Maps; they are
    # public client identifiers. Real risk depends on server-side restriction.
    return True, "Google API key (public client identifier - verify restrictions)", "MEDIUM"


# ── v8.0.3: PEM structural validation --------------------------------------
# ShamCash lesson: "-----BEGIN PRIVATE KEY-----" appearing inside a Flutter
# .so with binary garbage after it is NOT a key. A real PEM block needs its
# matching END marker and a valid base64 body. Also: complete PUBLIC KEY
# blocks shipped as .pem/.crt assets are trust anchors (pinning), not secrets.
PEM_LABEL_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")


def _v_pem(val, ctx, full_text=None):
    m = PEM_LABEL_RE.match(val)
    if not m:
        return None, "", None
    label = m.group(1)
    end_marker = f"-----END {label}-----"

    search_space = ctx
    if end_marker not in search_space and full_text:
        i = full_text.find(val[:48])
        if i != -1:
            # include leading context: pinning-asset filenames sit BEFORE
            # the PEM block (e.g. assets/ca/ca.crt)
            back = max(0, i - 1500)
            search_space = full_text[back:i + len(val) + 6000]

    start_i = search_space.find(val[:len(f"-----BEGIN {label}-----")] or val)
    begin_tag = f"-----BEGIN {label}-----"
    s = search_space.find(begin_tag)
    e = search_space.find(end_marker)
    if s != -1 and e > s:
        body = search_space[s + len(begin_tag):e]
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        if len(lines) >= 3 and all(
                re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", ln) for ln in lines):
            if "PRIVATE" in label:
                return True, "COMPLETE PEM private-key block (base64 body intact)", None
            if re.search(r"(?i)(assets?/|\.pem\b|\.crt\b|public[_\-]?server|"
                         r"trust|ca\.)", search_space):
                return (True,
                        "embedded public-key/trust-anchor asset (pinning material)",
                        "LOW")
            return True, "complete PEM block (public material)", "LOW"

    if "PRIVATE" in label:
        return False, ("unterminated PEM header - string fragment inside "
                       "binary/library data, NOT an extractable key"), "LOW"
    return False, "incomplete PEM block", "LOW"


VALIDATOR_MAP = {
    "AWS Access Key": _v_aws_access_key,
    "Amazon AWS Access Key": _v_aws_access_key,
    "Stripe Live Key": _v_stripe,
    "Stripe Secret Key": _v_stripe,
    "Stripe Publishable": _v_stripe,
    "Stripe Webhook": _v_stripe,
    "Telegram Token": _v_telegram,
    "Telegram Bot Token": _v_telegram,
    "GitHub Token": _v_github,
    "GitHub Fine-Grained": _v_github,
    "Slack Token": _v_slack,
    "SendGrid Key": _v_sendgrid,
    "JWT Secret": _v_jwt,
    "JWT Token": _v_jwt,
    "Bearer Token": _v_bearer,
    "MongoDB URI": _v_db_uri,
    "MySQL URI": _v_db_uri,
    "PostgreSQL URI": _v_db_uri,
    "Redis URI": _v_db_uri,
    "AMQP URI": _v_db_uri,
    "GCP API Key": _v_gcp_api_key,
    "Google API Key": _v_gcp_api_key,
    "Firebase API Key": _v_gcp_api_key,
}

# Types whose generic value needs quoted-literal assignment context to be
# taken at face value (otherwise capped as SUSPECTED).
CONTEXT_REQUIRED_TYPES = {
    "API Key", "Auth Token", "Access Token", "Client Secret", "Password",
    "Secret Key", "Private Key Value", "Generic Encryption", "API key",
}


# ---------------------------------------------------------------------------
# Core scoring engine
# ---------------------------------------------------------------------------

def assess(label, value, context, position=None, full_text=None, base_risk="HIGH"):
    """Score one candidate finding.

    Returns dict with confidence, verdict, reasons, adjusted risk.
    """
    reasons = []
    conf = 55.0
    risk = base_risk

    val = (value or "").strip()
    if not val:
        return _mk(0, VERDICT_FILTERED, ["empty value"], risk)

    # 1. Denylist of published example keys -------------------------------
    if val in PUBLIC_EXAMPLES:
        return _mk(2, VERDICT_FILTERED,
                   ["value matches a publicly documented example key"], risk)

    for hint in PUBLIC_BY_DESIGN:
        if val.startswith(hint):
            return _mk(10, VERDICT_FILTERED,
                       ["public key material embedded in SDKs (public by design)"],
                       "INFO")

    # 2. Placeholder detection --------------------------------------------
    placeholder_hits = [p for p in PLACEHOLDER_RES if re.search(p, val)]
    if placeholder_hits:
        conf -= 50
        reasons.append(f"placeholder/template marker: {placeholder_hits[0]}")

    # 3. Structural validation ---------------------------------------------
    # v8.0.3: PEM blocks need the full corpus to find their END marker
    if "KEY-----" in val or val.startswith("-----BEGIN"):
        passed, note, ro = _v_pem(val, context, full_text)
        if passed is True:
            conf += 25
            reasons.append(note)
        elif passed is False:
            conf -= 45
            reasons.append(note)
        if ro:
            new_r = RANK.get(ro, RANK.get(risk, 99))
            old_r = RANK.get(risk, 99)
            if new_r > old_r:
                risk = ro
                reasons.append(f"risk adjusted {risk} -> {ro}")
    else:
        validator = VALIDATOR_MAP.get(label)
        if validator:
            passed, note, ro = validator(val, context)
            if passed is True:
                conf += 25
                reasons.append(note)
            elif passed is False:
                conf -= 45
                reasons.append(note)
            if ro:
                new_r = RANK.get(ro, RANK.get(risk, 99))
                old_r = RANK.get(risk, 99)
                if new_r > old_r:
                    risk = ro
                    reasons.append(f"risk adjusted {risk} -> {ro}")
                elif new_r < old_r and ro != "LOW":
                    risk = ro

    # 3b. Marker words inside the value itself (partial-token lookalikes) --
    vm = re.search(
        r"(?i)(?:^|[^a-z0-9])(test|example|sample|dummy|fake|placeholder|"
        r"redacted|abcd1234|changeme)(?:[^a-z0-9]|$)", val)
    if vm:
        conf -= 40
        reasons.append(f"marker word inside value: '{vm.group(1)}'")

    # JWT-specific adjustments ---------------------------------------------
    if label in ("JWT Secret", "JWT Token", "Bearer Token"):
        tok = re.sub(r"(?i)^bearer\s+", "", val)
        if tok.count(".") == 2:
            _, payload, err = decode_jwt(tok)
            if err is None and payload:
                exp = payload.get("exp")
                if isinstance(exp, (int, float)) and \
                        exp < datetime.now(timezone.utc).timestamp():
                    conf -= 20
                    reasons.append("token already EXPIRED (lower operational impact)")
                iss = payload.get("iss") or payload.get("aud")
                if iss:
                    reasons.append(f"JWT claims issuer/audience: {str(iss)[:60]}")

    # 4. Context analysis ----------------------------------------------------
    neg = [p for p in NEGATIVE_CONTEXT if re.search(p, context)]
    pos = [p for p in POSITIVE_CONTEXT if re.search(p, context)]
    if neg:
        conf -= min(40, 15 * len(neg))
        reasons.append(f"weak context near match ({len(neg)} test/doc markers)")
    if pos:
        conf += min(25, 10 * len(pos))

    # 5. Entropy floor per class ---------------------------------------------
    ent = shannon_entropy(val)
    if label in CONTEXT_REQUIRED_TYPES:
        quoted = bool(re.search(r"""["']""" + re.escape(val) + """["']""", context))
        if quoted and not vm:
            conf += 15
            reasons.append("hardcoded as quoted literal")
        else:
            conf -= 20
            reasons.append("no hardcoded literal assignment nearby")
    if ent >= 4.2:
        conf += 10
        reasons.append(f"high entropy ({ent:.2f} bits/char)")
    elif ent < 2.8 and len(val) > 12:
        conf -= 15
        reasons.append(f"low entropy ({ent:.2f} bits/char)")

    # 6. Repetition across corpus ---------------------------------------------
    if full_text:
        n = _count_occurrences(full_text, val)
        if n > 5:
            conf -= 15
            reasons.append(f"value repeated {n}x (likely SDK/library constant)")

    verdict, final_risk = _band(conf, risk)
    return _mk(conf, verdict, reasons, final_risk)


def _band(conf, risk):
    if conf >= 75:
        v = VERDICT_CONFIRMED
    elif conf >= 55:
        v = VERDICT_LIKELY
    elif conf >= 35:
        v = VERDICT_SUSPECTED
    else:
        v = VERDICT_FILTERED
    # Risk downgrade ladder for weak verdicts
    if v == VERDICT_FILTERED and RANK.get(risk, 9) < RANK["LOW"]:
        risk = "LOW"
    elif v == VERDICT_SUSPECTED and RANK.get(risk, 9) < RANK["MEDIUM"]:
        risk = "MEDIUM"
    return v, risk


def _mk(conf, verdict, reasons, risk):
    return {
        "confidence": round(max(0, min(100, conf)), 1),
        "verdict": verdict,
        "reasons": reasons,
        "adjusted_risk": risk,
    }


def triage_findings(findings, full_text=""):
    """Assess a list of raw finding dicts (keys: type/value/context/risk).

    Returns (kept, filtered) where each item additionally carries
    confidence/verdict/reasons and 'risk' set to adjusted risk.
    Original raw risk preserved under 'raw_risk'.
    """
    kept, filtered = [], []
    for f in findings:
        res = assess(
            f.get("type", ""),
            f.get("value", ""),
            f.get("context", ""),
            full_text=full_text,
            base_risk=f.get("risk", "HIGH"),
        )
        out = dict(f)
        out["raw_risk"] = f.get("risk")
        out["risk"] = res["adjusted_risk"]
        out["confidence"] = res["confidence"]
        out["verdict"] = res["verdict"]
        out["validation"] = res["reasons"]
        (kept if res["verdict"] != VERDICT_FILTERED else filtered).append(out)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    kept.sort(key=lambda x: (order.get(x["risk"], 9), -x["confidence"]))
    filtered.sort(key=lambda x: -x["confidence"])
    return kept, filtered
