# authmap.py -- NightOwl v8 Authentication Flow Mapper & API Access-Point Capture
#
# Extracts the *authentication architecture* of an app straight from its
# binary/decompiled source:
#
#   1. Login / register / token / refresh / logout endpoints (with HTTP method
#      hints from Retrofit annotations and OkHttp call sites).
#   2. Credential parameter names the app transmits (username/email/password/
#      otp/pin) and grant types (password, refresh_token, authorization_code).
#   3. Token lifecycle: where tokens are stored (SharedPreferences vs
#      EncryptedSharedPreferences/KeyStore), how they are attached to requests
#      (Authorization header, custom headers, cookies), JWT handling.
#   4. Weaknesses: cleartext login transport, token-in-URL, Basic auth,
#      client-side-only session checks, missing pinning next to auth endpoints,
#      hardcoded client secrets in OAuth flows.
#
# Output is a structured "auth map" designed for both humans and AI agents.

import json
import re

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

AUTH_ENDPOINT_RES = [
    r"(?i)[a-z0-9_./:-]{0,60}/(api/v?\d*/)?(auth|login|log[-_]?in|signin|sign[-_]?in|register|signup|sign[-_]?up)(/[a-z0-9_./-]{0,40})?",
    r"(?i)[a-z0-9_./:-]{0,60}/(oauth2?|token|session|jwt|refresh[-_]token|logout|otp|verify[-_]?code|two[-_]?factor|mfa)(/[a-z0-9_./-]{0,40})?",
]

RETROFIT_ANNOTATION = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)["\']', re.I)

CREDENTIAL_FIELDS = [
    "username", "user_name", "email", "phone", "msisdn", "password", "passwd",
    "pass", "pin", "otp", "one_time_password", "verification_code",
    "refresh_token", "grant_type", "client_id", "client_secret", "device_id",
    "fcm_token", "id_token", "access_token", "code_verifier", "nonce",
]

GRANT_TYPES = ["password", "client_credentials", "authorization_code",
               "refresh_token", "otp", "sms"]

TOKEN_STORAGE_PATTERNS = [
    (r"(?i)EncryptedSharedPreferences", "EncryptedSharedPreferences (good)"),
    (r"(?i)AndroidKeyStore|KeyStore\.getInstance\(\s*\"AndroidKeyStore",
     "AndroidKeyStore-backed crypto (good)"),
    (r"(?i)getSharedPreferences\s*\([^)]*(token|auth|session)", 
     "Token stored in plain SharedPreferences"),
    (r"(?i)(putString|getString)\s*\(\s*\"(access_token|auth_token|jwt|bearer|id_token|refresh_token)\"",
     "Token persisted under a well-known key"),
    (r"(?i)CookieManager|CookieHandler", "Cookie-based sessions"),
]

HEADER_ATTACHMENT_PATTERNS = [
    (r"(?i)addHeader\s*\(\s*\"Authorization\"\s*,", "Authorization header attach"),
    (r"(?i)header\s*\(\s*[\"']Authorization[\"']", "Authorization header (Ktor/other)"),
    (r"(?i)Bearer\s*\+\s*\w+|\"Bearer \"", "Bearer scheme usage"),
    (r"(?i)addInterceptor\s*\(", "OkHttp interceptor chain (token injection site)"),
    (r"(?i)X-[A-Za-z]+-(Token|Auth|Session)|x-auth-token|x-access-token",
     "Custom auth header family"),
]

PINNING_PATTERNS = [
    r"CertificatePinner", r"pin-set", r"sha256/[A-Za-z0-9+/=]{20,}",
    r"network_security_config.*pin", r"TrustKit", r"sslSocketFactory\s*\(",
]

BASIC_AUTH_RE = re.compile(r"(?i)Credentials\.basic|Basic\s+[A-Za-z0-9+/=]{12,}")
TOKEN_IN_URL_RE = re.compile(r"""[?&](access_token|token|auth|session_id|jwt)=""")
CLEARTEXT_AUTH_RE = re.compile(
    r"http://[^\s\"']{0,120}(login|auth|token|session|signin|oauth)[^\s\"']{0,80}", re.I)

# v8.0.1: noise filters — real-world APKs are full of strings that merely
# *contain* auth/login segments without being endpoints.
DEX_DESCRIPTOR_RE = re.compile(r"^L[a-z][a-z0-9_]*(?:/[A-Za-z0-9_$]+)+;?$")
# DEX type references with junk prefixes: "...$rLandroid/support/v4/..."
DEX_TYPE_ANYWHERE_RE = re.compile(
    r"L(?:android|java|javax|kotlin|com|org|io|net|me|de|uk|cz|hu)"
    r"(?:/[A-Za-z0-9_$]+)+")
FS_PATH_RE = re.compile(
    r"^(?:/(?:usr|opt|system|proc|etc|var|home|Users|data|dev|sbin|bin|lib"
    r"|private|Applications)|[A-Za-z]:\\\\)")
STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|webp|gif|svg|ttf|otf|woff2?|dex|so|zip|mp3|mp4|wav)$",
    re.I)
RESOURCE_ROOT_RE = re.compile(r"^(?:assets?|res|mipmap|drawable|raw|values)/",
                              re.I)
FRAMEWORK_NS_RE = re.compile(
    r"(?:^|/)(?:android|javax?|kotlin|support|v4|x500|hostedtoolcache)"
    r"(?:/|$)", re.I)
# Long CamelCase segments are class names, not REST routes
# (e.g. MediaControllerCompat, GoogleSignInAccount).
CAMELCASE_SEG_RE = re.compile(r"[A-Z][a-z]+(?:[A-Z][a-z]+){2,}[A-Za-z0-9]*")


def _is_endpoint_noise(raw: str) -> str:
    """Return a rejection reason, or '' when the candidate looks real."""
    if DEX_DESCRIPTOR_RE.match(raw):
        return "dex class descriptor"
    if DEX_TYPE_ANYWHERE_RE.search(raw):
        return "dex type reference"
    if FS_PATH_RE.match(raw):
        return "filesystem path"
    if STATIC_EXT_RE.search(raw):
        return "static asset extension"
    if RESOURCE_ROOT_RE.match(raw):
        return "app resource path"
    if FRAMEWORK_NS_RE.search(raw) and CAMELCASE_SEG_RE.search(raw):
        return "framework namespace + class segment"
    segments = re.split(r"[/?#=]", raw)
    for seg in segments:
        if len(seg) >= 14 and CAMELCASE_SEG_RE.fullmatch(seg):
            return "camelcase class segment"
    # single segment like "/Auth" or "/login" with no host/query is usually a
    # class-name fragment; require >= 2 path segments for bare relative paths
    stripped = raw.strip("/")
    if not raw.startswith(("http://", "https://")):
        parts = [s for s in stripped.split("/") if s]
        if len(parts) < 2:
            return "single-segment relative path"
    return ""


def _dedupe(seq):
    out, seen = [], set()
    for x in seq:
        k = x if isinstance(x, str) else json.dumps(x, sort_keys=True)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def extract_access_points(txt, base_urls=None):
    """Capture every API access point reachable from app -> server."""
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>\\)]{8,200}", txt)))
    paths = []
    for m in RETROFIT_ANNOTATION.finditer(txt):
        paths.append({"method": m.group(1).upper(), "path": m.group(2)})
    for pat in AUTH_ENDPOINT_RES:
        for m in re.finditer(pat, txt):
            v = m.group(0).strip().strip('"\'')
            if len(v) > 4:
                paths.append({"method": None, "path": v})
    return {
        "absolute_urls": urls[:400],
        "annotated_calls": _dedupe(paths)[:300],
        "count_urls": len(urls),
        "count_paths": len(paths),
    }


def map_authentication(txt):
    """Build the full authentication map from a text corpus."""
    flows = []
    weaknesses = []

    # ── 1. Auth endpoints + methods ────────────────────────────────────────
    annotated = {}
    for m in RETROFIT_ANNOTATION.finditer(txt):
        path = m.group(2)
        annotated[path] = m.group(1).upper()

    for pat in AUTH_ENDPOINT_RES:
        for m in re.finditer(pat, txt):
            raw = m.group(0).strip().strip('"\'')
            if len(raw) < 5:
                continue
            if raw.startswith("http") and "w3.org" in raw:
                continue
            noise = _is_endpoint_noise(raw)
            if noise:
                continue
            ctx = txt[max(0, m.start()-150):m.end()+150]
            kind = ("login" if re.search(r"(?i)login|signin|sign_in|session", raw)
                    else "registration" if re.search(r"(?i)register|signup|sign_up", raw)
                    else "token" if re.search(r"(?i)token|jwt|oauth|refresh", raw)
                    else "mfa" if re.search(r"(?i)otp|mfa|two.factor|verify", raw)
                    else "logout" if re.search(r"(?i)logout|revoke", raw)
                    else "unknown")
            method = annotated.get(raw) or (
                "POST" if kind in ("login", "registration", "token") else None)
            params = [c for c in CREDENTIAL_FIELDS
                      if re.search(r"[\"'\s]" + c + r"[\"'\s:=]", ctx)]
            grants = [g for g in GRANT_TYPES
                      if re.search(r"[\"']" + g + r"[\"']", ctx)]
            flow = {
                "type": kind,
                "endpoint": raw[:160],
                "http_method": method,
                "credential_params": params[:10],
                "grant_types": grants,
                "transport": "https" if "https" in raw.split(":")[0] else (
                    "http" if raw.startswith("http://") else "unknown"),
            }
            flows.append(flow)

    # v8.0.1: annotated Retrofit calls are authoritative — keep them even if
    # a generic filter would reject the path shape.
    for path, method in annotated.items():
        if not any(f["endpoint"] == path for f in flows):
            kind = ("login" if re.search(r"(?i)login|signin|session", path)
                    else "registration" if re.search(r"(?i)register|signup", path)
                    else "token" if re.search(r"(?i)token|jwt|oauth|refresh", path)
                    else "mfa" if re.search(r"(?i)otp|mfa|verify", path)
                    else "unknown")
            ctx_match = re.search(re.escape(path), txt)
            ctx = txt[max(0, ctx_match.start()-150):ctx_match.end()+150] \
                if ctx_match else ""
            params = [c for c in CREDENTIAL_FIELDS
                      if re.search(r"[\"'\s]" + c + r"[\"'\s:=]", ctx)]
            flows.append({
                "type": kind,
                "endpoint": path[:160],
                "http_method": method,
                "credential_params": params[:10],
                "grant_types": [],
                "transport": "unknown",
            })

    flows = _dedupe(flows)[:60]

    # ── 2. Token lifecycle ────────────────────────────────────────────────
    storage = []
    for pat, desc in TOKEN_STORAGE_PATTERNS:
        if re.search(pat, txt):
            storage.append(desc)
    attachment = []
    for pat, desc in HEADER_ATTACHMENT_PATTERNS:
        if re.search(pat, txt):
            attachment.append(desc)

    jwt_sites = []
    for m in re.finditer(r"(?i)(decode|parse|verify)[A-Za-z]*\(\s*\"?(eyJ[A-Za-z0-9_\-]+)", txt):
        jwt_sites.append(m.group(1))
    jwt_usage = bool(jwt_sites) or "Bearer scheme usage" in attachment

    lifecycle = {
        "storage": storage,
        "request_attachment": attachment,
        "jwt_handling_detected": jwt_usage,
        "encrypted_storage_used": any("good)" in s for s in storage),
    }

    # ── 3. Weakness detection ─────────────────────────────────────────────
    for f in flows:
        ep, tr = f["endpoint"], f["transport"]
        if tr == "http":
            weaknesses.append({
                "severity": "CRITICAL",
                "title": "Authentication over cleartext HTTP",
                "detail": f"Credential endpoint travels unencrypted: {ep}",
                "masvs": "MASVS-NETWORK-1",
            })
    if TOKEN_IN_URL_RE.search(txt):
        weaknesses.append({
            "severity": "HIGH",
            "title": "Token passed in URL query string",
            "detail": "Tokens in URLs leak via logs, referrers and proxies.",
            "masvs": "MASVS-AUTH-1",
        })
    if BASIC_AUTH_RE.search(txt):
        weaknesses.append({
            "severity": "MEDIUM",
            "title": "HTTP Basic authentication in use",
            "detail": "Base64 Basic credentials are trivially decoded; "
                      "combined with weak TLS this exposes passwords.",
            "masvs": "MASVS-AUTH-1",
        })
    plain_sp = [s for s in storage if "plain SharedPreferences" in s]
    if plain_sp and not any("good)" in s for s in storage):
        weaknesses.append({
            "severity": "HIGH",
            "title": "Auth tokens stored unencrypted on device",
            "detail": "Tokens readable by backup extraction or on rooted devices.",
            "masvs": "MASVS-STORAGE-1",
        })
    has_auth_flow = bool(flows)
    pinned = any(re.search(p, txt) for p in PINNING_PATTERNS)
    if has_auth_flow and not pinned:
        weaknesses.append({
            "severity": "MEDIUM",
            "title": "No certificate pinning protecting auth traffic",
            "detail": "MITM of login/token exchange is possible after a "
                      "user-installed CA (or bypassed pinning elsewhere).",
            "masvs": "MASVS-NETWORK-2",
        })

    # Hardcoded OAuth client secret inside an authorization flow?
    if re.search(r"(?i)client_secret\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", txt):
        weaknesses.append({
            "severity": "HIGH",
            "title": "OAuth client_secret embedded in client",
            "detail": "Public clients must not hold secrets; extractable from APK.",
            "masvs": "MASVS-AUTH-3",
        })

    weaknesses.sort(key=lambda w: SEV_ORDER.get(w["severity"], 9))

    return {
        "module": "authentication-map",
        "flows": flows,
        "token_lifecycle": lifecycle,
        "certificate_pinning": pinned,
        "weaknesses": weaknesses,
        "summary": {
            "login_endpoints": sum(1 for f in flows if f["type"] == "login"),
            "token_endpoints": sum(1 for f in flows if f["type"] == "token"),
            "mfa_endpoints": sum(1 for f in flows if f["type"] == "mfa"),
        },
    }


def cmd_authmap(apk_path: str, analyzer=None, json_out=False):
    """CLI handler: nightowl authmap <apk>"""
    from . import core as nw
    az = analyzer
    if az is None:
        az = nw.NightOwlAnalyzer(apk_path)
        az.extract_strings()
        az.analyze_endpoints()
    access = extract_access_points(az.txt, az.d.get("endpoints", {}).get("urls"))
    amap = map_authentication(az.txt)
    amap["access_points"] = access

    if json_out:
        print(json.dumps(amap, indent=2, ensure_ascii=False))
        return amap

    RICH = getattr(nw, "RICH", False)
    con = getattr(nw, "con", None)
    lines = ["", "=== Authentication Map ==="]
    s = amap["summary"]
    lines.append(f"Login endpoints : {s['login_endpoints']} | "
                 f"Token: {s['token_endpoints']} | MFA: {s['mfa_endpoints']}")
    lines.append(f"Pinning         : {'YES' if amap['certificate_pinning'] else 'not detected'}")
    lines.append(f"Token storage   : {'; '.join(amap['token_lifecycle']['storage']) or '-'}")
    lines.append("")
    lines.append("-- Flows --")
    for f in amap["flows"][:15]:
        m = f["http_method"] or "?"
        lines.append(f"  [{f['type']:>12}] {m:6} {f['endpoint']}")
        if f["credential_params"]:
            lines.append(f"                  params: {', '.join(f['credential_params'])}")
    lines.append("")
    lines.append("-- Weaknesses --")
    for w in amap["weaknesses"]:
        lines.append(f"  [{w['severity']:8}] {w['title']} ({w['masvs']})")
    text = "\n".join(lines)
    if RICH and con:
        con.print(text)
    else:
        print(text)
    return amap
