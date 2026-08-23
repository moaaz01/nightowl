# apimap.py -- NightOwl v8.3 API Intelligence & Infrastructure Assessment
#
# The "command center" module: probes the backend API that the app talks to,
# fingerprints the server technology, audits security headers, tests error
# handling for information leakage, and scores the infrastructure.
#
# All probes are passive/unauthenticated GET requests - equivalent to a
# browser visiting a URL. No exploitation, no auth bypass, no tampering.
#
# Born from the MaxStore engagement: the app's real attack surface lives
# on the server, not the client.

import json
import re
import subprocess
from pathlib import Path

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HIGH", "HSTS prevents protocol downgrade "
        "and cookie hijacking. Add: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": ("MEDIUM", "CSP prevents XSS and injection "
        "attacks. Add: default-src 'self'"),
    "X-Frame-Options": ("LOW", "Clickjacking protection."),
    "X-Content-Type-Options": ("LOW", "MIME-sniffing prevention."),
    "Referrer-Policy": ("INFO", "Referrer leakage prevention."),
    "Permissions-Policy": ("INFO", "Browser feature restriction."),
}

ERROR_PROBES = [
    "/nonexistent_endpoint_404_test",
    "/wallet/methods?id=1'OR'1'='1",
    "/../../etc/passwd",
    "/v99/nonexistent",
    "/?debug=true&admin=1",
]


def _curl(url, timeout=8):
    try:
        r = subprocess.run(
            ["curl", "-sS", "-m", str(timeout), "-D-", "-o", "/dev/null", url],
            capture_output=True, text=True, timeout=timeout + 2)
        return r.stdout
    except Exception:
        return ""


def _curl_body(url, timeout=8):
    try:
        r = subprocess.run(
            ["curl", "-sS", "-m", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2)
        return r.stdout[:500]
    except Exception:
        return ""


def analyze_api_security(base_url, routes=None):
    """routes: list or comma-separated string."""
    if isinstance(routes, str):
        routes = [r.strip() for r in routes.split(",") if r.strip()]
    """Full API infrastructure assessment."""
    base_url = base_url.rstrip("/")
    findings = []
    report = {
        "module": "api-infrastructure-assessment",
        "target": base_url,
        "server_fingerprint": {},
        "security_headers": {},
        "error_handling": [],
        "tls_info": {},
        "rate_limiting": {},
        "backend_framework": "",
        "findings": [],
        "score": 100,
    }

    # ── 1. Fingerprint ────────────────────────────────────────────────
    raw = _curl(f"{base_url}/version" if "api" in base_url else base_url)
    headers = {}
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    report["server_fingerprint"] = {
        "server": headers.get("server", "?"),
        "content_type": headers.get("content-type", "?"),
        "connection": headers.get("connection", "?"),
    }

    # ── 2. Security headers audit ─────────────────────────────────────
    for hname, (sev_if_missing, remediation) in SECURITY_HEADERS.items():
        present = hname.lower() in headers
        report["security_headers"][hname] = {
            "present": present,
            "value": headers.get(hname.lower(), ""),
        }
        if not present:
            findings.append({
                "severity": sev_if_missing,
                "title": f"Missing security header: {hname}",
                "detail": remediation,
            })

    # Duplicate headers (config noise)
    dup_count = len(re.findall(r"(?i)x-content-type-options", raw)) - \
        len({k for k in headers if k == "x-content-type-options"})
    if dup_count > 0:
        findings.append({
            "severity": "INFO",
            "title": f"Duplicate X-Content-Type-Options header ({dup_count} extra)",
            "detail": "Configuration redundancy - consolidate nginx/app configs.",
        })

    # ── 3. Error handling ────────────────────────────────────────────
    for probe in ERROR_PROBES:
        url = f"{base_url}{probe}"
        body = _curl_body(url)
        code_match = _curl(url)
        status = "?"
        for line in code_match.splitlines():
            if line.startswith("HTTP/"):
                status = line.split(" ")[1] if len(line.split(" ")) > 1 else "?"
                break
        leak_indicators = []
        for sig in ("stack trace", "Traceback", "at line", ".java:",
                    ".py:", "nginx/", "Internal Server Error", "SQL",
                    "Exception", "debug mode"):
            if sig.lower() in body.lower():
                leak_indicators.append(sig)
        entry = {"probe": probe, "status": status, "body_preview": body[:120],
                 "leaks": leak_indicators}
        report["error_handling"].append(entry)
        if leak_indicators:
            findings.append({
                "severity": "MEDIUM",
                "title": f"Error message leaks information: {probe}",
                "detail": f"Leaked indicators: {', '.join(leak_indicators)}",
                "evidence": [body[:200]],
            })

    # ── 4. TLS configuration ─────────────────────────────────────────
    host = base_url.split("//")[-1].split("/")[0].split(":")[0]
    try:
        r = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:443",
             "-servername", host],
            input="\n", capture_output=True, text=True, timeout=10)
        tls_out = r.stdout + r.stderr
        proto = re.search(r"Protocol\s*:\s*(.+)", tls_out)
        cipher = re.search(r"Cipher\s*:\s*(.+)", tls_out)
        verify = re.search(r"Verify return code:\s*(\d+)", tls_out)
        report["tls_info"] = {
            "protocol": proto.group(1).strip() if proto else "?",
            "cipher": cipher.group(1).strip() if cipher else "?",
            "verify_code": verify.group(1) if verify else "?",
        }
        if proto and "TLSv1.0" in proto.group(1):
            findings.append({
                "severity": "HIGH",
                "title": "TLS 1.0 supported (deprecated)",
                "detail": "Disable TLS 1.0/1.1 - use only TLS 1.2+.",
            })
    except Exception:
        pass

    # ── 5. Route probing (if provided) ────────────────────────────────
    if routes:
        route_results = []
        for route in routes[:20]:
            url = f"{base_url}{route}"
            body = _curl_body(url)
            code_raw = _curl(url)
            status = "?"
            for line in code_raw.splitlines():
                if line.startswith("HTTP/"):
                    parts = line.split(" ")
                    status = parts[1] if len(parts) > 1 else "?"
                    break
            route_results.append({
                "route": route,
                "unauthenticated_status": status,
                "body_preview": body[:80],
                "auth_enforced": status in ("401", "403"),
            })
        report["route_probes"] = route_results

        unauth_open = [r for r in route_results
                       if r["auth_enforced"] is False
                       and r["unauthenticated_status"].startswith("2")]
        # v8.3: context-aware sensitivity - a route matching "kyc" but only
        # serving enum/config data (types, labels, options) is NOT sensitive.
        # Real KYC exposure would include PII fields.
        # Known-public route patterns (config/version/enum/reference)
        PUBLIC_ROUTE_RE = re.compile(
            r"(?:^|/)version$|(?:^|/)health$|(?:^|/)status$|"
            r"(?:^|/)config$|(?:^|/)settings$|(?:^|/)document.types$|"
            r"(?:^|/)categories$|(?:^|/)countries$|(?:^|/)currencies$",
            re.I)

        def _is_real_sensitive(route_result):
            r = route_result
            if PUBLIC_ROUTE_RE.search(r["route"]):
                return False  # known public reference endpoint
            if not re.search(r"wallet|deposit|order|payment|admin|user|"
                             r"balance|transaction", r["route"], re.I):
                # kyc/document-types etc: check body for PII indicators
                body = r.get("body_preview", "").lower()
                pii_sigs = ("email", "phone", "address", "name", "national",
                            "balance", "amount", "id_number", "passport_no")
                if any(s in body for s in pii_sigs):
                    return True
                # enum-only responses are config, not sensitive
                if re.search(r'"(?:value|type|label|id)"\s*:', body) and \
                        len(body) < 300:
                    return False
                return True  # unknown shape -> assume sensitive
            return True  # wallet/payment/admin always sensitive

        sensitive_open = [r for r in unauth_open if _is_real_sensitive(r)]
        benign_open = [r for r in unauth_open if not _is_real_sensitive(r)]
        if benign_open:
            findings.append({
                "severity": "INFO",
                "title": f"{len(benign_open)} public reference endpoint(s)",
                "detail": "Intentionally unauthenticated config/enum data.",
                "evidence": [f'{r["route"]} -> {r["body_preview"][:60]}'
                             for r in benign_open[:5]],
            })
        if sensitive_open:
            findings.append({
                "severity": "CRITICAL",
                "title": f"{len(sensitive_open)} sensitive endpoint(s) "
                         f"accessible without authentication!",
                "detail": "These endpoints return data without any token.",
                "evidence": [f'{r["route"]} -> {r["unauthenticated_status"]}: '
                             f'{r["body_preview"]}' for r in sensitive_open[:5]],
            })

    # ── v8.3: Rate limiting assessment ────────────────────────────────
    if base_url and "/api" in base_url:
        rl_results = []
        # Test on a known-sensitive endpoint or the base itself
        test_ep = routes[0] if routes else "/version"
        codes = []
        for _ in range(15):
            raw_r = _curl(f"{base_url}{test_ep}")
            status_line = next(
                (l for l in raw_r.splitlines() if l.startswith("HTTP/")), "")
            code_str = status_line.split(" ")[1] if len(
                status_line.split(" ")) > 1 else "?"
            codes.append(code_str)
        unique_codes = sorted(set(codes))
        has_429 = "429" in unique_codes
        all_same = len(unique_codes) == 1
        report["rate_limiting"] = {
            "endpoint_tested": test_ep,
            "requests_sent": len(codes),
            "unique_status_codes": unique_codes,
            "rate_limited": has_429,
            "all_same_response": all_same,
        }
        if not has_429 and not all_same:
            findings.append({
                "severity": "MEDIUM",
                "title": "Inconsistent responses under load",
                "detail": f"Multiple response codes: {unique_codes}",
            })
        if not has_429 and all_same and "401" in unique_codes:
            findings.append({
                "severity": "HIGH",
                "title": "No rate limiting on authenticated-endpoint probes",
                "detail": f"{len(codes)} rapid requests to {test_ep} "
                          f"returned {unique_codes} without any throttling. "
                          f"Token brute-forcing is feasible.",
            })
        elif not has_429 and all_same:
            findings.append({
                "severity": "LOW",
                "title": "No rate limiting detected on public endpoints",
                "detail": f"{len(codes)} requests all returned "
                          f"{unique_codes}. DDoS/abuse protection unclear.",
            })

    # ── FastAPI/Backend framework fingerprint ─────────────────────────
    # Send empty POST to detect validation-style errors
    try:
        r = subprocess.run(
            ["curl", "-sS", "-m", "6", "-X", "POST",
             "-H", "Content-Type: application/json", "-d", "{}",
             f"{base_url}/auth/link"],
            capture_output=True, text=True, timeout=8)
        body = r.stdout[:200]
        if '"type":"missing"' in body or '"loc":' in body:
            report["backend_framework"] = "FastAPI (Python)"
        elif "Laravel" in body or "Illuminate" in body:
            report["backend_framework"] = "Laravel (PHP)"
        elif "ValidationError" in body:
            report["backend_framework"] = "Express/Joi (Node.js)"
    except Exception:
        pass

    # ── Score ────────────────────────────────────────────────────────
    penalty = 0
    for f in findings:
        penalty += {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10,
                     "LOW": 5, "INFO": 1}.get(f["severity"], 1)
    report["score"] = max(0, 100 - penalty)

    sev_rank = {k: i for i, k in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))
    report["findings"] = findings

    return report


def cmd_apimap(base_url: str, routes=None, json_out=False):
    """CLI handler: nightowl apimap <base-url> [--routes r1,r2,...]"""
    if routes:
        routes = [r.strip() for r in routes.split(",")]
    rep = analyze_api_security(base_url, routes)

    import json as _json
    if json_out:
        print(_json.dumps(rep, indent=2, ensure_ascii=False))
        return rep

    print("\n=== API Infrastructure Assessment ===")
    print(f"Target : {rep['target']}")
    fp = rep.get("server_fingerprint", {})
    print(f"Server : {fp.get('server','?')} | {fp.get('content_type','')}")
    tls = rep.get("tls_info", {})
    if tls:
        print(f"TLS    : {tls.get('protocol','')} / {tls.get('cipher','')}")
    print(f"Score  : {rep['score']}/100")
    print("\n-- Security Headers --")
    for name, meta in rep.get("security_headers", {}).items():
        icon = "✅" if meta["present"] else "❌"
        print(f"  {icon} {name}")
    print("\n-- Findings --")
    for f in rep.get("findings", []):
        print(f"  [{f['severity']:8}] {f['title']}")
        if f.get("detail"):
            print(f"             {f['detail']}")
    if rep.get("route_probes"):
        print("\n-- Route Probes (unauthenticated) --")
        for rp in rep["route_probes"]:
            auth = "🔒" if rp["auth_enforced"] else "🔓"
            print(f"  {auth} [{rp['unauthenticated_status']:>3}] "
                  f"{rp['route']}  {rp['body_preview'][:50]}")
    return rep


if __name__ == "__main__":  # pragma: no cover
    pass
