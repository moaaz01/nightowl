# NightOwl JSON Contract

Every command emits one top-level object on stdout when `--json` is passed
(human progress goes to stderr). Exit codes: `0` ok, `1` analysis failure,
`2` usage error. All fields are additive-only across versions; consumers
should ignore unknown keys.

## Top level

```jsonc
{
  "tool": "NightOwl",
  "ts":   "2026-08-23T17:48:11",          // ISO-8601 local
  "apk":  "/abs/path/target.apk",

  "info": {
    "package": "com.example.app",
    "version_name": "1.2.3", "version_code": "42",
    "min_sdk": "24", "target_sdk": "34",
    "file_size_mb": 12.4, "dex_count": 2,
    "md5": "...", "sha1": "...", "sha256": "...",
    "native_libs": ["lib/arm64-v8a/libapp.so"]
  },

  "perms": {
    "all": ["android.permission.INTERNET"],
    "dangerous": [{ "name": "...", "risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
                    "desc_en": "..." }]
  },

  "endpoints": { "urls": [], "api": [], "servers": [], "domains": [],
                 "ips": [], "emails": [] },

  "security": { "score": 0-100, "grade": "A|B|C|D|E|F",
                "issues": [...], "categories": {...}, "debug_build": false },

  "vulns": [{ "id": "V-001", "title": "...", "risk": "...",
              "desc": "...", "rec": "...", "cat": "..." }],

  "arch": { "frameworks": [], "libraries": [], "native": [],
            "obfuscation": [] }
}
```

## secrets (validated) — the core contract

```jsonc
"secrets": [{
  "type": "AWS Access Key",
  "value": "<full value — treat as sensitive>",
  "risk": "HIGH",                 // adjusted risk after validation
  "raw_risk": "CRITICAL",         // pattern-level risk before validation
  "confidence": 90.0,             // 0..100
  "verdict": "CONFIRMED",         // CONFIRMED | LIKELY | SUSPECTED | FILTERED
  "validation": [                 // machine-readable reasons
     "well-formed AWS key ID", "high entropy (4.28 b/c)"
  ],
  "context": "±120 chars around the match",
  "source": "DEX strings | XML resource | Native library (.so) | ..."
}],

"secrets_filtered": [ /* same shape; rejected candidates + why */ ],
"secrets_stats": { "raw_candidates": 12, "reported": 3, "filtered": 9,
                   "confirmed": 2, "likely": 1, "suspected": 0 }
```

Verdict semantics: `CONFIRMED` ≥75 · `LIKELY` 55–74 · `SUSPECTED` 35–54 ·
`FILTERED` <35 (hidden from reports/vulns; retained for audit).

jq recipes:

```bash
nightowl secrets app.apk --json | jq '[.secrets[] | select(.confidence >= 75)]'
nightowl full app.apk --json   | jq '.secrets_stats'
```

## authmap

```jsonc
{
  "flows": [{
    "type": "login|registration|token|mfa|logout|unknown",
    "endpoint": "https://api.target.com/oauth/token",
    "http_method": "POST|null",
    "credential_params": ["username","password","grant_type"],
    "grant_types": ["password","refresh_token"],
    "transport": "https|http|unknown"
  }],
  "token_lifecycle": { "storage": [], "request_attachment": [],
                       "jwt_handling_detected": true,
                       "encrypted_storage_used": false },
  "certificate_pinning": false,
  "weaknesses": [{ "severity": "CRITICAL", "title": "...",
                   "detail": "...", "masvs": "MASVS-NETWORK-1" }],
  "summary": { "login_endpoints": 4, "token_endpoints": 2,
               "mfa_endpoints": 0 },
  "access_points": { "absolute_urls": [], "annotated_calls": [],
                     "count_urls": 0, "count_paths": 0 }
}
```

## billing

```jsonc
{
  "enforcement_model": "local-only | server-backed | sdk-managed | unknown",
  "billing_sdks": ["Google Play Billing"],
  "entitlement_indicators": [{ "pattern": "...", "match": "..." }],
  "server_validation_endpoints": [],
  "debug_switches": [],
  "paywall_resources": [],
  "billing_urls": [],
  "findings": [{ "severity": "HIGH", "title": "...", "why": "...",
                 "masvs": "MASVS-RESILIENCE-2", "evidence": [] }],
  "verification_script": "/…/workspace/bypass/<pkg>-premium-verify.js"
}
```

## deepscan / hardening / privacy / sca

```jsonc
"deepscan": { "attack_surface": {"exported_*": [...]},
              "uri_schemes": [], "findings": [
                { "severity": "...", "category": "...", "title": "...",
                  "matches": 2, "evidence": [], "cvss_vector": "CVSS:3.1/...",
                  "note": null } ] },

"hardening": { "packers_protectors": { "<name>":
                   { "category": "packer|protector|obfuscator",
                     "evidence": [] } },
               "compilers": [], "anti_analysis": { "<family>":
                   { "evidence": [], "count": 2 } },
               "obfuscation": [], "findings": [],
               "summary": { "packed": true, "obfuscated": true } },

"privacy": { "trackers": { "<sdk>": ["<class evidence>"] },
             "tracker_count": 4, "ad_sdk_count": 1, "analytics_count": 2,
             "data_collection_permissions": [
               { "permission": "ACCESS_FINE_LOCATION",
                 "exposes": "Precise location", "category": "location",
                 "risk": "HIGH" } ],
             "findings": [] },

"sca": { "components_found": ["okhttp"], "versions_detected": {},
         "vulnerable": [{ "component": "okhttp", "severity": "HIGH",
                          "version": "4.8.0", "advisory": "CVE-2021-0341",
                          "detail": "..." }],
         "needs_manual_review": [],
         "sbom": { "bomFormat": "CycloneDX", "specVersion": "1.5",
                   "components": [] } }
```

## diff output (`nightowl diff a.json b.json --json`)

```jsonc
{ "score": { "old": 80, "new": 70, "delta": -10 },
  "grade": { "old": "B", "new": "C" },
  "verdict": "IMPROVED | REGRESSED | SCORE_DROP | MIXED",
  "secrets": { "added": [{ "type": "", "masked": "", "risk": "",
                           "confidence": 0 }],
               "removed": [], "still_present": 0 },
  "vulns":             { "added": [], "resolved": [] },
  "auth_weaknesses":   { "added": [], "resolved": [] },
  "deepscan_findings": { "added": [], "resolved": [] },
  "servers":           { "added": [], "removed": [] },
  "billing": { "old": "local-only", "new": "server-backed",
               "changed": true } }
```
