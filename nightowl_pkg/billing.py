# billing.py -- NightOwl v8 Subscription & Monetization Enforcement Analyzer
#
# FOR AUTHORIZED SECURITY TESTING ONLY.
#
# Detects how an application enforces paid subscriptions / premium features
# and reports weaknesses that would allow a malicious user to unlock them
# without paying (client-side entitlement storage, missing server-side receipt
# validation, debug switches, weak license logic).
#
# It also generates tailored Frida hook scripts so a pentester can *verify*
# the weakness at runtime on a device they own. This mirrors the OWASP MASTG
# "Resilience Testing" methodology: a finding is only real if it can be
# demonstrated against the app under test.

import json
import re
from pathlib import Path

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── SDK / framework catalog ──────────────────────────────────────────────────
BILLING_SDKS = {
    "Google Play Billing": [
        "com.android.billingclient.api", "BillingClient", "BillingFlowParams",
        "PurchasesUpdatedListener", "queryPurchasesAsync", "acknowledgePurchase",
        "ProductDetails", "QueryProductDetailsParams",
    ],
    "RevenueCat": ["com.revenuecat.purchases", "Purchases.configure",
                   "CustomerInfo", "isEntitledTo", "PurchasesDelegate"],
    "Adapty": ["com.adapty", "Adapty.purchase", "AdaptyProfile"],
    "Superwall": ["com.superwall", "Superwall.shared", "subscriptionStatus"],
    "Qonversion": ["com.qonversion.android.sdk", "QonversionPurchase"],
    "Amazon IAP": ["com.amazon.device.iap", "PurchasingService"],
    "Aptoide/AppCoin": ["cm.aptoide.pt"],
}

ENTITLEMENT_PATTERNS = {
    # Local premium flags — the classic client-side enforcement smell
    r'(?i)["\']?(is[_\-]?(premium|pro|vip|subscribed|paid|unlocked))["\']?\s*[,=)]':
        "Local entitlement flag (isPremium/isPro family)",
    r'(?i)(getBoolean|putBoolean)\s*\(\s*"[^"]*(premium|pro|vip|subscri|unlock)[^"]*"':
        "Entitlement persisted in SharedPreferences",
    r'(?i)fun\s+(is[A-Z]\w*(premium|pro|subscri\w*)\w*)\s*\(':
        "Feature-gate function (Kotlin)",
    r'(?i)boolean\s+(is[A-Z]\w*(premium|pro|subscri\w*)\w*)\s*\(':
        "Feature-gate method (Java)",
    r'(?i)\b(premium|pro)_?(version|feature|content|user|plan|status)\b':
        "Premium plan identifier strings",
    r'(?i)\bfree_?(trial|period|tier)\b': "Free trial handling",
    r'(?i)\b(subscription|purchase)_?(token|status|state)\b': "Subscription state field",
    r'(?i)hasPurchased|checkSubscription|verifyPurchase|restorePurchases':
        "Purchase verification call sites",
}

SERVER_VALIDATION_HINTS = [
    r"(?i)/(receipt|purchase|subscription)s?/(verify|validate|check)",
    r"(?i)/api/(v\d+/)?(billing|iap|entitlement)",
    r"play\.google\.com/library/purchase/acknowledge",   # Play server ack proxy
    r"(?i)googleapis\.com/androidpublisher",             # server-side API
    r"(?i)receipthq|revenuecat.*api/receipts",
]

DEBUG_UNLOCK_PATTERNS = [
    r'(?i)["\']?debug[_\-]?(unlock|free|premium|all)["\']?',
    r'(?i)BuildConfig\.DEBUG[^;]{0,60}(premium|pro|unlock)',
    r'(?i)["\']?test[_\-]?(card|payment|purchase)["\']?',
]

PAYWALL_UI_HINTS = ["paywall", "upgrade_screen", "UpgradeActivity",
                    "PaywallActivity", "subscribe_button", "buy_premium"]

# v8.2.0: wallet/deposit systems (digital wallets, not subscriptions)
WALLET_SYSTEM_RES = [
    (r"/wallet/(?:deposits?|methods?|proof|manual)", "deposit flow"),
    (r"/wallet/(?:binance|usdt|shamcash|kazawallet|syriatel)",
     "third-party funding integration"),
    (r"(?i)(?:quick[_\-]?topup|topup[_\-]?screen|deposit[_\-]?screen)",
     "top-up UI screens"),
    (r"(?i)balance_before|ledger|transaction_log", "server-side ledger field"),
    (r"(?i)/kyc/(?:submit|status|document)", "KYC verification flow"),
    (r"(?i)(?:upload|submit).{0,20}(?:proof|receipt|screenshot)",
     "payment-proof upload"),
]

FRAUD_SENSITIVE_FLOWS = [
    ("/wallet/proof", "MEDIUM",
     "Manual payment-proof upload flow - classic first-party fraud vector "
     "(forged transfer screenshots). Verify server-side OCR/review pipeline "
     "and amount reconciliation."),
    # v8.2.1: live-probe calibration (MaxStore): auth IS enforced (401 on
    # wallet/kyc/orders without token), so unsigned requests are only
    # exploitable FROM an authenticated session -> MEDIUM conditional,
    # escalating to HIGH only if server-side replay/tamper checks are absent.
    ("no-request-signing-detected", "MEDIUM",
     "No HMAC/signature/nonce markers in the client. Auth is enforced at "
     "the gateway, but without request signing a valid session token can "
     "tamper amounts/IDs unless the server validates them independently. "
     "ESCALATE TO HIGH after an authenticated tamper test confirms missing "
     "server-side checks."),
]


def _scan_text(txt):
    """Run all static patterns over one text blob. Returns dict of hits."""
    hits = {
        "sdks": {},
        "entitlements": [],
        "server_validation": [],
        "debug_switches": [],
        "paywall_ui": [],
        "billing_urls": [],
        "wallet_flows": [],
        "signing_markers": 0,
    }
    for sdk, markers in BILLING_SDKS.items():
        found = sorted({m for m in markers if m in txt})
        if found:
            hits["sdks"][sdk] = found[:6]
    seen = set()
    for pat, desc in ENTITLEMENT_PATTERNS.items():
        for m in re.finditer(pat, txt):
            snippet = m.group(0)[:120]
            key = f"{desc}:{snippet[:40]}"
            if key not in seen:
                seen.add(key)
                hits["entitlements"].append({"pattern": desc, "match": snippet})
    for pat in SERVER_VALIDATION_HINTS:
        for m in re.finditer(pat, txt):
            hits["server_validation"].append(m.group(0)[:160])
    for pat in DEBUG_UNLOCK_PATTERNS:
        for m in re.finditer(pat, txt):
            hits["debug_switches"].append(m.group(0)[:120])
    for h in PAYWALL_UI_HINTS:
        if h.lower() in txt.lower():
            hits["paywall_ui"].append(h)
    for pat, label in WALLET_SYSTEM_RES:
        for m in re.finditer(pat, txt):
            hits["wallet_flows"].append(f"{label}::{m.group(0)[:80]}")
    # v8.2.1-calibration: 'signature' alone matches APK-signing APIs in
    # every app; only REQUEST-crypto markers count.
    hits["signing_markers"] = len(re.findall(
        r"(?i)\bhmac\b|x-signature|\bapi[_\-]?secret\b|\bnonce\b"
        r"|(?:request|payload)[_\-]?signature", txt))
    url_pat = re.compile(r'https?://[^\s"\']{6,200}')
    for u in set(url_pat.findall(txt)):
        low = u.lower()
        if any(k in low for k in ("billing", "subscribe", "purchase", "receipt",
                                  "license", "entitle", "payment")):
            hits["billing_urls"].append(u)
    return hits


def analyze_billing(txt, info=None, dart_txt=None):
    """Full subscription-enforcement assessment over the extracted text corpus.

    dart_txt: optional Flutter/Dart snapshot corpus - request signing in a
    Flutter app lives HERE, so signing-marker absence is judged on this
    scope (Java-side 'signature' strings are APK-signing APIs, not requests).
    """
    h = _scan_text(txt)
    signing_scope = dart_txt if dart_txt is not None else txt
    h["signing_markers"] = len(re.findall(
        r"(?i)\bhmac\b|x-signature|\bapi[_\-]?secret\b|\bnonce\b"
        r"|(?:request|payload)[_\-]?signature", signing_scope))
    h["signing_scope"] = "dart-snapshot" if dart_txt is not None else "full-corpus"
    findings = []

    monetized = bool(h["sdks"]) or bool(h["entitlements"]) or \
        bool(h["paywall_ui"]) or bool(h["billing_urls"])

    def add(sev, title, why, masvs, evidence):
        findings.append({
            "severity": sev, "title": title, "why": why,
            "masvs": masvs, "evidence": evidence[:8],
        })

    if monetized:
        add("INFO", "Monetization surface detected",
            "App ships paid features/subscriptions - enforcement testing applies.",
            "MASVS-RESILIENCE", [f"sdk={s}" for s in h["sdks"]] or ["entitlement flags"])
    else:
        add("INFO", "No monetization surface detected",
            "No billing SDKs, entitlement flags or paywall resources found.",
            "MASVS-RESILIENCE", [])

    local_only = False
    if h["entitlements"] and not h["server_validation"]:
        local_only = True

    if h["entitlements"]:
        add(
            "HIGH" if local_only else "MEDIUM",
            "Client-side entitlement storage",
            ("Premium state appears to be stored/read locally with no matching "
             "server-side validation endpoint in the binary. On a rooted device "
             "the flag can be flipped to unlock paid features for free."
             if local_only else
             "Premium state is cached locally; verify the server re-validates "
             "entitlements on each use."),
            "MASVS-RESILIENCE-2",
            [e["pattern"] + " :: " + e["match"][:80] for e in h["entitlements"]],
        )

    if h.get("wallet_flows"):
        flows = sorted({f.split("::")[0] for f in h["wallet_flows"]})
        add("INFO", f"Wallet/deposit system ({len(flows)} flow type(s))",
            "Digital-wallet architecture detected: " +
            ", ".join(flows[:6]) + ".",
            "MASVS-NETWORK", h["wallet_flows"][:8])
    if h.get("signing_markers", 0) == 0 and (
            h.get("wallet_flows") or monetized):
        sev, title, why = next((x[1], x[0], x[2])
                               for x in FRAUD_SENSITIVE_FLOWS
                               if x[0] == "no-request-signing-detected")
        add(sev, title, why, "MASVS-NETWORK-1",
            [f"hmac/signature/nonce scan: 0 hits in {h['signing_scope']}"])
    for marker, sev, why in FRAUD_SENSITIVE_FLOWS:
        if marker != "no-request-signing-detected" and any(
                marker in w for w in h.get("wallet_flows", [])):
            add(sev, f"Fraud-sensitive flow: {marker}", why,
                "MASVS-RESILIENCE", [marker])

    if h["sdks"] and local_only:
        sdk_names = ", ".join(h["sdks"])
        add("HIGH", f"Billing via {sdk_names} without visible receipt validation",
            "Purchases flow through a billing SDK but no receipt-verification "
            "endpoint was found. Unacknowledged/forged purchases may grant "
            "entitlements.",
            "MASVS-RESILIENCE-2", [s for s in h["sdks"]])

    if h["debug_switches"]:
        add("MEDIUM", "Debug/test purchase switches present",
            "Debug-only premium unlocks or test payment paths are compiled into "
            "this build. If reachable they bypass payment entirely.",
            "MASVS-RESILIENCE-1",
            h["debug_switches"])

    for u in h["billing_urls"]:
        if u.startswith("http://"):
            # v8.0.1: license/billing keywords appear in benign URLs too
            # (e.g. http://www.apache.org/licenses/). Only flag when the HOST
            # itself looks like a payment/license service.
            from urllib.parse import urlparse
            try:
                netloc = urlparse(u).netloc.lower()
            except Exception:
                continue
            benign = any(d in netloc for d in (
                "apache.org", "w3.org", "schemas.android.com",
                "google.com", "googleapis.com", "example.com", "github.com",
                "opensource.org", "creativecommons.org", "gnu.org"))
            relevant = any(k in netloc for k in (
                "pay", "billing", "purchase", "receipt", "license",
                "subscri", "iap", "wallet"))
            if not benign and relevant:
                add("CRITICAL", "Billing/license check over cleartext HTTP",
                    f"License or purchase endpoint sent over unencrypted "
                    f"HTTP: {u}",
                    "MASVS-NETWORK-1", [u])
                break

    if h["paywall_ui"] and not h["server_validation"] and h["entitlements"]:
        add("MEDIUM", "Paywall enforced only in UI layer",
            "Paywall components exist alongside local entitlement flags but no "
            "server validation - classic 'UI-level gating' failure mode.",
            "MASVS-RESILIENCE-2", h["paywall_ui"])

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    report = {
        "module": "subscription-enforcement",
        "monetized": monetized,
        "billing_sdks": list(h["sdks"].keys()),
        "sdk_evidence": h["sdks"],
        "entitlement_indicators": h["entitlements"][:20],
        "server_validation_endpoints": sorted(set(h["server_validation"]))[:10],
        "debug_switches": h["debug_switches"],
        "paywall_resources": h["paywall_ui"],
        "billing_urls": sorted(set(h["billing_urls"]))[:15],
        "findings": findings,
        "signing_scope": h.get("signing_scope"),
        "request_signing_markers": h.get("signing_markers", 0),
        "enforcement_model": (
            "unknown" if not monetized else
            "local-only" if local_only else
            "server-backed" if h["server_validation"] else
            "sdk-managed"),
    }
    return report


# ─────────────────────────────────────────────────────────────────────────────
# Frida script generation (authorized runtime verification)
# ─────────────────────────────────────────────────────────────────────────────

FRIDA_HEADER = """/*
 * NightOwl v8 - Subscription Enforcement Verification Script
 * Target : __PACKAGE__
 * Purpose: Verify client-side entitlement weaknesses identified statically.
 *
 * AUTHORIZED SECURITY TESTING ONLY.
 * Run against applications you own or are explicitly licensed to test.
 * Usage: frida -U -f __PACKAGE__ -l this_script.js --no-pause
 */
"""

HOOK_PREMIUM_FLAGS = """
// ── Hook SharedPreferences.getBoolean: force entitlement flags true ────────
var SP = Java.use('android.app.SharedPreferencesImpl');
SP.getBoolean.overload('java.lang.String', 'boolean').implementation = function (key, def) {
    var v = this.getBoolean(key, def);
    if (/__PREMIUM_KEY_REGEX__/i.test(key)) {
        console.log('[+] Entitlement "' + key + '" forced true (was ' + v + ')');
        return true;
    }
    return v;
};
"""

HOOK_BILLING = """
// ── Google Play Billing: rewrite purchase results as purchased+acknowledged ─
Java.perform(function () {
    try {
        var Purchase = Java.use('com.android.billingclient.api.Purchase');
        Purchase.getPurchaseState.overload().implementation = function () {
            console.log('[+] Purchase.getPurchaseState -> PURCHASED');
            return 2; // PURCHASED
        };
        Purchase.isAcknowledged.overload().implementation = function () {
            console.log('[+] Purchase.isAcknowledged -> true');
            return true;
        };
    } catch (e) { console.log('[!] BillingClient hooks skipped: ' + e); }

    try {
        var BP = Java.use('com.android.billingclient.api.BillingResult');
        // Any response code asked for by the listener becomes OK (0)
    } catch (e) {}
});
"""

HOOK_REVENUECAT = """
// ── RevenueCat: CustomerInfo always entitled ────────────────────────────────
Java.perform(function () {
    try {
        var CI = Java.use('com.revenuecat.purchases.CustomerInfo');
        CI.isEntitledTo.overload('java.lang.String').implementation = function (id) {
            console.log('[+] RevenueCat.isEntitledTo("' + id + '") -> true');
            return true;
        };
    } catch (e) { console.log('[!] RevenueCat hooks skipped: ' + e); }
});
"""

HOOK_GENERIC_GETTERS = """
// ── Generic feature-gate getters matching premium regex ────────────────────
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (!/__PACKAGE_SLASH__/i.test(name)) return;
            try {
                var cls = Java.use(name);
                var methods = cls.class.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var mname = methods[i].getName();
                    if (/^(is|has)[A-Za-z]*(premium|pro|vip|subscri|unlock)[a-z]*$/i.test(mname)) {
                        (function (clsRef, mName) {
                            try {
                                clsRef[mName].overload().implementation = function () {
                                    console.log('[+] ' + name + '.' + mName + '() -> true');
                                    return true;
                                };
                            } catch (e) {}
                        })(cls, mname);
                    }
                }
            } catch (e) {}
        },
        onComplete: function () { console.log('[*] getter sweep complete'); }
    });
});
"""


def generate_bypass_script(package: str, report: dict, out_path: Path) -> Path:
    """Compose a Frida JS script tailored to the static profile found."""
    parts = [FRIDA_HEADER.replace("__PACKAGE__", package)]
    premium_regex = r"(premium|pro(_|\\b)?|vip|subscri|unlock)"
    parts.append(HOOK_PREMIUM_FLAGS.replace("__PREMIUM_KEY_REGEX__", premium_regex))

    sdks = report.get("billing_sdks", [])
    if any("Play Billing" in s for s in sdks):
        parts.append(HOOK_BILLING)
    if any("RevenueCat" in s for s in sdks):
        parts.append(HOOK_REVENUECAT)

    parts.append(HOOK_GENERIC_GETTERS
                 .replace("__PACKAGE_SLASH__", package.replace(".", r"\.")))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(parts), encoding="utf-8")
    return out_path


def cmd_billing(apk_path: str, analyzer=None, json_out=False):
    """CLI handler: nightowl billing <apk>"""
    from . import core as nw  # reuse engine rendering helpers lazily
    az = analyzer
    if az is None:
        az = nw.NightOwlAnalyzer(apk_path)
        az.extract_strings()
    try:
        from .dart import extract_dart_strings
        dart_corpus = "\n".join(
            extract_dart_strings(str(az.path)).values()) or None
    except Exception:
        dart_corpus = None
    rep = analyze_billing(az.txt, az.d.get("info"), dart_txt=dart_corpus)
    pkg = az.d.get("info", {}).get("package") or "com.target.app"
    rep["package"] = pkg

    ws = Path(__file__).resolve().parent.parent / "workspace"
    script = generate_bypass_script(pkg, rep,
                                    ws / "bypass" / f"{pkg}-premium-verify.js")
    rep["verification_script"] = str(script)

    if json_out:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return rep

    RICH = getattr(nw, "RICH", False)
    con = getattr(nw, "con", None)
    lines = []
    lines.append(f"\n=== Subscription Enforcement Assessment: {pkg} ===")
    lines.append(f"Enforcement model : {rep['enforcement_model']}")
    lines.append(f"Billing SDKs      : {', '.join(rep['billing_sdks']) or '-'}")
    lines.append(f"Server validation : {len(rep['server_validation_endpoints'])} endpoint(s)")
    lines.append("")
    for f in rep["findings"]:
        lines.append(f"[{f['severity']:8}] {f['title']}")
        lines.append(f"           {f['why']}")
    lines.append("")
    lines.append(f"Frida verification script: {script}")
    text = "\n".join(lines)
    if RICH and con:
        con.print(text)
    else:
        print(text)
    return rep
