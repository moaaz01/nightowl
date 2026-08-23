#!/usr/bin/env python3
"""NightOwl v8 module tests (introduced in the v7 round): validators, billing,
authmap, deepscan, mcp."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nightowl_pkg.validators import (
    assess, triage_findings, shannon_entropy, decode_jwt,
)
from nightowl_pkg.billing import analyze_billing, generate_bypass_script
from nightowl_pkg.authmap import map_authentication, extract_access_points
from nightowl_pkg.deepscan import analyze_deep, attach_cvss


# ---------------------------------------------------------------------------
# Validators - the false-positive reduction engine
# ---------------------------------------------------------------------------

class TestValidatorsFPReduction(unittest.TestCase):
    """The exact false-positive classes the engine must eliminate."""

    def _v(self, label, val, ctx=""):
        return assess(label, val, ctx)["verdict"]

    def test_aws_docs_example_filtered(self):
        self.assertEqual(self._v("AWS Access Key", "AKIAIOSFODNN7EXAMPLE"),
                         "FILTERED")

    def test_telegram_docs_example_filtered(self):
        r = assess("Telegram Token",
                   "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "")
        self.assertEqual(r["verdict"], "FILTERED")

    def test_aws_docs_secret_filtered(self):
        r = assess("AWS Secret Key",
                   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "")
        self.assertEqual(r["verdict"], "FILTERED")

    def test_placeholder_api_key_filtered(self):
        r = assess("API Key", "my_test_api_key_value_here",
                   'api_key="my_test_api_key_value_here"')
        self.assertEqual(r["verdict"], "FILTERED")

    def test_stripe_live_with_test_marker_downgraded(self):
        sk = "sk_" "liv" "e_test1234567890abcdefghij"  # scanner-safe literal
        r = assess("Stripe Live Key", sk, "")
        self.assertEqual(r["verdict"], "FILTERED")
        self.assertEqual(r["adjusted_risk"], "LOW")

    def test_your_password_here_filtered(self):
        r = assess("Password", "your_password_here",
                   "password = your_password_here")
        self.assertEqual(r["verdict"], "FILTERED")

    def test_malformed_aws_length_not_confirmed(self):
        r = assess("AWS Access Key", "AKIAQ7F9XK2LM4RTY8U",
                   "production credentials")
        self.assertNotEqual(r["verdict"], "CONFIRMED")

    def test_github_alphabet_run_rejected(self):
        r = assess("GitHub Token", "ghp_" + "a" * 36, "")
        self.assertNotEqual(r["verdict"], "CONFIRMED")

    def test_valid_aws_key_confirmed(self):
        r = assess("AWS Access Key", "AKIAQ7F9XK2LM4RTY8UB",
                   "production credentials for s3 media sync")
        self.assertEqual(r["verdict"], "CONFIRMED")

    def test_valid_telegram_token_confirmed(self):
        r = assess("Telegram Token",
                   "7418295363:AAF3vHxNqPzKdLmWcYuIoBgTeRsUaZxCkQw",
                   "bot_token for prod notifier")
        self.assertEqual(r["verdict"], "CONFIRMED")

    def test_decodable_jwt_confirmed_with_claims(self):
        tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NSIsImlzcyI6Imh0dHBzOi8vYXV0aC5leGFtcGxlLmNvbSJ9."
               "ZkxF8mOkGpRnMtVcYlDqJfTzWwKbNhPdLsQeRmAoUiY")
        r = assess("JWT Secret", tok, "Authorization bearer to api server")
        self.assertEqual(r["verdict"], "CONFIRMED")

    def _b64(self, obj):
        import base64
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()).rstrip(b"=").decode()

    def test_expired_jwt_downgraded(self):
        import time
        past = int(time.time()) - 10 ** 7
        tok = f"{self._b64({'alg': 'HS256', 'typ': 'JWT'})}." \
              f"{self._b64({'sub': '1', 'exp': past})}.sig"
        r = assess("JWT Secret", tok, "")
        self.assertTrue(any("EXPIRED" in x for x in r["reasons"]))
        self.assertLess(r["confidence"], 75)

    def test_alg_none_jwt_flagged(self):
        tok = f"{self._b64({'alg': 'none'})}.{self._b64({'admin': True})}."
        r = assess("JWT Secret", tok, "")
        self.assertTrue(any("none" in x.lower() for x in r["reasons"]))

    def test_firebase_aiza_downgraded_to_medium(self):
        key = "AIzaSyD1234567890abcdefghijklmno"
        r = assess("GCP API Key", key,
                   "google-services.json firebase config default")
        self.assertEqual(r["adjusted_risk"], "MEDIUM")

    def test_db_uri_without_creds_low(self):
        r = assess("PostgreSQL URI", "postgres://db.internal.local:5432/app", "")
        self.assertEqual(r["adjusted_risk"], "LOW")

    def test_db_uri_with_creds_kept_high(self):
        r = assess("MongoDB URI",
                   "mongodb://admin:S3cretPw@10.0.0.5:27017/proddb", "")
        self.assertIn(r["verdict"], ("CONFIRMED", "LIKELY"))

    def test_negative_context_lowers_confidence(self):
        val = "ghp_x7Kp2mQzR8vTwYb3NdJfLh6GsAc5VeM1iU"
        clean = assess("GitHub Token", val,
                       "deploy token").get("confidence", 100)
        noisy = assess("GitHub Token", val,
                       "unit test mock sample example fixture").get(
                       "confidence", 100)
        self.assertGreater(clean, noisy)

    def test_triage_splits_kept_and_filtered(self):
        raw = [
            {"type": "AWS Access Key", "value": "AKIAIOSFODNN7EXAMPLE",
             "risk": "CRITICAL", "context": ""},
            {"type": "AWS Access Key", "value": "AKIAQ7F9XK2LM4RTY8UB",
             "risk": "CRITICAL", "context": "prod credentials"},
        ]
        kept, filt = triage_findings(raw)
        self.assertEqual(len(filt), 1)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["verdict"], "CONFIRMED")


# ---------------------------------------------------------------------------
# Billing / subscription enforcement
# ---------------------------------------------------------------------------

class TestBillingAnalyzer(unittest.TestCase):

    def test_monetized_app_local_only_enforcement(self):
        txt = """
        com.android.billingclient.api.BillingClient queryPurchasesAsync
        prefs.getBoolean("is_premium", false)
        boolean isProUnlocked()
        PaywallActivity upgrade_screen
        """
        rep = analyze_billing(txt)
        self.assertTrue(rep["monetized"])
        self.assertEqual(rep["enforcement_model"], "local-only")
        sev = [f["severity"] for f in rep["findings"]]
        self.assertIn("HIGH", sev)

    def test_server_backed_model_detected(self):
        txt = """
        BillingClient acknowledgePurchase
        is_premium flag cached
        https://api.target.com/v1/receipts/verify
        """
        rep = analyze_billing(txt)
        self.assertEqual(rep["enforcement_model"], "server-backed")

    def test_non_monetized_app(self):
        rep = analyze_billing("just a calculator app, no billing here")
        self.assertFalse(rep["monetized"])

    def test_debug_unlock_switch_found(self):
        rep = analyze_billing(
            'debug_unlock_all = BuildConfig.DEBUG && freeAccess')
        self.assertTrue(rep["debug_switches"])

    def test_bypass_script_generated_and_safe_header(self):
        import tempfile
        rep = analyze_billing("BillingClient is_premium RevenueCat isEntitledTo")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "verify.js"
            p = generate_bypass_script("com.example.app", rep, out)
            js = p.read_text()
            self.assertIn("AUTHORIZED SECURITY TESTING ONLY", js)
            self.assertIn("SharedPreferencesImpl", js)
            self.assertIn("com.example.app", js)

# ---------------------------------------------------------------------------
# Authentication map
# ---------------------------------------------------------------------------

class TestAuthMap(unittest.TestCase):

    TXT = """
    @POST("auth/login")
    fun login(@Body body: LoginRequest)   // username, password
    @POST("oauth/token") grant_type=refresh_token
    https://api.target.com/v2/auth/mfa/verify otp code
    addHeader("Authorization", "Bearer " + token)
    getSharedPreferences("auth_prefs", MODE_PRIVATE)
    putString("access_token", jwt)
    http://insecure.target.com/api/login
    CertificatePinner.Builder().add("api.target.com", sha256/AAAA=
    """

    def test_flows_extracted(self):
        m = map_authentication(self.TXT)
        types = {f["type"] for f in m["flows"]}
        self.assertIn("login", types)
        self.assertIn("token", types)

    def test_cleartext_login_flagged_critical(self):
        m = map_authentication(self.TXT)
        sev = [w["severity"] for w in m["weaknesses"]]
        self.assertIn("CRITICAL", sev)

    def test_token_storage_identified(self):
        m = map_authentication(self.TXT)
        self.assertTrue(m["token_lifecycle"]["storage"])

    def test_missing_pinning_detected_when_absent(self):
        txt = '@POST("auth/login") username password'
        m = map_authentication(txt)
        titles = [w["title"] for w in m["weaknesses"]]
        self.assertTrue(any("pinning" in t.lower() for t in titles))

    def test_access_points_capture(self):
        ap = extract_access_points(self.TXT)
        self.assertGreater(ap["count_urls"], 0)
        self.assertTrue(any(c["path"] == "auth/login"
                            for c in ap["annotated_calls"]))


# ---------------------------------------------------------------------------
# Deep scan layers
# ---------------------------------------------------------------------------

class TestDeepScan(unittest.TestCase):

    def test_webview_and_crypto_misuse(self):
        txt = """
        webView.getSettings().setJavaScriptEnabled(true);
        addJavascriptInterface(new JSBridge(), "android");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        new IvParameterSpec("1234567890123456");
        SecretKeySpec(spec, "AES") with key "0123456789abcdef";
        """
        rep = attach_cvss(analyze_deep(txt, None))
        titles = [f["title"] for f in rep["findings"]]
        self.assertTrue(any("JavaScript" in t for t in titles))
        self.assertTrue(any("ECB" in t for t in titles))
        self.assertTrue(any("Static/hardcoded IV" in t for t in titles))

    def test_manifest_exported_surface(self):
        manifest = {
            "activities": [{"name": "com.a.Main", "exported": True},
                           {"name": "com.a.Secret", "exported": False}],
            "providers": [{"name": "com.a.DBProvider", "exported": True}],
            "services": [], "receivers": [],
        }
        rep = attach_cvss(analyze_deep("", manifest))
        self.assertEqual(len(rep["attack_surface"]["exported_activities"]), 1)
        titles = [f["title"] for f in rep["findings"]]
        self.assertTrue(any("Exported ContentProviders" in t for t in titles))
        # provider finding must carry a CVSS vector
        prov = next(f for f in rep["findings"]
                    if "ContentProviders" in f["title"])
        self.assertIn("CVSS:3.1", prov["cvss_vector"])

    def test_deep_link_hijack_candidate(self):
        txt = 'android:scheme="myapp" android:host="open"'
        rep = analyze_deep(txt, None)
        titles = [f["title"] for f in rep["findings"]]
        self.assertTrue(any("custom URI scheme" in t for t in titles))
        self.assertEqual(rep["uri_schemes"], ["myapp"])


# ---------------------------------------------------------------------------
# MCP server protocol
# ---------------------------------------------------------------------------

class TestMCPProtocol(unittest.TestCase):

    def _handle(self, msg):
        from nightowl_pkg.mcp_server import handle
        return handle(msg)

    def test_initialize_handshake(self):
        r = self._handle({"jsonrpc": "2.0", "id": 1,
                          "method": "initialize", "params": {}})
        self.assertEqual(r["result"]["serverInfo"]["name"], "nightowl")

    def test_tools_list_has_core_scans(self):
        r = self._handle({"jsonrpc": "2.0", "id": 2,
                          "method": "tools/list", "params": {}})
        names = [t["name"] for t in r["result"]["tools"]]
        for expected in ("nightowl_full", "nightowl_secrets",
                         "nightowl_authmap", "nightowl_billing",
                         "nightowl_deepscan"):
            self.assertIn(expected, names)

    def test_unknown_method_error(self):
        r = self._handle({"jsonrpc": "2.0", "id": 3,
                          "method": "bogus/method", "params": {}})
        self.assertEqual(r["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main(verbosity=2)
