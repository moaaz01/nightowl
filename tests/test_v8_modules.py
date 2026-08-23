#!/usr/bin/env python3
"""NightOwl v8 module tests: hardening, privacy, sca, diff, report."""
import json
import os
import sys
import re
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nightowl_pkg.validators import assess
from nightowl_pkg.hardening import analyze_hardening, _signing_weaknesses
from nightowl_pkg.privacy import analyze_privacy
from nightowl_pkg.sca import analyze_sca, _lt, _detect_versions
from nightowl_pkg.diff import diff_reports, mask_value
from nightowl_pkg.report import build_html, build_md, mask_value as rmask

class TestHardening(unittest.TestCase):

    def test_packer_detection_360jiagu(self):
        rep = analyze_hardening("libjiagu.so present com.qihoo.util stub",
                                ["libjiagu.so"])
        self.assertTrue(rep["summary"]["packed"])
        self.assertIn("360 Jiagu (Qihoo)", rep["packers_protectors"])

    def test_obfuscator_dexguard(self):
        rep = analyze_hardening("protected by DexGuard build", [])
        names = set(rep["packers_protectors"])
        self.assertIn("DexGuard", names)
        self.assertEqual(
            rep["packers_protectors"]["DexGuard"]["category"], "obfuscator")

    def test_clean_app_not_flagged(self):
        rep = analyze_hardening("plain app nothing special here", [])
        self.assertFalse(rep["summary"]["packed"])

    def test_anti_analysis_family(self):
        rep = analyze_hardening("checks goldfish and qemu.hw.mainkeys "
                                "for emulator detection", [])
        self.assertIn("emulator-detect", rep["anti_analysis"])

    def test_v1_only_signing_janus(self):
        findings = _signing_weaknesses({"schemes": ["v1"]})
        self.assertTrue(any(f.get("cve") == "CVE-2017-13156"
                            for f in findings))


class TestPrivacy(unittest.TestCase):

    def test_tracker_detection(self):
        txt = ("com.appsflyer.AFInAppEventType com.google.android.gms.ads "
               "io.sentry.SentryClient")
        rep = analyze_privacy(txt)
        names = set(rep["trackers"])
        self.assertIn("AppsFlyer", names)
        self.assertIn("Google AdMob", names)
        self.assertGreaterEqual(rep["ad_sdk_count"], 1)

    def test_no_trackers(self):
        rep = analyze_privacy("clean private app")
        self.assertEqual(rep["tracker_count"], 0)

    def test_permission_mapping(self):
        perms = [{"name": "android.permission.ACCESS_FINE_LOCATION",
                  "risk": "HIGH"}]
        rep = analyze_privacy("", perms)
        cats = rep["collection_categories"]
        self.assertIn("location", cats)


class TestSCA(unittest.TestCase):

    def test_version_compare(self):
        self.assertTrue(_lt("4.9.1", "4.9.2"))
        self.assertFalse(_lt("4.9.2", "4.9.2"))
        self.assertFalse(_lt("5.0.0", "4.9.2"))

    def test_version_extraction_from_pom(self):
        vers = _detect_versions('okhttp_version" value="4.8.0"')
        self.assertEqual(vers.get("okhttp"), "4.8.0")

    def test_vulnerable_okhttp_detected(self):
        txt = "okhttp3.OkHttpClient okhttp_version=3.12.0"
        rep = analyze_sca(txt + ' res/values pom okhttp_version="4.8.0"')
        vuln_titles = [f["title"] for f in rep["vulnerable"]]
        self.assertTrue(any("okhttp" in t.lower() for t in vuln_titles))

    def test_sbom_structure(self):
        txt = "retrofit2.Retrofit com.google.gson.Gson"
        rep = analyze_sca(txt)
        sbom = rep["sbom"]
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        names = {c["name"] for c in sbom["components"]}
        self.assertIn("retrofit", names)
        self.assertIn("gson", names)


def _mk_scan(score, secrets, servers, grade=None):
    return {
        "apk": "/tmp/x.apk",
        "security": {"score": score, "grade": grade or "C"},
        "secrets": secrets,
        "vulns": [],
        "authmap": {"weaknesses": []},
        "deepscan": {"findings": []},
        "endpoints": {"servers": servers},
        "billing": {"enforcement_model": "unknown"},
    }


class TestDiff(unittest.TestCase):

    def test_secret_added_and_removed(self):
        old = _mk_scan(80, [{"type": "AWS Access Key",
                             "value": "AKIAQ7F9XK2LM4RTY8UB"}], ["api.old.com"])
        new = _mk_scan(70, [], ["api.new.com", "api.old.com"])
        d = diff_reports(old, new)
        self.assertEqual(len(d["secrets"]["added"]), 0)
        # secret removed -> improvement signal
        self.assertEqual(len(d["secrets"]["removed"]), 1)
        self.assertIn("api.new.com", d["servers"]["added"])
        self.assertEqual(d["score"]["delta"], -10)

    def test_regression_verdict(self):
        old = _mk_scan(90, [], [])
        new = _mk_scan(50, [{"type": "Password", "value": "super_secret_1234"}],
                       [])
        d = diff_reports(old, new)
        self.assertEqual(d["verdict"], "REGRESSED")

    def test_mask_value(self):
        m = mask_value("AKIAQ7F9XK2LM4RTY8UB", keep=6)
        self.assertTrue(m.startswith("AKIAQ7"))
        self.assertNotEqual(m, "AKIAQ7F9XK2LM4RTY8UB")


def _full_fixture():
    return {
        "apk": "/tmp/fake.apk", "ts": "2026-08-23T00:00:00",
        "info": {"package": "com.test.app", "version_name": "1.0",
                 "file_size_mb": 5, "min_sdk": 24, "target_sdk": 34,
                 "sha256": "ab" * 32},
        "security": {"score": 62, "grade": "C"},
        "secrets": [{"type": "AWS Access Key", "value": "AKIAQ7F9XK2LM4RTY8UB",
                     "risk": "HIGH", "verdict": "CONFIRMED", "confidence": 90,
                     "validation": ["well-formed AWS key ID"],
                     "raw_risk": "CRITICAL"}],
        "secrets_filtered": [{"type": "AWS Access Key",
                              "value": "AKIAIOSFODNN7EXAMPLE",
                              "raw_risk": "CRITICAL",
                              "validation": ["docs example"]}],
        "secrets_stats": {"raw_candidates": 2, "reported": 1, "filtered": 1,
                          "confirmed": 1},
        "vulns": [{"id": "V-001", "title": "Insecure HTTP", "risk": "HIGH",
                   "desc": "x", "rec": "y", "cat": "Network"}],
        "authmap": {"summary": {"login_endpoints": 1, "token_endpoints": 1,
                                "mfa_endpoints": 0},
                    "certificate_pinning": False,
                    "token_lifecycle": {"storage": ["plain SharedPreferences"],
                                        "request_attachment": ["Bearer"],
                                        "jwt_handling_detected": True},
                    "flows": [{"type": "login", "endpoint": "auth/login",
                               "http_method": "POST", "transport": "https",
                               "credential_params": ["username", "password"],
                               "grant_types": []}],
                    "weaknesses": [{"severity": "MEDIUM", "title": "No pinning",
                                    "masvs": "MASVS-NETWORK-2"}]},
        "billing": {"enforcement_model": "local-only", "billing_sdks": [],
                    "findings": [], "verification_script": "/tmp/x.js"},
        "deepscan": {"findings": [{"severity": "MEDIUM",
                                   "category": "Attack Surface",
                                   "title": "2 exported components",
                                   "matches": 2}]},
        "hardening": {"packers_protectors": {}, "anti_analysis": {},
                      "obfuscation": [], "compilers": [],
                      "summary": {"packed": False, "obfuscated": False}},
        "privacy": {"trackers": {"AppsFlyer": ["com.appsflyer"]},
                    "tracker_count": 1, "ad_sdk_count": 0,
                    "analytics_count": 1,
                    "data_collection_permissions":
                        [{"permission": "ACCESS_FINE_LOCATION",
                          "exposes": "Precise location",
                          "category": "location", "risk": "HIGH"}],
                    "findings": []},
        "sca": {"components_found": ["gson"], "versions_detected": {},
                "vulnerable": [], "needs_manual_review": [],
                "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.5",
                         "components": []}},
        "perms": {"dangerous": [{"name": "android.permission.CAMERA",
                                 "risk": "MEDIUM", "desc_en": "Camera"}],
                  "all": []},
        "endpoints": {"servers": ["api.test.com"], "urls":
                      ["https://api.test.com/v1"]},
        "arch": {"frameworks": [], "libraries": [], "native": [],
                 "obfuscation": []},
    }


class TestReportEngine(unittest.TestCase):

    def setUp(self):
        self.d = _full_fixture()

    def test_html_contains_all_sections(self):
        html_out = build_html(self.d)
        for marker in ("Executive Summary", "Secrets (validated)",
                       "Authentication Map", "Subscription Enforcement",
                       "Deep Static Layers", "Hardening &amp; Packers",
                       "Privacy &amp; Trackers", "Supply Chain", "Permissions",
                       "Endpoints", "Architecture", "applyFilters"):
            self.assertIn(marker, html_out)

    def test_html_masks_secret_but_keeps_reveal(self):
        html_out = build_html(self.d)
        self.assertIn("reveal", html_out)
        self.assertNotIn(">AKIAQ7F9XK2LM4RTY8UB<", html_out)

    def test_md_covers_layers(self):
        md = build_md(self.d)
        for marker in ("Secrets (validated)", "Authentication Map",
                       "Subscription Enforcement", "Privacy & Trackers",
                       "Supply Chain"):
            self.assertIn(marker, md)

    def test_filtered_audit_trail_present_in_html(self):
        html_out = build_html(self.d)
        self.assertIn("Filtered candidates", html_out)
        self.assertIn("docs example", html_out)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestStaticOnlyGuardRegression(unittest.TestCase):
    """v8.0.1 real-world find: the guard blocked dynamic commands even when
    static-only mode was OFF. Must never regress."""

    def _cli(self):
        from nightowl_pkg import cli
        return cli

    def test_dynamic_commands_allowed_without_flag(self):
        cli = self._cli()
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NIGHTOWL_STATIC_ONLY", None)
            for cmd in ("decompile", "rasp", "static-audit", "semgrep",
                        "proxy", "lab", "bypass", "bypass-premium"):
                self.assertFalse(cli._guard_static_only(cmd, argv=[cmd]),
                                 f"{cmd} must be allowed without the flag")

    def test_dynamic_commands_blocked_with_flag(self):
        cli = self._cli()
        with unittest.mock.patch.dict(
                os.environ, {"NIGHTOWL_STATIC_ONLY": "1"}):
            self.assertTrue(cli._guard_static_only("decompile",
                                                   argv=["decompile", "x"]))

    def test_dynamic_commands_blocked_with_inline_flag(self):
        cli = self._cli()
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NIGHTOWL_STATIC_ONLY", None)
            self.assertTrue(cli._guard_static_only(
                "lab", argv=["--static-only", "lab", "devices"]))

    def test_info_section_reports_real_permissions(self):
        """v8.0.1: run_section('info') used to skip analyze_perms -> 'Total: 0'.
        The renderer shows the permissions panel, so perms must be analyzed."""
        import inspect
        from nightowl_pkg import engine
        src = inspect.getsource(engine.NightOwlAnalyzer.run_section)
        # analyze_perms must execute unconditionally (not behind an
        # 'if section in' gate that excludes 'info')
        self.assertIn("self.analyze_perms()", src)
        gate = re.search(r"if section in \(([^)]*)\):\s*\n\s*self\.analyze_perms",
                         src)
        self.assertIsNone(gate,
                          "analyze_perms is gated again - info would lie")

    def test_authmap_filters_dex_descriptors(self):
        from nightowl_pkg.authmap import _is_endpoint_noise
        garbage = [
            "Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount",
            "rLandroid/support/v4/media/session/MediaControllerCompat",
            "6Landroid/hardware/camera2/params/Session",
            "/opt/hostedtoolcache/go/1.24.2/x64/src/crypto/tls/auth",
            "assets/svgs/session",
            "/Auth",
        ]
        for g in garbage:
            reason = _is_endpoint_noise(g)
            self.assertNotEqual(reason, "", f"leaked: {g}")
        legit = ["Authentication/signin", "util/registration/register",
                 "api/v2/login", "https://api.target.com/oauth/token"]
        for ok in legit:
            self.assertEqual(_is_endpoint_noise(ok), "",
                             f"false-rejected: {ok}")

    def test_billing_ignores_benign_license_urls(self):
        from nightowl_pkg.billing import analyze_billing
        rep = analyze_billing(
            "is_premium flag http://www.apache.org/licenses/ "
            "PaywallActivity")
        titles = [f["title"] for f in rep["findings"]]
        self.assertNotIn("Billing/license check over cleartext HTTP", titles)


class TestPEMValidationShamCash(unittest.TestCase):
    """v8.0.3: real-world ShamCash findings — unterminated PEM headers inside
    Flutter .so are NOT keys; embedded public-key assets are trust anchors."""

    def _fake_complete_privkey(self):
        import base64 as b64
        body = "\n".join(b64.b64encode(bytes([i % 256] * 48)).decode()
                         for i in range(12))
        return (f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n"
                f"-----END RSA PRIVATE KEY-----")

    def test_unterminated_pem_in_binary_filtered(self):
        # exactly the libapp.so case: header followed by binary garbage
        val = "-----BEGIN PRIVATE KEY-----\x83\x11\"\x83Q\xa6\x9eCameraOwner"
        r = assess("RSA Private Key", "-----BEGIN PRIVATE KEY-----",
                   "binary noise after header", )
        self.assertEqual(r["verdict"], "FILTERED")
        self.assertTrue(any("unterminated" in x for x in r["reasons"]))

    def test_complete_pem_private_key_confirmed(self):
        key = self._fake_complete_privkey()
        corpus = "some config\n" + key + "\ntrailer"
        r = assess("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----",
                   key[:200], full_text=corpus)
        self.assertEqual(r["verdict"], "CONFIRMED")
        self.assertTrue(any("COMPLETE PEM" in x for x in r["reasons"]))

    def test_public_key_asset_is_trust_anchor(self):
        import base64 as b64
        body = "\n".join(b64.b64encode(bytes([7] * 48)).decode()
                         for i in range(6))
        key = (f"-----BEGIN PUBLIC KEY-----\n{body}\n"
               f"-----END PUBLIC KEY-----")
        corpus = ("assets/flutter_assets/assets/public_server_new.pem\n"
                  + key)
        r = assess("RSA Public Key", "-----BEGIN PUBLIC KEY-----",
                   corpus[:200], full_text=corpus)
        self.assertEqual(r["adjusted_risk"], "LOW")
        self.assertTrue(any("trust-anchor" in x or "pinning" in x
                            for x in r["reasons"]))

    def test_flutter_ca_assets_detected_as_pinning(self):
        from nightowl_pkg.authmap import map_authentication
        txt = ("Loading certificate authority from assets/ca/ca.crt "
               "and isrgrootx1.pem with SecurityContext.setTrustedCertificates "
               "@POST(\"auth/login\") username password")
        m = map_authentication(txt)
        self.assertTrue(m["certificate_pinning"],
                        "Flutter embedded CA pinning missed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
