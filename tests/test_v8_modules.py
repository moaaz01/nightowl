#!/usr/bin/env python3
"""NightOwl v8 module tests: hardening, privacy, sca, diff, report."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
