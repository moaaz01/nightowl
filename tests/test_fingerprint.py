#!/usr/bin/env python3
"""Fingerprint contract tests: stability, idempotence, totality, format.

`fingerprint` is an additive JSON-contract field (docs/json-contract.md).
These tests pin the four properties consumers rely on: deterministic output,
identity-only hashing (volatile attributes never change it), idempotence, and
a total function that can never fail a scan.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nightowl_pkg.core import attach_fingerprints, fingerprint

# Contract pattern: starts alphanumeric, then only [A-Za-z0-9._:/@+-].
FP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")


def sample_payload() -> dict:
    return {
        "info": {"package": "com.example.app"},
        "secrets": [{"type": "AWS Access Key", "value": "AKIAABCDEFGHIJKLMNOP",
                     "risk": "HIGH", "confidence": 90.0}],
        "secrets_filtered": [{"type": "JWT", "value": "eyJhbGciOiJIUzI1NiJ9"}],
        "vulns": [{"id": "V-001", "title": "Exported activity",
                   "cat": "components", "risk": "MEDIUM"}],
        "deepscan": {"findings": [{"severity": "HIGH",
                                   "title": "Cleartext traffic",
                                   "category": "network"}]},
        "authmap": {"weaknesses": [{"severity": "CRITICAL",
                                    "title": "Cleartext login",
                                    "masvs": "MASVS-NETWORK-1"}]},
        "arch": {"frameworks": ["okhttp"]},
    }


class TestFingerprintPrimitive(unittest.TestCase):

    def test_deterministic_across_calls(self):
        self.assertEqual(fingerprint("secret", "pkg", "AWS", "AKIAxx"),
                         fingerprint("secret", "pkg", "AWS", "AKIAxx"))

    def test_parts_are_unambiguous(self):
        # ("ab","c") must not hash the same as ("a","bc")
        self.assertNotEqual(fingerprint("k", "ab", "c"), fingerprint("k", "a", "bc"))

    def test_format_and_kind_prefix(self):
        fp = fingerprint("finding", "com.x", "Title", "MASVS-NETWORK-1")
        self.assertTrue(fp.startswith("finding:"))
        self.assertRegex(fp, FP_RE)

    def test_none_and_empty_parts_are_ignored(self):
        self.assertEqual(fingerprint("k", None, "a", ""), fingerprint("k", "a"))

    def test_sha256_not_python_hash(self):
        # SHA-256 is stable across processes/hosts; Python's hash() is not.
        import hashlib
        expect = hashlib.sha256("secret\x1fcom.x\x1fAWS".encode()).hexdigest()[:16]
        self.assertEqual(fingerprint("secret", "com.x", "AWS"), f"secret:{expect}")


class TestAttachFingerprints(unittest.TestCase):

    def test_attaches_to_every_known_list(self):
        p = attach_fingerprints(sample_payload())
        self.assertIn("fingerprint", p["secrets"][0])
        self.assertIn("fingerprint", p["secrets_filtered"][0])
        self.assertIn("fingerprint", p["vulns"][0])
        self.assertIn("fingerprint", p["deepscan"]["findings"][0])
        self.assertIn("fingerprint", p["authmap"]["weaknesses"][0])

    def test_idempotent_and_never_overwrites(self):
        p = attach_fingerprints(sample_payload())
        first = p["secrets"][0]["fingerprint"]
        p["secrets"][0]["confidence"] = 10.0
        attach_fingerprints(p)
        self.assertEqual(p["secrets"][0]["fingerprint"], first)

    def test_stable_when_volatile_attributes_change(self):
        a = attach_fingerprints(sample_payload())
        b = sample_payload()
        b["secrets"][0]["confidence"] = 3.0
        b["deepscan"]["findings"][0]["severity"] = "INFO"
        b["vulns"][0]["id"] = "V-077"
        b["authmap"]["weaknesses"][0]["severity"] = "LOW"
        attach_fingerprints(b)
        self.assertEqual(a["secrets"][0]["fingerprint"], b["secrets"][0]["fingerprint"])
        self.assertEqual(a["vulns"][0]["fingerprint"], b["vulns"][0]["fingerprint"])
        self.assertEqual(a["deepscan"]["findings"][0]["fingerprint"],
                         b["deepscan"]["findings"][0]["fingerprint"])
        self.assertEqual(a["authmap"]["weaknesses"][0]["fingerprint"],
                         b["authmap"]["weaknesses"][0]["fingerprint"])

    def test_different_root_cause_gets_different_fingerprint(self):
        a = attach_fingerprints(sample_payload())
        b = sample_payload()
        b["vulns"][0]["title"] = "Exported receiver"
        attach_fingerprints(b)
        self.assertNotEqual(a["vulns"][0]["fingerprint"], b["vulns"][0]["fingerprint"])

    def test_package_is_never_part_of_the_identity(self):
        """`info.package` differs between a bare and a ``[full]`` install
        (no androguard ⇒ placeholder), so it must never reach the hash."""
        a = attach_fingerprints(sample_payload())
        b = sample_payload()
        b["info"]["package"] = "com.other.app"
        attach_fingerprints(b)
        self.assertEqual(a["vulns"][0]["fingerprint"], b["vulns"][0]["fingerprint"])
        self.assertEqual(a["secrets"][0]["fingerprint"], b["secrets"][0]["fingerprint"])

    def test_real_secret_record_is_stable_across_install_modes(self):
        """Regression: a real ``com.studyai.app`` scan produced one
        fingerprint in a ``[full]`` install and a different one in a bare
        install, because the derived ``context`` and the package placeholder
        differed. Record shape copied from that scan."""
        def scan(pkg, context, conf, verdict) -> dict:
            payload = {"info": {"package": pkg},
                       "secrets": [{
                           "type": "Google OAuth",
                           "value": "1003622846245-abcdefghijklmnopqrstuvwxyz0123456789.apps",
                           "raw_len": 66,
                           "context": context,
                           "confidence": conf,
                           "verdict": verdict,
                           "validation": ["high entropy (4.81 bits/char)"],
                           "description": "Google OAuth client secret.",
                           "risk": "HIGH",
                           "source": "DEX strings",
                       }]}
            return attach_fingerprints(payload)

        full = scan("com.studyai.app", "PostSignInFlowRequired\nX\nNn V(C",
                    65.0, "LIKELY")
        bare = scan("N/A (install androguard)",
                    "*Lcom/google/android/gms/internal/base/zaj;\nX\nLs0/m;",
                    30.0, "SUSPECTED")
        self.assertRegex(full["secrets"][0]["fingerprint"], FP_RE)
        self.assertEqual(full["secrets"][0]["fingerprint"],
                         bare["secrets"][0]["fingerprint"])

    def test_total_on_hostile_payloads(self):
        for hostile in (None, 42, "text", [], {}, {"secrets": "not-a-list"},
                        {"secrets": [None, "str", 5]},
                        {"deepscan": {"findings": [{"title": None}]}}):
            attach_fingerprints(hostile)   # must never raise

    def test_record_without_identity_is_left_alone(self):
        self.assertEqual(attach_fingerprints({"secrets": [{"no_identity": 1}]}),
                         {"secrets": [{"no_identity": 1}]})

    def test_unrelated_fields_are_untouched(self):
        p = sample_payload()
        before = repr(p["arch"]) + repr(p["info"])
        attach_fingerprints(p)
        self.assertEqual(before, repr(p["arch"]) + repr(p["info"]))


if __name__ == "__main__":
    unittest.main()
