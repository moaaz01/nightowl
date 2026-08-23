#!/usr/bin/env python3
"""Security-invariant tests: report XSS safety, MCP confinement, validators fuzz."""
import base64
import json
import os
import random
import string
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nightowl_pkg.report import build_html, mask_value
from nightowl_pkg.validators import assess, triage_findings

HOSTILE = '<img src=x onerror=alert(1)>` "\' & </span><script>document.location'


class TestReportXSSInvariants(unittest.TestCase):
    """H-02: no APK-derived byte may reach an HTML attribute position raw."""

    def _fixture(self, secret_value):
        return {
            "apk": "/tmp/hostile.apk", "ts": "2026-01-01T00:00:00",
            "info": {"package": HOSTILE, "version_name": '1.0"><script>',
                     "file_size_mb": 1, "min_sdk": 24, "target_sdk": 34,
                     "sha256": "cd" * 32},
            "security": {"score": 50, "grade": "D"},
            "secrets": [{"type": "Password", "value": secret_value,
                         "risk": "HIGH", "verdict": "CONFIRMED",
                         "confidence": 80,
                         "validation": [HOSTILE]}],
            "secrets_filtered": [{"type": "API Key",
                                  "value": '"onmouseover=alert(2) x',
                                  "raw_risk": "HIGH",
                                  "validation": [HOSTILE]}],
            "secrets_stats": {"raw_candidates": 2, "reported": 1,
                              "filtered": 1},
            "vulns": [], "authmap": {"weaknesses": []},
            "billing": None, "deepscan": None,
            "perms": {"dangerous": []},
            "endpoints": {"servers": ['"><svg onload=alert(3)>'], "urls": []},
            "arch": {},
        }

    def test_hostile_secret_never_reaches_attribute_raw(self):
        html = build_html(self._fixture(HOSTILE))
        # the escaped b64 must be present; raw angle-brackets must not appear
        # anywhere inside a data-b64="..." attribute value.
        import re
        for m in re.finditer(r'data-b64="([^"]*)"', html):
            blob = m.group(1)
            self.assertNotIn("<", blob)
            self.assertNotIn(">", blob)
            self.assertNotIn('"', blob.replace("&quot;", ""))
            decoded = base64.b64decode(blob).decode()
            self.assertEqual(decoded, HOSTILE)  # round-trip intact

    def test_hostile_context_escaped_in_text_nodes(self):
        html = build_html(self._fixture(HOSTILE))
        self.assertNotIn("<script>document.location", html)
        self.assertIn("&lt;script&gt;", html)

    def test_mask_never_leaks_full_value(self):
        long_val = "A" * 40 + "</span>"
        masked = mask_value(long_val)
        self.assertNotIn("</span>", masked)


class TestMCPConfinement(unittest.TestCase):
    """H-04: NIGHTOWL_WORKSPACE confines every path an agent may pass."""

    def setUp(self):
        from nightowl_pkg import mcp_server
        self.ms = mcp_server

    def test_unconfined_by_default(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NIGHTOWL_WORKSPACE", None)
            p = self.ms._confine("/tmp/anything.apk")
            self.assertEqual(p, "/tmp/anything.apk")

    def test_outside_workspace_rejected(self):
        with unittest.mock.patch.dict(
                os.environ, {"NIGHTOWL_WORKSPACE": str(Path.cwd())}):
            with self.assertRaises(PermissionError):
                self.ms._confine("/etc/passwd")

    def test_inside_workspace_allowed(self):
        ws = Path.cwd()
        with unittest.mock.patch.dict(
                os.environ, {"NIGHTOWL_WORKSPACE": str(ws)}):
            target = ws / "targets" / "test_secrets.apk"
            if target.exists():
                self.assertEqual(self.ms._confine(str(target)),
                                 str(target.resolve()))

    def test_allow_anywhere_escape_hatch(self):
        with unittest.mock.patch.dict(os.environ, {
                "NIGHTOWL_WORKSPACE": str(Path.cwd()),
                "NIGHTOWL_ALLOW_ANYWHERE": "1"}):
            self.assertEqual(self.ms._confine("/etc/passwd"), "/etc/passwd")


class TestValidatorFuzz(unittest.TestCase):
    """M-04: deterministic property-style sweep — assess() must never crash
    and always emit bounded, well-formed results."""

    ALPHABETS = [
        string.ascii_uppercase + string.digits,          # AWS-like
        string.ascii_letters + string.digits + "_-=",    # generic tokens
        string.printable,                                # hostile soup
        "01",                                            # degenerate
    ]
    LABELS = ["AWS Access Key", "Stripe Live Key", "Telegram Token",
              "GitHub Token", "Bearer Token", "JWT Secret", "MongoDB URI",
              "Password", "API Key", "GCP API Key", "SendGrid Key"]

    def test_fuzz_assess_bounded_and_safe(self):
        rng = random.Random(1337)
        for i in range(400):
            alpha = rng.choice(self.ALPHABETS)
            n = rng.randint(6, 90)
            val = "".join(rng.choice(alpha) for _ in range(n))
            ctx = "".join(rng.choice(string.printable[:94])
                          for _ in range(rng.randint(0, 200)))
            label = rng.choice(self.LABELS)
            res = assess(label, val, ctx)          # must not raise
            self.assertIn(res["verdict"],
                          ("CONFIRMED", "LIKELY", "SUSPECTED", "FILTERED"))
            self.assertGreaterEqual(res["confidence"], 0.0)
            self.assertLessEqual(res["confidence"], 100.0)
            self.assertIn(res["adjusted_risk"],
                          ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    def test_fuzz_triage_never_raises(self):
        rng = random.Random(42)
        findings = []
        for _ in range(120):
            n = rng.randint(8, 60)
            findings.append({
                "type": rng.choice(self.LABELS),
                "value": "".join(rng.choice(string.printable)
                                 for _ in range(n)),
                "risk": rng.choice(["CRITICAL", "HIGH", "MEDIUM"]),
                "context": "".join(rng.choice(string.ascii_lowercase)
                                   for _ in range(80)),
            })
        kept, filtered = triage_findings(findings, full_text="x" * 500)
        self.assertLessEqual(len(kept) + len(filtered), 120)
        for s in kept:
            self.assertIn(s["verdict"],
                          ("CONFIRMED", "LIKELY", "SUSPECTED"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
