#!/usr/bin/env python3
"""
NightOwl Test Suite
Run: cd ~/shamcash && .venv/bin/python tests/test_nightowl.py -v
"""
import sys
import os
import json
import tempfile
import zipfile
import unittest
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nightowl
from nightowl import (
    NightOwlAnalyzer, validate_apk, _resolve_apk,
    SECRET_PAT, DANGEROUS_PERMS, FRAMEWORKS, LIBRARIES,
    URL_RE, IP_RE, EMAIL_RE, DOMAIN_RE,
    RISK_PEN, NOISE,
)


def create_minimal_apk(tmpdir, with_secrets=False, with_strings=True):
    """Create a minimal valid APK for testing."""
    apk_path = Path(tmpdir) / 'test.apk'
    dex = b'dex\n035\x00' + b'\x00' * 100
    strings = []
    if with_strings:
        strings = [
            'https://api.testapp.com/v1/users',
            'https://secure.testapp.com/auth',
            'http://insecure.testapp.com/data',
            'contact@testapp.com',
            'com.testapp.MainActivity',
        ]
    if with_secrets:
        strings.extend([
            'AKIAIOSFODNN7EXAMPLE',
            'sk_' + 'live_TESTSTRIPEKEY0000PLACEHOLDER',
            'ghp_' + 'TEST_GITHUB_TOKEN_PLACEHOLDER_XYZ',
            'password="test_secret_123"',
            'api_key="my_test_api_key_value_here"',
            'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc',
        ])
    manifest = b'\x03\x00\x08\x00' + b'\x00' * 64
    with zipfile.ZipFile(str(apk_path), 'w') as zf:
        zf.writestr('classes.dex', dex)
        zf.writestr('AndroidManifest.xml', manifest)
        zf.writestr('resources.arsc', b'\x02\x00\x0c\x00' + b'\x00' * 8)
        if strings:
            zf.writestr('assets/config.txt', '\n'.join(strings))
        # Pad APK to exceed 1024 byte minimum validation
        zf.writestr('assets/_pad.dat', b'\x00' * 2048)
    return str(apk_path)


# ═══════════════════════════════════════════════════════════════════
# 1. VALIDATION
# ═══════════════════════════════════════════════════════════════════

class TestValidation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    def _make_apk(self, secrets=False, strings=True):
        return create_minimal_apk(self.tmpdir, secrets, strings)

    def test_nonexistent_file(self):
        ok, msg = validate_apk('/nonexistent/app.apk')
        self.assertFalse(ok)

    def test_wrong_extension(self):
        f = Path(self.tmpdir) / 'file.txt'
        f.write_text('hello')
        ok, _ = validate_apk(str(f))
        self.assertFalse(ok)

    def test_too_small(self):
        f = Path(self.tmpdir) / 'tiny.apk'
        f.write_bytes(b'\x00' * 100)
        ok, _ = validate_apk(str(f))
        self.assertFalse(ok)

    def test_invalid_zip(self):
        f = Path(self.tmpdir) / 'bad.apk'
        f.write_bytes(b'\x00' * 2000)
        ok, _ = validate_apk(str(f))
        self.assertFalse(ok)

    def test_no_dex(self):
        f = Path(self.tmpdir) / 'nodex.apk'
        with zipfile.ZipFile(str(f), 'w') as zf:
            zf.writestr('AndroidManifest.xml', b'\x00' * 64)
        ok, _ = validate_apk(str(f))
        self.assertFalse(ok)

    def test_valid_apk(self):
        ok, msg = validate_apk(self._make_apk())
        self.assertTrue(ok)
        self.assertEqual(msg, 'OK')

    def test_resolve_direct(self):
        apk = self._make_apk()
        self.assertTrue(Path(_resolve_apk(apk)).exists())

    def test_resolve_not_found(self):
        self.assertEqual(_resolve_apk('/no/fake.apk'), '/no/fake.apk')


# ═══════════════════════════════════════════════════════════════════
# 2. REGEX PATTERNS
# ═══════════════════════════════════════════════════════════════════

class TestRegex(unittest.TestCase):
    def test_url_detection(self):
        m = URL_RE.findall('Visit https://api.example.com/v1/users here')
        self.assertTrue(len(m) >= 1)

    def test_ip_detection(self):
        ips = IP_RE.findall('Server 8.8.8.8 and 192.168.1.1')
        self.assertIn('8.8.8.8', ips)

    def test_email_detection(self):
        emails = EMAIL_RE.findall('Contact admin@company.com')
        self.assertIn('admin@company.com', emails)

    def test_domain_detection(self):
        domains = DOMAIN_RE.findall('Connect api.server.com')
        self.assertIn('api.server.com', domains)

    def test_noise_filtering(self):
        self.assertGreater(len(NOISE), 10)


# ═══════════════════════════════════════════════════════════════════
# 3. SECRET DETECTION
# ═══════════════════════════════════════════════════════════════════

class TestSecrets(unittest.TestCase):
    def _match(self, label, text):
        import re
        return bool(re.search(SECRET_PAT[label][1], text))

    def test_aws_key(self):
        self.assertTrue(self._match('AWS Access Key', 'AKIAIOSFODNN7EXAMPLE'))

    def test_google_api_key(self):
        self.assertTrue(self._match('GCP API Key',
            'AIzaSyD-1234567890abcdefghijklmnopqrstuvwxyz'))

    def test_jwt(self):
        # JWT pattern removed from core — test via Bearer Token instead
        self.assertTrue(self._match('Bearer Token',
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def'))

    def test_rsa_private_key(self):
        self.assertTrue(self._match('RSA Private Key',
            '-----BEGIN RSA PRIVATE KEY-----'))

    def test_github_token(self):
        self.assertTrue(self._match('GitHub Token',
            'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'))

    def test_telegram_token(self):
        # Telegram: 8-10 digits + colon + exactly 35 chars
        tok_35 = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQq_'
        self.assertEqual(len(tok_35), 35)
        self.assertTrue(self._match('Telegram Token', f'123456789:{tok_35}'))

    def test_stripe_key(self):
        self.assertTrue(self._match('Stripe Live Key',
            'sk_' + 'live_TESTSTRIPEKEY0000PLACEHOLDER'))

    def test_password(self):
        self.assertTrue(self._match('Password', 'password="mysecret123"'))

    def test_api_key(self):
        self.assertTrue(self._match('API Key',
            'api_key = "abcdef123456789012345678"'))

    def test_bearer_token(self):
        self.assertTrue(self._match('Bearer Token',
            'Bearer abcdef1234567890abcdef1234567890'))

    def test_sendgrid_key(self):
        self.assertTrue(self._match('SendGrid Key',
            'SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr'))

    def test_pattern_count(self):
        self.assertGreaterEqual(len(SECRET_PAT), 50)

    def test_new_patterns(self):
        """Test newly added patterns."""
        self.assertTrue(self._match('Discord Token',
            'MTIzNDU2Nzg5MDEyMzQ1Njc4OQ' + '.GPLACE.abcdefghijklmnopqrstuvwxyz1234567890ABCDEF'))
        self.assertTrue(self._match('GitLab Token',
            'glpat-1234567890abcdefghij'))
        pat_59 = '1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLM'
        self.assertEqual(len(pat_59), 59)
        self.assertTrue(self._match('GitHub Fine-Grained',
            f'github_pat_11ABCDEFGHIJKLMNOPQRST_{pat_59}'))
        self.assertTrue(self._match('MongoDB URI',
            'mongodb+srv://user:pass@cluster0.abc.mongodb.net/mydb'))
        self.assertTrue(self._match('PostgreSQL URI',
            'postgres://user:pass@db.example.com:5432/mydb'))
        self.assertTrue(self._match('NPM Token',
            'npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234'))
        self.assertTrue(self._match('DigitalOcean Token',
            'dop_' + 'v1_aaaa0000111122223333444455556666777788889999aaaabbbbccccddddeeee'))
        self.assertTrue(self._match('Sentry DSN',
            'https://1234567890abcdef1234567890abcdef@o123456.ingest.sentry.io/12345'))
        self.assertTrue(self._match('Discord Webhook',
            'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz'))
        self.assertTrue(self._match('Slack Webhook',
            'https://hooks.slack.com/services/TPLACE00' + '/BPLACE00/fakeplaceholderfortestslwebhook'))
        self.assertTrue(self._match('Stripe Webhook', 'whsec_1234567890abcdef1234567890abcdef'))
        self.assertTrue(self._match('PyPI Token',
            'pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4LWFiY2QtZWZnaGlqa2xtbm9wcXJzdHV2d3h5'))
        self.assertTrue(self._match('New Relic Key', 'NRAK-' + 'PLACEHOLDERTESTKEY0000XYZ00'))
        self.assertTrue(self._match('Redis URI', 'redis://:password@redis.example.com:6379/0'))

    def test_all_patterns_valid_regex(self):
        import re
        for label, (_, pattern) in SECRET_PAT.items():
            try:
                re.compile(pattern)
            except re.error:
                self.fail(f"Invalid regex in SECRET_PAT['{label}']: {pattern}")

    def test_all_risks_valid(self):
        valid = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        for label, (risk, _) in SECRET_PAT.items():
            self.assertIn(risk, valid, f"Bad risk in SECRET_PAT['{label}']")


# ═══════════════════════════════════════════════════════════════════
# 4. ANALYZER INTEGRATION
# ═══════════════════════════════════════════════════════════════════

class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    def _make(self, secrets=False, strings=True):
        return create_minimal_apk(self.tmpdir, secrets, strings)

    def test_init(self):
        az = NightOwlAnalyzer(self._make())
        self.assertTrue(az.path.exists())
        self.assertEqual(az.d['security']['score'], 100)

    def test_extract_strings(self):
        az = NightOwlAnalyzer(self._make(strings=True))
        az.extract_strings()
        self.assertGreater(len(az.strings), 0)
        self.assertTrue(any('api.testapp.com' in s for s in az.strings))

    def test_analyze_info(self):
        az = NightOwlAnalyzer(self._make())
        az.analyze_info()
        info = az.d['info']
        self.assertEqual(info['file_name'], 'test.apk')
        self.assertGreaterEqual(info['file_size_mb'], 0)
        self.assertGreater(info['file_size_bytes'], 0)
        self.assertEqual(len(info['md5']), 32)
        self.assertEqual(len(info['sha256']), 64)
        self.assertGreaterEqual(info['dex_count'], 1)

    def test_analyze_endpoints(self):
        az = NightOwlAnalyzer(self._make(strings=True))
        az.extract_strings()
        az.analyze_endpoints()
        ep = az.d['endpoints']
        self.assertGreater(len(ep['urls']), 0)
        self.assertTrue(any('api.testapp.com' in s for s in ep['servers']))

    def test_secrets_detection(self):
        az = NightOwlAnalyzer(self._make(secrets=True))
        az.extract_strings()
        az.analyze_secrets()
        secrets = az.d['secrets']
        self.assertGreater(len(secrets), 0)
        types = [s['type'] for s in secrets]
        self.assertTrue(any(t in types for t in
            ['Password', 'API Key', 'AWS Access Key', 'Stripe Live Key', 'GitHub Token']))

    def test_full_pipeline(self):
        az = NightOwlAnalyzer(self._make(secrets=True))
        result = az.run_full()
        self.assertTrue(result)
        self.assertNotEqual(az.d['info'], {})
        self.assertNotEqual(az.d['endpoints'], {})

    def test_json_serializable(self):
        az = NightOwlAnalyzer(self._make(secrets=True))
        az.run_full()
        data = json.loads(json.dumps(az.d, ensure_ascii=False))
        self.assertIn('tool', data)
        self.assertIn('info', data)
        self.assertIn('endpoints', data)
        self.assertIn('secrets', data)
        self.assertIn('security', data)


# ═══════════════════════════════════════════════════════════════════
# 5. REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════

class TestReports(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.apk = create_minimal_apk(self.tmpdir)
    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_creates_all_formats(self):
        az = NightOwlAnalyzer(self.apk)
        az.run_full()
        report_dir = Path(self.tmpdir) / 'reports'
        az.save(str(report_dir))
        self.assertTrue(list(report_dir.glob('*.json')))
        self.assertTrue(list(report_dir.glob('*.md')))
        self.assertTrue(list(report_dir.glob('*.html')))

    def test_json_report_valid(self):
        az = NightOwlAnalyzer(self.apk)
        az.run_full()
        report_dir = Path(self.tmpdir) / 'reports'
        az.save(str(report_dir))
        json_file = list(report_dir.glob('*.json'))[0]
        data = json.loads(json_file.read_text())
        self.assertIn('tool', data)

    def test_html_has_content(self):
        az = NightOwlAnalyzer(self.apk)
        az.run_full()
        report_dir = Path(self.tmpdir) / 'reports'
        az.save(str(report_dir))
        html = list(report_dir.glob('*.html'))[0].read_text()
        self.assertIn('<!DOCTYPE html>', html)
        self.assertIn('NightOwl', html)

    def test_markdown_has_content(self):
        az = NightOwlAnalyzer(self.apk)
        az.run_full()
        report_dir = Path(self.tmpdir) / 'reports'
        az.save(str(report_dir))
        md = list(report_dir.glob('*.md'))[0].read_text()
        self.assertIn('# NightOwl', md)


# ═══════════════════════════════════════════════════════════════════
# 6. SCORING
# ═══════════════════════════════════════════════════════════════════

class TestScoring(unittest.TestCase):
    def test_risk_levels(self):
        self.assertIn('CRITICAL', RISK_PEN)
        self.assertIn('HIGH', RISK_PEN)
        self.assertIn('MEDIUM', RISK_PEN)
        self.assertIn('LOW', RISK_PEN)
        self.assertIn('INFO', RISK_PEN)

    def test_penalty_order(self):
        self.assertGreater(RISK_PEN['CRITICAL'], RISK_PEN['HIGH'])
        self.assertGreater(RISK_PEN['HIGH'], RISK_PEN['MEDIUM'])
        self.assertGreater(RISK_PEN['MEDIUM'], RISK_PEN['LOW'])
        self.assertEqual(RISK_PEN['INFO'], 0)

    def test_score_range(self):
        tmpdir = tempfile.mkdtemp()
        try:
            apk = create_minimal_apk(tmpdir)
            az = NightOwlAnalyzer(apk)
            az.run_full()
            self.assertGreaterEqual(az.d['security']['score'], 0)
            self.assertLessEqual(az.d['security']['score'], 100)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_grade_exists(self):
        tmpdir = tempfile.mkdtemp()
        try:
            apk = create_minimal_apk(tmpdir)
            az = NightOwlAnalyzer(apk)
            az.run_full()
            self.assertIn(az.d['security']['grade'], ['A', 'B', 'C', 'D', 'E', 'F'])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_category_scores_exist(self):
        tmpdir = tempfile.mkdtemp()
        try:
            apk = create_minimal_apk(tmpdir, with_secrets=True)
            az = NightOwlAnalyzer(apk)
            az.run_full()
            cats = az.d['security']['categories']
            for name in ['Network', 'Secrets', 'Crypto', 'Code Quality', 'Permissions', 'WebView']:
                self.assertIn(name, cats)
                self.assertGreaterEqual(cats[name], 0)
                self.assertLessEqual(cats[name], 100)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_debug_build_detection(self):
        tmpdir = tempfile.mkdtemp()
        try:
            apk = create_minimal_apk(tmpdir)
            az = NightOwlAnalyzer(apk)
            az.run_full()
            # Test APK has no debug flags
            self.assertIn('debug_build', az.d['security'])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_clean_apk_gets_high_grade(self):
        tmpdir = tempfile.mkdtemp()
        try:
            apk = create_minimal_apk(tmpdir, with_strings=False)
            az = NightOwlAnalyzer(apk)
            az.run_full()
            # A minimal clean APK should score well
            self.assertGreaterEqual(az.d['security']['score'], 70)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════
# 7. CONSTANTS INTEGRITY
# ═══════════════════════════════════════════════════════════════════

class TestConstants(unittest.TestCase):
    def test_dangerous_perms_count(self):
        self.assertGreater(len(DANGEROUS_PERMS), 20)

    def test_frameworks_count(self):
        self.assertGreaterEqual(len(FRAMEWORKS), 5)

    def test_libraries_count(self):
        self.assertGreaterEqual(len(LIBRARIES), 20)


if __name__ == '__main__':
    unittest.main(verbosity=2)
