#!/usr/bin/env python3
"""
NightOwl v4.0 — Advanced Android APK Security Analyzer · Premium TUI

Commands:
  nightowl full     app.apk   Full 8-section analysis
  nightowl info     app.apk   Basic info only
  nightowl perms    app.apk   Permissions analysis
  nightowl urls     app.apk   URLs & endpoints
  nightowl secrets  app.apk   Secret detection
  nightowl arch     app.apk   Architecture detection
  nightowl vulns    app.apk   Vulnerabilities only
  nightowl manifest app.apk   Manifest components
  nightowl scan     [dir]     Batch scan directory
  nightowl guide              Usage guide
  nightowl proxy              Network proxy setup
"""

__version__ = "4.0"

import os, sys, json, re, zipfile, hashlib, argparse, shutil, warnings
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Suppress noisy warnings from androguard about API level mismatches
warnings.filterwarnings('ignore', message='.*API level.*', category=UserWarning)
warnings.filterwarnings('ignore', message='.*Requested API level.*')

# ═══════════════════════════════════════════════════════════════════════
# RICH TUI  (graceful fallback when not installed)
# ═══════════════════════════════════════════════════════════════════════
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeElapsedColumn)
    from rich.tree import Tree
    from rich.text import Text
    from rich.columns import Columns
    from rich.markup import escape as esc
    from rich.theme import Theme
    from rich import box
    RICH = True
except ImportError:
    RICH = False
    def esc(s): return str(s)

try:
    # Suppress androguard API level warnings by redirecting stderr temporarily
    import logging
    logging.getLogger('androguard').setLevel(logging.ERROR)
    logging.getLogger('androguard.core').setLevel(logging.ERROR)
    # androguard 3.x path
    from androguard.core.bytecodes.apk import APK as AndroAPK
    AG = True
except ImportError:
    try:
        # androguard 4.x path
        from androguard.core import apk as _ag_apk
        AndroAPK = _ag_apk.APK
        AG = True
    except (ImportError, AttributeError):
        AG = False

# ─── Console ──────────────────────────────────────────────────────────
_THEME = Theme({
    "no.info": "cyan", "no.ok": "green", "no.warn": "yellow",
    "no.err": "bold red", "no.crit": "bold white on red",
    "no.dim": "dim", "no.h": "bold cyan", "no.lbl": "cyan",
}) if RICH else None
con = Console(theme=_THEME, highlight=False) if RICH else None

# ─── Paths ────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
TARGETS = ROOT / "targets"
REPORTS = ROOT / "workspace" / "reports"
WORKSPACE = ROOT / "workspace"

# ─── Tool Discovery ───────────────────────────────────────────────────
def _find_tool(name: str, hints: list = None) -> str:
    """Find a binary tool, checking known paths. Returns full path or name."""
    candidates = hints or []
    # Always also check PATH
    found = shutil.which(name)
    if found:
        return found
    for c in candidates:
        p = Path(c)
        if p.exists() and os.access(str(p), os.X_OK):
            return str(p)
    return name  # fallback — caller handles failure

JADX = _find_tool('jadx', [
    str(ROOT / 'tools' / 'jadx' / 'bin' / 'jadx'),
    '/home/ali/.local/share/jadx/bin/jadx',
    '/home/ali/shamcash/tools/jadx/bin/jadx',
    '/home/ali/tools/android-reverse-engineering/jadx/bin/jadx',
])
# Also check PATH fallback
if JADX == 'jadx':  # _find_tool returned the fallback name
    _jadx_path = shutil.which('jadx')
    if _jadx_path:
        JADX = _jadx_path
APKTOOL = _find_tool('apktool', [
    str(ROOT / 'tools' / 'apktool'),
    '/home/ali/shamcash/tools/apktool',
    '/home/ali/tools/apktool',
])
ADB = _find_tool('adb', [
    '/home/ali/tools/android-sdk/platform-tools/adb',
    '/usr/lib/android-sdk/platform-tools/adb',
])
STRINGS_BIN = _find_tool('strings')  # binutils strings

def _resolve_apk(apk_arg: str) -> str:
    """Smart APK resolution: tries given path, then targets/ dir."""
    p = Path(apk_arg)
    if p.exists():
        return str(p.resolve())
    # Try targets/ directory
    t = TARGETS / apk_arg
    if t.exists():
        return str(t.resolve())
    t2 = TARGETS / p.name
    if t2.exists():
        return str(t2.resolve())
    return str(p)  # return as-is; validation will catch the error

# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

RISK_STYLE = {
    'CRITICAL': 'bold white on red', 'HIGH': 'bold red',
    'MEDIUM': 'bold yellow', 'LOW': 'cyan', 'INFO': 'dim',
}
RISK_EM  = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '⚪'}
RISK_ORD = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
RISK_PEN = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2, 'INFO': 0}

def _badge_color(risk):
    return {'CRITICAL': '#ef4444', 'HIGH': '#f97316', 'MEDIUM': '#eab308',
            'LOW': '#22c55e', 'INFO': '#64748b'}.get(risk, '#555')

def _badge_text_color(risk):
    return '#000' if risk in ('MEDIUM', 'LOW') else '#fff'

def badge_html(risk):
    bg, fg = _badge_color(risk), _badge_text_color(risk)
    return (f'<span style="background:{bg};color:{fg};padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:bold">{risk}</span>')

def rbadge(risk):
    """Rich-formatted risk badge."""
    st = RISK_STYLE.get(risk, 'dim')
    return f"[{st}] {risk} [/]"

# ── Regex ─────────────────────────────────────────────────────────────
URL_RE    = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,}')
IP_RE     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
DEV_RE    = re.compile(r'/(?:Users|home)/[a-zA-Z0-9_.\-]+/[^\s"\'<>]{5,}')
EMAIL_RE  = re.compile(r'\b[a-zA-Z][a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z][a-zA-Z0-9\-]{0,62}\.)+(?:com|net|org|io|dev|app|co|me|info|biz|pro|xyz|tech|cloud|api|sy|ly|sa|ae|eg|tv|fm|ai|ng|pk|kw|qa|bh|om|jo|lb|ma|tn|dz|sd|iq|ps|tr|id|in|us|uk|de|fr|es|it|ru|jp|cn|kr|br|mx|ca|au|za|sg|hk|tw|my|th|vn|ph)\b')

NOISE = ('android.', 'schemas.android', 'apache.org', 'java.', 'javax.', 'junit',
         'google.com/intl', 'www.w3.org', 'www.openssl', 'pkgs.dev.android',
         'developer.android', 'play.google', 'docs.google', 'fonts.google',
         'www.googleapis.com/auth', 'mozilla.org', 'creativecommons.org',
         'xml.org', 'ietf.org', 'flutter.dev', 'dartbug.com', 'pub.dev',
         'dart.dev', 'api.flutter.dev', 'docs.flutter.dev', 'github.com',
         'issuetracker.google', 'tensorflow.org', 'openxmlformats.org',
         'microsoft.com', 'ibm.com', 'unicode.org', 'adobe.com', 'purl.org',
         'jsdelivr.com', 'fontello.com', 'dart-lang', 'flutter/flutter')

SECRET_PAT = {
    # ── Cloud Providers ──────────────────────────────────────────
    'AWS Access Key':       ('CRITICAL', r'AKIA[0-9A-Z]{16}'),
    'AWS Secret Key':       ('CRITICAL', r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})'),
    'AWS MWS Key':          ('HIGH',     r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    'GCP API Key':          ('CRITICAL', r'\bAIza[0-9A-Za-z\-_]{35}'),
    'GCP Service Account':  ('CRITICAL', r'"type"\s*:\s*"service_account"'),
    'Azure Storage Key':    ('CRITICAL', r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
    'Azure AD Client':      ('HIGH',     r'(?i)(?:client[_\-]?secret|ClientSecret)\s*[=:]\s*["\']?([A-Za-z0-9~._\-]{30,})'),
    'DigitalOcean Token':   ('CRITICAL', r'dop_v1_[a-f0-9]{64}'),
    'Heroku API Key':       ('CRITICAL', r'(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),

    # ── Source Control & CI/CD ────────────────────────────────────
    'GitHub Token':         ('CRITICAL', r'gh[ps]_[A-Za-z0-9_]{36}'),
    'GitHub Fine-Grained':  ('CRITICAL', r'github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}'),
    'GitLab Token':         ('CRITICAL', r'glpat-[A-Za-z0-9\-_]{20,}'),

    # ── Messaging & Communication ────────────────────────────────
    'Slack Token':          ('HIGH',     r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
    'Slack Webhook':        ('HIGH',     r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    'Discord Token':        ('CRITICAL', r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'),
    'Discord Webhook':      ('HIGH',     r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+'),
    'Telegram Token':       ('CRITICAL', r'\b\d{8,10}:[A-Za-z0-9_\-]{35}\b'),
    'Telegram Bot Config':  ('HIGH',     r'(?i)bot[_\-]?token\s*[=:]\s*["\']?(\d{8,10}:[A-Za-z0-9_\-]{35})'),

    # ── Payments ─────────────────────────────────────────────────
    'Stripe Live Key':      ('CRITICAL', r'sk_live_[0-9a-zA-Z]{24,}'),
    'Stripe Publishable':   ('MEDIUM',   r'pk_live_[0-9a-zA-Z]{24,}'),
    'Stripe Webhook':       ('HIGH',     r'whsec_[A-Za-z0-9]{32,}'),
    'PayPal Braintree':     ('CRITICAL', r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    'Square Token':         ('CRITICAL', r'sq0atp-[0-9A-Za-z\-_]{22}'),
    'Square OAuth':         ('CRITICAL', r'sq0csp-[0-9A-Za-z\-_]{43}'),

    # ── Maps & Location ──────────────────────────────────────────
    'Mapbox Token':         ('HIGH',     r'pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_\-]{20,}'),

    # ── Search & Analytics ───────────────────────────────────────
    'Algolia Key':          ('HIGH',     r'(?i)(?:algolia|ALGOLIA)[_\-]?(?:API|APP)[_\-]?KEY\s*[=:]\s*["\']?([a-f0-9]{32})'),

    # ── Monitoring & Observability ────────────────────────────────
    'Datadog API Key':      ('HIGH',     r'(?i)(?:datadog|dd)[_\-]?api[_\-]?key\s*[=:]\s*["\\x27]?([0-9a-f]{32})'),
    'New Relic Key':        ('HIGH',     r'NRAK-[A-Z0-9]{27}'),
    'Sentry DSN':           ('HIGH',     r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),

    # ── Auth Providers ───────────────────────────────────────────
    'Auth0 Key':            ('HIGH',     r'(?i)auth0.*client[_\-]?secret\s*[=:]\s*["\x27]?([A-Za-z0-9_\-]{32,})'),

    # ── Email & SMS ──────────────────────────────────────────────
    'Twilio SID':           ('HIGH',     r'\bAC[a-f0-9]{32}\b'),
    'Twilio Auth Token':    ('CRITICAL', r'(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*["\x27]?([a-f0-9]{32})'),
    'SendGrid Key':         ('HIGH',     r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'),
    'Mailgun Key':          ('HIGH',     r'key-[a-zA-Z0-9]{32}'),
    'Mailgun Webhook':      ('MEDIUM',   r'(?i)mailgun.*(?:signing[_\-]?key|api[_\-]?key)\s*[=:]\s*["\x27]?([a-zA-Z0-9\-]{32,})'),

    # ── Infrastructure & CDN ─────────────────────────────────────
    'Cloudflare API Token': ('CRITICAL', r'\bcf-[A-Za-z0-9_-]{35,}\b'),
    'Cloudflare Global':    ('HIGH',     r'v1\.0-[a-f0-9]{24}-[a-f0-9]{64}'),

    # ── Database Connection Strings ──────────────────────────────
    'MongoDB URI':          ('CRITICAL', r'mongodb(\+srv)?://[^\s"\'<>]{10,}'),
    'MySQL URI':            ('CRITICAL', r'mysql://[^\s"\'<>]{10,}'),
    'PostgreSQL URI':       ('CRITICAL', r'postgres(ql)?://[^\s"\'<>]{10,}'),
    'Redis URI':            ('HIGH',     r'redis://[^\s"\'<>]{5,}'),
    'AMQP URI':             ('HIGH',     r'amqp://[^\s"\'<>]{10,}'),

    # ── SSH & Crypto Keys ────────────────────────────────────────
    'RSA Private Key':      ('CRITICAL', r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    'DSA Private Key':      ('CRITICAL', r'-----BEGIN DSA PRIVATE KEY-----'),
    'OpenSSH Private Key':  ('CRITICAL', r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    'PGP Private Key':      ('CRITICAL', r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    'RSA Public Key':       ('HIGH',     r'-----BEGIN PUBLIC KEY-----'),
    'Generic Encryption':   ('HIGH',     r'(?i)(?:encrypt(?:ion)?[_\-]?key|ENCRYPTION_KEY)\s*[=:]\s*["\']?([A-Za-z0-9+/=]{16,})'),

    # ── Generic Credentials (catch-all) ──────────────────────────
    'API Key':              ('HIGH',     r'(?i)\bapi[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})\b'),
    'Auth Token':           ('HIGH',     r'(?i)\bauth[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})\b'),
    'Access Token':         ('HIGH',     r'(?i)\baccess[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})\b'),
    'Client Secret':        ('CRITICAL', r'(?i)\bclient[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})\b'),
    'Password':             ('HIGH',     r'(?i)\bpassword\s*[=:]\s*["\']([^"\']{8,})\b'),
    'Secret Key':           ('CRITICAL', r'(?i)\bsecret[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})\b'),
    'Private Key Value':    ('CRITICAL', r'(?i)\bprivate[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-/+=]{32,})\b'),
    'Bearer Token':         ('CRITICAL', r'\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b'),

    # ── Social Media ─────────────────────────────────────────────
    'Facebook Token':       ('HIGH',     r'EAACEdEose0cBA[0-9A-Za-z]{10,}'),
    'Facebook App Secret':  ('CRITICAL', r'(?i)(?:facebook|fb)[_\-]?(?:app)?[_\-]?secret\s*[=:]\s*["\']?([a-f0-9]{32})'),
    'Twitter Bearer':       ('HIGH',     r'(?i)(?:twitter|tw)[_\-]?bearer[_\-]?token\s*[=:]\s*["\']?([A-Za-z0-9\-_]{30,})'),

    # ── Misc Services ────────────────────────────────────────────
    'Firebase URL':         ('HIGH',     r'https://[a-zA-Z0-9\-]+\.firebaseio\.com'),
    'Firebase Config':      ('MEDIUM',   r'(?i)firebase[_\-]?config\s*[=:]\s*["\']?'),
    'Google OAuth':         ('HIGH',     r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    'Chatwoot Key':         ('HIGH',     r'(?i)chatwoot[^"\']{0,30}["\'][a-zA-Z0-9_\-]{20,}'),
    'NPM Token':            ('CRITICAL', r'npm_[A-Za-z0-9]{36}'),
    'PyPI Token':           ('CRITICAL', r'pypi-[A-Za-z0-9_\-]{50,}'),
    'Docker Hub Token':     ('HIGH',     r'(?i)docker[_\-]?(?:hub)?[_\-]?token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{30,})'),
    'Terraform Cloud':      ('CRITICAL', r'[A-Za-z0-9]{14}\.[A-Za-z0-9]{6}\.[A-Za-z0-9]{30,}'),
}

# Secret type descriptions — what each secret does and where it comes from
SECRET_DESC = {
    # Cloud Providers
    'AWS Access Key':       ('Used to authenticate API requests to Amazon Web Services. Found in code/config — enables access to S3, EC2, DynamoDB etc.'),
    'AWS Secret Key':       ('Paired with AWS Access Key to sign requests. Together they grant full AWS account access.'),
    'AWS MWS Key':          ('Amazon Marketplace Web Service key. Used for e-commerce integrations on AWS marketplace.'),
    'GCP API Key':          ('Google Cloud Platform API key. Authenticates requests to Google services (Firebase, Maps, Cloud Storage). Found in Firebase config or API client setup.'),
    'GCP Service Account':  ('Google Cloud service account JSON. Grants programmatic access to GCP resources with specific IAM roles.'),
    'Azure Storage Key':    ('Azure Storage account key. Full access to blob/table/queue storage.'),
    'Azure AD Client':      ('Azure Active Directory client secret. Used in OAuth2 flows for Microsoft identity platform.'),
    'DigitalOcean Token':   ('DigitalOcean API token. Manages droplets, databases, and other DO resources.'),
    'Heroku API Key':       ('Heroku platform API key. Manages apps, dynos, add-ons.'),
    'Mailgun API Key':      ('Mailgun email service API key. Sends transactional emails.'),
    'Twilio API Key':       ('Twilio API key. Sends SMS, makes voice calls, manages phone numbers.'),
    'SendGrid API Key':     ('SendGrid email delivery API key. Sends emails through Twilio SendGrid.'),
    'Stripe Publishable':   ('Stripe payment gateway publishable key. Used client-side for payment forms (safe to expose).'),
    'Stripe Secret':        ('Stripe payment gateway SECRET key. Full access to payments, customers, refunds — never expose!'),
    'Firebase URL':         ('Firebase Realtime Database URL. Identifies the database endpoint for read/write operations.'),
    'RapidAPI Key':         ('RapidAPI marketplace key. Accesses third-party APIs (weather, data, AI services).'),

    # Messaging & Tokens
    'Telegram Bot Token':   ('Telegram Bot API token. Controls the bot — sends messages, manages groups.'),
    'Discord Token':        ('Discord bot/user token. Full access to the Discord account or bot.'),
    'Slack Token':          ('Slack workspace API token. Accesses channels, messages, files.'),
    'GitHub Token':         ('GitHub personal access token. Accesses repos, issues, PRs — possibly with write access.'),
    'GitLab Token':         ('GitLab API token. Accesses repos, CI/CD pipelines.'),
    'Slack Webhook':        ('Slack incoming webhook URL. Posts messages to a specific Slack channel.'),
    'Google OAuth':         ('Google OAuth client secret. Used in OAuth2 login flows for Google Sign-In.'),
    'Facebook Access':      ('Facebook Graph API access token. Accesses user data, pages, ads.'),

    # JWT & Certificates
    'JWT Bearer':            ('JSON Web Token. Used for stateless authentication between client and server.'),
    'RSA Private Key':      ('RSA private key in PEM format. Used for encryption/decryption and digital signatures. Never should be in client code!'),
    'RSA Public Key':       ('RSA public key. Paired with private key for asymmetric encryption.'),
    'OpenSSH Private':      ('OpenSSH private key. Used for SSH server authentication.'),
    'PGP Private Key':      ('PGP/GPG private key. Used for email encryption and file signing.'),

    # Database & Auth
    'DB Connection':        ('Database connection string with credentials. Direct access to the app\'s database.'),
    'DB Password':          ('Database password found in config/code. Enables unauthorized DB access.'),
    'DB URI':               ('Full database URI with host, port, database name and credentials.'),
    'Firebase Key':         ('Firebase configuration — includes API key, project ID, and app ID. Connects the app to Firebase services.'),
    'Basic Auth':           ('HTTP Basic Authentication header. Base64-encoded username:password for API access.'),
    'Password in Code':     ('Hardcoded password in source code. Should be in environment variables or vault.'),
    'Hardcoded API Key':    ('Generic API key hardcoded in source. Should be loaded from environment or config.'),

    # DevOps
    'SSH Private Key':      ('SSH private key for server access. Grants shell access to remote machines.'),
    'Docker Registry':      ('Docker registry credentials. Accesses private container registries.'),
    'NPM Token':            ('NPM registry authentication token. Publishes packages to npmjs.com.'),
    'PyPI Token':           ('Python Package Index token. Uploads packages to PyPI.'),
    'Terraform Cloud':      ('Terraform Cloud API token. Manages infrastructure as code.'),
}

# Permissions: (risk, arabic_desc, english_desc)
# Arabic desc kept for report export only — never shown in terminal
DANGEROUS_PERMS = {
    'android.permission.READ_SMS':              ('CRITICAL', 'قراءة الرسائل النصية', 'SMS Reading'),
    'android.permission.RECEIVE_SMS':           ('CRITICAL', 'استقبال الرسائل', 'SMS Receiving'),
    'android.permission.SEND_SMS':              ('HIGH', 'إرسال رسائل نصية', 'Send SMS'),
    'android.permission.PROCESS_OUTGOING_CALLS': ('CRITICAL', 'اعتراض المكالمات', 'Intercept Calls'),
    'android.permission.READ_PHONE_STATE':      ('HIGH', 'حالة الهاتف (IMEI)', 'Phone State/IMEI'),
    'android.permission.READ_CONTACTS':         ('HIGH', 'قراءة جهات الاتصال', 'Read Contacts'),
    'android.permission.WRITE_CONTACTS':        ('HIGH', 'تعديل جهات الاتصال', 'Write Contacts'),
    'android.permission.READ_CALL_LOG':         ('HIGH', 'سجل المكالمات', 'Call Log'),
    'android.permission.GET_ACCOUNTS':          ('HIGH', 'حسابات الجهاز', 'Device Accounts'),
    'android.permission.SYSTEM_ALERT_WINDOW':   ('HIGH', 'الرسم فوق التطبيقات', 'Overlay'),
    'android.permission.REQUEST_INSTALL_PACKAGES': ('HIGH', 'تثبيت تطبيقات', 'Install APKs'),
    'android.permission.PACKAGE_USAGE_STATS':   ('HIGH', 'إحصائيات التطبيقات', 'App Usage Stats'),
    'android.permission.ACCESS_FINE_LOCATION':  ('HIGH', 'الموقع الدقيق GPS', 'Precise Location'),
    'android.permission.CAMERA':                ('MEDIUM', 'الكاميرا', 'Camera'),
    'android.permission.RECORD_AUDIO':          ('MEDIUM', 'الميكروفون', 'Microphone'),
    'android.permission.READ_EXTERNAL_STORAGE': ('MEDIUM', 'قراءة التخزين', 'Storage Read'),
    'android.permission.WRITE_EXTERNAL_STORAGE': ('MEDIUM', 'كتابة التخزين', 'Storage Write'),
    'android.permission.READ_MEDIA_IMAGES':     ('MEDIUM', 'قراءة الصور', 'Read Images'),
    'android.permission.READ_MEDIA_VIDEO':      ('MEDIUM', 'قراءة الفيديو', 'Read Video'),
    'android.permission.ACCESS_COARSE_LOCATION': ('MEDIUM', 'الموقع التقريبي', 'Coarse Location'),
    'android.permission.RECEIVE_BOOT_COMPLETED': ('MEDIUM', 'التشغيل التلقائي', 'Boot Start'),
    'android.permission.USE_BIOMETRIC':         ('MEDIUM', 'البصمة البيومترية', 'Biometric'),
    'android.permission.FOREGROUND_SERVICE':    ('LOW', 'خدمة أمامية', 'Foreground Service'),
    'android.permission.BLUETOOTH':             ('LOW', 'البلوتوث', 'Bluetooth'),
    'android.permission.BLUETOOTH_CONNECT':     ('LOW', 'اتصال البلوتوث', 'BT Connect'),
    'android.permission.CHANGE_WIFI_STATE':     ('LOW', 'تغيير الواي فاي', 'WiFi Control'),
    'android.permission.NFC':                   ('LOW', 'NFC', 'NFC'),
    'android.permission.INTERNET':              ('INFO', 'الإنترنت', 'Internet'),
    'android.permission.VIBRATE':               ('INFO', 'الاهتزاز', 'Vibrate'),
    'android.permission.WAKE_LOCK':             ('INFO', 'منع النوم', 'Wake Lock'),
    'android.permission.ACCESS_NETWORK_STATE':  ('INFO', 'حالة الشبكة', 'Network State'),
}

FRAMEWORKS = {
    'React Native': ['com.facebook.react', 'ReactNativeHost', 'ReactActivity', 'index.android.bundle'],
    'Flutter': ['io.flutter', 'FlutterActivity', 'libflutter.so', 'flutter_assets'],
    'Xamarin': ['mono.android', 'Xamarin', 'xamarin.android'],
    'Cordova': ['org.apache.cordova', 'CordovaActivity'],
    'Unity': ['com.unity3d', 'UnityPlayer', 'libunity.so'],
    'Kotlin': ['kotlin/', 'kotlinx/', 'kotlin-stdlib'],
    'Go (Golang)': ['libgojni.so', 'Go build ID', 'runtime.goexit'],
    'C/C++ Native': ['libapp.so', 'libmain.so', 'libnative-lib.so'],
    'Compose': ['androidx.compose', 'Composable'],
}

LIBRARIES = {
    'OkHttp': ['okhttp3', 'OkHttpClient'], 'Retrofit': ['retrofit2', 'Retrofit', '@GET(', '@POST('],
    'Glide': ['com.bumptech.glide', 'GlideApp'], 'Picasso': ['com.squareup.picasso'],
    'Firebase': ['com.google.firebase', 'FirebaseApp'], 'SQLite': ['android.database.sqlite'],
    'Realm': ['io.realm', 'RealmObject'], 'Room DB': ['androidx.room', 'RoomDatabase'],
    'RxJava': ['io.reactivex', 'Observable'], 'Gson': ['com.google.gson'],
    'Jackson': ['com.fasterxml.jackson'], 'Volley': ['com.android.volley'],
    'Facebook SDK': ['com.facebook.sdk'], 'Google Analytics': ['com.google.android.gms.analytics'],
    'Crashlytics': ['com.crashlytics'], 'Chatwoot': ['chatwoot'],
    'Intercom': ['io.intercom'], 'AppsFlyer': ['com.appsflyer'],
    'Adjust': ['com.adjust.sdk'], 'Braze': ['com.braze'],
    'Lottie': ['com.airbnb.lottie'], 'Stripe': ['com.stripe.android'],
    'PayPal': ['com.paypal.android'], 'Dagger/Hilt': ['dagger.android', 'hilt_'],
    'Sentry': ['io.sentry'], 'Amplitude': ['com.amplitude'],
    'Mixpanel': ['com.mixpanel'], 'OneSignal': ['com.onesignal'],
    'Koin': ['org.koin'], 'Coil': ['coil.compose', 'io.coil'],
    'Ktor': ['io.ktor'], 'Moshi': ['com.squareup.moshi'],
}

SSL_BY  = ['setHostnameVerifier', 'ALLOW_ALL_HOSTNAME_VERIFIER', 'checkServerTrusted',
           'X509TrustManager', 'onReceivedSslError', 'TrustAll', 'NullX509TrustManager',
           'IGNORE_SSL', 'SSLCertificateSocketFactory', 'setDefaultHostnameVerifier']
WEAK_C  = ['MD5', 'DES ', 'RC4', 'ECB', 'SHA1withRSA', 'PBEWITH', 'Blowfish', 'DESede']
DEBUG_F = ['android:debuggable', 'debuggable=true', 'BuildConfig.DEBUG',
           'setWebContentsDebuggingEnabled', 'Log.d(', 'Log.e(', 'Log.v(', 'StrictMode']
SQL_S   = ['SELECT * FROM', 'DROP TABLE', 'DELETE FROM', 'INSERT INTO',
           'rawQuery', 'execSQL', 'UNION SELECT']
ROOT_D  = ['RootBeer', 'isRooted', 'isDeviceRooted', 'su binary',
           '/system/app/Superuser.apk', 'com.noshufou.android.su', 'SafetyNet']
ANTI_H  = ['frida', 'xposed', 'substrate', 'anti-hook', 'ptrace',
           'TracerPid', 'IsDebuggerPresent', 'magisk']
WEBVIEW_JS = ['setJavaScriptEnabled(true)', 'addJavascriptInterface',
              'evaluateJavascript', 'WebView.loadUrl("javascript']

# App type keys: English only in terminal; Arabic added in reports when --lang ar
APP_TYPES = {
    'Payment':    ['payment', 'transaction', 'invoice', 'wallet', 'transfer', 'pay'],
    'Auth':       ['login', 'authenticate', 'two-factor', 'otp', 'biometric', 'signup'],
    'E-commerce': ['cart', 'checkout', 'product', 'catalog', 'order', 'shop'],
    'Social':     ['message', 'chat', 'friend', 'notification', 'feed', 'post'],
    'Maps':       ['location', 'map', 'gps', 'navigation', 'latitude', 'longitude'],
    'Banking':    ['bank', 'account', 'balance', 'deposit', 'withdraw', 'iban'],
    'Admin':      ['admin', 'dashboard', 'management', 'report', 'statistics'],
    'Support':    ['support', 'ticket', 'help', 'chatwoot', 'intercom', 'zendesk'],
    'Health':     ['health', 'medical', 'patient', 'doctor', 'prescription'],
    'Education':  ['learn', 'course', 'student', 'teacher', 'exam', 'quiz'],
    'Media':      ['video', 'audio', 'stream', 'player', 'music', 'podcast'],
}

# Arabic translations for report export (--lang ar)
APP_TYPES_AR = {
    'Payment': 'مالي', 'Auth': 'مصادقة', 'E-commerce': 'تجارة',
    'Social': 'تواصل', 'Maps': 'خرائط', 'Banking': 'بنكي',
    'Admin': 'إدارة', 'Support': 'دعم', 'Health': 'صحة',
    'Education': 'تعليم', 'Media': 'وسائط', 'General': 'عام',
}

# ═══════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════

def validate_apk(path: str) -> tuple:
    """Pre-validate APK before analysis. Returns (ok, message)."""
    p = Path(path)
    if not p.exists():
        return False, f"File not found: {path}"
    if p.suffix.lower() not in ('.apk', '.xapk'):
        return False, f"Not an APK file (got {p.suffix}): {path}"
    if p.stat().st_size < 1024:
        return False, f"File too small ({p.stat().st_size} bytes) — probably corrupted"
    if p.stat().st_size > 500 * 1024 * 1024:
        mb = p.stat().st_size / (1024 * 1024)
        return False, f"File too large ({mb:.0f} MB) — max 500 MB"
    try:
        with zipfile.ZipFile(str(p)) as z:
            if not any(n.endswith('.dex') for n in z.namelist()):
                return False, "Invalid APK: no DEX files inside"
    except zipfile.BadZipFile:
        return False, "Invalid APK: not a valid ZIP archive"
    return True, "OK"


def _iss(title, risk, desc, rec, ex=None):
    return {'title': title, 'risk': risk, 'desc': desc, 'rec': rec, 'ex': ex or []}


# ═══════════════════════════════════════════════════════════════════════
# ANALYZER ENGINE
# ═══════════════════════════════════════════════════════════════════════

# ── Smart filtering for secrets ──────────────────────────────────────────
def _is_flutter_app(txt):
    """Detect if the app is built with Flutter/Dart."""
    flutter_indicators = ['flutter', 'dart', 'dartlang', 'dart:core', 'dart:ui', 
                         'dart:async', 'dart:convert', 'dart:io', 'dart:ffi']
    dart_indicators = ['pubspec.yaml', 'dart_tool', '.dart_tool', 'package:flutter']
    
    # Check for Flutter indicators
    for indicator in flutter_indicators:
        if indicator.lower() in txt.lower():
            return True
    
    # Check for Dart package structure
    for indicator in dart_indicators:
        if indicator.lower() in txt.lower():
            return True
    
    return False

def _is_binary_noise(val):
    """Check if a value looks like binary noise (common in Flutter apps).
    Uses Shannon entropy — values above 4.5 bits/char are likely random.
    """
    import math
    if len(val) < 16:
        return False

    # Shannon entropy calculation
    freq = {}
    for c in val:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((cnt / len(val)) * math.log2(cnt / len(val)) for cnt in freq.values())

    # High entropy threshold — real secrets rarely exceed 4.5 bits/char
    # (e.g., AWS key AKIA... ≈ 3.5, UUID ≈ 3.8, base64 random ≈ 5.0+)
    if entropy > 4.5:
        return True
    return False

def _is_likely_false_positive(label, val, txt):
    """Determine if a detected secret is likely a false positive."""
    # Flutter apps have lots of random strings
    if _is_flutter_app(txt):
        # Check if the value appears in binary/library contexts
        flutter_noise_patterns = [
            r'NSt[0-9]_',  # C++ STL namespace prefixes
            r'_GLOBAL_',   # Global symbols
            r'__.*__',     # Dunder methods
            r'^[A-Z][a-z]+[A-Z]',  # CamelCase class names
            r'^[a-z]+_[a-z]+_',    # Snake case with prefix
        ]
        
        for pattern in flutter_noise_patterns:
            if re.search(pattern, val):
                return True
        
        # Check if value is likely binary noise
        if _is_binary_noise(val):
            return True
    
    # Common false positive patterns
    fp_patterns = [
        r'^test', r'^example', r'^dummy', r'^sample',
        r'^xxx', r'^placeholder', r'^your_', r'^my_',
        r'<.*>',  # HTML/XML tags
        r'\{.*\}',  # JSON-like
        r'\[.*\]',  # Array-like
    ]
    
    val_lower = val.lower()
    for pattern in fp_patterns:
        if re.search(pattern, val_lower):
            return True
    
    return False


class NightOwlAnalyzer:
    def __init__(self, apk_path: str, lang: str = 'en'):
        self.path = Path(apk_path).resolve()
        self.lang = lang  # 'en' (default) or 'ar' for Arabic reports
        self.strings: list = []
        self.txt = ""
        self.d = {
            'tool': f'NightOwl v{__version__}', 'ts': datetime.now().isoformat(),
            'apk': str(self.path),
            'info': {}, 'perms': {'all': [], 'dangerous': [], 'normal': []},
            'endpoints': {'urls': [], 'api': [], 'servers': [], 'domains': [], 'ips': [], 'emails': []},
            'secrets': [], 'security': {'issues': [], 'score': 100},
            'arch': {}, 'vulns': [], 'desc': {}, 'manifest': {}, 'components': {}, 'cert': {},
        }

    # ── String Extraction ─────────────────────────────────────────────
    def extract_strings(self):
        found = set()
        exts = ('.dex', '.xml', '.json', '.properties', '.config', '.txt',
                '.html', '.js', '.yml', '.yaml', '.ini', '.cfg', '.csv', '.smali')
        with zipfile.ZipFile(str(self.path)) as z:
            for fn in z.namelist():
                if fn.endswith(exts) or fn.startswith('assets/'):
                    try:
                        data = z.read(fn)
                        for s in re.findall(rb'[\x20-\x7e]{6,}', data):
                            d = s.decode('utf-8', errors='ignore').strip()
                            if d and len(d) >= 6:
                                found.add(d)
                    except Exception:
                        pass
            for fn in z.namelist():
                if re.match(r'classes\d*\.dex', fn):
                    try:
                        data = z.read(fn)
                        for s in re.findall(rb'[\x20-\x7e]{8,}', data):
                            d = s.decode('utf-8', errors='ignore').strip()
                            if d:
                                found.add(d)
                    except Exception:
                        pass
        self.strings = list(found)
        self.txt = '\n'.join(self.strings)
        # Always extract native lib strings (critical for Flutter apps)
        self.extract_strings_native(found)
        self.txt = '\n'.join(self.strings)

    def extract_strings_native(self, found: set = None):
        """Extract strings from native .so libs — essential for Flutter/NDK apps.

        Flutter apps store ALL Dart code in libapp.so. The DEX layer is
        essentially empty, so API URLs only appear in native memory.
        """
        import subprocess, tempfile
        if found is None:
            found = set(self.strings)

        native_count = 0
        try:
            with zipfile.ZipFile(str(self.path)) as z:
                so_files = [n for n in z.namelist() if n.endswith('.so')]
                # Prioritize libapp.so and libflutter.so
                so_files.sort(key=lambda x: (
                    0 if 'libapp' in x else
                    1 if 'libflutter' in x else 2
                ))
                for so_fn in so_files[:8]:  # cap at 8 to avoid huge binaries
                    try:
                        data = z.read(so_fn)
                        # Direct regex extraction (fast, no subprocess needed)
                        for s in re.findall(rb'[\x20-\x7e]{8,}', data):
                            try:
                                d = s.decode('utf-8', errors='ignore').strip()
                                if d and len(d) >= 8:
                                    found.add(d)
                                    native_count += 1
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception:
            pass
        self.strings = list(found)
        self.d['_native_strings_count'] = native_count
        return native_count

    def _mk_apk(self):
        """Create AndroAPK object, suppressing API-level stderr noise."""
        import io, contextlib
        with contextlib.redirect_stderr(io.StringIO()):
            return AndroAPK(str(self.path))

    # ── 1. Basic Info ─────────────────────────────────────────────────
    def analyze_info(self):
        bi = self.d['info']
        raw = self.path.read_bytes()
        st = self.path.stat()
        bi['file_name'] = self.path.name
        bi['file_size_mb'] = round(st.st_size / (1024 * 1024), 2)
        bi['file_size_bytes'] = st.st_size
        bi['md5'] = hashlib.md5(raw).hexdigest()
        bi['sha1'] = hashlib.sha1(raw).hexdigest()
        bi['sha256'] = hashlib.sha256(raw).hexdigest()
        if AG:
            a = self._mk_apk()
            bi['package'] = a.get_package() or 'N/A'
            try:
                bi['version_name'] = a.get_androidversion_name() or 'N/A'
            except (KeyError, AttributeError, Exception):
                bi['version_name'] = 'N/A'
            try:
                bi['version_code'] = a.get_androidversion_code() or 'N/A'
            except (KeyError, AttributeError, Exception):
                bi['version_code'] = 'N/A'
            bi['min_sdk'] = a.get_min_sdk_version() or 'N/A'
            bi['target_sdk'] = a.get_target_sdk_version() or 'N/A'
            bi['main_activity'] = a.get_main_activity() or 'N/A'
            bi['activities'] = len(a.get_activities())
            bi['services'] = len(a.get_services())
            bi['receivers'] = len(a.get_receivers())
            bi['providers'] = len(a.get_providers())
            bi['libraries'] = a.get_libraries()
            try:
                v3 = a.get_certificates_der_v3()
                v2 = a.get_certificates_der_v2()
                bi['signed'] = bool(v3 or v2)
                bi['sign_scheme'] = 'v3' if v3 else ('v2' if v2 else 'v1/unknown')
            except Exception:
                bi['signed'] = True
                bi['sign_scheme'] = 'unknown'
        else:
            bi['package'] = 'N/A (install androguard)'
        with zipfile.ZipFile(str(self.path)) as z:
            files = z.namelist()
            bi['total_files'] = len(files)
            bi['dex_count'] = sum(1 for f in files if re.match(r'classes\d*\.dex', f))
            bi['has_native'] = any(f.endswith('.so') for f in files)
            bi['native_libs'] = [f for f in files if f.endswith('.so')]
            bi['has_assets'] = any(f.startswith('assets/') for f in files)
            bi['has_net_config'] = 'res/xml/network_security_config.xml' in files
            bi['has_backup_rules'] = any('backup_rules' in f for f in files)

    # ── 1b. Certificate Analysis ─────────────────────────────────────────
    def analyze_cert(self):
        """Extract detailed signing certificate information."""
        if not AG:
            return
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        except ImportError:
            self.d['cert'] = {'status': 'unavailable', 'warning': 'cryptography library not installed'}
            return

        a = self._mk_apk()
        certs_der = []
        scheme = 'unknown'

        # Try v3 first, then v2, then v1
        try:
            v3 = a.get_certificates_der_v3()
            if v3:
                certs_der = v3
                scheme = 'v3'
        except Exception:
            pass
        if not certs_der:
            try:
                v2 = a.get_certificates_der_v2()
                if v2:
                    certs_der = v2
                    scheme = 'v2'
            except Exception:
                pass
        if not certs_der:
            try:
                v1 = a.get_certificates_der_v1()
                if v1:
                    certs_der = v1
                    scheme = 'v1'
            except Exception:
                pass

        if not certs_der:
            self.d['cert'] = {'status': 'unsigned', 'warning': 'No signing certificate found'}
            return

        warnings = []
        cert_details = []

        for der_bytes in certs_der:
            try:
                cert = x509.load_der_x509_certificate(der_bytes, default_backend())
            except Exception as e:
                warnings.append(f'Failed to parse certificate: {e}')
                continue

            detail = {}

            # Subject
            try:
                subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                detail['subject'] = subject_cn[0].value if subject_cn else 'N/A'
            except Exception:
                detail['subject'] = 'N/A'

            # Issuer
            try:
                issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                detail['issuer_cn'] = issuer_cn[0].value if issuer_cn else 'N/A'
                detail['issuer_org'] = issuer_org[0].value if issuer_org else 'N/A'
            except Exception:
                detail['issuer_cn'] = 'N/A'
                detail['issuer_org'] = 'N/A'

            # Validity
            try:
                detail['valid_from'] = cert.not_valid_before_utc.isoformat()
                detail['valid_until'] = cert.not_valid_after_utc.isoformat()
                now = datetime.now().astimezone()
                if cert.not_valid_after_utc.replace(tzinfo=None) < datetime.now():
                    warnings.append(f'Certificate EXPIRED on {detail["valid_until"]}')
                days_left = (cert.not_valid_after_utc.replace(tzinfo=None) - datetime.now()).days
                detail['days_remaining'] = days_left
                if 0 < days_left < 90:
                    warnings.append(f'Certificate expires in {days_left} days')
            except Exception:
                detail['valid_from'] = '?'
                detail['valid_until'] = '?'

            # Key size
            try:
                pub_key = cert.public_key()
                detail['key_size'] = pub_key.key_size
                detail['key_type'] = type(pub_key).__name__.replace('PublicKey', '').replace('EllipticCurve', 'EC')
                if hasattr(pub_key, 'key_size') and pub_key.key_size < 2048 and 'EC' not in detail['key_type']:
                    warnings.append(f'Weak key size: {pub_key.key_size} bits (recommended >= 2048)')
            except Exception:
                detail['key_size'] = '?'
                detail['key_type'] = '?'

            # Signature algorithm
            try:
                detail['sig_algorithm'] = cert.signature_algorithm_oid._name
            except Exception:
                detail['sig_algorithm'] = '?'

            # Serial number
            try:
                detail['serial'] = format(cert.serial_number, 'x')
            except Exception:
                detail['serial'] = '?'

            # SHA256 fingerprint
            try:
                import hashlib as _hl
                detail['sha256_fingerprint'] = _hl.sha256(der_bytes).hexdigest()
            except Exception:
                pass

            cert_details.append(detail)

        if not cert_details:
            self.d['cert'] = {'status': 'error', 'warning': 'No certificates could be parsed'}
            return

        primary = cert_details[0]
        self.d['cert'] = {
            'status': 'valid' if not any('EXPIRED' in w for w in warnings) else 'expired',
            'scheme': scheme,
            'subject': primary.get('subject', '?'),
            'issuer': primary.get('issuer_org', '?'),
            'issuer_cn': primary.get('issuer_cn', '?'),
            'valid_from': primary.get('valid_from', '?'),
            'valid_until': primary.get('valid_until', '?'),
            'days_remaining': primary.get('days_remaining', '?'),
            'key_size': primary.get('key_size', '?'),
            'key_type': primary.get('key_type', '?'),
            'sig_algorithm': primary.get('sig_algorithm', '?'),
            'serial': primary.get('serial', '?'),
            'sha256_fingerprint': primary.get('sha256_fingerprint', '?'),
            'warnings': warnings,
            'warning': '; '.join(warnings) if warnings else None,
            'all_certs_count': len(cert_details),
        }

    # ── 2. Permissions ────────────────────────────────────────────────
    def analyze_perms(self):
        if not AG:
            return
        a = self._mk_apk()
        for p in a.get_permissions():
            if p in DANGEROUS_PERMS:
                risk, ar, en = DANGEROUS_PERMS[p]
                e = {'name': p, 'risk': risk, 'desc_ar': ar, 'desc_en': en}
                self.d['perms']['dangerous'].append(e)
            else:
                short = p.split('.')[-1] if '.' in p else p
                e = {'name': p, 'risk': 'INFO', 'desc_ar': short, 'desc_en': short}
                self.d['perms']['normal'].append(e)
            self.d['perms']['all'].append(e)

    # ── 3. Endpoints ──────────────────────────────────────────────────
    def analyze_endpoints(self):
        urls, servers, apis = set(), set(), set()
        for url in URL_RE.findall(self.txt):
            url = url.rstrip('.,;"\')>}]')
            if any(n in url for n in NOISE) or len(url) < 12:
                continue
            urls.add(url)
            m = re.match(r'(https?://[^/?#]+)', url)
            if m:
                servers.add(m.group(1))
        for pat in [r'/api/v?\d+/[a-zA-Z0-9/_\-]{3,}',
                    r'/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+\.(?:php|json|xml|do|action|aspx)',
                    r'(?:endpoint|baseurl|api_?url|BASE_URL)[^"\']{0,5}["\']([^"\']{10,})']:
            apis.update(re.findall(pat, self.txt, re.IGNORECASE))
        domains = set(DOMAIN_RE.findall(self.txt))
        domains -= {d for d in domains if any(n.replace('https://', '').replace('http://', '') in d for n in NOISE)}
        ips = set(IP_RE.findall(self.txt))
        ips -= {ip for ip in ips if re.match(r'^(127\.|0\.0\.|255\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', ip)}
        emails = set(EMAIL_RE.findall(self.txt))
        emails = {e for e in emails
                  if not any(n in e for n in ['example.com', 'android.com', 'google.com',
                                               'apache.org', 'junit', 'java.', 'javax.',
                                               'flutter', 'dart', 'schemas.', 'openssl'])
                  and '@' in e
                  and len(e.split('@')[0]) >= 3
                  and not re.search(r'[A-Z]{3}', e.split('@')[0])  # skip ALL CAPS local parts
                  }
        self.d['endpoints'].update({
            'urls': sorted(urls)[:500], 'servers': sorted(servers),
            'api': sorted(apis)[:200], 'domains': sorted(domains)[:100],
            'ips': sorted(ips), 'emails': sorted(emails)[:50],
        })

    # ── 3b. Deep API Extraction ───────────────────────────────────────
    def analyze_apis(self):
        """Deep API call analysis: Retrofit, OkHttp, Volley, URL patterns.

        Works on both DEX-based and Flutter/native apps because it scans
        the combined string pool (DEX + libapp.so + assets).
        """
        txt = self.txt
        apis = self.d['endpoints'].get('api', [])
        api_set = set(apis)

        # Clean URL path pattern: starts with / only has URL-safe chars
        _clean_path = re.compile(r'^/[a-zA-Z0-9/_.\-]{3,}$')

        # Retrofit-style annotations
        for m in re.finditer(
            r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\s*\(\s*["\']([^"\']{3,})["\']',
            txt, re.IGNORECASE
        ):
            v = m.group(1)
            if _clean_path.match(v):
                api_set.add(v)

        # OkHttp / URLConnection — only clean quoted paths
        for m in re.finditer(
            r'(?:url|baseUrl|endpoint|path|route)\s*[=:]\s*"(/[a-zA-Z0-9/_.\-]{3,})"',
            txt, re.IGNORECASE
        ):
            api_set.add(m.group(1))

        # Full URLs anywhere in strings (already cleaned by URL_RE + NOISE)
        for m in re.finditer(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,}', txt):
            u = m.group(0).rstrip('.,;"\')>')
            if not any(n in u for n in NOISE) and len(u) >= 12:
                api_set.add(u)

        # Auth/token patterns (flag as sensitive endpoints)
        auth_hits = []
        for m in re.finditer(
            r'(?i)(api[_-]?key|auth[_-]?token|authorization|x-api-key'
            r'|client[_-]?secret|access[_-]?token)\s*[=:]\s*"([^"]{8,})"',
            txt
        ):
            val = m.group(2)
            if re.match(r'^[a-zA-Z0-9._\-/+=]{8,}$', val):
                auth_hits.append(f"{m.group(1)}: {val[:50]}")

        # Base URL patterns common in mobile apps
        for m in re.finditer(
            r'(?:BASE_URL|base_url|API_URL|api_url|SERVER_URL)\s*[=:]\s*"([^"]{8,})"',
            txt, re.IGNORECASE
        ):
            v = m.group(1)
            if v.startswith('http') or v.startswith('/'):
                api_set.add(v)

        self.d['endpoints']['api'] = sorted(api_set)[:300]
        self.d['endpoints']['auth_patterns'] = auth_hits[:20]

    # ── 4. Secrets ────────────────────────────────────────────────────
    def analyze_secrets(self):
        seen, results = set(), []
        is_flutter = _is_flutter_app(self.txt)

        # Pre-split text for context extraction
        txt_lines = self.txt.split('\n')

        for label, (risk, pattern) in SECRET_PAT.items():
            try:
                for m in re.finditer(pattern, self.txt, re.IGNORECASE):
                    val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    val = val.strip().strip('"\'')
                    if len(val) < 8:
                        continue

                    # Apply smart filtering
                    if _is_likely_false_positive(label, val, self.txt):
                        continue

                    key = f"{label}:{val[:20]}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # Additional context check for Flutter apps
                    if is_flutter:
                        # Skip if value appears to be a class/method name
                        if re.match(r'^[A-Z][a-z]+[A-Z][a-z]+', val):  # CamelCase
                            continue
                        # Skip if value is very long and random-looking
                        if len(val) > 40 and len(set(val)) / len(val) > 0.6:
                            continue

                    # Find context: surrounding code (2 lines before the match)
                    match_pos = m.start()
                    char_count = 0
                    ctx_line = 0
                    for li, l in enumerate(txt_lines):
                        char_count += len(l) + 1
                        if char_count >= match_pos:
                            ctx_line = li
                            break
                    ctx_start = max(0, ctx_line - 1)
                    ctx_end = min(len(txt_lines), ctx_line + 2)
                    context = '\n'.join(txt_lines[ctx_start:ctx_end]).strip()[:300]

                    # Determine file/source location from context
                    source = 'DEX strings'
                    if '.so' in context or 'lib' in context:
                        source = 'Native library (.so)'
                    elif 'xml' in context.lower():
                        source = 'XML resource'
                    elif 'flutter' in context.lower():
                        source = 'Flutter/Dart code'
                    elif 'assets' in context.lower():
                        source = 'Assets folder'

                    # Get description
                    desc = SECRET_DESC.get(label, 'Hardcoded credential — review and remove from source code.')

                    results.append({
                        'type': label,
                        'value': val,           # FULL value, not masked
                        'risk': risk,
                        'raw_len': len(val),
                        'source': source,
                        'context': context,
                        'description': desc,
                    })
            except re.error:
                pass

        # Sort by risk (CRITICAL first)
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        results.sort(key=lambda x: risk_order.get(x['risk'], 99))

        # Limit results to prevent overwhelming output
        self.d['secrets'] = results[:50]
        
        # If we have a Flutter app with many results, add a note
        if is_flutter and len(results) > 10:
            self.d['secrets_note'] = "Flutter app detected - some results may be framework artifacts"


    def analyze_security(self):
        issues, txt = [], self.txt

        # Detect if debug build (affects scoring)
        is_debug = any(s in txt for s in ['android:debuggable', 'debuggable=true',
                                           'BuildConfig.DEBUG'])

        http = [u for u in self.d['endpoints']['urls'] if u.startswith('http://')]
        if http:
            issues.append(_iss('Insecure HTTP', 'HIGH',
                f'{len(http)} URLs use unencrypted HTTP',
                'Use HTTPS for all connections', http[:5]))
        ssl = [s for s in SSL_BY if s in txt]
        if ssl:
            issues.append(_iss('SSL Bypass', 'CRITICAL',
                'SSL certificate validation bypass detected',
                'Never bypass TLS in production', ssl))
        dbg = [s for s in DEBUG_F if s in txt]
        if dbg:
            risk = 'MEDIUM' if is_debug else 'HIGH'
            issues.append(_iss('Debug Mode', risk,
                f'Debug flags found (debug_build={is_debug})',
                'Disable debug in production builds', dbg))
        cry = [c for c in WEAK_C if c in txt]
        if cry:
            issues.append(_iss('Weak Crypto', 'HIGH',
                f'Weak algorithms: {", ".join(cry)}',
                'Use AES-256-GCM, SHA-256+', cry))
        real_ips = list(self.d['endpoints']['ips'])
        if real_ips:
            issues.append(_iss('Hardcoded IPs', 'MEDIUM',
                f'{len(real_ips)} hardcoded IP addresses found',
                'Use DNS hostnames instead of hardcoded IPs', real_ips[:5]))
        devp = list(set(DEV_RE.findall(txt)))
        if devp:
            issues.append(_iss('Developer Paths', 'LOW',
                'Developer paths leaked in binary',
                'Strip paths from release builds', devp[:5]))
        sqls = [s for s in SQL_S if s.lower() in txt.lower()]
        if sqls:
            issues.append(_iss('Raw SQL', 'MEDIUM',
                'Raw SQL queries found',
                'Use parameterized queries', sqls))
        wv = [s for s in WEBVIEW_JS if s in txt]
        if wv:
            issues.append(_iss('WebView JS Enabled', 'MEDIUM',
                'JavaScript enabled in WebView',
                'Validate WebView URLs, restrict JS interfaces', wv))
        root = [s for s in ROOT_D if s in txt]
        if root:
            issues.append(_iss('Root Detection', 'INFO',
                'Root detection present',
                'Verify it resists Frida bypass', root))
        hook = [s for s in ANTI_H if s.lower() in txt.lower()]
        if hook:
            issues.append(_iss('Anti-Hook', 'INFO',
                'Anti-debug/hook mechanisms found',
                'Test bypass in dynamic analysis', hook))
        if not self.d['info'].get('has_net_config'):
            issues.append(_iss('No Network Config', 'LOW',
                'Missing network_security_config.xml',
                'Add network security config', []))
        if not self.d['info'].get('has_backup_rules'):
            issues.append(_iss('Backup Risk', 'LOW',
                'No backup rules — data may be extractable',
                'Set allowBackup=false', []))

        # ── Enhanced scoring (v2) ──────────────────────────────────
        # Base penalties by risk
        base_pen = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2, 'INFO': 0}

        # Category weights (multiply base penalty)
        cat_weight = {
            'SSL Bypass': 1.5,       # Most dangerous in practice
            'Insecure HTTP': 1.3,    # Real data exposure
            'Debug Mode': 1.0 if not is_debug else 0.3,  # Less bad in debug builds
            'Weak Crypto': 1.2,
            'Raw SQL': 1.1,
            'WebView JS Enabled': 1.2,
            'Hardcoded IPs': 0.8,
            'Developer Paths': 0.5,
            'No Network Config': 0.7,
            'Backup Risk': 0.6,
        }

        # Combination rules (escalation when multiple issues interact)
        issue_titles = {i['title'] for i in issues}
        combos = []
        if 'SSL Bypass' in issue_titles and 'Insecure HTTP' in issue_titles:
            combos.append(('CRITICAL', 'SSL Bypass + Cleartext HTTP',
                          'Complete traffic interception possible', 'Network'))
        if 'SSL Bypass' in issue_titles and 'Weak Crypto' in issue_titles:
            combos.append(('CRITICAL', 'SSL Bypass + Weak Crypto',
                          'Encrypted data also compromisable', 'Crypto'))
        if 'Debug Mode' in issue_titles and 'WebView JS Enabled' in issue_titles:
            combos.append(('HIGH', 'Debug + WebView JS',
                          'Remote code execution via debuggable WebView', 'WebView'))
        if 'Weak Crypto' in issue_titles and self.d['secrets']:
            combos.append(('HIGH', 'Weak Crypto + Hardcoded Secrets',
                          'Secrets protected by weak encryption', 'Secrets'))

        # Compute per-category scores
        categories = {
            'Network': {'pen': 0, 'issues': 0},
            'Secrets': {'pen': 0, 'issues': 0},
            'Crypto': {'pen': 0, 'issues': 0},
            'Code Quality': {'pen': 0, 'issues': 0},
            'Permissions': {'pen': 0, 'issues': 0},
            'WebView': {'pen': 0, 'issues': 0},
        }
        cat_map = {
            'SSL Bypass': 'Network', 'Insecure HTTP': 'Network',
            'No Network Config': 'Network', 'Hardcoded IPs': 'Network',
            'Weak Crypto': 'Crypto',
            'Debug Mode': 'Code Quality', 'Developer Paths': 'Code Quality',
            'Raw SQL': 'Code Quality', 'Backup Risk': 'Code Quality',
            'WebView JS Enabled': 'WebView',
        }

        total_pen = 0
        for i in issues:
            bp = base_pen.get(i['risk'], 0)
            w = cat_weight.get(i['title'], 1.0)
            pen = round(bp * w)
            total_pen += pen
            cat = cat_map.get(i['title'], 'Code Quality')
            categories[cat]['pen'] += pen
            categories[cat]['issues'] += 1

        # Secrets penalty (smart capping based on app type)
        secrets_pen = 0
        max_secrets_pen = 25  # Maximum penalty from secrets (reduced from 30)
        is_flutter = _is_flutter_app(txt)
        
        # Adjust max penalty based on app type
        if is_flutter:
            max_secrets_pen = 15  # Flutter apps get more lenient scoring
        
        # Count actual issues (not just secrets)
        actual_secrets_issues = 0
        for s in self.d['secrets']:
            sp = base_pen.get(s['risk'], 0)
            # Only count if not a likely false positive
            if not _is_likely_false_positive(s['type'], s.get('value', ''), txt):
                actual_secrets_issues += 1
                categories['Secrets']['issues'] += 1
                if secrets_pen < max_secrets_pen:
                    add = min(sp, max_secrets_pen - secrets_pen)
                    secrets_pen += add
                    categories['Secrets']['pen'] += add
        
        # If we filtered out many false positives, reduce penalty further
        if is_flutter and len(self.d['secrets']) > 5 and actual_secrets_issues < 3:
            secrets_pen = min(secrets_pen, 10)  # Extra lenient for Flutter with few real secrets
        
        total_pen += secrets_pen# Dangerous permissions penalty
        for p in self.d['perms'].get('dangerous', []):
            pp = base_pen.get(p['risk'], 0)
            total_pen += pp
            categories['Permissions']['pen'] += pp
            categories['Permissions']['issues'] += 1

        # Apply combo escalations
        combo_pen = 0
        for risk, title, desc, cat in combos:
            cp = base_pen.get(risk, 0)
            total_pen += cp
            combo_pen += cp
            issues.append(_iss(title, risk, desc,
                'Address the underlying issues immediately', []))

        score = max(0, 100 - total_pen)

        # Grade system
        if score >= 90:   grade = 'A'
        elif score >= 80: grade = 'B'
        elif score >= 65: grade = 'C'
        elif score >= 50: grade = 'D'
        elif score >= 30: grade = 'E'
        else:             grade = 'F'

        # Build category breakdown
        cat_scores = {}
        for name, data in categories.items():
            cat_scores[name] = max(0, 100 - data['pen'])

        self.d['security']['issues'] = issues
        self.d['security']['score'] = score
        self.d['security']['grade'] = grade
        self.d['security']['debug_build'] = is_debug
        self.d['security']['categories'] = cat_scores
        self.d['security']['combos'] = [{'risk': r, 'title': t, 'desc': d}
                                         for r, t, d, _ in combos]

    # ── 6. Architecture ───────────────────────────────────────────────
    def analyze_arch(self):
        txt = self.txt
        fw = [k for k, v in FRAMEWORKS.items() if any(p in txt for p in v)]
        lib = [k for k, v in LIBRARIES.items() if any(p in txt for p in v)]
        nat = sorted(set(os.path.basename(f) for f in self.d['info'].get('native_libs', [])))
        obf = []
        if re.search(r'\bclass [a-z]\b', txt):
            obf.append('ProGuard/R8')
        if re.search(r'\bpackage [a-z]\.[a-z]\.[a-z]\b', txt):
            obf.append('Name obfuscation')
        self.d['arch'] = {'frameworks': fw, 'libraries': lib, 'native': nat, 'obfuscation': obf}

    # ── 7. Vulnerabilities ────────────────────────────────────────────
    def analyze_vulns(self):
        vulns, n = [], [0]
        def add(t, r, d, rec, cat):
            n[0] += 1
            vulns.append({'id': f'V-{n[0]:03d}', 'title': t, 'risk': r, 'desc': d, 'rec': rec, 'cat': cat})
        for i in self.d['security']['issues']:
            if i['risk'] in ('CRITICAL', 'HIGH'):
                add(i['title'], i['risk'], i['desc'], i['rec'], 'Security')
        for s in self.d['secrets']:
            if s['risk'] in ('CRITICAL', 'HIGH'):
                add(f"Exposed {s['type']}", s['risk'],
                    f"Hardcoded {s['type']} in binary",
                    'Remove from code, use secure storage', 'Secrets')
        dp = self.d['perms']['dangerous']
        crits = [p for p in dp if p['risk'] == 'CRITICAL']
        if crits:
            names = ', '.join(p['name'].split('.')[-1] for p in crits[:3])
            add('Critical Permissions', 'CRITICAL',
                f'{len(crits)} critical: {names}',
                'Justify each permission', 'Permissions')
        if len(dp) > 5:
            add('Excessive Permissions', 'MEDIUM',
                f'{len(dp)} dangerous permissions',
                'Apply least privilege principle', 'Permissions')
        http = [u for u in self.d['endpoints']['urls'] if u.startswith('http://')]
        if len(http) > 2:
            add('Cleartext HTTP', 'HIGH',
                f'{len(http)} unencrypted endpoints',
                'Enforce HTTPS, usesCleartextTraffic=false', 'Network')
        vulns.sort(key=lambda v: RISK_ORD.get(v['risk'], 9))
        self.d['vulns'] = vulns

    # ── 8. Manifest ───────────────────────────────────────────────────
    def analyze_manifest(self):
        if not AG:
            return
        a = self._mk_apk()
        self.d['manifest'] = {
            'activities': a.get_activities(), 'services': a.get_services(),
            'receivers': a.get_receivers(), 'providers': a.get_providers(),
            'main_activity': a.get_main_activity(),
        }

    # ── 9. Components & Deep Links Security ────────────────────────────
    def analyze_components(self):
        """Analyze exported components, deep links, and intent filter security."""
        if not AG:
            return
        a = self._mk_apk()
        ns = '{http://schemas.android.com/apk/res/android}'
        xml = a.get_android_manifest_xml()
        if xml is None:
            return

        exported_no_perm = []
        deep_links = []
        unverified_links = []
        provider_issues = []
        implicit_receivers = []

        for tag in ['activity', 'service', 'receiver', 'provider']:
            for elem in a.find_tags(tag):
                name = elem.get(f'{ns}name', 'unknown')
                exported = elem.get(f'{ns}exported')
                perm = elem.get(f'{ns}permission')

                # Parse intent filters
                intent_filters = elem.findall('intent-filter')
                has_intent_filter = len(intent_filters) > 0

                # Check exported status
                # Android < 12: if has intent-filter and no explicit exported, defaults to true
                # Android >= 12: must explicitly set exported
                is_exported = exported == 'true'
                is_implicitly_exported = (exported is None and has_intent_filter
                                          and tag in ('activity', 'receiver'))

                if (is_exported or is_implicitly_exported) and not perm:
                    issue = {
                        'component': name,
                        'type': tag,
                        'exported': exported,
                        'has_permission': bool(perm),
                    }

                    # Check for intent filters
                    has_view_action = False
                    for inf in intent_filters:
                        actions = [a_el.get(f'{ns}name') for a_el in inf.findall('action')]
                        categories = [c.get(f'{ns}name') for c in inf.findall('category')]
                        datas = inf.findall('data')

                        schemes, hosts, paths = [], [], []
                        for d in datas:
                            s = d.get(f'{ns}scheme')
                            h = d.get(f'{ns}host')
                            p = d.get(f'{ns}pathPrefix') or d.get(f'{ns}path') or d.get(f'{ns}pathPattern')
                            if s: schemes.append(s)
                            if h: hosts.append(h)
                            if p: paths.append(p)

                        if 'android.intent.action.VIEW' in actions:
                            has_view_action = True

                        # Deep link detection
                        if schemes and 'android.intent.category.BROWSABLE' in categories:
                            for scheme in schemes:
                                for host in (hosts or ['*']):
                                    link = f"{scheme}://{host}"
                                    if paths:
                                        link += paths[0]
                                    auto_verify = elem.get(f'{ns}autoVerify')
                                    dl_entry = {
                                        'scheme': scheme,
                                        'host': host,
                                        'paths': paths,
                                        'component': name,
                                        'verified': scheme == 'https' and auto_verify == 'true',
                                    }
                                    deep_links.append(dl_entry)

                                    # Check for auto_verify (App Links vs Deep Links)
                                    if scheme == 'https' and not auto_verify:
                                        unverified_links.append({
                                            'component': name,
                                            'link': link,
                                            'issue': 'HTTPS deep link without autoVerify (not an App Link)',
                                        })
                                    elif scheme == 'http':
                                        unverified_links.append({
                                            'component': name,
                                            'link': link,
                                            'issue': 'HTTP deep link — unencrypted, vulnerable to MITM',
                                        })

                    # Exported without permission
                    if is_exported or (is_implicitly_exported and has_view_action):
                        exported_no_perm.append(issue)

                    # Implicit receiver (broadcast injection risk)
                    if tag == 'receiver' and is_implicitly_exported and not perm:
                        implicit_receivers.append({
                            'component': name,
                            'issue': 'Implicit receiver without permission — broadcast injection risk',
                        })

                # Provider-specific checks
                if tag == 'provider':
                    grant_uri = elem.get(f'{ns}grantUriPermissions')
                    read_perm = elem.get(f'{ns}readPermission')
                    write_perm = elem.get(f'{ns}writePermission')
                    if grant_uri == 'true' and not read_perm and not write_perm:
                        provider_issues.append({
                            'component': name,
                            'issue': 'Provider grants URI permissions without read/write permission',
                        })

        # Security issues from components
        issues = []
        if exported_no_perm:
            names = [e['component'].split('.')[-1] for e in exported_no_perm[:5]]
            issues.append(_iss('Exported Components', 'HIGH',
                f'{len(exported_no_perm)} component(s) exported without permission: {", ".join(names)}',
                'Set exported=false or add permission protection',
                [e['component'] for e in exported_no_perm[:5]]))

        if unverified_links:
            issues.append(_iss('Unverified Deep Links', 'MEDIUM',
                f'{len(unverified_links)} deep link(s) without proper verification',
                'Use android:autoVerify="true" for App Links; avoid HTTP schemes',
                [u['link'] for u in unverified_links[:5]]))

        if provider_issues:
            issues.append(_iss('Provider URI Grant', 'HIGH',
                f'{len(provider_issues)} provider(s) grant URI permissions unsafely',
                'Add readPermission/writePermission to providers',
                [p['component'] for p in provider_issues[:5]]))

        if implicit_receivers:
            issues.append(_iss('Implicit Receivers', 'MEDIUM',
                f'{len(implicit_receivers)} receiver(s) without explicit exported flag',
                'Set exported=false or add permission for implicit receivers',
                [r['component'] for r in implicit_receivers[:5]]))

        self.d['components'] = {
            'exported_no_perm': exported_no_perm,
            'deep_links': deep_links,
            'unverified_links': unverified_links,
            'provider_issues': provider_issues,
            'implicit_receivers': implicit_receivers,
            'issues': issues,
        }

        # Add to security issues
        self.d['security']['issues'].extend(issues)

    # ── 10. Description ────────────────────────────────────────────────
    def analyze_desc(self):
        types = [k for k, v in APP_TYPES.items() if any(w in self.txt.lower() for w in v)]
        info = self.d['info']
        self.d['desc'] = {
            'package': info.get('package', '?'),
            'version': f"{info.get('version_name', '?')} (build {info.get('version_code', '?')})",
            'app_type': types or ['General'],
            'frameworks': self.d['arch'].get('frameworks', []),
            'libraries': self.d['arch'].get('libraries', [])[:10],
            'servers': len(self.d['endpoints']['servers']),
            'endpoints': len(self.d['endpoints']['urls']),
            'secrets': len(self.d['secrets']),
            'vulns': len(self.d['vulns']),
            'dangerous_perms': len(self.d['perms']['dangerous']),
        }

    # ═════════════════════════════════════════════════════════════════
    # RUN
    # ═════════════════════════════════════════════════════════════════
    def run_full(self):
        ok, msg = validate_apk(str(self.path))
        if not ok:
            _err(msg)
            return False
        show_banner()
        steps = [
            ("Basic Info", self.analyze_info),
            ("Certificate", self.analyze_cert),
            ("Permissions", self.analyze_perms),
            ("Strings + Native", self.extract_strings),
            ("Endpoints", self.analyze_endpoints),
            ("Deep API Scan", self.analyze_apis),
            ("Secrets", self.analyze_secrets),
            ("Security", self.analyze_security),
            ("Architecture", self.analyze_arch),
            ("Vulnerabilities", self.analyze_vulns),
            ("Manifest", self.analyze_manifest),
            ("Components", self.analyze_components),
            ("Description", self.analyze_desc),
        ]
        if RICH:
            con.print(f"\n  [cyan]Target:[/] [bold white]{esc(self.path.name)}[/]  "
                      f"[dim]({self.path.stat().st_size / 1024 / 1024:.1f} MB)[/]\n")
            with Progress(
                SpinnerColumn("dots12", style="cyan"),
                TextColumn("[bold]{task.description:<30}[/]"),
                BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
                TextColumn("[dim]{task.completed}/{task.total}[/]"),
                TimeElapsedColumn(),
                console=con, transient=True,
            ) as pg:
                task = pg.add_task("Starting analysis...", total=len(steps))
                for name, fn in steps:
                    pg.update(task, description=name)
                    try:
                        fn()
                    except Exception as e:
                        con.print(f"  [red]x {name}: {e}[/]")
                    pg.advance(task)
            con.print("  [green]>[/] Analysis complete\n")
        else:
            print(f"\n  Analyzing: {self.path.name}\n")
            for name, fn in steps:
                try:
                    fn()
                    print(f"  > {name}")
                except Exception as e:
                    print(f"  x {name}: {e}")
            print()
        return True

    def run_section(self, section: str):
        ok, msg = validate_apk(str(self.path))
        if not ok:
            _err(msg)
            return False
        show_banner()
        self.analyze_info()
        self.analyze_cert()
        if section in ('perms', 'full'):
            self.analyze_perms()
        self.extract_strings()
        if section in ('urls', 'full', 'secrets', 'vulns', 'apis'):
            self.analyze_endpoints()
            self.analyze_apis()
        if section in ('secrets', 'full', 'vulns'):
            self.analyze_secrets()
        if section in ('vulns', 'full'):
            self.analyze_security()
        if section in ('arch', 'full'):
            self.analyze_arch()
        if section in ('vulns', 'full'):
            self.analyze_vulns()
        if section in ('manifest', 'full'):
            self.analyze_manifest()
        if section in ('manifest', 'full'):
            self.analyze_components()
        if section == 'full':
            self.analyze_desc()
        return True

    # ═════════════════════════════════════════════════════════════════
    # RICH TERMINAL RENDERER (English only)
    # ═════════════════════════════════════════════════════════════════
    def render(self, section='full'):
        if RICH:
            self._rich(section)
        else:
            self._plain(section)

    def _sec_panel(self, num, icon, title):
        """Create a section header panel."""
        if RICH:
            con.print(Panel(
                f"[bold]{icon} {title}[/]",
                border_style="blue", box=box.ROUNDED,
                title=f"[dim]Section {num}[/]", title_align="left",
            ))

    def _rich(self, section):
        if section in ('info', 'full'):
            self._ri_info()
        if section in ('info', 'full'):
            self._ri_cert()
        if section in ('perms', 'full'):
            self._ri_perms()
        if section in ('urls', 'full'):
            self._ri_urls()
        if section in ('secrets', 'full'):
            self._ri_secrets()
        if section in ('vulns', 'full'):
            self._ri_security()
            self._ri_vulns()
        if section in ('arch', 'full'):
            self._ri_arch()
        if section in ('manifest', 'full'):
            self._ri_manifest()
        if section in ('manifest', 'full'):
            self._ri_components()
        if section == 'full':
            self._ri_summary()

    def _ri_info(self):
        self._sec_panel("1", "📋", "Basic Information")
        info = self.d['info']
        t = Table(box=box.SIMPLE_HEAVY, border_style="dim blue",
                  show_header=False, pad_edge=True, expand=True)
        t.add_column("Property", style="cyan", width=20, no_wrap=True)
        t.add_column("Value", style="white")
        t.add_column("Property", style="cyan", width=20, no_wrap=True)
        t.add_column("Value", style="white")
        t.add_row("Package", esc(str(info.get('package', 'N/A'))),
                   "Version", f"{info.get('version_name', '?')} (build {info.get('version_code', '?')})")
        t.add_row("File", esc(str(info.get('file_name', '?'))),
                   "Size", f"{info.get('file_size_mb', '?')} MB")
        t.add_row("Min SDK", str(info.get('min_sdk', '?')),
                   "Target SDK", str(info.get('target_sdk', '?')))
        t.add_row("DEX Files", str(info.get('dex_count', 1)),
                   "Activities", str(info.get('activities', '?')))
        t.add_row("Services", str(info.get('services', '?')),
                   "Receivers", str(info.get('receivers', '?')))
        nat_s = "[yellow]! Yes[/]" if info.get('has_native') else "[green]No[/]"
        sig_s = f"[green]> {info.get('sign_scheme', '?')}[/]" if info.get('signed') else "[red]x No[/]"
        t.add_row("Native", nat_s, "Signed", sig_s)
        net_s = "[green]> Yes[/]" if info.get('has_net_config') else "[yellow]! Missing[/]"
        main_act = str(info.get('main_activity', '?'))
        if len(main_act) > 45:
            main_act = main_act[:42] + '...'
        t.add_row("NetSecConfig", net_s, "Main Activity", esc(main_act))
        t.add_row("MD5", f"[dim]{info.get('md5', '?')}[/]", "", "")
        t.add_row("SHA256", f"[dim]{str(info.get('sha256', '?'))[:48]}...[/]", "", "")
        con.print(t)
        con.print()

    def _ri_cert(self):
        """Render certificate details in Rich format."""
        cert = self.d.get('cert', {})
        if not cert:
            return
        status = cert.get('status', 'unknown')
        if status in ('unavailable', 'error'):
            warning = cert.get('warning', 'Certificate data unavailable')
            con.print(f"  [yellow]! Certificate: {warning}[/]\n")
            return
        if status == 'unsigned':
            con.print(f"  [red]x Certificate: No signing certificate found[/]\n")
            return
        self._sec_panel("1b", "🔑", "Certificate Details")
        t = Table(box=box.SIMPLE_HEAVY, border_style="dim blue",
                  show_header=False, pad_edge=True, expand=True)
        t.add_column("Property", style="cyan", width=20, no_wrap=True)
        t.add_column("Value", style="white")
        if cert.get('subject'):
            t.add_row("Subject", str(cert['subject']))
        if cert.get('issuer'):
            t.add_row("Issuer", str(cert['issuer']))
        t.add_row("Valid From", cert.get('valid_from', '?'))
        t.add_row("Valid Until", cert.get('valid_until', '?'))
        expired = status == 'expired'
        exp_s = "[red]x Expired[/]" if expired else "[green]> Valid[/]"
        t.add_row("Status", exp_s)
        days = cert.get('days_remaining', '?')
        if days != '?' and not expired:
            color = "red" if days < 90 else "green"
            t.add_row("Days Left", f"[{color}]{days}[/]")
        t.add_row("Algorithm", cert.get('sig_algorithm', '?'))
        t.add_row("Key Size", f"{cert.get('key_size', '?')} bits")
        t.add_row("Key Type", cert.get('key_type', '?'))
        if cert.get('serial'):
            t.add_row("Serial", str(cert['serial']))
        if cert.get('sha256_fingerprint'):
            t.add_row("SHA256", f"[dim]{cert['sha256_fingerprint'][:64]}[/]")
        scheme = cert.get('scheme', '?')
        t.add_row("Signing Scheme", scheme.upper())
        con.print(t)
        for w in cert.get('warnings', []):
            con.print(f"  [yellow]! {w}[/]")
        con.print()
        self._sec_panel("2", "🔐", "Permissions")
        pm = self.d['perms']
        dp = pm['dangerous']
        con.print(f"  Total: [bold]{len(pm['all'])}[/]  |  "
                  f"Dangerous: [bold red]{len(dp)}[/]  |  "
                  f"Normal: [dim]{len(pm['normal'])}[/]\n")
        if dp:
            t = Table(box=box.ROUNDED, border_style="dim", expand=True)
            t.add_column("Risk", width=12, justify="center")
            t.add_column("Permission", style="yellow", no_wrap=True)
            t.add_column("Description")
            for p in sorted(dp, key=lambda x: RISK_ORD.get(x['risk'], 9)):
                t.add_row(rbadge(p['risk']),
                          p['name'].split('.')[-1],
                          p['desc_en'])
            con.print(t)
        else:
            con.print("  [green]> No dangerous permissions[/]")
        con.print()

    def _ri_perms(self):
        """Render permissions in Rich format."""
        self._sec_panel("2", "🔐", "Permissions")
        perms = self.d['perms']
        total = len(perms.get('all', []))
        dangerous = len(perms.get('dangerous', []))
        normal = len(perms.get('normal', []))
        
        con.print(f"  Total: {total}  |  Dangerous: {dangerous}  |  Normal: {normal}\n")
        
        if dangerous:
            t = Table(box=box.SIMPLE_HEAVY, border_style="dim blue",
                      show_header=True, expand=True)
            t.add_column("Risk", style="bold red", width=10)
            t.add_column("Permission", style="cyan", width=30)
            t.add_column("Description", style="white")
            
            for p in perms['dangerous']:
                risk_style = "red" if p['risk'] in ('CRITICAL', 'HIGH') else "yellow"
                t.add_row(
                    f"[{risk_style}]{p['risk']}[/]",
                    p['name'].split('.')[-1],
                    p.get('desc_en', 'N/A')
                )
            con.print(t)
        con.print()

    def _ri_urls(self):
        self._sec_panel("3", "🌐", "URLs & Endpoints")
        ep = self.d['endpoints']
        native_count = self.d.get('_native_strings_count', 0)

        stats = Table(box=None, show_header=False, pad_edge=False)
        stats.add_column(style="dim")
        stats.add_column(style="bold")
        stats.add_row("Servers", f"[blue]{len(ep['servers'])}[/]")
        stats.add_row("URLs", str(len(ep['urls'])))
        stats.add_row("API Paths", f"[cyan]{len(ep.get('api', []))}[/]")
        stats.add_row("Domains", str(len(ep['domains'])))
        stats.add_row("IPs", str(len(ep['ips'])))
        stats.add_row("Emails", str(len(ep['emails'])))
        if native_count:
            stats.add_row("Native Strings", f"[dim]{native_count}[/]")
        con.print(stats)
        con.print()

        # Grouped endpoint tree
        srv_map = defaultdict(list)
        all_urls = list(ep['urls']) + [u for u in ep.get('api', []) if u.startswith('http')]
        for url in all_urls:
            m = re.match(r'(https?://[^/?#]+)', url)
            if m:
                srv_map[m.group(1)].append(url[len(m.group(1)):] or '/')

        if srv_map:
            tree = Tree("[bold cyan]Endpoints grouped by server[/]", guide_style="dim blue")
            for server, paths in sorted(srv_map.items()):
                unique_paths = sorted(set(paths))
                branch = tree.add(f"[bold blue]{esc(server)}[/] [dim]({len(unique_paths)} paths)[/]")
                for path in unique_paths[:30]:
                    branch.add(f"[dim]{esc(path)}[/]")
                if len(unique_paths) > 30:
                    branch.add(f"[dim italic]...+{len(unique_paths) - 30} more[/]")
            con.print(tree)

        # API paths (non-URL, relative paths from Retrofit etc.)
        rel_apis = [a for a in ep.get('api', []) if not a.startswith('http')]
        if rel_apis:
            con.print(f"\n  [bold]API Paths (relative):[/]")
            for a in rel_apis[:20]:
                con.print(f"    [cyan]{esc(a)}[/]")
            if len(rel_apis) > 20:
                con.print(f"    [dim]...+{len(rel_apis) - 20} more[/]")

        if ep['ips']:
            con.print(f"\n  [bold]IPs:[/] {', '.join(ep['ips'][:10])}")
        if ep['emails']:
            con.print(f"  [bold]Emails:[/] {', '.join(ep['emails'][:10])}")
        if ep['domains']:
            con.print(f"  [bold]Domains:[/] {', '.join(ep['domains'][:15])}")

        # Auth patterns
        auth_p = ep.get('auth_patterns', [])
        if auth_p:
            con.print(f"\n  [bold yellow]Auth/Token Patterns:[/]")
            for a in auth_p[:5]:
                con.print(f"    [yellow]{esc(a)}[/]")
        con.print()

    def _ri_secrets(self):
        self._sec_panel("4", "🔑", "Secrets")
        secs = self.d['secrets']
        if not secs:
            con.print("  [green]> No secrets found[/]\n")
            return
        t = Table(box=box.ROUNDED, border_style="dim", expand=True)
        t.add_column("Risk", width=12, justify="center")
        t.add_column("Type", style="yellow")
        t.add_column("Value (masked)", style="dim")
        for s in secs:
            t.add_row(rbadge(s['risk']), s['type'], esc(s['value']))
        con.print(t)
        con.print()

    def _ri_security(self):
        self._sec_panel("5", "🛡️", "Security Analysis")
        sec = self.d['security']
        score = sec['score']
        grade = sec.get('grade', '?')
        is_debug = sec.get('debug_build', False)

        # Grade color mapping
        grade_style = {'A': 'bold green', 'B': 'green', 'C': 'yellow',
                       'D': 'bold yellow', 'E': 'bold red', 'F': 'bold white on red'}
        sc_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        label = ('SAFE' if score >= 80 else 'MODERATE'
                 if score >= 60 else 'HIGH RISK' if score >= 40
                 else 'CRITICAL')

        # Main score panel with grade
        gs = grade_style.get(grade, 'dim')
        dbg_tag = "  [dim][DEBUG build][/]" if is_debug else ""
        con.print(Panel(
            f"[bold {sc_style}]{score}/100[/]  [{gs}]Grade: {grade}[/]  [dim]-> {label}[/]{dbg_tag}",
            border_style=sc_style, box=box.DOUBLE_EDGE, title="[dim]Score[/]",
            title_align="left", expand=False,
        ))

        # Category breakdown
        cats = sec.get('categories', {})
        if cats:
            cat_tbl = Table(box=None, show_header=True, pad_edge=False, expand=False)
            cat_tbl.add_column("Category", style="cyan", width=16)
            cat_tbl.add_column("Score", justify="center", width=8)
            cat_tbl.add_column("Bar", width=20)
            for name, val in cats.items():
                cs = "green" if val >= 80 else "yellow" if val >= 60 else "red"
                filled = int(val / 5)
                bar = f"[{cs}]{'█' * filled}{'░' * (20 - filled)}[/]"
                cat_tbl.add_row(name, f"[{cs}]{val}[/]", bar)
            con.print(cat_tbl)
            con.print()

        # Combo alerts
        combos = sec.get('combos', [])
        if combos:
            con.print(f"  [bold red]⚠ Combination Risks:[/]")
            for c in combos:
                con.print(f"    {RISK_EM.get(c['risk'], '')} {rbadge(c['risk'])} [bold]{esc(c['title'])}[/]")
                con.print(f"       [dim]{esc(c['desc'])}[/]")
            con.print()

        # Individual issues
        for i in sec['issues']:
            # Skip combo-generated issues in the detail list (already shown above)
            if i.get('title', '').startswith(('SSL Bypass +', 'Debug +', 'Weak Crypto +')):
                continue
            con.print(f"  {RISK_EM.get(i['risk'], '')} {rbadge(i['risk'])} [bold]{esc(i['title'])}[/]")
            con.print(f"     [dim]{esc(i['desc'])}[/]")
            con.print(f"     [green]>> {esc(i['rec'])}[/]")
            if i.get('ex'):
                ex_str = ', '.join(str(x) for x in i['ex'][:3])
                con.print(f"     [dim italic]Examples: {esc(ex_str)}[/]")
            con.print()

    def _ri_vulns(self):
        self._sec_panel("6", "🔴", "Vulnerabilities")
        vulns = self.d['vulns']
        if not vulns:
            con.print("  [green]> No vulnerabilities found[/]\n")
            return
        cr = sum(1 for v in vulns if v['risk'] == 'CRITICAL')
        hi = sum(1 for v in vulns if v['risk'] == 'HIGH')
        md = sum(1 for v in vulns if v['risk'] == 'MEDIUM')
        con.print(f"  [red]CRITICAL: {cr}[/]  [yellow]HIGH: {hi}[/]  [cyan]MEDIUM: {md}[/]\n")
        t = Table(box=box.ROUNDED, border_style="dim red", expand=True)
        t.add_column("ID", style="dim", width=8)
        t.add_column("Risk", width=12, justify="center")
        t.add_column("Vulnerability")
        t.add_column("Fix", style="green")
        for v in vulns:
            t.add_row(v['id'], rbadge(v['risk']), esc(v['title']), esc(v['rec']))
        con.print(t)
        con.print()

    def _ri_arch(self):
        self._sec_panel("7", "🏗️", "Architecture")
        ar = self.d['arch']
        tree = Tree("[bold cyan]Technical Stack[/]", guide_style="dim blue")
        if ar.get('frameworks'):
            fw_branch = tree.add("[bold]Frameworks[/]")
            for fw in ar['frameworks']:
                fw_branch.add(f"[cyan]{esc(fw)}[/]")
        if ar.get('libraries'):
            lib_branch = tree.add(f"[bold]Libraries ({len(ar['libraries'])})[/]")
            for lib in ar['libraries']:
                lib_branch.add(esc(lib))
        if ar.get('native'):
            nat_branch = tree.add("[bold]Native Libs[/]")
            for n in ar['native']:
                nat_branch.add(f"[dim]{esc(n)}[/]")
        if ar.get('obfuscation'):
            tree.add(f"[yellow]Obfuscation: {', '.join(ar['obfuscation'])}[/]")
        con.print(tree)
        con.print()

    def _ri_manifest(self):
        self._sec_panel("8", "📜", "Manifest Components")
        mn = self.d['manifest']
        if not mn:
            con.print("  [dim]No manifest data (install androguard)[/]\n")
            return
        tree = Tree("[bold cyan]AndroidManifest.xml[/]", guide_style="dim blue")
        for comp, label in [('activities', 'Activities'), ('services', 'Services'),
                            ('receivers', 'Receivers'), ('providers', 'Providers')]:
            items = mn.get(comp, [])
            branch = tree.add(f"[bold]{label}[/] [dim]({len(items)})[/]")
            for item in items[:20]:
                short = item.split('.')[-1] if '.' in item else item
                branch.add(f"[dim]{esc(short)}[/]")
            if len(items) > 20:
                branch.add(f"[dim italic]...+{len(items) - 20} more[/]")
        con.print(tree)
        con.print()

    def _ri_components(self):
        """Render component analysis and deep link security findings."""
        self._sec_panel("9", "\U0001f517", "Components & Deep Links")
        comps = self.d.get('components', {})
        if not comps:
            con.print("  [dim]No component analysis data[/]\n")
            return

        dl = comps.get('deep_links', [])
        exp = comps.get('exported_no_perm', [])
        prov = comps.get('provider_issues', [])
        impl = comps.get('implicit_receivers', [])
        unver = comps.get('unverified_links', [])

        # Deep Links
        if dl:
            con.print(f"  [bold]Deep Links[/] [dim]({len(dl)})[/]")
            t = Table(box=box.ROUNDED, border_style="dim", expand=True)
            t.add_column("Scheme", style="cyan", width=10)
            t.add_column("Host", style="white")
            t.add_column("Component", style="dim")
            t.add_column("Status", width=12, justify="center")
            for d in dl:
                host = d.get('host', '*')
                path_str = ', '.join(d.get('paths', []))
                display = f"{esc(host)}{esc(path_str)}"
                link = f"{d.get('scheme', '')}://{host}"
                is_unverified = any(u['link'] == link for u in unver)
                status = rbadge('HIGH') if is_unverified else rbadge('LOW')
                comp_name = d.get('component', '').split('.')[-1]
                t.add_row(d.get('scheme', ''), display, esc(comp_name), status)
            con.print(t)
            con.print()

        # Exported Components without Permission
        if exp:
            con.print(f"  [bold red]Exported Components Without Permission[/] [dim]({len(exp)})[/]")
            t = Table(box=box.ROUNDED, border_style="dim red", expand=True)
            t.add_column("Type", style="yellow", width=12)
            t.add_column("Component", style="red")
            t.add_column("Risk", width=12, justify="center")
            for e in exp:
                comp = e.get('component', '')
                short = comp.split('.')[-1] if '.' in comp else comp
                ctype = e.get('type', 'component')
                t.add_row(ctype.capitalize(), esc(short), rbadge('HIGH'))
            con.print(t)
            con.print()

        # Provider Issues
        if prov:
            con.print(f"  [bold yellow]Provider Issues[/] [dim]({len(prov)})[/]")
            for p in prov:
                comp = p.get('component', '')
                short = comp.split('.')[-1] if '.' in comp else comp
                con.print(f"    [yellow]! {rbadge('HIGH')}[/] [bold]{esc(short)}[/]")
                con.print(f"      [dim]{esc(p.get('issue', ''))}[/]")
            con.print()

        # Implicit Receivers
        if impl:
            con.print(f"  [bold yellow]Implicit Receivers[/] [dim]({len(impl)})[/]")
            for r in impl:
                comp = r.get('component', '')
                short = comp.split('.')[-1] if '.' in comp else comp
                con.print(f"    [yellow]! {rbadge('MEDIUM')}[/] [bold]{esc(short)}[/]")
                con.print(f"      [dim]{esc(r.get('issue', ''))}[/]")
            con.print()

        if not dl and not exp and not prov and not impl:
            con.print("  [green]> No component issues found[/]\n")

    def _ri_summary(self):
        """Dashboard-style summary with stat cards."""
        ep = self.d['endpoints']
        vulns = self.d['vulns']
        sec = self.d['security']
        score = sec['score']
        grade = sec.get('grade', '?')
        sc_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        crit_n = sum(1 for v in vulns if v['risk'] == 'CRITICAL')
        high_n = sum(1 for v in vulns if v['risk'] == 'HIGH')

        con.print(Panel(
            f"[bold]Overall Assessment[/]  [dim]Grade: {grade}[/]",
            border_style=sc_style, box=box.DOUBLE_EDGE,
        ))
        # Stat cards row
        cards = [
            Panel(f"[bold {sc_style}]{score}[/]\n[dim]Score[/]", box=box.ROUNDED, width=14, border_style=sc_style),
            Panel(f"[bold red]{crit_n}[/]\n[dim]CRITICAL[/]", box=box.ROUNDED, width=14, border_style="red"),
            Panel(f"[bold yellow]{high_n}[/]\n[dim]HIGH[/]", box=box.ROUNDED, width=14, border_style="yellow"),
            Panel(f"[bold blue]{len(ep['servers'])}[/]\n[dim]Servers[/]", box=box.ROUNDED, width=14, border_style="blue"),
            Panel(f"[bold]{len(ep['urls'])}[/]\n[dim]Endpoints[/]", box=box.ROUNDED, width=14),
            Panel(f"[bold red]{len(self.d['secrets'])}[/]\n[dim]Secrets[/]", box=box.ROUNDED, width=14, border_style="red"),
        ]
        con.print(Columns(cards, equal=False, expand=True, padding=(0, 1)))

        desc = self.d['desc']
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=True, border_style="dim")
        t.add_column("K", style="cyan", width=22)
        t.add_column("V", style="white")
        t.add_row("Package", esc(str(desc.get('package', '?'))))
        t.add_row("Version", str(desc.get('version', '?')))
        t.add_row("Type", ', '.join(desc.get('app_type', [])))
        t.add_row("Frameworks", ', '.join(desc.get('frameworks', [])) or '-')
        t.add_row("Libraries", ', '.join(desc.get('libraries', [])) or '-')
        con.print(t)
        con.print()

    # ── Plain fallback (no Rich) ──────────────────────────────────────
    def _plain(self, section):
        W = 72
        def hdr(n, en):
            print(f"\n{'_' * W}")
            print(f"  {n}  {en}")
            print(f"{'_' * W}")
        info = self.d['info']
        if section in ('info', 'full'):
            hdr("1", "Basic Information")
            for k, v in [("Package", info.get('package', 'N/A')), ("Version", info.get('version_name', '?')),
                         ("Size", f"{info.get('file_size_mb', '?')} MB"), ("MD5", info.get('md5', '?'))]:
                print(f"  {k:<20} {v}")
        if section in ('info', 'full'):
            cert = self.d.get('cert', {})
            status = cert.get('status', 'unknown')
            if status not in ('unavailable', 'error', 'unsigned') and cert:
                hdr("1b", "Certificate Details")
                for k, v in [("Subject", cert.get('subject', '?')), ("Issuer", cert.get('issuer', '?')),
                             ("Valid From", cert.get('valid_from', '?')), ("Valid Until", cert.get('valid_until', '?')),
                             ("Algorithm", cert.get('sig_algorithm', '?')), ("Key Size", f"{cert.get('key_size', '?')} bits"),
                             ("Scheme", cert.get('scheme', '?').upper())]:
                    print(f"  {k:<20} {v}")
                if status == 'expired':
                    print(f"  {'Status':<20} EXPIRED")
                for w in cert.get('warnings', []):
                    print(f"  WARNING: {w}")
        if section in ('perms', 'full'):
            hdr("2", "Permissions")
            for p in self.d['perms']['dangerous']:
                print(f"  [{p['risk']}] {p['name'].split('.')[-1]} -- {p['desc_en']}")
        if section in ('urls', 'full'):
            hdr("3", "Endpoints")
            for s in self.d['endpoints']['servers']:
                print(f"  >> {s}")
        if section in ('secrets', 'full'):
            hdr("4", "Secrets")
            for s in self.d['secrets']:
                print(f"  [{s['risk']}] {s['type']}: {s['value']}")
        if section in ('vulns', 'full'):
            hdr("5", "Security")
            print(f"  Score: {self.d['security']['score']}/100")
            for i in self.d['security']['issues']:
                print(f"  [{i['risk']}] {i['title']}")
            hdr("6", "Vulnerabilities")
            for v in self.d['vulns']:
                print(f"  [{v['id']}] [{v['risk']}] {v['title']}")
        if section in ('arch', 'full'):
            hdr("7", "Architecture")
            ar = self.d['arch']
            print(f"  Frameworks: {', '.join(ar.get('frameworks', [])) or '-'}")
            print(f"  Libraries:  {', '.join(ar.get('libraries', [])) or '-'}")
        if section in ('manifest', 'full'):
            hdr("8", "Manifest")
            mn = self.d['manifest']
            for k in ('activities', 'services', 'receivers', 'providers'):
                items = mn.get(k, [])
                print(f"  {k.title()} ({len(items)})")
        if section in ('manifest', 'full'):
            hdr("9", "Components & Deep Links")
            comps = self.d.get('components', {})
            dl = comps.get('deep_links', [])
            exp = comps.get('exported_no_perm', [])
            prov = comps.get('provider_issues', [])
            impl = comps.get('implicit_receivers', [])
            if dl:
                print(f"  Deep Links ({len(dl)}):")
                for d in dl:
                    host = d.get('host', '*')
                    comp = d.get('component', '').split('.')[-1]
                    print(f"    {d.get('scheme', '')}://{host} -> {comp}")
            if exp:
                print(f"  Exported Without Permission ({len(exp)}):")
                for e in exp:
                    comp = e.get('component', '').split('.')[-1]
                    print(f"    [{e.get('type', '?')}] {comp}")
            if prov:
                print(f"  Provider Issues ({len(prov)}):")
                for p in prov:
                    comp = p.get('component', '').split('.')[-1]
                    print(f"    ! {comp}: {p.get('issue', '')}")
            if impl:
                print(f"  Implicit Receivers ({len(impl)}):")
                for r in impl:
                    comp = r.get('component', '').split('.')[-1]
                    print(f"    ! {comp}: {r.get('issue', '')}")
            if not dl and not exp and not prov and not impl:
                print("  No component issues found")
        if section == 'full':
            hdr("10", "Summary")
            print(f"  Score: {self.d['security']['score']}/100  Vulns: {len(self.d['vulns'])}  Secrets: {len(self.d['secrets'])}")
        print()

    # ═════════════════════════════════════════════════════════════════
    # SAVE REPORTS
    # ═════════════════════════════════════════════════════════════════
    def save(self, out_dir: str = None) -> str:
        out_dir = out_dir or str(REPORTS)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = Path(out_dir) / f"{self.path.stem}_{ts}"
        jp = base.with_suffix('.json')
        jp.write_text(json.dumps(self.d, indent=2, ensure_ascii=False), encoding='utf-8')
        mp = base.with_suffix('.md')
        mp.write_text(self._mk_md(), encoding='utf-8')
        hp = base.with_suffix('.html')
        hp.write_text(self._mk_html(), encoding='utf-8')
        if RICH:
            t = Table(box=box.ROUNDED, border_style="green", title="[bold green]Reports Saved[/]")
            t.add_column("Format", style="cyan")
            t.add_column("Path", style="white")
            t.add_row("JSON", str(jp))
            t.add_row("Markdown", str(mp))
            t.add_row("HTML", str(hp))
            con.print(t)
        else:
            print(f"  JSON -> {jp}")
            print(f"  MD   -> {mp}")
            print(f"  HTML -> {hp}")
        return str(hp)

    # ── Markdown ──────────────────────────────────────────────────────
    def _mk_md(self) -> str:
        info = self.d['info']; ep = self.d['endpoints']; sec = self.d['security']
        ar = self.d['arch']; vulns = self.d['vulns']; pm = self.d['perms']
        is_ar = self.lang == 'ar'

        if is_ar:
            dp_rows = '\n'.join(
                f"| {p['risk']} | `{p['name'].split('.')[-1]}` | {p['desc_ar']} | {p['desc_en']} |"
                for p in pm['dangerous']) or '| - | No dangerous perms | - | - |'
        else:
            dp_rows = '\n'.join(
                f"| {p['risk']} | `{p['name'].split('.')[-1]}` | {p['desc_en']} |"
                for p in pm['dangerous']) or '| - | No dangerous perms | - |'

        sec_rows = '\n'.join(
            f"| {RISK_EM.get(i['risk'], '')} | **{i['title']}** | {i['risk']} | {i['desc']} |"
            for i in sec['issues']) or '| > | No issues | - | - |'
        vuln_rows = '\n'.join(
            f"| {v['id']} | {RISK_EM.get(v['risk'], '')} **{v['title']}** | {v['risk']} | {v['rec']} |"
            for v in vulns) or '| - | > No vulnerabilities | - | - |'

        title = 'NightOwl APK Analysis Report'
        if is_ar:
            title += ' | تقرير تحليل NightOwl'
        perm_hdr = '| Risk | Permission | AR | EN |' if is_ar else '| Risk | Permission | Description |'
        perm_sep = '|---|---|---|---|' if is_ar else '|---|---|---|'

        return f"""# NightOwl APK Analysis Report{' | تقرير تحليل NightOwl' if is_ar else ''}

> **Tool**: NightOwl v{__version__}
> **Date**: {self.d['ts']}
> **File**: `{self.path.name}`
> **Score**: **{sec['score']}/100**

## 1. Basic Info{' | المعلومات الأساسية' if is_ar else ''}
| Property | Value |
|---|---|
| Package | `{info.get('package', 'N/A')}` |
| Version | {info.get('version_name', '?')} (code {info.get('version_code', '?')}) |
| Size | {info.get('file_size_mb', '?')} MB |
| SDK | Min: {info.get('min_sdk', '?')} / Target: {info.get('target_sdk', '?')} |
| MD5 | `{info.get('md5', '?')}` |
| SHA256 | `{info.get('sha256', '?')}` |

## 2. Permissions{' | الأذونات' if is_ar else ''}
Total: {len(pm['all'])} | Dangerous: {len(pm['dangerous'])}
{perm_hdr}
{perm_sep}
{dp_rows}

## 3. Endpoints{' | نقاط الوصول' if is_ar else ''}
Servers: {len(ep['servers'])} | URLs: {len(ep['urls'])} | IPs: {len(ep['ips'])}
{''.join('- `' + s + '`' + chr(10) for s in ep['servers'])}

## 4. Security{' | التحليل الأمني' if is_ar else ''}
Score: **{sec['score']}/100**
| # | Issue | Risk | Details |
|---|---|---|---|
{sec_rows}

### Secrets
{''.join('- [' + s['risk'] + '] **' + s['type'] + '**: `' + s['value'] + '`' + chr(10) for s in self.d['secrets']) or '> No secrets found'}

## 5. Vulnerabilities{' | الثغرات' if is_ar else ''}
| ID | Vuln | Risk | Fix |
|---|---|---|---|
{vuln_rows}

## 6. Architecture{' | البنية' if is_ar else ''}
- **Frameworks**: {', '.join(ar.get('frameworks', [])) or '-'}
- **Libraries**: {', '.join(ar.get('libraries', [])) or '-'}
- **Native**: {', '.join(ar.get('native', [])) or '-'}
- **Obfuscation**: {', '.join(ar.get('obfuscation', [])) or '-'}

---
*Generated by NightOwl v{__version__} — Ethical use only*
"""

    # ── HTML Report ───────────────────────────────────────────────────
    @staticmethod
    def _esc(s):
        """Escape HTML entities for safe embedding."""
        return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    def _mk_html(self) -> str:
        info = self.d['info']; ep = self.d['endpoints']; sec = self.d['security']
        ar = self.d['arch']; vulns = self.d['vulns']; pm = self.d['perms']
        is_ar = self.lang == 'ar'
        score = sec['score']
        sc_color = '#22c55e' if score >= 80 else '#f59e0b' if score >= 60 else '#ef4444'

        if is_ar:
            perm_cards_html = ''.join(
                f'<div class="perm-card">'
                f'{badge_html(p["risk"])}'
                f'<code class="perm-name">{p["name"].split(".")[-1]}</code>'
                f'<div class="perm-desc" dir="rtl">{p["desc_ar"]}</div>'
                f'<div class="perm-desc">{p["desc_en"]}</div>'
                f'</div>'
                for p in pm['dangerous']
            ) or '<p style="color:#22c55e">✓ No dangerous permissions</p>'
            perm_th = '<tr><th>Risk</th><th>Permission</th><th dir="rtl">الوصف</th><th>Description</th></tr>'
        else:
            perm_cards_html = ''.join(
                f'<div class="perm-card">'
                f'{badge_html(p["risk"])}'
                f'<code class="perm-name">{p["name"].split(".")[-1]}</code>'
                f'<div class="perm-desc">{p["desc_en"]}</div>'
                f'</div>'
                for p in pm['dangerous']
            ) or '<p style="color:#22c55e">✓ No dangerous permissions</p>'
            perm_th = '<tr><th>Risk</th><th>Permission</th><th>Description</th></tr>'

        sec_html = ''
        for i in sec['issues']:
            clr = _badge_color(i['risk'])
            sec_html += (
                f'<div style="border-left:3px solid {clr};padding:10px 14px;margin:6px 0;'
                f'background:rgba(255,255,255,.03);border-radius:0 6px 6px 0">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
                f'{badge_html(i["risk"])} <strong>{i["title"]}</strong></div>'
                f'<p style="color:#94a3b8;font-size:.85rem">{i["desc"]}</p>'
                f'<p style="color:#4ade80;font-size:.85rem;margin-top:3px">>> {i["rec"]}</p></div>')
        if not sec_html:
            sec_html = '<p style="color:#22c55e">> No security issues</p>'

        secret_html = ''
        for s in self.d['secrets']:
            risk_color = {'CRITICAL': '#ef4444', 'HIGH': '#f97316', 'MEDIUM': '#eab308', 'LOW': '#22c55e'}.get(s['risk'], '#94a3b8')
            val_display = s['value']
            # Truncate very long values for display but show full in copy
            val_short = val_display[:80] + '...' if len(val_display) > 80 else val_display
            source = s.get('source', 'DEX strings')
            desc = s.get('description', '')
            ctx = s.get('context', '')
            ctx_html = ''
            if ctx:
                ctx_html = '<details><summary class="ctx-toggle">Context</summary><pre class="secret-ctx">' + self._esc(ctx) + '</pre></details>'
            secret_html += (
                f'<div class="secret-card">'
                f'<div class="secret-header">'
                f'<span class="risk-badge" style="background:{risk_color}">{s["risk"]}</span>'
                f'<strong class="secret-type">{self._esc(s["type"])}</strong>'
                f'<span class="secret-source">📍 {source}</span>'
                f'</div>'
                f'<div class="secret-desc">{self._esc(desc)}</div>'
                f'<div class="secret-val" onclick="navigator.clipboard.writeText(this.textContent)" title="Click to copy">'
                f'<code>{self._esc(val_short)}</code></div>'
                f'{ctx_html}'
                f'</div>')
        if not secret_html:
            secret_html = '<p style="color:#22c55e">✓ No secrets found</p>'

        srv_map = defaultdict(list)
        for url in ep['urls']:
            m = re.match(r'(https?://[^/?#]+)', url)
            if m:
                srv_map[m.group(1)].append(url[len(m.group(1)):] or '/')
        srv_html = ''
        for server, paths in srv_map.items():
            paths_h = ''.join(
                f'<div style="font-family:monospace;font-size:.75rem;color:#93c5fd;'
                f'background:rgba(255,255,255,.04);padding:3px 8px;border-radius:3px;margin:2px 0" dir="ltr">{p}</div>'
                for p in paths[:30])
            more = f'<small style="color:#64748b">...+{len(paths)-30} more</small>' if len(paths) > 30 else ''
            srv_html += (
                f'<div class="card" style="margin-bottom:12px">'
                f'<h4 style="color:#60a5fa;font-size:.9rem;margin-bottom:8px" dir="ltr">'
                f'<code>{server}</code> <span style="color:#64748b;font-size:.75rem">({len(paths)} paths)</span></h4>'
                f'{paths_h}{more}</div>')
        if not srv_html:
            srv_html = '<p style="color:#64748b">No endpoints</p>'

        vuln_html = ''
        for v in vulns:
            clr = _badge_color(v['risk'])
            vuln_html += (
                f'<div style="border-left:3px solid {clr};padding:12px 16px;margin:8px 0;'
                f'background:rgba(255,255,255,.03);border-radius:0 6px 6px 0">'
                f'<div style="display:flex;justify-content:space-between;margin-bottom:6px">'
                f'<strong>[{v["id"]}] {v["title"]}</strong>{badge_html(v["risk"])}</div>'
                f'<p style="color:#94a3b8;font-size:.85rem">{v["desc"]}</p>'
                f'<p style="color:#4ade80;font-size:.85rem;margin-top:4px">>> {v["rec"]}</p></div>')
        if not vuln_html:
            vuln_html = '<p style="color:#22c55e">> No vulnerabilities</p>'

        fw_pills = ''.join(f'<span class="pill">{fw}</span>' for fw in ar.get('frameworks', []))
        lib_pills = ''.join(f'<span class="pill">{l}</span>' for l in ar.get('libraries', []))
        nat_pills = ''.join(f'<span class="pill">{n}</span>' for n in ar.get('native', []))

        # Components & Deep Links HTML
        comp = self.d.get('components', {})
        dl_cards_html = ''
        for dl in comp.get('deep_links', []):
            paths_str = ', '.join(dl.get('paths', ['/']))[:80]
            verified = dl.get('verified', False)
            v_badge = '<span style="color:#22c55e">Verified</span>' if verified else '<span style="color:#f59e0b">Not Verified</span>'
            dl_cards_html += (
                f'<div class="card" style="margin-bottom:.5rem">'
                f'<div class="kv-label">URL Pattern</div>'
                f'<code dir="ltr" style="display:block;margin-bottom:.4rem">{dl["scheme"]}://{dl["host"]}{paths_str}</code>'
                f'<div style="display:flex;gap:1rem;align-items:center">'
                f'<div><span class="kv-label">Component</span><code>{dl.get("component","?").split(".")[-1]}</code></div>'
                f'<div><span class="kv-label">Status</span>{v_badge}</div>'
                f'</div></div>')
        if not dl_cards_html:
            dl_cards_html = '<p style="color:#64748b">No deep links</p>'

        exp_cards_html = ''
        for ex in comp.get('exported_no_perm', []):
            exp_cards_html += (
                f'<div class="card" style="margin-bottom:.5rem">'
                f'<div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">'
                f'<code>{ex["component"].split(".")[-1]}</code>'
                f'<span class="tag">{ex.get("type","?")}</span>'
                f'{badge_html(ex.get("risk","HIGH"))}'
                f'</div></div>')
        if not exp_cards_html:
            exp_cards_html = '<p style="color:#22c55e">No exported components without permission</p>'

        prov_cards_html = ''
        for pv in comp.get('provider_issues', []):
            prov_cards_html += (
                f'<div class="card" style="margin-bottom:.5rem">'
                f'<div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">'
                f'<code>{pv["component"].split(".")[-1]}</code>'
                f'<span class="kv-desc">{pv.get("issue","?")}</span>'
                f'</div></div>')
        if not prov_cards_html:
            prov_cards_html = '<p style="color:#22c55e">No provider issues</p>'

        comp_issues_html = ''
        for ci in comp.get('issues', []):
            clr = _badge_color(ci.get('risk', 'MEDIUM'))
            comp_issues_html += (
                f'<div style="border-left:3px solid {clr};padding:10px 14px;margin:6px 0;'
                f'background:rgba(255,255,255,.03);border-radius:0 6px 6px 0">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
                f'{badge_html(ci.get("risk","MEDIUM"))} <strong>{ci.get("title","")}</strong></div>'
                f'<p style="color:#94a3b8;font-size:.85rem">{ci.get("desc","")}</p>'
                f'<p style="color:#4ade80;font-size:.85rem;margin-top:3px">&gt;&gt; {ci.get("rec","")}</p></div>')
        if not comp_issues_html:
            comp_issues_html = '<p style="color:#22c55e">&gt; No component issues</p>'

        comp_html = (
            f'<h3 style="margin:0 0 .8rem">Deep Links</h3>'
            f'{dl_cards_html}'
            f'<h3 style="margin:1rem 0 .8rem">Exported Without Permission</h3>'
            f'{exp_cards_html}'
            f'<h3 style="margin:1rem 0 .8rem">Provider Issues</h3>'
            f'{prov_cards_html}'
            f'<h3 style="margin:1rem 0 .8rem">Security Issues</h3>{comp_issues_html}')

        ip_html = ''.join(f'<code class="tag">{ip}</code> ' for ip in ep.get('ips', [])[:15])
        email_html = ''.join(f'<code class="tag">{em}</code> ' for em in ep.get('emails', [])[:15])
        domain_html = ''.join(f'<code class="tag">{d}</code> ' for d in ep.get('domains', [])[:20])
        crit_n = sum(1 for v in vulns if v['risk'] == 'CRITICAL')
        high_n = sum(1 for v in vulns if v['risk'] == 'HIGH')

        # Arabic subtitles for sections (only when --lang ar)
        def ar_sub(text):
            return f'<span class="ar">{text}</span>' if is_ar else ''

        return f"""<!DOCTYPE html>
<html lang="{'ar' if is_ar else 'en'}" dir="ltr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NightOwl Report — {info.get('package', 'APK')}</title>
<style>
:root{{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--dim:#94a3b8;--accent:#3b82f6}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;word-wrap:break-word;overflow-wrap:break-word;-webkit-text-size-adjust:100%}}
.header{{background:linear-gradient(135deg,#0f172a,#1e3a5f);border-bottom:1px solid var(--border);padding:2rem;text-align:center}}
.header h1{{font-size:1.6rem;margin-bottom:.3rem}}.header .ar{{color:var(--dim);font-size:.95rem;direction:rtl}}
.meta{{color:var(--dim);font-size:.85rem}}
.score-pill{{display:inline-block;background:{sc_color};color:#fff;font-size:1.4rem;font-weight:700;padding:.4rem 1.5rem;border-radius:2rem;margin-top:.8rem}}
.container{{max-width:1200px;margin:0 auto;padding:1rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.8rem;margin:1rem 0}}
.stat-card{{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1rem;text-align:center}}
.stat-val{{font-size:1.6rem;font-weight:700}}.stat-lbl{{color:var(--dim);font-size:.7rem;margin-top:.2rem}}
.section{{background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1.2rem;margin-bottom:1rem}}
.section h2{{font-size:1rem;margin-bottom:.6rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}}
.section h2 .ar{{float:right;color:var(--dim);font-size:.85rem;direction:rtl}}
.card{{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:.5rem;padding:.8rem}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:.5rem .6rem;text-align:left;border-bottom:1px solid var(--border);font-size:.82rem;max-width:0;overflow:hidden;text-overflow:ellipsis;word-break:break-all}}
th{{color:var(--dim);font-weight:normal}}
code{{font-family:'JetBrains Mono',monospace;font-size:.78rem;background:rgba(255,255,255,.1);padding:1px 5px;border-radius:3px;word-break:break-all;white-space:pre-wrap}}
.pill{{display:inline-block;padding:2px 10px;border-radius:1rem;font-size:.72rem;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);margin:2px;color:#93c5fd}}
.tag{{display:inline-block;font-size:.72rem;background:rgba(255,255,255,.06);border:1px solid var(--border);padding:2px 6px;border-radius:3px;margin:2px}}
/* Secret cards */
.secret-card{{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:.6rem;padding:1rem;margin-bottom:.8rem}}
.secret-header{{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:.5rem}}
.risk-badge{{display:inline-block;padding:2px 10px;border-radius:1rem;font-size:.7rem;font-weight:700;color:#fff;text-transform:uppercase}}
.secret-type{{font-size:.95rem;color:#fbbf24}}
.secret-source{{font-size:.75rem;color:var(--dim);margin-left:auto}}
.secret-desc{{font-size:.82rem;color:var(--dim);margin-bottom:.6rem;line-height:1.5}}
.secret-val{{cursor:pointer;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:.4rem;padding:.5rem .8rem;margin-bottom:.4rem;transition:background .2s}}
.secret-val:hover{{background:rgba(255,255,255,.1)}}
.secret-val code{{background:none;padding:0;font-size:.82rem;word-break:break-all;white-space:pre-wrap;display:block;max-height:4em;overflow-y:auto}}
.ctx-toggle{{font-size:.78rem;color:var(--accent);cursor:pointer;margin:.3rem 0}}
.secret-ctx{{font-size:.72rem;background:rgba(0,0,0,.3);padding:.5rem;border-radius:.3rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:6em;overflow-y:auto}}
/* Responsive mobile */
@media(max-width:640px){{
  .container{{padding:.8rem}}
  .header h1{{font-size:1.2rem}}
  .grid{{grid-template-columns:repeat(2,1fr)}}
  .stat-val{{font-size:1.3rem}}
  .section{{padding:.8rem}}
  th,td{{padding:.4rem;font-size:.75rem}}
  .secret-header{{flex-direction:column;align-items:flex-start;gap:.3rem}}
  .secret-source{{margin-left:0}}
  .secret-val code{{font-size:.75rem}}
  table{{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}}
}}
footer{{text-align:center;padding:1.5rem;color:var(--dim);font-size:.72rem;border-top:1px solid var(--border)}}
[dir="rtl"]{{text-align:right}}
/* Key-Value Grid */
.kv-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}}
.kv-item{{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:.5rem;padding:.6rem .8rem}}
.kv-full{{grid-column:1/-1}}
.kv-label{{display:block;font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:.25rem}}
.kv-value{{font-size:.9rem;word-break:break-all}}
.kv-hash code{{font-size:.72rem;background:rgba(255,255,255,.06);padding:2px 6px;border-radius:3px;word-break:break-all;white-space:pre-wrap}}
/* Permission Cards */
.perm-card{{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:.5rem;padding:.7rem .9rem;margin-bottom:.5rem;display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}}
.perm-name{{font-size:.82rem;color:#fbbf24;margin-left:.3rem}}
.perm-desc{{font-size:.78rem;color:var(--dim);line-height:1.4;margin-top:.2rem;flex-basis:100%}}
@media(max-width:640px){{
  .kv-grid{{grid-template-columns:1fr}}
  .perm-card{{flex-direction:column;align-items:flex-start;gap:.3rem}}
  .perm-name{{margin-left:0}}
}}
</style></head><body>
<div class="header">
<h1>NightOwl — APK Security Report</h1>
{'<p class="ar">تقرير الأمان — نايت أول</p>' if is_ar else ''}
<p class="meta">{self.d['ts']} &middot; {self.path.name}</p>
<div class="score-pill">Security Score: {score}/100</div></div>
<div class="container">
<div class="grid">
<div class="stat-card"><div class="stat-val" style="color:#ef4444">{crit_n}</div><div class="stat-lbl">CRITICAL{' | حرج' if is_ar else ''}</div></div>
<div class="stat-card"><div class="stat-val" style="color:#f97316">{high_n}</div><div class="stat-lbl">HIGH{' | عالي' if is_ar else ''}</div></div>
<div class="stat-card"><div class="stat-val" style="color:#3b82f6">{len(ep['servers'])}</div><div class="stat-lbl">Servers{' | خوادم' if is_ar else ''}</div></div>
<div class="stat-card"><div class="stat-val" style="color:#22c55e">{len(ep['urls'])}</div><div class="stat-lbl">Endpoints{' | نقاط' if is_ar else ''}</div></div>
<div class="stat-card"><div class="stat-val" style="color:#ef4444">{len(self.d['secrets'])}</div><div class="stat-lbl">Secrets{' | أسرار' if is_ar else ''}</div></div>
<div class="stat-card"><div class="stat-val">{len(pm['all'])}</div><div class="stat-lbl">Permissions{' | أذونات' if is_ar else ''}</div></div>
</div>
<div class="section"><h2>1. Basic Information {ar_sub('المعلومات الأساسية')}</h2>
<div class="kv-grid">
  <div class="kv-item"><span class="kv-label">Package</span><span class="kv-value" dir="ltr"><code>{info.get('package','N/A')}</code></span></div>
  <div class="kv-item"><span class="kv-label">Version</span><span class="kv-value">{info.get('version_name','?')} (build {info.get('version_code','?')})</span></div>
  <div class="kv-item"><span class="kv-label">File</span><span class="kv-value">{info.get('file_name','?')}</span></div>
  <div class="kv-item"><span class="kv-label">Size</span><span class="kv-value">{info.get('file_size_mb','?')} MB</span></div>
  <div class="kv-item"><span class="kv-label">Min SDK</span><span class="kv-value">{info.get('min_sdk','?')}</span></div>
  <div class="kv-item"><span class="kv-label">Target SDK</span><span class="kv-value">{info.get('target_sdk','?')}</span></div>
  <div class="kv-item"><span class="kv-label">DEX Files</span><span class="kv-value">{info.get('dex_count',1)}</span></div>
  <div class="kv-item"><span class="kv-label">Activities</span><span class="kv-value">{info.get('activities','?')}</span></div>
  <div class="kv-item"><span class="kv-label">Native Libs</span><span class="kv-value">{'Yes' if info.get('has_native') else 'No'}</span></div>
  <div class="kv-item"><span class="kv-label">Signed</span><span class="kv-value">{'V' + str(info.get('sign_scheme','?')) if info.get('signed') else 'No'}</span></div>
  <div class="kv-item kv-full"><span class="kv-label">MD5</span><span class="kv-value kv-hash" dir="ltr"><code>{info.get('md5','?')}</code></span></div>
  <div class="kv-item kv-full"><span class="kv-label">SHA256</span><span class="kv-value kv-hash" dir="ltr"><code>{info.get('sha256','?')}</code></span></div>
</div></div>
<div class="section"><h2>2. Permissions {ar_sub('الأذونات')}</h2>
<p style="margin-bottom:.8rem">Total: <strong>{len(pm['all'])}</strong> | Dangerous: <strong style="color:#ef4444">{len(pm['dangerous'])}</strong></p>
{perm_cards_html}</div>
<div class="section"><h2>3. Endpoints {ar_sub('نقاط الـ API')}</h2>
<p style="margin-bottom:1rem;color:var(--dim)">Servers: <strong style="color:#60a5fa">{len(ep['servers'])}</strong> | URLs: <strong>{len(ep['urls'])}</strong> | IPs: <strong>{len(ep['ips'])}</strong></p>
<div style="display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem">
{''.join(f'<code style="background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.3);padding:4px 10px;border-radius:4px;color:#93c5fd" dir="ltr">{s}</code>' for s in ep['servers'])}</div>
{'<div class="card" style="margin-bottom:8px"><strong>IPs:</strong><br>'+ip_html+'</div>' if ip_html else ''}
{'<div class="card" style="margin-bottom:8px"><strong>Emails:</strong><br>'+email_html+'</div>' if email_html else ''}
{'<div class="card" style="margin-bottom:8px"><strong>Domains:</strong><br>'+domain_html+'</div>' if domain_html else ''}
</div>
<div class="section"><h2>4. Security {ar_sub('التحليل الأمني')}</h2>
<p style="margin-bottom:1rem">Score: <span style="color:{sc_color};font-weight:700;font-size:1.2rem">{score}/100</span></p>
{sec_html}
<div class="section"><h2>4a. Secrets Found ({len(self.d['secrets'])}) {ar_sub('الأسرار المكتشفة')}</h2>{secret_html}</div>
<div class="section"><h2>5. All Endpoints — Grouped {ar_sub('جميع نقاط الـ API')}</h2>{srv_html}</div>
<div class="section"><h2>6. Architecture {ar_sub('البنية التقنية')}</h2>
<p><strong>Frameworks:</strong> {fw_pills or '<span style="color:var(--dim)">Not detected</span>'}</p>
<p style="margin-top:.5rem"><strong>Libraries:</strong> {lib_pills or '<span style="color:var(--dim)">-</span>'}</p>
<p style="margin-top:.5rem"><strong>Native:</strong> {nat_pills or '<span style="color:var(--dim)">None</span>'}</p>
{'<p style="margin-top:.5rem;color:#f59e0b">Obfuscation: '+', '.join(ar.get('obfuscation',[]))+'</p>' if ar.get('obfuscation') else ''}
</div>
<div class="section"><h2>7. Vulnerabilities {ar_sub('الثغرات')}</h2>{vuln_html}</div>
<div class="section"><h2>8. Components & Deep Links {ar_sub('المكونات والروابط العميقة')}</h2>{comp_html}</div>
<div class="section"><h2>9. Frida Dynamic Analysis {ar_sub('تحليل فريدا الديناميكي')}</h2>
<p style="margin-bottom:1rem;color:var(--dim)">Frida is a dynamic instrumentation toolkit for runtime analysis. Customize and download scripts below.</p>

<!-- Package Name Input -->
<div style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);border-radius:6px;padding:12px;margin-bottom:1rem">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <label style="color:#60a5fa;font-weight:bold;white-space:nowrap">📦 Package Name:</label>
    <input type="text" id="pkg-input" value="{info.get('package','com.example.app')}" 
           style="flex:1;min-width:200px;padding:6px 12px;border-radius:4px;border:1px solid #3b82f6;background:rgba(0,0,0,.3);color:#e2e8f0;font-family:monospace"
           oninput="updateAllCommands(this.value)">
    <button onclick="updateAllCommands(document.getElementById('pkg-input').value)" 
            style="background:#3b82f6;color:white;border:none;padding:6px 16px;border-radius:4px;cursor:pointer">
      🔄 Update All Commands
    </button>
  </div>
</div>

<!-- Requirements -->
<div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:6px;padding:12px;margin-bottom:1rem">
<strong style="color:#ef4444">⚠️ Requirements:</strong> Rooted device or emulator with frida-server running<br>
<strong style="color:#f59e0b">Install:</strong> <code>pip install frida-tools</code> | <code>frida-deploy</code> to push server to device</div>

<!-- Tab Navigation -->
<div style="display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap">
  <button onclick="showTab('api')" id="tab-api" class="frida-tab active" style="background:#3b82f6;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer">📡 API Interceptor</button>
  <button onclick="showTab('ssl')" id="tab-ssl" class="frida-tab" style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:8px 16px;border-radius:4px;cursor:pointer">🔓 SSL Bypass</button>
  <button onclick="showTab('memory')" id="tab-memory" class="frida-tab" style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:8px 16px;border-radius:4px;cursor:pointer">🧠 Memory Dump</button>
  <button onclick="showTab('hooks')" id="tab-hooks" class="frida-tab" style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:8px 16px;border-radius:4px;cursor:pointer">🪝 Custom Hooks</button>
</div>

<!-- Script 1: API Interceptor -->
<div id="panel-api" class="frida-panel">
<div class="card" style="margin-bottom:12px">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
  <h4 style="color:#3b82f6;margin:0">📡 API & Network Interceptor</h4>
  <div style="display:flex;gap:8px">
    <button onclick="copyScript('api-interceptor')" style="background:#3b82f6;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">📋 Copy</button>
    <button onclick="downloadScript('api-interceptor', 'api-interceptor.js')" style="background:#22c55e;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">💾 Download</button>
  </div>
</div>
<p style="color:var(--dim);font-size:.8rem;margin-bottom:8px">Captures ALL HTTP/HTTPS traffic including headers, bodies, and responses. Auto-bypasses SSL pinning.</p>
<code class="frida-cmd" data-script="api" style="font-size:.75rem;color:#22c55e;display:block;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">frida -U -n {info.get('package','com.example.app')} -l frida-scripts/api-interceptor.js</code>
<pre id="api-interceptor" style="background:rgba(0,0,0,.3);padding:12px;border-radius:6px;overflow-x:auto;font-size:.72rem;color:#e2e8f0;margin-top:8px;max-height:300px;overflow-y:auto"><code>// NightOwl — Advanced API & Network Interceptor
// Captures ALL HTTP/HTTPS requests, responses, headers, and bodies at runtime

'use strict';

const TAG = '[NightOwl-Intercept]';
const captured = {{ requests: [], secrets: new Set() }};

const log  = m  => console.log(`${{TAG}} [*] ${{m}}`);
const warn = m  => console.log(`${{TAG}} [!] ${{m}}`);
const info = m  => console.log(`${{TAG}} [+] ${{m}}`);

function trunc(s, n = 500) {{
    s = String(s);
    return s.length > n ? s.slice(0, n) + `…[+${{s.length - n}}]` : s;
}}

function record(req) {{
    captured.requests.push(req);
    console.log(`\n╔──────────────────────────────────────────────────\n║ ${{req.method}} ${{req.url}}\n╚──────────────────────────────────────────────────`);
}}

// Hook OkHttp, Retrofit, HttpURLConnection, Volley, WebView
Java.perform(function() {{
    // OkHttp3
    try {{
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const RealCall = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.execute.implementation = function() {{
            const request = this.request();
            info(`OkHttp: ${{request.method()}} ${{request.url()}}`);
            return this.execute();}};
        log('OkHttp3 hooked');
    }} catch(e) {{}}

    // HttpURLConnection
    try {{
        const URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {{
            info(`URL.openConnection: ${{this.toString()}}`);
            return this.openConnection();}};
        log('HttpURLConnection hooked');
    }} catch(e) {{}}
}});</code></pre>
</div>
</div>

<!-- Script 2: SSL Bypass -->
<div id="panel-ssl" class="frida-panel" style="display:none">
<div class="card" style="margin-bottom:12px">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
  <h4 style="color:#f59e0b;margin:0">🔓 SSL Pinning Bypass</h4>
  <div style="display:flex;gap:8px">
    <button onclick="copyScript('ssl-bypass')" style="background:#f59e0b;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">📋 Copy</button>
    <button onclick="downloadScript('ssl-bypass', 'ssl-bypass.js')" style="background:#22c55e;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">💾 Download</button>
  </div>
</div>
<p style="color:var(--dim);font-size:.8rem;margin-bottom:8px">Bypasses all known SSL pinning implementations: OkHttp3, TrustManager, WebView, HostnameVerifier.</p>
<code class="frida-cmd" data-script="ssl" style="font-size:.75rem;color:#22c55e;display:block;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">frida -U -n {info.get('package','com.example.app')} -l frida-scripts/ssl-bypass.js --no-pause</code>
<pre id="ssl-bypass" style="background:rgba(0,0,0,.3);padding:12px;border-radius:6px;overflow-x:auto;font-size:.72rem;color:#e2e8f0;margin-top:8px;max-height:300px;overflow-y:auto"><code>// NightOwl — Focused SSL Pinning Bypass
// Bypasses all known SSL pinning implementations on Android

'use strict';

const TAG = '[NightOwl-SSL]';
let bypassed = 0;

function log(msg)  {{ console.log(`${{TAG}} [+] ${{msg}}`); }}
function warn(msg) {{ console.log(`${{TAG}} [!] ${{msg}}`); }}

// 1. OkHttp3 CertificatePinner
function bypassOkHttp3() {{
    try {{
        const CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname) {{
            warn(`OkHttp3 CertificatePinner.check bypassed for: ${{hostname}}`);}};
        log('OkHttp3 CertificatePinner bypassed');
        bypassed++;
    }} catch (_)
    {{}}
}}

// 2. TrustManagerImpl
function bypassTrustManagerImpl() {{
    try {{
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain) {{
            warn('TrustManagerImpl.verifyChain bypassed');
            return untrustedChain;}};
        log('TrustManagerImpl bypassed');
        bypassed++;
    }} catch (_)
    {{}}
}}

// Run all bypasses
Java.perform(function() {{
    bypassOkHttp3();
    bypassTrustManagerImpl();
    log(`SSL bypass complete: ${{bypassed}} techniques applied`);
}});</code></pre>
</div>
</div>

<!-- Script 3: Memory Dump -->
<div id="panel-memory" class="frida-panel" style="display:none">
<div class="card" style="margin-bottom:12px">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
  <h4 style="color:#22c55e;margin:0">🧠 Memory Dump & Analysis</h4>
  <div style="display:flex;gap:8px">
    <button onclick="copyScript('memory-dump')" style="background:#22c55e;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">📋 Copy</button>
    <button onclick="downloadScript('memory-dump', 'memory-dump.js')" style="background:#22c55e;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">💾 Download</button>
  </div>
</div>
<p style="color:var(--dim);font-size:.8rem;margin-bottom:8px">Dumps and searches memory for secrets, API keys, and sensitive data.</p>
<code class="frida-cmd" data-script="memory" style="font-size:.75rem;color:#22c55e;display:block;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">frida -U -n {info.get('package','com.example.app')} -l frida-scripts/memory-dump.js --no-pause</code>
<pre id="memory-dump" style="background:rgba(0,0,0,.3);padding:12px;border-radius:6px;overflow-x:auto;font-size:.72rem;color:#e2e8f0;margin-top:8px;max-height:300px;overflow-y:auto"><code>// NightOwl — Memory Dump & Analysis Script

'use strict';

const TAG = '[NightOwl-Memory]';

function log(msg)  {{ console.log(`${{TAG}} [+] ${{msg}}`); }}
function warn(msg) {{ console.log(`${{TAG}} [!] ${{msg}}`); }}

// 1. List loaded modules
function listModules() {{
    info('Loaded modules:');
    const modules = Process.enumerateModules();
    modules.forEach(function (m) {{
        console.log(`  ${{m.name.padEnd(40)}} base=${{m.base}} size=${{m.size}}`);}});
    log(`Total modules: ${{modules.length}}`);
    return modules;
}}

// 2. Search memory for string
function searchString(pattern) {{
    info(`Searching memory for: "${{pattern}}"`);
    const ranges = Process.enumerateRanges('r--');
    let found = 0;
    ranges.forEach(function (range) {{
        try {{
            const matches = Memory.scanSync(range.base, range.size, pattern);
            matches.forEach(function (match) {{
                warn(`Found at ${{match.address}}`);
                found++;}});
        }} catch (_)
        {{}}
    }});
    log(`Search complete: ${{found}} matches for "${{pattern}}"`);
}}

// Run all
setTimeout(function() {{
    listModules();
    searchString('password');
    searchString('api_key');
    searchString('token');
}}, 1000);</code></pre>
</div>
</div>

<!-- Script 4: Custom Hooks -->
<div id="panel-hooks" class="frida-panel" style="display:none">
<div class="card" style="margin-bottom:12px">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
  <h4 style="color:#a855f7;margin:0">🪝 Custom Method Hooks</h4>
  <div style="display:flex;gap:8px">
    <button onclick="copyScript('custom-hooks')" style="background:#a855f7;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">📋 Copy</button>
    <button onclick="downloadScript('custom-hooks', 'custom-hooks.js')" style="background:#22c55e;color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.75rem">💾 Download</button>
  </div>
</div>
<p style="color:var(--dim);font-size:.8rem;margin-bottom:8px">Template for hooking custom methods. Edit the class/method names below.</p>
<code class="frida-cmd" data-script="hooks" style="font-size:.75rem;color:#22c55e;display:block;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">frida -U -n {info.get('package','com.example.app')} -l frida-scripts/custom-hooks.js --no-pause</code>
<pre id="custom-hooks" style="background:rgba(0,0,0,.3);padding:12px;border-radius:6px;overflow-x:auto;font-size:.72rem;color:#e2e8f0;margin-top:8px;max-height:300px;overflow-y:auto"><code>// NightOwl — Custom Method Hooks Template
// Edit the class and method names below to hook specific functions

'use strict';

Java.perform(function() {{
    // Example: Hook a specific class method
    try {{
        const TargetClass = Java.use('com.example.app.TargetClass');
        
        // Hook method with no arguments
        TargetClass.targetMethod.implementation = function() {{
            console.log('[HOOK] targetMethod() called');
            const result = this.targetMethod();
            console.log('[HOOK] targetMethod() returned: ' + result);
            return result;
        }};
        
        // Hook overloaded method
        TargetClass.targetMethod.overload('java.lang.String').implementation = function(arg) {{
            console.log('[HOOK] targetMethod(" + arg + ") called');
            return this.targetMethod(arg);
        }};
        
        console.log('[+] Hooks installed successfully');
    }} catch(e) {{
        console.log('[-] Hook failed: ' + e);
    }}
}});</code></pre>
</div>
</div>

<!-- Contextual Recommendations -->
<div style="background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);border-radius:6px;padding:12px;margin-top:1rem">
<h4 style="color:#60a5fa;margin-bottom:8px">💡 Recommended Testing Workflow</h4>
<ol style="color:var(--dim);font-size:.85rem;padding-left:1.5rem">
<li style="margin-bottom:6px"><strong style="color:#3b82f6">Start with API Interceptor</strong> — captures all network traffic</li>
<li style="margin-bottom:6px"><strong style="color:#f59e0b">If SSL errors persist</strong> — use ssl-bypass.js</li>
<li style="margin-bottom:6px"><strong style="color:#22c55e">Memory analysis</strong> — search for leaked secrets</li>
<li style="margin-bottom:6px"><strong style="color:#a855f7">Interactive testing</strong> — use <code>objection -g {info.get('package','com.example.app')} explore</code></li>
</ol>
</div>

<!-- Quick Commands -->
<div style="background:rgba(0,0,0,.2);border-radius:6px;padding:12px;margin-top:1rem">
<h4 style="color:#94a3b8;margin-bottom:8px">⚡ Quick Commands</h4>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:8px">
  <code style="font-size:.75rem;color:#22c55e;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">adb root && adb shell "setenforce 0"</code>
  <code style="font-size:.75rem;color:#22c55e;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">frida-ps -U | grep {info.get('package','com.example.app')}</code>
  <code style="font-size:.75rem;color:#22c55e;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">objection -g {info.get('package','com.example.app')} explore</code>
</div>
</div>
</div>
<script>
// Tab switching
function showTab(tabName) {{
  // Hide all panels
  document.querySelectorAll('.frida-panel').forEach(p => p.style.display = 'none');
  // Deactivate all tabs
  document.querySelectorAll('.frida-tab').forEach(t => {{
    t.style.background = '#1e293b';
    t.style.color = '#94a3b8';
    t.style.border = '1px solid #334155';
  }});
  // Show selected panel
  document.getElementById('panel-' + tabName).style.display = 'block';
  // Activate selected tab
  const activeTab = document.getElementById('tab-' + tabName);
  activeTab.style.background = '#3b82f6';
  activeTab.style.color = 'white';
  activeTab.style.border = 'none';
}}

// Update all commands with new package name
function updateAllCommands(pkg) {{
  if (!pkg) return;
  document.querySelectorAll('.frida-cmd').forEach(el => {{
    const script = el.dataset.script;
    let cmd = '';
    switch(script) {{
      case 'api': cmd = `frida -U -n ${{pkg}} -l frida-scripts/api-interceptor.js`; break;
      case 'ssl': cmd = `frida -U -n ${{pkg}} -l frida-scripts/ssl-bypass.js --no-pause`; break;
      case 'memory': cmd = `frida -U -n ${{pkg}} -l frida-scripts/memory-dump.js --no-pause`; break;
      case 'hooks': cmd = `frida -U -n ${{pkg}} -l frida-scripts/custom-hooks.js --no-pause`; break;
    }}
    el.textContent = cmd;
  }});
  // Update quick commands too
  document.querySelectorAll('code').forEach(el => {{
    if (el.textContent.includes('frida-ps')) {{
      el.textContent = `frida-ps -U | grep ${{pkg}}`;
    }}
    if (el.textContent.includes('objection')) {{
      el.textContent = `objection -g ${{pkg}} explore`;
    }}
  }});
}}

// Copy script to clipboard
function copyScript(id) {{
  const pre = document.getElementById(id);
  const text = pre.textContent;
  navigator.clipboard.writeText(text).then(() => {{
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    btn.style.background = '#22c55e';
    setTimeout(() => {{ btn.textContent = orig; btn.style.background = ''; }}, 2000);
  }}).catch(err => {{
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    alert('Script copied to clipboard!');
  }});
}}

// Download script as file
function downloadScript(id, filename) {{
  const pre = document.getElementById(id);
  const text = pre.textContent;
  const blob = new Blob([text], {{ type: 'application/javascript' }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  // Visual feedback
  const btn = event.target;
  const orig = btn.textContent;
  btn.textContent = '✅ Downloaded!';
  setTimeout(() => {{ btn.textContent = orig; }}, 2000);
}}
</script>
<footer>Generated by NightOwl v{__version__} — For authorized security testing only{' | للاختبار الأمني المرخص فقط' if is_ar else ''}</footer>
</body></html>"""


# ═══════════════════════════════════════════════════════════════════════
# BANNER · GUIDE · PROXY · SCAN
# ═══════════════════════════════════════════════════════════════════════

def show_banner():
    if RICH:
        t = Text()
        t.append("NightOwl", style="bold cyan")
        t.append(f" v{__version__}\n", style="dim")
        t.append("Advanced Android Security Analyzer", style="white")
        con.print(Panel(t, border_style="cyan", box=box.DOUBLE_EDGE, padding=(0, 2)))
    else:
        print(f"\n  NightOwl v{__version__} — Android APK Security Analyzer\n")


def _err(msg):
    if RICH:
        con.print(Panel(f"[bold red]x Error:[/] {esc(str(msg))}", border_style="red", box=box.ROUNDED))
    else:
        print(f"\n  [ERROR] {msg}\n")


def _warn(msg):
    if RICH:
        con.print(f"  [yellow]! {esc(str(msg))}[/]")
    else:
        print(f"  [WARN] {msg}")


def cmd_guide():
    """Show comprehensive usage guide."""
    show_banner()
    if not RICH:
        print("  Install 'rich' for the full guide: pip install rich\n")
        print("  Commands: full, info, perms, urls, secrets, arch, vulns, manifest, scan, guide, proxy")
        return
    # Static analysis commands
    t1 = Table(title="[bold cyan]Static Analysis Commands[/]", box=box.ROUNDED,
               border_style="cyan", expand=True)
    t1.add_column("Command", style="bold yellow", no_wrap=True)
    t1.add_column("Description", style="white")
    t1.add_row("nightowl [bold]full[/] app.apk", "Full 9-step analysis (DEX + native + APIs)")
    t1.add_row("nightowl [bold]apis[/] app.apk", "Fast API/endpoint extraction (native-aware)")
    t1.add_row("nightowl [bold]decompile[/] app.apk", "Full decompile: jadx + apktool + native")
    t1.add_row("nightowl [bold]info[/] app.apk", "Basic APK info & hashes")
    t1.add_row("nightowl [bold]perms[/] app.apk", "Permission risk analysis")
    t1.add_row("nightowl [bold]urls[/] app.apk", "URLs, endpoints, servers")
    t1.add_row("nightowl [bold]secrets[/] app.apk", "API keys, tokens, passwords")
    t1.add_row("nightowl [bold]arch[/] app.apk", "Frameworks & libraries")
    t1.add_row("nightowl [bold]vulns[/] app.apk", "Security score & vulns")
    t1.add_row("nightowl [bold]manifest[/] app.apk", "Components & activities")
    t1.add_row("nightowl [bold]scan[/] [dim][dir][/]", "Batch scan APKs (default: targets/)")
    con.print(t1)
    con.print()

    # Notes about Flutter apps
    con.print(Panel(
        "[bold]Flutter / React Native apps:[/]\n"
        "  These frameworks compile code into native [cyan]libapp.so[/] / [cyan]libflutter.so[/]\n"
        "  DEX scanning alone misses all API endpoints!\n"
        "  NightOwl automatically scans native libs for URLs, secrets, and API paths.\n"
        "  Use [cyan]nightowl decompile app.apk[/] + jadx for full source reconstruction.",
        border_style="yellow", box=box.ROUNDED,
        title="[dim]Native App Note[/]", title_align="left",
    ))
    con.print()

    # Dynamic analysis commands
    t2 = Table(title="[bold red]Dynamic Analysis[/] [dim](requires rooted device + frida-server)[/]",
               box=box.ROUNDED, border_style="red", expand=True)
    t2.add_column("Step", style="dim", width=6)
    t2.add_column("Command", style="yellow")
    t2.add_column("Purpose")
    t2.add_row("1", "source env.sh", "Load tool aliases")
    t2.add_row("2", "frida-deploy", "Push frida-server to device")
    t2.add_row("3", "frida-intercept com.app -l frida-scripts/api-interceptor.js",
               "Capture all HTTP traffic + SSL bypass")
    t2.add_row("4", "frida -f com.app -l frida-scripts/ssl-bypass.js --no-pause",
               "Dedicated SSL pinning bypass")
    t2.add_row("5", "frida -f com.app -l frida-scripts/memory-dump.js --no-pause",
               "Memory analysis & secret scanning")
    t2.add_row("6", "obj com.app", "Interactive objection shell")
    con.print(t2)
    con.print()

    # Flags
    t3 = Table(title="[bold]Flags[/]", box=box.SIMPLE, expand=True)
    t3.add_column("Flag", style="yellow")
    t3.add_column("Effect")
    t3.add_row("--json", "Output JSON only (for scripting & AI agents)")
    t3.add_row("--save", "Save HTML + MD + JSON reports to disk")
    t3.add_row("--report-dir DIR", "Custom report output directory")
    t3.add_row("--lang ar", "Generate reports with Arabic translations")
    con.print(t3)
    con.print()

    # Directory structure
    tree = Tree("[bold cyan]Directory Structure[/]", guide_style="dim blue")
    tree.add("[bold]targets/[/]         [dim]<- Place APK files here for scanning[/]")
    tree.add("[bold]workspace/reports/[/] [dim]<- Reports saved here[/]")
    tree.add("[bold]frida-scripts/[/]    [dim]<- Frida hook scripts[/]")
    tree.add("[bold]tools/[/]            [dim]<- Installed binary tools[/]")
    con.print(tree)
    con.print()

    # Tips
    con.print(Panel(
        "[bold]Tips[/]\n"
        "  Run [cyan]nightowl app.apk[/] — auto-runs full analysis\n"
        "  Run [cyan]nightowl scan[/] — scans all APKs in [bold]targets/[/]\n"
        "  Use [cyan]--json[/] for AI-agent-parseable output\n"
        "  Use [cyan]--lang ar[/] for Arabic report export\n"
        "  Check [bold]SKILL.md[/] for AI agent integration manual",
        border_style="green", box=box.ROUNDED,
        title="[dim]Pro Tips[/]", title_align="left",
    ))


def cmd_proxy():
    """Network proxy setup instructions."""
    show_banner()
    if RICH:
        con.print(Panel("[bold]Network Proxy Setup[/]",
                        border_style="blue", box=box.DOUBLE_EDGE))
        t = Table(box=box.ROUNDED, border_style="dim", expand=True)
        t.add_column("Tool", style="cyan bold")
        t.add_column("Setup Command", style="yellow")
        t.add_column("Notes")
        t.add_row("mitmproxy", "pip install mitmproxy && mitmproxy --listen-port 8080",
                   "Transparent proxy, auto-captures HTTPS")
        t.add_row("Burp Suite", "Open Burp -> Proxy -> Options -> Bind 0.0.0.0:8080",
                   "Set device WiFi proxy to PC_IP:8080")
        t.add_row("Device Proxy", "adb shell settings put global http_proxy PC_IP:8080",
                   "Route all device traffic through proxy")
        t.add_row("Clear Proxy", "adb shell settings put global http_proxy :0",
                   "Remove proxy from device")
        t.add_row("Install CA", "adb push cert.pem /sdcard/ && install via Settings",
                   "Needed for HTTPS interception")
        con.print(t)
        con.print()
        con.print("[dim]For automated setup, run: bash scripts/network-setup.sh[/]\n")
    else:
        print("  Network Proxy Setup:")
        print("  mitmproxy: pip install mitmproxy && mitmproxy --listen-port 8080")
        print("  Burp Suite: Bind 0.0.0.0:8080 and set device WiFi proxy")
        print("  Device: adb shell settings put global http_proxy PC_IP:8080")
        print("  Clear:  adb shell settings put global http_proxy :0")


def cmd_scan(directory=None, lang='en'):
    """Batch scan all APKs in a directory."""
    scan_dir = Path(directory) if directory else TARGETS
    scan_dir.mkdir(parents=True, exist_ok=True)
    show_banner()
    apks = sorted(scan_dir.glob("*.apk"))
    if not apks:
        _warn(f"No APK files found in {scan_dir}")
        if RICH:
            con.print(f"  [dim]Place APK files in:[/] [bold]{scan_dir}[/]\n")
        return
    if RICH:
        con.print(f"  [cyan]Batch scan:[/] [bold]{len(apks)}[/] APKs in [bold]{scan_dir}[/]\n")
    results = []
    for apk_path in apks:
        az = NightOwlAnalyzer(str(apk_path), lang=lang)
        if az.run_full():
            az.save()
            results.append({
                'file': apk_path.name,
                'package': az.d['info'].get('package', '?'),
                'score': az.d['security']['score'],
                'vulns': len(az.d['vulns']),
                'secrets': len(az.d['secrets']),
            })
    if RICH and results:
        con.print()
        t = Table(title="[bold]Batch Scan Results[/]", box=box.ROUNDED,
                  border_style="cyan", expand=True)
        t.add_column("APK", style="white")
        t.add_column("Package", style="dim")
        t.add_column("Score", justify="center")
        t.add_column("Vulns", justify="center")
        t.add_column("Secrets", justify="center")
        for r in results:
            sc = r['score']
            sc_s = f"[green]{sc}[/]" if sc >= 80 else f"[yellow]{sc}[/]" if sc >= 60 else f"[red]{sc}[/]"
            con.print()
            t.add_row(r['file'], r['package'], sc_s, str(r['vulns']), str(r['secrets']))
        con.print(t)
        con.print()


def cmd_decompile(apk_path: str, out_dir: str = None):
    """Full decompilation pipeline: jadx (Java source) + apktool (smali/resources)."""
    import subprocess
    apk_path = _resolve_apk(apk_path)
    apk = Path(apk_path)
    if not apk.exists():
        _err(f"APK not found: {apk_path}")
        return False

    stem = apk.stem
    base_out = Path(out_dir) if out_dir else WORKSPACE / "decompiled" / stem
    base_out.mkdir(parents=True, exist_ok=True)

    show_banner()
    if RICH:
        con.print(Panel(
            f"[bold]Decompiling:[/] [cyan]{apk.name}[/]\n"
            f"[dim]Output: {base_out}[/]",
            border_style="cyan", box=box.ROUNDED
        ))
    else:
        print(f"  Decompiling: {apk.name}\n  Output: {base_out}")

    results = {}

    # jadx — Java/Kotlin source reconstruction
    jadx_out = base_out / "jadx-src"
    jadx_path = JADX
    jadx_ok = False
    if jadx_path and Path(jadx_path).exists():
        if RICH:
            con.print(f"  [cyan]>[/] Running jadx...")
        jadx_out.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run(
                [jadx_path, '--output-dir', str(jadx_out),
                 '--no-res', '--show-bad-code', '--deobf', str(apk)],
                capture_output=True, text=True, timeout=300
            )
            jadx_ok = r.returncode == 0 or jadx_out.exists()
            results['jadx'] = str(jadx_out) if jadx_ok else f"FAILED: {r.stderr[:200]}"
            if RICH:
                st = "[green]done[/]" if jadx_ok else "[red]failed[/]"
                con.print(f"    jadx: {st}")
        except Exception as e:
            results['jadx'] = f"ERROR: {e}"
            if RICH:
                con.print(f"    [red]jadx error: {e}[/]")
    else:
        results['jadx'] = f"SKIPPED (jadx not found at {jadx_path})"
        _warn(f"jadx not found — install with: scripts/smart-update.sh")

    # apktool — smali + resources
    apktool_path = APKTOOL
    apktool_out = base_out / "apktool"
    apktool_ok = False
    if shutil.which('apktool') or Path(apktool_path).exists():
        if RICH:
            con.print(f"  [cyan]>[/] Running apktool...")
        try:
            cmd = ['apktool', 'd', '-f', '-o', str(apktool_out), str(apk)]
            if not shutil.which('apktool'):
                cmd = ['java', '-jar', apktool_path + '.jar', 'd', '-f', '-o',
                       str(apktool_out), str(apk)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            apktool_ok = r.returncode == 0
            results['apktool'] = str(apktool_out) if apktool_ok else f"FAILED: {r.stderr[:200]}"
            if RICH:
                st = "[green]done[/]" if apktool_ok else "[red]failed[/]"
                con.print(f"    apktool: {st}")
        except Exception as e:
            results['apktool'] = f"ERROR: {e}"
            if RICH:
                con.print(f"    [red]apktool error: {e}[/]")
    else:
        results['apktool'] = "SKIPPED (apktool not found)"
        _warn("apktool not found — install with: sudo apt-get install apktool")

    # Extract native libs for strings analysis
    native_out = base_out / "native-libs"
    try:
        native_out.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(str(apk)) as z:
            so_files = [n for n in z.namelist() if n.endswith('.so')]
            for so_fn in so_files:
                out_path = native_out / Path(so_fn).name
                with open(str(out_path), 'wb') as f:
                    f.write(z.read(so_fn))
        results['native_libs'] = str(native_out)
        if RICH:
            con.print(f"    [green]native libs extracted ({len(so_files)})[/]")
    except Exception as e:
        results['native_libs'] = f"ERROR: {e}"

    if RICH:
        con.print()
        t = Table(title="[bold]Decompilation Results[/]", box=box.ROUNDED,
                  border_style="green", expand=True)
        t.add_column("Stage", style="cyan")
        t.add_column("Result", style="white")
        for k, v in results.items():
            t.add_row(k, esc(str(v)))
        con.print(t)

        if jadx_ok or apktool_ok:
            con.print(Panel(
                f"[bold]Next steps:[/]\n"
                f"  grep -r 'http' [cyan]{jadx_out}[/]       (search source)\n"
                f"  grep -ri 'password\\|secret\\|key' [cyan]{jadx_out}[/]\n"
                f"  strings [cyan]{native_out}[/]/*.so | grep -E 'https?://'",
                border_style="dim", box=box.ROUNDED,
                title="[dim]Post-Decompile[/]", title_align="left"
            ))
    return jadx_ok or apktool_ok


def cmd_apis(apk_path: str, lang: str = 'en', json_out: bool = False):
    """Dedicated API/endpoint extractor — fast mode, no full report."""
    apk_path = _resolve_apk(apk_path)
    ok_v, msg = validate_apk(apk_path)
    if not ok_v:
        _err(msg)
        return
    show_banner()
    az = NightOwlAnalyzer(apk_path, lang=lang)
    az.analyze_info()
    az.extract_strings()
    az.analyze_endpoints()
    az.analyze_apis()

    if json_out:
        out = {
            'servers': az.d['endpoints']['servers'],
            'urls': az.d['endpoints']['urls'],
            'api': az.d['endpoints']['api'],
            'ips': az.d['endpoints']['ips'],
            'auth_patterns': az.d['endpoints'].get('auth_patterns', []),
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    if RICH:
        con.print(Panel(
            f"[bold]API Extraction:[/] [cyan]{Path(apk_path).name}[/]",
            border_style="cyan", box=box.ROUNDED
        ))
        az._ri_urls()
    else:
        ep = az.d['endpoints']
        print(f"\n  Servers ({len(ep['servers'])}):")
        for s in ep['servers']:
            print(f"    {s}")
        print(f"\n  API Paths ({len(ep['api'])}):")
        for a in ep['api'][:30]:
            print(f"    {a}")


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        prog='nightowl',
        description=f'NightOwl v{__version__} — Advanced Android APK Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'nightowl guide' for detailed usage instructions.")

    sub = p.add_subparsers(dest='cmd')

    # Analysis subcommands
    for name, ht in [
        ('full', 'Full 8-section analysis'), ('info', 'Basic info'),
        ('perms', 'Permissions'), ('urls', 'URLs & endpoints'),
        ('secrets', 'Secret detection'), ('arch', 'Architecture'),
        ('vulns', 'Security + vulnerabilities'), ('manifest', 'Manifest components'),
    ]:
        sp = sub.add_parser(name, help=ht)
        sp.add_argument('apk', help='Path to APK file')
        sp.add_argument('--report-dir', default=None, help='Output dir')
        sp.add_argument('--json', action='store_true', help='JSON output only')
        sp.add_argument('--save', action='store_true', help='Save report files')
        sp.add_argument('--lang', default='en', choices=['en', 'ar'],
                        help='Report language: en (default) or ar (Arabic)')

    # Utility subcommands
    sc = sub.add_parser('scan', help='Batch scan directory of APKs')
    sc.add_argument('dir', nargs='?', default=None, help='Directory (default: targets/)')
    sc.add_argument('--lang', default='en', choices=['en', 'ar'],
                    help='Report language: en (default) or ar (Arabic)')

    sp_dc = sub.add_parser('decompile', help='Full decompilation: jadx + apktool + native libs')
    sp_dc.add_argument('apk', help='Path to APK file')
    sp_dc.add_argument('--out', default=None, help='Output directory')

    sp_ap = sub.add_parser('apis', help='Fast API/endpoint extraction only')
    sp_ap.add_argument('apk', help='Path to APK file')
    sp_ap.add_argument('--json', action='store_true', help='JSON output')
    sp_ap.add_argument('--lang', default='en', choices=['en', 'ar'])

    sub.add_parser('guide', help='Show comprehensive usage guide')
    sub.add_parser('proxy', help='Network proxy setup instructions')

    # Smart default: nightowl app.apk -> nightowl full app.apk
    if len(sys.argv) == 2 and sys.argv[1].endswith('.apk'):
        sys.argv.insert(1, 'full')
    if len(sys.argv) < 2:
        show_banner()
        # Show available targets
        TARGETS.mkdir(parents=True, exist_ok=True)
        apks = sorted(TARGETS.glob("*.apk"))
        if RICH:
            cmd_guide()
        else:
            p.print_help()
        if apks:
            if RICH:
                con.print(f"\n  [cyan]APKs in targets/:[/]")
                for a in apks:
                    con.print(f"    - [bold]{a.name}[/]  [dim]({a.stat().st_size / 1024 / 1024:.1f} MB)[/]")
                con.print()
            else:
                print(f"\n  APKs in targets/:")
                for a in apks:
                    print(f"    - {a.name}")
        sys.exit(0)

    args = p.parse_args()

    if args.cmd == 'guide':
        cmd_guide()
        return
    if args.cmd == 'proxy':
        cmd_proxy()
        return
    if args.cmd == 'scan':
        lang = getattr(args, 'lang', 'en')
        cmd_scan(args.dir, lang=lang)
        return
    if args.cmd == 'decompile':
        cmd_decompile(args.apk, out_dir=args.out)
        return
    if args.cmd == 'apis':
        cmd_apis(args.apk, lang=getattr(args, 'lang', 'en'),
                 json_out=getattr(args, 'json', False))
        return
    if not args.cmd:
        p.print_help()
        return

    # Ensure targets/ exists
    TARGETS.mkdir(parents=True, exist_ok=True)

    lang = getattr(args, 'lang', 'en')
    apk_path = _resolve_apk(args.apk)
    az = NightOwlAnalyzer(apk_path, lang=lang)
    ok = az.run_full() if args.cmd == 'full' else az.run_section(args.cmd)
    if not ok:
        sys.exit(1)

    if args.json:
        print(json.dumps(az.d, indent=2, ensure_ascii=False))
    else:
        az.render(args.cmd)
        if args.cmd == 'full' or args.save:
            az.save(args.report_dir)


if __name__ == '__main__':
    main()
