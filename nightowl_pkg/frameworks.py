# NightOwl v6 — frameworks.py
# Framework-specific analysis: Flutter, React Native, Cordova, Unity

import os, sys, json, re, subprocess, shutil, zipfile
from pathlib import Path
from datetime import datetime
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ROOT / "targets"
WORKSPACE = ROOT / "workspace"

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
    con = Console(highlight=False)
    RICH = True
except ImportError:
    RICH = False
    class con:
        @staticmethod
        def print(*a, **kw): print(*a)


class FrameworkAnalyzer:
    """Detect and analyze cross-platform mobile frameworks."""
    
    FLUTTER_INDICATORS = ['libapp.so', 'flutter_assets', 'io.flutter.', 'FlutterMain']
    RN_INDICATORS = ['com.facebook.react', 'react-native', 'react_native', 'ReactApplication']
    CORDOVA_INDICATORS = ['org.apache.cordova', 'CordovaActivity', 'cordova']
    UNITY_INDICATORS = ['com.unity3d', 'UnityPlayerActivity', 'libunity.so', 'libil2cpp.so']
    
    def __init__(self, apk_path):
        self.apk_path = str(Path(apk_path).resolve())
        self.apk = Path(apk_path)
        self.text = ""
        self._extract_text()
        self.framework = self._detect()
    
    def _extract_text(self):
        """Extract strings from APK for framework detection."""
        try:
            r = subprocess.run(['strings', '-n', '6', self.apk_path], 
                             capture_output=True, text=True, timeout=60)
            self.text = r.stdout
        except: 
            self.text = ""
    
    def _detect(self):
        """Detect which frameworks are used."""
        detected = []
        if any(x in self.text for x in self.FLUTTER_INDICATORS):
            detected.append('flutter')
        if any(x in self.text for x in self.RN_INDICATORS):
            detected.append('react-native')
        if any(x in self.text for x in self.CORDOVA_INDICATORS):
            detected.append('cordova')
        if any(x in self.text for x in self.UNITY_INDICATORS):
            detected.append('unity')
        return detected
    
    def analyze(self):
        """Run framework-specific analysis."""
        results = {
            'apk': self.apk.name,
            'frameworks': self.framework,
            'analysis': {}
        }
        
        if 'flutter' in self.framework:
            results['analysis']['flutter'] = self._analyze_flutter()
        if 'react-native' in self.framework:
            results['analysis']['react_native'] = self._analyze_react_native()
        if 'cordova' in self.framework:
            results['analysis']['cordova'] = self._analyze_cordova()
        if 'unity' in self.framework:
            results['analysis']['unity'] = self._analyze_unity()
        
        return results
    
    def _analyze_flutter(self):
        """Flutter-specific security analysis."""
        findings = []
        
        # Check for libapp.so
        libapp = False
        try:
            with zipfile.ZipFile(self.apk_path) as z:
                libapp = any('libapp.so' in n for n in z.namelist())
                # Extract libapp.so for analysis
                libapp_data = None
                for n in z.namelist():
                    if n.endswith('libapp.so'):
                        libapp_data = z.read(n)
                        break
        except: libapp_data = None
        
        findings.append({
            'check': 'libapp.so',
            'found': libapp,
            'detail': 'Dart AOT compiled code' if libapp else 'Not found',
            'risk': 'INFO',
        })
        
        # Dart analysis
        dart_strings = ""
        if libapp_data:
            try:
                # Try 'strings' on libapp data
                p = subprocess.run(['strings'], input=libapp_data, capture_output=True, timeout=15)
                dart_strings = p.stdout.decode('utf-8', errors='replace')
            except: pass
        
        # URLs in Dart
        urls = re.findall(r'https?://[a-zA-Z0-9._/~:&=?%-]+', dart_strings)
        urls = [u for u in urls if not any(n in u for n in ['flutter.dev', 'pub.dev', 'dart.dev', 'googleapis', 'gstatic'])]
        findings.append({'check': 'URLs in Dart', 'found': len(urls), 'detail': f'{len(urls)} URLs found', 'risk': 'MEDIUM'})
        
        # Secrets in Dart
        secrets = re.findall(r'(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*["\\\']([^"\\\']{8,})', dart_strings)
        if secrets:
            findings.append({'check': 'Secrets in Dart', 'found': len(secrets), 'detail': f'{len(secrets)} potential secrets', 'risk': 'CRITICAL'})
        
        # Method channels
        channels = re.findall(r'(MethodChannel|EventChannel|BasicMessageChannel)[^(]*\(["\\\']([^"\\\']+)', dart_strings)
        findings.append({'check': 'Method Channels', 'found': len(channels), 'detail': f'{len(channels)} channels', 'risk': 'LOW'})
        
        # Storage
        if 'SharedPreferences' in dart_strings:
            findings.append({'check': 'SharedPreferences', 'found': True, 'detail': 'Potentially insecure local storage', 'risk': 'MEDIUM'})
        if 'flutter_secure_storage' in dart_strings:
            findings.append({'check': 'flutter_secure_storage', 'found': True, 'detail': 'Secure storage detected', 'risk': 'INFO'})
        
        # Crypto
        if any(x in dart_strings for x in ['encrypt', 'aes', 'rsa']):
            findings.append({'check': 'Crypto Usage', 'found': True, 'detail': 'Encryption detected', 'risk': 'INFO'})
        
        return {'findings': findings, 'dart_urls': urls[:20]}
    
    def _analyze_react_native(self):
        """React Native specific analysis."""
        findings = []
        
        # Check for bundle
        has_bundle = False
        has_hermes = False
        try:
            with zipfile.ZipFile(self.apk_path) as z:
                names = z.namelist()
                has_bundle = any('index.android.bundle' in n for n in names)
                has_hermes = any('libhermes.so' in n for n in names)
        except: pass
        
        findings.append({'check': 'JS Bundle', 'found': has_bundle, 'detail': 'React Native JS bundle' if has_bundle else 'Not found', 'risk': 'INFO'})
        findings.append({'check': 'Hermes Engine', 'found': has_hermes, 'detail': 'Hermes compiled bytecode' if has_hermes else 'JSC or other', 'risk': 'INFO'})
        
        # Extract bundle strings
        bundle_text = ""
        if has_bundle:
            try:
                with zipfile.ZipFile(self.apk_path) as z:
                    for n in z.namelist():
                        if 'index.android.bundle' in n:
                            bundle_text = z.read(n).decode('utf-8', errors='replace')
                            break
            except: pass
            
            apis = re.findall(r'https?://[a-zA-Z0-9._/~:&=?%-]+', bundle_text)
            apis = [u for u in apis if 'facebook' not in u.lower()][:30]
            findings.append({'check': 'API Endpoints', 'found': len(apis), 'detail': f'{len(apis)} endpoints', 'risk': 'MEDIUM'})
        
        return {'findings': findings}
    
    def _analyze_cordova(self):
        """Cordova/PhoneGap specific analysis."""
        findings = []
        
        has_config = False
        has_whitelist = False
        try:
            with zipfile.ZipFile(self.apk_path) as z:
                names = z.namelist()
                has_config = any('config.xml' in n for n in names)
                has_whitelist = any('whitelist' in n.lower() for n in names)
        except: pass
        
        findings.append({'check': 'config.xml', 'found': has_config, 'detail': 'Cordova configuration', 'risk': 'INFO'})
        findings.append({'check': 'Whitelist plugin', 'found': has_whitelist, 'detail': 'Navigation whitelist' if has_whitelist else 'Missing — open navigation', 'risk': 'HIGH' if not has_whitelist else 'INFO'})
        
        return {'findings': findings}
    
    def _analyze_unity(self):
        """Unity game engine specific analysis."""
        findings = []
        
        has_il2cpp = False
        try:
            with zipfile.ZipFile(self.apk_path) as z:
                names = z.namelist()
                has_il2cpp = any('libil2cpp.so' in n for n in names)
        except: pass
        
        findings.append({'check': 'il2cpp', 'found': has_il2cpp, 'detail': 'IL2CPP compiled code' if has_il2cpp else 'Mono runtime', 'risk': 'INFO'})
        
        return {'findings': findings}


def _run_framework_analysis(apk_path):
    """Run full framework analysis and print results."""
    fa = FrameworkAnalyzer(apk_path)
    results = fa.analyze()
    
    if RICH:
        con.print(Panel(f"[bold cyan]Framework Analysis:[/] {Path(apk_path).name}", border_style="cyan"))
        con.print(f"  Detected: [bold]{', '.join(results['frameworks']) if results['frameworks'] else 'Native/Unknown'}[/]")
        con.print()
        
        for fw, analysis in results['analysis'].items():
            con.print(Rule(f"[bold]{fw.replace('_', ' ').title()}[/]", style="blue"))
            t = Table(box=box.ROUNDED, border_style="dim")
            t.add_column("Check", style="cyan")
            t.add_column("Found", style="bold")
            t.add_column("Detail")
            t.add_column("Risk")
            for f in analysis.get('findings', []):
                em = {True: '✅', False: '❌', '': '⚪'}.get(f.get('found'), '⚪')
                t.add_row(f['check'], str(em), f.get('detail', ''), f.get('risk', 'INFO'))
            con.print(t)
            con.print()
    else:
        print(f"\nFramework Analysis: {Path(apk_path).name}")
        print(f"Detected: {results['frameworks']}")
        for fw, analysis in results['analysis'].items():
            print(f"\n  {fw}:")
            for f in analysis.get('findings', []):
                print(f"    - {f['check']}: {f['detail']} [{f['risk']}]")
    
    return results


def cmd_framework(apk_path, framework=None):
    """Run framework-specific analysis."""
    fa = FrameworkAnalyzer(apk_path)
    results = fa.analyze()
    
    if framework and framework not in results['frameworks']:
        if RICH:
            con.print(f"[yellow]Framework '{framework}' not detected in APK[/]")
        return results
    
    return results


def cmd_flutter(apk_path):
    """Flutter-specific analysis."""
    return _run_framework_analysis(apk_path)


def cmd_react_native(apk_path):
    """React Native analysis."""
    results = cmd_framework(apk_path, 'react-native')
    if RICH:
        fw_results = results.get('analysis', {}).get('react_native', {})
        if 'js_bundle_paths' in fw_results:
            t = Table(title="[bold]React Native Bundle Analysis[/]", box=box.ROUNDED)
            t.add_column("Item")
            t.add_column("Value")
            for k, v in fw_results.items():
                if isinstance(v, (int, str, bool)):
                    t.add_row(k, str(v))
            con.print(t)
    return results


def cmd_cordova(apk_path):
    """Cordova analysis."""
    return _run_framework_analysis(apk_path)


def cmd_unity(apk_path):
    """Unity analysis."""
    return _run_framework_analysis(apk_path)
