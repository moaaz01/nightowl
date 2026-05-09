# NightOwl v6 — dragonjar.py
# DragonJAR Static Audit, Semgrep, CVSS Scoring — fully integrated

import os, sys, json, re, subprocess, shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DJ = ROOT / "scripts-dragonjar"
TARGETS = ROOT / "targets"
WORKSPACE = ROOT / "workspace"

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.markup import escape as esc
    from rich import box
    con = Console(highlight=False)
    RICH = True
except ImportError:
    RICH = False
    class con:
        @staticmethod
        def print(*a, **kw): print(*a)

# ─── Static Audit (ported from auto-audit-static.sh) ───────────────────

class StaticAuditor:
    """Full static analysis pipeline: decode → attack surface → patterns → report."""

    def __init__(self, apk_path, output_dir=None, mode='full', reuse_jadx=None):
        self.apk_path = apk_path
        self.apk = Path(apk_path)
        self.mode = mode
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        stem = self.apk.stem
        if output_dir:
            self.out_dir = Path(output_dir)
        else:
            self.out_dir = WORKSPACE / "audit" / f"{stem}-{self.timestamp}"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        
        self.results = {
            'apk': apk_path,
            'timestamp': self.timestamp,
            'mode': mode,
            'phases': {},
            'findings': [],
            'summary': {}
        }
        
        # Paths
        self.jadx_out = self.out_dir / "jadx-src"
        self.apktool_out = self.out_dir / "apktool"
        self.reuse_jadx = reuse_jadx

    def run(self):
        """Run full audit pipeline."""
        if RICH:
            con.print(Panel(f"[bold cyan]Static Audit:[/] {self.apk.name}\n"
                          f"[dim]Mode: {self.mode.upper()} | Output: {self.out_dir}[/]",
                          border_style="cyan"))
        
        self._phase_decode()
        self._phase_attack_surface()
        if self.mode == 'full':
            self._phase_grep_patterns()
        self._phase_report()
        return self.results

    def _phase_decode(self):
        """Phase 0: Decode APK with apktool + jadx."""
        if RICH: con.print(Rule("[bold]Phase 0: Decode[/]", style="cyan"))
        
        decode_info = []
        
        # apktool decode
        if RICH: con.print("  [cyan]>[/] Running apktool...")
        try:
            r = subprocess.run(
                ['apktool', 'd', '-f', '-o', str(self.apktool_out), str(self.apk)],
                capture_output=True, text=True, timeout=180
            )
            apk_ok = r.returncode == 0
            decode_info.append(f"apktool: {'SUCCESS' if apk_ok else 'FAILED'}")
            if RICH: con.print(f"    {'[green]done[/]' if apk_ok else '[red]failed[/]'}")
        except Exception as e:
            decode_info.append(f"apktool: ERROR - {e}")
            if RICH: con.print(f"    [red]apktool error: {e}[/]")
        
        # jadx decompile
        if self.reuse_jadx:
            jadx_path = Path(self.reuse_jadx)
            if jadx_path.exists():
                self.jadx_out = jadx_path
                decode_info.append(f"jadx: REUSED {self.reuse_jadx}")
                if RICH: con.print(f"  [cyan]>[/] Reusing jadx output: {self.reuse_jadx}")
        else:
            if RICH: con.print("  [cyan]>[/] Running jadx...")
            try:
                jadx_bin = shutil.which('jadx')
                if jadx_bin:
                    self.jadx_out.mkdir(parents=True, exist_ok=True)
                    r = subprocess.run(
                        [jadx_bin, '--output-dir', str(self.jadx_out), '--no-res',
                         '--show-bad-code', str(self.apk)],
                        capture_output=True, text=True, timeout=300
                    )
                    jadx_ok = r.returncode == 0 or self.jadx_out.exists()
                    jc = len(list(self.jadx_out.glob('sources/**/*.java'))) if self.jadx_out.exists() else 0
                    decode_info.append(f"jadx: {'SUCCESS' if jadx_ok else 'FAILED'} ({jc} .java files)")
                    if RICH: con.print(f"    {'[green]done[/]' if jadx_ok else '[red]failed[/]'}")
                else:
                    decode_info.append("jadx: SKIPPED (not installed)")
                    if RICH: con.print(f"    [yellow]skipped (jadx not found)[/]")
            except Exception as e:
                decode_info.append(f"jadx: ERROR - {e}")
        
        self.results['phases']['decode'] = decode_info
    
    def _phase_attack_surface(self):
        """Phase 1: Map attack surface from AndroidManifest."""
        if RICH: con.print(Rule("[bold]Phase 1: Attack Surface[/]", style="cyan"))
        
        manifest_path = self.apktool_out / "AndroidManifest.xml"
        findings = []
        
        if manifest_path.exists():
            manifest_text = manifest_path.read_text(errors='replace')
            
            # Detect exported components
            exported = re.findall(r'android:exported=["\']true["\']', manifest_text)
            activities = re.findall(r'<activity[^>]+android:name=["\']([^"\']+)["\']', manifest_text)
            receivers = re.findall(r'<receiver[^>]+android:name=["\']([^"\']+)["\']', manifest_text)
            services = re.findall(r'<service[^>]+android:name=["\']([^"\']+)["\']', manifest_text)
            providers = re.findall(r'<provider[^>]+android:name=["\']([^"\']+)["\']', manifest_text)
            
            # Intent filters
            intent_filters = manifest_text.count('<intent-filter>')
            
            # Permissions
            perms_used = re.findall(r'<uses-permission[^>]+android:name=["\']([^"\']+)["\']', manifest_text)
            
            # Debuggable
            debuggable = 'android:debuggable="true"' in manifest_text
            
            findings.append({
                'title': 'Exported Components',
                'detail': f'{len(exported)} components exported | {len(activities)} activities | {len(receivers)} receivers | {len(services)} services | {len(providers)} providers',
                'risk': 'HIGH' if len(exported) > 3 else 'MEDIUM',
            })
            findings.append({
                'title': 'Intent Filters',
                'detail': f'{intent_filters} intent filters defined',
                'risk': 'MEDIUM' if intent_filters > 0 else 'INFO',
            })
            findings.append({
                'title': 'Permissions',
                'detail': f'{len(perms_used)} permissions requested',
                'risk': 'INFO',
            })
            if debuggable:
                findings.append({
                    'title': 'Debuggable',
                    'detail': 'App is debuggable — production risk',
                    'risk': 'HIGH',
                })
            
            if RICH:
                t = Table(box=box.ROUNDED, border_style="dim")
                t.add_column("Component", style="cyan")
                t.add_column("Count")
                t.add_row("Exported", str(len(exported)))
                t.add_row("Activities", str(len(activities)))
                t.add_row("Receivers", str(len(receivers)))
                t.add_row("Services", str(len(services)))
                t.add_row("Providers", str(len(providers)))
                t.add_row("Intent Filters", str(intent_filters))
                t.add_row("Permissions", str(len(perms_used)))
                con.print(t)
        else:
            findings.append({'title': 'Manifest', 'detail': 'AndroidManifest not found', 'risk': 'ERROR'})
        
        self.results['phases']['attack_surface'] = findings
        self.results['findings'].extend(findings)

    def _phase_grep_patterns(self):
        """Phase 2: Pattern matching on decompiled sources."""
        if RICH: con.print(Rule("[bold]Phase 2: Pattern Analysis[/]", style="cyan"))
        
        findings = []
        source_dirs = []
        
        # Collect source directories
        if self.jadx_out.exists():
            src = self.jadx_out / "sources"
            if src.exists(): source_dirs.append(src)
        if self.apktool_out.exists():
            source_dirs.append(self.apktool_out)
        
        if not source_dirs:
            if RICH: con.print("  [yellow]No source directories to scan[/]")
            self.results['phases']['patterns'] = findings
            self.results['findings'].extend(findings)
            return
        
        # Patterns to search
        patterns = {
            'HTTP URLs': (r'https?://[a-zA-Z0-9.\-_:~]+', 'MEDIUM', 'endpoints'),
            'API Keys': (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\\\']([^"\\\']{8,})', 'HIGH', 'secrets'),
            'Hardcoded Secrets': (r'(?i)(?:secret|password|token)\s*[=:]\s*["\\\']([^"\\\']{8,})', 'CRITICAL', 'secrets'),
            'AWS Keys': (r'AKIA[0-9A-Z]{16}', 'CRITICAL', 'secrets'),
            'Weak Crypto': (r'(?i)(MD5|SHA1|DES|RC4)\b', 'HIGH', 'crypto'),
            'Base64': (r'Base64\.decode\(', 'LOW', 'encoding'),
            'WebView': (r'(?i)(setJavaScriptEnabled|loadUrl|addJavascriptInterface)', 'HIGH', 'webview'),
            'SQL Injection': (r'(?i)(rawQuery|execSQL|db\.rawQuery)', 'MEDIUM', 'database'),
            'SSL Bypass': (r'(?i)(X509TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER| unsafeTrustManager)', 'CRITICAL', 'network'),
            'File IO': (r'(?i)(openFileOutput|getFilesDir|getCacheDir|openFileInput)', 'LOW', 'storage'),
            'Logging': (r'(?i)(log\.d|Log\.v|Log\.i|android\.util\.Log)', 'LOW', 'logging'),
            'Root Detection': (r'(?i)(rootbeer|isRooted|su\s+binary|checkRoot)', 'INFO', 'defense'),
            'SharedPreferences': (r'(?i)(SharedPreferences|getSharedPreferences|edit\(\))', 'LOW', 'storage'),
            'Debug Mode': (r'(?i)(BuildConfig\.DEBUG|android:debuggable)', 'HIGH', 'config'),
            'IP Addresses': (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'MEDIUM', 'network'),
            'Dynamic Loading': (r'(?i)(DexClassLoader|PathClassLoader|loadDex)', 'HIGH', 'code_exec'),
            'JNI Calls': (r'(?i)(System\.loadLibrary|JNI_CreateJavaVM|RegisterNatives)', 'LOW', 'native'),
        }
        
        grep_bin = 'rg' if shutil.which('rg') else 'grep'
        grep_flags = ['-rnE'] if grep_bin == 'grep' else ['-n']
        
        for label, (pattern, risk, category) in patterns.items():
            counts = 0
            for src_dir in source_dirs:
                try:
                    cmd = [grep_bin] + grep_flags + ['--include=*.java', '--include=*.kt', '--include=*.xml',
                           '--include=*.dart', '--include=*.js', '--include=*.ts',
                           pattern, str(src_dir)]
                    if grep_bin == 'rg':
                        cmd = [grep_bin, '-rnE', '--no-ignore', pattern, str(src_dir)]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    counts += len(r.stdout.strip().split('\n')) if r.stdout.strip() else 0
                except: pass
            
            if counts > 0:
                findings.append({
                    'title': label,
                    'detail': f'{counts} matches found',
                    'risk': risk,
                    'category': category,
                    'count': counts,
                })
        
        # Sort by risk
        risk_sort = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'ERROR': 5}
        findings.sort(key=lambda x: risk_sort.get(x.get('risk', 'INFO'), 99))
        
        if RICH:
            t = Table(box=box.ROUNDED, border_style="dim")
            t.add_column("Risk", style="bold")
            t.add_column("Pattern", style="cyan")
            t.add_column("Count", justify="right")
            t.add_column("Category")
            for f in findings:
                risk_em = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','INFO':'⚪'}.get(f['risk'], '⚪')
                t.add_row(f"{risk_em} {f['risk']}", f['title'], str(f['count']), f.get('category',''))
            con.print(t)
        
        self.results['phases']['patterns'] = findings
        self.results['findings'].extend(findings)

    def _phase_report(self):
        """Phase 3: Generate summary and save results."""
        findings = self.results['findings']
        
        # Calculate score
        risk_pen = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2, 'INFO': 0}
        total_pen = sum(risk_pen.get(f.get('risk', 'INFO'), 0) for f in findings)
        score = max(0, 100 - total_pen)
        
        if score >= 90: grade = 'A'
        elif score >= 80: grade = 'B'
        elif score >= 60: grade = 'C'
        elif score >= 40: grade = 'D'
        else: grade = 'F'
        
        self.results['summary'] = {
            'score': score,
            'grade': grade,
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f.get('risk') == 'CRITICAL'),
            'high': sum(1 for f in findings if f.get('risk') == 'HIGH'),
            'medium': sum(1 for f in findings if f.get('risk') == 'MEDIUM'),
            'low': sum(1 for f in findings if f.get('risk') == 'LOW'),
        }
        
        # Save results
        report_file = self.out_dir / "static-audit-report.json"
        report_file.write_text(json.dumps(self.results, indent=2, ensure_ascii=False))
        
        if RICH:
            s = self.results['summary']
            sc = "green" if s['score'] >= 80 else "yellow" if s['score'] >= 60 else "red"
            con.print(Rule("[bold]Audit Complete[/]", style="green"))
            t = Table(box=box.ROUNDED, border_style="green")
            t.add_column("Metric", style="cyan")
            t.add_column("Value")
            t.add_row("Score", f"[bold {sc}]{s['score']}/100 (Grade {s['grade']})[/]")
            t.add_row("Findings", str(s['total_findings']))
            t.add_row("  Critical", f"[bold red]{s['critical']}[/]")
            t.add_row("  High", f"[bold yellow]{s['high']}[/]")
            t.add_row("  Medium", f"[yellow]{s['medium']}[/]")
            t.add_row("  Low", f"[cyan]{s['low']}[/]")
            t.add_row("Report", f"[dim]{report_file}[/]")
            con.print(t)

# ─── Semgrep Scanner ─────────────────────────────────────────────────

class SemgrepScanner:
    """Run Semgrep MASTG rules against decompiled source."""
    
    def __init__(self, scan_dir, rules_file=None):
        self.scan_dir = scan_dir
        self.rules_file = rules_file or str(SCRIPTS_DJ / "semgrep-rules" / "MASTG-rules.yaml")
    
    def check_available(self):
        try:
            r = subprocess.run(['semgrep', '--version'], capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except: return False
    
    def run(self, output_file=None):
        if not self.check_available():
            return {'tool_available': False, 'findings': [], 'error': 'semgrep not installed'}
        
        cmd = ['semgrep', '--config', self.rules_file, '--quiet', '--json',
               '--no-git-ignore', '--exclude', '*.min.js', '--exclude', '*.min.css',
               str(self.scan_dir)]
        
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings = []
            if r.stdout:
                try:
                    data = json.loads(r.stdout)
                    results = data.get('results', []) if isinstance(data, dict) else data
                    for f in results:
                        findings.append({
                            'check_id': f.get('check_id', ''),
                            'message': f.get('message', ''),
                            'severity': f.get('extra', {}).get('severity', 'WARNING'),
                            'path': f.get('path', ''),
                            'line': f.get('start', {}).get('line', 0),
                            'metadata': f.get('extra', {}).get('metadata', {}),
                        })
                except: pass
            
            result = {
                'tool_available': True,
                'findings': findings,
                'count': len(findings),
                'returncode': r.returncode,
            }
            
            if output_file:
                Path(output_file).write_text(json.dumps(result, indent=2))
            
            return result
        except subprocess.TimeoutExpired:
            return {'tool_available': True, 'findings': [], 'error': 'timeout'}
        except: return {'tool_available': False, 'findings': [], 'error': 'unknown'}

# ─── CVSS / MASVS Scoring ────────────────────────────────────────────

class CVSScorer:
    """Calculate MASVS compliance score from findings."""
    
    def __init__(self):
        self.masvs_controls = {
            'M1': 'Data Storage and Privacy',
            'M2': 'Authentication and Session Management',
            'M3': 'Communication Security',
            'M4': 'Platform Interaction',
            'M5': 'Network Communication',
            'M6': 'Cryptography',
            'M7': 'Code Quality',
            'M8': 'Resilience',
        }
    
    def score_findings(self, findings):
        """Calculate score (0-100) from list of findings."""
        if not findings:
            return {'score': 100, 'grade': 'A', 'controls': {}}
        
        risk_scores = {'CRITICAL': 15, 'HIGH': 8, 'MEDIUM': 4, 'LOW': 1, 'INFO': 0}
        total_penalty = 0
        control_hits = defaultdict(list)
        
        for f in findings:
            risk = f.get('risk', f.get('severity', 'MEDIUM')).upper()
            total_penalty += risk_scores.get(risk, 4)
            
            # Map to MASVS control
            cat = f.get('category', f.get('source', 'unknown'))
            for ctrl_id, ctrl_name in self.masvs_controls.items():
                if any(word in cat.lower() for word in ctrl_name.lower().split()):
                    control_hits[ctrl_id].append(f)
                    break
            else:
                control_hits['M7'].append(f)  # Default: Code Quality
        
        score = max(0, min(100, 100 - total_penalty))
        
        if score >= 90: grade = 'A'
        elif score >= 80: grade = 'B'
        elif score >= 60: grade = 'C'
        elif score >= 40: grade = 'D'
        else: grade = 'F'
        
        return {
            'score': score,
            'grade': grade,
            'total_findings': len(findings),
            'penalty': total_penalty,
            'controls': {k: len(v) for k, v in control_hits.items()},
        }

# ─── Export Functions ────────────────────────────────────────────────

def cmd_static_audit(apk_path, output_dir=None, mode='full', reuse_jadx=None):
    """Run full DragonJAR-style static audit."""
    auditor = StaticAuditor(apk_path, output_dir, mode, reuse_jadx)
    return auditor.run()

def cmd_semgrep(scan_target, rules_file=None, output_file=None, reuse_jadx=None):
    """Run Semgrep MASTG scan. Accepts APK path or decompiled directory."""
    # If an APK file, decompile with jadx first
    if str(scan_target).endswith('.apk') and Path(scan_target).is_file():
        from nightowl_pkg.core import decompile_apk
        apk_name = Path(scan_target).stem
        jadx_dir = WORKSPACE / "decompiled" / apk_name / "jadx-src" / "sources"
        if not jadx_dir.exists():
            jadx_out, _ = decompile_apk(scan_target)
            if jadx_out:
                jadx_dir = Path(jadx_out) / "sources"
        scan_dir = str(jadx_dir) if jadx_dir.exists() else scan_target
    else:
        scan_dir = scan_target
    
    scanner = SemgrepScanner(scan_dir, rules_file)
    return scanner.run(output_file)

def cmd_cvss(findings_file):
    """Calculate CVSS/MASVS score from findings JSON."""
    if not Path(findings_file).exists():
        return {'error': f'File not found: {findings_file}'}
    data = json.loads(Path(findings_file).read_text())
    findings = data.get('findings', data) if isinstance(data, dict) else data
    scorer = CVSScorer()
    return scorer.score_findings(findings)

def cmd_merge_findings(input_files, output_file=None):
    """Merge multiple findings files."""
    all_findings = []
    seen = set()
    
    for fpath in input_files:
        p = Path(fpath)
        if not p.exists(): continue
        try:
            data = json.loads(p.read_text())
            items = data.get('findings', data) if isinstance(data, dict) else data
            for item in items:
                key = f"{item.get('title','')}:{item.get('risk','')}"
                if key not in seen:
                    seen.add(key)
                    all_findings.append(item)
        except: pass
    
    result = {'findings': all_findings, 'count': len(all_findings), 'sources': input_files}
    
    if output_file:
        Path(output_file).write_text(json.dumps(result, indent=2))
    
    return result
