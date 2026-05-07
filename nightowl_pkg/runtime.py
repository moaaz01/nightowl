# NightOwl v6 — runtime.py
# RASP detection, Frida bypass generation, runtime analysis

import os, sys, json, re, subprocess
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "workspace"
TARGETS = ROOT / "targets"

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box
    con = Console(highlight=False)
    RICH = True
except ImportError:
    RICH = False
    class con:
        @staticmethod
        def print(*a, **kw): print(*a)


# ─── RASP Detection Patterns ──────────────────────────────────────────

RASP_DETECTORS = {
    'rootbeer': {
        'name': 'RootBeer Library',
        'patterns': ['RootBeer', 'com.scottyab.rootbeer', 'isRooted', 'rootbeer'],
        'bypass': 'rootbeer',
        'risk': 'MEDIUM',
        'description': 'Root detection library — common in banking apps'
    },
    'frida_detect': {
        'name': 'Frida Detection',
        'patterns': ['frida', 'Frida', 'frida-server', 'frida-agent',
                     'linjector', 'substrate', 'xposed'],
        'bypass': 'frida',
        'risk': 'HIGH',
        'description': 'Detects Frida hooks and dynamic instrumentation'
    },
    'safety_net': {
        'name': 'SafetyNet/Play Integrity',
        'patterns': ['SafetyNet', 'playintegrity', 'Play Integrity', 'attest',
                     'getAttestation', 'integrity', 'nonce'],
        'bypass': 'safetynet',
        'risk': 'HIGH',
        'description': 'Google Play Integrity / SafetyNet attestation'
    },
    'talsec': {
        'name': 'Talsec',
        'patterns': ['Talsec', 'talsec', 'com.aheaditec', 'FreeRASP'],
        'bypass': 'talsec',
        'risk': 'MEDIUM',
        'description': 'Talsec / FreeRASP mobile security library'
    },
    'dexguard': {
        'name': 'DexGuard',
        'patterns': ['DexGuard', 'dexguard'],
        'bypass': 'dexguard',
        'risk': 'MEDIUM',
        'description': 'DexGuard code obfuscation and protection'
    },
    'emulator_detect': {
        'name': 'Emulator Detection',
        'patterns': ['build.FINGERPRINT', 'build.TAGS', 'ro.kernel.qemu',
                     'genymotion', 'goldfish', 'ranchu', 'Build.DEVICE'],
        'bypass': 'emulator',
        'risk': 'MEDIUM',
        'description': 'Detects if running on emulator or simulator'
    },
    'debug_detect': {
        'name': 'Debug Detection',
        'patterns': ['isDebuggerConnected', 'android:debuggable',
                     'waitForDebugger', 'Debug.isDebuggerConnected',
                     'android.os.Debug'],
        'bypass': 'debug',
        'risk': 'LOW',
        'description': 'Checks if app is running in debug mode'
    },
    'hook_detect': {
        'name': 'Hook Detection',
        'patterns': ['XposedBridge', 'xposed', 'CydiaSubstrate',
                     'MSHookFunction', 'substrate'],
        'bypass': 'hook',
        'risk': 'HIGH',
        'description': 'Detects code hooking frameworks'
    },
    'os_detect': {
        'name': 'OS Detection',
        'patterns': ['Build.DISPLAY', 'Build.HOST', 'Build.PRODUCT',
                     'Build.MODEL', 'Build.MANUFACTURER', 'android.os.Build'],
        'bypass': 'os',
        'risk': 'LOW',
        'description': 'Collects OS and device information'
    },
    'ssl_pinning': {
        'name': 'SSL Pinning',
        'patterns': ['CertificatePinner', 'pinning', 'TrustManager',
                     'certificatePinner', 'SSLPinning', 'pub-key-pins'],
        'bypass': 'ssl_pinning',
        'risk': 'INFO',
        'description': 'SSL/TLS certificate pinning'
    },
}

# ─── Bypass Profiles ─────────────────────────────────────────────────

BYPASS_PROFILES = {
    'rootbeer': {
        'name': 'RootBeer Bypass',
        'scripts': [
            {
                'name': 'rootbeer_bypass',
                'code': '''
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() { return false; };
    console.log("[+] RootBeer.isRooted bypassed");
});
'''
            }
        ]
    },
    'frida': {
        'name': 'Frida Detection Bypass',
        'scripts': [
            {
                'name': 'frida_bypass',
                'code': '''
// Universal Frida detection bypass
var frida_detection = Java.use("com.example.FridaDetection");
if (frida_detection) {
    frida_detection.isFridaPresent.implementation = function() { return false; };
}
// Backup: patch common detection points
setTimeout(function() {
    Java.perform(function() {
        // Patch dlsym for frida_server detection
        var dlsym = Module.findExportByName("libc.so", "dlsym");
        if (dlsym) {
            Interceptor.attach(dlsym, {
                onLeave: function(retval) {
                    var symbol = Memory.readUtf8String(this.context.x1);
                    if (symbol && symbol.indexOf("frida") >= 0) {
                        retval.replace(0);
                    }
                }
            });
        }
    });
}, 100);
'''
            }
        ]
    },
    'safetynet': {
        'name': 'SafetyNet Bypass',
        'scripts': [
            {
                'name': 'safetynet_bypass',
                'code': '''
Java.perform(function() {
    // Patch SafetyNet attestation
    var SafetyNet = Java.use("com.google.android.gms.safetynet.SafetyNet");
    SafetyNet.getClient.implementation = function() { return null; };
    console.log("[+] SafetyNet client patched");
});
'''
            }
        ]
    },
    'talsec': {
        'name': 'Talsec Bypass',
        'scripts': [
            {
                'name': 'talsec_bypass',
                'code': '''
Java.perform(function() {
    var Talsec = Java.use("com.aheaditec.talsec.security.Talsec");
    if (Talsec) {
        Talsec.isRootDetected.implementation = function() { return false; };
        Talsec.isDebuggerPresent.implementation = function() { return false; };
        console.log("[+] Talsec bypassed");
    }
});
'''
            }
        ]
    },
    'ssl_pinning': {
        'name': 'SSL Pinning Bypass (Universal)',
        'scripts': [
            {
                'name': 'ssl_universal_bypass',
                'code': '''
// Universal SSL pinning bypass
Java.perform(function() {
    // Method 1: TrustManager override
    var TrustManager = Java.registerClass({
        name: 'com.example.TrustAllManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(certs, authType) {},
            checkServerTrusted: function(certs, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // Method 2: OkHttp pinning bypass
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    console.log("[+] SSL pinning bypassed");
});
'''
            }
        ]
    },
    'debug': {
        'name': 'Debug Detection Bypass',
        'scripts': [
            {
                'name': 'debug_bypass',
                'code': '''
Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() { return false; };
    Debug.waitingForDebugger.implementation = function() { return false; };
    console.log("[+] Debug detection bypassed");
});
'''
            }
        ]
    },
}


class RASPAnalyzer:
    """Analyze APK for runtime defense mechanisms."""

    def __init__(self, apk_path, package_name=None):
        self.apk_path = apk_path
        self.package_name = package_name
        self.text = ""
        self._extract_text()
    
    def _extract_text(self):
        try:
            r = subprocess.run(['strings', '-n', '6', self.apk_path],
                             capture_output=True, text=True, timeout=60)
            self.text = r.stdout
        except: self.text = ""
    
    def analyze(self):
        """Detect all RASP/defense mechanisms."""
        results = {'detectors': [], 'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0}}
        
        for det_id, det in RASP_DETECTORS.items():
            matches = []
            for pat in det['patterns']:
                if pat in self.text:
                    matches.append(pat)
            
            if matches:
                entry = {
                    'id': det_id,
                    'name': det['name'],
                    'detected': True,
                    'patterns_matched': matches[:5],
                    'risk': det['risk'],
                    'bypass': det['bypass'],
                    'description': det['description'],
                }
                results['detectors'].append(entry)
                results['summary']['total'] += 1
                if det['risk'] == 'CRITICAL': results['summary']['critical'] += 1
                elif det['risk'] == 'HIGH': results['summary']['high'] += 1
                elif det['risk'] == 'MEDIUM': results['summary']['medium'] += 1
        
        return results
    
    def display(self, results):
        """Display RASP analysis results."""
        if RICH:
            con.print(Panel(f"[bold]Runtime Defense Analysis[/]", border_style="yellow"))
            
            if not results['detectors']:
                con.print("  [green]No RASP/defense mechanisms detected[/]")
                return
            
            t = Table(box=box.ROUNDED)
            t.add_column("Risk")
            t.add_column("Detector")
            t.add_column("Description")
            t.add_column("Bypass Available")
            
            for d in results['detectors']:
                em = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(d['risk'], '⚪')
                t.add_row(f"{em} {d['risk']}", d['name'], d['description'], d['bypass'])
            con.print(t)
            
            s = results['summary']
            con.print(Panel(
                f"Total: {s['total']}  "
                f"[red]Critical: {s['critical']}[/]  "
                f"[yellow]High: {s['high']}[/]  "
                f"[orange1]Medium: {s['medium']}[/]",
                border_style="dim"
            ))


class BypassRunner:
    """Generate Frida bypass scripts for detected defenses."""
    
    def __init__(self, package_name):
        self.package_name = package_name
    
    def generate_bypass(self, detector_ids, output_dir=None):
        """Generate Frida bypass scripts for given detectors."""
        scripts = []
        
        for det_id in detector_ids:
            if det_id in BYPASS_PROFILES:
                profile = BYPASS_PROFILES[det_id]
                for s in profile['scripts']:
                    scripts.append({
                        'profile': profile['name'],
                        'name': s['name'],
                        'code': s['code'].strip(),
                        'target_package': self.package_name,
                    })
        
        if output_dir:
            out_path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)
            
            for s in scripts:
                fname = out_path / f"{s['name']}.js"
                fname.write_text(s['code'])
            
            # Also generate combined script
            combined = "\n\n".join([s['code'] for s in scripts])
            combined_path = out_path / "combined_bypass.js"
            combined_path.write_text(combined)
            
            # Generate Frida run commands
            commands = []
            for s in scripts:
                cmd = f"frida -U -l {out_path.name}/{s['name']}.js -f {self.package_name} --no-pause"
                commands.append({'script': s['name'], 'command': cmd})
            commands.append({'script': 'combined', 'command': f"frida -U -l {out_path.name}/combined_bypass.js -f {self.package_name} --no-pause"})
            
            return {'scripts': scripts, 'commands': commands, 'output_dir': str(out_path)}
        
        return {'scripts': scripts, 'commands': []}


# ─── Export Functions ─────────────────────────────────────────────────

def cmd_rasp(apk_path, package_name=None):
    """Run RASP detection analysis."""
    analyzer = RASPAnalyzer(apk_path, package_name)
    results = analyzer.analyze()
    analyzer.display(results)
    
    # Save results
    report_file = WORKSPACE / "reports" / f"rasp-{Path(apk_path).stem}.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(results, indent=2))
    
    if RICH:
        con.print(f"  Report saved: [dim]{report_file}[/]")
    
    return results


def cmd_bypass(package_name, detector_ids=None, output_dir=None):
    """Generate Frida bypass scripts."""
    if not detector_ids:
        detector_ids = list(BYPASS_PROFILES.keys())
    
    runner = BypassRunner(package_name)
    if not output_dir:
        output_dir = WORKSPACE / "bypass" / package_name
    
    result = runner.generate_bypass(detector_ids, str(output_dir))
    
    if RICH:
        con.print(Panel(f"[bold green]Bypass Scripts Generated[/]\n"
                      f"Package: {package_name}\n"
                      f"Scripts: {len(result['scripts'])}\n"
                      f"Output: {result['output_dir']}",
                      border_style="green"))
        
        t = Table(box=box.ROUNDED)
        t.add_column("Script")
        t.add_column("Command")
        for c in result.get('commands', []):
            t.add_row(c['script'], f"[dim]{c['command']}[/]")
        con.print(t)
    
    return result
