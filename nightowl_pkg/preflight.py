# NightOwl v6 — preflight.py
# Dependency checker — inspired by DragonJAR preflight-check.sh

import os, subprocess, shutil, sys
from pathlib import Path
from collections import OrderedDict

ROOT = Path(__file__).resolve().parent.parent

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


# ─── Tool definitions ────────────────────────────────────────────────

TOOLS = OrderedDict([
    # (name, critical, check_fn, version_fn, install_hint)
    ('jadx', {
        'critical': True,
        'check': lambda: shutil.which('jadx'),
        'version': lambda: subprocess.run(['jadx', '--version'], capture_output=True, text=True).stdout.strip()[:30] if shutil.which('jadx') else '',
        'install': 'brew install jadx / apt install jadx',
    }),
    ('apktool', {
        'critical': True,
        'check': lambda: shutil.which('apktool'),
        'version': lambda: subprocess.run(['apktool', '--version'], capture_output=True, text=True).stdout.strip()[:30] if shutil.which('apktool') else '',
        'install': 'brew install apktool / apt install apktool',
    }),
    ('java', {
        'critical': True,
        'check': lambda: shutil.which('java'),
        'version': lambda: subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.split('\n')[0].strip() if shutil.which('java') else '',
        'install': 'apt install default-jdk / brew install openjdk',
    }),
    ('adb', {
        'critical': True,
        'check': lambda: shutil.which('adb'),
        'version': lambda: subprocess.run(['adb', 'version'], capture_output=True, text=True).stdout.split('\n')[0].strip()[:40] if shutil.which('adb') else '',
        'install': 'apt install android-tools-adb / brew install --cask android-platform-tools',
    }),
    ('python3', {
        'critical': True,
        'check': lambda: shutil.which('python3'),
        'version': lambda: subprocess.run(['python3', '--version'], capture_output=True, text=True).stdout.strip() if shutil.which('python3') else '',
        'install': 'apt install python3',
    }),
    ('pip3', {
        'critical': False,
        'check': lambda: shutil.which('pip3') or shutil.which('pip'),
        'version': lambda: subprocess.run([shutil.which('pip3') or 'pip', '--version'], capture_output=True, text=True).stdout.strip()[:40] if (shutil.which('pip3') or shutil.which('pip')) else '',
        'install': 'apt install python3-pip',
    }),
    ('frida', {
        'critical': False,
        'check': lambda: shutil.which('frida'),
        'version': lambda: subprocess.run(['frida', '--version'], capture_output=True, text=True).stdout.strip()[:20] if shutil.which('frida') else '',
        'install': 'pip3 install frida-tools',
    }),
    ('objection', {
        'critical': False,
        'check': lambda: shutil.which('objection'),
        'version': lambda: '',
        'install': 'pip3 install objection',
    }),
    ('semgrep', {
        'critical': False,
        'check': lambda: shutil.which('semgrep'),
        'version': lambda: subprocess.run(['semgrep', '--version'], capture_output=True, text=True).stdout.strip()[:20] if shutil.which('semgrep') else '',
        'install': 'pip3 install semgrep',
    }),
    ('apkid', {
        'critical': False,
        'check': lambda: shutil.which('apkid'),
        'version': lambda: '',
        'install': 'pip3 install apkid',
    }),
    ('rg (ripgrep)', {
        'critical': False,
        'check': lambda: shutil.which('rg'),
        'version': lambda: subprocess.run(['rg', '--version'], capture_output=True, text=True).stdout.split('\n')[0].strip()[:40] if shutil.which('rg') else '',
        'install': 'apt install ripgrep / brew install ripgrep',
    }),
    ('strings', {
        'critical': True,
        'check': lambda: shutil.which('strings'),
        'version': lambda: '',
        'install': 'apt install binutils',
    }),
    ('zipalign', {
        'critical': False,
        'check': lambda: shutil.which('zipalign'),
        'version': lambda: '',
        'install': 'Install Android SDK build-tools',
    }),
    ('apksigner', {
        'critical': False,
        'check': lambda: shutil.which('apksigner'),
        'version': lambda: '',
        'install': 'Install Android SDK build-tools',
    }),
    ('jarsigner', {
        'critical': False,
        'check': lambda: shutil.which('jarsigner'),
        'version': lambda: '',
        'install': 'Part of JDK',
    }),
])

# Python packages
PYTHON_PACKAGES = [
    ('rich', 'pip3 install rich'),
    ('androguard', 'pip3 install androguard'),
    ('requests', 'pip3 install requests'),
    ('colorama', 'pip3 install colorama'),
]


class PreflightChecker:
    """Check all dependencies for NightOwl."""

    def __init__(self):
        self.results = {
            'tools': {'found': 0, 'missing': 0, 'critical_missing': 0, 'list': []},
            'python_packages': {'found': 0, 'missing': 0, 'list': []}
        }
    
    def check_tools(self):
        """Check all system tools."""
        for name, info in TOOLS.items():
            found = info['check']()
            version = info['version']() if found else ''
            entry = {
                'name': name,
                'found': bool(found),
                'critical': info['critical'],
                'version': version,
                'install': info['install'] if not found else ''
            }
            self.results['tools']['list'].append(entry)
            if found:
                self.results['tools']['found'] += 1
            else:
                self.results['tools']['missing'] += 1
                if info['critical']:
                    self.results['tools']['critical_missing'] += 1
    
    def check_python_packages(self):
        """Check required Python packages."""
        for pkg_name, install_cmd in PYTHON_PACKAGES:
            try:
                __import__(pkg_name)
                found = True
            except ImportError:
                found = False
            self.results['python_packages']['list'].append({
                'name': pkg_name,
                'found': found,
                'install': install_cmd if not found else ''
            })
            if found:
                self.results['python_packages']['found'] += 1
            else:
                self.results['python_packages']['missing'] += 1
    
    def run(self):
        """Run full preflight check."""
        if RICH:
            con.print(Panel("[bold]NightOwl Preflight Check[/]", border_style="cyan"))
        
        self.check_tools()
        self.check_python_packages()
        
        return self.results
    
    def display(self):
        """Display preflight results."""
        r = self.results
        ts = r['tools']
        ps = r['python_packages']
        
        if RICH:
            # Tools table
            t = Table(box=box.ROUNDED, border_style="dim")
            t.add_column("Status", style="bold")
            t.add_column("Tool", style="cyan")
            t.add_column("Version")
            t.add_column("Critical")
            t.add_column("Install")
            
            for entry in ts['list']:
                status = "[green]✅[/]" if entry['found'] else "[red]❌[/]"
                crit = "[red]YES[/]" if (entry['critical'] and not entry['found']) else "[dim]-[/]"
                install = f"[yellow]{entry['install']}[/]" if not entry['found'] else ""
                t.add_row(status, entry['name'], entry['version'], crit, install)
            
            con.print(Rule("[bold]System Tools[/]", style="cyan"))
            con.print(t)
            
            # Python packages table
            t2 = Table(box=box.ROUNDED, border_style="dim")
            t2.add_column("Status", style="bold")
            t2.add_column("Package")
            t2.add_column("Install")
            
            for entry in ps['list']:
                status = "[green]✅[/]" if entry['found'] else "[red]❌[/]"
                install = f"[yellow]{entry['install']}[/]" if not entry['found'] else ""
                t2.add_row(status, entry['name'], install)
            
            con.print(Rule("[bold]Python Packages[/]", style="cyan"))
            con.print(t2)
            
            # Summary
            summary = Panel(
                f"[bold]Tools:[/] {ts['found']}/{len(ts['list'])} found, "
                f"[red]{ts['critical_missing']} critical missing[/]\n"
                f"[bold]Packages:[/] {ps['found']}/{len(ps['list'])} installed\n"
                + ("\n[red bold]⚠ Some critical tools missing — functionality limited[/]" if ts['critical_missing'] > 0 else "\n[green]✅ All critical tools present[/]"),
                border_style="yellow" if ts['critical_missing'] > 0 else "green"
            )
            con.print(summary)
        else:
            print("\n=== Preflight Check ===")
            for entry in ts['list']:
                s = "✅" if entry['found'] else "❌"
                print(f"  {s} {entry['name']} {entry['version']}")
            print(f"\nTools: {ts['found']}/{len(ts['list'])}")
        
        return r['tools']['critical_missing'] == 0


def cmd_preflight():
    """Run preflight check from command line."""
    checker = PreflightChecker()
    checker.run()
    return checker.display()
