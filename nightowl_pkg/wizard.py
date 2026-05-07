# NightOwl v6 — wizard.py
# Interactive scan wizard — asks what you want and runs it

import os, sys, json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ROOT / "targets"

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.markup import escape as esc
    from rich import box
    con = Console(highlight=False)
    RICH = True
except ImportError:
    RICH = False
    class con:
        @staticmethod
        def print(*a, **kw): print(*a)
    class Prompt:
        @staticmethod
        def ask(msg, default=None, choices=None):
            if choices: return input(f"{msg} ({'/'.join(choices)}): ").strip()
            return input(f"{msg} [{default}]: ").strip() or default
    class Confirm:
        @staticmethod
        def ask(msg, default=True):
            r = input(f"{msg} (Y/n): " if default else f"{msg} (y/N): ").lower().strip()
            if not r: return default
            return r in ('y', 'yes')


def get_apk_choices():
    """List available APKs in targets/."""
    apks = sorted(TARGETS.glob("*.apk"))
    return apks


def select_apk():
    """Interactive APK selection."""
    apks = get_apk_choices()
    
    if not apks:
        if RICH:
            con.print("[yellow]No APKs found in targets/[/]")
        path = Prompt.ask("  Enter APK path", default="")
        if not path:
            return None
        return path
    
    if RICH:
        con.print(Panel("[bold]Available APKs[/]", border_style="cyan"))
        for i, apk in enumerate(apks, 1):
            size = apk.stat().st_size / (1024*1024)
            con.print(f"  [{i}] [bold]{apk.name}[/] [dim]({size:.1f} MB)[/]")
        con.print(f"  [{len(apks)+1}] Enter custom path")
        con.print()
        
        choice = IntPrompt.ask("  Select APK", default=1)
        if choice == len(apks) + 1:
            return Prompt.ask("  Enter APK path")
        elif 1 <= choice <= len(apks):
            return str(apks[choice - 1])
        else:
            return str(apks[0])
    else:
        print("\nAvailable APKs:")
        for i, apk in enumerate(apks, 1):
            print(f"  [{i}] {apk.name}")
        choice = input("Select APK [1]: ").strip()
        if not choice:
            return str(apks[0])
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(apks):
                return str(apks[idx])
        except: pass
        return str(apks[0])


def show_menu():
    """Show the main interactive menu."""
    if RICH:
        con.print(Panel.fit(
            "[bold cyan]🦉 NightOwl v6.0 — Unified Android Security Suite[/]\n"
            "[dim]Everything in one tool[/]",
            border_style="cyan"
        ))
        con.print()
        
        menu_items = [
            ("1", "Full Scan", "Complete analysis: info + perms + URLs + secrets + vulns + manifest", "cyan"),
            ("2", "Quick Scan", "Basic info + critical vulnerabilities only", "green"),
            ("3", "API Extraction", "Extract all API endpoints and URLs", "blue"),
            ("4", "Secrets Discovery", "Find hardcoded keys, tokens, passwords", "red"),
            ("5", "Static Audit", "Full jadx/apktool decode + pattern analysis (DragonJAR)", "yellow"),
            ("6", "Framework Analysis", "Flutter / React Native / Cordova / Unity", "magenta"),
            ("7", "RASP Detection", "Detect root detection, anti-tamper, bypasses", "orange1"),
            ("8", "Decompile", "Decompile APK with jadx + apktool", "dim"),
            ("9", "Semgrep Scan", "Run MASTG static analysis rules", "bright_cyan"),
            ("10", "Bypass Generator", "Generate Frida bypass scripts", "bright_magenta"),
            ("11", "Preflight Check", "Check all dependencies", "bright_green"),
            ("12", "Batch Scan", "Scan all APKs in directory", "bright_white"),
            ("0", "Exit", "", "dim"),
        ]
        
        t = Table(box=box.ROUNDED, border_style="dim", show_header=False, expand=True)
        t.add_column("#", style="bold", width=4)
        t.add_column("Scan Type", style="cyan", width=20)
        t.add_column("Description", style="white", width=50)
        
        for num, name, desc, style in menu_items:
            style_attr = f"bold {style}" if style else ""
            t.add_row(f"[{style_attr}]{num}[/]", f"[{style_attr}]{name}[/]", desc)
        
        con.print(t)
        con.print()
    else:
        print("\n=== NightOwl v6.0 ===")
        print("1. Full Scan")
        print("2. Quick Scan")
        print("3. API Extraction")
        print("4. Secrets Discovery")
        print("5. Static Audit (DragonJAR)")
        print("6. Framework Analysis")
        print("7. RASP Detection")
        print("8. Decompile")
        print("9. Semgrep Scan")
        print("10. Bypass Generator")
        print("11. Preflight Check")
        print("12. Batch Scan")
        print("0. Exit")


def interactive_wizard():
    """Main interactive wizard loop."""
    while True:
        show_menu()
        choice = Prompt.ask("  What do you want to do?", choices=["0","1","2","3","4","5","6","7","8","9","10","11","12"], default="1")
        
        if choice == "0":
            if RICH:
                con.print("[dim]Goodbye! 🦉[/]")
            break
        
        # Commands that don't need APK
        if choice == "11":
            from nightowl_pkg.preflight import cmd_preflight
            cmd_preflight()
            confirm_continue()
            continue
        
        if choice == "12":
            from nightowl_pkg import core as nw
            nw.cmd_scan()
            confirm_continue()
            continue
        
        # Commands that need APK
        if choice in ("1","2","3","4","5","6","7","8","9","10"):
            apk_path = select_apk()
            if not apk_path:
                continue
            
            apk_path = str(Path(apk_path).resolve())
            if not Path(apk_path).exists():
                if RICH:
                    con.print(f"[red]File not found: {apk_path}[/]")
                confirm_continue()
                continue
            
            _run_scan_choice(choice, apk_path)
        
        confirm_continue()


def _run_scan_choice(choice, apk_path):
    """Execute the selected scan type."""
    # Import the main module
    import importlib
    nw = importlib.import_module('nightowl_pkg.core')
    dj = importlib.import_module('nightowl_pkg.dragonjar')
    fw = importlib.import_module('nightowl_pkg.frameworks')
    rt = importlib.import_module('nightowl_pkg.runtime')
    
    lang = "ar" if Confirm.ask("  Arabic report?", default=False) else "en"
    
    if choice == "1":  # Full Scan
        if RICH:
            con.print(f"[cyan]Running full scan on:[/] {Path(apk_path).name}")
        az = nw.NightOwlAnalyzer(apk_path, lang=lang)
        az.run_full()
        az.render('full')
        if Confirm.ask("  Save report?", default=True):
            az.save()
    
    elif choice == "2":  # Quick Scan
        if RICH:
            con.print(f"[green]Quick scan:[/] {Path(apk_path).name}")
        az = nw.NightOwlAnalyzer(apk_path, lang=lang)
        az.run_full()
        # Only show essential info
        az.render('info')
        if az.d['vulns']:
            t = Table(box=box.ROUNDED, border_style="red")
            t.add_column("Risk")
            t.add_column("Issue")
            for v in az.d['vulns'][:10]:
                t.add_row(v['risk'], v['title'])
            con.print(t)
    
    elif choice == "3":  # API Extraction
        if RICH:
            con.print(f"[blue]Extracting APIs from:[/] {Path(apk_path).name}")
        az = nw.NightOwlAnalyzer(apk_path, lang=lang)
        az.analyze_info()
        az.extract_strings()
        az.analyze_endpoints()
        az.analyze_apis()
        
        ep = az.d['endpoints']
        if RICH:
            t = Table(box=box.ROUNDED, border_style="blue")
            t.add_column("Type", style="cyan")
            t.add_column("Count", justify="right")
            t.add_row("Servers", str(len(ep.get('servers', []))))
            t.add_row("URLs", str(len(ep.get('urls', []))))
            t.add_row("API Paths", str(len(ep.get('api', []))))
            t.add_row("IPs", str(len(ep.get('ips', []))))
            con.print(t)
            
            if ep.get('api'):
                con.print(f"\n[bold]Top API Paths:[/]")
                for a in ep['api'][:20]:
                    con.print(f"  [dim]{a}[/]")
    
    elif choice == "4":  # Secrets
        if RICH:
            con.print(f"[red]Scanning for secrets in:[/] {Path(apk_path).name}")
        az = nw.NightOwlAnalyzer(apk_path, lang=lang)
        az.analyze_info()
        az.extract_strings()
        az.analyze_secrets()
        
        if RICH and az.d.get('secrets'):
            t = Table(box=box.ROUNDED, border_style="red")
            t.add_column("Risk")
            t.add_column("Type")
            t.add_column("Value (truncated)")
            t.add_column("Source")
            for s in az.d['secrets'][:15]:
                val = s['value'][:40] + "..." if len(s['value']) > 40 else s['value']
                t.add_row(f"{s['risk']}", s['type'], val, s.get('source', ''))
            con.print(t)
    
    elif choice == "5":  # Static Audit
        if RICH:
            con.print(f"[yellow]Static audit (DragonJAR):[/] {Path(apk_path).name}")
        mode = 'full' if Confirm.ask("  Full audit? (slower)", default=True) else 'quick'
        dj.cmd_static_audit(apk_path, mode=mode)
    
    elif choice == "6":  # Framework
        if RICH:
            con.print(f"[magenta]Framework analysis:[/] {Path(apk_path).name}")
        fw.cmd_flutter(apk_path)
    
    elif choice == "7":  # RASP
        if RICH:
            con.print(f"[orange1]RASP detection:[/] {Path(apk_path).name}")
        rt.cmd_rasp(apk_path)
    
    elif choice == "8":  # Decompile
        if RICH:
            con.print(f"[dim]Decompiling:[/] {Path(apk_path).name}")
        nw.cmd_decompile(apk_path)
    
    elif choice == "9":  # Semgrep
        if RICH:
            con.print(f"[bright_cyan]Semgrep scan:[/] {Path(apk_path).name}")
        if not Confirm.ask("  Decompile first? (needed for source)", default=True):
            con.print("[yellow]Semgrep needs decompiled source[/]")
        else:
            jadx_out, _ = nw.decompile_apk(apk_path)
            if jadx_out:
                src_dir = Path(jadx_out) / "sources"
                if src_dir.exists():
                    result = dj.cmd_semgrep(str(src_dir))
                    if result.get('tool_available'):
                        con.print(f"  Semgrep found [bold]{result['count']}[/] findings")
                    else:
                        con.print(f"  [yellow]Semgrep: {result.get('error', 'not available')}[/]")
    
    elif choice == "10":  # Bypass
        pkg = Prompt.ask("  Package name (e.g., com.example.app)")
        if pkg:
            rt.cmd_bypass(pkg)
    
    if RICH:
        con.print()


def confirm_continue():
    """Ask if user wants to continue."""
    if RICH:
        con.print()
        if not Confirm.ask("  Continue?", default=True):
            if RICH:
                con.print("[dim]Goodbye! 🦉[/]")
            sys.exit(0)
        con.print(Rule(style="dim"))


def main():
    """Entry point for interactive mode."""
    interactive_wizard()
