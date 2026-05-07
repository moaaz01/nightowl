# NightOwl v6 — core.py
# Re-exports the original NightOwl engine

import os, sys, json, re, subprocess, shutil, zipfile, hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import importlib.util

# Import the original nightowl.py as a module
_NW_PATH = Path(__file__).resolve().parent.parent / "nightowl.py"
spec = importlib.util.spec_from_file_location("_nightowl_orig", _NW_PATH)
_nw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_nw)

# Re-export everything from the original module
for _attr in dir(_nw):
    if not _attr.startswith('_') or _attr in ('__version__', '_resolve_apk', '_is_flutter_app', '_is_likely_false_positive', '_find_tool', '_iss'):
        globals()[_attr] = getattr(_nw, _attr)

# Override version to show unified
__version__ = "6.0"

# Silence the original v5.0 show_banner — the unified entry point shows its own
_nw.show_banner = lambda: None

# Additional core functions for DragonJAR integration
ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DJ = ROOT / "scripts-dragonjar"

def decompile_apk(apk_path, out_dir=None):
    """Decompile APK using jadx and apktool. Returns (jadx_output, apktool_output)."""
    apk_path = _resolve_apk(apk_path)
    apk = Path(apk_path)
    if not apk.exists():
        return None, None
    
    stem = apk.stem
    base = Path(out_dir) if out_dir else ROOT / "workspace" / "decompiled" / stem
    base.mkdir(parents=True, exist_ok=True)
    
    # jadx
    jadx_out = base / "jadx-src"
    jadx_ok = False
    if JADX and Path(JADX).exists():
        jadx_out.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run(
                [JADX, '--output-dir', str(jadx_out), '--no-res', '--show-bad-code', str(apk)],
                capture_output=True, text=True, timeout=300
            )
            jadx_ok = r.returncode == 0 or jadx_out.exists()
        except: pass
    
    # apktool
    apktool_out = base / "apktool"
    apktool_ok = False
    try:
        cmd = shutil.which('apktool') if shutil.which('apktool') else APKTOOL
        if cmd:
            r = subprocess.run(['apktool', 'd', '-f', '-o', str(apktool_out), str(apk)],
                             capture_output=True, text=True, timeout=180)
            apktool_ok = r.returncode == 0
    except: pass
    
    return (str(jadx_out) if jadx_ok else None,
            str(apktool_out) if apktool_ok else None)

def extract_strings_from_apk(apk_path, output_file=None):
    """Extract all strings from APK using 'strings' command."""
    r = subprocess.run(['strings', '-n', '6', apk_path], capture_output=True, text=True, timeout=120)
    txt = r.stdout
    if output_file:
        Path(output_file).write_text(txt, encoding='utf-8')
    return txt
