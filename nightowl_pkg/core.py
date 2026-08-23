# core.py -- NightOwl engine facade.
#
# Single source of truth: nightowl_pkg/engine.py. This module re-exports the
# whole engine surface (NightOwlAnalyzer, pattern tables, helpers, constants)
# under `nightowl_pkg.core` for the rest of the package.

import os
import subprocess
import shutil
from pathlib import Path

from . import engine as _nw

__version__ = "8.0"

# Re-export everything public plus the underscore helpers other modules use.
for _attr in dir(_nw):
    if not _attr.startswith("_") or _attr in (
        "__version__", "_resolve_apk", "_is_flutter_app",
        "_is_likely_false_positive", "_find_tool", "_iss",
    ):
        globals()[_attr] = getattr(_nw, _attr)

# ── Path resolution -----------------------------------------------------------
# ROOT  : repo/checkout root (works in git clones and source trees)
# DATA_DIR: where runtime artifacts (reports, bypass scripts, captures) go.
#           Override with NIGHTOWL_HOME when installed via pip/Docker so we
#           never write into site-packages.
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("NIGHTOWL_HOME") or ROOT)
REPORTS = getattr(_nw, "REPORTS", None)


def _resolve_data_dir(path):
    """Rewrite legacy repo-root workspace paths onto DATA_DIR."""
    try:
        p = Path(path)
    except TypeError:
        return path
    if str(p).startswith(str(ROOT)):
        return DATA_DIR / p.relative_to(ROOT)
    return p


def decompile_apk(apk_path, out_dir=None):
    """Decompile APK using jadx and apktool. Returns (jadx_output, apktool_output)."""
    apk_path = _nw._resolve_apk(apk_path)
    apk = Path(apk_path)
    if not apk.exists():
        return None, None

    stem = apk.stem
    base = Path(out_dir) if out_dir else DATA_DIR / "workspace" / "decompiled" / stem
    base.mkdir(parents=True, exist_ok=True)

    jadx_out = base / "jadx-src"
    jadx_ok = False
    if _nw.JADX and Path(_nw.JADX).exists():
        jadx_out.mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run(
                [_nw.JADX, "--output-dir", str(jadx_out), "--no-res",
                 "--show-bad-code", str(apk)],
                capture_output=True, text=True, timeout=300,
            )
            jadx_ok = r.returncode == 0 or jadx_out.exists()
        except Exception:
            pass

    apktool_out = base / "apktool"
    apktool_ok = False
    try:
        cmd = shutil.which("apktool") if shutil.which("apktool") else _nw.APKTOOL
        if cmd:
            r = subprocess.run(
                ["apktool", "d", "-f", "-o", str(apktool_out), str(apk)],
                capture_output=True, text=True, timeout=180,
            )
            apktool_ok = r.returncode == 0
    except Exception:
        pass

    return (str(jadx_out) if jadx_ok else None,
            str(apktool_out) if apktool_ok else None)


def extract_strings_from_apk(apk_path, output_file=None):
    """Extract all strings from an APK using the strings(1) binary."""
    r = subprocess.run(["strings", "-n", "6", apk_path],
                       capture_output=True, text=True, timeout=120)
    txt = r.stdout
    if output_file:
        Path(output_file).write_text(txt, encoding="utf-8")
    return txt
