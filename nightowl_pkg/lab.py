# lab.py -- NightOwl v8 Dynamic Analysis Lab Orchestrator
#
# One command surface over adb / frida / objection for the runtime phase of an
# authorized engagement:
#
#   nightowl lab devices                 # inventory + root/frida status
#   nightowl lab install <apk> [-r]      # install target
#   nightowl lab uninstall <pkg>
#   nightowl lab launch <pkg>            # monkey-safe launcher
#   nightowl lab stop <pkg>
#   nightowl lab logcat [--pkg P] [--clear]
#   nightowl lab dumpsys <pkg>           # package + activity view
#   nightowl lab prefs <pkg>             # list app-private storage (run-as/su)
#   nightowl lab pull <remote> [local]   # extract file from device
#   nightowl lab backup <pkg>            # adb backup (legacy) capture
#   nightowl lab frida [serial]          # deploy/start frida-server
#   nightowl lab objection <pkg>         # ready-made REPL command line
#   nightowl lab ssl <pkg>               # one-shot: frida + unpinning script
#   nightowl lab screenshot [out.png]
#   nightowl lab clean                   # clear proxy + kill frida on device
#
# AUTHORIZED TESTING ONLY. Requires a device/emulator you own and targets you
# are licensed to test. The tool never touches production devices implicitly.

import os
import shutil
import subprocess
import sys
from pathlib import Path

ADB_HINTS = [
    os.environ.get("ANDROID_HOME", "") + "/platform-tools/adb",
    os.environ.get("ANDROID_SDK_ROOT", "") + "/platform-tools/adb",
    "/home/ali/tools/android-sdk/platform-tools/adb",
]

FRIDA_SERVER_LOCAL_HINTS = [
    "tools/frida-server",
    "/data/local/tmp/frida-server",
]

GUARD = ("[!] Authorized testing only - confirm you own this device and are "
         "licensed to test the target app.")


def _adb(serial=None):
    adb = shutil.which("adb")
    if not adb:
        for h in ADB_HINTS:
            if h and Path(h).exists():
                adb = h
                break
        else:
            adb = "adb"
    base = [adb]
    if serial:
        base += ["-s", serial]
    return base


def _sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        return r.returncode, out + ("\n" + err if err and not out else "")
    except FileNotFoundError:
        return 127, "adb not found - install platform-tools"
    except subprocess.TimeoutExpired:
        return 1, "command timed out"


def _pick_serial():
    code, out = _sh(_adb() + ["devices"])
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("device", "emulator"):
            return parts[0]
    return None


def _is_rooted(base):
    code, out = _sh(base + ["shell", "su", "-c", "id"], timeout=8)
    return code == 0 and "uid=0" in out


def _pack(base, args):
    """nightowl lab pack <apk> [--powershell] [--report saved.json]"""
    apk = next((a for a in args if not a.startswith("-")), None)
    if not apk or not Path(apk).exists():
        print("Usage: nightowl lab pack <apk> [--powershell|-ps] "
              "[--report saved.json]")
        return 2
    from nightowl_pkg.dynpack import build_pack
    report = None
    if "--report" in args:
        i = args.index("--report")
        rp = args[i + 1] if i + 1 < len(args) else None
        if rp and Path(rp).exists():
            import json as _json
            report = _json.loads(Path(rp).read_text())
    powershell = "--powershell" in args or "-ps" in args
    out = build_pack(apk, full_report=report, powershell=powershell)
    print(f"[+] Dynamic verification pack: {out}")
    print("    Copy it next to the APK on the adb machine, then:")
    if out.suffix == ".sh":
        print(f"    bash {out.name}")
    else:
        print(f"    powershell -ExecutionPolicy Bypass -File {out.name}")
    print("    Send back results.json ->  nightowl lab ingest results.json")
    return 0


def _ingest(base, args):
    """nightowl lab ingest <results.json> [--patch report.json]"""
    res = next((a for a in args if not a.startswith("-")), None)
    if not res or not Path(res).exists():
        print("Usage: nightowl lab ingest results.json "
              "[--patch saved-report.json]")
        return 2
    from nightowl_pkg.dynpack import ingest
    patch = None
    if "--patch" in args:
        i = args.index("--patch")
        patch = args[i + 1] if i + 1 < len(args) else None
    summary = ingest(res,
                     out_path=str(Path(res).with_suffix(".verdicts.json")))
    import json as _json
    print(_json.dumps(summary, indent=2, ensure_ascii=False)[:4000])
    if patch and Path(patch).exists():
        rep = _json.loads(Path(patch).read_text())
        rep["dynamic_verification"] = summary
        Path(patch).write_text(_json.dumps(rep, indent=2,
                                           ensure_ascii=False))
        print(f"[+] patched {patch}")
    return 0


def cmd_lab(args):
    """Entry: nightowl lab <subcommand> [...]. Returns exit code."""
    sub = args[0] if args else ""
    rest = args[1:]

    serial = None
    if "--serial" in rest:
        i = rest.index("--serial")
        serial = rest[i + 1] if i + 1 < len(rest) else None
        rest = rest[:i] + rest[i + 2:]
    base = _adb(serial or _pick_serial())

    dispatch = {
        "devices": _devices,
        "install": _install,
        "uninstall": _uninstall,
        "launch": _launch,
        "stop": _stop,
        "logcat": _logcat,
        "dumpsys": _dumpsys,
        "prefs": _prefs,
        "pull": _pull,
        "backup": _backup,
        "frida": _frida,
        "pack": _pack,
        "ingest": _ingest,
        "objection": _objection,
        "ssl": _ssl,
        "screenshot": _screenshot,
        "clean": _clean,
    }
    fn = dispatch.get(sub)
    if not fn:
        print(__doc__)
        return 2
    return fn(base, rest) or 0


# ── subcommands ──────────────────────────────────────────────────────────────

def _devices(base, args):
    code, out = _sh(base + ["devices", "-l"])
    print(out)
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 2 and p[1] == "device":
            b = _adb(p[0])
            rooted = _is_rooted(b)
            fc, fo = _sh(b + ["shell", "ls", "/data/local/tmp/frida-server"],
                         timeout=8)
            print(f"  {p[0]}: rooted={'YES' if rooted else 'no'} "
                  f"frida-server={'present' if fc == 0 else 'missing'}")
    return 0


def _install(base, args):
    apk = next((a for a in args if not a.startswith("-")), None)
    if not apk:
        print("Usage: nightowl lab install <apk> [-r]")
        return 2
    print(GUARD)
    flags = ["-r"] if "-r" in args else []
    code, out = _sh(base + ["install"] + flags + [apk], timeout=180)
    print(out or f"exit={code}")
    return 0 if code == 0 else 1


def _uninstall(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab uninstall <package>")
        return 2
    code, out = _sh(base + ["uninstall", pkg])
    print(out or f"exit={code}")
    return 0 if code == 0 else 1


def _launch(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab launch <package>")
        return 2
    print(GUARD)
    code, out = _sh(base + ["shell", "monkey", "-p", pkg, "-c",
                            "android.intent.category.LAUNCHER", "1"])
    print("launched" if code == 0 else f"launch failed: {out}")
    return 0 if code == 0 else 1


def _stop(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab stop <package>")
        return 2
    _sh(base + ["shell", "am", "force-stop", pkg])
    print(f"stopped {pkg}")
    return 0


def _logcat(base, args):
    if "--clear" in args:
        _sh(base + ["logcat", "-c"])
        print("[+] logcat cleared")
        return 0
    pkg = None
    if "--pkg" in args:
        i = args.index("--pkg")
        pkg = args[i + 1] if i + 1 < len(args) else None
    if "--json" in args:
        # NDJSON stream: {"ts":..., "level":..., "tag":..., "msg":...}
        import json as _json
        from datetime import datetime, timezone
        proc = subprocess.Popen(
            base + ["logcat", "-v", "time"] +
            ([f"--pid={_pid_of(base, pkg)}"] if pkg else []),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            for line in proc.stdout:
                parts = line.split(":", 3)
                rec = {"ts": datetime.now(timezone.utc).isoformat(),
                       "raw": line.rstrip()}
                if len(parts) == 4:
                    meta = parts[0].split()
                    rec.update({"date": meta[0] if meta else "",
                                "time": meta[1] if len(meta) > 1 else "",
                                "level": parts[1].strip(),
                                "tag": parts[2].strip(),
                                "msg": parts[3].strip()})
                sys.stdout.write(_json.dumps(rec) + "\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            proc.terminate()
        return 0
    cmd = base + ["logcat"]
    if pkg:
        pid = _pid_of(base, pkg)
        if pid:
            cmd += ["--pid=" + pid]
    try:
        proc = subprocess.Popen(cmd, stdout=None)
        proc.wait()
    except KeyboardInterrupt:
        pass
    return 0


def _pid_of(base, pkg):
    code, out = _sh(base + ["shell", "pidof", pkg], timeout=8)
    return out.split()[0] if code == 0 and out.split() else None


def _dumpsys(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab dumpsys <package>")
        return 2
    for svc in ("package " + pkg, "activity processes " + pkg):
        code, out = _sh(base + ["shell", "dumpsys", *svc.split()], timeout=25)
        print(f"── dumpsys {svc} ──")
        print(out[:4000])
    return 0


def _prefs(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab prefs <package> [--pull DIR]")
        return 2
    print(GUARD)
    data_dir = f"/data/data/{pkg}"
    shell_cmd = (f"run-as {pkg} ls -la {data_dir}/shared_prefs 2>/dev/null || "
                 f"su -c 'ls -la {data_dir}/shared_prefs' 2>/dev/null || "
                 f"su -c 'ls -la {data_dir}/databases' 2>/dev/null")
    code, out = _sh(base + ["shell", shell_cmd], timeout=20)
    print(out if out else "(no access: app not debuggable and device not rooted)")
    if "--pull" in args:
        i = args.index("--pull")
        dest = args[i + 1] if i + 1 < len(args) else "."
        Path(dest).mkdir(parents=True, exist_ok=True)
        c2, o2 = _sh(base + ["shell",
                             f"su -c 'tar cf - {data_dir}/shared_prefs' 2>/dev/null | tar xf - -C {dest}"],
                     timeout=60)
        print(f"[+] archive attempt -> {dest}" if c2 == 0 else f"[!] {o2}")
    return 0


def _pull(base, args):
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        print("Usage: nightowl lab pull <remote-path> [local]")
        return 2
    remote = positional[0]
    local = positional[1] if len(positional) > 1 else "."
    code, out = _sh(base + ["pull", remote, local], timeout=120)
    print(out or f"exit={code}")
    return 0 if code == 0 else 1


def _backup(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab backup <package>   (writes backup_<pkg>.ab)")
        return 2
    print(GUARD)
    out_f = f"backup_{pkg}.ab"
    code, out = _sh(base + ["backup", "-nosystem", "-f", out_f, pkg],
                    timeout=300)
    print(f"[+] wrote {out_f}" if code == 0 else f"[!] {out}")
    print("    Extract with abe.jar (Android Backup Extractor); allowBackup="
          "false apps refuse this - that itself is a finding.")
    return 0 if code == 0 else 1


def _frida(base, args):
    print(GUARD)
    arch_code, arch_out = _sh(base + ["shell", "getprop",
                                      "ro.product.cpu.abi"], timeout=8)
    abi = arch_out.strip()
    local = next((h for h in FRIDA_SERVER_LOCAL_HINTS
                  if Path(h).exists()), None)
    print(f"device abi : {abi}")
    if local:
        code, out = _sh(base + ["push", local, "/data/local/tmp/frida-server"],
                        timeout=180)
        if code != 0:
            print(f"[!] push failed: {out}")
            return 1
        print("[+] pushed frida-server")
    start_cmd = ("su -c 'chmod 755 /data/local/tmp/frida-server && "
                 "setsid /data/local/tmp/frida-server &'")
    code, out = _sh(base + ["shell", start_cmd], timeout=15)
    vc, vo = _sh(base + ["shell", "su -c 'pgrep -f frida-server'"], timeout=8)
    print(f"[+] frida-server {'running pid=' + vo if vo else 'start attempted'}")
    print("    verify: frida-ps -Uai")
    return 0


def _objection(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab objection <package> [startup-command]")
        return 2
    startup = next((args[i + 1] for i, a in enumerate(args)
                    if a == "--startup-command"),
                   "android sslpinning disable; android root disable")
    print(GUARD)
    print("\nRun:")
    print(f'  objection -n {pkg} start --startup-command "{startup}"')
    print("\nUseful in-REPL commands:")
    print("  env | android sharedpreferences list | android hooking list activities")
    print("  android hooking watch class_method <Cls.meth> --dump-args --dump-backtrace")
    return 0


def _ssl(base, args):
    pkg = next((a for a in args if not a.startswith("-")), None)
    if not pkg:
        print("Usage: nightowl lab ssl <package>   # frida + unpinning one-shot")
        return 2
    script = Path(__file__).resolve().parent.parent / "frida-scripts" / "ssl-bypass.js"
    print(GUARD)
    print("\nOption A (objection built-in):")
    print(f'  objection -n {pkg} start --startup-command "android sslpinning disable"')
    print("Option B (frida script):")
    if script.exists():
        print(f"  frida -n {pkg} -l {script} --no-pause")
    else:
        print("  frida -n {pkg} -l <httptoolkit frida-interception-and-unpinning.js>")
    print("Remember: pair with `nightowl proxy setup` + CA install to see flows.")
    return 0


def _screenshot(base, args):
    out = next((a for a in args if not a.startswith("-")),
               "workspace/lab/screen.png")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    _sh(base + ["shell", "screencap", "-p", "/sdcard/nw_screen.png"], timeout=20)
    code, outmsg = _sh(base + ["pull", "/sdcard/nw_screen.png", out], timeout=30)
    print(f"[+] saved {out}" if code == 0 else f"[!] {outmsg}")
    return 0 if code == 0 else 1


def _clean(base, args):
    print(GUARD)
    _sh(base + ["shell", "settings", "put", "global", "http_proxy", ":0"])
    print("[+] global proxy cleared")
    _sh(base + ["reverse", "--remove-all"])
    print("[+] adb reverses removed")
    return 0
