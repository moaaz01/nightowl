# proxy.py -- NightOwl v7 Universal Traffic Capture & Proxy Integration
#
# One module that works with ANY interception proxy:
#   mitmproxy / Burp Suite / Charles / HTTP Toolkit / Reqable / Fiddler /
#   a plain HTTP CONNECT proxy on the network.
#
# What it does:
#   status   - show current device/emulator proxy + tool availability
#   setup    - point an Android device or emulator at any proxy (adb)
#   clear    - remove global proxy from the device
#   ca       - compute the OpenSSL subject_hash_old name for a CA cert and
#              print exact install commands (system-store via Magisk or user
#              store) so TLS interception works even against API>=24 apps
#   netconfig- emit a network_security_config.xml trusting user CAs, plus the
#              apktool one-liner to inject it into any APK
#   capture  - generate a mitmproxy addon writing JSONL flows filtered to the
#              app's hosts, ready for `mitmdump`/`mitmweb`
#   env      - print shell exports so NightOwl itself and agent harnesses
#              (OpenClaw/Hermes/Claude Code/Codex/OpenCode) inherit the proxy

import json
import os
import shutil
import subprocess
from pathlib import Path

ADB_HINTS = [
    os.environ.get("ANDROID_HOME", "") + "/platform-tools/adb",
    os.environ.get("ANDROID_SDK_ROOT", "") + "/platform-tools/adb",
    "/home/ali/tools/android-sdk/platform-tools/adb",
]


def _find_adb():
    p = shutil.which("adb")
    if p:
        return p
    for h in ADB_HINTS:
        if h and Path(h).exists():
            return h
    return "adb"


def _sh(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as e:
        return 1, str(e)


def _device_serial(args):
    serial = None
    if "--serial" in args:
        i = args.index("--serial")
        serial = args[i + 1] if i + 1 < len(args) else None
    adb = _find_adb()
    base = [adb] + (["-s", serial] if serial else [])
    return base


MITM_ADDON = '''"""
NightOwl v7 universal capture addon for mitmproxy/mitmweb/mitmdump.

Records every request/response pair as JSON lines so AI agents can diff,
grep or post-process captured app traffic without a GUI.

Run:
    mitmdump -s __OUT__ -p __PORT__
    mitmweb  -s __OUT__ -p __PORT__

Filter (optional): set NIGHTOWL_CAPTURE_HOSTS=host1,host2
Output:            set NIGHTOWL_CAPTURE_OUT=/path/capture.jsonl
"""

import json
import os
from datetime import datetime, timezone

HOST_FILTER = [h.strip() for h in
               os.environ.get("NIGHTOWL_CAPTURE_HOSTS", "").split(",") if h.strip()]
OUT = os.environ.get("NIGHTOWL_CAPTURE_OUT", "__OUTDATA__")


def _want(host):
    if not HOST_FILTER:
        return True
    return any(h in (host or "") for h in HOST_FILTER)


def response(flow):
    host = flow.request.pretty_host
    if not _want(host):
        return
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": host,
        "path": flow.request.path,
        "req_headers": dict(flow.request.headers),
        "req_body": flow.request.get_text(strict=False)[:20000],
        "status": flow.response.status_code,
        "resp_headers": dict(flow.response.headers),
        "resp_body": flow.response.get_text(strict=False)[:20000],
    }
    try:
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\\n")
    except Exception as e:
        print(f"[nightowl-capture] write failed: {e}")
'''


def cmd_proxy(args):
    """Entry: nightowl proxy <subcommand> [options]"""
    sub = args[0] if args else "status"
    rest = args[1:]

    if sub == "status":
        return _status(rest)
    if sub == "setup":
        return _setup(rest)
    if sub == "clear":
        return _clear(rest)
    if sub == "ca":
        return _ca(rest)
    if sub == "netconfig":
        return _netconfig(rest)
    if sub == "capture":
        return _capture(rest)
    if sub == "env":
        return _env(rest)
    print("Usage: nightowl proxy {status|setup|clear|ca|netconfig|capture|env}")
    return 1


def _status(args):
    adb = _find_adb()
    code, out = _sh([adb, "devices"])
    print("== Devices ==")
    print(out or "(no adb)")
    for dev_line in out.splitlines()[1:]:
        parts = dev_line.split()
        if len(parts) >= 2 and parts[1] == "device":
            c2, o2 = _sh([adb, "-s", parts[0], "settings", "get", "global",
                          "http_proxy"])
            print(f"proxy[{parts[0]}] = {o2 or '(none)'}")
    tools = {"mitmproxy": "mitmdump", "burp": None, "charles": None}
    for name in ("mitmdump", "mitmweb"):
        print(f"{name}: {shutil.which(name) or 'not found'}")
    return 0


def _setup(args):
    target = None
    for flag in ("--burp", "--mitm", "--charles"):
        if flag in args:
            target = "127.0.0.1:" + {"--burp": "8080", "--mitm": "8080",
                                     "--charles": "8888"}[flag]
            break
    if "--target" in args:
        i = args.index("--target")
        target = args[i + 1]
    if not target:
        print("Usage: nightowl proxy setup (--burp|--mitm|--charles|--target HOST:PORT)"
              " [--serial SERIAL]")
        return 2
    base = _device_serial(args)
    # adb reverse lets the DEVICE reach a proxy running on THIS machine via USB
    port = target.split(":")[1]
    _sh(base + ["reverse", f"tcp:{port}", f"tcp:{port}"])
    code, out = _sh(base + ["shell", "settings", "put", "global", "http_proxy",
                            f"127.0.0.1:{port}"])
    print(f"[+] Device global http_proxy -> {target}")
    print("[+] adb reverse added (device can reach your host proxy over USB)")
    print("    Verify: nightowl proxy status")
    print("    NOTE: install the proxy CA cert first: nightowl proxy ca <cert.pem>")
    return 0


def _clear(args):
    base = _device_serial(args)
    code, out = _sh(base + ["shell", "settings", "put", "global", "http_proxy",
                            ":0"])
    print("[+] Global proxy cleared" if code == 0 else f"[!] {out}")
    return 0 if code == 0 else 1


def _ca(args):
    cert = next((a for a in args if not a.startswith("--")), None)
    if not cert or not Path(cert).exists():
        print("Usage: nightowl proxy ca <proxy-ca.(pem|crt|der)>")
        return 2
    if not shutil.which("openssl"):
        print("[!] openssl not found; install it to hash the cert.")
        return 1
    r = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout",
         "-in", cert],
        capture_output=True, text=True)
    h = r.stdout.strip() or subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-subject_hash_old", "-noout",
         "-in", cert], capture_output=True, text=True).stdout.strip()
    if not h:
        print("[!] Could not parse certificate")
        return 1
    name = f"{h}.0"
    print(f"[+] System-store filename: {name}  (Magisk: /data/adb/modules/.../system/etc/security/cacerts/{name})")
    print(f"""Next steps (choose ONE):

A) USER STORE (Android <=6 or apps trusting user CAs / patched APKs):
   adb push "{cert}" /sdcard/{name}
   adb shell "cp /sdcard/{name} /data/misc/user/0/cacerts-added/{name} && chmod 644 /data/misc/user/0/cacerts-added/{name}"

B) SYSTEM STORE (rooted, survives API>=24 distrust of user CAs):
   adb push "{cert}" /sdcard/{name}
   adb shell "su -c 'mount -o rw,remount /system; cp /sdcard/{name} /system/etc/security/cacerts/{name}; chmod 644 /system/etc/security/cacerts/{name}'"

C) NO ROOT: patch the APK instead -> nightowl proxy netconfig <apk>
""")
    return 0


NETCONFIG_XML = '''<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by NightOwl v7 -- trust user-installed CAs for authorized testing -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
'''


def _netconfig(args):
    apk = next((a for a in args if not a.startswith("--")), None)
    outdir = Path("workspace/netconfig").resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    xml_path = outdir / "network_security_config.xml"
    xml_path.write_text(NETCONFIG_XML)
    print(f"[+] Wrote {xml_path}")
    print("""
Patch steps (authorized testing only):
  apktool d target.apk -o work/
  cp workspace/netconfig/network_security_config.xml work/res/xml/
  # add inside <application ...> in work/AndroidManifest.xml:
  #     android:networkSecurityConfig="@xml/network_security_config"
  apktool b work/ -o target-patched.apk
  apksigner sign --ks testkey.jks target-patched.apk   # re-sign required
""")
    return 0


def _capture(args):
    out = "workspace/capture/nightowl_capture_addon.py"
    if "--out" in args:
        out = args[args.index("--out") + 1]
    outp = Path(out).expanduser().resolve()
    outp.parent.mkdir(parents=True, exist_ok=True)

    data = outp.parent / "capture.jsonl"
    script = (MITM_ADDON.replace("__OUTDATA__", str(data))
              .replace("__OUT__", str(outp)).replace("__PORT__", "8080"))
    outp.write_text(script)
    print(f"[+] mitmproxy addon written : {outp}")
    print(f"[+] JSONL output file       : {data}")
    print(f"""
Run the capture (any terminal, no GUI needed):
  mitmdump -s {outp} -p 8080          # headless
  mitmweb  -s {outp} -p 8080          # browser UI

Scope it to the app under test:
  NIGHTOWL_CAPTURE_HOSTS=api.target.com mitmdump -s {outp} -p 8080

Then point the device here:
  nightowl proxy setup --mitm

Works identically behind Burp/Charles: run them on 8080 and skip this addon;
use their native export instead - the JSONL schema above is what agents parse.
""")
    return 0


AGENT_SNIPPETS = {
    "openclaw": {
        "env": ["HTTP_PROXY", "HTTPS_PROXY"],
        "note": "Set proxy vars in the OpenClaw process environment; every "
                "child tool inherits them.",
    },
    "hermes": {
        "env": ["HTTP_PROXY", "HTTPS_PROXY"],
        "note": "Hermes passes env through to spawned shells - export before launch.",
    },
    "claude-code": {
        "env": ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"],
        "note": "Claude Code honors HTTPS_PROXY for web tools; child bash "
                "processes inherit all three.",
    },
    "codex": {
        "env": ["HTTP_PROXY", "HTTPS_PROXY"],
        "note": "Codex CLI sandbox: allow outbound to proxy host:port in config.",
    },
    "opencode": {
        "env": ["HTTP_PROXY", "HTTPS_PROXY"],
        "note": "opencode spawns bash directly - standard env inheritance applies.",
    },
}


def _env(args):
    agent = None
    if "--agent" in args:
        i = args.index("--agent")
        agent = args[i + 1]
    host = "127.0.0.1"
    port = "8080"
    exports = "\n".join([
        f"export HTTP_PROXY=http://{host}:{port}",
        f"export HTTPS_PROXY=http://{host}:{port}",
        f"export NO_PROXY=localhost,127.0.0.1",
    ])
    print(exports)
    if agent:
        info = AGENT_SNIPPETS.get(agent.lower())
        if info:
            print(f"\n# Agent bridge: {agent}\n# {info['note']}")
    return 0


def cmd_capture_wrapper(args):
    return _capture(args)
