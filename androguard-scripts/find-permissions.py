#!/usr/bin/env python3
"""
NightOwl — Permission Analyzer Helper
Analyzes Android permissions from APK with risk classification.

Usage:
    python3 find-permissions.py app.apk
    python3 find-permissions.py app.apk --risk critical
    python3 find-permissions.py app.apk --json
"""

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Optional

# Permission risk database
PERMISSION_RISKS: dict[str, dict] = {
    "INTERNET": {"risk": "MEDIUM", "desc": "Full network access", "desc_ar": "وصول كامل للشبكة"},
    "READ_CONTACTS": {"risk": "HIGH", "desc": "Read contacts", "desc_ar": "قراءة جهات الاتصال"},
    "WRITE_CONTACTS": {"risk": "HIGH", "desc": "Modify contacts", "desc_ar": "تعديل جهات الاتصال"},
    "READ_SMS": {"risk": "CRITICAL", "desc": "Read SMS messages", "desc_ar": "قراءة الرسائل النصية"},
    "SEND_SMS": {"risk": "CRITICAL", "desc": "Send SMS messages", "desc_ar": "إرسال رسائل نصية"},
    "RECEIVE_SMS": {"risk": "CRITICAL", "desc": "Receive SMS", "desc_ar": "استقبال الرسائل النصية"},
    "READ_PHONE_STATE": {"risk": "HIGH", "desc": "Read phone state/identity", "desc_ar": "قراءة حالة الهاتف"},
    "READ_CALL_LOG": {"risk": "CRITICAL", "desc": "Read call history", "desc_ar": "قراءة سجل المكالمات"},
    "CAMERA": {"risk": "HIGH", "desc": "Camera access", "desc_ar": "الوصول للكاميرا"},
    "RECORD_AUDIO": {"risk": "CRITICAL", "desc": "Microphone recording", "desc_ar": "تسجيل الصوت"},
    "ACCESS_FINE_LOCATION": {"risk": "HIGH", "desc": "GPS precise location", "desc_ar": "الموقع الدقيق GPS"},
    "ACCESS_COARSE_LOCATION": {"risk": "MEDIUM", "desc": "Approximate location", "desc_ar": "الموقع التقريبي"},
    "ACCESS_BACKGROUND_LOCATION": {"risk": "CRITICAL", "desc": "Background location tracking", "desc_ar": "تتبع الموقع في الخلفية"},
    "READ_EXTERNAL_STORAGE": {"risk": "HIGH", "desc": "Read storage", "desc_ar": "قراءة التخزين"},
    "WRITE_EXTERNAL_STORAGE": {"risk": "HIGH", "desc": "Write storage", "desc_ar": "الكتابة على التخزين"},
    "MANAGE_EXTERNAL_STORAGE": {"risk": "CRITICAL", "desc": "Full storage management", "desc_ar": "إدارة التخزين الكامل"},
    "READ_CALENDAR": {"risk": "MEDIUM", "desc": "Read calendar", "desc_ar": "قراءة التقويم"},
    "WRITE_CALENDAR": {"risk": "MEDIUM", "desc": "Modify calendar", "desc_ar": "تعديل التقويم"},
    "GET_ACCOUNTS": {"risk": "HIGH", "desc": "Access accounts", "desc_ar": "الوصول للحسابات"},
    "INSTALL_PACKAGES": {"risk": "CRITICAL", "desc": "Install apps silently", "desc_ar": "تثبيت التطبيقات"},
    "REQUEST_INSTALL_PACKAGES": {"risk": "HIGH", "desc": "Request app install", "desc_ar": "طلب تثبيت التطبيقات"},
    "SYSTEM_ALERT_WINDOW": {"risk": "HIGH", "desc": "Draw over other apps", "desc_ar": "الرسم فوق التطبيقات"},
    "RECEIVE_BOOT_COMPLETED": {"risk": "MEDIUM", "desc": "Auto-start on boot", "desc_ar": "التشغيل التلقائي عند الإقلاع"},
    "WAKE_LOCK": {"risk": "LOW", "desc": "Prevent sleep", "desc_ar": "منع السكون"},
    "VIBRATE": {"risk": "INFO", "desc": "Vibration control", "desc_ar": "التحكم بالاهتزاز"},
    "NFC": {"risk": "MEDIUM", "desc": "NFC access", "desc_ar": "الوصول لـ NFC"},
    "BLUETOOTH": {"risk": "MEDIUM", "desc": "Bluetooth access", "desc_ar": "الوصول للبلوتوث"},
    "BLUETOOTH_ADMIN": {"risk": "HIGH", "desc": "Bluetooth admin", "desc_ar": "إدارة البلوتوث"},
    "FOREGROUND_SERVICE": {"risk": "LOW", "desc": "Foreground service", "desc_ar": "خدمة أمامية"},
    "ACCESS_NETWORK_STATE": {"risk": "LOW", "desc": "Network state info", "desc_ar": "معلومات حالة الشبكة"},
    "BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "desc": "Accessibility service (can read screen)", "desc_ar": "خدمة الوصول (يمكنها قراءة الشاشة)"},
}


def extract_permissions(apk_path: str) -> list[str]:
    """Extract permissions from APK's AndroidManifest.xml."""
    permissions: list[str] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            if "AndroidManifest.xml" in z.namelist():
                data = z.read("AndroidManifest.xml")
                # Binary XML - extract permission strings
                found = re.findall(
                    rb"android\.permission\.([A-Z_]+)", data
                )
                for p in found:
                    perm = p.decode("utf-8", errors="ignore")
                    if perm not in permissions:
                        permissions.append(perm)

            # Also check raw strings in all DEX for permission references
            for name in z.namelist():
                if name.endswith(".dex"):
                    dex_data = z.read(name)
                    dex_found = re.findall(
                        rb"android\.permission\.([A-Z_]+)", dex_data
                    )
                    for p in dex_found:
                        perm = p.decode("utf-8", errors="ignore")
                        if perm not in permissions:
                            permissions.append(perm)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)

    return sorted(permissions)


def classify_permission(perm: str) -> dict:
    """Get risk info for a permission."""
    if perm in PERMISSION_RISKS:
        info = PERMISSION_RISKS[perm]
        return {
            "permission": f"android.permission.{perm}",
            "short": perm,
            "risk": info["risk"],
            "description": info["desc"],
            "description_ar": info["desc_ar"],
        }
    return {
        "permission": f"android.permission.{perm}",
        "short": perm,
        "risk": "UNKNOWN",
        "description": "Unknown permission",
        "description_ar": "صلاحية غير معروفة",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="NightOwl Permission Analyzer")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument(
        "--risk",
        "-r",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by risk level",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="JSON output"
    )
    args = parser.parse_args()

    if not Path(args.apk).exists():
        print(f"[!] File not found: {args.apk}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing permissions: {args.apk}")

    perms = extract_permissions(args.apk)
    classified = [classify_permission(p) for p in perms]

    if args.risk:
        classified = [
            c for c in classified if c["risk"].lower() == args.risk
        ]

    if args.json:
        print(json.dumps(classified, indent=2, ensure_ascii=False))
        return

    # Summary counts
    counts: dict[str, int] = {}
    for c in classified:
        r = c["risk"]
        counts[r] = counts.get(r, 0) + 1

    risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    risk_colors = {
        "CRITICAL": "\033[1;31m",
        "HIGH": "\033[0;31m",
        "MEDIUM": "\033[0;33m",
        "LOW": "\033[0;34m",
        "INFO": "\033[0;36m",
        "UNKNOWN": "\033[0;37m",
    }
    reset = "\033[0m"

    print(f"\n{'='*60}")
    print(f" Permission Analysis Report / تقرير تحليل الصلاحيات")
    print(f" APK: {args.apk}")
    print(f" Total Permissions: {len(classified)}")
    print(f"{'='*60}\n")

    # Print by risk level
    for risk in risk_order:
        group = [c for c in classified if c["risk"] == risk]
        if not group:
            continue
        color = risk_colors.get(risk, "")
        print(f"{color}[{risk}]{reset} ({len(group)} permissions):")
        for c in group:
            print(f"  {color}●{reset} {c['short']}")
            print(f"    EN: {c['description']}")
            print(f"    AR: {c['description_ar']}")
        print()

    # Summary
    print(f"{'─'*40}")
    print("Summary / ملخص:")
    for risk in risk_order:
        if risk in counts:
            color = risk_colors.get(risk, "")
            print(f"  {color}{risk}{reset}: {counts[risk]}")

    # Risk score
    risk_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    total_risk = sum(
        risk_weights.get(c["risk"], 0) for c in classified
    )
    print(f"\n  Permission Risk Score: {total_risk}")
    if total_risk > 100:
        print("  ⚠️  HIGH RISK — هذا التطبيق يطلب صلاحيات خطيرة جداً")
    elif total_risk > 50:
        print("  ⚠️  MEDIUM RISK — يطلب صلاحيات تحتاج مراجعة")
    else:
        print("  ✅ LOW RISK — الصلاحيات المطلوبة معقولة")


if __name__ == "__main__":
    main()
