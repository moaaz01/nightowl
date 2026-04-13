#!/usr/bin/env python3
"""
Android APK Analysis Script
Comprehensive analysis using Androguard, APKiD, and Quark Engine
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.dex import DEX
except ImportError:
    print("[ERROR] androguard not installed. Run: pip install androguard")
    sys.exit(1)

try:
    from apkid import apkid
except ImportError:
    print("[WARNING] APKiD not installed. Some features will be skipped.")
    apkid = None

try:
    from quark.quark import Quark
except ImportError:
    print("[WARNING] Quark Engine not installed. Some features will be skipped.")
    Quark = None


class APKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        self.results = {}

    def analyze_with_androguard(self):
        """Analyze APK using Androguard"""
        print("[*] Analyzing with Androguard...")
        try:
            apk, dex, dx = AnalyzeAPK(str(self.apk_path))

            self.results['androguard'] = {
                'package': apk.get_package(),
                'version': apk.get_android_manifest_xml().find('manifest').get('android:versionName'),
                'permissions': apk.get_permissions(),
                'activities': apk.get_activities(),
                'services': apk.get_services(),
                'receivers': apk.get_receivers(),
                'providers': apk.get_providers(),
                'libraries': apk.get_libraries(),
                'min_sdk': apk.get_min_sdk_version(),
                'target_sdk': apk.get_target_sdk_version(),
                'signing_certificate_fingerprints': apk.get_certificate_der_v3() or apk.get_certificate_der_v2() or apk.get_certificate_der(),
            }
            print(f"[+] Package: {self.results['androguard']['package']}")
            print(f"[+] Permissions: {len(self.results['androguard']['permissions'])} found")
            return True
        except Exception as e:
            print(f"[-] Androguard analysis failed: {e}")
            return False

    def analyze_with_apkid(self):
        """Analyze APK using APKiD"""
        if apkid is None:
            print("[!] APKiD skipped (not installed)")
            return False

        print("[*] Analyzing with APKiD...")
        try:
            results = apkid.identify(str(self.apk_path), timeout=60)
            self.results['apkid'] = results
            if results:
                print(f"[+] Packers/Obfuscators detected:")
                for category, items in results.items():
                    for item in items:
                        print(f"    - {item}")
            return True
        except Exception as e:
            print(f"[-] APKiD analysis failed: {e}")
            return False

    def analyze_with_quark(self):
        """Analyze APK using Quark Engine"""
        if Quark is None:
            print("[!] Quark Engine skipped (not installed)")
            return False

        print("[*] Analyzing with Quark Engine...")
        try:
            quark = Quark(str(self.apk_path))
            quark.run()

            self.results['quark'] = {
                'risk_score': quark.get_risk_score(),
                'behaviors': []
            }

            for behavior in quark.get_crimes():
                self.results['quark']['behaviors'].append({
                    'name': behavior.name,
                    'score': behavior.score,
                    'confidence': behavior.confidence,
                })

            print(f"[+] Quark Risk Score: {self.results['quark']['risk_score']}")
            print(f"[+] Behaviors detected: {len(self.results['quark']['behaviors'])}")
            return True
        except Exception as e:
            print(f"[-] Quark analysis failed: {e}")
            return False

    def extract_strings(self):
        """Extract strings from APK"""
        print("[*] Extracting strings...")
        try:
            apk, _, _ = AnalyzeAPK(str(self.apk_path))
            strings = apk.get_android_manifest_xml().tostring().decode('utf-8')
            self.results['strings_sample'] = strings[:500]
            return True
        except Exception as e:
            print(f"[-] String extraction failed: {e}")
            return False

    def analyze(self):
        """Run all analyses"""
        print(f"\n[=] Analyzing: {self.apk_path.name}")
        print(f"[=] File size: {self.apk_path.stat().st_size / (1024*1024):.2f} MB")
        print()

        self.analyze_with_androguard()
        self.analyze_with_apkid()
        self.analyze_with_quark()
        self.extract_strings()

        return self.results

    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)

        if 'androguard' in self.results:
            ag = self.results['androguard']
            print(f"\n[Package Information]")
            print(f"  Package: {ag.get('package', 'N/A')}")
            print(f"  Version: {ag.get('version', 'N/A')}")
            print(f"  Min SDK: {ag.get('min_sdk', 'N/A')}")
            print(f"  Target SDK: {ag.get('target_sdk', 'N/A')}")

            print(f"\n[Components]")
            print(f"  Activities: {len(ag.get('activities', []))}")
            print(f"  Services: {len(ag.get('services', []))}")
            print(f"  Receivers: {len(ag.get('receivers', []))}")
            print(f"  Providers: {len(ag.get('providers', []))}")

            print(f"\n[Permissions ({len(ag.get('permissions', []))})]")
            for perm in sorted(ag.get('permissions', []))[:10]:
                print(f"  - {perm}")
            if len(ag.get('permissions', [])) > 10:
                print(f"  ... and {len(ag.get('permissions', [])) - 10} more")

            print(f"\n[Libraries]")
            for lib in ag.get('libraries', []):
                print(f"  - {lib}")

        if 'quark' in self.results:
            quark_data = self.results['quark']
            print(f"\n[Quark Engine Results]")
            print(f"  Risk Score: {quark_data.get('risk_score', 'N/A')}")
            print(f"  Behaviors: {len(quark_data.get('behaviors', []))}")

            high_risk = [b for b in quark_data.get('behaviors', []) if b.get('score', 0) > 5]
            if high_risk:
                print(f"  High Risk Behaviors:")
                for behavior in high_risk[:5]:
                    print(f"    - {behavior['name']} (Score: {behavior['score']})")

        print("\n" + "="*60)

    def save_report(self, output_path=None):
        """Save analysis report to JSON"""
        if output_path is None:
            output_path = self.apk_path.parent / f"{self.apk_path.stem}_analysis.json"

        report = {
            'timestamp': datetime.now().isoformat(),
            'apk_path': str(self.apk_path),
            'results': self.results
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report saved to: {output_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive Android APK Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 analyze.py app.apk
  python3 analyze.py app.apk -o report.json
  python3 analyze.py /path/to/apps/*.apk
        '''
    )

    parser.add_argument('apk', help='APK file or pattern to analyze')
    parser.add_argument('-o', '--output', help='Output JSON report path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Handle single APK
    analyzer = APKAnalyzer(args.apk)
    results = analyzer.analyze()
    analyzer.print_summary()
    analyzer.save_report(args.output)


if __name__ == '__main__':
    main()
