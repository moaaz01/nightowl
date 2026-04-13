#!/usr/bin/env python3
"""
NightOwl — String Extraction Helper
Extracts all strings from APK (DEX, XML, assets) with categorization.

Usage:
    python3 extract-strings.py app.apk
    python3 extract-strings.py app.apk --output strings.txt
    python3 extract-strings.py app.apk --min-length 10
    python3 extract-strings.py app.apk --filter url
"""

import argparse
import re
import sys
import zipfile
from pathlib import Path
from typing import Optional


def extract_dex_strings(apk_path: str, min_length: int = 4) -> list[dict]:
    """Extract strings from all DEX files in APK."""
    strings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    data = z.read(name)
                    found = re.findall(rb"[\x20-\x7e]{%d,}" % min_length, data)
                    for s in found:
                        try:
                            decoded = s.decode("utf-8", errors="ignore")
                            strings.append({"source": name, "value": decoded})
                        except Exception:
                            pass
    except Exception as e:
        print(f"[!] Error reading DEX: {e}", file=sys.stderr)
    return strings


def extract_xml_strings(apk_path: str) -> list[dict]:
    """Extract strings from XML resources."""
    strings = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.endswith(".xml"):
                    try:
                        data = z.read(name)
                        found = re.findall(rb"[\x20-\x7e]{4,}", data)
                        for s in found:
                            decoded = s.decode("utf-8", errors="ignore")
                            strings.append({"source": name, "value": decoded})
                    except Exception:
                        pass
    except Exception as e:
        print(f"[!] Error reading XML: {e}", file=sys.stderr)
    return strings


def extract_asset_strings(apk_path: str, min_length: int = 4) -> list[dict]:
    """Extract strings from assets/ directory."""
    strings = []
    text_exts = {".txt", ".json", ".xml", ".html", ".js", ".css", ".properties", ".cfg", ".ini", ".yaml", ".yml"}
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for name in z.namelist():
                if name.startswith("assets/"):
                    ext = Path(name).suffix.lower()
                    if ext in text_exts:
                        try:
                            data = z.read(name).decode("utf-8", errors="ignore")
                            for line in data.splitlines():
                                line = line.strip()
                                if len(line) >= min_length:
                                    strings.append({"source": name, "value": line})
                        except Exception:
                            pass
    except Exception as e:
        print(f"[!] Error reading assets: {e}", file=sys.stderr)
    return strings


def categorize_string(value: str) -> str:
    """Categorize a string by its content."""
    if re.match(r"https?://", value):
        return "URL"
    if re.match(r"[\w.-]+@[\w.-]+\.\w+", value):
        return "EMAIL"
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value):
        return "IP"
    if re.match(r"[A-Za-z_][\w.]+\.[A-Za-z_][\w.]+", value) and "/" not in value:
        return "CLASS"
    if re.search(r"(api[_-]?key|token|secret|password|auth)", value, re.I):
        return "SECRET"
    if re.search(r"/[a-z]+/[a-z]", value):
        return "PATH"
    return "STRING"


def filter_strings(
    strings: list[dict], filter_type: Optional[str] = None
) -> list[dict]:
    """Filter strings by category."""
    if not filter_type:
        return strings
    ft = filter_type.upper()
    return [s for s in strings if categorize_string(s["value"]) == ft]


def main() -> None:
    parser = argparse.ArgumentParser(description="NightOwl String Extractor")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument(
        "--min-length", "-m", type=int, default=4, help="Minimum string length"
    )
    parser.add_argument(
        "--filter",
        "-f",
        choices=["url", "email", "ip", "class", "secret", "path"],
        help="Filter by category",
    )
    parser.add_argument(
        "--unique", "-u", action="store_true", help="Remove duplicates"
    )
    args = parser.parse_args()

    if not Path(args.apk).exists():
        print(f"[!] File not found: {args.apk}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Extracting strings from: {args.apk}")

    all_strings: list[dict] = []
    all_strings.extend(extract_dex_strings(args.apk, args.min_length))
    all_strings.extend(extract_xml_strings(args.apk))
    all_strings.extend(extract_asset_strings(args.apk, args.min_length))

    if args.filter:
        all_strings = filter_strings(all_strings, args.filter)

    if args.unique:
        seen: set[str] = set()
        unique: list[dict] = []
        for s in all_strings:
            if s["value"] not in seen:
                seen.add(s["value"])
                unique.append(s)
        all_strings = unique

    # Categorize
    for s in all_strings:
        s["category"] = categorize_string(s["value"])

    # Output
    output_lines = []
    for s in all_strings:
        line = f"[{s['category']:>7}] [{s['source']}] {s['value']}"
        output_lines.append(line)

    if args.output:
        Path(args.output).write_text("\n".join(output_lines), encoding="utf-8")
        print(f"[+] Saved {len(all_strings)} strings to: {args.output}")
    else:
        for line in output_lines:
            print(line)

    # Summary
    categories: dict[str, int] = {}
    for s in all_strings:
        cat = s["category"]
        categories[cat] = categories.get(cat, 0) + 1

    print(f"\n[+] Total strings: {len(all_strings)}")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"    {cat}: {count}")


if __name__ == "__main__":
    main()
