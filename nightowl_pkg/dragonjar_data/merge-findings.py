#!/usr/bin/env python3
"""
Merge Findings

Merges findings from different sources (semgrep, grep, rasp) into a single
findings file, handling duplicates by cvss_4_0_score + cwe_id key.

Usage:
    python3 merge-findings.py [--input INPUT_FILES] [--output OUTPUT_FILE]

Exit codes:
    0 - Success
    1 - Error
"""

import json
import os
import sys
import argparse
from typing import Dict, List, Set
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Import shared utilities


def load_findings(file_path: str) -> List[Dict]:
    """Load findings from a JSON file."""
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            return []

        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "findings" in data:
                return data["findings"]
            else:
                return [data]
        except json.JSONDecodeError:
            return []


def generate_finding_key(finding: Dict) -> str:
    """
    Generate a unique key for a finding based on its core identifying attributes.
    Used for deduplication.
    """
    cwe_id = finding.get("cwe_id", "CWE-000")
    title = finding.get("title", "")
    source = finding.get("source", "unknown")

    # Create a normalized key
    return f"{cwe_id}:{title}:{source}"


def merge_findings(
    all_findings: List[Dict],
    prefer_higher_confidence: bool = True
) -> List[Dict]:
    """
    Merge findings, removing duplicates.

    Duplicates are identified by same (cwe_id + title + source).
    When duplicates exist, prefer the one with higher confidence.

    Args:
        all_findings: List of all findings from all sources
        prefer_higher_confidence: If True, prefer findings with higher confidence

    Returns:
        Deduplicated list of findings
    """
    seen_keys: Set[str] = set()
    unique_findings: List[Dict] = []

    confidence_order = {"High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

    for finding in all_findings:
        key = generate_finding_key(finding)

        if key not in seen_keys:
            seen_keys.add(key)
            unique_findings.append(finding)
        else:
            # Find existing finding with same key
            for existing in unique_findings:
                if generate_finding_key(existing) == key:
                    # Prefer higher confidence if enabled
                    if prefer_higher_confidence:
                        existing_conf = confidence_order.get(
                            existing.get("confidence", "Unknown"), 0
                        )
                        new_conf = confidence_order.get(
                            finding.get("confidence", "Unknown"), 0
                        )
                        if new_conf > existing_conf:
                            # Replace with higher confidence version
                            unique_findings.remove(existing)
                            unique_findings.append(finding)
                            seen_keys.add(key)  # Keep tracking this key
                    break

    return unique_findings


def validate_finding(finding: Dict) -> bool:
    """
    Validate a finding against the shared DRY findings contract.

    Falls back to the legacy minimum required by this merge tool if the shared
    module cannot be imported in an unusual execution context.
    """
    try:
        from scripts.lib.findings import validate_finding as validate_shared_finding

        return validate_shared_finding(finding)
    except Exception:
        required_fields = ["title", "severity", "source"]
        if not all(field in finding for field in required_fields):
            return False

        valid_severities = ["Critical", "High", "Medium", "Low", "Informational"]
        valid_sources = ["semgrep", "rasp", "grep", "manual", "mobsf", "burp", "frida"]
        return finding.get("severity") in valid_severities and finding.get("source") in valid_sources


def main():
    parser = argparse.ArgumentParser(
        description="Merge findings from multiple sources into a single findings file"
    )
    parser.add_argument(
        "--input",
        "-i",
        nargs="+",
        default=["findings.json"],
        help="Input findings files to merge (default: findings.json)"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="findings.json",
        help="Output merged findings file (default: findings.json)"
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        default=True,
        help="Remove duplicate findings (default: True)"
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    # Load all findings
    all_findings = []
    sources = []

    for input_file in args.input:
        findings = load_findings(input_file)
        if findings:
            all_findings.extend(findings)
            sources.append(input_file)
            print(f"Loaded {len(findings)} findings from {input_file}")

    if not all_findings:
        print("Warning: No findings found in any input file", file=sys.stderr)
        print("[]", file=sys)
        # Write empty array to output
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([], f)
        sys.exit(0)

    print(f"Total findings loaded: {len(all_findings)}")

    # Merge and deduplicate
    if args.dedupe:
        before_count = len(all_findings)
        all_findings = merge_findings(all_findings)
        after_count = len(all_findings)
        print(f"After deduplication: {after_count} findings (removed {before_count - after_count} duplicates)")

    # Sort by severity
    severity_order = {
        "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4
    }
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Low"), 5))

    # Validate and report invalid findings
    valid_findings = []
    invalid_count = 0
    for finding in all_findings:
        if validate_finding(finding):
            valid_findings.append(finding)
        else:
            invalid_count += 1
            print(f"Warning: Invalid finding skipped: {finding.get('title', 'unknown')}", file=sys.stderr)

    if invalid_count > 0:
        print(f"Warning: {invalid_count} invalid findings were skipped", file=sys.stderr)

    # Write output
    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(valid_findings, f, indent=2)

    print(f"Merged findings written to: {output_path}")

    # Output summary if not JSON
    if not args.json_output:
        print("\nSummary:")
        print(f"  Total valid findings: {len(valid_findings)}")
        print("  By severity:")
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            count = sum(1 for f in valid_findings if f.get("severity") == sev)
            if count > 0:
                print(f"    {sev}: {count}")

    sys.exit(0)


if __name__ == "__main__":
    main()
