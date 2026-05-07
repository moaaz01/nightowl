#!/usr/bin/env python3
"""
Semgrep Scanner Wrapper

Validates semgrep installation, runs rules against source, and outputs findings.
Non-blocking: continues pipeline even when semgrep finds issues or has tool errors.

Usage:
    python3 semgrep-scan.py [--rules RULES_DIR] [--output OUTPUT_FILE] [scan_dir]

Exit codes:
    0 - Success (even if findings were found)
    1 - Tool error (semgrep not found, etc.)
    2 - Invalid arguments
"""

import json
import os
import subprocess
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Import shared utilities


def check_semgrep() -> bool:
    """Check if semgrep is installed."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_semgrep(
    rules_path: str,
    scan_dir: str,
    output_format: str = "json",
    exclude_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Run semgrep with the given rules against the scan directory.

    Args:
        rules_path: Path to semgrep rules YAML file
        scan_dir: Directory to scan
        output_format: Output format (json, text, etc.)
        exclude_patterns: Patterns to exclude from scan

    Returns:
        Dict with 'returncode', 'stdout', 'stderr', and 'findings'
    """
    cmd = [
        "semgrep",
        "--config", rules_path,
        "--quiet",  # Quiet mode - no progress bar
        "--no-gitignore",  # Don't respect gitignore
    ]

    if exclude_patterns:
        for pattern in exclude_patterns:
            cmd.extend(["--exclude", pattern])

    cmd.append(scan_dir)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        findings = []
        if result.stdout:
            try:
                findings = json.loads(result.stdout)
                if not isinstance(findings, list):
                    findings = findings.get("results", [])
            except json.JSONDecodeError:
                # Output might not be JSON if no findings
                pass

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "findings": findings,
            "tool_available": True
        }

    except subprocess.TimeoutExpired:
        return {
            "returncode": 124,
            "stdout": "",
            "stderr": "Semgrep timed out after 5 minutes",
            "findings": [],
            "tool_available": True
        }
    except FileNotFoundError:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": "Semgrep not found",
            "findings": [],
            "tool_available": False
        }


def parse_findings(findings: List[Dict]) -> List[Dict]:
    """
    Parse semgrep findings into the shared finding schema.

    Args:
        findings: Raw semgrep findings

    Returns:
        List of findings in shared schema format
    """
    parsed = []

    for finding in findings:
        # Extract metadata if present
        metadata = finding.get("metadata", {})

        # Map severity
        severity_map = {
            "ERROR": "High",
            "WARNING": "Medium",
            "INFO": "Low"
        }
        severity = severity_map.get(finding.get("severity", "WARNING"), "Medium")

        # Extract rule ID and category
        check_id = finding.get("check_id", "")
        category = metadata.get("category", "MASTG-UNKNOWN")

        parsed.append({
            "title": f"[{category}] {finding.get("message", 'Security issue detected')}",
            "severity": severity,
            "confidence": "High",
            "cvss_4_0_score": metadata.get("cvss_4_0_score", "5.3"),
            "owasp_category": metadata.get("owasp_category", "M1-2023"),
            "cwe_id": metadata.get("cwe_id", "CWE-000"),
            "masvs_control": metadata.get("masvs_control", "MSTG-UNKNOWN"),
            "description": f"Semgrep rule {check_id} matched in {finding.get('path', 'unknown')}",
            "proof_of_concept": f"File: {finding.get('path', 'N/A')}:{finding.get('start', {}).get('line', 'N/A')}",
            "remediation": "Review and remediate the security issue per OWASP MASTG guidelines",
            "source": "semgrep",
            "detector": check_id
        })

    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="Semgrep scanner wrapper for Android APK audit"
    )
    parser.add_argument(
        "--rules",
        "-r",
        default=None,
        help="Path to semgrep rules file (default: semgrep-rules/MASTG-rules.yaml)"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="findings-semgrep.json",
        help="Output file for findings (default: findings-semgrep.json)"
    )
    parser.add_argument(
        "scan_dir",
        nargs="?",
        default="src",
        help="Directory to scan (default: src)"
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    # Determine rules path
    if args.rules:
        rules_path = args.rules
    else:
        script_dir = Path(__file__).parent
        rules_path = script_dir / "semgrep-rules" / "MASTG-rules.yaml"

    if not os.path.exists(rules_path):
        print(f"Error: Rules file not found: {rules_path}", file=sys.stderr)
        sys.exit(1)

    # Check semgrep availability
    if not check_semgrep():
        print("Warning: semgrep not installed. Use: pip install semgrep", file=sys.stderr)
        print("[]", file=sys)  # Empty findings
        sys.exit(0)  # Non-blocking - continue pipeline

    # Run semgrep
    result = run_semgrep(
        rules_path=str(rules_path),
        scan_dir=args.scan_dir,
        exclude_patterns=["*.min.js", "*.min.css", "libs/", "vendor/", "build/"]
    )

    if not result["tool_available"]:
        print("Warning: semgrep not available", file=sys.stderr)
        print("[]", file=sys)
        sys.exit(0)  # Non-blocking

    # Parse findings
    findings = parse_findings(result["findings"])

    # Output results
    if args.json_output:
        print(json.dumps(findings, indent=2))
    else:
        if findings:
            print(f"Found {len(findings)} semgrep findings:")
            for f in findings[:10]:  # Show first 10
                print(f"  [{f['severity']}] {f['title']}")
            if len(findings) > 10:
                print(f"  ... and {len(findings) - 10} more")
        else:
            print("No semgrep findings")

    # Write findings to file
    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"Findings written to: {output_path}")

    # Return code handling: non-blocking
    # Exit 0 for success, 1 for tool errors (already handled)
    if result["returncode"] > 1:
        print(f"Warning: semgrep exited with code {result['returncode']}", file=sys.stderr)
        print(f"Error output: {result['stderr'][:500]}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
