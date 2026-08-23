#!/usr/bin/env python3
"""
MASVS Scoring Engine

Calculates MASVS v2 compliance score (0-100) and letter grade (A/B/C/D/F)
from audit findings mapped to the 24-control MASVS matrix.

Usage:
    python3 calculate-score.py findings.json [--json-output]

Exit codes:
    0 - Success
    1 - Error (file not found)
"""

import json
import sys
import argparse
from typing import Dict, List, Any
from pathlib import Path
from collections import defaultdict
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Import shared utilities


def load_findings(input_path: str) -> List[Dict]:
    """Load findings from JSON file."""
    if not Path(input_path).exists():
        print(f"Error: Findings file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
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


def load_masvs_mapping(mapping_path: str) -> Dict:
    """Load MASVS mapping configuration."""
    if not Path(mapping_path).exists():
        # Return minimal default mapping
        return {"controls": {}, "source_to_control_mapping": {}}

    with open(mapping_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_masvs_matrix(matrix_path: str) -> Dict:
    """Load MASVS matrix."""
    if not Path(matrix_path).exists():
        return {"categories": [], "total_controls": 24}

    with open(matrix_path, "r", encoding="utf-8") as f:
        return json.load(f)


def map_finding_to_controls(finding: Dict, mapping: Dict) -> List[str]:
    """
    Map a finding to its corresponding MASVS controls.

    Returns:
        List of MASVS control IDs
    """
    source = finding.get("source", "unknown")
    detector = finding.get("detector", "")

    # Direct mapping via masvs_control field
    if "masvs_control" in finding:
        return [finding["masvs_control"]]

    # Source-based mapping
    source_map = mapping.get("source_to_control_mapping", {})
    if source in source_map:
        # Try detector-level mapping first
        if detector and detector in source_map[source]:
            return source_map[source][detector]
        # Fall back to source-level patterns
        for pattern, controls in source_map[source].items():
            if pattern in str(finding):
                return controls

    # Check by finding category
    title = finding.get("title", "").lower()
    # Crypto issues
    if "crypto" in title or "cipher" in title or "md5" in title or "aes/ecb" in title:
        return ["MSTG-CRYPTO-2"]
    if "key" in title and ("hardcoded" in title or "secret" in title):
        return ["MSTG-CRYPTO-1", "MSTG-STORAGE-1"]
    if "password" in title or "credential" in title:
        return ["MSTG-STORAGE-1"]
    if "token" in title or "api" in title:
        return ["MSTG-AUTH-2", "MSTG-STORAGE-1"]

    # Network issues
    if "ssl" in title or "tls" in title or "certificate" in title or "cleartext" in title:
        return ["MSTG-NET-1", "MSTG-NET-2"]
    if "hostname" in title or "verifier" in title:
        return ["MSTG-NET-2"]

    # Storage issues
    if "sharedpreferences" in title or "storage" in title or "file" in title:
        return ["MSTG-STORAGE-1", "MSTG-STORAGE-3"]
    if "backup" in title:
        return ["MSTG-STORAGE-1"]
    if "external" in title:
        return ["MSTG-STORAGE-1"]

    # Platform issues
    if "webview" in title or "javascript" in title:
        return ["MSTG-PLATFORM-3"]
    if "intent" in title or "broadcast" in title or "ipc" in title:
        return ["MSTG-PLATFORM-1"]
    if "serial" in title or "parcel" in title:
        return ["MSTG-PLATFORM-1"]

    # Authentication
    if "biometric" in title or "auth" in title:
        return ["MSTG-AUTH-1"]

    # Resilience/RASP findings
    if "root" in title or "rooting" in title:
        return ["MSTG-RESILIENCE-2"]
    if "emulator" in title or "debug" in title or "frida" in title:
        return ["MSTG-RESILIENCE-3", "MSTG-RESILIENCE-4"]
    if "screenshot" in title or "screen" in title:
        return ["MSTG-PLATFORM-3"]

    # Default to catch-all
    return ["MSTG-UNKNOWN"]


def calculate_score(findings: List[Dict], mapping: Dict) -> Dict[str, Any]:
    """
    Calculate MASVS compliance score.

    Returns:
        Dict with score, grade, passed_controls, failed_controls, control_details
    """
    matrix = load_masvs_matrix(Path(__file__).parent / "masvs-matrix.json")

    # Initialize all 24 controls as PASSED with no findings
    control_status = defaultdict(lambda: {"status": "PASSED", "findings": []})

    for category in matrix.get("categories", []):
        for control in category.get("controls", []):
            control_id = control["id"]
            control_status[control_id] = {
                "status": "PASSED",
                "findings": [],
                "title": control.get("title", ""),
                "weight": mapping.get("controls", {}).get(control_id, {}).get("weight", 1)
            }

    # Process findings and mark failed controls
    for finding in findings:
        controls = map_finding_to_controls(finding, mapping)
        for control_id in controls:
            if control_id == "MSTG-UNKNOWN":
                continue

            if control_id not in control_status:
                control_status[control_id] = {
                    "status": "PASSED",
                    "findings": [],
                    "title": control_id,
                    "weight": 1
                }

            # Mark as FAILED if there's a finding
            if control_status[control_id]["status"] != "FAILED":
                control_status[control_id]["status"] = "FAILED"
                control_status[control_id]["findings"].append(finding)

    # Calculate weighted score
    total_weight = 0
    earned_weight = 0
    total_controls = 0
    failed_controls = []

    for control_id, details in control_status.items():
        if control_id == "MSTG-UNKNOWN":
            continue

        weight = details.get("weight", 1)
        total_weight += weight
        total_controls += 1

        if details["status"] == "PASSED":
            earned_weight += weight
        else:
            failed_controls.append({
                "id": control_id,
                "title": details["title"],
                "findings_count": len(details["findings"]),
                "top_finding": details["findings"][0] if details["findings"] else None
            })

    # Calculate percentage
    if total_weight > 0:
        percentage = (earned_weight / total_weight) * 100
    else:
        percentage = 100

    # Determine letter grade
    if percentage >= 90:
        grade = "A"
    elif percentage >= 80:
        grade = "B"
    elif percentage >= 70:
        grade = "C"
    elif percentage >= 60:
        grade = "D"
    else:
        grade = "F"

    # Build passed controls list
    passed_controls = [
        {
            "id": control_id,
            "title": details["title"]
        }
        for control_id, details in control_status.items()
        if details["status"] == "PASSED" and control_id != "MSTG-UNKNOWN"
    ]

    return {
        "score": round(percentage, 1),
        "grade": grade,
        "total_controls": total_controls,
        "passed_controls": len(passed_controls),
        "failed_controls": len(failed_controls),
        "passed_control_list": passed_controls,
        "failed_control_list": failed_controls,
        "control_details": dict(control_status),
        "findings_by_control": {
            c["id"]: len(c.get("findings", []))
            for c in failed_controls
        }
    }


def format_text_output(result: Dict) -> str:
    """Format results as text."""
    lines = [
        "=" * 60,
        "MASVS COMPLIANCE SCORE",
        "=" * 60,
        f"Score: {result['score']}%  |  Grade: {result['grade']}",
        f"Controls Passed: {result['passed_controls']}/{result['total_controls']}",
        "",
    ]

    if result["failed_controls"] > 0:
        lines.append("FAILED CONTROLS:")
        lines.append("-" * 40)
        for ctrl in result["failed_control_list"]:
            lines.append(f"  [{ctrl['id']}] {ctrl['title']}")
            if ctrl.get("findings_count", 0) > 0:
                lines.append(f"    Findings: {ctrl['findings_count']}")
                top = ctrl.get("top_finding")
                if top:
                    lines.append(f"    Top: {top.get('title', 'N/A')}")
        lines.append("")

    lines.append("PASSED CONTROLS:")
    lines.append("-" * 40)
    for ctrl in result["passed_control_list"]:
        lines.append(f"  [✓] [{ctrl['id']}] {ctrl['title']}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="MASVS v2 compliance scoring engine"
    )
    parser.add_argument(
        "findings_file",
        nargs="?",
        default="findings.json",
        help="Path to findings JSON file (default: findings.json)"
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--mapping",
        default=None,
        help="Path to MASVS mapping file"
    )

    args = parser.parse_args()

    # Determine mapping path
    if args.mapping:
        mapping_path = args.mapping
    else:
        script_dir = Path(__file__).parent
        mapping_path = script_dir / "05-scoring" / "masvs-mapping.json"

    # Load data
    findings = load_findings(args.findings_file)
    mapping = load_masvs_mapping(mapping_path)

    if not findings:
        print("Warning: No findings found", file=sys.stderr)
        result = {
            "score": 0,
            "grade": "F",
            "total_controls": 24,
            "passed_controls": 0,
            "failed_controls": 24,
            "passed_control_list": [],
            "failed_control_list": [],
            "error": "No findings file found"
        }
    else:
        result = calculate_score(findings, mapping)

    # Output
    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(format_text_output(result))

    sys.exit(0)


if __name__ == "__main__":
    main()
