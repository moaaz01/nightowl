#!/usr/bin/env python3
"""
Update MASVS coverage status based on findings.

Reads findings from JSON/JSONL and updates masvs-matrix.json accordingly.
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Optional


def load_findings(findings_path: Path) -> list[dict]:
    """Load findings from JSON array or JSONL file."""
    with open(findings_path, 'r', encoding='utf-8') as f:
        content = f.read().strip()

    if not content:
        return []

    # Try JSON array first
    if content.startswith('['):
        return json.loads(content)

    # Fallback to JSONL (one finding per line)
    findings = []
    for line in content.split('\n'):
        line = line.strip()
        if line:
            findings.append(json.loads(line))
    return findings


def load_masvs_matrix(matrix_path: Path) -> dict:
    """Load the MASVS matrix."""
    with open(matrix_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_control_id(masvs_control: str) -> Optional[str]:
    """Extract normalized control ID from various formats."""
    if not masvs_control:
        return None

    # Already in MSTG-XXX format
    if masvs_control.startswith('MSTG-'):
        return masvs_control

    # Handle M1-NET-1 style (MASVS legacy) - convert to MSTG
    if '-' in masvs_control and not masvs_control.startswith('MSTG-'):
        # M1-NET-1 -> MSTG-NET-1 (rough mapping)
        parts = masvs_control.split('-')
        if len(parts) >= 3:
            category_map = {
                'ARCH': 'ARCH', 'CRYPTO': 'CRYPTO', 'AUTH': 'AUTH',
                'NET': 'NET', 'PLATFORM': 'PLATFORM', 'RESILIENCE': 'RESILIENCE',
                'STORAGE': 'STORAGE', 'BINARY': 'BINARY'
            }
            cat = parts[1].upper()
            ctrl = parts[2]
            if cat in category_map:
                return f"MSTG-{cat}-{ctrl}"

    return None


def map_finding_to_controls(finding: dict) -> list[str]:
    """Map a finding to relevant MASVS controls based on CWE and metadata."""
    masvs_control = finding.get('masvs_control', '')
    cwe_id = finding.get('cwe_id', '')
    framework = finding.get('framework', '')

    controls = []

    # Direct mapping if provided
    if masvs_control:
        ctrl_id = extract_control_id(masvs_control)
        if ctrl_id:
            controls.append(ctrl_id)

    # CWE-based control inference
    if cwe_id:
        cwe_to_masvs = {
            'CWE-798': ['MSTG-CRYPTO-1', 'MSTG-AUTH-1'],
            'CWE-200': ['MSTG-STORAGE-1', 'MSTG-NET-3'],
            'CWE-295': ['MSTG-NET-2'],
            'CWE-312': ['MSTG-STORAGE-1'],
            'CWE-89': ['MSTG-CRYPTO-1', 'MSTG-PLATFORM-1'],
            'CWE-90': ['MSTG-PLATFORM-1'],
            'CWE-346': ['MSTG-RESILIENCE-1'],
            'CWE-347': ['MSTG-CRYPTO-2'],
            'CWE-918': ['MSTG-NET-1', 'MSTG-PLATFORM-1'],
            'CWE-74': ['MSTG-PLATFORM-1'],
            'CWE-20': ['MSTG-PLATFORM-1'],
            'CWE-502': ['MSTG-PLATFORM-3'],
            'CWE-939': ['MSTG-PLATFORM-1'],
        }
        controls.extend(cwe_to_masvs.get(cwe_id, []))

    # React Native specific
    if framework == 'react-native':
        controls.extend(['MSTG-PLATFORM-1', 'MSTG-NET-1'])

    # Remove duplicates
    return list(set(controls))


def determine_status(finding: dict) -> str:
    """Determine the MASVS control status from finding properties."""
    severity = finding.get('severity', '').lower()
    confidence = finding.get('confidence', '').lower()

    if confidence == 'rejected':
        return 'not-applicable'

    if confidence == 'needs dynamic confirmation':
        return 'needs-dynamic-confirmation'

    if severity in ['critical', 'high', 'medium']:
        if confidence == 'confirmed':
            return 'covered-fail'
        elif confidence == 'likely':
            return 'covered-fail'  # Still a fail, just lower confidence
    elif severity in ['low', 'informational']:
        return 'covered-pass'

    return 'covered-fail'


def update_matrix_with_findings(matrix: dict, findings: list[dict]) -> dict:
    """Update MASVS matrix statuses based on findings."""

    # Build lookup of control -> status based on findings
    control_statuses: dict[str, dict] = {}

    for finding in findings:
        controls = map_finding_to_controls(finding)
        status = determine_status(finding)

        for ctrl_id in controls:
            # Only upgrade status (don't downgrade from covered-pass to not-tested)
            existing = control_statuses.get(ctrl_id, {})
            if existing.get('status') in ['covered-pass', 'covered-fail', 'needs-dynamic-confirmation']:
                continue
            control_statuses[ctrl_id] = {
                'status': status,
                'notes': finding.get('title', '')
            }

    # Update matrix with findings
    for category in matrix.get('categories', []):
        for control in category.get('controls', []):
            ctrl_id = control.get('id', '')
            if ctrl_id in control_statuses:
                control['status'] = control_statuses[ctrl_id]['status']
                if control_statuses[ctrl_id].get('notes'):
                    control['notes'] = control_statuses[ctrl_id]['notes']

    # Update total count
    total = sum(len(cat['controls']) for cat in matrix.get('categories', []))
    matrix['total_controls'] = total

    return matrix


def main():
    parser = argparse.ArgumentParser(
        description='Update MASVS coverage matrix based on findings'
    )
    parser.add_argument(
        '--findings', '-f',
        required=True,
        help='Path to findings JSON/JSONL file'
    )
    parser.add_argument(
        '--matrix', '-m',
        default='masvs-matrix.json',
        help='Path to MASVS matrix (default: masvs-matrix.json)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output path (default: overwrite matrix)'
    )

    args = parser.parse_args()

    findings_path = Path(args.findings)
    matrix_path = Path(args.matrix)
    output_path = Path(args.output) if args.output else matrix_path

    if not findings_path.exists():
        print(f"Error: Findings file not found: {findings_path}", file=sys.stderr)
        sys.exit(1)

    if not matrix_path.exists():
        print(f"Error: Matrix file not found: {matrix_path}", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(findings_path)
    matrix = load_masvs_matrix(matrix_path)

    updated_matrix = update_matrix_with_findings(matrix, findings)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(updated_matrix, f, indent=2, ensure_ascii=False)

    print(f"Updated {output_path} with {len(findings)} findings")


if __name__ == '__main__':
    main()