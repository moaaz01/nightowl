#!/usr/bin/env python3
"""Fail CI when a redistributed file is missing from THIRD-PARTY-NOTICES.md.

NightOwl ships files derived from other projects under their own licenses
(Apache-2.0 for the DragonJAR Android Pentesting Skill). Those licenses
require disclosure, so every file under nightowl_pkg/dragonjar_data/ must
appear in the provenance table — otherwise a new import would silently bypass
the notice, which is exactly the gap this check exists to close.

Exit codes: 0 = every shipped file documented, 1 = undocumented or stale row,
2 = required file missing (misconfigured checkout).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHIPPED_DIR = REPO / "nightowl_pkg" / "dragonjar_data"
NOTICES = REPO / "THIRD-PARTY-NOTICES.md"

# First table cell wrapped in backticks: | `some/file.sh` | ... |
TABLE_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|")


def documented_paths(notices_text: str) -> set[str]:
    """First-column entries of the provenance table."""
    found: set[str] = set()
    for line in notices_text.splitlines():
        match = TABLE_ROW.match(line.strip())
        if match:
            found.add(match.group(1).strip())
    return found


def shipped_paths() -> set[str]:
    return {
        str(path.relative_to(SHIPPED_DIR))
        for path in SHIPPED_DIR.rglob("*")
        if path.is_file()
    }


def main() -> int:
    if not NOTICES.is_file():
        print(f"ERROR: {NOTICES} not found", file=sys.stderr)
        return 2
    if not SHIPPED_DIR.is_dir():
        print(f"ERROR: {SHIPPED_DIR} not found", file=sys.stderr)
        return 2

    documented = documented_paths(NOTICES.read_text(encoding="utf-8"))
    shipped = shipped_paths()

    undocumented = sorted(shipped - documented)
    stale = sorted(documented - shipped)

    for rel in undocumented:
        print(f"UNDOCUMENTED: nightowl_pkg/dragonjar_data/{rel} "
              f"— add it to the provenance table in THIRD-PARTY-NOTICES.md")
    for rel in stale:
        print(f"STALE ROW: THIRD-PARTY-NOTICES.md lists '{rel}' but it is not shipped")

    if undocumented or stale:
        print(f"\n{len(undocumented)} undocumented, {len(stale)} stale row(s)",
              file=sys.stderr)
        return 1

    print(f"OK: all {len(shipped)} redistributed files are disclosed "
          f"in THIRD-PARTY-NOTICES.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
