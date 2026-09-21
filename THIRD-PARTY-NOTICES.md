# Third-Party Notices

NightOwl itself is distributed under the MIT License — see [LICENSE](LICENSE).
This distribution also redistributes files derived from other projects. Those
files remain under **their original licenses**. Apache License 2.0 §4 requires
that the copyright notice, the license text and a description of changes be
kept with the redistributed files; this file is that disclosure.

Bundled license text: [`licenses/Apache-2.0.txt`](licenses/Apache-2.0.txt) —
retrieved from <https://www.apache.org/licenses/LICENSE-2.0.txt> on
2026-09-21 (11,358 bytes · 202 lines · sha256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`).

---

## DragonJAR Android Pentesting Skill

| Field | Value |
|---|---|
| Upstream | <https://github.com/DragonJAR/Android-Pentesting-Skill> |
| Author / copyright | DragonJAR SAS |
| Upstream version at import | 1.7.0 |
| License | Apache License, Version 2.0 (declared in the upstream `SKILL.md` frontmatter: `license: Apache-2.0`) |
| Local directory | `nightowl_pkg/dragonjar_data/` |
| Nature of modification | Imported as NightOwl's static-audit, scoring and cross-platform layer, then adapted to NightOwl's JSON contract, CLI wiring and paths. |
| Verification method | Per-file SHA-256 comparison against the upstream `main` branch, 2026-09-21. |

**How to read the status column:** *unmodified* = byte-identical to upstream;
*adapted* = the local file differs from upstream (trimmed, reformatted or
extended for NightOwl). Of the 22 redistributed files, **6 are byte-identical
and 16 are adapted**.

### File-by-file provenance

| NightOwl path (`nightowl_pkg/dragonjar_data/…`) | Upstream path | Status |
|---|---|---|
| `auto-audit-static.sh` | `scripts/auto-audit-static.sh` | adapted (32,128 B vs 32,541 B) |
| `bypass-profiles.json` | `scripts/02-rasp/bypass-profiles.json` | adapted (6,555 B vs 6,537 B) |
| `calculate-score.py` | `scripts/05-scoring/calculate-score.py` | adapted (10,564 B vs 11,352 B) |
| `cordova-analysis.sh` | `scripts/01-cross-platform/cordova-analysis.sh` | adapted (27,948 B vs 27,962 B) |
| `detector-catalog.json` | `scripts/02-rasp/detector-catalog.json` | unmodified |
| `findings-schema.json` | `scripts/02-rasp/findings-schema.json` | unmodified |
| `flutter-analysis.sh` | `scripts/01-cross-platform/flutter-analysis.sh` | adapted (27,544 B vs 27,548 B) |
| `frida-exploit-helper.py` | `scripts/07-tools/frida-exploit-helper.py` | adapted (29,759 B vs 29,993 B) |
| `masvs-mapping.json` | `scripts/05-scoring/masvs-mapping.json` | unmodified |
| `masvs-matrix.json` | `scripts/05-scoring/masvs-matrix.json` | unmodified |
| `merge-findings.py` | `scripts/03-static-analysis/merge-findings.py` | adapted (7,281 B vs 7,622 B) |
| `preflight-check.py` | `scripts/06-setup/preflight-check.py` | adapted (37,169 B vs 39,167 B) |
| `preflight-check.sh` | `scripts/06-setup/preflight-check.sh` | adapted (same size, content differs) |
| `rasp-bypass-runner.sh` | `scripts/02-rasp/rasp-bypass-runner.sh` | unmodified |
| `react-native-analysis.sh` | `scripts/01-cross-platform/react-native-analysis.sh` | adapted (21,581 B vs 21,592 B) |
| `runtime-defense-analyzer.sh` | `scripts/02-rasp/runtime-defense-analyzer.sh` | adapted (10,316 B vs 10,549 B) |
| `semgrep-rules/.semgrepignore` | `scripts/03-static-analysis/semgrep-rules/.semgrepignore` | unmodified |
| `semgrep-rules/MASTG-rules.yaml` | `scripts/03-static-analysis/semgrep-rules/MASTG-rules.yaml` | adapted (33,912 B vs 32,006 B) |
| `semgrep-scan.py` | `scripts/03-static-analysis/semgrep-scan.py` | adapted (7,522 B vs 8,492 B) |
| `unity-analysis.sh` | `scripts/01-cross-platform/unity-analysis.sh` | adapted (30,233 B vs 30,230 B) |
| `update-coverage.py` | `scripts/05-scoring/update-coverage.py` | adapted (6,787 B vs 7,094 B) |
| `update-rules.sh` | `scripts/03-static-analysis/update-rules.sh` | adapted (4,566 B vs 4,843 B) |

The Apache License, Version 2.0 applies to the files listed above. Everything
in this repository not listed here is covered by the MIT License in
[LICENSE](LICENSE).

---

## Enforcing this document

`scripts/check_third_party.py` fails CI when a file exists under
`nightowl_pkg/dragonjar_data/` without an entry in the table above, so a new
import cannot silently bypass this disclosure. Run it locally with:

```bash
python scripts/check_third_party.py
```
