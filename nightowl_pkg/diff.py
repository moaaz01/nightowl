# diff.py -- NightOwl v8 Report Differ (build regression tracking)
#
# Compare two saved full-scan JSONs and answer:
#   - did the security posture improve or regress?
#   - which secrets/vulns/endpoints/auth weaknesses appeared or disappeared?
#   - did the subscription enforcement model change?
#
# Usage:
#   nightowl diff old.json new.json [--json]

import hashlib
import json


def mask_value(val, keep=6):
    if not val or len(val) <= keep + 4:
        return val
    return val[:keep] + "..." + val[-4:]


def _secret_key(s):
    raw = f"{s.get('type')}|{s.get('value')}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _title_set(items):
    return {i.get("title") for i in items or [] if i.get("title")}


def _added_resolved(old_items, new_items, key=None):
    ko = {key(i) for i in old_items} if key else _title_set(old_items)
    kn = {key(i) for i in new_items} if key else _title_set(new_items)
    return {"added": sorted(kn - ko), "resolved": sorted(ko - kn)}


def diff_reports(old, new):
    sec_o = old.get("security") or {}
    sec_n = new.get("security") or {}

    out = {
        "module": "report-diff",
        "old_apk": old.get("apk"),
        "new_apk": new.get("apk"),
        "score": {
            "old": sec_o.get("score"),
            "new": sec_n.get("score"),
        },
        "grade": {"old": sec_o.get("grade"), "new": sec_n.get("grade")},
    }
    try:
        out["score"]["delta"] = int(sec_n.get("score") or 0) - \
            int(sec_o.get("score") or 0)
    except (TypeError, ValueError):
        out["score"]["delta"] = None

    # Secrets by type+value hash
    so = {_secret_key(s): s for s in old.get("secrets") or []}
    sn = {_secret_key(s): s for s in new.get("secrets") or []}
    added_keys = set(sn) - set(so)
    removed_keys = set(so) - set(sn)
    out["secrets"] = {
        "added": [{"type": sn[k]["type"],
                   "masked": mask_value(sn[k].get("value", "")),
                   "risk": sn[k].get("risk"),
                   "confidence": sn[k].get("confidence")}
                  for k in sorted(added_keys)],
        "removed": [{"type": so[k]["type"],
                     "masked": mask_value(so[k].get("value", ""))}
                    for k in sorted(removed_keys)],
        "still_present": len(set(sn) & set(so)),
    }

    # Title-keyed collections
    out["vulns"] = _added_resolved(old.get("vulns"), new.get("vulns"))
    auth_w_old = (old.get("authmap") or {}).get("weaknesses")
    auth_w_new = (new.get("authmap") or {}).get("weaknesses")
    out["auth_weaknesses"] = _added_resolved(auth_w_old, auth_w_new)
    ds_old = (old.get("deepscan") or {}).get("findings")
    ds_new = (new.get("deepscan") or {}).get("findings")
    out["deepscan_findings"] = _added_resolved(ds_old, ds_new)

    # Servers / endpoints
    servers_old = set((old.get("endpoints") or {}).get("servers") or [])
    servers_new = set((new.get("endpoints") or {}).get("servers") or [])
    out["servers"] = {
        "added": sorted(servers_new - servers_old),
        "removed": sorted(servers_old - servers_new),
    }

    # Billing model change
    billing_old = (old.get("billing") or {}).get("enforcement_model")
    billing_new = (new.get("billing") or {}).get("enforcement_model")
    out["billing"] = {
        "old": billing_old,
        "new": billing_new,
        "changed": billing_old != billing_new,
    }

    delta = out["score"]["delta"]
    regressions = (len(out["secrets"]["added"]) +
                   len(out["vulns"]["added"]) +
                   len(out["auth_weaknesses"]["added"]))
    improvements = (len(out["secrets"]["removed"]) +
                    len(out["vulns"]["resolved"]) +
                    len(out["auth_weaknesses"]["resolved"]))
    if delta is not None and delta > 0 and regressions == 0:
        verdict = "IMPROVED"
    elif regressions > improvements:
        verdict = "REGRESSED"
    elif delta is not None and delta < 0:
        verdict = "SCORE_DROP"
    elif regressions == 0 and improvements > 0:
        verdict = "IMPROVED"
    else:
        verdict = "MIXED"
    out["verdict"] = verdict

    return out


def cmd_diff(old_path, new_path, json_out=False):
    """CLI handler: nightowl diff <old.json> <new.json>"""
    try:
        old = json.loads(Path_read(old_path))
    except Exception as e:
        print(f"Cannot read old report: {e}")
        return 2
    try:
        new = json.loads(Path_read(new_path))
    except Exception as e:
        print(f"Cannot read new report: {e}")
        return 2

    result = diff_reports(old, new)

    if json_out:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    print("\n=== Report Diff ===")
    print(f"Old : {result['old_apk']}")
    print(f"New : {result['new_apk']}")
    print(f"Score: {result['score']['old']} -> {result['score']['new']} "
          f"(delta {result['score']['delta']}) | "
          f"Grade: {result['grade']['old']} -> {result['grade']['new']}")
    print(f"Verdict: {result['verdict']}")
    if result["secrets"]["added"]:
        print("Secrets ADDED:")
        for s in result["secrets"]["added"]:
            print(f"  + [{s['risk']}] {s['type']}: {s['masked']} "
                  f"(conf {s['confidence']})")
    if result["secrets"]["removed"]:
        print("Secrets REMOVED:")
        for s in result["secrets"]["removed"]:
            print(f"  - {s['type']}: {s['masked']}")
    for label in ("vulns", "auth_weaknesses", "deepscan_findings"):
        d = result[label]
        if d["added"]:
            print(f"{label} ADDED:")
            for t in d["added"]:
                print(f"  + {t}")
        if d["resolved"]:
            print(f"{label} RESOLVED:")
            for t in d["resolved"]:
                print(f"  - {t}")
    if result["billing"]["changed"]:
        print(f"Billing model changed: "
              f"{result['billing']['old']} -> {result['billing']['new']}")
    return 0


def Path_read(path):
    from pathlib import Path
    return Path(path).read_text()

