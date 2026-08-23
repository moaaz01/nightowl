# report.py -- NightOwl v8 Report Engine
#
# Replaces the legacy 6-section HTML/MD reports with a comprehensive,
# single-file, interactive report covering EVERY layer NightOwl produces:
#
#   executive summary - validated secrets (+ filtered audit) - authmap -
#   subscription enforcement - deepscan layers - hardening/packers -
#   privacy/trackers - SCA/SBOM - permissions - endpoints - architecture
#
# UX goals:
#   dark/light themes, severity filter chips, live search, click-to-reveal
#   secret values, confidence bars, sticky nav, print-friendly CSS.
#   Zero external assets: safe to email/archive.

import html as _html
import base64
import json


def esc(s):
    return _html.escape(str(s if s is not None else ""))


SEV_COLOR = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
    "LOW": "#3b82f6", "INFO": "#64748b",
}
GRADE_COLOR = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316"}


def grade_color(g):
    if not g:
        return "#64748b"
    return GRADE_COLOR.get(str(g)[0], "#ef4444")


def mask_value(val, keep=8):
    val = str(val or "")
    if len(val) <= keep + 4:
        return val
    return val[:keep] + "…" + val[-4:]


def sev_badge(sev):
    c = SEV_COLOR.get(sev, "#64748b")
    return (f'<span class="badge" style="background:{c}1a;color:{c};'
            f'border:1px solid {c}55">{esc(sev)}</span>')


def conf_bar(conf):
    try:
        pct = max(0, min(100, float(conf)))
    except (TypeError, ValueError):
        return ""
    color = "#22c55e" if pct >= 75 else "#eab308" if pct >= 55 else "#f97316"
    return (f'<div class="confbar" title="confidence {pct:.0f}%">'
            f'<div style="width:{pct:.0f}%;background:{color}"></div></div>')

# ─────────────────────────────────────────────────────────────────────────────
# Section renderers (each returns HTML or "" when module absent)
# ─────────────────────────────────────────────────────────────────────────────

def _table(headers, rows, cls="tbl"):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
        for row in rows) or '<tr><td colspan="99" class="muted">none</td></tr>'
    return f'<table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def _findings_table(findings, with_detail=True):
    rows = []
    for f in findings:
        detail = ""
        if with_detail:
            bits = [f.get("detail")] if f.get("detail") else []
            if f.get("evidence"):
                ev = f["evidence"]
                ev = ev if isinstance(ev, list) else [ev]
                bits.append("<code>" + esc("; ".join(str(x) for x in ev[:4]))
                            + "</code>")
            if f.get("masvs"):
                bits.append(f'<span class="masvs">{esc(f["masvs"])}</span>')
            note = f.get("note") or f.get("rec") or f.get("why")
            if note and note not in bits:
                bits.append(esc(note))
            detail = f'<div class="sub">{"".join(bits)}</div>'
        rows.append([sev_badge(f.get("severity", "INFO")),
                     esc(f.get("title", "")), detail])
    return _table(["Severity", "Finding", "Detail"], rows)


def _sec_secrets(d):
    secrets = d.get("secrets") or []
    stats = d.get("secrets_stats") or {}
    filtered = d.get("secrets_filtered") or []
    rows = []
    for i, s in enumerate(secrets):
        val = s.get("value", "")
        masked = esc(mask_value(val))
        # Defensive invariant: the value originates from untrusted APK
        # content. base64 is attribute-safe today, but we escape anyway so a
        # future encoding change can never become a stored-XSS vector.
        val_b64 = _html.escape(
            base64.b64encode(str(val).encode()).decode(), quote=True)
        reveal = (f'<button class="reveal" data-i="{i}">reveal</button>'
                  f'<span class="val" id="v{i}" hidden '
                  f'data-b64="{val_b64}"></span>')
        reasons = "; ".join(s.get("validation", [])[:4])
        rows.append([
            sev_badge(s.get("risk")),
            esc(s.get("type")),
            f'{reveal}',
            conf_bar(s.get("confidence")) +
            f'<span class="muted">{esc(s.get("verdict", ""))} '
            f'{s.get("confidence", "")}%</span>',
            f'<div class="sub">{esc(reasons)}</div>',
        ])
    tbl = _table(["Risk", "Type", "Value", "Confidence", "Why"], rows)

    filt_rows = [[sev_badge(f.get("raw_risk") or f.get("risk")), esc(f["type"]),
                  esc(mask_value(f.get("value", ""))),
                  f'<div class="sub">{esc("; ".join(f.get("validation", [])[:3]))}</div>']
                 for f in filtered]
    filt_tbl = _table(["Raw risk", "Type", "Value", "Rejected because"],
                      filt_rows) if filt_rows else ""

    stat_chips = " ".join(
        f'<span class="chip">{esc(k)}: <b>{v}</b></span>'
        for k, v in stats.items())
    return f"""
    <div class="chips">{stat_chips}</div>
    {tbl}
    {'<h4>Filtered candidates (audit trail)</h4>' + filt_tbl if filt_tbl else ''}
    """


def _sec_authmap(am):
    flows = am.get("flows") or []
    rows = []
    for f in flows:
        params = ", ".join(f.get("credential_params") or [])
        grants = ", ".join(f.get("grant_types") or [])
        tr = f.get("transport", "?")
        tcol = "#ef4444" if tr == "http" else ("#22c55e" if tr == "https" else "#64748b")
        rows.append([
            f'<span class="flowtype">{esc(f.get("type"))}</span>',
            esc(f.get("http_method") or "-"),
            f"<code>{esc(f.get('endpoint'))}</code>",
            f'<span style="color:{tcol}">{tr}</span>',
            esc(params), esc(grants),
        ])
    fl = _table(["Kind", "Method", "Endpoint", "Transport", "Credential params",
                 "Grants"], rows) if flows else ""

    lc = am.get("token_lifecycle") or {}
    lc_html = "".join(f'<li>{esc(x)}</li>' for x in lc.get("storage", []))
    att = "".join(f'<li>{esc(x)}</li>' for x in lc.get("request_attachment", []))
    wk = _findings_table(am.get("weaknesses") or []) \
        if am.get("weaknesses") else '<p class="muted">No auth weaknesses detected.</p>'
    pinning = am.get("certificate_pinning")
    return f"""
    {fl}
    <div class="cols">
      <div><h4>Token storage</h4><ul>{lc_html or '<li class="muted">unknown</li>'}</ul></div>
      <div><h4>Request attachment</h4><ul>{att or '<li class="muted">unknown</li>'}</ul></div>
      <div><h4>Pinning / JWT</h4>
        <p>Cert pinning: <b>{"yes" if pinning else "not detected"}</b><br/>
           JWT handling: <b>{"yes" if lc.get("jwt_handling_detected") else "no"}</b></p>
      </div>
    </div>
    <h4>Weaknesses</h4>{wk}
    """


def _sec_billing(b):
    model_colors = {"local-only": "#ef4444", "server-backed": "#22c55e",
                    "sdk-managed": "#eab308"}
    mc = model_colors.get(b.get("enforcement_model"), "#64748b")
    card = (f'<div class="modelcard" style="border-color:{mc}">'
            f'<span style="color:{mc}">{esc(b.get("enforcement_model", "unknown"))}'
            f"</span><br/><small>Sdk: "
            f"{esc(', '.join(b.get('billing_sdks') or []) or '-')}"
            f"</small></div>")
    script = b.get("verification_script")
    return f"""
    {card}
    {_findings_table(b.get("findings") or [])}
    {f'<p class="muted">Frida verification script: <code>{esc(script)}</code></p>' if script else ''}
    """


def _sec_hardening(h):
    packers = h.get("packers_protectors") or {}
    rows = [[esc(name), esc(info.get("category")),
             "<code>" + esc(", ".join(info.get("evidence", [])[:3])) + "</code>"]
            for name, info in sorted(packers.items())]
    pt = _table(["Name", "Category", "Evidence"], rows) if rows else \
        '<p class="muted">No packers/protectors detected.</p>'
    anti = "".join(f'<span class="chip">{esc(k)}</span>'
                   for k in (h.get("anti_analysis") or {})) or \
        '<span class="muted">none detected</span>'
    obf = ", ".join(h.get("obfuscation") or []) or "-"
    return f"{pt}<p><b>Anti-analysis:</b> {anti}<br/><b>Obfuscation:</b> {esc(obf)}</p>"


def _sec_privacy(p):
    trs = sorted((p.get("trackers") or {}).keys())
    grid = "".join(f'<span class="chip">{esc(t)}</span>' for t in trs) or \
        '<span class="muted">no known trackers detected</span>'
    rows = [[esc(r["permission"]), esc(r["exposes"]), esc(r["category"]),
             sev_badge(r.get("risk") or "INFO")]
            for r in p.get("data_collection_permissions") or []]
    perm_t = _table(["Permission", "Exposes", "Category", "Risk"], rows) if rows else ""
    return (f'<div class="chips">{grid}</div>'
            f'<p><b>Ad SDKs:</b> {p.get("ad_sdk_count", 0)} · '
            f'<b>Analytics/crash:</b> {p.get("analytics_count", 0)}</p>'
            f'<h4>Data-collection permissions</h4>{perm_t}')


def _sec_sca(sc):
    vuln_rows = [
        [sev_badge(f.get("severity")), esc(f.get("component")),
         esc(f.get("version") or "?"), esc(f.get("advisory")),
         f'<div class="sub">{esc(f.get("detail"))}</div>']
        for f in sc.get("vulnerable") or []]
    vt = _table(["Severity", "Component", "Version", "Advisory", "Detail"],
                vuln_rows) if vuln_rows else \
        '<p class="muted">No vulnerable components matched.</p>'
    comps = " ".join(f'<span class="chip">{esc(c)}</span>'
                     for c in sc.get("components_found") or [])
    sbom_json = json.dumps(sc.get("sbom") or {}, indent=2)
    sbom_b64 = base64.b64encode(sbom_json.encode()).decode()
    return f"""
    <p><b>Inventory ({len(sc.get('components_found') or [])}):</b> {comps}</p>
    <p><b>Versions extracted:</b> <code>{esc(sc.get('versions_detected') or '-')}</code></p>
    {vt}
    <a class="btn" download="sbom.json"
       href="data:application/json;base64,{sbom_b64}">Download SBOM (CycloneDX)</a>
    """

# ─────────────────────────────────────────────────────────────────────────────
# Full HTML document
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
:root{--bg:#0b1020;--card:#121933;--tx:#e5eaf5;--mut:#8a93ad;--line:#232c4d;
      --acc:#7aa2ff}
body.light{--bg:#f6f7fb;--card:#ffffff;--tx:#1a2340;--mut:#5b6478;--line:#e3e7f2}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
     font:14px/1.55 -apple-system,'Segoe UI',Roboto,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:24px 20px 80px}
header.hero{display:flex;gap:18px;align-items:center;flex-wrap:wrap;
            background:var(--card);border:1px solid var(--line);
            border-radius:16px;padding:22px;margin-bottom:14px}
.grade{font-size:44px;font-weight:800;line-height:1;padding:14px 18px;
       border-radius:14px;border:2px solid}
.scorebar{flex:1;min-width:220px}
.scorebar .track{height:10px;background:var(--line);border-radius:99px;
                 overflow:hidden;margin-top:6px}
.scorebar .fill{height:100%;border-radius:99px}
h1{font-size:20px;margin:0 0 2px} small{color:var(--mut)}
nav.top{position:sticky;top:0;z-index:5;background:var(--bg);padding:8px 0;
        border-bottom:1px solid var(--line);display:flex;gap:4px;
        flex-wrap:wrap;margin-bottom:16px}
nav.top a{color:var(--acc);text-decoration:none;font-size:12.5px;
          padding:4px 9px;border-radius:8px}
nav.top a:hover{background:var(--card)}
section.card{background:var(--card);border:1px solid var(--line);
             border-radius:16px;padding:20px;margin-bottom:16px}
h2{font-size:16px;margin:0 0 12px;display:flex;align-items:center;gap:8px}
h3,h4{font-size:13.5px;margin:16px 0 8px;color:var(--mut);text-transform:
      uppercase;letter-spacing:.04em}
table.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;color:var(--mut);font-weight:600;font-size:11.5px;
        text-transform:uppercase;letter-spacing:.05em;
        padding:8px 10px;border-bottom:1px solid var(--line)}
.tbl td{padding:9px 10px;border-bottom:1px solid var(--line);
        vertical-align:top}
.badge{font-size:10.5px;font-weight:700;padding:3px 8px;border-radius:99px;
       letter-spacing:.03em}
.chip{display:inline-block;background:var(--line);color:var(--tx);
      border-radius:99px;padding:3px 10px;margin:2px;font-size:12px}
.chips{line-height:2}
code{background:var(--line);padding:1px 6px;border-radius:6px;
     font-size:12px;word-break:break-all}
.sub{color:var(--mut);font-size:12px;margin-top:4px}
.muted{color:var(--mut)}
.cols{display:flex;gap:26px;flex-wrap:wrap}.cols>div{min-width:200px}
.modelcard{display:inline-block;border-width:2px;border-style:solid;
           border-radius:12px;padding:12px 18px;font-weight:700;font-size:17px}
.flowtype{font-weight:700}
.confbar{width:90px;height:6px;background:var(--line);border-radius:99px;
         display:inline-block;margin-right:8px;vertical-align:middle}
.confbar>div{height:100%;border-radius:99px}
button.reveal{background:var(--line);border:none;color:var(--acc);
              border-radius:7px;padding:2px 9px;cursor:pointer;font-size:12px}
.masvs{background:#7aa2ff22;color:#7aa2ff;border-radius:6px;
       padding:1px 7px;font-size:11px;margin-left:6px}
.controls{display:flex;gap:10px;align-items:center;margin-bottom:12px;
          flex-wrap:wrap}
input.search{background:var(--bg);border:1px solid var(--line);
             color:var(--tx);border-radius:9px;padding:7px 12px;width:230px}
.fchip{cursor:pointer;user-select:none}
.fchip.on{outline:2px solid var(--acc)}
.btn{background:var(--acc);color:#0b1020;text-decoration:none;font-weight:700;
     border-radius:9px;padding:8px 14px;display:inline-block}
footer{color:var(--mut);text-align:center;font-size:12px;margin-top:30px}
@media print{nav.top,.controls,button.reveal{display:none}
             body{background:#fff;color:#111}}
"""

_JS = """
function toggleTheme(){document.body.classList.toggle('light')}
function reveal(i){
  const v=document.getElementById('v'+i);
  if(v.hidden){v.textContent=atob(v.dataset.b64);v.hidden=false;}
  else{v.textContent='';v.hidden=true;}
}
function applyFilters(){
  const q=(document.getElementById('q')||{}).value?.toLowerCase()||'';
  const on=[...document.querySelectorAll('.fchip.on')]
             .map(x=>x.dataset.sev);
  const anySev=on.length>0;
  document.querySelectorAll('section[data-severity-scope] tr').forEach(tr=>{
    if(!tr.parentElement.closest('tbody'))return;
    const badge=tr.querySelector('.badge');
    const sev=badge?badge.textContent:'';
    const okS=!anySev||on.includes(sev);
    const okT=tr.textContent.toLowerCase().includes(q);
    tr.style.display=(okS&&okT)?'':'none';
  });
}
"""


def build_html(d):
    """Render the comprehensive single-file HTML report."""
    info = d.get("info") or {}
    sec = d.get("security") or {}
    score = sec.get("score", 0)
    grade = sec.get("grade", "?")
    secrets = d.get("secrets") or []
    vulns = d.get("vulns") or []

    sev_counts = {}
    for s in secrets:
        sev_counts[s.get("risk")] = sev_counts.get(s.get("risk"), 0) + 1
    for v in vulns:
        sev_counts[v.get("risk")] = sev_counts.get(v.get("risk"), 0) + 1
    for w in (d.get("authmap") or {}).get("weaknesses") or []:
        sev_counts[w.get("severity")] = sev_counts.get(w.get("severity"), 0) + 1

    stat_cards = "".join(
        f'<div class="stat"><small>{esc(k.title())}</small>'
        f'<b style="color:{SEV_COLOR.get(k, "#8a93ad")}">{n}</b></div>'
        for k, n in sorted(sev_counts.items(),
                           key=lambda kv: -{"CRITICAL": 0, "HIGH": 1,
                                            "MEDIUM": 2, "LOW": 3,
                                            "INFO": 4}.get(kv[0], 9)))

    sections = []

    # 1 Executive summary
    sections.append(("summary", "Executive Summary", "", f"""
      <p><b>{esc(info.get('package', '?'))}</b>
      {esc(info.get('version_name', ''))} · size {info.get('file_size_mb', '?')}MB
      · minSdk {info.get('min_sdk', '?')} / targetSdk {info.get('target_sdk', '?')}</p>
      <div class="cols">
        <div><h3>Posture</h3>
          <p>Score <b>{score}/100</b> (grade <b style="color:{grade_color(grade)}">{esc(grade)}</b>)
          <br/>Validated secrets: <b>{len(secrets)}</b> reported /
          {(d.get('secrets_stats') or {}).get('filtered', 0)} filtered
          <br/>Vulnerabilities: <b>{len(vulns)}</b></p></div>
        <div><h3>Severity mix</h3><div class="chips">{stat_cards}</div></div>
        <div><h3>Modules run</h3><div class="chips">{
          ''.join(f'<span class="chip">{m}</span>' for m in (
            'core' if info else '', 'secrets' if secrets is not None else '',
            'authmap' if d.get('authmap') else '',
            'billing' if d.get('billing') else '',
            'deepscan' if d.get('deepscan') else '',
            'hardening' if d.get('hardening') else '',
            'privacy' if d.get('privacy') else '',
            'sca' if d.get('sca') else '') ) if True else ''}
        </div></div>
      </div>"""))

    # 2 Secrets
    sections.append(("secrets", "Secrets (validated)", "data-severity-scope",
                     _sec_secrets(d)))
    # 3 Vulnerabilities
    vrows = [[esc(v.get("id")), sev_badge(v.get("risk")), esc(v.get("title")),
              esc(v.get("desc")),
              f'<div class="sub">{esc(v.get("rec"))}</div>',
              esc(v.get("cat"))] for v in vulns]
    sections.append(("vulns", "Vulnerabilities", "data-severity-scope",
                     _table(["ID", "Risk", "Title", "Description", "Fix",
                             "Category"], vrows)))
    # 4 AuthMap
    if d.get("authmap"):
        sections.append(("authmap", "Authentication Map", "data-severity-scope",
                         _sec_authmap(d["authmap"])))
    # 5 Billing
    if d.get("billing"):
        sections.append(("billing", "Subscription Enforcement", "",
                         _sec_billing(d["billing"])))
    # 6 Deepscan
    if d.get("deepscan"):
        sections.append(("deepscan", "Deep Static Layers", "data-severity-scope",
                         _findings_table(d["deepscan"].get("findings") or [])))
    # 7 Hardening
    if d.get("hardening"):
        sections.append(("hardening", "Hardening & Packers", "",
                         _sec_hardening(d["hardening"])))
    # 8 Privacy
    if d.get("privacy"):
        sections.append(("privacy", "Privacy & Trackers", "",
                         _sec_privacy(d["privacy"])))
    # 9 SCA
    if d.get("sca"):
        sections.append(("sca", "Supply Chain (SCA)", "data-severity-scope",
                         _sec_sca(d["sca"])))
    # 10 Permissions
    pm = d.get("perms") or {}
    prows = [[sev_badge(p.get("risk")), esc(p.get("name")),
              esc(p.get("desc_en") or "")] for p in pm.get("dangerous") or []]
    sections.append(("perms", "Permissions", "data-severity-scope",
                     _table(["Risk", "Permission", "Meaning"], prows)))
    # 11 Endpoints
    ep = d.get("endpoints") or {}
    servers = "".join(f'<span class="chip"><code>{esc(s)}</code></span>'
                      for s in ep.get("servers") or []) or '<span class="muted">-</span>'
    urls = "<br/>".join(f"<code>{esc(u)}</code>" for u in ep.get("urls")[:60])
    sections.append(("endpoints", "Endpoints", "", f"""
       <p><b>Servers ({len(ep.get('servers') or [])})</b>: {servers}</p>
       <p class="muted">URLs ({len(ep.get('urls') or [])}) — first 60 shown</p>
       {urls}"""))
    # 12 Architecture
    ar = d.get("arch") or {}
    sections.append(("arch", "Architecture", "", f"""
      <p><b>Frameworks:</b> {esc(', '.join(ar.get('frameworks') or []) or '-')}<br/>
      <b>Libraries:</b> {esc(', '.join(ar.get('libraries') or []) or '-')}<br/>
      <b>Native:</b> {esc(', '.join(ar.get('native') or []) or '-')}<br/>
      <b>Obfuscation:</b> {esc(', '.join(ar.get('obfuscation') or []) or '-')}</p>"""))

    nav = "".join(f'<a href="#{sid}">{esc(title)}</a>' for sid, title, _, _ in sections)

    body_sections = ""
    for sid, title, attrs, content in sections:
        body_sections += (f'<section class="card" id="{sid}" {attrs}>'
                          f"<h2>{esc(title)}</h2>{content}</section>")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>NightOwl Report — {esc(info.get('package', d.get('apk', '')))}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header class="hero">
  <div class="grade" style="color:{grade_color(grade)};border-color:{grade_color(grade)}">{esc(grade)}</div>
  <div class="scorebar">
    <h1>🦉 NightOwl Security Report</h1>
    <small>{esc(info.get('package', ''))} {esc(info.get('version_name', ''))} · {esc(str(d.get('ts', '')))}</small>
    <div class="track"><div class="fill" style="width:{score}%;background:{grade_color(grade)}"></div></div>
    <small>score {score}/100 · sha256 {esc(info.get('sha256', '')[:32])}…</small>
  </div>
  <button class="reveal" onclick="toggleTheme()">theme</button>
</header>
<nav class="top">{nav}</nav>
<div class="controls">
  <input class="search" id="q" placeholder="search findings…"
         oninput="applyFilters()"/>
  {''.join(f'<span class="chip fchip" data-sev="{s}" onclick="this.classList.toggle(\'on\');applyFilters()" style="color:{SEV_COLOR[s]}">{s}</span>' for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))}
</div>
{body_sections}
<footer>Generated by NightOwl v8 · Authorized security testing only ·
Values are masked — handle full values from the JSON export responsibly.</footer>
<script>{_JS}</script>
</div></body></html>"""

# ─────────────────────────────────────────────────────────────────────────────
# Markdown report (comprehensive)
# ─────────────────────────────────────────────────────────────────────────────

def build_md(d):
    info = d.get("info") or {}
    sec = d.get("security") or {}
    ep = d.get("endpoints") or {}
    pm = d.get("perms") or {}
    ar = d.get("arch") or {}
    lines = []
    add = lines.append

    add(f"# NightOwl Security Report — {info.get('package', '?')}")
    add("")
    add(f"> Score **{sec.get('score')}/100** · grade "
        f"**{sec.get('grade')}** · {d.get('ts')} · "
        f"sha256 `{(info.get('sha256') or '')[:32]}…`")
    add("")
    add("| Property | Value |")
    add("|---|---|")
    add(f"| Version | {info.get('version_name', '?')} "
        f"(code {info.get('version_code', '?')}) |")
    add(f"| Size | {info.get('file_size_mb', '?')} MB |")
    add(f"| SDK | min {info.get('min_sdk', '?')} / target "
        f"{info.get('target_sdk', '?')} |")

    stats = d.get("secrets_stats") or {}
    if stats:
        add("")
        add("## Secrets (validated)")
        add(f"Candidates: {stats.get('raw_candidates', 0)} · reported: "
            f"{stats.get('reported', 0)} · filtered: {stats.get('filtered', 0)}")
        add("")
        add("| Risk | Verdict | Conf % | Type | Value (masked) | Why |")
        add("|---|---|---|---|---|---|")
        for s in d.get("secrets") or []:
            reasons = "; ".join(s.get("validation", [])[:3])
            add(f"| {s['risk']} | {s.get('verdict')} | {s.get('confidence')} "
                f"| {s['type']} | `{mask_value(s.get('value'))}` | {reasons} |")

    vulns = d.get("vulns") or []
    if vulns:
        add("")
        add("## Vulnerabilities")
        add("| ID | Risk | Title | Fix |")
        add("|---|---|---|---|")
        for v in vulns:
            add(f"| {v.get('id')} | {v.get('risk')} | {v.get('title')} "
                f"| {v.get('rec')} |")

    am = d.get("authmap")
    if am:
        add("")
        add("## Authentication Map")
        s = am.get("summary", {})
        add(f"Login: {s.get('login_endpoints', 0)} · token: "
            f"{s.get('token_endpoints', 0)} · MFA: {s.get('mfa_endpoints', 0)} "
            f"· pinning: {'yes' if am.get('certificate_pinning') else 'not detected'}")
        add("")
        add("| Kind | Method | Endpoint | Transport | Params |")
        add("|---|---|---|---|---|")
        for f in am.get("flows") or []:
            add(f"| {f.get('type')} | {f.get('http_method') or '-'} "
                f"| `{f.get('endpoint')}` | {f.get('transport')} "
                f"| {', '.join(f.get('credential_params') or []) or '-'} |")
        weaknesses = am.get("weaknesses") or []
        if weaknesses:
            add("")
            add("### Auth weaknesses")
            for w in weaknesses:
                add(f"- **[{w['severity']}]** {w['title']} ({w.get('masvs', '')})")

    b = d.get("billing")
    if b:
        add("")
        add("## Subscription Enforcement")
        add(f"Model: **{b.get('enforcement_model')}** · SDKs: "
            f"{', '.join(b.get('billing_sdks') or []) or '-'}")
        for f in b.get("findings") or []:
            add(f"- **[{f['severity']}]** {f['title']}")

    ds = d.get("deepscan")
    if ds and ds.get("findings"):
        add("")
        add("## Deep Static Layers")
        for f in ds["findings"]:
            add(f"- **[{f['severity']}]** ({f['category']}) {f['title']} "
                f"x{f.get('matches', '')}")

    h = d.get("hardening")
    if h:
        add("")
        add("## Hardening & Packers")
        for name, inf in sorted((h.get("packers_protectors") or {}).items()):
            add(f"- {name} ({inf['category']}): "
                f"`{', '.join(inf['evidence'][:3])}`")
        anti = ", ".join((h.get("anti_analysis") or {}).keys()) or "none"
        add(f"- Anti-analysis families: {anti}")

    p = d.get("privacy")
    if p:
        add("")
        add("## Privacy & Trackers")
        add(f"Trackers detected: {p.get('tracker_count', 0)} "
            f"(ads {p.get('ad_sdk_count', 0)} / analytics "
            f"{p.get('analytics_count', 0)})")
        for t in sorted((p.get("trackers") or {})):
            add(f"- {t}")

    sc = d.get("sca")
    if sc:
        add("")
        add("## Supply Chain (SCA)")
        for f in sc.get("vulnerable") or []:
            add(f"- **[{f['severity']}]** {f['title']}")
        add(f"- Components inventoried: "
            f"{len(sc.get('components_found') or [])}")

    dangerous = pm.get("dangerous") or []
    if dangerous:
        add("")
        add("## Permissions")
        add("| Risk | Permission | Meaning |")
        add("|---|---|---|")
        for perm in dangerous:
            add(f"| {perm.get('risk')} | `{perm.get('name')}` "
                f"| {perm.get('desc_en') or ''} |")

    servers = ep.get("servers") or []
    if servers:
        add("")
        add("## Endpoints")
        add("**Servers:** " + ", ".join(f"`{s}`" for s in servers))

    add("")
    add("---")
    add("*Generated by NightOwl v8 — authorized security testing only. "
        "Secret values masked; full values are in the JSON export.*")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Console summary card (for `nightowl start`)
# ─────────────────────────────────────────────────────────────────────────────

def render_console_summary(d):
    sec = d.get("security") or {}
    info = d.get("info") or {}
    stats = d.get("secrets_stats") or {}

    def line(ch, txt):
        print(f"  {ch} {txt}")

    print()
    print("┌─────────────────────────────────────────────────────────┐")
    print("│                 SCAN COMPLETE — SUMMARY                  │")
    print("└─────────────────────────────────────────────────────────┘")
    line("pkg", f"{info.get('package', '?')} {info.get('version_name', '')}")
    line("score", f"{sec.get('score', '?')}/100  grade {sec.get('grade', '?')}")
    line("secrets",
         f"{stats.get('reported', 0)} reported "
         f"({stats.get('confirmed', 0)} confirmed, {stats.get('filtered', 0)} "
         f"false positives auto-filtered)")
    line("vulns", f"{len(d.get('vulns') or [])} vulnerabilities")
    am = d.get("authmap") or {}
    if am:
        s = am.get("summary", {})
        line("auth", f"{s.get('login_endpoints', 0)} login / "
                     f"{s.get('token_endpoints', 0)} token endpoints · "
                     f"{len(am.get('weaknesses') or [])} weaknesses")
    b = d.get("billing")
    if b:
        line("billing", f"enforcement model: "
                        f"{b.get('enforcement_model')} · "
                        f"{len(b.get('findings') or [])} findings")
    ds = d.get("deepscan")
    if ds:
        line("deepscan", f"{len(ds.get('findings') or [])} advanced findings")
    h = d.get("hardening")
    if h:
        line("hardening", f"packed={h['summary']['packed']} "
                          f"obfuscated={h['summary']['obfuscated']}")
    p = d.get("privacy")
    if p:
        line("privacy", f"{p.get('tracker_count', 0)} trackers")
    sc = d.get("sca")
    if sc:
        line("sca", f"{len(sc.get('components_found') or [])} components · "
                    f"{len(sc.get('vulnerable') or [])} vulnerable")
    print()
    print("  Next steps:")
    print("   - full JSON export : nightowl full <apk> --json --save")
    print("   - HTML report      : included via --save (workspace/reports/)")
    print("   - dynamic testing  : nightowl lab devices && nightowl lab ssl <pkg>")
    print()

