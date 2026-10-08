"""k1rby modern HTML report — a dashboard, not a spreadsheet.

Self-contained HTML (inline CSS, no external calls): posture score, severity donut, findings
ranked by severity with affected objects + remediation + MITRE, and the full inventory in
collapsible tables. Dark by default, print/PDF friendly.
"""

from __future__ import annotations

import datetime
import html

from .findings import Finding, posture_score, severity_counts

_SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
              "low": "#8e8e8e", "info": "#4f8cf7"}


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _donut(counts: dict) -> str:
    total = sum(counts.values()) or 1
    stops, acc = [], 0.0
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if not n:
            continue
        start = acc / total * 360
        acc += n
        stops.append(f"{_SEV_COLOR[sev]} {start:.1f}deg {acc / total * 360:.1f}deg")
    grad = ", ".join(stops) or "#2a2f3a 0 360deg"
    return (f"<div class='donut' style='background:conic-gradient({grad})'>"
            f"<div class='donut-hole'><span>{sum(counts.values())}</span><small>findings</small></div></div>")


def _score_class(score: int) -> str:
    return "crit" if score < 40 else "high" if score < 60 else "med" if score < 80 else "good"


def _affected_preview(f: Finding, limit: int = 12) -> str:
    rows = f.affected[:limit]
    keys = list(rows[0].keys()) if rows and isinstance(rows[0], dict) else []
    if not keys:
        items = "".join(f"<li>{_esc(x)}</li>" for x in rows)
        extra = f"<li class='more'>+{f.count - limit} more</li>" if f.count > limit else ""
        return f"<ul class='affected'>{items}{extra}</ul>"
    head = "".join(f"<th>{_esc(k)}</th>" for k in keys)
    body = "".join("<tr>" + "".join(f"<td>{_esc(r.get(k))}</td>" for k in keys) + "</tr>" for r in rows)
    extra = (f"<tr class='more'><td colspan='{len(keys)}'>+{f.count - limit} more "
             f"(see xlsx)</td></tr>") if f.count > limit else ""
    return f"<table class='affected-tbl'><thead><tr>{head}</tr></thead><tbody>{body}{extra}</tbody></table>"


def _finding_card(f: Finding) -> str:
    return f"""
    <div class="card sev-{f.severity}">
      <div class="card-top">
        <span class="sev-tag" style="background:{_SEV_COLOR[f.severity]}">{f.severity.upper()}</span>
        <h3>{_esc(f.title)}</h3>
        <span class="cnt">{f.count} affected</span>
      </div>
      <div class="meta"><span>{_esc(f.id)}</span><span>{_esc(f.category)}</span>
        <span>MITRE {_esc(f.mitre)}</span></div>
      <p class="desc">{_esc(f.description)}</p>
      {_affected_preview(f)}
      <div class="rem"><b>Remediation.</b> {_esc(f.remediation)}</div>
    </div>"""


def _inventory(sections: dict) -> str:
    blocks = []
    for name, rows in sections.items():
        if not rows:
            continue
        keys = [k for k in rows[0].keys() if not str(k).startswith("_")][:10]
        head = "".join(f"<th>{_esc(k)}</th>" for k in keys)
        body = "".join("<tr>" + "".join(f"<td>{_esc(r.get(k))}</td>" for k in keys) + "</tr>"
                       for r in rows[:300])
        more = f"<p class='more'>showing 300 of {len(rows)} — full data in the xlsx</p>" if len(rows) > 300 else ""
        blocks.append(f"<details><summary>{_esc(name)} <span>({len(rows)})</span></summary>"
                      f"<table class='inv'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}</details>")
    return "".join(blocks)


def build(domain: str, findings: list[Finding], sections: dict,
          external: dict | None = None) -> str:
    score = posture_score(findings)
    counts = severity_counts(findings)
    sc = _score_class(score)
    ext = ""
    if external:
        ext = "<div class='ext'>" + " · ".join(
            f"<span>{_esc(k)}: {_esc(v)}</span>" for k, v in external.items()) + "</div>"
    cards = "".join(_finding_card(f) for f in findings) or "<p class='none'>No findings fired.</p>"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    totobj = sum(len(v) for v in sections.values())
    chips = "".join(
        f"<span class='chip' style='border-color:{_SEV_COLOR[s]}'>"
        f"<b style='color:{_SEV_COLOR[s]}'>{counts[s]}</b> {s}</span>"
        for s in ("critical", "high", "medium", "low", "info"))

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>k1rby — {_esc(domain)}</title><style>
:root{{--bg:#0f1218;--panel:#161b24;--line:#232a36;--ink:#e8ecf3;--ink2:#9aa5b5;--accent:#4f8cf7}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}
header{{display:flex;align-items:baseline;gap:14px;border-bottom:1px solid var(--line);padding-bottom:14px}}
header h1{{margin:0;font-size:22px;letter-spacing:.5px}}header .dom{{color:var(--accent);font-weight:700}}
header .ts{{margin-left:auto;color:var(--ink2);font-size:12px}}
.dash{{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center;
background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;margin:22px 0}}
.score{{text-align:center}}.score .num{{font-size:54px;font-weight:800;line-height:1}}
.score.good .num{{color:#30a46c}}.score.med .num{{color:#ffb224}}.score.high .num{{color:#f76808}}.score.crit .num{{color:#e5484d}}
.score small{{color:var(--ink2);text-transform:uppercase;letter-spacing:.1em;font-size:11px}}
.dash-right{{display:flex;align-items:center;gap:26px;flex-wrap:wrap}}
.donut{{width:104px;height:104px;border-radius:50%;display:grid;place-items:center;position:relative}}
.donut-hole{{width:70px;height:70px;border-radius:50%;background:var(--panel);display:grid;place-items:center;text-align:center}}
.donut-hole span{{font-size:22px;font-weight:800}}.donut-hole small{{color:var(--ink2);font-size:10px}}
.chips{{display:flex;gap:10px;flex-wrap:wrap}}
.chip{{border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:12px;color:var(--ink2)}}
.chip b{{font-size:14px;margin-right:4px}}
.stat{{color:var(--ink2);font-size:12px}}.ext{{margin-top:10px;color:var(--ink2);font-size:11px}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink2);margin:30px 0 12px}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--line);
border-radius:12px;padding:16px 18px;margin:12px 0}}
.card.sev-critical{{border-left-color:#e5484d}}.card.sev-high{{border-left-color:#f76808}}
.card.sev-medium{{border-left-color:#ffb224}}.card.sev-low{{border-left-color:#8e8e8e}}.card.sev-info{{border-left-color:#4f8cf7}}
.card-top{{display:flex;align-items:center;gap:12px}}.card-top h3{{margin:0;font-size:16px;flex:1}}
.sev-tag{{color:#0f1218;font-weight:800;font-size:10.5px;padding:3px 9px;border-radius:5px}}
.cnt{{color:var(--ink2);font-size:12px;white-space:nowrap}}
.meta{{display:flex;gap:14px;color:var(--ink2);font-size:11.5px;margin:8px 0}}
.desc{{color:#c6cddb;margin:6px 0 12px}}
.affected,.affected-tbl{{margin:8px 0;font-size:12.5px}}.affected{{padding-left:18px;color:var(--ink2)}}
.affected-tbl{{width:100%;border-collapse:collapse}}
.affected-tbl th,.affected-tbl td{{border:1px solid var(--line);padding:5px 8px;text-align:left}}
.affected-tbl th{{background:#1b212c;color:var(--ink2);font-weight:600}}
.more{{color:var(--ink2);font-style:italic}}
.rem{{background:#12161e;border:1px solid var(--line);border-radius:8px;padding:10px 13px;margin-top:10px;font-size:13px;color:#c6cddb}}
details{{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:4px 14px}}
summary{{cursor:pointer;padding:8px 0;font-weight:600}}summary span{{color:var(--ink2);font-weight:400}}
table.inv{{width:100%;border-collapse:collapse;font-size:12px;margin:6px 0 12px}}
table.inv th,table.inv td{{border:1px solid var(--line);padding:4px 7px;text-align:left}}
table.inv th{{background:#1b212c;color:var(--ink2)}}
.none{{color:#30a46c}}
@media print{{body{{background:#fff;color:#111}}.card,.dash,details{{break-inside:avoid}}}}
</style></head><body><div class="wrap">
<header><h1>k1rby</h1><span class="dom">{_esc(domain)}</span>
<span class="stat">· {totobj} objects · {len(findings)} findings</span>
<span class="ts">{now}</span></header>
<div class="dash">
  <div class="score {sc}"><div class="num">{score}</div><small>posture / 100</small></div>
  <div class="dash-right">{_donut(counts)}<div class="chips">{chips}</div></div>
</div>{ext}
<h2>Findings</h2>{cards}
<h2>Inventory</h2>{_inventory(sections)}
</div></body></html>"""
