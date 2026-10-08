"""k1rby xlsx report — turns the collected sections into a clean, multi-sheet workbook
(ADRecon-style), with a Summary tab and light highlighting of the risky rows."""

from __future__ import annotations

from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_HEAD = Font(bold=True, color="FFFFFF")
_HEAD_FILL = PatternFill("solid", fgColor="2F3B52")
_RISK_FILL = PatternFill("solid", fgColor="FBE4D5")   # soft amber for risky rows
_TITLE = Font(bold=True, size=14)


def _autosize(ws, rows: list[dict]) -> None:
    if not rows:
        return
    cols = list(rows[0].keys())
    for i, c in enumerate(cols, 1):
        width = max([len(str(c))] + [len(str(r.get(c, ""))) for r in rows[:200]])
        ws.column_dimensions[get_column_letter(i)].width = min(max(width + 2, 10), 70)


def _sheet(wb: Workbook, name: str, rows: list[dict], risk_when=None) -> int:
    ws = wb.create_sheet(name[:31])
    if not rows:
        ws["A1"] = "(no results)"
        return 0
    cols = [c for c in rows[0].keys() if not c.startswith("_")]
    for i, c in enumerate(cols, 1):
        cell = ws.cell(1, i, c)
        cell.font = _HEAD
        cell.fill = _HEAD_FILL
    for ri, r in enumerate(rows, 2):
        risky = bool(risk_when(r)) if risk_when else False
        for ci, c in enumerate(cols, 1):
            cell = ws.cell(ri, ci, _fmt(r.get(c)))
            if risky:
                cell.fill = _RISK_FILL
    ws.freeze_panes = "A2"
    _autosize(ws, [{c: r.get(c) for c in cols} for r in rows])
    return len(rows)


def _fmt(v: Any) -> Any:
    if isinstance(v, bool):
        return "YES" if v else "no"
    if isinstance(v, (list, tuple)):
        return "; ".join(str(x) for x in v)
    return "" if v is None else v


def build(path: str, domain: str, sections: dict[str, list[dict]],
          external: dict[str, str] | None = None) -> dict[str, int]:
    """sections: {sheet_name: rows}. Returns per-sheet counts (also used for the Summary)."""
    wb = Workbook()
    wb.remove(wb.active)

    # risk highlighters per sheet
    risk = {
        "Users": lambda r: r.get("asrepRoastable") or r.get("pwdNotRequired")
        or r.get("unconstrainedDeleg") or (r.get("hasSPN") and str(r.get("adminCount")) == "1"),
        "Computers": lambda r: r.get("unconstrainedDeleg") or r.get("rbcd"),
        "Kerberoastable": lambda r: str(r.get("adminCount")) == "1",
        "AS-REP Roastable": lambda r: True,
        "Delegation": lambda r: "unconstrained" in str(r.get("delegation", "")),
        "Privileged Users": lambda r: r.get("pwdNeverExpires"),
    }

    counts: dict[str, int] = {}
    for name, rows in sections.items():
        counts[name] = _sheet(wb, name, rows, risk.get(name))

    # ---- Summary tab (first) ----
    summ = wb.create_sheet("Summary", 0)
    summ["A1"] = f"k1rby — AD recon: {domain}"
    summ["A1"].font = _TITLE
    summ["A3"] = "Section"
    summ["B3"] = "Count"
    summ["A3"].font = summ["B3"].font = _HEAD
    summ["A3"].fill = summ["B3"].fill = _HEAD_FILL
    r = 4
    for name, n in counts.items():
        summ.cell(r, 1, name)
        summ.cell(r, 2, n)
        r += 1
    if external:
        r += 1
        summ.cell(r, 1, "External collectors").font = Font(bold=True)
        r += 1
        for tool, status in external.items():
            summ.cell(r, 1, tool)
            summ.cell(r, 2, status)
            r += 1
    summ.column_dimensions["A"].width = 34
    summ.column_dimensions["B"].width = 50
    summ["A1"].alignment = Alignment(vertical="center")

    wb.save(path)
    return counts
