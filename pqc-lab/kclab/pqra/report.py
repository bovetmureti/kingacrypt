"""Render a PQRA result + roadmap as Markdown."""
from __future__ import annotations

from .scoring import Result


def _bar(S: float | None, width: int = 12) -> str:
    if S is None:
        return "n/a"
    k = round(S / 3 * width)
    return "#" * k + "." * (width - k)


def markdown(assessment: dict, result: Result, roadmap: dict) -> str:
    org = assessment.get("organisation", {})
    L = [f"# PQRA readiness report: {org.get('label') or 'unnamed estate'}", ""]
    L += [f"- Sector: {org.get('sector') or '-'}  |  Rater role: {org.get('rater_role') or '-'}  |  Date: {org.get('date') or '-'}"]
    if result.R is not None:
        L += [f"- **Overall readiness R = {result.R:.2f} / 3 -> band: {result.band}**"]
    else:
        L += ["- **Overall readiness: not computed (incomplete)**"]
    if result.sensitivity:
        d = result.sensitivity["dirichlet"]
        L += [f"- Weight sensitivity: {d['same_band_share']:.0%} of {d['draws']} random weightings keep the band "
              f"(R 5th-95th pct {d['R_p05']:.2f}-{d['R_p95']:.2f})"]
    L += ["", "## Dimension scores (eq. 1)", "", "| Dim | Name | S_d | | m_d | N/A |", "|---|---|---:|---|---:|---:|"]
    for d in result.dimensions:
        s = "-" if d.S is None else f"{d.S:.2f}"
        L.append(f"| {d.id} | {d.name} | {s} | `{_bar(d.S)}` | {d.m} | {d.na} |")
    if result.gate:
        g = result.gate
        L += ["", "## D4 technical gate (eq. 4)", ""]
        if g.get("indicator") is None:
            L.append(f"- {g.get('reason')}")
        else:
            L.append(f"- KEM {g['kem']} ({g['iut']}, session {g['session']}): median Encaps "
                     f"{g['L_median_encaps_us']:.1f} us vs cap {g['L_cap_us']:.0f} us; ciphertext "
                     f"{g['C_ciphertext_bytes']:.0f} B vs cap {g['C_cap_bytes']:.0f} B -> "
                     f"**I = {g['indicator']}** (policy: {g['policy']})")
    if result.mosca:
        m = result.mosca
        L += ["", "## HNDL exposure (Mosca)", "",
              f"- x (shelf-life) + y (migration) = {m['x_plus_y']} years vs z (CRQC horizon) = {m['z_horizon']} years "
              f"-> **{'EXPOSED' if m['exposed'] else 'not yet exposed'}** (margin {m['margin_years']:+} years)"]
    L += ["", "## Roadmap", "", f"Start at **{roadmap['start_phase']}**. {roadmap['framing']}", ""]
    for u in roadmap["urgent"]:
        L.append(f"> **Urgent.** {u}")
        L.append("")
    L += ["| Phase | Name | Status | Weak dims | What |", "|---|---|---|---|---|"]
    for p in roadmap["phases"]:
        L.append(f"| {p['id']} | {p['name']} | {p['status']} | {', '.join(p['weak_dimensions']) or '-'} | {p['description']} |")
    if roadmap["next_steps"]:
        L += ["", "### Next concrete steps (lowest indicators in dimensions below 2.0)", ""]
        for s in roadmap["next_steps"]:
            L.append(f"- **{s['indicator']}** ({s['current']} -> {s['target']}): {s['next_level']}. "
                     f"_Practice:_ {s['practice']}")
    L += ["", "### Lab evidence", ""] + [f"- {n}" for n in roadmap["lab_notes"]]
    if result.warnings:
        L += ["", "### Warnings", ""] + [f"- {w}" for w in result.warnings]
    L += ["", "---", "_PQRA draft instrument; scores are self-assessed unless evidence pointers are verified._", ""]
    return "\n".join(L)
