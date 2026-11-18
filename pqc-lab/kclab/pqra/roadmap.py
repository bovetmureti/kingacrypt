"""Translate a PQRA result into a phased migration roadmap (RQ4, claim C4).

Three inputs drive the output:
  * the band (Critical -> Optimising) sets where the organisation starts;
  * the weakest indicators give the concrete next step: the anchor text of
    the next level up, so every recommendation traces back to the rubric;
  * lab evidence (T3/T5) and the Mosca check add sequencing constraints.
"""
from __future__ import annotations

from .scoring import Result, load_instrument

PHASES = [
    ("P0", "Mobilise", "Name an owner, record HNDL in the risk register, set the CRQC planning assumption.", ["D5", "D2"]),
    ("P1", "Discover", "Build the cryptographic inventory and map long-lived data flows.", ["D1", "D2"]),
    ("P2", "Prioritise", "Rank flows by Mosca exposure and by size/latency headroom.", ["D2", "D4"]),
    ("P3", "Hybrid pilots", "Run hybrid classical+ML-KEM on the highest-exposure flow; test middleboxes and rollback.", ["D3", "D4", "D6"]),
    ("P4", "Scale & agility", "Extend hybrid KEM to all internet-facing services; begin PKI/signature migration; keep rotation exercised.", ["D3", "D6"]),
]

BAND_START = {
    "Critical": ("P0", "Start with governance and discovery. Buying PQC products before the inventory exists usually moves risk around without reducing it."),
    "Developing": ("P1", "Finish the inventory and exposure mapping, then pilot hybrid key exchange on one high-exposure flow."),
    "Managed": ("P3", "Pilots can move to production for key exchange; plan the slower PKI and signature migration."),
    "Optimising": ("P4", "Keep algorithm rotation exercised, track the NIST IR 8547 deprecation dates (2030 / 2035), and complete signature migration."),
}


def _next_steps(result: Result, instrument: dict, threshold: float = 2.0, per_dim: int = 2) -> list[dict]:
    anchors = {i["id"]: i["anchors"] for d in instrument["dimensions"] for i in d["indicators"]}
    texts = {i["id"]: i["text"] for d in instrument["dimensions"] for i in d["indicators"]}
    out = []
    for d in sorted((x for x in result.dimensions if x.S is not None), key=lambda x: x.S):
        if d.S >= threshold:
            continue
        weak = sorted(((k, v) for k, v in d.scores.items() if v is not None and v < 3), key=lambda kv: kv[1])
        for iid, v in weak[:per_dim]:
            out.append({"dimension": d.id, "S_d": round(d.S, 2), "indicator": iid, "current": v,
                        "target": v + 1, "practice": texts[iid], "next_level": anchors[iid][v + 1]})
    return out


def _lab_notes(lab: dict | None, gate: dict | None) -> list[str]:
    if not lab:
        return ["No lab session attached: D4 relies on self-report. Run `kclab run` and pass --lab to score against measured data."]
    notes = []
    for r in lab.get("overhead", []):
        if r["metric"] == "bytes on wire" and r["rho"] == r["rho"]:
            added = r["M_pqc"] - r["M_classical"]
            notes.append(f"{r['use_case']} ({r['pqc']} vs {r['classical']}): {r['rho']:.1f}x bytes on the wire "
                         f"(+{added:,.0f} B per exchange).")
        if r["metric"].startswith("latency") and r["rho"] == r["rho"]:
            notes.append(f"{r['use_case']} ({r['pqc']} vs {r['classical']}): {r['rho']:.2f}x latency "
                         f"({r['M_pqc']:,.0f} vs {r['M_classical']:,.0f} us, sum of medians).")
    over = sorted((s for s in lab.get("sizes", [])
                   if s["kind"] == "kem" and s["family"] == "pqc" and s["wire_B"] > 1500),
                  key=lambda s: s["wire_B"])
    if over:
        names = ", ".join(f"{s['algorithm']} ({s['wire_B']:,.0f} B)" for s in over)
        notes.append(f"pk+ct exceeds a 1500 B MTU for {names}: in a hybrid TLS handshake the ClientHello "
                     "spans more than one packet; test middleboxes (D4.4) before rollout.")
    if gate and gate.get("indicator") is not None:
        verdict = "passes" if gate["indicator"] else "fails"
        notes.append(f"D4 gate (eq. 4) {verdict} for {gate['kem']}: L={gate['L_median_encaps_us']:.0f} us "
                     f"(cap {gate['L_cap_us']:.0f}), C={gate['C_ciphertext_bytes']:.0f} B (cap {gate['C_cap_bytes']:.0f}).")
    return notes


def build(result: Result, lab: dict | None = None, instrument: dict | None = None) -> dict:
    inst = instrument or load_instrument()
    start, framing = BAND_START.get(result.band, ("P0", "Assessment incomplete; complete scoring first."))
    idx = [p[0] for p in PHASES].index(start)
    S = {d.id: d.S for d in result.dimensions}
    phases = []
    for i, (pid, name, desc, dims) in enumerate(PHASES):
        weak = [d for d in dims if S.get(d) is not None and S[d] < 2]
        status = "done" if i < idx and not weak else ("revisit" if i < idx else ("start here" if i == idx else "later"))
        phases.append({"id": pid, "name": name, "description": desc, "dimensions": dims,
                       "weak_dimensions": weak, "status": status})

    urgent = []
    if result.mosca and result.mosca["exposed"]:
        m = result.mosca
        urgent.append(f"Mosca check: shelf-life {m['x_shelf_life']} + migration {m['y_migration']} = "
                      f"{m['x_plus_y']} years > horizon {m['z_horizon']} years. Long-lived data is already "
                      "harvest-exposed: put hybrid key exchange for those flows ahead of the band sequence.")
    return {"band": result.band, "R": result.R, "start_phase": start, "framing": framing,
            "urgent": urgent, "phases": phases, "next_steps": _next_steps(result, inst),
            "lab_notes": _lab_notes(lab, result.gate)}
