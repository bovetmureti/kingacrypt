"""PQRA scoring: equations (1)-(4) of the working paper, plus the Mosca
inequality for D2 and a weight-sensitivity check ("equal weights in v1;
sensitivity analysis may reweight").

Assessment file format (JSON)::

    {
      "organisation": {"label": "...", "sector": "...", "rater_role": "...", "date": "YYYY-MM-DD"},
      "scores":   {"D1.1": 2, "D1.2": null, ...},     # 0..3, null = not applicable, "" = unanswered
      "evidence": {"D1.1": "inventory v3, 2026-10"},
      "na_justification": {"D1.2": "..."},
      "mosca":    {"shelf_life_years": 10, "migration_years": 6, "crqc_horizon_years": 12},
      "d4_gate":  {"kem": "ML-KEM-768", "latency_cap_us": 1000, "ciphertext_cap_bytes": 1500,
                   "policy": "report"}                 # or "cap": gate fail caps S_D4 at 1
    }
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

INSTRUMENT_PATH = Path(__file__).with_name("instrument.json")
VALID = {0, 1, 2, 3}


def load_instrument(path: Path = INSTRUMENT_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def band(R: float, instrument: dict | None = None) -> str:
    """Equation (3)."""
    bands = (instrument or load_instrument())["bands"]
    R = round(R, 9)          # weighted means drift by ~1e-16; do not let that flip a band
    if not 0 <= R <= 3:
        raise ValueError(f"R={R} outside [0, 3]")
    for b in bands:
        upper_ok = R <= b["max"] if b["max_inclusive"] else R < b["max"]
        if b["min"] <= R and upper_ok:
            return b["label"]
    raise AssertionError("bands do not cover [0, 3]")


@dataclass
class DimensionScore:
    id: str
    name: str
    S: float | None          # eq. (1); None when every indicator is N/A or unrated
    m: int                   # indicators counted
    na: int                  # indicators marked N/A
    missing: list[str] = field(default_factory=list)
    scores: dict = field(default_factory=dict)


@dataclass
class Result:
    dimensions: list[DimensionScore]
    R: float | None          # eq. (2)
    band: str | None         # eq. (3)
    complete: bool
    weights: dict
    gate: dict | None = None         # eq. (4)
    mosca: dict | None = None
    sensitivity: dict | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def d4_gate(lab_summary: dict, kem: str, latency_cap_us: float, ciphertext_cap_bytes: float) -> dict:
    """Equation (4): I = 1 iff median Encaps latency L <= L* and ciphertext C <= C*."""
    lat = [r for r in lab_summary["latency"] if r["algorithm"] == kem and r["operation"] == "Encaps"]
    siz = [r for r in lab_summary["sizes"] if r["algorithm"] == kem]
    if not lat or not siz:
        return {"kem": kem, "indicator": None, "reason": f"{kem} not in lab session {lab_summary.get('session')}"}
    L, C = float(lat[0]["median_us"]), float(siz[0]["ciphertext_B"])
    ok = (L <= latency_cap_us) and (C <= ciphertext_cap_bytes)
    return {"kem": kem, "iut": lat[0]["iut"], "session": lab_summary.get("session"),
            "L_median_encaps_us": L, "L_cap_us": latency_cap_us,
            "C_ciphertext_bytes": C, "C_cap_bytes": ciphertext_cap_bytes,
            "latency_ok": L <= latency_cap_us, "size_ok": C <= ciphertext_cap_bytes,
            "indicator": int(ok)}


def mosca(shelf_life_years: float, migration_years: float, crqc_horizon_years: float) -> dict:
    """Mosca's inequality: if x + y > z, data encrypted today is already exposed."""
    x, y, z = shelf_life_years, migration_years, crqc_horizon_years
    return {"x_shelf_life": x, "y_migration": y, "z_horizon": z, "x_plus_y": x + y,
            "exposed": x + y > z, "margin_years": z - (x + y)}


def _weighted_R(S: dict, w: dict) -> float:
    tot = sum(w[d] for d in S)
    return sum(S[d] * w[d] for d in S) / tot


def sensitivity(S: dict, instrument: dict, draws: int = 2000, seed: int = 2026) -> dict:
    """Band stability under (a) leave-one-dimension-out and (b) random weights
    drawn from a flat Dirichlet. Reports the share of draws that keep the
    equal-weight band."""
    import numpy as np
    ids = list(S)
    base = band(sum(S.values()) / len(S), instrument)
    loo = {}
    for d in ids:
        rest = {k: v for k, v in S.items() if k != d}
        r = sum(rest.values()) / len(rest)
        loo[d] = {"R": r, "band": band(r, instrument)}
    rng = np.random.default_rng(seed)
    W = rng.dirichlet(np.ones(len(ids)), size=draws)
    vals = W @ np.array([S[d] for d in ids])
    bands = [band(float(v), instrument) for v in vals]
    return {"base_band": base, "leave_one_out": loo,
            "dirichlet": {"draws": draws, "seed": seed,
                          "R_p05": float(np.percentile(vals, 5)), "R_p95": float(np.percentile(vals, 95)),
                          "same_band_share": bands.count(base) / draws}}


def score(assessment: dict, instrument: dict | None = None, lab_summary: dict | None = None,
          gate_defaults: dict | None = None) -> Result:
    inst = instrument or load_instrument()
    raw = assessment.get("scores", {})
    warnings: list[str] = []
    known = {i["id"] for d in inst["dimensions"] for i in d["indicators"]}
    for k in raw:
        if k not in known:
            warnings.append(f"unknown indicator {k} ignored")

    dims: list[DimensionScore] = []
    for d in inst["dimensions"]:
        vals, na, missing, per = [], 0, [], {}
        for ind in d["indicators"]:
            iid = ind["id"]
            if iid not in raw or raw[iid] == "":          # "" = not yet answered
                missing.append(iid)
                continue
            v = raw[iid]
            per[iid] = v
            if v is None:
                na += 1
                if not assessment.get("na_justification", {}).get(iid):
                    warnings.append(f"{iid} marked N/A without justification")
                continue
            if v not in VALID:
                raise ValueError(f"{iid}: score {v!r} not in {{0,1,2,3}}")
            vals.append(int(v))
        S = sum(vals) / len(vals) if vals else None                      # eq. (1)
        dims.append(DimensionScore(d["id"], d["name"], S, len(vals), na, missing, per))

    # D4 technical gate, eq. (4)
    gate = None
    g = {**(gate_defaults or {}), **assessment.get("d4_gate", {})}
    if lab_summary is not None and {"kem", "latency_cap_us", "ciphertext_cap_bytes"} <= set(g):
        gate = d4_gate(lab_summary, g["kem"], float(g["latency_cap_us"]), float(g["ciphertext_cap_bytes"]))
        gate["policy"] = g.get("policy", "report")
        d4 = next(x for x in dims if x.id == "D4")
        if gate["indicator"] == 0 and gate["policy"] == "cap" and d4.S is not None and d4.S > 1:
            warnings.append(f"D4 capped from {d4.S:.2f} to 1.00 by the lab gate (policy=cap)")
            d4.S = 1.0

    complete = all(x.S is not None and not x.missing for x in dims)
    scored = {x.id: x.S for x in dims if x.S is not None}
    weights = assessment.get("weights") or {x.id: 1.0 for x in dims}
    R = Rband = None
    if len(scored) == len(dims):
        R = _weighted_R(scored, weights)                                   # eq. (2)
        Rband = band(R, inst)                                              # eq. (3)
    else:
        warnings.append("R not computed: at least one dimension has no scored indicator")
    if not complete:
        warnings.append("assessment incomplete: some indicators missing")

    m = assessment.get("mosca")
    mos = mosca(m["shelf_life_years"], m["migration_years"], m["crqc_horizon_years"]) if m else None
    sens = sensitivity(scored, inst) if R is not None else None
    return Result(dims, R, Rband, complete, weights, gate, mos, sens, warnings)


def template(instrument: dict | None = None) -> dict:
    inst = instrument or load_instrument()
    ids = [i["id"] for d in inst["dimensions"] for i in d["indicators"]]
    return {
        "instrument": f"{inst['id']} {inst['version']}",
        "organisation": {"label": "", "sector": "", "rater_role": "", "date": ""},
        "_how_to": "Set each score to 0, 1, 2 or 3; null = not applicable (add na_justification); \"\" = not yet answered.",
        "scores": {i: "" for i in ids},
        "evidence": {i: "" for i in ids},
        "na_justification": {},
        "mosca": {"shelf_life_years": None, "migration_years": None, "crqc_horizon_years": None},
        "d4_gate": {"kem": "ML-KEM-768", "latency_cap_us": 1000, "ciphertext_cap_bytes": 1500,
                    "policy": "report"},
    }
