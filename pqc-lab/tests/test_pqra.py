import json
from pathlib import Path

import pytest

from kclab.pqra import roadmap, scoring

ROOT = Path(__file__).resolve().parent.parent
INST = scoring.load_instrument()
IDS = [i["id"] for d in INST["dimensions"] for i in d["indicators"]]


def _all(v):
    return {"scores": {i: v for i in IDS}}


@pytest.mark.parametrize("R,label", [(0, "Critical"), (0.999, "Critical"), (1, "Developing"),
                                     (1.99, "Developing"), (2, "Managed"), (2.49, "Managed"),
                                     (2.5, "Optimising"), (3, "Optimising")])
def test_band_cut_points_eq3(R, label):
    assert scoring.band(R, INST) == label


def test_band_rejects_out_of_range():
    with pytest.raises(ValueError):
        scoring.band(3.01, INST)


def test_instrument_shape():
    assert [d["id"] for d in INST["dimensions"]] == ["D1", "D2", "D3", "D4", "D5", "D6"]
    for d in INST["dimensions"]:
        for i in d["indicators"]:
            assert len(i["anchors"]) == 4, i["id"]


@pytest.mark.parametrize("v,band", [(0, "Critical"), (1, "Developing"), (2, "Managed"), (3, "Optimising")])
def test_uniform_scores(v, band):
    r = scoring.score(_all(v), INST)
    assert r.R == pytest.approx(v) and r.band == band and r.complete


def test_eq1_eq2_by_hand():
    a = _all(0)
    a["scores"].update({"D1.1": 3, "D1.2": 3})          # S_D1 = 6/4 = 1.5
    a["scores"]["D2.1"] = None                          # N/A excluded from m_d
    a["scores"].update({"D2.2": 3, "D2.3": 3, "D2.4": 0})  # S_D2 = 6/3 = 2
    a["na_justification"] = {"D2.1": "x"}
    r = scoring.score(a, INST)
    S = {d.id: d.S for d in r.dimensions}
    assert S["D1"] == 1.5 and S["D2"] == 2.0 and S["D3"] == 0
    assert [d.m for d in r.dimensions if d.id == "D2"] == [3]
    assert r.R == pytest.approx((1.5 + 2.0) / 6)


def test_invalid_score_rejected():
    a = _all(1)
    a["scores"]["D1.1"] = 4
    with pytest.raises(ValueError):
        scoring.score(a, INST)


def test_incomplete_assessment_has_no_R():
    r = scoring.score({"scores": {"D1.1": 2}}, INST)
    assert r.R is None and not r.complete


LAB = {"session": "t", "latency": [{"algorithm": "ML-KEM-768", "operation": "Encaps", "median_us": 80.0, "iut": "x"}],
       "sizes": [{"algorithm": "ML-KEM-768", "ciphertext_B": 1088, "kind": "kem", "family": "pqc", "wire_B": 2272}],
       "overhead": []}


def test_gate_eq4():
    g = scoring.d4_gate(LAB, "ML-KEM-768", 100, 1500)
    assert g["indicator"] == 1
    assert scoring.d4_gate(LAB, "ML-KEM-768", 50, 1500)["indicator"] == 0
    assert scoring.d4_gate(LAB, "ML-KEM-768", 100, 1000)["indicator"] == 0


def test_gate_cap_policy():
    a = _all(3)
    a["d4_gate"] = {"kem": "ML-KEM-768", "latency_cap_us": 10, "ciphertext_cap_bytes": 1500, "policy": "cap"}
    r = scoring.score(a, INST, lab_summary=LAB)
    assert next(d.S for d in r.dimensions if d.id == "D4") == 1.0
    a["d4_gate"]["policy"] = "report"
    r = scoring.score(a, INST, lab_summary=LAB)
    assert next(d.S for d in r.dimensions if d.id == "D4") == 3.0 and r.gate["indicator"] == 0


def test_mosca():
    assert scoring.mosca(10, 6, 12)["exposed"] is True
    assert scoring.mosca(2, 3, 12)["exposed"] is False


def test_sensitivity_uniform_is_stable():
    r = scoring.score(_all(2), INST)
    assert r.sensitivity["dirichlet"]["same_band_share"] == 1.0


def test_example_roadmap():
    a = json.loads((ROOT / "examples" / "synthetic_bank_assessment.json").read_text())
    r = scoring.score(a, INST, lab_summary=LAB)
    rm = roadmap.build(r, LAB, INST)
    assert r.band == "Critical" and rm["start_phase"] == "P0"
    assert rm["urgent"]                                    # 10 + 6 > 12
    assert all(s["target"] == s["current"] + 1 for s in rm["next_steps"])
    assert any("MTU" in n for n in rm["lab_notes"])
