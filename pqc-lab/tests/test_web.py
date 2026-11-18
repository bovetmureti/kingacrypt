"""The browser scorer (web/pqra.js) must agree with the Python scorer."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from kclab.pqra import scoring

ROOT = Path(__file__).resolve().parent.parent


def test_web_instrument_in_sync():
    a = json.loads((ROOT / "kclab" / "pqra" / "instrument.json").read_text(encoding="utf-8"))
    b = json.loads((ROOT / "web" / "instrument.json").read_text(encoding="utf-8"))
    assert a == b, "run: python -m kclab web (or copy kclab/pqra/instrument.json to web/)"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_python_parity():
    example = ROOT / "examples" / "synthetic_bank_assessment.json"
    js = f"""
      const P = require({json.dumps(str(ROOT / 'web' / 'pqra.js'))});
      const inst = require({json.dumps(str(ROOT / 'kclab' / 'pqra' / 'instrument.json'))});
      const a = require({json.dumps(str(example))});
      const r = P.score(a, inst);
      console.log(JSON.stringify({{R: r.R, band: r.band, S: r.dimensions.map(d => d.S), exposed: r.mosca.exposed}}));
    """
    out = json.loads(subprocess.check_output(["node", "-e", js], text=True))
    py = scoring.score(json.loads(example.read_text()))
    assert out["band"] == py.band
    assert out["R"] == pytest.approx(py.R)
    assert out["S"] == pytest.approx([d.S for d in py.dimensions])
    assert out["exposed"] == py.mosca["exposed"]
