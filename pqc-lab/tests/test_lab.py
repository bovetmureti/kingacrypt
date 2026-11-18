import json
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from kclab import analysis, backends, protocol, worker

PRIMARY = protocol.load().tasks("primary")


@pytest.mark.parametrize("alg,be", PRIMARY)
def test_correctness_gate_passes(alg, be):
    a = backends.get(be, alg)
    g = worker.correctness_gate(a, 3, [32, 1024])
    assert g["checks_failed"] == 0, g


# FIPS 203 / 204 encoded sizes (bytes): pk, ct-or-sig
FIPS = {"ML-KEM-512": (800, 768), "ML-KEM-768": (1184, 1088), "ML-KEM-1024": (1568, 1568),
        "ML-DSA-44": (1312, 2420), "ML-DSA-65": (1952, 3309), "ML-DSA-87": (2592, 4627)}


@pytest.mark.parametrize("alg", list(FIPS))
@pytest.mark.parametrize("be", ["pqcrypto", "openssl"])
def test_fips_sizes(alg, be):
    if alg not in backends.available(be):
        pytest.skip(f"{be} lacks {alg}")
    s = worker.object_sizes(backends.get(be, alg), [32], samples=2)
    pk, other = FIPS[alg]
    assert s["public_key"]["max"] == pk
    assert (s.get("ciphertext") or s["signature"])["max"] == other


def test_cross_iut_interop_mlkem768():
    """Keys from one IUT must decapsulate ciphertexts from the other."""
    o, p = backends.get("openssl", "ML-KEM-768"), backends.get("pqcrypto", "ML-KEM-768")
    pk_p, sk_p = p.keygen()
    from cryptography.hazmat.primitives.asymmetric import mlkem
    ct, ss = o.encaps(mlkem.MLKEM768PublicKey.from_public_bytes(pk_p))
    assert p.decaps(sk_p, ct) == ss


def test_stats_equations():
    rows = []
    for rep, base in ((1, 100), (2, 200)):
        for i, v in enumerate([base, base, base * 2, base * 3]):
            rows.append(dict(algorithm="A", iut="x", family="pqc", operation="Encaps", msg_len=0,
                             rep=rep, iter=i, ns=v * 1000))
    runs = analysis.run_level(pd.DataFrame(rows), 95)
    assert list(runs["mean"]) == [175.0, 350.0]                    # eq. 6, in us
    assert list(runs["median"]) == [150.0, 300.0]                  # eq. 7
    agg = analysis.across_runs(runs).iloc[0]
    assert agg.mean_us == pytest.approx(262.5)                     # eq. 9
    assert agg.sd_us == pytest.approx(np.std([175, 350], ddof=1))
    assert agg.throughput_ops_s == pytest.approx(1e6 / 262.5)      # eq. 10


def test_freeze_diverts_unfrozen_to_sandbox(tmp_path, monkeypatch):
    p = protocol.load()
    p.frozen = False
    monkeypatch.setattr(protocol, "ROOT", tmp_path)
    from kclab import harness
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    out = harness.run_session(p, only=["X25519"], quick=True, log=lambda *a: None)
    assert out.parent.name == "sandbox"
    meta = json.loads((out / "session.json").read_text())
    assert meta["official"] is False and meta["results"][0]["status"] == "ok"
    proc = analysis.analyse(out, tmp_path / "proc", figures=False)
    assert (proc / "T1_latency.csv").exists() and (proc / "manifest.json").exists()


def test_cli_template():
    out = subprocess.run([sys.executable, "-m", "kclab", "pqra", "template"], capture_output=True, text=True)
    assert len(json.loads(out.stdout)["scores"]) == 24
