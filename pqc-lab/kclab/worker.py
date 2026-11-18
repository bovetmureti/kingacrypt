"""One repetition r of one algorithm, in its own OS process.

Run by the orchestrator (``kclab.harness``) as
``python -m kclab.worker <json-spec>``. A fresh process per repetition gives
the "independent batch repetitions (process restart)" the protocol requires,
and makes peak RSS (M8) attributable to a single algorithm.

Order inside the process:
  1. import backend, record baseline RSS
  2. correctness gate (must be 100 %, otherwise exit 3 and write no timings)
  3. object sizes (M3-M7)
  4. per operation: W warm-up calls, then N individually timed calls (M1)
  5. peak RSS (M8), timer overhead calibration, sidecar JSON
"""
from __future__ import annotations

import csv
import gc
import json
import os
import statistics
import sys
import time
from pathlib import Path

import psutil

from . import backends

EXIT_GATE_FAILED = 3


def _peak_rss(proc: psutil.Process) -> int:
    mi = proc.memory_info()
    if hasattr(mi, "peak_wset"):                      # Windows
        return int(mi.peak_wset)
    try:
        import resource                              # POSIX: ru_maxrss
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(r if sys.platform == "darwin" else r * 1024)
    except Exception:
        return int(mi.rss)


def _flip(b: bytes) -> bytes:
    if not b:
        return b"\x01"
    return bytes([b[0] ^ 0x01]) + b[1:]


def correctness_gate(alg, trials: int, msg_lens: list[int]) -> dict:
    passed = failed = 0
    detail: list[str] = []
    for _ in range(trials):
        pk, sk = alg.keygen()
        if alg.kind == "kem":
            ct, ss = alg.encaps(pk)
            ok = alg.decaps(sk, ct) == ss
            try:                               # tampered ct must not yield ss
                ok_t = alg.decaps(sk, _flip(ct)) != ss
            except Exception:
                ok_t = True
            checks = [("roundtrip", ok), ("tamper-reject", ok_t)]
        else:
            checks = []
            for L in msg_lens:
                m = os.urandom(L)
                sig = alg.sign(sk, m)
                checks.append((f"verify[{L}]", alg.verify(pk, m, sig)))
                checks.append((f"reject-msg[{L}]", not alg.verify(pk, _flip(m), sig)))
                checks.append((f"reject-sig[{L}]", not alg.verify(pk, m, _flip(sig))))
        for name, ok in checks:
            if ok:
                passed += 1
            else:
                failed += 1
                detail.append(name)
    return {"checks_passed": passed, "checks_failed": failed,
            "pass_rate": passed / max(1, passed + failed), "failures": sorted(set(detail))}


def object_sizes(alg, msg_lens: list[int], samples: int = 20) -> dict:
    """Encoded sizes. Variable-length objects (DER ECDSA signatures) are
    sampled; min/max/mean are recorded."""
    obs: dict[str, list[int]] = {}

    def add(k, v):
        obs.setdefault(k, []).append(len(v))

    for _ in range(samples):
        pk, sk = alg.keygen()
        add("public_key", alg.encode_pk(pk))
        add("secret_key", alg.encode_sk(sk))
        if alg.kind == "kem":
            ct, ss = alg.encaps(pk)
            add("ciphertext", ct)
            add("shared_secret", ss)
        else:
            for L in msg_lens:
                add(f"signature@{L}", alg.sign(sk, os.urandom(L)))
    out = {}
    for k, v in obs.items():
        out[k] = {"min": min(v), "max": max(v), "mean": statistics.fmean(v)}
    sigs = [k for k in out if k.startswith("signature@")]
    if sigs:  # signature length does not depend on message length; pool it
        allv = [x for k in sigs for x in obs[k]]
        out["signature"] = {"min": min(allv), "max": max(allv), "mean": statistics.fmean(allv)}
    return out


def _timer_overhead_ns(n: int = 2000) -> float:
    f = (lambda: None)
    pc = time.perf_counter_ns
    xs = []
    for _ in range(n):
        t0 = pc()
        f()
        xs.append(pc() - t0)
    return float(statistics.median(xs))


def _time_op(fn, warmup: int, n: int) -> list[int]:
    pc = time.perf_counter_ns
    for _ in range(warmup):
        fn()
    out = [0] * n
    gc_was = gc.isenabled()
    gc.disable()
    try:
        for i in range(n):
            t0 = pc()
            fn()
            out[i] = pc() - t0
    finally:
        if gc_was:
            gc.enable()
    return out


def run(spec: dict) -> int:
    proc = psutil.Process()
    if spec.get("pin_cpu", -1) >= 0:
        try:
            proc.cpu_affinity([int(spec["pin_cpu"])])
        except Exception as e:  # macOS has no affinity API
            print(f"[worker] cpu pin ignored: {e}", file=sys.stderr)

    alg = backends.get(spec["backend"], spec["algorithm"])
    # force lazy library initialisation before the baseline is taken
    pk0, sk0 = alg.keygen()
    gc.collect()
    rss_base = int(proc.memory_info().rss)

    msg_lens = list(spec["message_lengths"])
    gate = correctness_gate(alg, int(spec["correctness_trials"]), msg_lens)
    side = {
        "spec": spec, "algorithm": alg.name, "iut": alg.iut, "family": alg.family, "kind": alg.kind,
        "nist_category": alg.nist_category, "encoding_note": alg.encoding_note,
        "iut_version": backends.version(alg.iut), "pid": os.getpid(), "correctness": gate,
    }
    out_dir = Path(spec["out_dir"])
    stem = f"{alg.name}__{alg.iut}__r{spec['rep']}"
    if gate["checks_failed"]:
        side["status"] = "gate_failed"
        (out_dir / f"{stem}.json").write_text(json.dumps(side, indent=2))
        print(f"[worker] CORRECTNESS GATE FAILED {stem}: {gate['failures']}", file=sys.stderr)
        return EXIT_GATE_FAILED

    side["sizes"] = object_sizes(alg, msg_lens)

    # fixed operands for keyed operations (SUPERCOP / liboqs-speed convention)
    pk, sk = alg.keygen()
    plans = spec["plans"]
    rows: list[tuple] = []
    t_start = time.time()

    def record(op, L, xs):
        w, n = plans[op]["warmup"], plans[op]["n"]
        for i, ns in enumerate(xs):
            rows.append((spec["session"], spec["protocol_id"], alg.name, alg.iut, alg.family,
                         op, L, spec["rep"], i, ns))
        side.setdefault("ops", {})[f"{op}@{L}"] = {"warmup": w, "n": n}

    if alg.kind == "kem":
        ct, _ = alg.encaps(pk)
        for op, fn in (("KeyGen", alg.keygen), ("Encaps", lambda: alg.encaps(pk)),
                       ("Decaps", lambda: alg.decaps(sk, ct))):
            p = plans[op]
            record(op, 0, _time_op(fn, p["warmup"], p["n"]))
    else:
        p = plans["KeyGen"]
        record("KeyGen", 0, _time_op(alg.keygen, p["warmup"], p["n"]))
        for L in msg_lens:
            m = bytes(range(256)) * (L // 256) + bytes(range(L % 256))
            sig = alg.sign(sk, m)
            for op, fn in (("Sign", lambda: alg.sign(sk, m)), ("Verify", lambda: alg.verify(pk, m, sig))):
                p = plans[op]
                record(op, L, _time_op(fn, p["warmup"], p["n"]))

    side["wall_seconds"] = time.time() - t_start
    side["rss_baseline_bytes"] = rss_base
    side["rss_peak_bytes"] = _peak_rss(proc)
    side["rss_delta_bytes"] = max(0, side["rss_peak_bytes"] - rss_base)
    side["timer_overhead_ns_median"] = _timer_overhead_ns()
    side["status"] = "ok"

    with open(out_dir / f"{stem}.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["session", "protocol_id", "algorithm", "iut", "family", "operation",
                    "msg_len", "rep", "iter", "ns"])
        w.writerows(rows)
    (out_dir / f"{stem}.json").write_text(json.dumps(side, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(run(json.loads(sys.argv[1])))
