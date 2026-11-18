"""Orchestrates a protocol session: environment profile, freeze check, then
R fresh worker processes per (algorithm, IUT).

Output layout (paper section 4.4, item 5)::

    data/raw/<session>/           protocol run (config hash == protocol.lock)
    sandbox/<session>/            anything else (exploratory, --quick, unfrozen)
        session.json              env profile, protocol snapshot + hash, plan, status
        <ALG>__<IUT>__r<k>.csv    one row per timed call (M1 raw)
        <ALG>__<IUT>__r<k>.json   sizes, RSS, correctness, timer overhead
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import envprofile
from .protocol import ROOT, Protocol

PKG_ROOT = Path(__file__).resolve().parent.parent   # where `python -m kclab.worker` resolves
KEM_OPS = ("KeyGen", "Encaps", "Decaps")
SIG_OPS = ("KeyGen", "Sign", "Verify")


def _kind(proto: Protocol, alg: str) -> str:
    a = proto.raw["algorithms"]
    return "kem" if alg in a["kem_pqc"] + a["kem_classical"] else "sig"


def session_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def plan(proto: Protocol, which: str, only: list[str] | None, quick: bool) -> list[dict]:
    tasks = []
    for alg, be in proto.tasks(which):
        if only and alg not in only:
            continue
        ops = KEM_OPS if _kind(proto, alg) == "kem" else SIG_OPS
        plans = {}
        for op in ops:
            w, n, why = proto.op_plan(alg, op)
            if quick:
                w, n = min(w, 5), min(n, 30 if why is None else 3)
            plans[op] = {"warmup": w, "n": n, "reduced_reason": why}
        tasks.append({"algorithm": alg, "backend": be, "plans": plans})
    return tasks


def run_session(proto: Protocol, *, which: str = "primary", only: list[str] | None = None,
                quick: bool = False, sandbox: bool = False, reps: int | None = None,
                python: str = sys.executable, log=print) -> Path:
    official = proto.frozen and not quick and not sandbox and not only and reps is None
    if not proto.frozen and not sandbox:
        log("[harness] protocol.toml does not match protocol.lock -> diverting to sandbox/")
    sid = session_id() + ("" if official else "-sandbox") + ("" if which == "primary" else f"-{which}")
    out = ROOT / ("data/raw" if official else "sandbox") / sid
    out.mkdir(parents=True, exist_ok=True)

    R = reps or (1 if quick else int(proto.run["repetitions"]))
    tasks = plan(proto, which, only, quick)
    meta = {
        "session": sid, "official": official, "which": which, "quick": quick,
        "protocol_id": proto.id, "protocol_sha256": proto.sha256, "protocol_frozen": proto.frozen,
        "protocol_lock": proto.lock, "protocol_snapshot": proto.raw,
        "repetitions": R, "tasks": tasks, "environment": envprofile.profile(),
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": [],
    }
    (out / "session.json").write_text(json.dumps(meta, indent=2, default=str))
    log(f"[harness] session {sid} -> {out.relative_to(ROOT)}  ({len(tasks)} algorithms x R={R})")

    env = dict(os.environ, PYTHONHASHSEED="0")
    for t in tasks:
        for r in range(1, R + 1):
            spec = {
                "session": sid, "protocol_id": proto.id, "algorithm": t["algorithm"],
                "backend": t["backend"], "rep": r, "plans": t["plans"],
                "message_lengths": proto.run["message_lengths"],
                "correctness_trials": 3 if quick else int(proto.run["correctness_trials"]),
                "pin_cpu": int(proto.run.get("pin_cpu", -1)), "out_dir": str(out),
            }
            t0 = time.time()
            p = subprocess.run([python, "-m", "kclab.worker", json.dumps(spec)], cwd=PKG_ROOT, env=env)
            status = {0: "ok", 3: "gate_failed"}.get(p.returncode, f"error({p.returncode})")
            meta["results"].append({"algorithm": t["algorithm"], "backend": t["backend"], "rep": r,
                                    "status": status, "seconds": round(time.time() - t0, 2)})
            log(f"  {t['algorithm']:<14} {t['backend']:<9} r{r}/{R}  {status:<12} {time.time() - t0:7.1f}s")
            if status == "gate_failed":
                log("  !! correctness gate failed: no timings for this algorithm enter Results")
                break
    meta["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (out / "session.json").write_text(json.dumps(meta, indent=2, default=str))
    return out
