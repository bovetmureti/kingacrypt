"""Load, hash and freeze the laboratory protocol (paper section 4.4, item 1)."""
from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config" / "protocol.toml"
LOCK = ROOT / "config" / "protocol.lock"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    # Normalise line endings so a Windows checkout and a Linux checkout of the
    # same commit hash identically.
    h.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


@dataclass
class Protocol:
    raw: dict
    path: Path
    sha256: str
    frozen: bool
    lock: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.raw["protocol"]["id"]

    @property
    def run(self) -> dict:
        return self.raw["run"]

    def op_plan(self, algorithm: str, op: str) -> tuple[int, int, str | None]:
        """(warmup W, iterations N, justification) for one operation."""
        r = self.run
        red = r.get("reduced_n", {}).get(f"{algorithm}:{op}")
        if red:
            return int(red.get("warmup", r["warmup"])), int(red["n"]), red.get("reason")
        return int(r["warmup"]), int(r["iterations"]), None

    def tasks(self, which: str = "primary") -> list[tuple[str, str]]:
        """(algorithm, backend) pairs. ``primary`` = the T1-T5 set;
        ``secondary`` = cross-implementation checks of the PQC rows."""
        from . import backends
        a, iut = self.raw["algorithms"], self.raw["iut"]
        if which == "primary":
            prim = set(backends.available(iut["pqc_primary"]))
            fb = iut.get("fallback", {})
            pqc = []
            for n in a["kem_pqc"] + a["sig_pqc"]:
                if n in prim:
                    pqc.append((n, iut["pqc_primary"]))
                elif n in fb:
                    pqc.append((n, fb[n]))
                else:
                    raise RuntimeError(f"{n}: not in primary IUT {iut['pqc_primary']} and no fallback")
            return pqc + [(n, iut["classical"]) for n in a["kem_classical"] + a["sig_classical"]]
        if which == "secondary":
            out = []
            for be in iut.get("pqc_secondary", []):
                have = set(backends.available(be))
                out += [(n, be) for n in a["kem_pqc"] + a["sig_pqc"] if n in have]
            return out
        raise ValueError(which)

    @property
    def use_cases(self) -> list[dict]:
        return self.raw.get("use_case", [])


def load(path: Path = CONFIG) -> Protocol:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    digest = sha256_file(path)
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {}
    return Protocol(raw, path, digest, lock.get("sha256") == digest, lock)


def freeze(note: str, path: Path = CONFIG) -> dict:
    from datetime import datetime, timezone
    p = load(path)
    lock = {
        "protocol_id": p.id,
        "sha256": p.sha256,
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": note,
    }
    LOCK.write_text(json.dumps(lock, indent=2) + "\n")
    return lock
