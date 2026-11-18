# pqc-lab: PQC readiness prototype

Research prototype for the working paper **"Harvest-Now Threats and Post-Quantum Readiness: A Reproducible
Assessment and Migration-Management Approach for East African Critical Digital Infrastructure"**
(Githinji & Mureti, USIU-Africa; protocol `KC-LAB-PQC-2026-v1`).

The paper makes four claims (C1–C4). This folder holds the artefacts behind C2–C4:

| Paper element | What is here | Where |
|---|---|---|
| C3 / RQ3: reproducible lab evaluation, metrics M1–M9 | Benchmark harness: correctness gate, W/N/R timing, sizes, RSS, overhead ratios | `kclab/harness.py`, `kclab/worker.py`, `config/protocol.toml` |
| Equations (5)–(11), Tables T1–T5, Figures F1–F2 | Analysis that builds every results table and figure from raw CSVs | `kclab/analysis.py` |
| C2 / RQ2: PQRA instrument (D1–D6) | 24 draft indicators with 0–3 anchors, evidence prompts | `kclab/pqra/instrument.json` |
| Equations (1)–(4) | Scoring S_d, R, Band(R), D4 lab gate, Mosca check, weight sensitivity | `kclab/pqra/scoring.py` |
| C4 / RQ4: band → phased roadmap | Roadmap P0–P4, next steps traced to rubric anchors, lab-informed notes | `kclab/pqra/roadmap.py` |
| Operator-facing tool | Browser PQRA form (runs locally, exports JSON for the CLI) | `web/` |

It is a contribution of framework design plus lab evaluation. It contains no new cryptography and does no cryptanalysis.

## Quick start

```bash
cd pqc-lab
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[test]"

python -m kclab env                          # machine profile for the config sheet
python -m kclab run --quick                  # 1-minute smoke test -> sandbox/
pytest -q                                    # ~56 tests: correctness gate, FIPS sizes, interop, equations, JS/Python parity

# PQRA
python -m kclab pqra template > my_assessment.json
python -m kclab pqra score examples/synthetic_bank_assessment.json \
       --lab sandbox/<session>_processed/summary.json --md report.md
python -m kclab web                          # browser form on http://localhost:8000
```

## The protocol run (what goes into the paper)

1. Agree the final `config/protocol.toml` (algorithms, W=50, N=1000, R=5, use cases U1–U3, IUTs).
2. Freeze it: `python -m kclab freeze --note "v1 frozen for DTRAP submission"`. This writes the SHA-256 to `config/protocol.lock`.
3. On the lab machine (AC power, background apps closed, optional `pin_cpu`): `python -m kclab run`.
   - If the config hash matches the lock, output goes to `data/raw/<session>/` and `data/processed/`.
   - Any other run (unfrozen, `--quick`, `--only`, `--reps`) is diverted to `sandbox/`. Freeze compliance is enforced by the code, so it does not rely on the operator remembering to check.
4. Optional: `python -m kclab run --secondary` for the cross-implementation check (reported separately).
5. Use `data/processed/<session>/T*.tex` and `F*.pdf` directly in the manuscript. `manifest.json` holds the SHA-256 of every raw and processed file for the artifact appendix.

A full session on a 4-core laptop takes about 25–35 minutes; the RSA-3072 key generations account for most of it.

## Implementations under test

| Role | Backend | Version recorded in `session.json` |
|---|---|---|
| PQC primary + classical | OpenSSL via `pyca/cryptography` (native ML-KEM / ML-DSA) | e.g. cryptography 50.0.2 / OpenSSL 4.0.3 |
| ML-KEM-512 fallback, PQC cross-check | `pqcrypto` (Rust/PQClean bindings) | e.g. pqcrypto 1.0.0 |
| Optional, protocol-preferred on Linux | liboqs via `liboqs-python` (`pip install -e ".[oqs]"`, set `pqc_primary = "oqs"`) | liboqs version |

`pyca/cryptography` does not expose ML-KEM-512, so that one row comes from `pqcrypto`. The `iut` column says so and
the paper should footnote it, or switch to `oqs` on Linux to cover all six parameter sets from a single IUT.

Classical key agreement is wrapped in KEM shape the way DHKEM (RFC 9180) does it: Encaps = ephemeral key + DH, with the
ephemeral public key as "ciphertext". RSA-OAEP is wrapped as key transport of a 32-byte secret. This makes the KEM rows of T1–T5
comparable line by line.

## Measurement notes (threats to validity, also listed in `docs/METHOD.md`)

- Timings are taken around single Python calls into C/Rust libraries. The harness records the median overhead of an empty
  timed call (`timer_overhead_ns_median`, about 100–300 ns), which is negligible beside ML-DSA or RSA operations
  but is a visible share of X25519 and ML-KEM (tens of µs). Treat sub-50 µs differences as indicative.
- M8 (RSS) is the increase in peak working set over a post-import baseline in a fresh process. It shows how much memory
  an algorithm adds to the process. It does not measure the algorithm's own stack/heap use, which needs valgrind/massif in C.
- The harness runs single-threaded on one IUT and one machine, and does not exercise a full TLS stack (see paper §4.5).

## Layout

```
config/protocol.toml     the protocol (frozen via protocol.lock)
kclab/                   harness, worker, analysis, backends/, pqra/
data/raw|processed/      official sessions only
sandbox/                 everything else (gitignored)
web/                     browser PQRA tool (static; deployable by copying into ../public/pqra/)
examples/                SYNTHETIC assessment for tests and demos, not research data
docs/                    METHOD.md (equation ↔ code map), pilot/ (dev-laptop dry run)
tests/                   pytest suite
```
