# Method ↔ code map

Every equation and procedural step in the working paper, and where it is implemented.

## PQRA (paper §3)

| Paper | Code | Notes |
|---|---|---|
| Indicator scores s_{d,i} ∈ {0,1,2,3} | `pqra/scoring.py::score` validation | `null` = N/A (excluded from m_d, needs a justification), `""` = unanswered |
| Eq. (1) S_d = (1/m_d) Σ s_{d,i} | `pqra/scoring.py::score` | |
| Eq. (2) R = (1/6) Σ S_d | `pqra/scoring.py::_weighted_R` | equal weights by default; `weights` in the assessment file reweights |
| "sensitivity analysis may reweight" | `pqra/scoring.py::sensitivity` | leave-one-dimension-out + 2,000 flat-Dirichlet weightings, seed 2026; reports share keeping the band |
| Eq. (3) Band(R) | `pqra/scoring.py::band`, cut-points in `instrument.json` | Critical [0,1), Developing [1,2), Managed [2,2.5), Optimising [2.5,3] |
| Eq. (4) D4 gate | `pqra/scoring.py::d4_gate` | L = median Encaps latency of the chosen KEM from a lab `summary.json`; C = its ciphertext bytes. `policy: report` (default) shows it; `policy: cap` caps S_D4 at 1 on failure |
| D2 HNDL exposure | `pqra/scoring.py::mosca` | Mosca's inequality x + y > z |
| C4 roadmap | `pqra/roadmap.py::build` | Band → start phase P0–P4; next steps = next anchor up for the lowest indicators in dimensions with S_d < 2 |

## Laboratory (paper §4.2–4.5)

| Paper | Code | Notes |
|---|---|---|
| Freeze compliance (§4.4.1) | `protocol.py::freeze/load`, `harness.py::run_session` | hash mismatch, `--quick`, `--only`, `--reps` → `sandbox/` |
| Eq. (5) W=50, N=1000, R=5 | `config/protocol.toml [run]` | reduced N=100 (W=5) only for RSA KeyGen, with the justification stored in the config |
| R independent repetitions with process restart | `harness.py` spawns `python -m kclab.worker` per (algorithm, r) | |
| Correctness gate, 100 % before timing | `worker.py::correctness_gate` | KEM: round-trip and tampered-ciphertext rejection; signatures: verify, reject modified message, reject modified signature, for both message lengths. A failing algorithm gets no timings; analysis also drops it |
| Messages 32 B and 1024 B | `[run] message_lengths` | |
| M1 per-op wall-clock | `worker.py::_time_op` | `perf_counter_ns` around each call; GC disabled while timing; fixed keys for keyed ops |
| Eq. (6)–(8) mean, median, p̂95 per run | `analysis.py::run_level` | µs |
| Eq. (9) x̄• and s across R runs | `analysis.py::across_runs` | s = SD of run means, ddof = 1 |
| Eq. (10) Θ = 1/x̄ (M2) | `analysis.py::across_runs` | ops/s |
| M3–M7 sizes | `worker.py::object_sizes` | max over 20 samples (ECDSA DER signatures vary by ±2 B) |
| M8 peak RSS | `worker.py::_peak_rss` | peak working set (Windows) / ru_maxrss (POSIX); reported as peak and as delta over the post-import baseline |
| Eq. (11) ρ_u (M9) for U1–U3 | `analysis.py::overhead_ratios` | latency = sum of the use case's operation medians; bytes = sum of on-wire objects; RSS delta |
| Tables T1–T5 | `analysis.py::analyse` → `T*_*.csv` + `.tex` | |
| Figures F1–F2 | `analysis.py::_figures` | F1a/F1b median latency (log) per op; F2 bytes on wire with the 1500 B MTU line |
| Config sheet | `envprofile.py::profile` → `session.json` | CPU, RAM, OS, Python and compiler, IUT versions, harness commit and dirty flag, power profile |
| Artifact appendix hashes | `analysis.py` → `manifest.json` | SHA-256 of every raw and processed file |

## Use-case definitions (M9). These are proposals for the authors to confirm.

| ID | Pair | Latency ops | Size objects |
|---|---|---|---|
| U1 Key establishment | ML-KEM-768 vs X25519 | KeyGen + Encaps + Decaps | pk + ct |
| U2 Document signing (1 KiB) | ML-DSA-65 vs ECDSA-P256 | Sign + Verify | signature |
| U3 Certificate-style auth | ML-DSA-44 vs RSA-2048-PSS | Verify | pk + signature |

## Threats to validity that the code makes visible

- **Single IUT per row.** `iut` column in every table. The `--secondary` session gives a cross-implementation check.
- **Python call overhead.** Recorded per worker (`timer_overhead_ns_median`) and in `summary.json`.
- **Commodity hardware.** `session.json` records whether the machine was on AC power and which power plan was active.
- **Lab ≠ TLS.** The U1 sizes show where a handshake will exceed one MTU. Whether that matters on real paths is the D4.4 middlebox test, not the lab.
