# Pilot session 20261118T092240Z (sandbox, not protocol data)

This is a full-size dry run of the harness (W=50, N=1000, R=5, 16 algorithms, 80 worker processes, all correctness
gates 100 %). It went to `sandbox/` and does **not** count as `KC-LAB-PQC-2026-v1` results, for three reasons:

- the protocol was not frozen (`config/protocol.lock` absent);
- the harness tree was uncommitted at run time (`harness_tree_dirty: true`);
- the machine was a development laptop (Intel i5-6300U, 4 logical cores, Windows 10, Balanced power plan, AC power) with
  normal background load, which shows up as wide p95 and SD on the sub-200 µs operations.

The pilot is useful for checking that the pipeline produces every table and figure, and for an early read on effect sizes:

| Use case | Latency ρ | Bytes on wire ρ |
|---|---:|---:|
| U1 ML-KEM-768 vs X25519 (KeyGen+Encaps+Decaps) | 1.85 | 35.5 (2,272 vs 64 B) |
| U2 ML-DSA-65 vs ECDSA-P256 (Sign+Verify, 1 KiB) | 12.6 | 46.0 (3,309 vs 72 B) |
| U3 ML-DSA-44 vs RSA-2048-PSS (Verify) | 5.3 | 7.1 (3,732 vs 526 B) |

Early read: on this hardware, PQC key establishment costs about the same in latency as classical, but its size
crosses the 1500 B MTU at every parameter set. Signatures cost more in both latency and bytes. That points to
"hybrid KEM first, signatures later", which matches the roadmap logic in `kclab/pqra/roadmap.py`.

Files: `T1`–`T5` (`.csv` and `.tex`), `F1a`/`F1b`/`F2` (`.png` and `.pdf`), `summary.json`, `session.json` (config sheet),
`manifest.json` (SHA-256 of raw and processed files; the 28 MB of raw CSVs are not committed).
