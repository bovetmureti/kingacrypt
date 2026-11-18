"""Raw timings -> Tables T1-T5, Figures F1-F2, summary.json, manifest.json.

Every number in the paper's results section comes out of this module; no core
cell is hand-typed (paper section 4.5, item 2).

Equations implemented (numbering follows the working paper):
  (6)  run mean            x_bar_r = (1/N) sum x_j
  (7)  run median          Med_r
  (8)  run p95             empirical 95th percentile
  (9)  across runs         x_bar_. = (1/R) sum x_bar_r,  s = sd of the R run means (ddof=1)
  (10) throughput          Theta = 1 / x_bar_.   (ops/s)
  (11) overhead ratio      rho_u = M_pqc,u / M_classical,u
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .protocol import ROOT

# Validated reference palette (dataviz skill, categorical slots 1-2, light mode).
PQC_COLOR, CLASSICAL_COLOR = "#2a78d6", "#eb6834"
INK, INK_2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

# FIPS 203 / 204 expanded secret-key sizes. OpenSSL serialises PQC private keys
# as the 64/32-byte seed, PQClean/liboqs as the expanded key; T3 reports both so
# rows from different IUTs stay comparable.
FIPS_EXPANDED_SK = {"ML-KEM-512": 1632, "ML-KEM-768": 2400, "ML-KEM-1024": 3168,
                    "ML-DSA-44": 2560, "ML-DSA-65": 4032, "ML-DSA-87": 4896}


def _natural(name: str):
    import re
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name)]


# --------------------------------------------------------------------------- load
def load_session(session_dir: Path) -> tuple[pd.DataFrame, list[dict], dict]:
    csvs = sorted(session_dir.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(f"no timing CSVs in {session_dir}")
    df = pd.concat([pd.read_csv(p) for p in csvs], ignore_index=True)
    sides = [json.loads(p.read_text()) for p in sorted(session_dir.glob("*__r*.json"))]
    meta = json.loads((session_dir / "session.json").read_text())
    ok = {(s["algorithm"], s["iut"]) for s in sides if s.get("status") == "ok"}
    bad = {(s["algorithm"], s["iut"]) for s in sides if s.get("status") != "ok"}
    # correctness gate: an algorithm with any failed repetition is excluded entirely
    keep = ok - bad
    df = df[[(a, i) in keep for a, i in zip(df.algorithm, df.iut)]]
    return df, sides, meta


# --------------------------------------------------------------------------- stats
def run_level(df: pd.DataFrame, pct: int = 95) -> pd.DataFrame:
    """Equations (6)-(8): one row per (algorithm, iut, op, msg_len, rep)."""
    g = df.assign(us=df.ns / 1e3).groupby(
        ["algorithm", "iut", "family", "operation", "msg_len", "rep"])["us"]
    return g.agg(n="size", mean="mean", median="median",
                 p95=lambda x: float(np.percentile(x, pct))).reset_index()


def across_runs(runs: pd.DataFrame) -> pd.DataFrame:
    """Equation (9) and (10): aggregate the R run-level statistics."""
    g = runs.groupby(["algorithm", "iut", "family", "operation", "msg_len"])
    out = g.agg(R=("rep", "nunique"), N=("n", "first"),
                mean_us=("mean", "mean"),
                sd_us=("mean", lambda x: float(np.std(x, ddof=1)) if len(x) > 1 else float("nan")),
                median_us=("median", "mean"), p95_us=("p95", "mean")).reset_index()
    out["throughput_ops_s"] = 1e6 / out["mean_us"]
    return out


def sizes_table(sides: list[dict]) -> pd.DataFrame:
    rows = {}
    for s in sides:
        if s.get("status") != "ok":
            continue
        key = (s["algorithm"], s["iut"])
        if key in rows:
            continue
        sz = s["sizes"]
        get = lambda k: sz[k]["max"] if k in sz else np.nan  # noqa: E731
        rows[key] = {
            "algorithm": s["algorithm"], "iut": s["iut"], "family": s["family"], "kind": s["kind"],
            "nist_category": s.get("nist_category"),
            "public_key_B": get("public_key"), "secret_key_B": get("secret_key"),
            "secret_key_fips_B": FIPS_EXPANDED_SK.get(s["algorithm"], get("secret_key")),
            "ciphertext_B": get("ciphertext"), "shared_secret_B": get("shared_secret"),
            "signature_B": get("signature"),
            "signature_mean_B": sz["signature"]["mean"] if "signature" in sz else np.nan,
            "encoding": s.get("encoding_note", ""),
        }
    t = pd.DataFrame(rows.values())
    t["wire_B"] = np.where(t.kind == "kem", t.public_key_B + t.ciphertext_B,
                           t.public_key_B + t.signature_B)
    return t


def rss_table(sides: list[dict]) -> pd.DataFrame:
    d = pd.DataFrame([{"algorithm": s["algorithm"], "iut": s["iut"], "family": s["family"],
                       "rep": s["spec"]["rep"], "baseline": s["rss_baseline_bytes"],
                       "peak": s["rss_peak_bytes"], "delta": s["rss_delta_bytes"]}
                      for s in sides if s.get("status") == "ok"])
    g = d.groupby(["algorithm", "iut", "family"])
    return g.agg(R=("rep", "nunique"), peak_rss_MiB=("peak", lambda x: x.mean() / 2**20),
                 delta_rss_KiB=("delta", lambda x: x.mean() / 2**10),
                 delta_rss_sd_KiB=("delta", lambda x: x.std(ddof=1) / 2**10 if len(x) > 1 else np.nan)
                 ).reset_index()


def overhead_ratios(lat: pd.DataFrame, sizes: pd.DataFrame, rss: pd.DataFrame,
                    use_cases: list[dict]) -> pd.DataFrame:
    """Equation (11) for each paired use case U1-U3 (metric M9)."""
    rows = []
    for u in use_cases:
        def lat_sum(alg):
            L = u.get("message_length")
            sub = lat[(lat.algorithm == alg) & lat.operation.isin(u["latency_ops"])]
            if L is not None:
                sub = sub[(sub.msg_len == L) | (sub.operation == "KeyGen")]
            if set(sub.operation) != set(u["latency_ops"]):
                return np.nan
            return float(sub.groupby("operation")["median_us"].first().sum())

        def bytes_sum(alg):
            r = sizes[sizes.algorithm == alg]
            if r.empty:
                return np.nan
            col = {"public_key": "public_key_B", "ciphertext": "ciphertext_B",
                   "signature": "signature_B", "secret_key": "secret_key_B"}
            return float(sum(r.iloc[0][col[o]] for o in u["size_objects"]))

        def rss_of(alg):
            r = rss[rss.algorithm == alg]
            return float(r.iloc[0]["delta_rss_KiB"]) if not r.empty else np.nan

        for metric, fn, unit in (("latency (sum of median)", lat_sum, "us"),
                                 ("bytes on wire", bytes_sum, "B"),
                                 ("incremental peak RSS", rss_of, "KiB")):
            p, c = fn(u["pqc"]), fn(u["classical"])
            rows.append({"use_case": u["id"], "name": u["name"], "pqc": u["pqc"],
                         "classical": u["classical"], "metric": metric, "unit": unit,
                         "M_pqc": p, "M_classical": c,
                         "rho": p / c if c and not np.isnan(c) and c > 0 else np.nan})
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------- output
def _tex(df: pd.DataFrame, path: Path, caption: str, label: str, fmt: dict | None = None):
    fmt = fmt or {}
    d = df.copy()
    for c, f in fmt.items():
        if c in d:
            d[c] = d[c].map(lambda v, f=f: "--" if pd.isna(v) else f.format(v))
    def esc(v) -> str:
        s = "--" if (not isinstance(v, str) and pd.isna(v)) else str(v)
        for a, b in (("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"), ("_", r"\_"),
                     ("#", r"\#"), ("$", r"\$"), ("µ", r"$\mu$")):
            s = s.replace(a, b)
        return s

    num = [pd.api.types.is_numeric_dtype(df[c]) for c in df.columns]
    spec = "".join("r" if n else "l" for n in num)
    lines = [r"\begin{table}[ht]", r"\centering", f"\\caption{{{caption}}}", f"\\label{{{label}}}",
             r"\small", f"\\begin{{tabular}}{{@{{}}{spec}@{{}}}}", r"\toprule",
             " & ".join(esc(c) for c in d.columns) + r" \\", r"\midrule"]
    lines += [" & ".join(esc(v) for v in row) + r" \\" for row in d.itertuples(index=False)]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def _figures(lat: pd.DataFrame, sizes: pd.DataFrame, out: Path, title_suffix: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    plt.rcParams.update({"font.size": 8.5, "axes.edgecolor": INK_2, "axes.labelcolor": INK,
                         "xtick.color": INK_2, "ytick.color": INK_2, "axes.titlecolor": INK,
                         "axes.spines.top": False, "axes.spines.right": False})
    legend = [Patch(color=PQC_COLOR, label="PQC (FIPS 203/204)"),
              Patch(color=CLASSICAL_COLOR, label="Classical baseline")]

    # F1: median latency per operation, small multiples, log scale
    for kind, ops, fname in (("kem", ["KeyGen", "Encaps", "Decaps"], "F1a_kem_latency"),
                             ("sig", ["KeyGen", "Sign", "Verify"], "F1b_sig_latency")):
        sub_s = sizes[sizes.kind == kind]
        algs = sorted(sub_s.algorithm, key=lambda a: (sub_s.set_index("algorithm").family[a] != "pqc",
                                                      _natural(a)))
        if not algs:
            continue
        fig, axes = plt.subplots(1, 3, figsize=(7.2, 0.28 * len(algs) + 1.2), sharey=True)
        for ax, op in zip(axes, ops):
            sub = lat[(lat.operation == op) & lat.algorithm.isin(algs)]
            if kind == "sig" and op != "KeyGen":
                sub = sub[sub.msg_len == 1024]
            sub = sub.set_index("algorithm").reindex(algs)
            y = np.arange(len(algs))
            colors = [PQC_COLOR if f == "pqc" else CLASSICAL_COLOR for f in sub.family.fillna("")]
            ax.barh(y, sub.median_us, color=colors, height=0.62, edgecolor="white", linewidth=1)
            ax.set_xscale("log")
            ax.set_title(op + (" (1 KiB msg)" if kind == "sig" and op != "KeyGen" else ""), fontsize=8.5)
            ax.grid(axis="x", color=GRID, linewidth=0.6)
            ax.set_axisbelow(True)
            ax.set_yticks(y, algs)
            ax.invert_yaxis()
            ax.tick_params(axis="y", length=0)
            ax.set_xlabel("median latency (µs, log)")
        fig.legend(handles=legend, loc="upper center", ncol=2, frameon=False,
                   bbox_to_anchor=(0.5, 1.0))
        fig.suptitle(None)
        fig.tight_layout(rect=(0, 0, 1, 0.93))
        for ext in ("png", "pdf"):
            fig.savefig(out / f"{fname}.{ext}", dpi=200)
        plt.close(fig)

    # F2: bytes on the wire per exchange (pk + ct, or pk + sig)
    d = sizes.sort_values(["kind", "wire_B"])
    fig, ax = plt.subplots(figsize=(6.2, 0.26 * len(d) + 1.0))
    y = np.arange(len(d))
    ax.barh(y, d.wire_B, color=[PQC_COLOR if f == "pqc" else CLASSICAL_COLOR for f in d.family],
            height=0.62, edgecolor="white", linewidth=1)
    ax.set_xscale("log")
    ax.set_yticks(y, [f"{a}  ({'pk+ct' if k == 'kem' else 'pk+sig'})" for a, k in zip(d.algorithm, d.kind)])
    ax.invert_yaxis()
    ax.tick_params(axis="y", length=0)
    for yi, v in zip(y, d.wire_B):
        ax.text(v * 1.08, yi, f"{int(v):,} B", va="center", fontsize=7, color=INK_2)
    ax.set_xlim(right=float(d.wire_B.max()) * 2.2)
    ax.set_ylim(len(d) - 0.5, -1.3)
    ax.axvline(1500, color=INK_2, linestyle=(0, (3, 3)), linewidth=0.8)
    ax.text(1500 * 1.05, -1.0, "1500 B Ethernet MTU", fontsize=7, color=INK_2, va="center")
    ax.grid(axis="x", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.set_xlabel("bytes on the wire per exchange (log)")
    fig.legend(handles=legend, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.0))
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    for ext in ("png", "pdf"):
        fig.savefig(out / f"F2_wire_size.{ext}", dpi=200)
    plt.close(fig)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyse(session_dir: Path, out_dir: Path | None = None, figures: bool = True) -> Path:
    session_dir = Path(session_dir)
    df, sides, meta = load_session(session_dir)
    proto = meta["protocol_snapshot"]
    pct = int(proto["run"].get("percentile", 95))
    official = meta.get("official", False)
    out = Path(out_dir) if out_dir else (
        ROOT / ("data/processed" if official else "sandbox") / f"{session_dir.name}_processed")
    out.mkdir(parents=True, exist_ok=True)

    runs = run_level(df, pct)
    lat = across_runs(runs)
    sizes = sizes_table(sides)
    rss = rss_table(sides)
    rho = overhead_ratios(lat, sizes, rss, proto.get("use_case", []))

    runs.to_csv(out / "run_level.csv", index=False)
    t1 = lat[["algorithm", "iut", "family", "operation", "msg_len", "R", "N",
              "mean_us", "sd_us", "median_us", "p95_us"]]
    t2 = lat[["algorithm", "iut", "operation", "msg_len", "throughput_ops_s"]]
    t3 = sizes[["algorithm", "iut", "nist_category", "public_key_B", "secret_key_B", "secret_key_fips_B",
                "ciphertext_B", "shared_secret_B", "signature_B", "wire_B", "encoding"]]
    tables = {"T1_latency": t1, "T2_throughput": t2, "T3_sizes": t3, "T4_memory": rss, "T5_overhead": rho}
    for name, t in tables.items():
        t.to_csv(out / f"{name}.csv", index=False)

    tag = f"Protocol {meta['protocol_id']}, session {meta['session']}"
    _tex(t1.drop(columns=["family"]), out / "T1_latency.tex", "M1 latency in $\\mu$s (" + tag + ").", "tab:t1",
         {c: "{:,.1f}" for c in ("mean_us", "sd_us", "median_us", "p95_us")})
    _tex(t2, out / "T2_throughput.tex", f"M2 single-thread throughput, ops/s ({tag}).", "tab:t2",
         {"throughput_ops_s": "{:,.0f}"})
    _tex(t3.drop(columns=["encoding"]), out / "T3_sizes.tex", f"M3--M7 encoded object sizes, bytes ({tag}).",
         "tab:t3", {c: "{:,.0f}" for c in t3.columns if c.endswith("_B")} | {"nist_category": "{:.0f}"})
    _tex(rss, out / "T4_memory.tex", f"M8 peak and incremental RSS ({tag}).", "tab:t4",
         {"peak_rss_MiB": "{:.1f}", "delta_rss_KiB": "{:,.0f}", "delta_rss_sd_KiB": "{:,.0f}"})
    _tex(rho.drop(columns=["name"]), out / "T5_overhead.tex", f"M9 overhead ratios $\\rho_u$ ({tag}).",
         "tab:t5", {"M_pqc": "{:,.1f}", "M_classical": "{:,.1f}", "rho": "{:.2f}"})

    if figures:
        _figures(lat, sizes, out, tag)

    env = meta["environment"]
    summary = {
        "session": meta["session"], "official": official, "protocol_id": meta["protocol_id"],
        "protocol_sha256": meta["protocol_sha256"], "repetitions": meta["repetitions"],
        "environment": env,
        "timer_overhead_ns_median": float(np.median([s["timer_overhead_ns_median"]
                                                     for s in sides if s.get("status") == "ok"])),
        "correctness": {f"{s['algorithm']}|{s['iut']}|r{s['spec']['rep']}": s["correctness"]["pass_rate"]
                        for s in sides},
        "latency": lat.to_dict(orient="records"),
        "sizes": sizes.to_dict(orient="records"),
        "memory": rss.to_dict(orient="records"),
        "overhead": rho.to_dict(orient="records"),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=float))

    manifest = {
        "session": meta["session"], "protocol_sha256": meta["protocol_sha256"],
        "raw": {p.name: sha256(p) for p in sorted(session_dir.iterdir()) if p.is_file()},
        "processed": {p.name: sha256(p) for p in sorted(out.iterdir())
                      if p.is_file() and p.name != "manifest.json"},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return out
