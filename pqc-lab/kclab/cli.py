"""Command line: ``python -m kclab <command>``.

  env                         print the machine profile (config sheet)
  freeze --note TEXT          hash config/protocol.toml into config/protocol.lock
  run [--quick] [--sandbox] [--only ALG ...] [--secondary] [--reps R]
  analyse SESSION_DIR         T1-T5, F1-F2, summary.json, manifest.json
  pqra template               blank assessment JSON on stdout
  pqra score FILE [--lab SUMMARY_JSON] [--md OUT.md] [--json OUT.json]
  web [--port 8000]           serve the browser PQRA tool from web/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import PROTOCOL_ID, __version__
from .protocol import ROOT


def _cmd_env(a):
    from .envprofile import profile
    print(json.dumps(profile(), indent=2))


def _cmd_freeze(a):
    from .protocol import freeze
    print(json.dumps(freeze(a.note), indent=2))


def _cmd_run(a):
    from . import harness, protocol
    p = protocol.load()
    out = harness.run_session(p, which="secondary" if a.secondary else "primary", only=a.only,
                              quick=a.quick, sandbox=a.sandbox, reps=a.reps)
    print(out)
    if not a.no_analyse:
        from .analysis import analyse
        print(analyse(out))


def _cmd_analyse(a):
    from .analysis import analyse
    print(analyse(Path(a.session), Path(a.out) if a.out else None, figures=not a.no_figures))


def _cmd_pqra(a):
    from .pqra import roadmap, scoring
    from .pqra.report import markdown
    if a.pqra_cmd == "template":
        print(json.dumps(scoring.template(), indent=2))
        return
    assessment = json.loads(Path(a.file).read_text(encoding="utf-8"))
    lab = json.loads(Path(a.lab).read_text()) if a.lab else None
    from . import protocol
    defaults = protocol.load().raw.get("d4_gate_defaults", {})
    gd = {"kem": defaults.get("kem"), "latency_cap_us": defaults.get("latency_cap_us"),
          "ciphertext_cap_bytes": defaults.get("ciphertext_cap_bytes")}
    res = scoring.score(assessment, lab_summary=lab, gate_defaults={k: v for k, v in gd.items() if v is not None})
    rm = roadmap.build(res, lab)
    md = markdown(assessment, res, rm)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps({"result": res.to_dict(), "roadmap": rm}, indent=2, default=float))
    if not a.md and not a.json:
        sys.stdout.reconfigure(encoding="utf-8")
        print(md)


def _cmd_web(a):
    import functools
    import http.server
    import shutil
    web = ROOT / "web"
    shutil.copy(ROOT / "kclab" / "pqra" / "instrument.json", web / "instrument.json")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(web))
    print(f"PQRA web tool on http://localhost:{a.port}/  (Ctrl+C to stop)")
    http.server.ThreadingHTTPServer(("127.0.0.1", a.port), handler).serve_forever()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kclab", description=f"KingaCrypt PQC lab {__version__} ({PROTOCOL_ID})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("env").set_defaults(fn=_cmd_env)
    f = sub.add_parser("freeze")
    f.add_argument("--note", required=True)
    f.set_defaults(fn=_cmd_freeze)
    r = sub.add_parser("run")
    r.add_argument("--quick", action="store_true", help="tiny N for a smoke test (always sandboxed)")
    r.add_argument("--sandbox", action="store_true")
    r.add_argument("--only", nargs="+", metavar="ALG")
    r.add_argument("--secondary", action="store_true", help="run the cross-check IUT(s) instead")
    r.add_argument("--reps", type=int)
    r.add_argument("--no-analyse", action="store_true")
    r.set_defaults(fn=_cmd_run)
    an = sub.add_parser("analyse")
    an.add_argument("session")
    an.add_argument("--out")
    an.add_argument("--no-figures", action="store_true")
    an.set_defaults(fn=_cmd_analyse)
    pq = sub.add_parser("pqra")
    pqs = pq.add_subparsers(dest="pqra_cmd", required=True)
    pqs.add_parser("template")
    sc = pqs.add_parser("score")
    sc.add_argument("file")
    sc.add_argument("--lab", help="summary.json from a processed lab session")
    sc.add_argument("--md")
    sc.add_argument("--json")
    pq.set_defaults(fn=_cmd_pqra)
    w = sub.add_parser("web")
    w.add_argument("--port", type=int, default=8000)
    w.set_defaults(fn=_cmd_web)
    a = ap.parse_args(argv)
    a.fn(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
