"""CLI: jev-sanitizer {ask,dry-run,models,sanitize}. Request JSON on stdin.

Exit codes: 0 ok · 1 invalid request/config · 2 blocked · 3 unavailable.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .client import JevClient
from .config import load_config
from txt_sanitizer import Sanitizer

EXIT = {"ok": 0, "blocked": 2, "unavailable": 3}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="jev-sanitizer", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--provider", choices=["typesafe", "vercel"])
    ap.add_argument("--model")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("ask", "dry-run"):
        p = sub.add_parser(name, help="request JSON on stdin: {state, questions, origin?}")
        p.add_argument("--origin", default="cli")
    sub.add_parser("models")
    sub.add_parser("sanitize", help="sanitize plain text from stdin (offline, nothing is sent)")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "sanitize":
            cfg = load_config(provider=args.provider, model=args.model)  # same rules ask would apply
            clean, report = Sanitizer(cfg.extra_masks, cfg.extra_blocks, cfg.max_chars, ner=cfg.ner).sanitize(sys.stdin.read())
            print(clean, end="")
            print(json.dumps({"masks": report.masks, "blocked": report.blocked}), file=sys.stderr)
            return 0 if report.ok else 2
        client = JevClient(provider=args.provider, model=args.model)
        if args.cmd == "models":
            out = client.models()
        else:
            req = json.load(sys.stdin)
            if args.cmd == "ask":
                out = client.ask(req.get("state"), req.get("questions"), req.get("model"), req.get("origin", args.origin))
            else:
                out = client.dry_run(req.get("state"), req.get("questions"), req.get("model"))
    except (ValueError, json.JSONDecodeError) as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=1))
    if "can_send" in out:
        return 0 if out["can_send"] else 2
    return EXIT.get(out.get("status"), 0)


if __name__ == "__main__":
    sys.exit(main())
