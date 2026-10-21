"""Compare AI Goat's original KB injection regex with the KB Firewall.

Run from the AIGoat root:

    venv/Scripts/python.exe -m eval.kb_firewall.run_benchmark          (Windows)
    venv/bin/python -m eval.kb_firewall.run_benchmark                  (Linux/macOS)

Prints detection rate on attacks and false-positive rate on legitimate
entries, per category, for three detectors:
  1. original   app.rag.injection_detector (what level 2 uses today)
  2. patterns   the firewall without the embedding model
  3. firewall   normalization + patterns + embedding similarity
Add --details to list every miss and false positive.
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict

from app.core.config import get_settings
from app.kb_firewall.scanner import Scanner
from app.kb_firewall.semantic import SemanticScanner
from app.rag.injection_detector import detect_injection
from eval.kb_firewall.dataset import ATTACKS, BENIGN


def _rate(hits: int, total: int) -> str:
    return f"{hits}/{total} ({100 * hits / total:.0f}%)" if total else "-"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--details", action="store_true")
    ap.add_argument("--model", default=None, help="embedding model (default: kb_firewall.semantic_model)")
    args = ap.parse_args()

    cfg = get_settings().kb_firewall
    semantic = SemanticScanner(args.model or cfg.semantic_model, get_settings().rag.embedding_model)
    detectors = {
        "original": lambda t: detect_injection(t)[0],
        "patterns": Scanner(None, threshold=cfg.risk_threshold).scan,
        "firewall": Scanner(semantic, threshold=cfg.risk_threshold, semantic_margin=cfg.semantic_margin).scan,
    }

    rows: dict[str, dict[str, list[int]]] = {name: defaultdict(lambda: [0, 0]) for name in detectors}
    misses: dict[str, list[str]] = defaultdict(list)
    timings: dict[str, float] = {}
    for name, fn in detectors.items():
        start = time.perf_counter()
        for label, items in (("attack", ATTACKS), ("benign", BENIGN)):
            for category, text in items:
                out = fn(text)
                flagged = out if isinstance(out, bool) else out.flagged
                key = f"{label}:{category}"
                rows[name][key][1] += 1
                if flagged:
                    rows[name][key][0] += 1
                if (label == "attack") != flagged:
                    kind = "MISS" if label == "attack" else "FALSE POSITIVE"
                    extra = "" if isinstance(out, bool) else f" risk={out.risk:.2f} {out.reasons}"
                    misses[name].append(f"  {kind} [{category}] {text[:110]!r}{extra}")
        timings[name] = (time.perf_counter() - start) * 1000 / (len(ATTACKS) + len(BENIGN))

    print(f"Embedding model: {semantic.model_name} (requested {args.model or cfg.semantic_model})")
    if semantic.error:
        print(f"  semantic layer unavailable: {semantic.error}")
    keys = sorted({k for r in rows.values() for k in r})
    header = f"{'set':28}" + "".join(f"{n:>18}" for n in detectors)
    print("\n" + header + "\n" + "-" * len(header))
    for key in keys:
        print(f"{key:28}" + "".join(f"{_rate(*rows[n][key]):>18}" for n in detectors))
    print("-" * len(header))
    for label in ("attack", "benign"):
        line = f"{('ALL ' + label + 's'):28}"
        for n in detectors:
            hit = sum(v[0] for k, v in rows[n].items() if k.startswith(label))
            tot = sum(v[1] for k, v in rows[n].items() if k.startswith(label))
            line += f"{_rate(hit, tot):>18}"
        print(line)
    print(f"{'ms per entry':28}" + "".join(f"{timings[n]:>18.1f}" for n in detectors))
    print("\nattack rows = detection rate (higher is better); benign rows = false positives (lower is better)")

    if args.details:
        for name in detectors:
            print(f"\n{name}: {len(misses[name])} errors")
            print("\n".join(misses[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
