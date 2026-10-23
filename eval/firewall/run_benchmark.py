"""Before and after numbers for the action firewall, the leak firewall and the KB split check.

    python -m eval.firewall.run_benchmark

"Before" is the action firewall as it was when both firewalls were first
merged (git ref BASELINE_REF), and AI Goat's stock output moderator. The
baseline column is skipped when git cannot show that ref. Everything runs
offline: no model, no database.
"""
from __future__ import annotations

import asyncio
import importlib.util
import itertools
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from types import ModuleType, SimpleNamespace

from app.defense.control import DefenseStage
from app.defense.controls import action_firewall, ensure_registered
from app.defense.controls.leak_firewall import leak_verdict
from app.defense.output_moderator import OutputModerator
from app.defense.pipeline import defense_pipeline
from app.defense.rejection import get_rejection_response
from app.kb_firewall.firewall import KBFirewall
from app.kb_firewall.scanner import Scanner
from eval.firewall.datasets import ACTION_ATTACKS, ACTION_BENIGN, INPUT, LEAK_ATTACKS, LEAK_BENIGN
from eval.kb_firewall.dataset import ATTACKS as KB_ATTACKS
from eval.kb_firewall.dataset import BENIGN as KB_BENIGN

BASELINE_REF = "90b54a5"  # "Merge christopher/kb-firewall into simon/both-firewalls"
ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "prompts"
STAGE = {INPUT: DefenseStage.INPUT, "output": DefenseStage.OUTPUT}
COUPONS = [SimpleNamespace(code="WELCOME10", target_audience="all"), SimpleNamespace(code="STAFF100", target_audience="staff")]
ACCOUNTS = ["carol", "alice", "bob", "charlie", "frank"]


def _order(order_id: int, total: float, status: str, user_id: int) -> SimpleNamespace:
    return SimpleNamespace(
        id=order_id, custom_order_id=f"ORD-{order_id}", user_id=user_id,
        total_amount=total, final_amount=None, status=status,
    )


CAROL = SimpleNamespace(id=7, username="carol", email="carol@aigoatshop.com", is_staff=False)
CAROL_ORDERS = [
    _order(41, 80.0, "delivered", 7), _order(42, 400.0, "delivered", 7),
    _order(43, 30.0, "pending", 7), _order(1003, 512.5, "pending", 2),
]
ALICE = SimpleNamespace(id=1, username="alice", email="alice@example.com", is_staff=False)
ALICE_ORDERS = [_order(1001, 245.0, "delivered", 1), _order(1002, 89.99, "shipped", 1)]


def _baseline() -> ModuleType | None:
    """The pre-upgrade action firewall, loaded from git."""
    try:
        source = subprocess.run(
            ["git", "show", f"{BASELINE_REF}:app/defense/controls/action_firewall.py"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    path = Path(tempfile.mkdtemp()) / "baseline_action_firewall.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("baseline_action_firewall", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


def _table(rows: list[list[str]], header: list[str]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _rate(hits: int, total: int) -> str:
    return f"{hits}/{total} ({round(100 * hits / total) if total else 0}%)"


# ── action firewall ──────────────────────────────────────────────────


def action_report() -> str:
    now = action_firewall.build_actor(CAROL, CAROL_ORDERS, COUPONS, ACCOUNTS)
    detectors = {"Now": (action_firewall, now)}
    old = _baseline()
    if old is not None:
        detectors = {"Before": (old, old.build_actor(CAROL, CAROL_ORDERS, COUPONS)), **detectors}

    def stopped(module, actor, stage, text) -> bool:
        return module.firewall_verdict(text, STAGE[stage], actor).decision.value != "allow"

    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: dict[str, int] = defaultdict(int)
    for cat, stage, text in ACTION_ATTACKS:
        totals[cat] += 1
        for name, (module, actor) in detectors.items():
            by_cat[cat][name] += stopped(module, actor, stage, text)
    rows = [[cat] + [_rate(by_cat[cat][name], totals[cat]) for name in detectors] for cat in totals]
    rows.append(["**all attacks**"] + [
        _rate(sum(by_cat[c][name] for c in totals), len(ACTION_ATTACKS)) for name in detectors
    ])
    fp = {name: sum(stopped(m, a, s, t) for _, s, t in ACTION_BENIGN) for name, (m, a) in detectors.items()}
    rows.append(["**honest messages blocked**"] + [_rate(fp[name], len(ACTION_BENIGN)) for name in detectors])
    return "### Action firewall (attacks stopped)\n\n" + _table(rows, ["Category", *detectors])


# ── leak firewall ────────────────────────────────────────────────────


class _NoTelemetry:
    """The pipeline logs every refusal to the app database; a benchmark must not."""

    async def log(self, **_: object) -> None:
        return None


async def _leak_results() -> tuple[list[dict[str, tuple[bool, bool]]], list[dict[str, tuple[bool, bool]]]]:
    ensure_registered()
    defense_pipeline.telemetry = _NoTelemetry()
    moderator = OutputModerator()
    refusal = get_rejection_response("default")
    actor = action_firewall.build_actor(ALICE, ALICE_ORDERS, COUPONS, ACCOUNTS)
    prompts: dict[str, str] = {}

    def prompt(name: str) -> str:
        if name not in prompts:
            prompts[name] = (PROMPTS / f"{name}.md").read_text(encoding="utf-8")
        return prompts[name]

    async def run(reply: str, name: str) -> dict[str, tuple[bool, bool]]:
        """detector -> (changed or refused, refused)"""
        l1, l2 = moderator.moderate(reply, 1), moderator.moderate(reply, 2)
        now = await defense_pipeline.review_output(reply, 1, context={"actor": actor, "system_prompt": prompt(name)})
        leaked = leak_verdict(reply, prompt(name), actor).leaked
        return {
            "Stock Level 1 output": (l1 != reply, l1 == refusal),
            "Stock Level 2 output": (l2 != reply, l2 == refusal),
            "Leak firewall alone": (leaked, leaked),
            "Level 1 now (all output controls)": (now.message != reply, not now.allowed),
        }

    attacks = [await run(reply, name) for _, name, reply in LEAK_ATTACKS]
    benign = [await run(reply, name) for _, name, reply in LEAK_BENIGN]
    return attacks, benign


def leak_report() -> str:
    attacks, benign = asyncio.run(_leak_results())
    names = list(attacks[0])
    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: dict[str, int] = defaultdict(int)
    for (cat, _, _), result in zip(LEAK_ATTACKS, attacks):
        totals[cat] += 1
        for detector, (caught, _refused) in result.items():
            by_cat[cat][detector] += caught
    rows = [[cat] + [_rate(by_cat[cat][d], totals[cat]) for d in names] for cat in totals]
    rows.append(["**all leaks**"] + [_rate(sum(by_cat[c][d] for c in totals), len(LEAK_ATTACKS)) for d in names])
    fp = defaultdict(int)
    for result in benign:
        for detector, (_caught, refused) in result.items():
            fp[detector] += refused
    rows.append(["**honest replies refused**"] + [_rate(fp[d], len(LEAK_BENIGN)) for d in names])
    note = (
        "\n\nA stock moderator counts as catching a leak when it changes the reply at all "
        "(for example masking an email address)."
    )
    return "### Leak firewall (leaks stopped)\n\n" + _table(rows, ["Category", *names]) + note


# ── KB firewall: instructions split across entries ───────────────────


def split_report() -> str:
    fw = KBFirewall()
    fw._scanner = Scanner(None)
    fw.enabled, fw.mode = True, "block"

    def chunk(text: str) -> dict:
        return {"content": text, "trust_tier": "user"}

    def blocked(*texts: str) -> bool:
        return bool(fw.filter_chunks([chunk(t) for t in texts], surface="eval")[1])

    honest = [t for _, t in KB_BENIGN if not fw.scan(t).flagged]
    pairs = list(itertools.combinations(honest, 2))
    triples = list(itertools.combinations(honest, 3))
    split = re.compile(r"(?<=[.!?:])\s+")
    halves = []
    for _, text in KB_ATTACKS:
        parts = split.split(text)
        for i in range(1, len(parts)):
            a, b = " ".join(parts[:i]), " ".join(parts[i:])
            if not fw.scan(a).flagged and not fw.scan(b).flagged and (fw.scan(a).signals or fw.scan(b).signals):
                halves.append((a, b))
    rows = [
        ["Attacks cut in two, both halves pass alone", _rate(sum(blocked(a, b) for a, b in halves), len(halves))],
        ["Pairs of honest entries blocked", _rate(sum(blocked(*p) for p in pairs), len(pairs))],
        ["Triples of honest entries blocked", _rate(sum(blocked(*t) for t in triples), len(triples))],
    ]
    return "### KB firewall: split payloads (patterns only)\n\n" + _table(rows, ["Case", "Blocked"])


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    print(action_report(), leak_report(), split_report(), sep="\n\n")


if __name__ == "__main__":
    main()
