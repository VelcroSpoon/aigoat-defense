"""action.firewall — permissions for sensitive chat actions, enforced in code.

The chat model can be talked into *saying* it refunded someone else's order or
applied a staff-only coupon. This control never asks the model whether an
action is allowed. It finds the action in the user's request (input stage) or
in the model's reply (output stage) and checks it against facts the prompt
cannot change: the user row behind the JWT, the orders that user owns in the
database, and the coupon table.

Each action gets one of three decisions:
  allow    the action is within the caller's own rights
  confirm  a person must approve it first; nothing has happened yet
  block    the caller may not do this; the text is replaced with a refusal

Every decision on a detected action is appended to a JSON-lines audit log.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.defense.control import (
    ControlAction,
    ControlOutcome,
    DefenseControl,
    DefenseDecision,
    DefenseStage,
)
from app.defense.rejection import get_rejection_response

logger = get_logger(__name__)

BLOCK_MESSAGE = get_rejection_response("action_blocked")
CONFIRM_MESSAGE = get_rejection_response("action_needs_confirmation")

# ── Policy limits ────────────────────────────────────────────────────
CUSTOMER_REFUND_LIMIT = 250.00
REFUNDABLE_STATUSES = frozenset({"delivered", "shipped"})


class Decision(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


_SEVERITY = {Decision.ALLOW: 0, Decision.CONFIRM: 1, Decision.BLOCK: 2}


# ── Who is asking (built from the database, never from the prompt) ───


@dataclass(frozen=True)
class OrderFacts:
    order_id: int
    paid: float
    status: str


@dataclass(frozen=True)
class ActorContext:
    user_id: int
    username: str
    is_staff: bool
    orders: Mapping[str, OrderFacts]  # every id a user might type for an order they own
    coupons: Mapping[str, str]  # upper-case code -> target_audience


def build_actor(user: Any, orders: Iterable[Any], coupons: Iterable[Any]) -> ActorContext:
    """Snapshot the caller's identity, own orders and the coupon table.

    ``orders`` may contain other users' rows; only the caller's are kept.
    """
    own: dict[str, OrderFacts] = {}
    for order in orders:
        if order.user_id != user.id:
            continue
        paid = order.final_amount if order.final_amount is not None else order.total_amount
        facts = OrderFacts(order.id, float(paid), (order.status or "").lower())
        own[str(order.id)] = facts
        custom = re.search(r"(\d+)$", order.custom_order_id or "")
        if custom:
            own[custom.group(1)] = facts
    return ActorContext(
        user_id=user.id,
        username=user.username,
        is_staff=bool(user.is_staff),
        orders=own,
        coupons={c.code.upper(): c.target_audience for c in coupons},
    )


# ── Detection: what action does this text request or claim? ──────────


@dataclass(frozen=True)
class DetectedAction:
    kind: str  # refund | coupon | export | status_change | data_access
    order_ids: tuple[str, ...] = ()
    amount: float | None = None
    codes: tuple[str, ...] = ()
    scope: str = ""  # export: "self" or "all"
    new_status: str = ""
    subject: str = ""  # data_access: whose data ("*" = everyone)


_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_ORDER_ID = re.compile(
    r"\bORD-(\d+)"
    r"|\border\s+(?:#\s?|(?:id|no\.?|number)\s*#?\s*)(\d+)"
    r"|\border\s+(\d{3,})\b"
    r"|#(\d{3,})\b",
    re.I,
)
_AMOUNT = re.compile(r"\$\s?(\d[\d,]*(?:\.\d{1,2})?)")
_REFUND = re.compile(r"\brefund", re.I)
_COUPON_WORD = re.compile(r"\b(?:coupon|promo|discount|voucher|code)\b|\bappl", re.I)
_CODE = re.compile(r"\b[a-z]{3,}\d{1,4}\b", re.I)
_EXPORT = re.compile(r"\bexport", re.I)
_EXPORT_ALL = re.compile(r"\b(?:all|every|entire|bulk|customers|users|database)\b", re.I)
_EXPORT_SELF = re.compile(r"\b(?:my|mine|own|your)\b", re.I)
_STATUS_CHANGE = re.compile(
    r"\b(?:update|change|set|mark|modif)\w*\b.{0,40}?\bstatus\b"
    r"|\bstatus\b.{0,40}?\b(?:updated|changed|set|marked)\b",
    re.I,
)
_NEW_STATUS = re.compile(
    r"\b(?:to|as)\s+[\"']?(pending|processing|shipped|delivered|cancell?ed|refunded)\b", re.I
)
_CANCEL = re.compile(
    r"\bcancel\w*\s+(?:my\s+|your\s+|the\s+|this\s+)?order\b"
    r"|\border\b[^.]{0,20}?\b(?:has been|was|is now)\s+cancell?ed\b",
    re.I,
)
_BULK_DATA = re.compile(
    r"\b(?:all|every|other)\s+(?:the\s+)?(?:customer|user|account)s?(?:'s?)?\s+"
    r"(?:data|records?|details|info\w*|emails?|orders?|accounts?|list)\b",
    re.I,
)
_ORDERS_FOR = re.compile(r"\borders?\s+(?:for|of|belonging\s+to|placed\s+by)\s+([a-z][\w.-]*)", re.I)
_NOT_A_NAME = frozenset({"me", "my", "mine", "myself", "you", "your", "the", "this", "that", "a", "an", "our", "us"})
# In a reply, an action only counts when the sentence says it was done.
_CLAIM = re.compile(
    r"\b(?:i(?:'ve| have)|we(?:'ve| have)|has been|have been|is now|successfully)\b"
    r"|\b(?:processed|approved|issued|applied|exported|updated|changed|marked|cancell?ed|refunded|completed|confirmed)\b",
    re.I,
)


def _order_ids(sentence: str) -> tuple[str, ...]:
    found = (next(g for g in m.groups() if g) for m in _ORDER_ID.finditer(sentence))
    return tuple(dict.fromkeys(found))


def _amount(sentence: str) -> float | None:
    match = _AMOUNT.search(sentence)
    return float(match.group(1).replace(",", "")) if match else None


def _codes(sentence: str, known_codes: Iterable[str]) -> tuple[str, ...]:
    found = [m.group(0).upper() for m in _CODE.finditer(sentence)]
    found += [code for code in known_codes if re.search(rf"\b{re.escape(code)}\b", sentence, re.I)]
    return tuple(dict.fromkeys(found))


def detect_actions(text: str, stage: DefenseStage, known_codes: Iterable[str] = ()) -> list[DetectedAction]:
    """Sentence by sentence, so an order id is tied to the verb next to it."""
    known_codes = tuple(known_codes)
    actions: list[DetectedAction] = []
    for sentence in filter(None, (s.strip() for s in _SENTENCE_SPLIT.split(text))):
        ids = _order_ids(sentence)
        amount = _amount(sentence)
        # A request names an action; a reply must also claim it was done.
        claimed = stage is DefenseStage.INPUT or bool(_CLAIM.search(sentence))

        if claimed and _REFUND.search(sentence) and (ids or amount is not None or stage is DefenseStage.OUTPUT):
            actions.append(DetectedAction("refund", order_ids=ids, amount=amount))

        codes = _codes(sentence, known_codes)
        if claimed and codes and _COUPON_WORD.search(sentence):
            actions.append(DetectedAction("coupon", codes=codes))

        if claimed and _EXPORT.search(sentence):
            scope = "self" if _EXPORT_SELF.search(sentence) and not _EXPORT_ALL.search(sentence) else "all"
            actions.append(DetectedAction("export", scope=scope))

        if claimed and (_STATUS_CHANGE.search(sentence) or _CANCEL.search(sentence)):
            status = _NEW_STATUS.search(sentence)
            new_status = status.group(1).lower() if status else ""
            if _CANCEL.search(sentence) or new_status.startswith("cancel"):
                new_status = "cancelled"
            actions.append(DetectedAction("status_change", order_ids=ids, new_status=new_status))

        named = [m.group(1) for m in _ORDERS_FOR.finditer(sentence) if m.group(1).lower() not in _NOT_A_NAME]
        if _BULK_DATA.search(sentence):
            actions.append(DetectedAction("data_access", subject="*"))
        for name in named:
            actions.append(DetectedAction("data_access", subject=name))
        if ids:
            actions.append(DetectedAction("data_access", order_ids=ids))
    return actions


# ── Policy: may this actor do this action? ───────────────────────────


def _check_refund(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if actor.is_staff:
        for oid in action.order_ids:
            facts = actor.orders.get(oid)
            if facts and action.amount is not None and action.amount > facts.paid:
                return Decision.BLOCK, f"refund exceeds the ${facts.paid:.2f} paid for order {oid}"
        return Decision.CONFIRM, "staff refunds need a second person to confirm"
    if not action.order_ids:
        return Decision.BLOCK, "refund does not name an order on this account"
    for oid in action.order_ids:
        facts = actor.orders.get(oid)
        if facts is None:
            return Decision.BLOCK, f"order {oid} does not belong to this user"
        if facts.status not in REFUNDABLE_STATUSES:
            return Decision.BLOCK, f"order {oid} is {facts.status or 'unknown'} and cannot be refunded"
        amount = action.amount if action.amount is not None else facts.paid
        if amount > facts.paid:
            return Decision.BLOCK, f"refund ${amount:.2f} exceeds the ${facts.paid:.2f} paid for order {oid}"
        if amount > CUSTOMER_REFUND_LIMIT:
            return Decision.BLOCK, f"refund ${amount:.2f} is over the ${CUSTOMER_REFUND_LIMIT:.0f} customer limit"
    return Decision.CONFIRM, "refund of the caller's own order needs staff confirmation"


def _check_coupon(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    for code in action.codes:
        audience = actor.coupons.get(code)
        if audience is None:
            return Decision.BLOCK, f"coupon {code} does not exist"
        if audience == "all" or (audience == "staff" and actor.is_staff):
            continue
        return Decision.BLOCK, f"coupon {code} is restricted to {audience}"
    return Decision.ALLOW, "coupon is available to this user"


def _check_export(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if action.scope == "self":
        return Decision.CONFIRM, "export of the caller's own data needs confirmation"
    if actor.is_staff:
        return Decision.CONFIRM, "bulk export needs a second person to confirm"
    return Decision.BLOCK, "customers cannot export other customers' data"


def _check_status_change(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if actor.is_staff:
        return Decision.CONFIRM, "staff status changes need confirmation"
    if action.new_status == "cancelled" and action.order_ids:
        for oid in action.order_ids:
            facts = actor.orders.get(oid)
            if facts is None or facts.status != "pending":
                return Decision.BLOCK, f"order {oid} is not a pending order of this user"
        return Decision.CONFIRM, "cancelling the caller's own pending order needs confirmation"
    return Decision.BLOCK, "customers cannot change order status"


def _check_data_access(action: DetectedAction, actor: ActorContext) -> tuple[Decision, str]:
    if actor.is_staff:
        return Decision.ALLOW, "staff may look up customers"
    for oid in action.order_ids:
        if oid not in actor.orders:
            return Decision.BLOCK, f"order {oid} belongs to another customer"
    if action.subject and action.subject.lower() != actor.username.lower():
        return Decision.BLOCK, "customers cannot look up other customers' data"
    return Decision.ALLOW, "caller's own data"


_CHECKS = {
    "refund": _check_refund,
    "coupon": _check_coupon,
    "export": _check_export,
    "status_change": _check_status_change,
    "data_access": _check_data_access,
}


@dataclass(frozen=True)
class FirewallVerdict:
    decision: Decision
    reason: str
    actions: tuple[tuple[DetectedAction, Decision, str], ...] = ()


def firewall_verdict(text: str, stage: DefenseStage, actor: ActorContext | None) -> FirewallVerdict:
    """Detect actions in ``text`` and return the strictest decision among them."""
    known_codes = actor.coupons.keys() if actor else ()
    results: list[tuple[DetectedAction, Decision, str]] = []
    for action in detect_actions(text, stage, known_codes):
        if actor is None:
            results.append((action, Decision.BLOCK, "cannot verify who is asking"))
        else:
            results.append((action, *_CHECKS[action.kind](action, actor)))
    if not results:
        return FirewallVerdict(Decision.ALLOW, "no sensitive action")
    _, decision, reason = max(results, key=lambda r: _SEVERITY[r[1]])
    return FirewallVerdict(decision, reason, tuple(results))


# ── Audit log ────────────────────────────────────────────────────────


def _audit(decision: DefenseDecision, actor: ActorContext | None, verdict: FirewallVerdict) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "surface": decision.surface,
        "stage": decision.stage.value,
        "level": decision.level,
        "user_id": actor.user_id if actor else decision.user_id,
        "is_staff": actor.is_staff if actor else None,
        "decision": verdict.decision.value,
        "reason": verdict.reason,
        "actions": [
            {**asdict(action), "decision": result.value, "reason": reason}
            for action, result, reason in verdict.actions
        ],
        "text_preview": decision.payload[:200],
    }
    logger.info("action_firewall %s", record)
    path = Path(get_settings().defense.action_firewall_audit_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("Action firewall audit write failed: %s", exc)


# ── The control ──────────────────────────────────────────────────────


class ActionFirewallControl(DefenseControl):
    id = "action.firewall"
    name = "Action firewall"
    verifies = (
        "Refunds, coupon codes, data exports and order-status changes in the request "
        "or the reply are checked against the caller's own account, role and limits. "
        "Money-moving and bulk actions need staff confirmation; anything outside the "
        "caller's rights is replaced with a refusal. Switch: ACTION_FIREWALL_ENABLED."
    )
    applies_to = (DefenseStage.INPUT, DefenseStage.OUTPUT)

    async def _evaluate(self, decision: DefenseDecision) -> ControlOutcome:
        if not get_settings().defense.action_firewall_enabled:
            return ControlOutcome(action=ControlAction.ALLOW, payload=decision.payload, control_id=self.id)
        actor = decision.context.get("actor")
        verdict = firewall_verdict(decision.payload, decision.stage, actor)
        if verdict.actions:
            _audit(decision, actor, verdict)
        if verdict.decision is Decision.BLOCK:
            return ControlOutcome(
                action=ControlAction.DENY,
                payload=BLOCK_MESSAGE,
                control_id=self.id,
                reason=verdict.reason,
                rejection_key="action_blocked",
            )
        if verdict.decision is Decision.CONFIRM:
            return ControlOutcome(
                action=ControlAction.REQUIRE_APPROVAL,
                payload=CONFIRM_MESSAGE,
                control_id=self.id,
                reason=verdict.reason,
                rejection_key="action_needs_confirmation",
            )
        return ControlOutcome(action=ControlAction.ALLOW, payload=decision.payload, control_id=self.id)
