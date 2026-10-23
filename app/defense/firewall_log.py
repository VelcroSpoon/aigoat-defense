"""One live event log for the three firewalls: KB, action and leak.

The admin page at /admin/kb-firewall reads it, so one screen shows every
poisoned chunk dropped, every action refused and every leak stopped. It is a
short in-memory ring that a restart clears; the action firewall also keeps its
JSON-lines audit file, which survives restarts.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, deque
from typing import Any

logger = logging.getLogger(__name__)

FIREWALLS = ("kb", "action", "leak")
_MAX_EVENTS = 300

_events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_counts: dict[str, Counter[str]] = {name: Counter() for name in FIREWALLS}
_lock = threading.Lock()


def record(firewall: str, **event: Any) -> dict[str, Any]:
    """Add one decision to the log. ``event["action"]`` is what was done."""
    entry = {"firewall": firewall, "at": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
    with _lock:
        _events.appendleft(entry)
        _counts.setdefault(firewall, Counter())[str(entry.get("action") or "event")] += 1
    logger.info("firewall %s", entry)
    return entry


def recent(limit: int | None = None, firewall: str | None = None) -> list[dict[str, Any]]:
    """Newest first, optionally only one firewall's events."""
    with _lock:
        items = list(_events)
    if firewall is not None:
        items = [e for e in items if e.get("firewall") == firewall]
    return items if limit is None else items[:limit]


def counts(firewall: str) -> dict[str, int]:
    with _lock:
        return dict(_counts.get(firewall, Counter()))


def clear() -> None:
    with _lock:
        _events.clear()
        for counter in _counts.values():
            counter.clear()
