# ADR-0009: One event log for the three firewalls

**Status:** Accepted · **Date:** 2026-10-22

## Context

The KB firewall kept its own in-memory event list; the action firewall wrote only a JSON-lines audit
file. An operator had no single place to see what was stopped, and the demo needed one screen.

## Decision

Add `app/defense/firewall_log.py`: a 300-entry in-memory ring with per-layer counters. All three
layers call `record(firewall, **event)`. The admin API serves it merged or filtered by layer. The
action firewall keeps its JSON-lines audit (it survives restarts) and sends only blocks and
confirmations to the live log, so a reply the leak firewall later refuses is not echoed there.

## Consequences

- One console (`/admin/kb-firewall`) shows all layers, filterable by tab.
- The live log is lost on restart by design; quarantined entries and the action audit persist.
- Secrets are masked before they reach the log.
