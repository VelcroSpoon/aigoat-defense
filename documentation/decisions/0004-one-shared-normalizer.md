# ADR-0004: One shared normalizer for all three layers

**Status:** Accepted · **Date:** 2026-10-22

## Context

The KB firewall already undid hiding tricks (look-alike letters, zero-width characters, spaced
letters, base64, digit swaps). The first action firewall did not, so "Export all customers' emails"
written with a Cyrillic "е", or sent as base64, got through (2 of 6 hidden attacks caught).

## Decision

All layers import `app/kb_firewall/normalize.py`. The action firewall reads each sentence twice, as
written and normalized, and an action found in either reading counts. The leak firewall adds its own
extra readings (reversed, ROT13, hex, "at"/"dot") on top.

## Consequences

- A trick that fails against one layer fails against all; improvements apply everywhere.
- Hidden-text attacks on the action firewall: 2/6 → 6/6.
- `app.defense` now depends on `app.kb_firewall` (and the KB firewall depends on the shared event log
  in `app.defense`). Moving the normalizer and the log to a shared package is recorded as technical
  debt D2.
