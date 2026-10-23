# ADR-0010: Level 0 stays vulnerable; every layer has a runtime switch

**Status:** Accepted · **Date:** 2026-10-20

## Context

AI Goat is a training range. Its labs are meant to be broken at Level 0, and a demo has to show each
attack working before it is stopped. Restarting the backend to change a setting would break a live
demo.

## Decision

- The chat firewalls run only at Levels 1 and 2 (AI Goat's rule that Level 0 profiles are empty).
- The KB firewall is off by default in `config/config.yml`.
- Each layer has a switch that changes it in memory at runtime through
  `POST /api/kb-firewall/toggle`, shown as three switches in the admin console; env vars
  `ACTION_FIREWALL_ENABLED` and `LEAK_FIREWALL_ENABLED` set the start-up value.

## Consequences

- Labs behave exactly as upstream at Level 0; tests assert this.
- Demos flip one switch between "attack works" and "attack stopped".
- Runtime switches are process-wide and not persisted; a restart returns to the configured defaults.
