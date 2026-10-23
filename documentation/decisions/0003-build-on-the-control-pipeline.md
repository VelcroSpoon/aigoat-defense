# ADR-0003: Build the chat layers on AI Goat's control pipeline

**Status:** Accepted · **Date:** 2026-10-20

## Context

AI Goat already has a defense architecture: each defense is a `DefenseControl` with an id, the
stages it applies to and a `verifies` contract. `config/defense_profiles.yml` lists which controls run
for each surface and level, and `run_chain()` executes them in order, stopping at the first deny.
Writing a separate proxy or rewriting the chat endpoint would duplicate this and break labs.

## Decision

Implement the action and leak firewalls as controls (`action.firewall`, `leak.firewall`), register
them in `app/defense/controls/__init__.py`, and list them in the `chat.cracky` profiles for Levels 1
and 2, before `output.moderate`. The KB firewall, which works on retrieved chunks rather than on a
message, is called from the three places that put KB text in a prompt.

## Consequences

- No change to the chat flow for Level 0; labs keep working.
- Order matters and is explicit in YAML: action before leak before moderation.
- The pipeline needed one extension: `review_output()` returns which control acted, so the defense
  panel credits the right control.
- The KB firewall's three call sites must stay in sync (Cracky chat, challenge chat, RAG service).
