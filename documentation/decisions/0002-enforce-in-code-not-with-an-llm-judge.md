# ADR-0002: Enforce in code, not with an LLM judge

**Status:** Accepted · **Date:** 2026-10-19

## Context

A common defense is a second language model that judges inputs or outputs. In AI Goat:

- the judge would read the same untrusted text, so it can be injected the same way;
- it costs one extra model call per check on a laptop running Mistral 7B locally;
- it cannot know facts such as who owns order #1003 or which secrets the prompt contained.

## Decision

Every block decision is made by ordinary code using facts the attacker cannot change:

- **Action firewall:** the user row behind the JWT, that user's orders, the coupon table, the list of
  account names.
- **Leak firewall:** the system prompt that was actually sent on that turn.
- **KB firewall:** who wrote the entry (trust tier) and its scan result.

Patterns and embeddings are used only to *find* the action, secret or instruction.

## Consequences

- Deterministic, explainable decisions; every block carries a human-readable reason.
- No extra model calls; checks take under a millisecond (embeddings for new KB chunks excepted).
- Paraphrases that the patterns do not find are missed (see risks R2 and R3 in the architecture
  document). An LLM judge for borderline scores remains a possible later addition.
