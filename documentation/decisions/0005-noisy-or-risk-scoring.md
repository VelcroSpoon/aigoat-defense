# ADR-0005: Score KB text with weighted signals and noisy-OR

**Status:** Accepted · **Date:** 2026-10-20

## Context

AI Goat's original detector is a short list of English regular expressions: any match blocks, no
match passes. It caught 6 of 30 attacks and blocked honest text that mentions passwords. Honest store
policies legitimately say things like "we will never ask for your card number".

## Decision

The scanner finds signals in ten categories (talks to the assistant, asks it to keep quiet, asks for
card/CVV, sends customers to an outside number, ...) in five languages, plus a meaning-based signal
from sentence embeddings. Each category counts once with its weight; a quoted mention counts half.
Signals combine as `risk = 1 − Π(1 − wᵢ)`; text at or above 0.6 is flagged.

## Consequences

- One weak cue never blocks; several independent cues do. Each verdict lists its reasons.
- KB attacks caught: 20% → 97% (patterns + embeddings), 1 of 35 legitimate entries flagged.
- Weights and threshold are hand-tuned on our own set (risk R1); they live in one file
  (`patterns.py`) and one config value (`kb_firewall.risk_threshold`).
