# Architecture decision log

Each significant decision is recorded as an Architecture Decision Record (ADR) in
[Michael Nygard's format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions):
**Status, Context, Decision, Consequences**. Records are never rewritten; a later decision that
replaces one gets a new record and marks the old one *Superseded*.

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted | 2026-10-22 |
| [0002](0002-enforce-in-code-not-with-an-llm-judge.md) | Enforce in code, not with an LLM judge | Accepted | 2026-10-19 |
| [0003](0003-build-on-the-control-pipeline.md) | Build the chat layers on AI Goat's control pipeline | Accepted | 2026-10-20 |
| [0004](0004-one-shared-normalizer.md) | One shared normalizer for all three layers | Accepted | 2026-10-22 |
| [0005](0005-noisy-or-risk-scoring.md) | Score KB text with weighted signals and noisy-OR | Accepted | 2026-10-20 |
| [0006](0006-score-untrusted-chunks-together.md) | Score untrusted retrieved chunks together | Accepted | 2026-10-22 |
| [0007](0007-compare-replies-with-the-real-system-prompt.md) | Detect leaks by comparing replies with the real system prompt | Accepted | 2026-10-22 |
| [0008](0008-release-streams-sentence-by-sentence.md) | Release streamed replies one checked sentence at a time | Accepted | 2026-10-22 |
| [0009](0009-one-event-log-for-three-firewalls.md) | One event log for the three firewalls | Accepted | 2026-10-22 |
| [0010](0010-level-zero-stays-vulnerable.md) | Level 0 stays vulnerable; every layer has a runtime switch | Accepted | 2026-10-20 |

## How to add one

1. Copy the newest file, give it the next number and a short kebab-case title.
2. Fill in Status (`Proposed` while under discussion), Context, Decision and Consequences.
3. Add a row to the table above and link it from the architecture document if it changes a
   building block.
