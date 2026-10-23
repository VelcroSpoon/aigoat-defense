# ADR-0008: Release streamed replies one checked sentence at a time

**Status:** Accepted · **Date:** 2026-10-22

## Context

The chat streams tokens to the browser. Output checks ran only after the whole reply had streamed,
so a leaked secret or a claimed refund was visible for a moment before being replaced.

## Decision

At Levels 1 and 2, `chat_stream` buffers tokens and, at each sentence end (or after 400 characters
without one), runs `review_output()` on all text so far with `preview=True`. It sends only the new
part; if a control refuses, it sends a `replace` event with the refusal and closes the Ollama stream.
The frontend already supported `replace`, so it needed no change. Level 0 streams raw tokens.

## Consequences

- Nothing that will be blocked ever reaches the screen; generation stops early on a refusal.
- Text appears sentence by sentence instead of word by word at Levels 1 and 2.
- Checks run several times per reply; the controls are cheap and preview mode logs only refusals, so
  the audit and telemetry are not flooded.
