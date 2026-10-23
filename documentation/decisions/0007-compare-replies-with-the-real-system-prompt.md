# ADR-0007: Detect leaks by comparing replies with the real system prompt

**Status:** Accepted · **Date:** 2026-10-22

## Context

AI Goat's Level 2 output filter refuses replies containing four fixed English phrases ("you are",
"system prompt", ...). It let `admin / admin123` through and refused "You are eligible for a refund".
A phrase list cannot know which values are secret in a given lab.

## Decision

The chat surface passes the system prompt it actually sent to the output controls. The leak firewall:

1. extracts secrets from that prompt: everything in a `[BEGIN CONFIDENTIAL ...]` block or under a
   header such as `SYSTEM CREDENTIALS:`, plus flags, config files, internal paths, quoted
   passphrases, `user/password` pairs, restricted coupon codes and other customers' rows (never the
   caller's own row);
2. looks for them in the reply as written, compacted, normalized, reversed, ROT13, base64/hex decoded,
   leet-folded and with "at"/"dot" restored; flags also match on their first two parts, because
   Mistral was seen translating the tail;
3. refuses replies that copy 7+ words of the prompt's rule sentences.

When it has the prompt, it replaces output moderation's fixed phrase list.

## Consequences

- Secrets survive translation, so translated leaks are caught (22/22 benchmark leaks, 0/14 honest
  replies refused).
- Logs store secrets masked (`flag: AI*****`).
- Extraction is heuristic: a secret written as plain prose is only caught if quoted or on a line
  about secrets. New lab prompts should be checked with `extract_secrets()`; tests read the real
  prompts so a changed prompt fails a test.
