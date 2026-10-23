# ADR-0001: Record architecture decisions

**Status:** Accepted · **Date:** 2026-10-22

## Context

Three layers were built by two people on separate branches and then merged. The reasons behind
several choices (why no LLM judge, why noisy-OR, why sentence-by-sentence streaming) lived only in
chat messages and commit text. Judges and future maintainers need to see *why*, not only *what*.

## Decision

Keep one Markdown file per significant decision in `documentation/decisions/`, numbered, in
Nygard's format. Write a new record instead of editing an accepted one.

## Consequences

- Reasons are reviewable next to the code and versioned with it.
- Small cost per decision (a short file).
- Decisions made before this ADR were recorded afterwards from commits and design notes; their dates
  are the dates the code landed.
