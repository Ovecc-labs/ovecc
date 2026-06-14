# ovecc-ai

## Purpose

`ovecc-ai` is the explanation layer. Ovecc's intelligence is deterministic; an LLM is never required and is never part of the analysis. This crate turns a `ContextSlice` into a readable architectural narrative.

## DeterministicExplainer

The shipped provider, `DeterministicExplainer`, implements the `ExplanationProvider` contract and does the work entirely offline: it reads nothing but the slice and emits no network traffic, so the same input always produces the same explanation. `ovecc explain <target>` produces a Markdown report describing:

- the component's architectural role, characterized from its fan-in and fan-out (isolated, entry point, foundational, or intermediary);
- its dependencies and dependents;
- its change impact (blast radius), illustrated by the traced internal paths;
- its findings, ordered most-severe first.

Every sentence is grounded in an explicit fact from the slice — the traceability rule applies to explanations as well, so no claim appears that the slice does not support.

## Extensibility

An LLM-backed provider can be added later behind the same `ExplanationProvider` trait. When none is configured, or one fails, this deterministic provider is the fallback, so `ovecc explain` always works. The crate depends only on `ovecc-core`.
