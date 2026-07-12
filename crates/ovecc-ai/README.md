# ovecc-ai

Turns a `ContextSlice` into a readable architectural narrative. Ovecc's
analysis is deterministic; no LLM is required, and none takes part in the
analysis itself.

`DeterministicExplainer` implements the `ExplanationProvider` contract fully
offline: it reads nothing but the slice and emits no network traffic, so the
same input always produces the same explanation. `ovecc explain <target>`
renders a Markdown report covering the component's architectural role
(characterized from its fan-in and fan-out: isolated, entry point,
foundational, or intermediary), its dependencies and dependents, its blast
radius with the traced internal paths, and its findings, most severe first.
Every sentence is grounded in an explicit fact from the slice: no claim
appears that the slice does not support.

An LLM-backed provider can be added later behind the same trait; the
deterministic provider stays the fallback, so `ovecc explain` always works.
The crate depends only on `ovecc-core`.
