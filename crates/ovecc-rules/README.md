# ovecc-rules

## Purpose

`ovecc-rules` turns the resolved architecture into findings. It evaluates the
built-in rules, the security classifications, and the explicit rules from
configuration, and emits `FindingRecord`s with traceable evidence. Every
finding points back to the facts that produced it — a file, a line, a dependency,
a module pair — so it can be defended in review.

## What it evaluates

- **Security classification** — maps each `SecurityPatternFact` from the parser
  to a finding: hardcoded secrets, dynamic execution and command execution
  (`InsecurePattern`), weak crypto, and permissive CORS. Severity follows the
  pattern kind.
- **Boundary rules** — the explicit `[[rules.boundaries]]` entries (e.g. "Billing
  must not depend on User"). Each `allowed = false` rule that matches a real
  module-to-module dependency becomes one finding, with the offending imports as
  evidence.
- **Layer rules** — the explicit `[[rules.layers]]` entries (e.g. "controllers
  cannot access tables").
- **Circular dependencies** — module cycles surfaced from the graph.

## Inputs and outputs

A rule reads a `RuleInput` (repository id, modules, dependencies, security
patterns, configuration) and returns findings. The findings are persisted by
`ovecc-db` and read back by `summary` and `violations`. Convention deviations are
produced separately by `ovecc-graph`; this crate covers the explicit and
security rule families.
