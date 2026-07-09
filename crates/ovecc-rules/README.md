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
- **Dead code** (`deadcode` module) — entry-point reachability over the import
  graph: unused exports, unreachable files, and re-export chains.
- **Code smells** (`smells` module) — the classic-catalog detectors computed
  from resolved facts at index time: *feature envy* (a function whose resolved
  calls predominantly target one other module), *large class* (a
  class/struct/enum with too many methods in one file), and *data clumps* (the
  same group of ≥ 3 parameter names recurring across ≥ 3 functions of one
  language family). Test files are excluded; feature envy also skips entry
  points, and idiomatic signatures (`req/res/next`, `event/context/callback`)
  never count as clumps.

## Inputs and outputs

A rule reads a `RuleInput` (repository id, modules, dependencies, security
patterns, configuration) and returns findings. The findings are persisted by
`ovecc-db` and read back by `summary` and `violations`. Convention deviations are
produced separately by `ovecc-graph`; this crate covers the explicit and
security rule families.
