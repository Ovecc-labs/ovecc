# ovecc-rules

Turns the resolved architecture into findings: the built-in rules, the
security classifications, and the explicit rules from configuration. Every
finding carries traceable evidence (a file, a line, a dependency, a module
pair) so it can be defended in review.

- Security classification maps each `SecurityPatternFact` from the parser to
  a finding: hardcoded secrets, dynamic execution and command execution,
  weak crypto, and permissive CORS. Severity follows the pattern kind.
- Boundary rules evaluate the explicit `[[rules.boundaries]]` entries
  ("Billing must not depend on User"); each violated rule becomes one
  finding with the offending imports as evidence. Layer rules
  (`[[rules.layers]]`) work the same way ("controllers cannot access
  tables").
- Circular dependencies surface module cycles from the graph.
- Dead code (`deadcode`) runs entry-point reachability over the import
  graph: unused exports, unreachable files, and re-export chains.
- Code smells (`smells`) computes the classic-catalog detectors from the
  resolved facts: feature envy (a function whose resolved calls
  predominantly target one other module), large class, and data clumps (the
  same group of 3+ parameter names recurring across 3+ functions of one
  language family). Test files are excluded, feature envy skips entry
  points, and idiomatic framework signatures (`req/res/next`,
  `event/context/callback`) never count as clumps.

A rule reads a `RuleInput` and returns findings, persisted by `ovecc-db` and
read back by `summary`, `violations`, and `review`. Convention deviations
are produced separately by `ovecc-graph`.
