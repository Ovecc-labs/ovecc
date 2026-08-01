# Command reference

Every ovecc command, what question it answers, and what it returns, with real
output excerpts. All commands:

- take `--repo <path>` (default: the current directory) and read the model that
  `ovecc index` persisted into `.ovecc/`;
- render as `text` (default), `json`, `ndjson`, or `markdown` via `--format`
  (plus `sarif` and `codeclimate` where noted);
- are deterministic: an unchanged database renders byte-identical output;
- are exposed 1:1 as MCP tools (see [dev/MCP.md](dev/MCP.md)).

Exit codes are stable: `0` ok · `1` a `--fail-on` threshold crossed · `2` usage
· `3` repository/config · `4` index/db · `5` parser · `6` git · `7` internal.
A downstream reader closing the pipe early (`ovecc report | head`, quitting a
pager) is not an error: output stops quietly and the exit code is `0`.

---

## Foundation

### `ovecc init`

Sets up a repository: writes a fully commented `.ovecc/config.toml` (every
value shown is the default), adds `.ovecc/` to `.gitignore`, and prints the
first commands to run. Idempotent; `--force` overwrites the config.

`--agent` also wires the repository's coding agent (Claude Code hooks in
`.claude/settings.json`) to query the graph before a broad text search: the
block fails open the moment ovecc cannot answer, so the agent is never
trapped. `OVECC_AGENT_HOOKS=off` disables it for a session; `--agent --remove`
undoes the wiring.

### `ovecc index [path]`

Parses, resolves, and persists the architecture model (symbols, imports, calls,
APIs, schema accesses, git history, findings) into `.ovecc/graph.db`. Run it
once per revision; re-runs are incremental (content-addressed parse cache,
differential sync). Everything below reads this model.

```
Files: 52   Modules: 13   Dependencies: 264   Commits ingested: 99
```

Key flags: `--exclude <glob>` (adds to the built-in `node_modules`/`target`/…
excludes), `--no-git`, `--stats` (phase timings + peak memory).

`--coverage <path>` reads per-file line coverage from an LCOV tracefile (also
settable as `[index] coverage`). Without it the conventional locations are
tried — `coverage/lcov.info`, `lcov.info`, `coverage.lcov` — and finding none
is not an error. A tracefile that *was* named and cannot be used says so and
leaves the previous run's coverage in place, so a failed read never reads as
"the tests cover nothing".

### `ovecc capabilities`

The machine-readable contract: every command, every metric and rule (with a
definition), the severity vocabulary, exit codes, output formats. An agent
calls this first and needs nothing else to drive the tool.

### `ovecc summary`

One-screen health: files, modules, dependency counts, circular deps, coupling
density, risk score. Files the last index found but could not read or parse are
counted here too, since every other figure covers only the rest.

```
Files: 52          Modules: 13
Dependencies: 264  External dependencies: 137
Circular deps: 0   Coupling density: 11.54%
Risk score: Low
```

### `ovecc report`

The assembled architecture report (summary + hotspots + violations + drift) in
one call: the dashboard payload. Best consumed as `--format markdown|json`.

---

## Architecture intelligence

### `ovecc architecture init [--force] [--template <name>]`

Drafts `.ovecc/architecture.toml` — the intended architecture as code — from
the observed graph: one component per detected module (narrowed to its common
directory), `depends_on` set to exactly the module-to-module imports that
exist today, and a commented `interface` suggestion when one file already
receives at least 80% of a component's incoming imports. Because every entry
mirrors a real import, the contract starts with zero violations; governance is
deleting the entries you regret. `--force` regenerates over an existing file.

`--template <name>` writes a built-in reference architecture instead of
mirroring the graph, and needs no index — the contract-first workflow starts
on an empty repository. A templated contract is the target, not a mirror:
divergences on day one are expected, and the `diff` report is the migration
plan. Templates ship with `mode = "warn"`; tighten to `new-violations` plus
`check --freeze` once the paths are rebound, and let the ratchet shrink the
rest. Each component carries a `role` (`"fsd/shared"`) naming its layer in
the source architecture, so paths can be rebound without losing the mapping.

### `ovecc architecture templates`

The built-in templates: reference architectures distilled from each
ecosystem's published canon (name, summary, target stacks, canonical source).
JavaScript/TypeScript today:

- `fsd` — Feature-Sliced Design: six layers importing strictly downward
  (app > pages > widgets > features > entities > shared), with slice isolation
  on pages/widgets/features/entities.
- `bulletproof-react` — a unidirectional codebase where imports flow
  shared > features > app and features never import each other (slice
  isolation on features).
- `nx-workspace` — Nx module boundaries by library type
  (app > feature > (ui, data-access) > util). Nx binds types with tags, not
  folders, so this template approximates them by the conventional
  `libs/<domain>/<type>-<name>` layout; rebind `paths` if yours differs.
- `clean-architecture` — Clean/Hexagonal: dependencies point inward
  (presentation > application > domain, infrastructure implements the ports),
  and the domain is a pure ring — `deny_capabilities` forbids it network,
  filesystem, storage, dom, process, clock, and randomness, with a per-function
  complexity budget.

### `ovecc architecture suggest`

Recognizes which built-in template the indexed repository most resembles, and
binds it to the repository's real root. For each template it detects the root
(`src/`, `apps/web/src/` in a monorepo, or the repository root), rebinds the
template there, and scores the fit as coverage × conformance: coverage is the
share of the repository's source files a component claims, conformance the
share of the internal import edges the template allows. It reports the ranked
fits and, above a 50% threshold, the best match with the command that applies
it.

```
Best match: fsd (fit 1.00)
  root: src/
  coverage: 100% (64/64 source files, 3 components)
  conformance: 100% (0 divergent edge(s) of 143)
  apply: ovecc architecture init --template fsd
```

This is recognition against a curated basket of archetypes, not architecture
recovery from scratch: automatic recovery of an arbitrary architecture is a
hard, low-accuracy problem, but classifying a repository against a handful of
known targets is well-posed. A repository that follows none of them is told so
rather than pushed a template it does not fit. Needs an index.

### `ovecc architecture show [paths...]`

The contract resolved, from the contract alone — no index required. Without
paths, every component; with paths, the components owning them. Each component
lists what it may import (with the target's interface files as the legal
doors), its own interface, its external deny-list, whether its slices are
isolated, the capabilities it denies, and any per-function budget. This is the
pre-edit question — "I'm editing this file, what am I allowed to import and
do?" — and what the `ovecc_architecture` MCP tool serves to agents.

```
Contract mode new-violations, 1 component(s):

cli (crates/ovecc-cli/**)
  may import: core, db, graph, git, audit, ai, indexer, rules
```

### `ovecc architecture diff`

The reflexion report between the contract and the stored graph, in the
Murphy/Notkin/Sullivan vocabulary: convergences (declared and implemented,
with import counts), divergences (imports the contract does not allow),
slice-isolation breaches (imports between sibling slices of a `slices = true`
component), interface bypasses (imports that skip a component's declared entry
files), deprecated dependencies still in use, banned external packages, denied
capabilities used, complexity budgets exceeded, coverage floors missed,
unassigned files, and absences (declared but never implemented). Divergences,
slice breaches, and bypasses are High; deprecated, banned, capability, budget
and coverage are Medium; hygiene is Low.
`mode = "warn"` caps everything at Low so nothing gates.

One verdict reads no code at all. **Behavioral coupling** names two components
the contract declares independent, and that no import connects, whose files the
history keeps changing in the same commits. No static analysis can see it: the
only witness is the commits, and they come with the finding. Two components must
share at least two coupled file pairs before it is reported: one is an accident,
and the honest exception is real (a version field every implementer of a
protocol must bump). It is Low by default, under every gate's threshold, because
the deviation is a question for the reader; `coupling = "medium"` (or `"high"`)
in the contract puts it in the gate, `coupling = "off"` stops reporting it.

Beyond the import graph, two verdicts read the code itself (JS/TS): a
`deny_capabilities` list forbids a component the ambient capabilities that
break functional purity (network, filesystem, storage, dom, process, the
clock, randomness), reported with the exact `file:line` and API; and
`max_cyclomatic` / `max_cognitive` set a per-function complexity budget, an
architectural fitness function checked against every function the component
owns.

`min_coverage` is the third fitness function, and the only one that reads a
file the repository produces rather than a metric ovecc derives: a fraction in
`(0, 1]`, and a component under it is an `architecture/coverage-floor` verdict
at Medium. It is checked only when a tracefile was indexed, and only over the
files that tracefile mentions: with none, the component is unmeasured, and
calling that 0% would say more than the data does. Unlike every other verdict
it cannot be baselined: a floor is one aggregate per component, so accepting it
once accepts the whole condition, which is what deleting the declaration
already does.

```
Architecture contract: 13 components, 25/25 declared dependencies implemented, mode new-violations

Divergences (1):
  [High] cli -> parser is not in the contract
    crates/ovecc-cli/src/render.rs:12 (ovecc_parser::outline)
```

The contract file is re-read on every run and judged against the persisted
graph, so editing `architecture.toml` never requires re-indexing. The same
findings also land in `violations`/`gate` at each `ovecc index`.

### `ovecc architecture check [--fail-on medium|high|any] [--freeze]`

The same report as an exit code for CI: `1` when a contract finding crosses
the threshold (default `high`, i.e. any divergence or interface bypass).

Progressive adoption runs through the baseline store. `--freeze` accepts every
current violation into `.ovecc/architecture/baseline/` — one file per
component, one sorted `rule<TAB>file<TAB>specifier` line per violation, so
concurrent branches merge line by line. No line numbers: an entry survives
edits around the import; renaming the file resurrects the violation on
purpose, because moving a file is the moment to pay its debt.

In `new-violations` mode, baselined entries stop gating (the report header
counts them) and every `check` ratchets: entries whose violation no longer
exists leave the store, so the debt counter never climbs back. `strict`
ignores the baseline entirely — the whole debt gates again.

Behavioral coupling goes into the same store, one line per coupled file pair
(`behavioral-coupling<TAB>left file<TAB>right file`). Accepting today's pairs
does not silence the component pair for good: the next file that joins the
coupling comes back on its own, even though a single pair would never have
raised the finding.

### `ovecc diagnose`

Named architectural smells at component (directory) granularity: cycles with
per-hop `file:line` witness edges, hub-like and god components, zone of pain
(Martin distance), dense structure, hotspots, unstable interfaces, change
coupling, modularity violations. Every finding carries evidence, the design
principle it breaks, a curated remediation, a deterministic confidence, and a
machine `fix` action.

```
[High] Zone of Pain — component crates/ovecc-core/src  (confidence 0.87)
  Principle: Stable Abstractions Principle (main sequence)
  Evidence: distance=0.94 (>= 0.70), abstractness=0.06, instability=0, fan_in=9
  Fix: A rigid, concrete core that many components depend on: introduce
       abstractions so dependents rely on a stable contract. [Dependency Inversion]
  Action: introduce_abstraction (auto-fixable: no)
```

Key flags: `--target <substr>`, `--severity`, `--group-by
family|severity|component`, `--fail-on`. Formats: + `sarif`, `codeclimate`.

### `ovecc advise <target>`

The agent surface: every finding touching one file/module/component, each with
its established fix. Call it before editing something. Two parts: the persisted
findings whose evidence touches the target (what `violations` would attribute
to it), then the component-level design smells around it.

```
Advise for src/utils/helpers.ts: 3 finding(s), 1 design smell(s)
[Medium] Unused export: formatEuros
  Evidence: src/utils/helpers.ts:24
  Fix: Remove the export keyword... (auto-fixable: yes)
```

### `ovecc metrics [--target]`

Per-component Martin metrics: fan-in/out, coupling, instability *I*,
abstractness *A*, distance from the main sequence *D = |A + I − 1|*, churn,
plus repo-wide coupling density. The trendable numbers behind `diagnose`.

### `ovecc explain <target>`

A deterministic, offline explanation of an element's role: coupling
characterization (isolated / entry-point / foundational / intermediary), blast
radius, findings. Every sentence is backed by a fact from the context slice.
Dependencies/Dependents list the *direct* edges; change-impact paths follow
the reverse-dependency direction (who is affected), up to three hops.

```
versions.ts is foundational: 90 components depend on it.
```

### `ovecc export context <target>`

The same context slice as raw JSON: the clean, deterministic input for an
external LLM or tool. Nothing is sent anywhere; it just prints.

### `ovecc export graph [--html [path]]`

The whole dependency graph as data: module-level and file-level nodes and
edges, sorted so an unchanged database exports byte-identical output, ready
for Graphviz, d3, or any external tool. With `--html`, writes a
self-contained interactive viewer instead (default `ovecc-graph.html`):
force-directed canvas, module/file views, search, external-dependency toggle,
per-node detail panel. The renderer ships inside the binary (no CDN, no
runtime dependency); the file opens offline.

```
{ "html": "ovecc-graph.html", "bytes": 158014, "modules": 209, "files": 252, "file_edges": 535 }
```

### `ovecc grep <pattern> [path...] [--limit]`

Search served from the index: symbol definitions first (name, kind,
`file:start-end` span), then text matches from an ignore-aware disk scan —
configs and docs included — in the familiar `path:line: text` form. Matches are
deduplicated and capped (20 definitions, 5 matches per file, 50 matches
overall; totals always cover the full set), with test files ranked after
source. `--limit` raises both caps at once and `--limit 0` lifts them.
All-lowercase patterns search case-insensitively (smart case). Same coverage as
`grep -r`, a fraction of the output.

### `ovecc read <target> [--limit]`

One element's source instead of a whole file. Accepts a symbol name (prints
its exact body, line-numbered, with a `file:start-end` header), a `file:line`
anchor (expands to the enclosing symbol — the form `query`, `impact`, and
`grep` emit), a `file:start-end` range, or a bare file path (prints the file's
symbol outline to pick from). Several definitions under one name list their
anchors instead of guessing.

### `ovecc query "<expr>"`

Structured graph queries: `deps X`, `rdeps X`, `paths X`, `module X`,
`"a -> b"` (reachability with the path), `hotspots`, `violations`, `cycles`
(elementary module cycles with `file:line` witness edges per hop).

### `ovecc impact <target> [--direction] [--max-depth]`

Blast radius of changing a module, symbol, `table:NAME`, or `api:<route>`: the
impacted nodes, the paths that reach them, and a risk score. "What breaks if I
touch this?" API labels have the form `GET /users/:id`; `api:GET:/users/:id`,
`api:GET /users/:id`, and the substring form `api:/users` all resolve. A target
that matches nothing is a usage error (exit 2), so scripts can tell a typo
from a genuinely empty blast radius. Dependency edges are module-level, so a
file target is answered through the module that contains it; the report names
the file it started from (`redirected_from` in JSON).

---

## Findings

### `ovecc violations`

Every architecture + rule finding: boundary violations, banned imports,
circular dependencies, security patterns, complexity, dead code, unit size,
code smells (feature envy, large classes, data clumps), with `file:line`
evidence and a machine `fix` per finding. The CI artifact (`--format sarif`
for GitHub code scanning, `codeclimate` for GitLab).

Key flags: `--severity`, `--fail-on`, `--write-baseline` / `--baseline`
(ratchet: only new findings fail).

### `ovecc security`

The security slice: hardcoded secrets (provider patterns + entropy), dynamic
eval, command execution, weak crypto, permissive CORS (both the middleware
`origin: "*"` form and raw `setHeader("Access-Control-Allow-Origin", "*")`),
and tainted source→sink flows (HTTP route → SQL/eval/exec, for named *and*
inline arrow handlers, with `file:line` evidence for the sink and the route).
Deterministic, offline, no LLM. Findings in test code (test dirs *and* Rust
inline `#[cfg(test)]`) are down-ranked to Low, not hidden.

```
Security findings: 15    secrets 8, insecure 7, tainted-flows 0
[Low] Hardcoded secret: AWS access key — crates/ovecc-parser/src/security.rs:302
```

### `ovecc audit [--fetch]`

OSV audit: declared dependencies checked against the local vulnerability
database in `.ovecc/osv/`. Reads npm `package-lock.json` today (other lockfile
formats are planned). Offline by default; `--fetch` first downloads the
advisories for the discovered packages. This is the **only** ovecc operation that
ever touches the network, and only with this flag. Severity follows the
advisory's own label (GHSA `LOW`/`MODERATE`/`HIGH`/`CRITICAL`); unlabeled
advisories default to High. A scan of 0 packages says which of the three cases
it is: no lockfile, a lockfile that could not be read, or no advisories on
disk yet.

```
Fetched 27 new advisory(ies) for 1 package(s).
[High] Vulnerable dependency: axios@1.7.2 (GHSA-8hc4-vh64-cxmj)
```

### `ovecc health`

Functions over the complexity thresholds (cyclomatic/cognitive) plus oversized
units (long functions, long parameter lists).

```
Code health: 78 high-complexity function(s), 43 oversized unit(s)
[High] High complexity: ArchitectureStore.sync_current_index (cyclomatic 202, cognitive 121)
```

### `ovecc deadcode`

Likely-dead code from exports + entry-point reachability: unused exports
(type-only exports tagged `unused-type`), unreachable files, unused manifest
dependencies (opt-in: `[index] detect_unused_deps = true`), and phantom
(unlisted) dependencies. When nothing is flagged the report states its
coverage (entry points found, JS/TS files analyzed), so a clean result is
distinguishable from an analysis that never ran (no entry points, or no JS/TS
sources for the unused-export pass; file reachability itself is
language-agnostic).

```
Dead code: 47 unused export(s), 46 unused file(s), 0 unused dependency(ies), 0 unlisted dependency(ies)
```

### `ovecc fix [--apply] [--rule <rule>]`

Applies the mechanical fixes for auto-fixable findings: deletes unreachable
files, drops the `export` keyword on unused exports (and prunes names from
re-export lists), removes unused manifest dependencies, **declares** phantom
dependencies with the version the lockfile already resolves, and deletes stale
`ovecc-ignore` comments. All format-preserving and JSON-validated. **Dry-run
by default**; every edit re-verifies the file against the index and skips
stale entries with a reason. Anything needing judgement (default exports,
architectural smells) is never touched.

```
Fix plan: 5 change(s), 0 skipped — dry-run (pass --apply to write)
[planned] remove_unused_export — src/orphan.ts:1 (unused-export)
    - export const neverUsed = 42;
    + const neverUsed = 42;
```

### `ovecc dupes [--min-tokens]`

Clone families over a normalized token stream, with `file:line` ranges:
duplicated logic before it propagates. Same-file duplication is reported by
default (copy-paste within one file is still duplication); pass
`--cross-file-only` to keep only families spanning at least two files.

### `ovecc coupling [--min-confidence] [--limit]`

The file pairs the history keeps changing in the same commit, whether or not
anything in the code connects them. Each pair carries the commits they met in,
the Jaccard strength, the lift (how much more often than chance), and both
directed confidences, plus witness shas.

Only commits touching between 2 and 30 indexed files count: one file says
nothing about a pair, and a sweep across the tree says nothing about any of
them. A pair is stored when it met at least 3 times, with Jaccard at least 0.35
and lift above 1 — the lift is what keeps two merely busy files apart.

### `ovecc hotspots [--limit]`

Technical-debt ranking: churn × coupling × fan-in/out × ownership
fragmentation × violations, normalized 0–100. Where refactoring pays first.
Churn follows renames, so moving a file does not reset its history. A file that
was split keeps it under whichever part kept the path: git records the other
part as a new file.

Each module also carries its bug-fix history: how many commits classified as
fixes touched it, the same count weighted so a fix loses half its weight every
180 days, and the date of the last one. It sits beside the score rather than
inside it — what a correction says about a module is a judgment call, so the
number is there to be argued with, not to hand down a verdict.

When an LCOV tracefile was indexed (see `ovecc index --coverage`), line
coverage sits on the same row, and a closing line names the least-covered
module of those ranked. That crossing is the point: churn alone ranks the code
that keeps moving, coverage alone ranks the code nobody tests, and only
together do they say where a change is most likely to break something no test
would catch. Coverage stays out of the score for the same reason the fix
history does.

### `ovecc selfcheck`

Turns the tool on itself: for each rule, does the code it flags get corrected
more often than the rest of the repository? Rules are ranked by lift over the
repository's own base rate, so a quiet codebase and a burning one are each
judged against themselves.

```
Base rate: 0.04 fixes/KB over 109 file(s), 1661.2 KB (half-life 180 days)

architecture/behavioral-coupling (lift 1.63)
  7 file(s), 165.8 KB, fix mass 11.70 -> 0.07 fixes/KB
```

Rates are per kilobyte, not per file: large files collect more findings *and*
more corrections, so a per-file rate would flatter every rule that happens to
fire on large files. Bytes rather than lines because bytes are what the index
stores, and the lift is a ratio, so the unit cancels.

Fix mass that landed on paths the index does not hold — deleted files, docs,
unsupported languages — is reported as a share and excluded from both rates.
Excluding it silently is how a self-check flatters itself: the files a team
deletes are often the ones it fixed the most.

What the number does not show: findings are computed on today's code while the
corrections happened in the past, so this is association, not proof, and a rule
can be right about code nobody has got round to fixing. There is no published
bar to clear here — the protocol is ours, and the figure ships whatever it says.

### `ovecc conventions`

Conventions learned from the repository itself (naming roles, dependency
directions, DB access patterns) and the files deviating from them. Silent
below the evidence thresholds.

---

## Change scope (PR loop)

### `ovecc review [base] [head]`

The named, new defects a change introduced between two snapshots: new findings
with `file:line`, new dependency cycles **with their concrete import witness
edges**, and added duplication. Findings are matched by content identity
(enclosing symbol / pattern), not by line, so a pre-existing finding that
merely moved is not blamed on the change. A clone family is charged only when
the change touched one of the tokens it is made of, so reflowing the comments
around a clone does not report it as new. Works on the uncommitted working tree
too, not only between two commits. The actionable PR artifact
(`--format markdown` is a ready-to-post PR comment). Defaults:
`previous → latest`.

```
review: FAIL (2 new finding(s) at or above 'any')
  new cycle: src/core/db.ts:3 <-> src/services/billing.ts:2
```

### `ovecc gate [base] [head]`

The pass/fail CI verdict behind `review`: fails on new cycles, violations, or
quality regressions (security / dead code / complexity / code-smell counts).
Counts only; use `review` for the names.

### `ovecc diff <base> <head>`

Raw structural deltas between snapshots or git refs: added/removed modules and
dependency edges, metric deltas, and a diff risk score.

### `ovecc drift [--since <ref>]`

Trend over time: coupling, complexity, security, dead-code and ownership
metrics versus an earlier snapshot. "Is the codebase getting worse?"
`security_findings` counts *code* findings only; OSV advisories are tracked
separately as `dependency_advisories`, so running `audit --fetch` never reads
as a code-quality regression.

### `ovecc history [metric] [--limit N]`

One metric across *every* snapshot: per-index values, deltas, and a
sparkline. Without a metric, lists everything trendable (25+ metrics are
recorded at each `ovecc index`).

```
History: unused_files over 10 snapshot(s)   0 -> 1 (+1)
  ▁▁▁█▆▁▃▃▃▃
```

---

## Integration

### `ovecc mcp`

A Model Context Protocol server over stdio exposing all of the above as tools
(`ovecc_diagnose`, `ovecc_review`, `ovecc_fix`, …) for Claude Code, Cursor, and
any MCP client:

```json
{ "mcpServers": { "ovecc": { "command": "ovecc", "args": ["mcp"] } } }
```

### GitHub Action

The repo root ships a composite action ([action.yml](../action.yml)) that
downloads the binary, indexes base + head, posts the `review` markdown as a PR
comment, and gates on `fail-on`:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: Ovecc-labs/ovecc@main
  with: { fail-on: high }
```
