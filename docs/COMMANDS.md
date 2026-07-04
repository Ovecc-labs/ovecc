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

---

## Foundation

### `ovecc init`

Sets up a repository: writes a fully commented `.ovecc/config.toml` (every
value shown is the default), adds `.ovecc/` to `.gitignore`, and prints the
first commands to run. Idempotent; `--force` overwrites the config.

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

### `ovecc capabilities`

The machine-readable contract: every command, every metric and rule (with a
definition), the severity vocabulary, exit codes, output formats. An agent
calls this first and needs nothing else to drive the tool.

### `ovecc summary`

One-screen health: files, modules, dependency counts, circular deps, coupling
density, risk score.

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
its established fix. Call it before editing something.

### `ovecc metrics [--target]`

Per-component Martin metrics: fan-in/out, coupling, instability *I*,
abstractness *A*, distance from the main sequence *D = |A + I − 1|*, churn,
plus repo-wide coupling density. The trendable numbers behind `diagnose`.

### `ovecc explain <target>`

A deterministic, offline explanation of an element's role: coupling
characterization (isolated / entry-point / foundational / intermediary), blast
radius, findings. Every sentence is backed by a fact from the context slice.

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

### `ovecc query "<expr>"`

Structured graph queries: `deps X`, `rdeps X`, `paths X`, `module X`,
`"a -> b"` (reachability with the path), `hotspots`, `violations`, `cycles`
(elementary module cycles with `file:line` witness edges per hop).

### `ovecc impact <target> [--direction] [--max-depth]`

Blast radius of changing a module, symbol, `table:NAME`, or
`api:METHOD:/path`: the impacted nodes, the paths that reach them, and a risk
score. "What breaks if I touch this?"

---

## Findings

### `ovecc violations`

Every architecture + rule finding: boundary violations, banned imports,
circular dependencies, security patterns, complexity, dead code, unit size,
with `file:line` evidence and a machine `fix` per finding. The CI artifact
(`--format sarif` for GitHub code scanning, `codeclimate` for GitLab).

Key flags: `--severity`, `--fail-on`, `--write-baseline` / `--baseline`
(ratchet: only new findings fail).

### `ovecc security`

The security slice: hardcoded secrets (provider patterns + entropy), dynamic
eval, command execution, weak crypto, permissive CORS, and tainted
source→sink flows (HTTP route → SQL/eval/exec). Deterministic, offline, no
LLM. Findings in test code (test dirs *and* Rust inline `#[cfg(test)]`) are
down-ranked to Low, not hidden.

```
Security findings: 15    secrets 8, insecure 7, tainted-flows 0
[Low] Hardcoded secret: AWS access key — crates/ovecc-parser/src/security.rs:302
```

### `ovecc audit [--fetch]`

OSV audit: declared dependencies checked against the local vulnerability
database in `.ovecc/osv/`. Reads npm `package-lock.json` today (other lockfile
formats are planned). Offline by default; `--fetch` first downloads the
advisories for the discovered packages. This is the **only** ovecc operation that
ever touches the network, and only with this flag.

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
(unlisted) dependencies.

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
duplicated logic before it propagates.

### `ovecc hotspots [--limit]`

Technical-debt ranking: churn × coupling × fan-in/out × ownership
fragmentation × violations, normalized 0–100. Where refactoring pays first.

### `ovecc conventions`

Conventions learned from the repository itself (naming roles, dependency
directions, DB access patterns) and the files deviating from them. Silent
below the evidence thresholds.

---

## Change scope (PR loop)

### `ovecc review [base] [head]`

The named, new defects a change introduced between two snapshots: new findings
with `file:line`, new dependency cycles **with their concrete import witness
edges**, and added duplication. The actionable PR artifact
(`--format markdown` is a ready-to-post PR comment). Defaults:
`previous → latest`.

```
review: FAIL (2 new finding(s) at or above 'any')
  new cycle: src/core/db.ts:3 <-> src/services/billing.ts:2
```

### `ovecc gate [base] [head]`

The pass/fail CI verdict behind `review`: fails on new cycles, violations, or
quality regressions (security / dead code / complexity counts). Counts only;
use `review` for the names.

### `ovecc diff <base> <head>`

Raw structural deltas between snapshots or git refs: added/removed modules and
dependency edges, metric deltas, and a diff risk score.

### `ovecc drift [--since <ref>]`

Trend over time: coupling, complexity, security, dead-code and ownership
metrics versus an earlier snapshot. "Is the codebase getting worse?"

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
- uses: gitvonBS/ovecc@main
  with: { fail-on: high }
```
