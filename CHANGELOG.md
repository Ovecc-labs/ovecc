# Changelog

Notable changes to ovecc are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0, minor releases may contain breaking
changes).

## [Unreleased]

### Fixed

- `import type` no longer inflates the persisted `circular_dependencies` metric.
  The type-only filter landed in `cycles.rs` but never reached the SCC pass in
  `analyze_modules`, so `gate`, `diff`, `drift`, `history` and the repository
  risk score all carried phantom cycles while `violations`, `query cycles` and
  `review` — which go through `cycles.rs` — were right. A PR adding a single
  `import type` could fail the gate with a cycle the review comment beside it
  said did not exist. `is_runtime_edge` is now the one definition both paths
  call. Coupling density and fan-in/out still count type edges, deliberately: a
  type dependency is coupling, it just cannot form a load-order loop. The two
  edge sets are deduplicated separately, so a `type_import` row arriving before
  the value import for the same pair can no longer hide it.
- Unresolved relative imports are no longer reported as external *packages*.
  A specifier naming a path that resolves to nothing became `external:.` (or
  `external:..`), which collapsed every unresolved `./x` in a file onto one
  node, lost the specifier, and inflated `external_dependencies` — on any
  repository with a broken import, an unmodelled bundler alias, or an unusual
  resolution scheme. Such a target is now `unresolved:<specifier>`, a specifier
  that reached a real but unindexed file (an asset, a declaration file, a
  package in `node_modules`) is `unindexed:<specifier>`, and neither is counted
  as an external dependency or fabricated as a package node in `export graph`.
- `import { x } from "./y"` backed only by a `y.d.ts` now resolves to that
  declaration file instead of reading as a broken import.
- `review` no longer invents new dependency cycles, which made the gate fail a
  change that introduced nothing. A loop counted as new when it was absent from
  the base's *enumerated* cycle set, and that enumeration is capped at
  `MAX_CYCLES_PER_SCC`: a component over the cap yields a different truncation
  of the same loops on either side, so untouched cycles surfaced as new. The two
  sides were not even reading one graph, since a snapshot records no
  `dependency_kind` and its edges cannot drop `import type` the way the head
  graph does. A cycle is now new when one of its edges is absent from the base,
  tested edge by edge, which needs no enumeration of the base at all. On hono,
  indexing twice with no change between reported three new cycles and exited 1;
  it now passes.
- A cycle witness cites the import the change added. The walk chains each hop
  off the file the previous one arrived at, so its shape follows from where it
  starts, and it always started at hop 0 with that pair's canonical
  representative. `review` therefore named pre-existing imports and omitted the
  one edge the author could remove. The walk now anchors on a hop whose
  importing file the change touched, and chains the rest of the loop off it as
  before; `query cycles`, `diagnose` and the rules pass nothing to prefer and
  are byte-identical.
- `impact <file>` answers for the file. The index writes file→file `depends_on`
  edges so the blast radius can be computed at file granularity, but the target
  was redirected to its containing module unconditionally, and the note beside
  the answer ("has no dependency edges of its own") stated a condition the code
  never evaluated. Every file reported `Affected files: 0` while `query rdeps`
  listed its dependents from the same database, and through MCP an agent asking
  what a change breaks got a falsely reassuring zero. The fallback now applies
  only when the file really has no edge to follow in the direction asked for, so
  `impact --max-depth 1` and `query rdeps` agree.
- The age-weighted fix mass is summed as `DECIMAL`. DuckDB aggregates in
  parallel and float addition is not associative, so the sum landed on a
  different last bit per run: `hotspots` produced six distinct JSON outputs over
  six runs against one unchanged database, against a byte-identical guarantee.
  Ranking never moved, the bytes did.

### Added

- `query deps`, `rdeps`, `module` and `a -> b` answer ternary: `resolved`,
  `none`, or `could_not_resolve`. An empty result used to mean both "nothing
  references this" and "I could not work out what references this", and an agent
  that cannot tell them apart acts on the second as if it were the first —
  deletes the symbol, breaks the build, and had no sign the tool was guessing.
  The answer now names the unresolved imports behind the doubt, with their
  `file:line`. On `deps` those are the target file's own unresolved imports,
  which is exact; on `rdeps` they are unresolved imports elsewhere whose
  specifier names the target, which is plausible and deliberately errs toward
  doubt. Scoped to the target rather than the repository: a global "N imports
  are unresolved" would annotate every answer and be ignored within a day.
- Three constraint forms in `.ovecc/architecture.toml`, closing the gap between
  an allow-list and what an architecture actually needs to say. `depends_on` is
  a strictly positive bipartite set: it can express permission and nothing else.
  Terra & Valente's DCL identifies four forms, and ovecc supported one.
  - `cannot_depend_on` — a stated prohibition rather than a prohibition by
    omission. Reported as `architecture/forbidden-dependency` (high).
  - `consumed_by` — the only components allowed to import this one, declared on
    the target, where the sentence belongs: "the database is reached only
    through the repository" is one claim about the database, not an edit to
    every other component's allow-list. `consumed_by = []` admits nobody — the
    strangler-fig rule, "no new code may touch this" — without naming a single
    consumer. Reported as `architecture/restricted-access` (high).
  - `must_depend_on` — a mandatory dependency, judged per file, since the
    component-level question is what `depends_on` and the absence verdict
    already answer. Files that import nothing at all are exempt, and a required
    dependency implies permission, so it is never also a divergence. Reported as
    `architecture/required-dependency` (high).

  The two prohibitions *replace* the divergence an edge would otherwise have
  been rather than adding a second finding, and contradictions between the forms
  fail at parse time — a target both forbidden and required, or a dependency the
  target's `consumed_by` does not admit — so every import still carries exactly
  one verdict. All three freeze into the baseline and shrink with the ratchet
  like any other violation.
- `unresolved-import` (medium): an import naming a path inside the repository
  that the resolver rejected outright — a rename or deletion its importers never
  followed. Precision-first: a specifier that reached a real file is a different
  state and says nothing; asset extensions and loader queries (`./a.css`,
  `./b.svg?url`) are left alone because a bundler rule, not ovecc, resolves
  those; and only JS/TS sources are judged, since there a specifier is a path
  the resolver walked the filesystem for. Elsewhere "unresolved" can also mean
  ambiguous, or legal with no file to find at all — a Python namespace package
  has no `__init__.py` — and reporting those would be guessing.
- `summary` states the cycles its own count cannot represent. Two sibling
  directories of one module importing each other collapse into a self-edge the
  module graph drops, so the count read `0` while `diagnose`, which works at
  directory granularity, reported the loop with full confidence — the two
  commands contradicted each other on the same repository. The new
  `intra_module_cycles` figure qualifies the count and points at `diagnose` and
  at `[architecture] module_depth`, which promotes those directories to modules
  in their own right.
- A Linux aarch64 binary, on the release page and as `@ovecc/cli-linux-arm64` on
  npm. `npx ovecc` used to fail outright on arm64 Linux, which is what a
  container built on an Apple Silicon Mac runs by default. The GitHub Action
  picks it up too, so arm64 runners no longer download an x86_64 binary.

### Changed

- The cycle count is labelled "Cyclic module components" in `summary` and
  `report`, and its metric description says so: it counts strongly-connected
  components, while `query cycles` lists *elementary* loops, and one component
  can hold several. The two numbers differing is correct, and the old wording
  made it read as an inconsistency.
- MCP tells "unknown tool" and "missing required argument" apart, naming the
  argument (`missing required argument 'target' for ovecc_impact`). One message
  for both left an agent unable to tell a typo from an omission.

## [0.2.4] - 2026-08-08

### Added

- A `server.json`, and the matching `mcpName` in the npm manifest, so a tagged
  release also publishes to the official MCP registry as
  `io.github.Ovecc-labs/ovecc`. Directories that mirror the registry then carry
  the real version and launch command rather than guessing them from this repo.

### Changed

- The MCP client snippet in the README registers `npx -y ovecc mcp`, which needs
  nothing installed first. The bare binary still works and is documented next to
  it.

## [0.2.3] - 2026-08-07

### Added

- A macOS arm64 binary in the releases, built on the standard `macos-15` runner
  alongside the Linux and Windows ones. The GitHub Action picks it up when the
  caller's job runs on macOS. It is unsigned, so the first run needs `xattr -d
  com.apple.quarantine`.
- `npx ovecc`: the same binaries published to npm, one platform package per
  target that npm picks by its `os` and `cpu` fields, behind an `ovecc` launcher
  with no install script (so it works under `--ignore-scripts`). Installing this
  way also avoids the macOS quarantine flag, which only browsers set.

## [0.2.2] - 2026-08-01

### Added

- Behavioral coupling: the files a repository keeps changing in the same
  commits, mined from the history and persisted in a `co_changes` table. `ovecc
  coupling` ranks the pairs by support, Jaccard and lift, with the witness
  commits.
- The contract verdict on top of it, `architecture/behavioral-coupling`: two
  components no import and no `depends_on` connects, whose files keep changing
  together across at least two file pairs. No static analysis can produce this
  one — the only witness is the history, and the commits ship with the finding.
  Low by default, `coupling = "medium" | "high" | "off"` in the contract moves
  or silences it, and `check --freeze` accepts the pairs one at a time like any
  other debt.
- `hotspots` and `summary` report each module's fix history: how many bug-fix
  commits touched it, the same count weighted by age (180-day half-life), and
  the date of the last one.
- `ovecc selfcheck`: ovecc's own findings measured against the repository's fix
  history, as a lift per rule over the repository's own base rate. It ships in
  `report` and in `BENCHMARKS.md` with the number as it comes — on this
  repository two rules of eleven clearly beat the base rate. With no ingested
  history it says it had nothing to measure instead of printing a table of
  zeros that reads as a rule set predicting nothing.
- Line coverage from an LCOV tracefile: `index --coverage <path>`, or the
  conventional locations (`coverage/lcov.info`, `lcov.info`, `coverage.lcov`)
  when none is given. Stored per file, reported per module by `hotspots`, and
  crossed with the ranking to name the hotspot the tests reach least.
- `min_coverage` per component in `.ovecc/architecture.toml`: a verdict when a
  component's measured line coverage sits under the floor it declared. A
  component the tracefile never mentions is skipped rather than reported at 0%,
  because what is known is that it is unmeasured, not that it is untested.
- `review` and `gate` report the shape of a change: the files and head lines it
  touches, the contract components it reaches, how evenly it spreads over its
  files, the ranked hotspots it lands on, its share of the repository's
  age-weighted fix mass, and the mean age of the files it edits. The file,
  component, fix-mass and age measurements each carry a percentile against the
  repository's own indexed commits, so a change is read against the codebase it
  lands in rather than against a constant. Information, never a verdict: no rank
  fails the gate, and under 100 indexed commits none is reported at all.

### Fixed

- Churn follows renames: a file's history no longer restarts at its new path.
  Tree diffs also stopped counting directories as files.
- `grep --limit` cuts the definitions returned, not the matches alone, so one
  symbol with many call sites no longer crowds every other result out of the
  page.
- `audit` tells an unreadable lockfile apart from an absent one, instead of
  reporting both as no dependencies found.
- `impact` says when it answered for a file's module rather than for the file
  itself, instead of widening the question in silence.
- `summary` carries the files the index could not read, so a partial index shows
  up in the report and not only in the output of the run that produced it.

### Changed

- The commit index records where a renamed file came from, and the co-change
  pairs get their own table (schema 10). Existing databases migrate on the next
  `index`, which re-ingests the commit history so old renames get linked.
- Per-file coverage gets its own table (schema 11), migrated on the next
  `index`.
- Finding severities are coloured when stdout is a terminal and left plain when
  it is piped or redirected.
- The first-run hints name the command that helps instead of describing it.

## [0.2.1] - 2026-07-31

### Fixed

- `review` no longer blames pre-existing clone families on the change. A family
  is charged only when the change touched one of the tokens it is made of, so
  reflowing the comments around a clone does not report it as new duplication.
- `review` scopes an uncommitted change to the lines it touched, by diffing the
  working tree against the base commit. Two snapshots sitting on the same commit
  — the index, edit, index loop an agent runs — used to fall back to charging
  every finding and every clone family in an edited file to the change.
- Diffs normalize CRLF, so a working copy checked out under `core.autocrlf` no
  longer reads as if every line of every file had changed.
- `dupes` folds overlapping instances of one family: a block of near-identical
  lines gives consecutive sliding windows the same fingerprint, and one region
  was reported as several copies of itself. Duplicated-line counts drop 17 to
  30 percent on the six repositories benchmarked.
- Building from source on Windows works around the multiple-definition bug in
  GCC 16.1.0's libstdc++.

### Changed

- The commit index stores whether a commit's subject describes a bug fix
  (schema 7). Existing databases gain the columns on the next `index`.

## [0.2.0] - 2026-07-22

### Added

- Architecture contracts as code: `.ovecc/architecture.toml` declares
  components (path globs), the only dependencies each may have, virtual
  interface files, and per-component external deny-lists. Every index diffs
  the code against the contract with reflexion-model verdicts (divergence,
  interface bypass, deprecated use, absence) that flow into `violations`,
  `gate`, and `review` as standard findings.
- `ovecc architecture init`: drafts the contract from the observed graph —
  every entry mirrors an existing import, so the contract starts with zero
  violations. Proposes the de facto interface of a component in comments.
- Architecture templates: `ovecc architecture init --template <name>` writes a
  reference architecture instead of mirroring the graph, and needs no index.
  Four JavaScript/TypeScript templates ship in the binary: `fsd`
  (Feature-Sliced Design), `bulletproof-react` (unidirectional shared >
  features > app), `nx-workspace` (Nx module boundaries by library type), and
  `clean-architecture` (Clean/Hexagonal with a pure domain). The diff against a
  template is the migration plan; `architecture templates` lists what ships in
  the binary.
- Slice isolation: `slices = true` on a component forbids imports between its
  sibling slices (each first-level directory under the glob prefix), the rule
  behind Feature-Sliced Design and bulletproof-react. FSD's `@x` public-API
  notation (`<neighbour>/@x/<slice>`) is honored as the exception. Reported as
  the `architecture/slice-isolation` verdict.
- Capability contracts: `deny_capabilities` forbids a component the ambient
  JS/TS capabilities that break functional purity — network, filesystem,
  storage, dom, process, time, random — matched against a curated API basket
  (globals, ambient receivers, constructors, node builtins) and reported with
  the exact `file:line` and API as the `architecture/capability` verdict. The
  uses are indexed into a `capability_uses` table.
- Per-component complexity budgets: `max_cyclomatic` / `max_cognitive` set a
  per-function ceiling checked against every function the component owns, an
  architectural fitness function reported as `architecture/complexity-budget`.
- `ovecc architecture suggest`: recognizes which built-in template an indexed
  repository most resembles. For each template it detects the root (`src/`,
  `apps/web/src/` in a monorepo, or the repository root), binds it there, and
  scores the fit as coverage × conformance; above a threshold it reports the
  best match and the command that applies it. Recognition against a curated
  basket of archetypes, deterministic and offline.
- `ovecc architecture diff` / `check`: the reflexion report (declared edges
  with occurrence counts, findings with file:line evidence) and its CI gate.
  Both re-read the contract on every run; editing it needs no re-index.
- `ovecc architecture check --freeze` and a per-component baseline store
  (`.ovecc/architecture/baseline/`, one sorted line per accepted violation,
  no line numbers): freeze once, gate new violations from then on. Every
  check ratchets — corrected entries leave the store automatically.
- `ovecc architecture show [paths]`: the contract resolved for the paths an
  agent is about to edit — owning component, what it may import and through
  which interface files. Exposed as the `ovecc_architecture` MCP tool in the
  agent profile; the SessionStart hook announces the contract.
- The GitHub Action gates on `architecture check` and includes the contract
  verdicts in its PR comment when a contract exists.
- A JSON Schema for the contract at `docs/schemas/architecture.schema.json`.
- `ovecc init` now writes a granular `.ovecc/*` ignore (upgrading an existing
  blanket `.ovecc/` line) so the contract and its baseline stay trackable.
- `ovecc grep <pattern> [paths]`: a symbol-aware search built for coding
  agents. It answers from the index first (matching symbol definitions with
  their `file:start-end`), then scans the working tree like an ignore-aware
  grep, deduplicates, and caps the result so an agent gets a few kilobytes
  back instead of a whole file's worth of hits.
- `ovecc read <target>`: prints one symbol's source, or a file's symbol
  outline, straight from the index — a symbol name, `file:line`,
  `file:start-end`, or a bare path all resolve to the right slice, so an agent
  reads a function instead of the file around it.
- `ovecc init --agent`: wires a coding agent to the graph, installing the
  hooks that route its searches through ovecc.
- MCP: `ovecc_grep` and `ovecc_read` tools, with an agent profile that leads
  with them.
- `cargo xtask`: a std-only development task runner (`crates/xtask`) that
  defines every quality gate once for contributors, git hooks, and CI —
  `check`, `fix`, `lint`, `test`, `ci`, `audit`, `coverage`, `suppressions`,
  `dogfood`, `precommit`, `prepush`, and `hooks` (installs the pre-commit
  and pre-push git hooks).
- An accuracy corpus (`tests/fixtures/accuracy/`): per-detector fixture
  repositories with `require`/`deny` manifests; the `accuracy` e2e suite
  fails when a required finding goes missing or a must-stay-silent probe
  fires.
- CI: the lint job now runs `cargo xtask lint`, a strict `cargo-audit` pass,
  and the suppression report; a new `self-review` job feeds the freshly
  built binary back onto ovecc's own repository and blocks the release when
  a change introduces new high-severity findings.

### Changed

- Agent search hooks redirect a repository-wide search to `ovecc grep` and let
  path-scoped ones through, replacing the earlier block-and-unlock window.
- `query` and `impact` cap oversized result sets with an "and N more" hint,
  and a no-op `index` collapses to a single up-to-date line.
- Contributions are Apache-2.0 inbound and carry a Developer Certificate of
  Origin sign-off (`git commit -s`); see CONTRIBUTING.md.

### Fixed

- Rust import resolution no longer resolves a bare external-crate path
  (`use tracing::…`, `std::fs`) to a homonymous local file, which produced
  phantom internal edges and dependency cycles on Rust monorepos.
- `ovecc --repo <path> mcp` runs its tools against that repository by default
  instead of the server's working directory.
- Oversized files are skipped by a built-in 5 MiB default, not only when
  `max_file_size_bytes` is set, so an unconfigured repo never tries to parse a
  multi-megabyte generated blob.
- Complexity findings in test files are down-ranked to Low, and clone families
  made only of test files sink below production duplication, so `health` and
  `dupes` lead with what is worth acting on.
- `index` reports how many files parsed with syntax errors, so a partial
  extraction from invalid source is no longer silent.

## [0.1.0] - 2026-07-11

Initial public release.

### Added

- `ovecc init` to scaffold `.ovecc/config.toml`, and `ovecc index` to build the
  model: tree-sitter + oxc parsing, import/call resolution, DuckDB persistence,
  incremental re-index (unchanged files are never re-parsed).
- `ovecc capabilities`: machine-readable contract listing every command, metric,
  rule, severity, exit code, and output format.
- Analysis commands: `summary`, `impact`, `query`, `violations`, `security`,
  `audit` (offline OSV), `hotspots`, `dupes`, `health`, `deadcode`, `fix`,
  `diagnose`, `advise`, `metrics`, `conventions`, `diff`, `drift`, `history`,
  `gate`, `review`, `report`, `explain`, `export context`, `export graph`.
- Code-smell detectors over the resolved call graph: feature envy, large
  class, and data clumps; counted by `gate` and named by `review`.
- `ovecc mcp`: Model Context Protocol server over stdio exposing every command
  as an agent tool.
- Drop-in GitHub Action (`action.yml`): indexes base and head of a PR, comments
  the named new defects, and gates on severity.
- Output formats: `text`, `json`, `ndjson`, `markdown`, plus `sarif` and
  `codeclimate`; stable exit codes for CI.
- Governance rules in `.ovecc/config.toml`: module boundaries, banned imports,
  severities, baselines, inline `ovecc-ignore` suppressions.
- Languages: JavaScript/TypeScript (tree-sitter + oxc resolution, complexity,
  exports); Python, Go, Rust, and C++ through a specification-driven adapter.
