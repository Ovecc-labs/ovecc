# Changelog

Notable changes to ovecc are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0, minor releases may contain breaking
changes).

## [Unreleased]

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

## [0.2.0] - 2026-07-18

### Added

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
