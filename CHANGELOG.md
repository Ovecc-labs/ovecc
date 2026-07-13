# Changelog

Notable changes to ovecc are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0, minor releases may contain breaking
changes).

## [Unreleased]

### Added

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
