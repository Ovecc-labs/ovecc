# Changelog

Notable changes to ovecc are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0, minor releases may contain breaking
changes).

## [Unreleased]

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
