# ovecc-cli

## Purpose

`ovecc-cli` is the command-line interface for Ovecc. The command line is the primary interface: every capability is reachable without a dashboard, scriptable for CI, and deterministic. The binary is `ovecc`.

## Commands

- `index` — run the full pipeline and persist the model.
- `summary` — repository-level coupling, density, cycles, and risk score.
- `impact <target>` — blast radius of a change, upstream/downstream/both.
- `diff <base> <head>` / `drift` — compare two indexed points, with a CI failure threshold (`--fail-on`).
- `violations` — rule and security findings, with severity filtering and a CI baseline (`--baseline` / `--write-baseline`).
- `hotspots` — the weighted risk ranking.
- `conventions` — learned conventions and their deviations.
- `query "<expr>"` — the structured query grammar: `deps`, `rdeps`, `paths`, `module`, `a -> b`, `hotspots`, `violations`, `cycles`.
- `export context <target>` — the deterministic `ContextSlice` as JSON.
- `explain <target>` — an offline architectural explanation (`ovecc-ai`).

## Conventions

- **Output formats** — every command renders as text, JSON, NDJSON, or Markdown, selected by `--format` or the configured default. Machine-readable output goes to stdout; diagnostics go to stderr.
- **Exit codes** — stable across commands, so CI can branch on them.
- **`--stats`** — prints the per-phase indexing breakdown and the peak heap usage to stderr. A `peak_alloc` global allocator tracks the heap.

This crate wires the library crates together and owns argument parsing (`clap`) and rendering; the analysis itself lives in the crates it calls.
