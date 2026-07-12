# ovecc-cli

The `ovecc` binary. Every capability is reachable from the command line,
scriptable for CI, and deterministic; there is no dashboard to click through.

The everyday commands:

- `index`: run the full pipeline and persist the model.
- `summary`: repository-level coupling, density, cycles, and risk score.
- `impact <target>`: blast radius of a change, upstream/downstream/both.
- `diff <base> <head>` / `drift`: compare two indexed points, with a CI
  failure threshold (`--fail-on`).
- `review <base> <head>`: the named findings a change introduced or resolved.
- `violations`: rule and security findings, with severity filtering and a CI
  baseline (`--baseline` / `--write-baseline`).
- `hotspots`: the weighted risk ranking.
- `conventions`: learned conventions and their deviations.
- `query "<expr>"`: the structured query grammar (`deps`, `rdeps`, `paths`,
  `module`, `a -> b`, `hotspots`, `violations`, `cycles`).
- `export context <target>`: the deterministic `ContextSlice` as JSON.
- `explain <target>`: an offline architectural explanation (`ovecc-ai`).

The full reference, including the analysis and maintenance commands, is in
[docs/COMMANDS.md](../../docs/COMMANDS.md).

Every command renders as text, JSON, NDJSON, or Markdown (`--format`).
Machine-readable output goes to stdout, diagnostics to stderr, and exit codes
are stable so CI can branch on them. `--stats` prints the per-phase indexing
breakdown and the peak heap usage.

This crate owns argument parsing (clap) and rendering; the analysis lives in
the crates it calls.
