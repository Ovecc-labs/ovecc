# Ovecc

Ovecc is a CLI-first architecture intelligence engine. It builds a deterministic,
persistent model of a repository and answers architectural questions about
structure, change impact, coupling, drift, ownership, security, and long-term
maintainability.

The focus is not code generation, chat, or dashboards. It is a reliable
architecture database and a set of deterministic analysis commands that make
architecture observable, queryable, measurable, and governable — built for an era
where AI-assisted coding raises both code output and the risk of architectural
erosion. An LLM may consume Ovecc's output, but it is never the source of truth.

```text
Repository -> deterministic analysis -> architecture database -> insights -> optional AI explanation
```

The full design is in [ARCHITECTURE.md](ARCHITECTURE.md). Measured performance on
real repositories is in [BENCHMARKS.md](BENCHMARKS.md).

## Build

The workspace builds on the `windows-gnu` toolchain (DuckDB is bundled and
compiled from source on the first build).

```sh
cargo build --release
cargo test --workspace
```

The binary is `ovecc` (`crates/ovecc-cli`).

## Quick start

```sh
ovecc index .              # parse, resolve, and persist the model into .ovecc/
ovecc summary              # coupling, density, cycles, risk score
ovecc violations           # rule and security findings
ovecc impact Billing       # blast radius of a change
ovecc query "deps Billing" # structured architecture query
ovecc explain Billing      # offline, deterministic explanation
ovecc index . --stats      # per-phase timing and peak memory
```

Every command renders as `text`, `json`, `ndjson`, or `markdown` via `--format`,
and returns stable exit codes for CI.

## Languages

A bespoke adapter covers the JavaScript/TypeScript family; a single
specification-driven adapter covers Python, Go, Rust, and C++. All feed the same
language-agnostic model, so resolution, the call graph, taint, and the rules work
across every supported language.

## Workspace layout

Ten library crates and one binary, each documented in its own `README.md`:

| Crate | Responsibility |
| --- | --- |
| [`ovecc-core`](crates/ovecc-core) | Data model, typed ids, config, error type, trait contracts |
| [`ovecc-parser`](crates/ovecc-parser) | Tree-sitter adapters and security pattern detection |
| [`ovecc-indexer`](crates/ovecc-indexer) | Indexing pipeline: discover, parse, resolve, analyze, persist |
| [`ovecc-db`](crates/ovecc-db) | DuckDB persistence, migrations, differential sync |
| [`ovecc-git`](crates/ovecc-git) | Native Git history, churn, ownership (via gix) |
| [`ovecc-graph`](crates/ovecc-graph) | Blast radius, hotspots, cycles, conventions |
| [`ovecc-rules`](crates/ovecc-rules) | Rule evaluation and security classification |
| [`ovecc-dataflow`](crates/ovecc-dataflow) | Source-to-sink taint reachability |
| [`ovecc-audit`](crates/ovecc-audit) | Offline OSV dependency audit |
| [`ovecc-ai`](crates/ovecc-ai) | Optional deterministic, offline explanation |
| [`ovecc-cli`](crates/ovecc-cli) | Command-line interface |

## Design guarantees

- **Deterministic before generative.** Every finding is traceable to explicit
  facts; the same input produces the same output.
- **Local and private.** Indexing, analysis, and explanation run on the machine;
  nothing is sent anywhere.
- **Incremental.** A re-index of an unchanged repository re-parses nothing and
  writes only a new snapshot.
