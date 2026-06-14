# ovecc-db

## Purpose

`ovecc-db` is the persistence layer. It owns the local architecture database — a
single embedded DuckDB file under `.ovecc/` — and implements the
`ArchitectureStore` contract. It is the only crate that issues SQL, and it keeps
no sibling-crate dependencies so the storage schema stays independent of the
analysis stages.

## Schema and migrations

The schema includes: repositories, files, modules, dependencies, symbols,
calls, apis, schema_objects, migrations, ownership, commits, file_changes, the
graph (`graph_nodes`/`graph_edges`), snapshots with their metrics, findings, and
the package inventory. Each table is created by a numbered, idempotent migration
(`v1` MVP baseline, `v2` full schema, `v3` package inventory) recorded in
`ovecc_schema`; `migrate_to_latest` applies the pending ones, each in its own
transaction.

## Incremental writes

`sync_current_index` writes one repository state in a single transaction:

- History is preserved. Facts are replaced per file, never wholesale; rows are
  diffed by their stable id, so re-indexing an unchanged file is a no-op and a
  changed file replaces only its own rows.
- The high-volume code facts (symbols, calls, and their graph nodes/edges) are
  written through the DuckDB **appender** rather than per-row `INSERT`s. The
  appender buffers into columnar chunks, which is dramatically cheaper for the
  thousands of rows a large repository produces. Within one batch, ids are
  deduplicated through `seen_*` sets before they reach the appender, because a
  duplicate primary key would otherwise surface only when the appender flushes on
  drop and would poison the transaction.

Snapshots, metrics, and findings accumulate across runs so `summary`, `diff`,
`drift`, and `violations` can read point-in-time and historical state.

## Reads

The store exposes the queries the CLI needs: `current_modules`,
`current_dependencies`, `findings`, snapshot resolution, graph-layer loading, and
the metric/drift accessors. Reads load only what a command needs rather than the
whole graph.
