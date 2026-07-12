# ovecc-db

The persistence layer: a single embedded DuckDB file under `.ovecc/`, owned
by `ArchitectureStore`. This is the only crate that issues SQL, and it keeps
no sibling-crate dependencies, so the storage schema stays independent of
the analysis stages.

The schema covers repositories, files, modules, dependencies, the code facts
(symbols, calls, apis, schema objects), per-function complexity and
per-file exports, Git history and ownership, the graph
(`graph_nodes`/`graph_edges`), snapshots with their metrics, findings with
per-snapshot retention, and the package inventory. Each table is created by
a numbered, idempotent migration recorded in `ovecc_schema`;
`migrate_to_latest` applies the pending ones in order, each in its own
transaction, and a shipped migration is never edited.

`sync_current_index` writes one repository state in a single transaction.
Rows are diffed by their stable id, so re-indexing an unchanged file is a
no-op and a changed file replaces only its own rows. The high-volume tables
go through the DuckDB appender rather than per-row `INSERT`s: the appender
buffers into columnar chunks, which is far cheaper for the tens of thousands
of rows a large repository produces. Ids are deduplicated before they reach
an appender, because a duplicate primary key would otherwise surface only
when the appender flushes on drop and poison the transaction.

Snapshots, metrics, and findings accumulate across runs so `summary`,
`diff`, `drift`, `review`, and `violations` can read point-in-time and
historical state. Reads load only what a command needs rather than the whole
graph.
