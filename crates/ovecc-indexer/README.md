# ovecc-indexer

## Purpose

`ovecc-indexer` orchestrates a full indexing run. It is the component that turns a
repository on disk into the persisted architecture model, coordinating every
other crate. It is also the only place that converts raw `*Fact`s into normalized
`*Record`s.

## The pipeline

`index_repository` runs five phases, each measured for `--stats`:

1. **Discovery** — walk the tree, apply include/exclude filters and the built-in
   exclusions, and select source files by extension.
2. **Parse** — hash and parse each file in parallel (rayon), serving unchanged
   files from the content-addressed parse cache so a re-run re-parses nothing. The JS/TS family goes to `TypeScriptAdapter`; every other language to
   `GenericAdapter`.
3. **Resolve** — assign stable ids, attach each fact to its file and module,
   resolve imports to files (per-language candidate generation plus a unique
   path-suffix match), and link the call graph
   (AST-only resolution, precision over recall). Call resolution is scoped by
   language so a callee never binds across language boundaries.
4. **Analyze** — compute snapshot metrics and conventions (`ovecc-graph`),
   evaluate rules, dead code, and code smells — feature envy, large class, data
   clumps — (`ovecc-rules`), run taint (`ovecc-dataflow`), audit dependencies
   (`ovecc-audit`), and ingest Git history (`ovecc-git`). Findings are
   deduplicated by id and inline-suppressed lines are dropped.
5. **Persist** — write the snapshot, graph, and findings through `ovecc-db` in one
   transaction.

## Incremental behaviour

A re-index of an unchanged repository parses zero files (parse cache) and writes
only a new snapshot (differential sync by stable id). A file that fails to parse
keeps the dependencies from its last successful run rather than appearing to have
none. Module boundaries are inferred from directory conventions
(`src/`, `crates/`, `packages/`, `services/`, ...).
