# ovecc-indexer

Orchestrates a full indexing run: it turns a repository on disk into the
persisted architecture model, coordinating every other crate, and it is the
only place that converts raw `*Fact`s into normalized `*Record`s.

`index_repository` runs the phases that `--stats` reports:

1. Discovery (`discover`): walk the tree, apply the include/exclude filters
   and the built-in exclusions, skip generated files, and infer module names
   from directory conventions (`src/`, `crates/`, `packages/`, ...).
2. Parse: hash and parse every file in parallel (rayon), serving unchanged
   files from the content-addressed parse cache, so a re-run re-parses
   nothing. The JS/TS family goes to `TypeScriptAdapter`; every other
   language goes to `GenericAdapter`.
3. Resolve (`imports`, `resolve`): resolve imports to files (oxc_resolver
   for JS/TS, per-language candidate generation for the rest, precision over
   recall throughout), assign stable ids, and link the call graph. Call
   resolution is scoped by language, so a callee never binds across language
   boundaries.
4. Analyze: snapshot metrics and conventions (`ovecc-graph`), rules
   (`ovecc-rules`), taint (`ovecc-dataflow`), the OSV audit (`ovecc-audit`),
   Git ingestion (`ovecc-git`), complexity findings, dead code anchored on
   the detected entry points (`entrypoints`), code smells, and dependency
   hygiene (`hygiene`). Findings are deduplicated by id and
   inline-suppressed lines are dropped.
5. Persist: write the snapshot, graph, and findings through `ovecc-db` in
   one transaction.

A re-index of an unchanged repository parses zero files and writes only a
new snapshot. A file that fails to parse keeps the dependencies from its
last successful run rather than appearing to have none.
