# ovecc-core

## Purpose

`ovecc-core` is the foundation crate. It holds the data model, the typed
identifiers, the configuration, the error type, and the trait contracts that the
specialized crates implement. It depends on no other workspace crate, so it
defines the vocabulary the rest of the system speaks without creating cycles.

Nothing in this crate performs analysis. It describes *what* the system
manipulates, not *how* any stage does its work.

## Modules

- `facts` — the architecture data model in two layers:
  - Raw `*Fact` types (`SymbolFact`, `CallFact`, `ImportFact`, `ApiFact`,
    `SchemaRefFact`, `SecurityPatternFact`) are what a language adapter extracts
    from a single file, before any cross-file resolution: no stable IDs, no
    module attribution.
  - Normalized `*Record` types (`SymbolRecord`, `CallRecord`, `DependencyRecord`,
    `FindingRecord`, ...) are the resolved, persistable form and mirror the
    database tables one to one. The indexer is the only component that converts
    facts into records.
- `id` — typed stable identifiers (`SymbolId`, `CallId`, `FileId`, ...). Each is
  a content hash of its defining parts (`from_parts`) so the same entity gets the
  same id across runs, which is what makes differential indexing possible.
- `lang` — `SourceLanguage` and extension detection.
- `config` — `OveccConfig`, `ProjectPaths`, CLI overrides, and the `[languages]`
  gate.
- `error` — `OveccError` and the stable `ExitCode` mapping.
- `traits` — the contracts the other crates implement: `LanguageAdapter`
  (ovecc-parser), `ArchitectureStore` (ovecc-db), `GitProvider` (ovecc-git),
  `Rule` and `ConventionLearner` (ovecc-rules), `ExplanationProvider` (ovecc-ai),
  `Renderable` (rendering).
- `graph` — graph value types (`NodeKind`, `GraphNode`, `GraphEdge`, layers).
- `query` — the structured query grammar (`Query`, `TargetSelector`) and the
  shared target syntax.
- `report` — output shapes for the CLI: `ContextSlice`, `IndexTimings`,
  and the per-command report structs.
- `legacy` — transitional types carried over from the pre-workspace MVP. They are
  being replaced by the `facts`/`report` models as the migration finishes; no new
  features are built on them.

## Place in the pipeline

Every other crate depends on `ovecc-core` and on nothing heavier from the
workspace. Adapters return `FileFacts`; the store accepts `FactBatch`; rules
return `FindingRecord`s; the CLI renders `report` types. The contracts live here
so those crates never need to depend on each other directly.
