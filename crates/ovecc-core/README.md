# ovecc-core

The data model, typed identifiers, configuration, error type, and trait
contracts that the specialized crates implement. It depends on no other
workspace crate: it defines the vocabulary the rest of the system speaks
without creating cycles, and nothing in it performs analysis.

Modules:

- `facts`: the architecture data model in two layers. Raw `*Fact` types
  (`SymbolFact`, `CallFact`, `ImportFact`, `ApiFact`, `SchemaRefFact`,
  `SecurityPatternFact`) are what a language adapter extracts from a single
  file, before any cross-file resolution: no stable IDs, no module
  attribution. Normalized `*Record` types (`SymbolRecord`, `CallRecord`,
  `DependencyRecord`, `FindingRecord`, ...) are the resolved, persistable
  form and mirror the database tables one to one. The indexer is the only
  component that converts facts into records.
- `id`: typed stable identifiers (`SymbolId`, `CallId`, `FileId`, ...), each
  a content hash of its defining parts, so the same entity gets the same id
  across runs. This is what makes differential indexing possible.
- `lang`: `SourceLanguage` and extension detection.
- `config`: `OveccConfig`, `ProjectPaths`, CLI overrides, and the
  `[languages]` gate.
- `error`: `OveccError` and the stable `ExitCode` mapping.
- `traits`: the cross-crate contracts (`LanguageAdapter`, `GitProvider`,
  `ArchitectureStore`, `Rule`, `ConventionLearner`, `ExplanationProvider`,
  `Renderable`), so the implementing crates never depend on each other
  directly.
- `graph`: graph value types (`NodeKind`, `GraphNode`, `GraphEdge`, layers).
- `query`: the structured query grammar (`Query`, `TargetSelector`) and the
  shared target syntax.
- `report`: output shapes for the CLI (`ContextSlice`, `IndexTimings`, and
  the per-command report structs).
- `legacy`: transitional types being replaced by the `facts`/`report`
  models; no new features are built on them.
