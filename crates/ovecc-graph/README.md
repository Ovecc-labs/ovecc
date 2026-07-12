# ovecc-graph

Graph algorithms over the persisted model. The crate takes plain node and
edge data and returns structural results; it reads neither the database nor
the filesystem.

- Blast radius (`blast`): `resolve_target` maps a target string (`Billing`,
  `table:customers`, `api:GET:/x`) to a graph node, and `blast_radius` runs
  a depth-bounded traversal upstream, downstream, or both, returning the
  impacted nodes and the concrete paths that reach them. Backs `impact`, the
  graph `query` verbs, and the `ContextSlice`.
- Diagnosis (`diagnose`): the component-level detectors behind
  `ovecc diagnose` and `advise`: cyclic dependencies with witness edges,
  hub-like components, unstable dependencies, zone of pain, god components,
  hotspots, unstable interfaces, and change coupling.
- Duplication (`dupes`): token-based clone detection over the indexed files.
- Hotspots (`compute_hotspots`): the weighted risk score over churn,
  coupling, fan-in, fan-out, ownership fragmentation, and violations,
  normalized to a 0-100 scale.
- Cycles (`cycles`): strongly connected components of the module graph, with
  the elementary loops that witness them.
- Conventions (`conventions`): `learn_conventions` infers the repository's
  dominant rules (dependency direction, database-access boundaries) with a
  confidence score, and reports deviations above thresholds.

The indexer computes snapshot metrics and conventions with this crate; the
CLI uses it to answer `impact`, `hotspots`, `diagnose`, `dupes`,
`conventions`, and the graph `query` verbs.
