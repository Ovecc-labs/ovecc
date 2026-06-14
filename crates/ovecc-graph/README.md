# ovecc-graph

## Purpose

`ovecc-graph` holds the graph algorithms that run over the persisted model. It
takes plain node and edge data, computes structural results, and returns them;
it does not read the database or the filesystem itself.

## What it computes

- **Blast radius** (`blast` module) — `resolve_target` maps a target string
  (`Billing`, `table:customers`, `api:GET:/x`) to a graph node, and
  `blast_radius` runs a depth-bounded traversal upstream, downstream, or both,
  returning the impacted nodes and the concrete paths that reach them. This backs
  `impact`, the graph `query` verbs, and the `ContextSlice`.
- **Hotspots** (`compute_hotspots`) — the weighted risk score over
  churn, coupling, fan-in, fan-out, ownership fragmentation, and violations,
  normalized to a 0–100 scale.
- **Cycles** (`strongly_connected_modules`) — strongly connected components of the
  module graph, i.e. circular dependencies.
- **Instability** — the fan-in/fan-out instability metric per module.
- **Conventions** (`conventions` module) — `learn_conventions` infers the
  repository's dominant rules (dependency direction, database-access boundaries)
  with a confidence score, and reports deviations above thresholds.

## Place in the pipeline

The indexer uses this crate during the analyze phase to compute snapshot metrics
and conventions; the CLI uses it to answer `impact`, `hotspots`, `conventions`,
and the graph `query` verbs. Centrality and richer layered views are noted in the
architecture as later additions.
