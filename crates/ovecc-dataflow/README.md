# ovecc-dataflow

## Purpose

`ovecc-dataflow` contains the taint analysis engine. It checks whether user-controlled inputs (sources) can reach dangerous actions (sinks) by querying the architecture graph.

## How it works

The analysis runs a depth-bounded forward breadth-first search (BFS) starting from each source:

- **Sources**: API handler symbols — externally reachable, user-controlled entry points connected to an `api` node via a `handles` edge.
- **Sinks**: Database operations (`reads` or `writes` edges to a table node) or dangerous call patterns (`eval` or OS command execution).
- **Path Evidence**: A sink reached from a source within the depth limit is reported as a potential tainted flow finding, including the traversal path.

The search is bounded to a default depth of 8 to prevent traversal loops and keep execution times predictable. Because the analysis performs control-flow reachability (over-approximation) rather than precise value-level tracking, findings are classified as warnings requiring developer review.

## Place in the pipeline

The indexer builds the flow graph from the resolved facts, passes the dangerous
sinks, and merges the resulting `TaintedFlow` findings with the rule findings
before persisting. Once the parser emits API routes and dangerous calls for a
language, full source-to-sink flows light up for that language with no change
here.
