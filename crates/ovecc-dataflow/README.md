# ovecc-dataflow

Taint analysis over the architecture graph: can user-controlled input reach
a dangerous action?

The engine runs a depth-bounded forward BFS from each source. Sources are
API handler symbols, the externally reachable entry points (connected to an
`api` node via a `handles` edge). Sinks are database operations
(`reads`/`writes` edges to a table node) and dangerous calls (`eval`, OS
command execution). A sink reached within the depth limit (default 8)
becomes a `TaintedFlow` finding carrying the traversal path as evidence.

The analysis is control-flow reachability, an over-approximation, not
value-level tracking, so findings are warnings for developer review rather
than proven exploits. The indexer builds the flow graph from the resolved
facts and merges the findings with the rule findings before persisting. Once
the parser emits API routes and dangerous calls for a language,
source-to-sink flows light up for that language with no change here.
