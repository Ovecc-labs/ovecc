//! Deterministic data-flow / taint analysis.
//!
//! # Source → sink reachability
//!
//! This is the reachability query layer of the taint engine: a deterministic
//! source-to-sink **reachability** query over the persisted architecture
//! graph.
//!
//! - **Sources**: API handler symbols — externally reachable, user-controlled
//!   entry points (`apis.handler_symbol_id`, via the `handles` edge).
//! - **Sinks**: symbols that touch the database (a `reads`/`writes` edge to a
//!   table) — the SQL operations where untrusted input is dangerous.
//! - **Propagation**: a depth-bounded forward BFS over `handles` + `calls`
//!   edges. A sink reached from a source is a candidate tainted flow, reported
//!   with the full path as evidence.
//! - **Requirement**: some symbol on the path must read client-sent request
//!   data (`req.body`, `req.query`, ...). A route that reaches a table without
//!   any of them carries nothing the caller controls, so it is not a flow. A
//!   public endpoint listing a public table is the case this exists to drop.
//!
//! **Honest limitation:** this is *control-flow reachability*, an
//! over-approximation — it proves that a handler which reads client input *can*
//! reach a DB operation through the call graph, not that the tainted value is
//! the one flowing into the sink argument. Precise value tracking (SSA,
//! points-to/alias, dynamic dispatch resolution) is a future refinement.
//! Findings are therefore Medium/High and explicitly framed as "requires review".

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::Utc;
use ovecc_core::facts::{EntityRef, Evidence, FindingKind, FindingRecord, Severity};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_graph::blast::{BlastEdge, BlastNode};

/// Default call-depth bound for taint propagation. Higher than blast's
/// indirection bound because handler→…→DB call chains are often longer; still
/// bounded to keep the analysis tractable.
pub const DEFAULT_FLOW_DEPTH: usize = 8;

/// Source locations for flow endpoints, so findings cite real `file:line`
/// evidence instead of just labels. All maps are optional; a missing entry
/// degrades to label-only evidence.
#[derive(Debug, Default, Clone)]
pub struct FlowLocations {
    /// API node id → where the route is declared.
    pub apis: HashMap<String, Evidence>,
    /// (accessor symbol id, table id) → where the DB access happens.
    pub db_accesses: HashMap<(String, String), Evidence>,
    /// Dangerous-call symbol id → where the eval/exec happens.
    pub dangerous: HashMap<String, Evidence>,
}

/// The graph a flow analysis runs over, with the two symbol sets that give it
/// its endpoints.
#[derive(Debug, Clone, Copy)]
pub struct FlowGraph<'a> {
    pub nodes: &'a [BlastNode],
    pub edges: &'a [BlastEdge],
    /// Symbols that execute code or a command: `(symbol id, "eval" | "command")`.
    pub dangerous: &'a [(String, String)],
    /// Symbols that read client-sent request data.
    pub client_inputs: &'a [String],
}

/// Analyzes source→sink reachability and returns one finding per distinct
/// (source API, sink symbol, table) flow.
pub fn analyze(
    repository_id: &str,
    snapshot_id: Option<&str>,
    graph: &FlowGraph<'_>,
    locations: &FlowLocations,
    max_depth: usize,
) -> Vec<FindingRecord> {
    let node_by_id: HashMap<&str, &BlastNode> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();

    // Forward adjacency over propagation edges, and the DB-access adjacency
    // (symbol → tables it reads/writes) that marks SQL sinks.
    let mut forward: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut db_access: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for edge in graph.edges {
        match edge.kind.as_str() {
            "handles" | "calls" => forward
                .entry(edge.source.as_str())
                .or_default()
                .push(edge.target.as_str()),
            "reads" | "writes" => db_access
                .entry(edge.source.as_str())
                .or_default()
                .push((edge.target.as_str(), edge.kind.as_str())),
            _ => {}
        }
    }
    // Dangerous-call sinks: symbol → label ("eval" | "command").
    let dangerous_by_id: HashMap<&str, &str> = graph
        .dangerous
        .iter()
        .map(|(id, label)| (id.as_str(), label.as_str()))
        .collect();
    let walk = Walk {
        forward,
        db_access,
        dangerous_by_id,
        client_inputs: graph.client_inputs.iter().map(String::as_str).collect(),
        node_by_id,
        locations,
        max_depth,
    };

    let mut findings = Vec::new();
    let mut seen_flows: HashSet<(String, String, String)> = HashSet::new();

    // Each API node is a taint source.
    for source in graph.nodes.iter().filter(|node| node.kind == "api") {
        for flow in trace_flows(source, &walk) {
            let dedup_key = (
                source.id.clone(),
                flow.sink_symbol_id.clone(),
                flow.sink_label.clone(),
            );
            if !seen_flows.insert(dedup_key) {
                continue;
            }
            findings.push(flow.into_finding(repository_id, snapshot_id, source, locations));
        }
    }

    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings
}

/// The adjacency the BFS reads, built once and shared by every source.
struct Walk<'a> {
    forward: HashMap<&'a str, Vec<&'a str>>,
    db_access: HashMap<&'a str, Vec<(&'a str, &'a str)>>,
    dangerous_by_id: HashMap<&'a str, &'a str>,
    client_inputs: HashSet<&'a str>,
    node_by_id: HashMap<&'a str, &'a BlastNode>,
    locations: &'a FlowLocations,
    max_depth: usize,
}

struct Flow {
    sink_symbol_id: String,
    /// `"writes"`, `"reads"`, `"eval"`, or `"command"`.
    sink_kind: String,
    /// Table name for a DB sink; the kind label for a dangerous call.
    sink_label: String,
    /// Node labels from the source through to the sink.
    path: Vec<String>,
    /// Where the sink statement lives, when known.
    sink_evidence: Option<Evidence>,
}

impl Flow {
    fn into_finding(
        self,
        repository_id: &str,
        snapshot_id: Option<&str>,
        source: &BlastNode,
        locations: &FlowLocations,
    ) -> FindingRecord {
        // Code/command execution reached from user input is the worst case;
        // a DB write is the classic injection; a read is lower.
        let severity = match self.sink_kind.as_str() {
            "eval" | "command" => Severity::Critical,
            "writes" => Severity::High,
            _ => Severity::Medium,
        };
        let what = match self.sink_kind.as_str() {
            "eval" => "dynamic code execution".to_string(),
            "command" => "OS command execution".to_string(),
            access => format!("database {access} on {}", self.sink_label),
        };
        FindingRecord {
            id: FindingId::from_parts(&[
                repository_id,
                "taint",
                &source.id,
                &self.sink_symbol_id,
                &self.sink_kind,
                &self.sink_label,
            ]),
            repository_id: RepositoryId::from_raw(repository_id),
            snapshot_id: snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::TaintedFlow,
            severity,
            rule_name: Some(format!("taint/{}", self.sink_kind)),
            target: Some(EntityRef {
                kind: NodeKind::Symbol,
                id: self.sink_symbol_id.clone(),
            }),
            title: format!(
                "Potential tainted flow: {} -> {} ({})",
                source.label, self.sink_label, self.sink_kind
            ),
            description: format!(
                "User-controlled input from {} may reach {} via {}. \
                 Reachability over-approximation — requires review.",
                source.label,
                what,
                self.path.join(" -> ")
            ),
            evidence: {
                // Real locations first: the sink statement, then the route
                // declaration. Label-only evidence is the fallback when no
                // location was supplied.
                let mut evidence = Vec::new();
                if let Some(sink) = self.sink_evidence {
                    evidence.push(Evidence {
                        detail: Some(format!("sink: {}", self.sink_kind)),
                        ..sink
                    });
                }
                if let Some(api) = locations.apis.get(&source.id) {
                    evidence.push(Evidence {
                        detail: Some(format!("source: {}", source.label)),
                        ..api.clone()
                    });
                }
                if evidence.is_empty() {
                    evidence.push(Evidence {
                        file_path: source.label.clone(),
                        line: None,
                        symbol: Some(self.path.join(" -> ")),
                        detail: Some(format!("sink: {}", self.sink_kind)),
                    });
                }
                evidence
            },
            created_at: Utc::now(),
        }
    }
}

/// Depth-bounded forward BFS from one source, collecting every sink reached
/// (DB reads/writes and dangerous calls) once the path carries client input.
///
/// The visited set is keyed by `(node, carries input)` rather than by node
/// alone. A node reachable both through a symbol that reads the request and
/// through one that does not would otherwise keep whichever path arrived first,
/// and BFS order has nothing to do with which of the two is the real flow.
fn trace_flows(source: &BlastNode, walk: &Walk<'_>) -> Vec<Flow> {
    let Walk {
        forward,
        db_access,
        dangerous_by_id,
        client_inputs,
        node_by_id,
        locations,
        max_depth,
    } = walk;
    let mut flows = Vec::new();
    let mut visited: HashSet<(&str, bool)> = HashSet::new();
    visited.insert((source.id.as_str(), false));
    let mut queue: VecDeque<(&str, Vec<String>, usize, bool)> = VecDeque::from([(
        source.id.as_str(),
        vec![source.label.clone()],
        0usize,
        false,
    )]);

    while let Some((current, path, depth, carried)) = queue.pop_front() {
        // A symbol that both reads the request and queries the table is one
        // node, so the source check runs before the sink checks.
        let tainted = carried || client_inputs.contains(current);
        // DB sink?
        if tainted && let Some(accesses) = db_access.get(current) {
            for (table_id, access) in accesses {
                let table_label = node_by_id
                    .get(table_id)
                    .map(|node| node.label.clone())
                    .unwrap_or_else(|| (*table_id).to_string());
                let mut sink_path = path.clone();
                sink_path.push(table_label.clone());
                flows.push(Flow {
                    sink_symbol_id: current.to_string(),
                    sink_kind: (*access).to_string(),
                    sink_label: table_label,
                    path: sink_path,
                    sink_evidence: locations
                        .db_accesses
                        .get(&(current.to_string(), (*table_id).to_string()))
                        .cloned(),
                });
            }
        }
        // Dangerous-call sink (eval / command exec)? An `eval` on a constant is
        // still reported, by the security pattern rule that owns it; this layer
        // only claims the ones a caller can steer.
        if tainted && let Some(label) = dangerous_by_id.get(current) {
            flows.push(Flow {
                sink_symbol_id: current.to_string(),
                sink_kind: (*label).to_string(),
                sink_label: (*label).to_string(),
                path: path.clone(),
                sink_evidence: locations.dangerous.get(current).cloned(),
            });
        }
        if depth >= *max_depth {
            continue;
        }
        if let Some(neighbors) = forward.get(current) {
            let mut sorted: Vec<&str> = neighbors.clone();
            sorted.sort_unstable();
            sorted.dedup();
            for neighbor in sorted {
                if !visited.insert((neighbor, tainted)) {
                    continue;
                }
                let mut next_path = path.clone();
                if let Some(node) = node_by_id.get(neighbor) {
                    next_path.push(node.label.clone());
                }
                queue.push_back((neighbor, next_path, depth + 1, tainted));
            }
        }
    }
    flows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: &str, label: &str) -> BlastNode {
        BlastNode {
            id: id.to_string(),
            kind: kind.to_string(),
            label: label.to_string(),
            file: None,
            line: None,
        }
    }
    fn edge(source: &str, target: &str, kind: &str) -> BlastEdge {
        BlastEdge {
            source: source.to_string(),
            target: target.to_string(),
            kind: kind.to_string(),
        }
    }
    /// The default bound, no snapshot, no dangerous calls: what every test but
    /// the depth and eval ones runs.
    fn flows(
        nodes: &[BlastNode],
        edges: &[BlastEdge],
        client_inputs: &[String],
    ) -> Vec<FindingRecord> {
        analyze(
            "r",
            None,
            &FlowGraph {
                nodes,
                edges,
                dangerous: &[],
                client_inputs,
            },
            &FlowLocations::default(),
            DEFAULT_FLOW_DEPTH,
        )
    }

    #[test]
    fn finds_flow_from_api_to_db_write() {
        // api --handles--> handler --calls--> repo --writes--> customers
        let nodes = vec![
            node("a:1", "api", "POST /customers"),
            node("s:handler", "symbol", "createCustomer"),
            node("s:repo", "symbol", "CustomerRepo.insert"),
            node("t:customers", "table", "customers"),
            node("s:unrelated", "symbol", "helper"),
        ];
        let edges = vec![
            edge("a:1", "s:handler", "handles"),
            edge("s:handler", "s:repo", "calls"),
            edge("s:repo", "t:customers", "writes"),
        ];

        let findings = analyze(
            "repo:test",
            Some("snap"),
            &FlowGraph {
                nodes: &nodes,
                edges: &edges,
                dangerous: &[],
                client_inputs: &["s:handler".to_string()],
            },
            &FlowLocations::default(),
            DEFAULT_FLOW_DEPTH,
        );
        assert_eq!(findings.len(), 1);
        let flow = &findings[0];
        assert_eq!(flow.kind, FindingKind::TaintedFlow);
        assert_eq!(flow.severity, Severity::High, "a write sink is High");
        assert!(flow.description.contains("createCustomer"));
        assert!(flow.description.contains("customers"));
        assert!(flow.description.contains("CustomerRepo.insert"));
    }

    #[test]
    fn no_flow_when_sink_is_unreachable() {
        // The DB write is in a symbol the handler never calls.
        let nodes = vec![
            node("a:1", "api", "GET /ping"),
            node("s:handler", "symbol", "ping"),
            node("s:repo", "symbol", "CustomerRepo.insert"),
            node("t:customers", "table", "customers"),
        ];
        let edges = vec![
            edge("a:1", "s:handler", "handles"),
            edge("s:repo", "t:customers", "writes"),
        ];
        assert!(flows(&nodes, &edges, &["s:handler".to_string()]).is_empty());
    }

    #[test]
    fn flow_to_eval_sink_is_critical() {
        // api --handles--> handler --calls--> run, and `run` does eval.
        let nodes = vec![
            node("a:1", "api", "POST /run"),
            node("s:handler", "symbol", "handle"),
            node("s:run", "symbol", "runUserCode"),
        ];
        let edges = vec![
            edge("a:1", "s:handler", "handles"),
            edge("s:handler", "s:run", "calls"),
        ];
        let dangerous = vec![("s:run".to_string(), "eval".to_string())];
        let findings = analyze(
            "repo:test",
            None,
            &FlowGraph {
                nodes: &nodes,
                edges: &edges,
                dangerous: &dangerous,
                client_inputs: &["s:handler".to_string()],
            },
            &FlowLocations::default(),
            DEFAULT_FLOW_DEPTH,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("eval"));
    }

    #[test]
    fn read_sink_is_medium_severity() {
        let nodes = vec![
            node("a:1", "api", "GET /customers"),
            node("s:handler", "symbol", "listCustomers"),
            node("t:customers", "table", "customers"),
        ];
        let edges = vec![
            edge("a:1", "s:handler", "handles"),
            edge("s:handler", "t:customers", "reads"),
        ];
        let findings = flows(&nodes, &edges, &["s:handler".to_string()]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn a_route_that_never_reads_the_request_is_not_a_flow() {
        // `GET /stats/public` listing a public table: reachability says the
        // route touches the table, and there is nothing the caller can steer.
        let nodes = vec![
            node("a:1", "api", "GET /stats/public"),
            node("s:handler", "symbol", "publicStats"),
            node("t:trips", "table", "trips"),
        ];
        let edges = vec![
            edge("a:1", "s:handler", "handles"),
            edge("s:handler", "t:trips", "reads"),
        ];
        let findings = flows(&nodes, &edges, &[]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn input_read_below_the_handler_still_reaches_the_sink() {
        // The handler passes `req` down; the service is what reads it. The
        // second path exists so the shorter untainted one is dequeued first,
        // which is what the (node, tainted) visited key is for.
        let nodes = vec![
            node("a:1", "api", "GET /trips"),
            node("s:h", "symbol", "listTrips"),
            node("s:svc", "symbol", "TripService.list"),
            node("s:repo", "symbol", "TripRepo.find"),
            node("t:trips", "table", "trips"),
        ];
        let edges = vec![
            edge("a:1", "s:h", "handles"),
            edge("s:h", "s:repo", "calls"),
            edge("s:h", "s:svc", "calls"),
            edge("s:svc", "s:repo", "calls"),
            edge("s:repo", "t:trips", "reads"),
        ];
        let findings = flows(&nodes, &edges, &["s:svc".to_string()]);
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn depth_bound_stops_long_chains() {
        // api -> h -> a -> b -> c -> writes; bound of 2 cannot reach it.
        let nodes = vec![
            node("a:1", "api", "POST /x"),
            node("s:h", "symbol", "h"),
            node("s:a", "symbol", "a"),
            node("s:b", "symbol", "b"),
            node("s:c", "symbol", "c"),
            node("t:x", "table", "x"),
        ];
        let edges = vec![
            edge("a:1", "s:h", "handles"),
            edge("s:h", "s:a", "calls"),
            edge("s:a", "s:b", "calls"),
            edge("s:b", "s:c", "calls"),
            edge("s:c", "t:x", "writes"),
        ];
        let graph = FlowGraph {
            nodes: &nodes,
            edges: &edges,
            dangerous: &[],
            client_inputs: &["s:h".to_string()],
        };
        assert!(analyze("r", None, &graph, &FlowLocations::default(), 2).is_empty());
        assert_eq!(
            analyze(
                "r",
                None,
                &graph,
                &FlowLocations::default(),
                DEFAULT_FLOW_DEPTH
            )
            .len(),
            1
        );
    }

    #[test]
    fn duplicate_edges_do_not_double_report() {
        // The same write edge appears twice; the (source, sink, table) dedup
        // must collapse them into a single finding.
        let nodes = vec![
            node("a:1", "api", "POST /customers"),
            node("s:repo", "symbol", "CustomerRepo.insert"),
            node("t:customers", "table", "customers"),
        ];
        let edges = vec![
            edge("a:1", "s:repo", "handles"),
            edge("s:repo", "t:customers", "writes"),
            edge("s:repo", "t:customers", "writes"),
        ];
        assert_eq!(flows(&nodes, &edges, &["s:repo".to_string()]).len(), 1);
    }

    #[test]
    fn one_source_reaching_two_tables_yields_two_findings() {
        // A handler that both writes one table and reads another is two flows.
        let nodes = vec![
            node("a:1", "api", "ALL /x"),
            node("s:h", "symbol", "handle"),
            node("t:a", "table", "accounts"),
            node("t:b", "table", "audit"),
        ];
        let edges = vec![
            edge("a:1", "s:h", "handles"),
            edge("s:h", "t:a", "writes"),
            edge("s:h", "t:b", "reads"),
        ];
        let findings = flows(&nodes, &edges, &["s:h".to_string()]);
        assert_eq!(findings.len(), 2, "distinct tables are distinct flows");
    }
}
