//! Blast-radius analysis over the persisted architecture graph.
//!
//! Works on any node/edge slice (modules, symbols, APIs, tables, ...) loaded
//! from `graph_edges`, so the same engine answers `impact BillingService`,
//! `impact table:customers`, and `impact api:GET:/users`.
//!
//! Traversal is a **depth-bounded** reverse BFS. The bound `k` implements the
//! indirection limit: the vast majority of
//! significant impact reaches within a low indirection depth, so capping at
//! `k≈3` preserves precision/recall while avoiding combinatorial blow-up.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use ovecc_core::legacy::{ImpactDirection, RiskLevel};
use serde::Serialize;

/// Default indirection bound (recommends 2–4; 3 is the sweet spot).
pub const DEFAULT_MAX_DEPTH: usize = 3;

/// Edge kinds traversed by default during impact analysis.
pub const IMPACT_EDGE_KINDS: &[&str] = &[
    "depends_on",
    "calls",
    "reads",
    "writes",
    "exposes",
    "handles",
];

/// A persisted graph node, reduced to what blast analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlastNode {
    pub id: String,
    /// `graph_nodes.node_kind` (e.g. `module`, `symbol`, `api`, `table`).
    pub kind: String,
    pub label: String,
}

/// A persisted directed graph edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlastEdge {
    pub source: String,
    pub target: String,
    pub kind: String,
}

/// (impacted entities by category and representative paths).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlastResult {
    pub target_id: String,
    pub target_label: String,
    pub impacted_modules: usize,
    pub impacted_apis: usize,
    pub impacted_tables: usize,
    pub impacted_symbols: usize,
    /// Dependent source files reached over file→file dependency edges. This is
    /// the file-granularity blast radius the module counts can't express.
    pub impacted_files: usize,
    /// Labels of every impacted node, sorted for determinism.
    pub impacted_labels: Vec<String>,
    /// Up to a few representative label paths from the target outward.
    pub paths: Vec<Vec<String>>,
    pub risk_value: u32,
    pub risk: RiskLevel,
}

/// Coarse category of a node, derived from its `node_kind` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    Module,
    Api,
    Table,
    Symbol,
    File,
    Other,
}

fn categorize(kind: &str) -> Category {
    match kind {
        "module" | "namespace" => Category::Module,
        "api" | "route" | "rpc_method" | "event" => Category::Api,
        "table" | "view" | "column" => Category::Table,
        "symbol" | "function" | "class" | "trait" | "interface" | "type" => Category::Symbol,
        "file" => Category::File,
        _ => Category::Other,
    }
}

/// Resolves a user target string to a node id, honoring the prefixes:
/// `table:name`, `api:METHOD:/path` (or `api:name`), or a free label/id match.
/// Returns the single match, or `None` when nothing or several things match
/// (the caller decides how to disambiguate).
pub fn resolve_target<'a>(input: &str, nodes: &'a [BlastNode]) -> Option<&'a BlastNode> {
    // Exact id match wins outright.
    if let Some(node) = nodes.iter().find(|node| node.id == input) {
        return Some(node);
    }

    let (kind_filter, needles): (Option<Category>, Vec<String>) =
        if let Some(rest) = input.strip_prefix("table:") {
            (Some(Category::Table), vec![rest.to_string()])
        } else if let Some(rest) = input.strip_prefix("api:") {
            (Some(Category::Api), api_needles(rest))
        } else {
            (None, vec![input.to_string()])
        };
    let lowered: Vec<String> = needles
        .iter()
        .map(|needle| needle.to_ascii_lowercase())
        .collect();

    let in_category = |node: &BlastNode| {
        kind_filter
            .map(|category| categorize(&node.kind) == category)
            .unwrap_or(true)
    };
    let exact = |node: &BlastNode| {
        needles
            .iter()
            .any(|needle| node.label.eq_ignore_ascii_case(needle))
    };

    let mut matches = nodes.iter().filter(|node| {
        in_category(node)
            && (exact(node) || {
                let label = node.label.to_ascii_lowercase();
                lowered.iter().any(|needle| label.contains(needle))
            })
    });
    let first = matches.next()?;
    // Prefer an exact (case-insensitive) label match if one exists among many.
    if matches.next().is_none() {
        return Some(first);
    }
    nodes
        .iter()
        .find(|node| in_category(node) && exact(node))
        .or(Some(first))
}

// An `api:METHOD:/path` target may be labeled "METHOD:/path" or "METHOD /path"
// in the graph; search with both spellings.
fn api_needles(rest: &str) -> Vec<String> {
    let mut needles = vec![rest.to_string()];
    if let Some((method, path)) = rest.split_once(':')
        && !method.is_empty()
        && method.chars().all(|c| c.is_ascii_alphabetic())
    {
        needles.push(format!("{method} {path}").trim().to_string());
    }
    needles
}

/// The "did you mean" pool for a target `resolve_target` returned `None` for:
/// nodes whose label sits within a small edit distance of the input, closest
/// first. Ties go to the node with the most incoming impact edges (the most
/// referenced element is the likeliest intent), then to label order, so the
/// list is identical run to run.
pub fn closest_targets<'a>(
    input: &str,
    nodes: &'a [BlastNode],
    edges: &[BlastEdge],
    limit: usize,
) -> Vec<&'a BlastNode> {
    let needle = input
        .strip_prefix("table:")
        .or_else(|| input.strip_prefix("api:"))
        .unwrap_or(input)
        .to_ascii_lowercase();
    // One tolerated edit per four characters: a 7-char target forgives two
    // typos, a 3-char one only a single edit. Looser and the pool fills with
    // noise; resolve_target already handled every substring match.
    let budget = 1 + needle.chars().count() / 4;

    let impact_kinds: HashSet<&str> = IMPACT_EDGE_KINDS.iter().copied().collect();
    let mut incoming: HashMap<&str, usize> = HashMap::new();
    for edge in edges {
        if impact_kinds.contains(edge.kind.as_str()) {
            *incoming.entry(edge.target.as_str()).or_default() += 1;
        }
    }

    let mut scored: Vec<(usize, std::cmp::Reverse<usize>, &str, &BlastNode)> = nodes
        .iter()
        .filter_map(|node| {
            let distance = label_distance(&needle, &node.label);
            (distance <= budget).then(|| {
                let references = incoming.get(node.id.as_str()).copied().unwrap_or(0);
                (
                    distance,
                    std::cmp::Reverse(references),
                    node.label.as_str(),
                    node,
                )
            })
        })
        .collect();
    scored.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    scored.truncate(limit);
    scored.into_iter().map(|(.., node)| node).collect()
}

// A file label is a path and a nested module label may be `a::b::c`; the user
// usually types the leaf (`sync.rs`, `c`), so the leaf competes on equal
// footing with the full label.
fn label_distance(needle: &str, label: &str) -> usize {
    let label = label.to_ascii_lowercase();
    let mut best = levenshtein(needle, &label);
    for separator in ["/", "::"] {
        if let Some((_, leaf)) = label.rsplit_once(separator) {
            best = best.min(levenshtein(needle, leaf));
        }
    }
    best
}

// Two-row Levenshtein over chars; label and needle are short, no need for a
// dependency or early exit.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() || b.is_empty() {
        return a.len().max(b.len());
    }
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != cb);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

/// The CLI-typable form of a node: the prefix `resolve_target` parses back,
/// plus the label. Modules, files, and symbols resolve by bare label.
pub fn target_syntax(node: &BlastNode) -> String {
    match categorize(&node.kind) {
        Category::Table => format!("table:{}", node.label),
        Category::Api => format!("api:{}", node.label),
        _ => node.label.clone(),
    }
}

/// Computes the blast radius of `target_id` over the impact edge kinds.
///
/// Impact follows reverse dependency direction by default: if `A`
/// depends on / calls `B`, changing `B` may affect `A`, so we walk edges
/// backwards from the target to its dependents.
pub fn blast_radius(
    nodes: &[BlastNode],
    edges: &[BlastEdge],
    target_id: &str,
    direction: ImpactDirection,
    max_depth: usize,
) -> Option<BlastResult> {
    let node_by_id: HashMap<&str, &BlastNode> =
        nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    let target = *node_by_id.get(target_id)?;

    let impact_kinds: HashSet<&str> = IMPACT_EDGE_KINDS.iter().copied().collect();

    // Adjacency restricted to impact edges. `predecessors`: who points at a
    // node (downstream impact). `successors`: what a node points at (upstream).
    let mut predecessors: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut successors: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in edges {
        if !impact_kinds.contains(edge.kind.as_str()) {
            continue;
        }
        predecessors
            .entry(edge.target.as_str())
            .or_default()
            .push(edge.source.as_str());
        successors
            .entry(edge.source.as_str())
            .or_default()
            .push(edge.target.as_str());
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut paths: Vec<Vec<String>> = Vec::new();
    let mut queue: VecDeque<(&str, Vec<&str>, usize)> =
        VecDeque::from([(target_id, vec![target_id], 0usize)]);

    while let Some((current, path, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let mut neighbors: Vec<&str> = Vec::new();
        if matches!(
            direction,
            ImpactDirection::Downstream | ImpactDirection::Both
        ) && let Some(preds) = predecessors.get(current)
        {
            neighbors.extend(preds.iter().copied());
        }
        if matches!(direction, ImpactDirection::Upstream | ImpactDirection::Both)
            && let Some(succs) = successors.get(current)
        {
            neighbors.extend(succs.iter().copied());
        }
        // Deterministic, duplicate-free expansion.
        neighbors.sort_unstable();
        neighbors.dedup();
        for neighbor in neighbors {
            if neighbor == target_id || !visited.insert(neighbor) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(neighbor);
            paths.push(label_path(&next_path, &node_by_id));
            queue.push_back((neighbor, next_path, depth + 1));
        }
    }

    let (mut modules, mut apis, mut tables, mut symbols, mut files) = (0, 0, 0, 0, 0);
    for id in &visited {
        match node_by_id.get(id).map(|node| categorize(&node.kind)) {
            Some(Category::Module) => modules += 1,
            Some(Category::Api) => apis += 1,
            Some(Category::Table) => tables += 1,
            Some(Category::Symbol) => symbols += 1,
            Some(Category::File) => files += 1,
            _ => {}
        }
    }

    // Impacted files weigh like symbols (1 each) in the risk score, so a file
    // with many dependents doesn't score Low just because no module is crossed.
    let (risk_value, risk) = risk_score(modules, apis, tables, symbols + files, false);
    let mut impacted_labels: Vec<String> = visited
        .iter()
        .filter_map(|id| node_by_id.get(id).map(|node| node.label.clone()))
        .collect();
    impacted_labels.sort();
    paths.sort();
    paths.truncate(20);

    Some(BlastResult {
        target_id: target_id.to_string(),
        target_label: target.label.clone(),
        impacted_modules: modules,
        impacted_apis: apis,
        impacted_tables: tables,
        impacted_symbols: symbols,
        impacted_files: files,
        impacted_labels,
        paths,
        risk_value,
        risk,
    })
}

fn label_path(ids: &[&str], node_by_id: &HashMap<&str, &BlastNode>) -> Vec<String> {
    ids.iter()
        .map(|id| {
            node_by_id
                .get(id)
                .map(|node| node.label.clone())
                .unwrap_or_else(|| (*id).to_string())
        })
        .collect()
}

/// Risk score: a weighted sum of impacted entities mapped to a
/// severity band (0-24 Low, 25-49 Medium, 50-74 High, 75+ Critical). Public
/// surface (APIs) and shared data (tables) weigh more than internal symbols;
/// cycle membership adds a fixed penalty. `value` is capped at 100 for display
/// while the severity uses the uncapped score.
pub fn risk_score(
    modules: usize,
    apis: usize,
    tables: usize,
    symbols: usize,
    in_cycle: bool,
) -> (u32, RiskLevel) {
    let raw = modules * 5 + apis * 6 + tables * 6 + symbols + if in_cycle { 15 } else { 0 };
    let level = match raw {
        0..=24 => RiskLevel::Low,
        25..=49 => RiskLevel::Medium,
        50..=74 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };
    (raw.min(100) as u32, level)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: &str, label: &str) -> BlastNode {
        BlastNode {
            id: id.to_string(),
            kind: kind.to_string(),
            label: label.to_string(),
        }
    }
    fn edge(source: &str, target: &str, kind: &str) -> BlastEdge {
        BlastEdge {
            source: source.to_string(),
            target: target.to_string(),
            kind: kind.to_string(),
        }
    }

    #[test]
    fn reverse_reachability_classifies_and_bounds_depth() {
        // checkout --depends_on--> billing --depends_on--> user
        // controller --calls--> billing ; billing --reads--> customers(table)
        let nodes = vec![
            node("m:user", "module", "user"),
            node("m:billing", "module", "billing"),
            node("m:checkout", "module", "checkout"),
            node("s:controller", "symbol", "Controller"),
            node("t:customers", "table", "customers"),
        ];
        let edges = vec![
            edge("m:checkout", "m:billing", "depends_on"),
            edge("m:billing", "m:user", "depends_on"),
            edge("s:controller", "m:billing", "calls"),
            edge("m:billing", "t:customers", "reads"),
        ];

        // Impact of changing `user`: who (transitively) depends on it.
        let result = blast_radius(
            &nodes,
            &edges,
            "m:user",
            ImpactDirection::Downstream,
            DEFAULT_MAX_DEPTH,
        )
        .unwrap();
        // billing (depth 1), checkout + controller (depth 2)
        assert_eq!(result.impacted_modules, 2, "billing + checkout");
        assert_eq!(result.impacted_symbols, 1, "controller");
        assert_eq!(
            result.impacted_tables, 0,
            "tables are downstream of billing, not user"
        );
        assert!(result.impacted_labels.contains(&"checkout".to_string()));

        // Depth bound of 1 stops at direct dependents only.
        let shallow =
            blast_radius(&nodes, &edges, "m:user", ImpactDirection::Downstream, 1).unwrap();
        assert_eq!(shallow.impacted_modules, 1, "only billing at depth 1");
        assert_eq!(shallow.impacted_symbols, 0);
    }

    #[test]
    fn upstream_follows_dependencies_outward() {
        let nodes = vec![
            node("m:billing", "module", "billing"),
            node("m:user", "module", "user"),
            node("t:customers", "table", "customers"),
        ];
        let edges = vec![
            edge("m:billing", "m:user", "depends_on"),
            edge("m:billing", "t:customers", "reads"),
        ];
        let result = blast_radius(
            &nodes,
            &edges,
            "m:billing",
            ImpactDirection::Upstream,
            DEFAULT_MAX_DEPTH,
        )
        .unwrap();
        assert_eq!(result.impacted_modules, 1, "user");
        assert_eq!(result.impacted_tables, 1, "customers");
    }

    #[test]
    fn resolves_prefixed_and_free_targets() {
        let nodes = vec![
            node("m:billing", "module", "Billing"),
            node("t:customers", "table", "customers"),
            node("a:1", "api", "GET /users"),
        ];
        assert_eq!(resolve_target("Billing", &nodes).unwrap().id, "m:billing");
        assert_eq!(resolve_target("billing", &nodes).unwrap().id, "m:billing");
        assert_eq!(
            resolve_target("table:customers", &nodes).unwrap().id,
            "t:customers"
        );
        // `table:` prefix must not match the module of the same-ish name.
        assert_eq!(
            resolve_target("table:customers", &nodes).unwrap().kind,
            "table"
        );
        assert!(resolve_target("nonexistent", &nodes).is_none());
    }

    #[test]
    fn resolves_documented_api_target_forms() {
        let nodes = vec![
            node("m:users", "module", "users"),
            node("a:get", "api", "GET /users/:id"),
            node("a:post", "api", "POST /users/:id"),
            node("a:list", "api", "GET /users"),
        ];
        assert_eq!(
            resolve_target("api:GET:/users/:id", &nodes).unwrap().id,
            "a:get"
        );
        assert_eq!(
            resolve_target("api:post:/users/:id", &nodes).unwrap().id,
            "a:post"
        );
        assert_eq!(
            resolve_target("api:GET /users/:id", &nodes).unwrap().id,
            "a:get"
        );
        assert_eq!(resolve_target("api:/users", &nodes).unwrap().kind, "api");
        assert_eq!(
            resolve_target("api:GET:/users", &nodes).unwrap().id,
            "a:list"
        );
        assert!(resolve_target("api:DELETE:/users", &nodes).is_none());
    }

    #[test]
    fn typo_suggestions_rank_distance_then_references() {
        let nodes = vec![
            node("m:usery", "module", "usery"),
            node("m:users", "module", "users"),
            node("m:billing", "module", "billing"),
        ];
        // `users` and `usery` are both one edit from `user`; two modules
        // depending on `users` must rank it first.
        let edges = vec![
            edge("m:billing", "m:users", "depends_on"),
            edge("m:usery", "m:users", "depends_on"),
        ];
        let labels: Vec<&str> = closest_targets("user", &nodes, &edges, 5)
            .iter()
            .map(|n| n.label.as_str())
            .collect();
        assert_eq!(labels, vec!["users", "usery"]);
        assert!(closest_targets("zzzzz", &nodes, &edges, 5).is_empty());
    }

    #[test]
    fn suggestions_match_file_basenames_and_module_leaves() {
        let nodes = vec![
            node("f:sync", "file", "crates/ovecc-db/src/sync.rs"),
            node("m:leaf", "module", "billing::invoice"),
        ];
        // One substitution from the `/` basename, one from the `::` leaf.
        for (input, expected) in [("sinc.rs", "f:sync"), ("invoyce", "m:leaf")] {
            let suggested = closest_targets(input, &nodes, &[], 5);
            assert_eq!(suggested.len(), 1, "{input}");
            assert_eq!(suggested[0].id, expected, "{input}");
        }
    }

    #[test]
    fn target_syntax_restores_resolver_prefixes() {
        for (kind, label, expected) in [
            ("table", "customers", "table:customers"),
            ("api", "GET /users", "api:GET /users"),
            ("module", "billing", "billing"),
        ] {
            assert_eq!(target_syntax(&node("n", kind, label)), expected);
        }
    }

    #[test]
    fn risk_bands_follow_the_spec_thresholds() {
        assert_eq!(risk_score(0, 0, 0, 1, false).1, RiskLevel::Low); // 1
        assert_eq!(risk_score(4, 0, 0, 0, false).1, RiskLevel::Low); // 20
        assert_eq!(risk_score(5, 0, 0, 0, false).1, RiskLevel::Medium); // 25
        assert_eq!(risk_score(0, 5, 0, 0, false).1, RiskLevel::Medium); // 30
        assert_eq!(risk_score(8, 1, 1, 0, false).1, RiskLevel::High); // 40+6+6=52
        assert_eq!(risk_score(12, 4, 2, 0, false).1, RiskLevel::Critical); // 60+24+12=96
        // Cycle membership pushes a borderline case up a band.
        assert_eq!(risk_score(9, 0, 0, 0, true).1, RiskLevel::High); // 45+15=60
    }
}
