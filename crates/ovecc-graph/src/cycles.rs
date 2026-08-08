// SPDX-License-Identifier: MIT
//! Elementary circular-dependency enumeration.
//!
//! Tarjan's strongly-connected-components pass (iterative, `O(V + E)`) isolates
//! the cyclic components of the module graph, then an iterative-deepening DFS
//! enumerates the individual *elementary* cycles inside each component,
//! shortest-first and deterministic. This upgrades cycle reporting from
//! "these modules form a cycle" to the actual loops `A -> B -> C -> A`, which an
//! auditor can act on directly.
//!
//! The enumeration is bounded — at most [`MAX_CYCLES_PER_SCC`] cycles per
//! component and [`MAX_CYCLE_DEPTH`] nodes per cycle — so dense graphs stay
//! tractable. Output is canonicalized (rotated to the lexicographically-smallest
//! member) and deduplicated, then sorted by length then first-member name, so
//! identical inputs always produce byte-identical output.
//!
//! Portions of this file (the Tarjan SCC + iterative-deepening elementary-cycle
//! enumeration) are adapted from fallow (github.com/fallow-rs/fallow),
//! MIT (c) 2026 Bart Waardenburg. See THIRD-PARTY-NOTICES.md.

use ovecc_core::legacy::DependencyRecord;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Maximum number of elementary cycles enumerated per strongly-connected
/// component. Dense components have factorially many cycles; the shortest are
/// the most actionable, and iterative deepening surfaces those first.
pub const MAX_CYCLES_PER_SCC: usize = 20;

/// Maximum cycle length enumerated. Longer loops are rarely actionable and the
/// search is exponential in depth.
pub const MAX_CYCLE_DEPTH: usize = 12;

/// Local module→module adjacency, with self-edges and duplicates removed and
/// external dependencies dropped (only runtime, in-repository edges form a
/// reportable cycle).
struct ModuleAdjacency {
    /// Module names, indexed by node id (the position in this vector).
    names: Vec<String>,
    /// `succ[i]` = the distinct successor node ids of module `i`.
    succ: Vec<Vec<usize>>,
}

/// Whether a dependency edge can participate in a *runtime* cycle. Type-only
/// imports (`import type`) are erased at compile time — they contribute
/// coupling and reachability, but never a load-order loop, so cycle detection
/// (and its witnesses) must exclude them.
pub(crate) fn is_runtime_edge(dependency: &DependencyRecord) -> bool {
    dependency.dependency_kind != "type_import"
}

impl ModuleAdjacency {
    fn build(modules: &[String], dependencies: &[DependencyRecord]) -> Self {
        Self::from_module_edges(
            modules,
            dependencies
                .iter()
                .filter(|dependency| !dependency.is_external && is_runtime_edge(dependency))
                .map(|dependency| {
                    (
                        dependency.source_module.clone(),
                        dependency.target_module.clone(),
                    )
                }),
        )
    }

    /// Builds the adjacency from already-collapsed module→module edges (no
    /// file-level facts). External edges must be filtered by the caller; self
    /// edges and duplicates are dropped here, matching [`build`].
    fn from_module_edges(
        modules: &[String],
        edges: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        let names: Vec<String> = modules.to_vec();
        let index: HashMap<&str, usize> = names
            .iter()
            .enumerate()
            .map(|(i, name)| (name.as_str(), i))
            .collect();
        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); names.len()];
        let mut seen: Vec<HashSet<usize>> = vec![HashSet::new(); names.len()];
        for (source_module, target_module) in edges {
            if source_module == target_module {
                continue;
            }
            let (Some(&source), Some(&target)) = (
                index.get(source_module.as_str()),
                index.get(target_module.as_str()),
            ) else {
                continue;
            };
            if seen[source].insert(target) {
                succ[source].push(target);
            }
        }
        Self { names, succ }
    }
}

/// A concrete file-level import edge that participates in a module cycle — the
/// witness an auditor needs to actually cut the loop. `to_file` is `None` when
/// the dependency resolved to a module without a concrete target file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WitnessEdge {
    pub from_module: String,
    pub to_module: String,
    pub from_file: String,
    pub to_file: Option<String>,
    pub specifier: String,
    pub line: usize,
}

/// An elementary module cycle together with the file-level import edges that
/// form it. This upgrades "modules A and B form a cycle" to "src/a/x.ts:12
/// imports ../b/y, and src/b/z.ts:8 imports ../a/w" — directly fixable, and
/// it stops a consumer from having to guess (and mis-guess) the edges.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CycleWitness {
    /// Canonical module path of the cycle (same form as [`elementary_cycles`]).
    pub modules: Vec<String>,
    /// One representative file-level edge per consecutive module hop, in cycle
    /// order. May be shorter than `modules` if an edge has no in-repo witness.
    pub edges: Vec<WitnessEdge>,
}

/// Enumerates the elementary dependency cycles among `modules` as ordered
/// module-name paths (e.g. `["billing", "tasks"]` for `billing -> tasks ->
/// billing`). Shortest-first, canonicalized, deduplicated, and deterministic.
pub fn elementary_cycles(
    modules: &[String],
    dependencies: &[DependencyRecord],
) -> Vec<Vec<String>> {
    cycles_from_adjacency(&ModuleAdjacency::build(modules, dependencies))
}

/// Like [`elementary_cycles`] but over already-collapsed module→module edges
/// (no file-level facts). Lets a caller (e.g. snapshot drift) enumerate the
/// cycle set of a past snapshot, whose stored edges are module-level only.
pub fn module_cycles(modules: &[String], edges: &[(String, String)]) -> Vec<Vec<String>> {
    cycles_from_adjacency(&ModuleAdjacency::from_module_edges(
        modules,
        edges.iter().cloned(),
    ))
}

/// A file-level dependency edge between two named groups (modules at the
/// standard granularity, or directory components in `diagnose`), carrying the
/// evidence a witness edge needs. This is the granularity-neutral input to
/// [`witness_walk`], so every cycle-reporting surface picks witnesses with the
/// same algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFileEdge {
    pub from_group: String,
    pub to_group: String,
    pub from_file: String,
    pub to_file: Option<String>,
    pub specifier: String,
    pub line: usize,
}

/// Walks one cycle of group names and picks a representative file-level edge
/// per hop. The witness is threaded through the file the previous hop arrived
/// at, so the edges read as one connected file-level walk around the loop —
/// and we never cite a parallel-but-unrelated file (e.g. a dead module that
/// imports the target but isn't on the live path). `edges` must be sorted
/// deterministically per group pair before calling (see [`group_candidates`]).
pub fn witness_walk(cycle: &[String], candidates: &GroupCandidates<'_>) -> Vec<WitnessEdge> {
    let len = cycle.len();
    let mut edges: Vec<WitnessEdge> = Vec::with_capacity(len);
    let mut arrived_at: Option<String> = None;
    for i in 0..len {
        let from = &cycle[i];
        let to = &cycle[(i + 1) % len];
        let Some(choices) = candidates.get(&(from.as_str(), to.as_str())) else {
            arrived_at = None;
            continue;
        };
        let chosen = arrived_at
            .as_deref()
            .and_then(|file| choices.iter().find(|edge| edge.from_file == file))
            .copied()
            .unwrap_or(choices[0]);
        arrived_at = chosen.to_file.clone();
        edges.push(WitnessEdge {
            from_module: from.clone(),
            to_module: to.clone(),
            from_file: chosen.from_file.clone(),
            to_file: chosen.to_file.clone(),
            specifier: chosen.specifier.clone(),
            line: chosen.line,
        });
    }
    edges
}

/// Candidate file edges per `(from_group, to_group)` pair, sorted for
/// deterministic witness selection.
pub type GroupCandidates<'a> = HashMap<(&'a str, &'a str), Vec<&'a GroupFileEdge>>;

/// Groups `edges` by `(from_group, to_group)`, each list sorted by
/// (from_file, line, specifier) so the first element is the canonical
/// representative and [`witness_walk`] is stable across runs. Self-edges are
/// dropped.
pub fn group_candidates(edges: &[GroupFileEdge]) -> GroupCandidates<'_> {
    let mut map: GroupCandidates<'_> = HashMap::new();
    for edge in edges {
        if edge.from_group == edge.to_group {
            continue;
        }
        map.entry((edge.from_group.as_str(), edge.to_group.as_str()))
            .or_default()
            .push(edge);
    }
    for choices in map.values_mut() {
        choices.sort_by(|a, b| {
            a.from_file
                .cmp(&b.from_file)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.specifier.cmp(&b.specifier))
        });
    }
    map
}

/// Enumerates the elementary cycles and attaches the file-level import edges
/// that witness each one (see [`CycleWitness`]). The witness is drawn from
/// `dependencies`, so callers pass the *current/head* graph to get concrete
/// `file:line` evidence; cycle membership itself is identical to
/// [`elementary_cycles`].
pub fn elementary_cycles_with_witness(
    modules: &[String],
    dependencies: &[DependencyRecord],
) -> Vec<CycleWitness> {
    let group_edges: Vec<GroupFileEdge> = dependencies
        .iter()
        .filter(|dependency| {
            !dependency.is_external
                && is_runtime_edge(dependency)
                && dependency.source_module != dependency.target_module
        })
        .map(|dependency| GroupFileEdge {
            from_group: dependency.source_module.clone(),
            to_group: dependency.target_module.clone(),
            from_file: dependency.source_file_path.clone(),
            to_file: dependency.target_file_path.clone(),
            specifier: dependency.specifier.clone(),
            line: dependency.evidence_line,
        })
        .collect();
    let candidates = group_candidates(&group_edges);
    elementary_cycles(modules, dependencies)
        .into_iter()
        .map(|cycle| {
            let edges = witness_walk(&cycle, &candidates);
            CycleWitness {
                modules: cycle,
                edges,
            }
        })
        .collect()
}

/// Shared SCC + elementary-cycle enumeration over a prebuilt adjacency.
fn cycles_from_adjacency(adjacency: &ModuleAdjacency) -> Vec<Vec<String>> {
    let sccs = strongly_connected(adjacency);

    let mut seen: HashSet<Vec<usize>> = HashSet::new();
    let mut cycles: Vec<Vec<usize>> = Vec::new();
    for scc in &sccs {
        if scc.len() == 2 {
            // A 2-node SCC has exactly one elementary cycle: a <-> b.
            let mut cycle = vec![scc[0], scc[1]];
            if adjacency.names[cycle[1]] < adjacency.names[cycle[0]] {
                cycle.swap(0, 1);
            }
            if seen.insert(cycle.clone()) {
                cycles.push(cycle);
            }
            continue;
        }
        for cycle in enumerate_scc_cycles(scc, adjacency) {
            if seen.insert(cycle.clone()) {
                cycles.push(cycle);
            }
        }
    }

    cycles.sort_by(|a, b| {
        a.len()
            .cmp(&b.len())
            .then_with(|| adjacency.names[a[0]].cmp(&adjacency.names[b[0]]))
    });
    cycles
        .into_iter()
        .map(|cycle| {
            cycle
                .into_iter()
                .map(|node| adjacency.names[node].clone())
                .collect()
        })
        .collect()
}

pub fn intra_module_cycle_count(dependencies: &[DependencyRecord]) -> usize {
    let mut directories = BTreeSet::<String>::new();
    let mut edges = BTreeSet::<(String, String)>::new();
    for dependency in dependencies {
        if dependency.is_external
            || !is_runtime_edge(dependency)
            || dependency.source_module != dependency.target_module
        {
            continue;
        }
        let Some(target_file) = dependency.target_file_path.as_deref() else {
            continue;
        };
        let source = parent_directory(&dependency.source_file_path);
        let target = parent_directory(target_file);
        if source == target || nests(source, target) || nests(target, source) {
            continue;
        }
        directories.insert(source.to_string());
        directories.insert(target.to_string());
        edges.insert((source.to_string(), target.to_string()));
    }
    let names: Vec<String> = directories.into_iter().collect();
    strongly_connected(&ModuleAdjacency::from_module_edges(&names, edges)).len()
}

fn parent_directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

fn nests(outer: &str, inner: &str) -> bool {
    if outer.is_empty() {
        return !inner.is_empty();
    }
    inner.len() > outer.len() && inner.starts_with(outer) && inner.as_bytes()[outer.len()] == b'/'
}

/// Iterative Tarjan SCC. Returns components of size >= 2 (the cyclic ones).
fn strongly_connected(adjacency: &ModuleAdjacency) -> Vec<Vec<usize>> {
    let mut tarjan = Tarjan::new(adjacency);
    for start in 0..adjacency.names.len() {
        if tarjan.index[start] == u32::MAX {
            tarjan.visit(start);
        }
    }
    tarjan.sccs
}

/// The mutable state of one iterative Tarjan run. Kept as a struct so the DFS
/// step splits into small methods rather than one deeply nested loop body.
struct Tarjan<'a> {
    adjacency: &'a ModuleAdjacency,
    index: Vec<u32>,
    lowlink: Vec<u32>,
    on_stack: Vec<bool>,
    stack: Vec<usize>,
    counter: u32,
    sccs: Vec<Vec<usize>>,
}

impl<'a> Tarjan<'a> {
    fn new(adjacency: &'a ModuleAdjacency) -> Self {
        let n = adjacency.names.len();
        Self {
            adjacency,
            index: vec![u32::MAX; n],
            lowlink: vec![0; n],
            on_stack: vec![false; n],
            stack: Vec::new(),
            counter: 0,
            sccs: Vec::new(),
        }
    }

    /// Assigns a node its discovery index and pushes it onto the Tarjan stack.
    fn discover(&mut self, node: usize) {
        self.index[node] = self.counter;
        self.lowlink[node] = self.counter;
        self.counter += 1;
        self.on_stack[node] = true;
        self.stack.push(node);
    }

    /// Pops the current SCC once `node` is confirmed as its root, recording it
    /// when it is a genuine cycle (size >= 2).
    fn close_scc(&mut self, node: usize) {
        let mut scc = Vec::new();
        loop {
            let popped = self.stack.pop().expect("SCC stack non-empty");
            self.on_stack[popped] = false;
            scc.push(popped);
            if popped == node {
                break;
            }
        }
        if scc.len() >= 2 {
            self.sccs.push(scc);
        }
    }

    fn visit(&mut self, start: usize) {
        self.discover(start);
        // DFS frames: (node, next successor position).
        let mut dfs: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&(node, pos)) = dfs.last() {
            if pos < self.adjacency.succ[node].len() {
                dfs.last_mut().expect("frame present").1 += 1;
                let next = self.adjacency.succ[node][pos];
                if self.index[next] == u32::MAX {
                    self.discover(next);
                    dfs.push((next, 0));
                } else if self.on_stack[next] {
                    self.lowlink[node] = self.lowlink[node].min(self.index[next]);
                }
            } else {
                let node_lowlink = self.lowlink[node];
                dfs.pop();
                if let Some(&(parent, _)) = dfs.last() {
                    self.lowlink[parent] = self.lowlink[parent].min(node_lowlink);
                }
                if self.lowlink[node] == self.index[node] {
                    self.close_scc(node);
                }
            }
        }
    }
}

/// Rotates a cycle so its lexicographically-smallest member is first — a
/// canonical form so rotations of the same loop deduplicate.
fn canonical(cycle: &[usize], names: &[String]) -> Vec<usize> {
    if cycle.is_empty() {
        return Vec::new();
    }
    let min_pos = cycle
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| names[**a].cmp(&names[**b]))
        .map_or(0, |(i, _)| i);
    let mut out = cycle[min_pos..].to_vec();
    out.extend_from_slice(&cycle[..min_pos]);
    out
}

/// Enumerates elementary cycles within one SCC by iterative deepening: all
/// 2-node cycles first, then 3-node, etc., so the shortest surface first.
fn enumerate_scc_cycles(scc: &[usize], adjacency: &ModuleAdjacency) -> Vec<Vec<usize>> {
    let scc_set: HashSet<usize> = scc.iter().copied().collect();
    let mut cycles: Vec<Vec<usize>> = Vec::new();
    let mut seen: HashSet<Vec<usize>> = HashSet::new();

    let mut sorted: Vec<usize> = scc.to_vec();
    sorted.sort_by(|a, b| adjacency.names[*a].cmp(&adjacency.names[*b]));

    let max_depth = scc.len().min(MAX_CYCLE_DEPTH);
    for depth_limit in 2..=max_depth {
        if cycles.len() >= MAX_CYCLES_PER_SCC {
            break;
        }
        for &start in &sorted {
            if cycles.len() >= MAX_CYCLES_PER_SCC {
                break;
            }
            dfs_cycles(
                start,
                depth_limit,
                &scc_set,
                adjacency,
                &mut seen,
                &mut cycles,
            );
        }
    }
    cycles
}

/// Bounded DFS from `start` collecting elementary cycles of exactly
/// `depth_limit` nodes (deduplicated via `seen`). Stops once `cycles` reaches
/// [`MAX_CYCLES_PER_SCC`].
fn dfs_cycles(
    start: usize,
    depth_limit: usize,
    scc_set: &HashSet<usize>,
    adjacency: &ModuleAdjacency,
    seen: &mut HashSet<Vec<usize>>,
    cycles: &mut Vec<Vec<usize>>,
) {
    let mut path: Vec<usize> = vec![start];
    let mut path_set: HashSet<usize> = HashSet::from([start]);
    // Per-path-level next successor position; kept in lockstep with `path`.
    let mut frames: Vec<usize> = vec![0];

    while let Some(&pos) = frames.last() {
        if cycles.len() >= MAX_CYCLES_PER_SCC {
            return;
        }
        let node = *path.last().expect("path tracks frames");
        if pos >= adjacency.succ[node].len() {
            frames.pop();
            if path.len() > 1 {
                let removed = path.pop().expect("path non-empty");
                path_set.remove(&removed);
            }
            continue;
        }
        *frames.last_mut().expect("frame present") += 1;
        let next = adjacency.succ[node][pos];

        if !scc_set.contains(&next) {
            continue;
        }
        if next == start && path.len() >= 2 && path.len() == depth_limit {
            let canon = canonical(&path, &adjacency.names);
            if seen.insert(canon.clone()) {
                cycles.push(canon);
            }
            continue;
        }
        if path_set.contains(&next) || path.len() >= depth_limit {
            continue;
        }
        path.push(next);
        path_set.insert(next);
        frames.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(source: &str, target: &str) -> DependencyRecord {
        DependencyRecord {
            id: format!("{source}->{target}"),
            repository_id: "r".to_string(),
            source_file_id: "f".to_string(),
            target_file_id: None,
            source_file_path: format!("src/{source}/x.ts"),
            target_file_path: None,
            source_module_id: format!("m:{source}"),
            target_module_id: format!("m:{target}"),
            source_module: source.to_string(),
            target_module: target.to_string(),
            specifier: format!("../{target}/x"),
            dependency_kind: "static_import".to_string(),
            is_external: false,
            evidence_line: 1,
        }
    }

    fn modules(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn intra(module: &str, from: &str, to: &str) -> DependencyRecord {
        let mut dependency = dep(module, module);
        dependency.source_file_path = format!("src/{module}/{from}");
        dependency.target_file_path = Some(format!("src/{module}/{to}"));
        dependency
    }

    #[test]
    fn no_cycle_in_a_dag() {
        let mods = modules(&["a", "b", "c"]);
        let deps = vec![dep("a", "b"), dep("b", "c")];
        assert!(elementary_cycles(&mods, &deps).is_empty());
    }

    #[test]
    fn a_cycle_between_sibling_directories_of_one_module_is_counted() {
        let deps = vec![
            intra("feature", "alpha/index.ts", "beta/scoring.ts"),
            intra("feature", "beta/scoring.ts", "alpha/types.ts"),
        ];
        assert_eq!(intra_module_cycle_count(&deps), 1);
        assert!(elementary_cycles(&modules(&["feature"]), &deps).is_empty());
    }

    #[test]
    fn intra_module_counting_ignores_parent_child_loops_and_type_imports() {
        let barrel = vec![
            intra("feature", "index.ts", "alpha/api.ts"),
            intra("feature", "alpha/api.ts", "index.ts"),
        ];
        assert_eq!(intra_module_cycle_count(&barrel), 0);

        let acyclic = vec![intra("feature", "alpha/x.ts", "beta/y.ts")];
        assert_eq!(intra_module_cycle_count(&acyclic), 0);

        let mut type_back = intra("feature", "beta/y.ts", "alpha/x.ts");
        type_back.dependency_kind = "type_import".to_string();
        let type_only = vec![intra("feature", "alpha/x.ts", "beta/y.ts"), type_back];
        assert_eq!(intra_module_cycle_count(&type_only), 0);

        let cross = vec![dep("a", "b"), dep("b", "a")];
        assert_eq!(intra_module_cycle_count(&cross), 0);
    }

    #[test]
    fn two_node_cycle_reports_the_path() {
        let mods = modules(&["tasks", "services"]);
        let deps = vec![dep("services", "tasks"), dep("tasks", "services")];
        let cycles = elementary_cycles(&mods, &deps);
        assert_eq!(cycles.len(), 1);
        // Canonicalized to the lexicographically-smallest first member.
        assert_eq!(cycles[0], vec!["services".to_string(), "tasks".to_string()]);
    }

    #[test]
    fn three_node_cycle() {
        let mods = modules(&["a", "b", "c"]);
        let deps = vec![dep("a", "b"), dep("b", "c"), dep("c", "a")];
        let cycles = elementary_cycles(&mods, &deps);
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
        assert_eq!(cycles[0][0], "a", "canonical rotation starts at the min");
    }

    #[test]
    fn self_import_is_not_a_cycle() {
        let mods = modules(&["a"]);
        let deps = vec![dep("a", "a")];
        assert!(elementary_cycles(&mods, &deps).is_empty());
    }

    #[test]
    fn external_edges_never_form_a_cycle() {
        let mods = modules(&["a", "b"]);
        let mut external = dep("a", "b");
        external.is_external = true;
        let deps = vec![external, dep("b", "a")];
        assert!(elementary_cycles(&mods, &deps).is_empty());
    }

    #[test]
    fn overlapping_cycles_are_enumerated_individually() {
        // a<->b and b<->c share node b but are two distinct elementary cycles.
        let mods = modules(&["a", "b", "c"]);
        let deps = vec![dep("a", "b"), dep("b", "a"), dep("b", "c"), dep("c", "b")];
        let cycles = elementary_cycles(&mods, &deps);
        assert_eq!(cycles.len(), 2, "two elementary cycles, not one SCC");
        assert!(cycles.iter().all(|c| c.len() == 2));
    }

    #[test]
    fn sorted_by_length_shortest_first() {
        // a<->b (len 2) and c->d->e->c (len 3).
        let mods = modules(&["a", "b", "c", "d", "e"]);
        let deps = vec![
            dep("a", "b"),
            dep("b", "a"),
            dep("c", "d"),
            dep("d", "e"),
            dep("e", "c"),
        ];
        let cycles = elementary_cycles(&mods, &deps);
        assert_eq!(cycles.len(), 2);
        assert!(cycles[0].len() <= cycles[1].len());
    }

    #[test]
    fn deterministic_across_runs() {
        let mods = modules(&["a", "b", "c"]);
        let deps = vec![dep("a", "b"), dep("b", "c"), dep("c", "a")];
        assert_eq!(
            elementary_cycles(&mods, &deps),
            elementary_cycles(&mods, &deps)
        );
    }

    #[test]
    fn witness_attaches_file_level_edges_to_a_two_cycle() {
        // alpha/x imports ../beta/y ; beta/z imports ../alpha/w → alpha<->beta.
        let mods = modules(&["alpha", "beta"]);
        let mut a_to_b = dep("alpha", "beta");
        a_to_b.source_file_path = "src/alpha/x.ts".to_string();
        a_to_b.target_file_path = Some("src/beta/y.ts".to_string());
        a_to_b.specifier = "../beta/y".to_string();
        a_to_b.evidence_line = 12;
        let mut b_to_a = dep("beta", "alpha");
        b_to_a.source_file_path = "src/beta/z.ts".to_string();
        b_to_a.target_file_path = Some("src/alpha/w.ts".to_string());
        b_to_a.specifier = "../alpha/w".to_string();
        b_to_a.evidence_line = 8;

        let witnessed = elementary_cycles_with_witness(&mods, &[a_to_b, b_to_a]);
        assert_eq!(witnessed.len(), 1);
        let cycle = &witnessed[0];
        assert_eq!(cycle.modules, vec!["alpha".to_string(), "beta".to_string()]);
        // Both hops are witnessed with concrete file:line evidence.
        assert_eq!(cycle.edges.len(), 2);
        let ab = cycle
            .edges
            .iter()
            .find(|e| e.from_module == "alpha")
            .expect("alpha->beta edge");
        assert_eq!(ab.from_file, "src/alpha/x.ts");
        assert_eq!(ab.to_file.as_deref(), Some("src/beta/y.ts"));
        assert_eq!(ab.line, 12);
        let ba = cycle
            .edges
            .iter()
            .find(|e| e.from_module == "beta")
            .expect("beta->alpha edge");
        assert_eq!(ba.from_file, "src/beta/z.ts");
        assert_eq!(ba.line, 8);
    }

    #[test]
    fn witness_picks_a_deterministic_representative_edge() {
        // Two alpha->beta edges; the witness must pick the lexicographically
        // first (by path, then line), regardless of input order.
        let mods = modules(&["alpha", "beta"]);
        let mut early = dep("alpha", "beta");
        early.source_file_path = "src/alpha/a.ts".to_string();
        early.evidence_line = 3;
        let mut late = dep("alpha", "beta");
        late.source_file_path = "src/alpha/z.ts".to_string();
        late.evidence_line = 99;
        let back = dep("beta", "alpha");

        let one =
            elementary_cycles_with_witness(&mods, &[late.clone(), early.clone(), back.clone()]);
        let two = elementary_cycles_with_witness(&mods, &[early, late, back]);
        let edge_of = |w: &[CycleWitness]| {
            w[0].edges
                .iter()
                .find(|e| e.from_module == "alpha")
                .unwrap()
                .from_file
                .clone()
        };
        assert_eq!(edge_of(&one), "src/alpha/a.ts");
        assert_eq!(edge_of(&one), edge_of(&two), "order-independent");
    }

    #[test]
    fn module_cycles_matches_elementary_cycles_over_collapsed_edges() {
        let mods = modules(&["a", "b", "c"]);
        let deps = vec![dep("a", "b"), dep("b", "c"), dep("c", "a")];
        let from_deps = elementary_cycles(&mods, &deps);
        let edges: Vec<(String, String)> = deps
            .iter()
            .map(|d| (d.source_module.clone(), d.target_module.clone()))
            .collect();
        let from_edges = module_cycles(&mods, &edges);
        assert_eq!(from_deps, from_edges);
        assert_eq!(from_edges.len(), 1);
        assert_eq!(from_edges[0].len(), 3);
    }

    #[test]
    fn dense_component_is_capped() {
        // K5 complete digraph has far more than 20 elementary cycles.
        let names = ["a", "b", "c", "d", "e"];
        let mods = modules(&names);
        let mut deps = Vec::new();
        for s in names {
            for t in names {
                if s != t {
                    deps.push(dep(s, t));
                }
            }
        }
        let cycles = elementary_cycles(&mods, &deps);
        assert!(!cycles.is_empty());
        assert!(cycles.len() <= MAX_CYCLES_PER_SCC);
    }
}
