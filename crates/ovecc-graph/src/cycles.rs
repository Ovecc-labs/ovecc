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
use std::collections::{HashMap, HashSet};

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

impl ModuleAdjacency {
    fn build(modules: &[String], dependencies: &[DependencyRecord]) -> Self {
        let names: Vec<String> = modules.to_vec();
        let index: HashMap<&str, usize> = names
            .iter()
            .enumerate()
            .map(|(i, name)| (name.as_str(), i))
            .collect();
        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); names.len()];
        let mut seen: Vec<HashSet<usize>> = vec![HashSet::new(); names.len()];
        for dependency in dependencies {
            if dependency.is_external || dependency.source_module == dependency.target_module {
                continue;
            }
            let (Some(&source), Some(&target)) = (
                index.get(dependency.source_module.as_str()),
                index.get(dependency.target_module.as_str()),
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

/// Enumerates the elementary dependency cycles among `modules` as ordered
/// module-name paths (e.g. `["billing", "tasks"]` for `billing -> tasks ->
/// billing`). Shortest-first, canonicalized, deduplicated, and deterministic.
pub fn elementary_cycles(
    modules: &[String],
    dependencies: &[DependencyRecord],
) -> Vec<Vec<String>> {
    let adjacency = ModuleAdjacency::build(modules, dependencies);
    let sccs = strongly_connected(&adjacency);

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
        for cycle in enumerate_scc_cycles(scc, &adjacency) {
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

/// Iterative Tarjan SCC. Returns components of size >= 2 (the cyclic ones).
fn strongly_connected(adjacency: &ModuleAdjacency) -> Vec<Vec<usize>> {
    let n = adjacency.names.len();
    let mut index = vec![u32::MAX; n];
    let mut lowlink = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut counter: u32 = 0;
    let mut sccs: Vec<Vec<usize>> = Vec::new();

    for start in 0..n {
        if index[start] != u32::MAX {
            continue;
        }
        index[start] = counter;
        lowlink[start] = counter;
        counter += 1;
        on_stack[start] = true;
        stack.push(start);
        // DFS frames: (node, next successor position).
        let mut dfs: Vec<(usize, usize)> = vec![(start, 0)];

        while let Some(&(node, pos)) = dfs.last() {
            if pos < adjacency.succ[node].len() {
                dfs.last_mut().expect("frame present").1 += 1;
                let next = adjacency.succ[node][pos];
                if index[next] == u32::MAX {
                    index[next] = counter;
                    lowlink[next] = counter;
                    counter += 1;
                    on_stack[next] = true;
                    stack.push(next);
                    dfs.push((next, 0));
                } else if on_stack[next] {
                    lowlink[node] = lowlink[node].min(index[next]);
                }
            } else {
                let node_lowlink = lowlink[node];
                dfs.pop();
                if let Some(&(parent, _)) = dfs.last() {
                    lowlink[parent] = lowlink[parent].min(node_lowlink);
                }
                if lowlink[node] == index[node] {
                    let mut scc = Vec::new();
                    loop {
                        let popped = stack.pop().expect("SCC stack non-empty");
                        on_stack[popped] = false;
                        scc.push(popped);
                        if popped == node {
                            break;
                        }
                    }
                    if scc.len() >= 2 {
                        sccs.push(scc);
                    }
                }
            }
        }
    }
    sccs
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

    #[test]
    fn no_cycle_in_a_dag() {
        let mods = modules(&["a", "b", "c"]);
        let deps = vec![dep("a", "b"), dep("b", "c")];
        assert!(elementary_cycles(&mods, &deps).is_empty());
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
        let deps = vec![
            dep("a", "b"),
            dep("b", "a"),
            dep("b", "c"),
            dep("c", "b"),
        ];
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
        assert_eq!(elementary_cycles(&mods, &deps), elementary_cycles(&mods, &deps));
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
