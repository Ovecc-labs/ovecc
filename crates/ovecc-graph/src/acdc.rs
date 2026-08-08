// SPDX-License-Identifier: MIT
//! Comprehension-driven clustering — ACDC (Tzerpos & Holt, WCRE 2000).
//!
//! Recovers a *containment tree* of subsystems from the file→file dependency
//! graph, independently of the directory layout that names ovecc's modules. Two
//! phases, as in the paper:
//!
//! 1. **Skeleton construction** applies subsystem patterns. The body-header
//!    pattern folds `x.c` and `x.h` into one unit; the support-library pattern
//!    lifts out the nodes that everything depends on, which would otherwise
//!    destroy dominance for the rest of the graph; the subgraph-dominator
//!    pattern then claims, for each node, the nodes reachable only through it.
//! 2. **Orphan adoption** assigns every file the patterns did not claim to the
//!    subsystem it is most connected to.
//!
//! The published algorithm leaves tie-breaking unspecified, and the ICSE 2015
//! comparison had to run it five times per subject and keep the best score. Every
//! choice here is totally ordered — connectivity, then cardinality, then name —
//! so one graph always yields one clustering, byte for byte.
//!
//! Type-only imports participate. Clustering measures coupling, and a type
//! dependency is coupling even though it can never form a runtime cycle.
//!
//! Reference: Tzerpos & Holt, *ACDC: An Algorithm for Comprehension-Driven
//! Clustering*, WCRE 2000. Empirical standing: Lutellier et al., *Comparing
//! Software Architecture Recovery Techniques Using Accurate Dependencies*,
//! ICSE 2015.

use crate::diagnose::FileDep;
use petgraph::algo::dominators::simple_fast;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The subsystem name for nodes lifted out by the support-library pattern.
pub const SUPPORT_LIBRARY: &str = "<support>";

/// The directory name reported for a file that sits at the repository root.
pub const ROOT_DIRECTORY: &str = "<root>";

/// Header extensions for the body-header pattern.
const HEADER_EXTENSIONS: [&str; 5] = ["h", "hh", "hpp", "hxx", "h++"];

/// Body extensions for the body-header pattern.
const BODY_EXTENSIONS: [&str; 6] = ["c", "cc", "cpp", "cxx", "c++", "m"];

/// Tuning for the two size-sensitive patterns. The defaults are the ones the
/// ACDC literature uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcdcConfig {
    /// Largest node count a subgraph-dominator subsystem may claim. Above this
    /// the dominator is rejected and its children are considered instead, which
    /// is what keeps ACDC producing many small, comprehensible clusters.
    pub max_subsystem_size: usize,
    /// In-degree above which a node counts as a support library.
    pub support_in_degree: usize,
}

impl Default for AcdcConfig {
    fn default() -> Self {
        Self {
            max_subsystem_size: 20,
            support_in_degree: 20,
        }
    }
}

/// Which subsystem pattern produced a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    /// The nodes reachable only through one dominating node.
    SubgraphDominator,
    /// Nodes with in-degree above the threshold — used by everything, owned by
    /// nothing.
    SupportLibrary,
    /// The fallback for a file with no dependency edge to any skeleton
    /// subsystem: its own directory.
    Directory,
}

/// One recovered subsystem. `files` are the files it owns directly; nested
/// subsystems are named in `children`, so the collection forms a containment
/// tree rather than a flat partition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Subsystem {
    pub name: String,
    pub pattern: Pattern,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub children: Vec<String>,
    pub files: Vec<String>,
    /// How many of `files` arrived through orphan adoption rather than through a
    /// pattern match. Adoption is the weaker signal, so it is reported, not
    /// hidden.
    pub adopted: usize,
}

/// A full clustering: every indexed file lands in exactly one subsystem.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Clustering {
    /// Every subsystem, sorted by name.
    pub subsystems: Vec<Subsystem>,
    /// The subsystems with no parent, sorted by name.
    pub roots: Vec<String>,
    /// Files claimed by a pattern during skeleton construction.
    pub skeleton_files: usize,
    /// Files placed by orphan adoption.
    pub adopted_files: usize,
}

impl Clustering {
    /// The subsystem owning `file`, if any.
    pub fn subsystem_of(&self, file: &str) -> Option<&Subsystem> {
        let path = normalize(file);
        self.subsystems
            .iter()
            .find(|subsystem| subsystem.files.contains(&path))
    }
}

/// Clusters `files` into a subsystem containment tree using the dependency
/// edges in `deps`. Files absent from `files` are ignored, so a caller may pass
/// the edge set unfiltered.
pub fn cluster(files: &[String], deps: &[FileDep], config: &AcdcConfig) -> Clustering {
    let units = Units::build(files);
    let edges = units.edges(deps);
    let support = support_library(&units, &edges, config.support_in_degree);
    let skeleton = dominator_subsystems(&units, &edges, &support, config);
    assemble(&units, &edges, support, skeleton)
}

/// The graph nodes ACDC clusters. A node is one file, except where the
/// body-header pattern folded a `.c`/`.h` pair into a single translation unit.
struct Units {
    /// Representative path per unit, in lexicographic order.
    names: Vec<String>,
    /// The files each unit covers, sorted.
    files: Vec<Vec<String>>,
    /// File path → unit id.
    owner: HashMap<String, usize>,
}

impl Units {
    fn build(files: &[String]) -> Self {
        let mut groups = BTreeMap::<(bool, String), BTreeSet<String>>::new();
        for file in files {
            let path = normalize(file);
            let key = match translation_unit(&path) {
                Some(stem) => (true, stem.to_string()),
                None => (false, path.clone()),
            };
            groups.entry(key).or_default().insert(path);
        }

        let mut members: Vec<Vec<String>> = groups
            .into_values()
            .map(|group| group.into_iter().collect())
            .collect();
        members.sort();

        let names = members
            .iter()
            .map(|group| group[0].clone())
            .collect::<Vec<_>>();
        let owner = members
            .iter()
            .enumerate()
            .flat_map(|(id, group)| group.iter().map(move |file| (file.clone(), id)))
            .collect();

        Self {
            names,
            files: members,
            owner,
        }
    }

    fn len(&self) -> usize {
        self.names.len()
    }

    /// Distinct unit→unit edges, self-edges dropped, in sorted order.
    fn edges(&self, deps: &[FileDep]) -> BTreeSet<(usize, usize)> {
        deps.iter()
            .filter_map(|dep| {
                let source = *self.owner.get(&normalize(&dep.source))?;
                let target = *self.owner.get(&normalize(&dep.target))?;
                (source != target).then_some((source, target))
            })
            .collect()
    }
}

/// The `dir/stem` shared by a C-family body and header file, or `None` when the
/// path is not one of the two.
fn translation_unit(path: &str) -> Option<&str> {
    let (stem, extension) = path.rsplit_once('.')?;
    let extension = extension.to_ascii_lowercase();
    let paired = HEADER_EXTENSIONS.contains(&extension.as_str())
        || BODY_EXTENSIONS.contains(&extension.as_str());
    paired.then_some(stem)
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

/// The units used by more than `threshold` other units. They are lifted out
/// before dominance is computed: a node every subsystem depends on is dominated
/// by none of them, and leaving it in collapses the skeleton.
fn support_library(
    units: &Units,
    edges: &BTreeSet<(usize, usize)>,
    threshold: usize,
) -> BTreeSet<usize> {
    let mut in_degree = vec![0_usize; units.len()];
    for (_, target) in edges {
        in_degree[*target] += 1;
    }
    in_degree
        .into_iter()
        .enumerate()
        .filter(|(_, degree)| *degree > threshold)
        .map(|(unit, _)| unit)
        .collect()
}

/// The skeleton: for each unit, the deepest dominator subsystem that claims it,
/// plus the parent link between nested subsystems.
struct Skeleton {
    /// Dominator unit → its parent dominator unit, if it has one.
    parents: BTreeMap<usize, Option<usize>>,
    /// Unit → the dominator subsystem that owns it directly.
    owner: BTreeMap<usize, usize>,
}

/// Applies the subgraph-dominator pattern over the units that the support
/// library did not claim.
fn dominator_subsystems(
    units: &Units,
    edges: &BTreeSet<(usize, usize)>,
    support: &BTreeSet<usize>,
    config: &AcdcConfig,
) -> Skeleton {
    let live: Vec<usize> = (0..units.len())
        .filter(|unit| !support.contains(unit))
        .collect();
    let tree = dominator_tree(&live, edges);
    let sizes = subtree_sizes(&tree);
    let claims = (1..tree.children.len())
        .filter(|node| (2..=config.max_subsystem_size).contains(&sizes[*node]))
        .collect::<BTreeSet<usize>>();
    let ownership = assign_owners(&tree, &claims);

    Skeleton {
        parents: claims
            .iter()
            .map(|node| {
                let parent = tree.parents[*node].filter(|p| claims.contains(p));
                (tree.units[*node], parent.map(|p| tree.units[p]))
            })
            .collect(),
        owner: ownership
            .into_iter()
            .map(|(node, owner)| (tree.units[node], tree.units[owner]))
            .collect(),
    }
}

/// A dominator tree over the live units, rooted at a virtual entry that stands
/// for "the world outside". Node `0` is that entry; node `i + 1` holds
/// `units[i]`.
struct DominatorTree {
    /// Unit id per tree node, entry included at index 0 (where it is unused).
    units: Vec<usize>,
    /// Immediate dominator per tree node.
    parents: Vec<Option<usize>>,
    /// Dominator-tree children per node, in ascending order.
    children: Vec<Vec<usize>>,
}

fn dominator_tree(live: &[usize], edges: &BTreeSet<(usize, usize)>) -> DominatorTree {
    let mut graph = DiGraph::<(), ()>::new();
    let entry = graph.add_node(());
    let nodes: Vec<NodeIndex> = live.iter().map(|_| graph.add_node(())).collect();
    let slot: HashMap<usize, usize> = live.iter().enumerate().map(|(i, u)| (*u, i)).collect();

    for (source, target) in edges {
        if let (Some(source), Some(target)) = (slot.get(source), slot.get(target)) {
            graph.add_edge(nodes[*source], nodes[*target], ());
        }
    }
    attach_entry(&mut graph, entry, &nodes);

    let dominators = simple_fast(&graph, entry);
    let parents: Vec<Option<usize>> = std::iter::once(None)
        .chain(nodes.iter().map(|node| {
            dominators
                .immediate_dominator(*node)
                .map(|parent| parent.index())
        }))
        .collect();

    let mut children = vec![Vec::new(); parents.len()];
    for (node, parent) in parents.iter().enumerate() {
        if let Some(parent) = parent {
            children[*parent].push(node);
        }
    }

    DominatorTree {
        units: std::iter::once(usize::MAX)
            .chain(live.iter().copied())
            .collect(),
        parents,
        children,
    }
}

/// Links the virtual entry to the graph's own sources first, then to anything
/// still unreachable — a cycle nothing outside it enters — in ascending order.
/// Both steps are needed: without the second, dominance is undefined for such a
/// cycle; without the first ordering, the entry would reach a dominated node
/// directly and dissolve the very dominance we are looking for.
fn attach_entry(graph: &mut DiGraph<(), ()>, entry: NodeIndex, nodes: &[NodeIndex]) {
    let sources: Vec<NodeIndex> = nodes
        .iter()
        .copied()
        .filter(|node| {
            graph
                .neighbors_directed(*node, petgraph::Direction::Incoming)
                .next()
                .is_none()
        })
        .collect();
    let mut seen = vec![false; nodes.len() + 1];
    seen[entry.index()] = true;
    for node in sources.iter().chain(nodes.iter()) {
        if seen[node.index()] {
            continue;
        }
        graph.add_edge(entry, *node, ());
        mark_reachable(graph, *node, &mut seen);
    }
}

fn mark_reachable(graph: &DiGraph<(), ()>, start: NodeIndex, seen: &mut [bool]) {
    let mut stack = vec![start];
    while let Some(current) = stack.pop() {
        if std::mem::replace(&mut seen[current.index()], true) {
            continue;
        }
        stack.extend(graph.neighbors(current));
    }
}

/// Node count of each dominator subtree, the node itself included.
fn subtree_sizes(tree: &DominatorTree) -> Vec<usize> {
    let mut sizes = vec![1_usize; tree.children.len()];
    for node in postorder(tree) {
        let total: usize = tree.children[node].iter().map(|child| sizes[*child]).sum();
        sizes[node] += total;
    }
    sizes
}

/// Dominator-tree nodes, children before parents.
fn postorder(tree: &DominatorTree) -> Vec<usize> {
    let mut order = Vec::with_capacity(tree.children.len());
    let mut stack = vec![(0_usize, false)];
    while let Some((node, expanded)) = stack.pop() {
        if expanded {
            order.push(node);
            continue;
        }
        stack.push((node, true));
        stack.extend(tree.children[node].iter().map(|child| (*child, false)));
    }
    order
}

/// Maps every tree node to the deepest claimed ancestor-or-self that owns it.
/// Nodes with no claimed ancestor are absent — they are the orphans.
fn assign_owners(tree: &DominatorTree, claims: &BTreeSet<usize>) -> BTreeMap<usize, usize> {
    let mut owners = BTreeMap::new();
    let mut stack: Vec<(usize, Option<usize>)> = vec![(0, None)];
    while let Some((node, inherited)) = stack.pop() {
        let owner = if claims.contains(&node) {
            Some(node)
        } else {
            inherited
        };
        if let Some(owner) = owner
            && node != 0
        {
            owners.insert(node, owner);
        }
        stack.extend(tree.children[node].iter().map(|child| (*child, owner)));
    }
    owners
}

/// Turns the skeleton into named subsystems and adopts every orphan into the
/// one it is most connected to.
fn assemble(
    units: &Units,
    edges: &BTreeSet<(usize, usize)>,
    support: BTreeSet<usize>,
    skeleton: Skeleton,
) -> Clustering {
    let mut members = BTreeMap::<String, Vec<usize>>::new();
    let mut pattern = BTreeMap::<String, Pattern>::new();
    let mut parent = BTreeMap::<String, Option<String>>::new();

    if !support.is_empty() {
        pattern.insert(SUPPORT_LIBRARY.to_string(), Pattern::SupportLibrary);
        parent.insert(SUPPORT_LIBRARY.to_string(), None);
        members.insert(
            SUPPORT_LIBRARY.to_string(),
            support.iter().copied().collect(),
        );
    }
    for (dominator, above) in &skeleton.parents {
        let name = units.names[*dominator].clone();
        pattern.insert(name.clone(), Pattern::SubgraphDominator);
        parent.insert(name.clone(), above.map(|unit| units.names[unit].clone()));
        members.entry(name).or_default();
    }
    for (unit, dominator) in &skeleton.owner {
        members
            .entry(units.names[*dominator].clone())
            .or_default()
            .push(*unit);
    }

    let orphans: Vec<usize> = (0..units.len())
        .filter(|unit| !support.contains(unit) && !skeleton.owner.contains_key(unit))
        .collect();
    let mut adopted = BTreeMap::<String, usize>::new();
    for orphan in orphans {
        let name = adopt(orphan, edges, &members)
            .unwrap_or_else(|| directory_of(&units.names[orphan]).to_string());
        pattern.entry(name.clone()).or_insert(Pattern::Directory);
        parent.entry(name.clone()).or_insert(None);
        members.entry(name.clone()).or_default().push(orphan);
        *adopted.entry(name).or_default() += units.files[orphan].len();
    }

    build_clustering(units, members, pattern, parent, adopted)
}

/// The existing subsystem an orphan is most connected to: most edges first,
/// then the larger subsystem, then the lexicographically smaller name. `None`
/// when the orphan touches no subsystem at all.
fn adopt(
    orphan: usize,
    edges: &BTreeSet<(usize, usize)>,
    members: &BTreeMap<String, Vec<usize>>,
) -> Option<String> {
    let mut connectivity = BTreeMap::<usize, usize>::new();
    for (source, target) in edges {
        match (*source == orphan, *target == orphan) {
            (true, false) => *connectivity.entry(*target).or_default() += 1,
            (false, true) => *connectivity.entry(*source).or_default() += 1,
            _ => {}
        }
    }
    if connectivity.is_empty() {
        return None;
    }

    members
        .iter()
        .filter_map(|(name, owned)| {
            let score: usize = owned.iter().filter_map(|unit| connectivity.get(unit)).sum();
            (score > 0).then(|| (score, owned.len(), std::cmp::Reverse(name.clone())))
        })
        .max()
        .map(|(_, _, name)| name.0)
}

/// The directory a file lives in, or [`ROOT_DIRECTORY`] for a file at the top.
fn directory_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((directory, _)) if !directory.is_empty() => directory,
        _ => ROOT_DIRECTORY,
    }
}

fn build_clustering(
    units: &Units,
    members: BTreeMap<String, Vec<usize>>,
    pattern: BTreeMap<String, Pattern>,
    parent: BTreeMap<String, Option<String>>,
    adopted: BTreeMap<String, usize>,
) -> Clustering {
    let mut children = BTreeMap::<String, Vec<String>>::new();
    for (name, above) in &parent {
        if let Some(above) = above {
            children
                .entry(above.clone())
                .or_default()
                .push(name.clone());
        }
    }

    let subsystems: Vec<Subsystem> = members
        .iter()
        .map(|(name, owned)| {
            let mut files: Vec<String> = owned
                .iter()
                .flat_map(|unit| units.files[*unit].iter().cloned())
                .collect();
            files.sort();
            Subsystem {
                name: name.clone(),
                pattern: pattern.get(name).copied().unwrap_or(Pattern::Directory),
                parent: parent.get(name).cloned().flatten(),
                children: children.get(name).cloned().unwrap_or_default(),
                files,
                adopted: adopted.get(name).copied().unwrap_or(0),
            }
        })
        .collect();

    let roots = subsystems
        .iter()
        .filter(|subsystem| subsystem.parent.is_none())
        .map(|subsystem| subsystem.name.clone())
        .collect();
    let total: usize = subsystems.iter().map(|s| s.files.len()).sum();
    let adopted_files: usize = adopted.values().sum();

    Clustering {
        skeleton_files: total - adopted_files,
        adopted_files,
        subsystems,
        roots,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(source: &str, target: &str) -> FileDep {
        FileDep::bare(source, target)
    }

    fn files(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| path.to_string()).collect()
    }

    #[test]
    fn a_dominator_claims_only_what_is_reachable_through_it() {
        // gate is the single way in to a and b; loose hangs off nothing.
        let paths = files(&["src/gate.ts", "src/a.ts", "src/b.ts", "src/loose.ts"]);
        let deps = vec![
            edge("src/gate.ts", "src/a.ts"),
            edge("src/gate.ts", "src/b.ts"),
        ];

        let clustering = cluster(&paths, &deps, &AcdcConfig::default());

        let gate = clustering.subsystem_of("src/a.ts").expect("a is clustered");
        assert_eq!(gate.name, "src/gate.ts");
        assert_eq!(gate.pattern, Pattern::SubgraphDominator);
        assert_eq!(
            gate.files,
            files(&["src/a.ts", "src/b.ts", "src/gate.ts"]),
            "the dominator owns itself and both dominated files"
        );
        // An unconnected file cannot be adopted, so it falls back to its directory.
        let loose = clustering.subsystem_of("src/loose.ts").unwrap();
        assert_eq!(
            (loose.name.as_str(), loose.pattern),
            ("src", Pattern::Directory)
        );
    }

    #[test]
    fn a_shared_target_is_dominated_by_nobody() {
        // shared has two independent entries, so neither caller dominates it.
        let paths = files(&["src/one.ts", "src/two.ts", "src/shared.ts"]);
        let deps = vec![
            edge("src/one.ts", "src/shared.ts"),
            edge("src/two.ts", "src/shared.ts"),
        ];

        let clustering = cluster(&paths, &deps, &AcdcConfig::default());

        assert!(
            clustering
                .subsystems
                .iter()
                .all(|subsystem| subsystem.pattern != Pattern::SubgraphDominator),
            "no dominator exists: {:?}",
            clustering.subsystems
        );
        // Adoption still places it, against the larger-then-lexicographic rule.
        let shared = clustering.subsystem_of("src/shared.ts").unwrap();
        assert_eq!(shared.name, "src");
        assert_eq!(clustering.skeleton_files, 0);
        assert_eq!(clustering.adopted_files, 3);
    }

    #[test]
    fn sibling_slices_stay_apart_even_inside_one_directory() {
        // The lab/demo-crash shape: alpha and beta are sibling slices under one
        // parent directory, which the module heuristic collapses into a single
        // module. Structure, not layout, has to keep them apart.
        let paths = files(&[
            "src/feature/alpha/index.ts",
            "src/feature/alpha/types.ts",
            "src/feature/alpha/policy.ts",
            "src/feature/beta/scoring.ts",
            "src/feature/beta/rollup.ts",
        ]);
        let deps = vec![
            edge("src/feature/alpha/index.ts", "src/feature/alpha/types.ts"),
            edge("src/feature/alpha/index.ts", "src/feature/alpha/policy.ts"),
            edge("src/feature/beta/scoring.ts", "src/feature/beta/rollup.ts"),
        ];

        let clustering = cluster(&paths, &deps, &AcdcConfig::default());

        let alpha = clustering
            .subsystem_of("src/feature/alpha/types.ts")
            .unwrap();
        let beta = clustering
            .subsystem_of("src/feature/beta/rollup.ts")
            .unwrap();
        assert_ne!(
            alpha.name, beta.name,
            "two slices, two subsystems: {:?}",
            clustering.subsystems
        );
        assert_eq!(alpha.name, "src/feature/alpha/index.ts");
        assert_eq!(beta.name, "src/feature/beta/scoring.ts");
    }

    #[test]
    fn the_support_library_is_lifted_out_before_dominance() {
        // util is imported by everything, so nothing dominates it, and its
        // presence would otherwise stop gate from dominating its callers.
        let mut paths = files(&["src/gate.ts", "src/util.ts"]);
        let mut deps = vec![edge("src/gate.ts", "src/util.ts")];
        for index in 0..5 {
            let leaf = format!("src/leaf{index}.ts");
            deps.push(edge("src/gate.ts", &leaf));
            deps.push(edge(&leaf, "src/util.ts"));
            paths.push(leaf);
        }
        let config = AcdcConfig {
            support_in_degree: 3,
            ..AcdcConfig::default()
        };

        let clustering = cluster(&paths, &deps, &config);

        let support = clustering.subsystem_of("src/util.ts").unwrap();
        assert_eq!(support.pattern, Pattern::SupportLibrary);
        assert_eq!(support.name, SUPPORT_LIBRARY);
        // With util out of the way, gate dominates all five leaves.
        let leaf = clustering.subsystem_of("src/leaf0.ts").unwrap();
        assert_eq!(leaf.name, "src/gate.ts");
        assert_eq!(leaf.files.len(), 6);
    }

    #[test]
    fn a_body_and_its_header_never_split() {
        let paths = files(&["src/gate.c", "src/gate.h", "src/leaf.c", "src/leaf.h"]);
        let deps = vec![edge("src/gate.c", "src/leaf.h")];

        let clustering = cluster(&paths, &deps, &AcdcConfig::default());

        let body = clustering.subsystem_of("src/leaf.c").unwrap();
        let header = clustering.subsystem_of("src/leaf.h").unwrap();
        assert_eq!(body.name, header.name);
        assert_eq!(
            body.files,
            files(&["src/gate.c", "src/gate.h", "src/leaf.c", "src/leaf.h"])
        );
        // A .ts pair is not a translation unit and must not fold.
        assert_eq!(translation_unit("src/gate.ts"), None);
        assert_eq!(translation_unit("src/gate.h"), Some("src/gate"));
    }

    #[test]
    fn a_dominator_bigger_than_the_bound_yields_to_its_children() {
        // gate dominates six nodes; with the bound at 3 it is rejected, and the
        // two mid-level dominators it contains are accepted instead.
        let paths = files(&[
            "src/gate.ts",
            "src/left.ts",
            "src/left_a.ts",
            "src/left_b.ts",
            "src/right.ts",
            "src/right_a.ts",
        ]);
        let deps = vec![
            edge("src/gate.ts", "src/left.ts"),
            edge("src/gate.ts", "src/right.ts"),
            edge("src/left.ts", "src/left_a.ts"),
            edge("src/left.ts", "src/left_b.ts"),
            edge("src/right.ts", "src/right_a.ts"),
        ];
        let config = AcdcConfig {
            max_subsystem_size: 3,
            ..AcdcConfig::default()
        };

        let clustering = cluster(&paths, &deps, &config);

        assert_eq!(
            clustering.subsystem_of("src/left_a.ts").unwrap().name,
            "src/left.ts"
        );
        assert_eq!(
            clustering.subsystem_of("src/right_a.ts").unwrap().name,
            "src/right.ts"
        );
        // The oversized dominator is not a subsystem; it is adopted by one.
        assert!(
            !clustering
                .subsystems
                .iter()
                .any(|subsystem| subsystem.name == "src/gate.ts")
        );
    }

    #[test]
    fn a_cycle_nothing_enters_is_still_clustered() {
        // a <-> b with no external entry: unreachable from any in-degree-zero
        // node, so the virtual entry has to be attached for dominance to exist.
        let paths = files(&["src/a.ts", "src/b.ts"]);
        let deps = vec![edge("src/a.ts", "src/b.ts"), edge("src/b.ts", "src/a.ts")];

        let clustering = cluster(&paths, &deps, &AcdcConfig::default());

        assert!(clustering.subsystem_of("src/a.ts").is_some());
        assert!(clustering.subsystem_of("src/b.ts").is_some());
    }

    #[test]
    fn every_file_lands_somewhere_exactly_once() {
        let paths = files(&[
            "src/gate.ts",
            "src/a.ts",
            "src/b.ts",
            "src/loose.ts",
            "readme.md",
        ]);
        let deps = vec![
            edge("src/gate.ts", "src/a.ts"),
            edge("src/gate.ts", "src/b.ts"),
            edge("src/a.ts", "missing/elsewhere.ts"),
        ];

        let clustering = cluster(&paths, &deps, &AcdcConfig::default());

        let mut placed: Vec<String> = clustering
            .subsystems
            .iter()
            .flat_map(|subsystem| subsystem.files.iter().cloned())
            .collect();
        placed.sort();
        let mut expected = paths.clone();
        expected.sort();
        assert_eq!(placed, expected, "partition, with no file lost or doubled");
        assert_eq!(
            clustering.skeleton_files + clustering.adopted_files,
            paths.len()
        );
        // A file at the repository root has no directory to fall back to.
        assert_eq!(
            clustering.subsystem_of("readme.md").unwrap().name,
            ROOT_DIRECTORY
        );
    }

    #[test]
    fn the_same_graph_always_clusters_the_same_way() {
        let paths = files(&[
            "src/gate.ts",
            "src/a.ts",
            "src/b.ts",
            "src/c.ts",
            "src/shared.ts",
        ]);
        let forward = vec![
            edge("src/gate.ts", "src/a.ts"),
            edge("src/gate.ts", "src/b.ts"),
            edge("src/a.ts", "src/shared.ts"),
            edge("src/c.ts", "src/shared.ts"),
        ];
        let mut shuffled = forward.clone();
        shuffled.reverse();
        let mut reordered_files = paths.clone();
        reordered_files.reverse();

        let baseline = cluster(&paths, &forward, &AcdcConfig::default());
        assert_eq!(baseline, cluster(&paths, &shuffled, &AcdcConfig::default()));
        assert_eq!(
            baseline,
            cluster(&reordered_files, &shuffled, &AcdcConfig::default())
        );
    }
}
