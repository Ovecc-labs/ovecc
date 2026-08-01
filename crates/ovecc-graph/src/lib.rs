//! Module-level graph analysis.
//! the MVP. The layered graph views, centrality metrics, and multi-target
//! blast radius land in the graph roadmap step.
//!
//! Note: `drift_trend` lives in `ovecc_core::legacy` so that `ovecc-db` can
//! classify drift without depending on this crate.

pub mod blast;
pub mod cochange;
pub mod conventions;
pub mod cycles;
pub mod diagnose;
pub mod dupes;

use ovecc_core::legacy::{
    DependencyRecord, FixHistory, Hotspot, HotspotEntry, ImpactDirection, ImpactReport, RiskLevel,
    SummaryReport,
};
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeSet, HashMap, VecDeque};

pub fn summarize(
    repository_root: String,
    snapshot_id: Option<String>,
    files: usize,
    modules: Vec<String>,
    dependencies: &[DependencyRecord],
    boundary_violations: usize,
    parse_failures: usize,
) -> SummaryReport {
    let analysis = analyze_modules(&modules, dependencies);
    let external_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.is_external)
        .count();
    let risk_score = summary_risk(
        analysis.cycle_count,
        analysis.coupling_density,
        analysis.hotspots.first(),
    );

    SummaryReport {
        repository_root,
        snapshot_id,
        files,
        parse_failures,
        modules: modules.len(),
        dependencies: dependencies.len(),
        external_dependencies,
        circular_dependencies: analysis.cycle_count,
        boundary_violations,
        coupling_density: analysis.coupling_density,
        hotspots: analysis.hotspots,
        risk_score,
    }
}

pub fn impact(
    target: &str,
    direction: ImpactDirection,
    max_depth: usize,
    modules: &[String],
    dependencies: &[DependencyRecord],
) -> ImpactReport {
    let matched_module = modules
        .iter()
        .find(|module| module.eq_ignore_ascii_case(target))
        .or_else(|| {
            modules.iter().find(|module| {
                module
                    .to_ascii_lowercase()
                    .contains(&target.to_ascii_lowercase())
            })
        })
        .cloned();

    let Some(start) = matched_module.clone() else {
        return ImpactReport {
            target: target.to_string(),
            matched_module: None,
            direction,
            affected_modules: Vec::new(),
            dependency_paths: Vec::new(),
            risk_score: RiskLevel::Low,
        };
    };

    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([(start.clone(), vec![start.clone()], 0_usize)]);
    let mut paths = Vec::new();

    while let Some((current, path, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        for neighbor in neighbors(&current, direction, dependencies) {
            if neighbor == start || !visited.insert(neighbor.clone()) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(neighbor.clone());
            paths.push(next_path.clone());
            queue.push_back((neighbor, next_path, depth + 1));
        }
    }

    let affected_modules = visited.into_iter().collect::<Vec<_>>();
    let risk_score = impact_risk(affected_modules.len(), paths.len());

    ImpactReport {
        target: target.to_string(),
        matched_module,
        direction,
        affected_modules,
        dependency_paths: paths.into_iter().take(20).collect(),
        risk_score,
    }
}

pub fn local_dependency_edges(dependencies: &[DependencyRecord]) -> BTreeSet<(String, String)> {
    dependencies
        .iter()
        .filter(|dependency| !dependency.is_external)
        .filter(|dependency| dependency.source_module != dependency.target_module)
        .map(|dependency| {
            (
                dependency.source_module.clone(),
                dependency.target_module.clone(),
            )
        })
        .collect()
}

pub fn cycle_count(modules: &[String], dependencies: &[DependencyRecord]) -> usize {
    analyze_modules(modules, dependencies).cycle_count
}

/// Module instability `I = fan_out / (fan_in + fan_out)`. A module with
/// no coupling is treated as maximally stable (`0.0`).
pub fn instability(fan_in: usize, fan_out: usize) -> f64 {
    let total = fan_in + fan_out;
    if total == 0 {
        0.0
    } else {
        fan_out as f64 / total as f64
    }
}

/// Computes technical-debt hotspots: a weighted blend of churn,
/// coupling, fan-in/out, ownership fragmentation, and violations. Each
/// component is normalized to `[0,1]` against the repository maximum, so the
/// score is relative and explainable; the result is sorted by score, highest
/// first, and truncated to `limit`.
///
/// `fixes` rides along untouched: it is reported next to the score, not scored.
#[allow(clippy::too_many_arguments)]
pub fn compute_hotspots(
    modules: &[String],
    dependencies: &[DependencyRecord],
    churn: &HashMap<String, f64>,
    fragmentation: &HashMap<String, f64>,
    violations: &HashMap<String, usize>,
    complexity: &HashMap<String, f64>,
    fixes: &HashMap<String, FixHistory>,
    limit: usize,
) -> Vec<HotspotEntry> {
    let mut fan_in = HashMap::<String, usize>::new();
    let mut fan_out = HashMap::<String, usize>::new();
    let mut edges = BTreeSet::<(String, String)>::new();
    for dependency in dependencies {
        if dependency.is_external || dependency.source_module == dependency.target_module {
            continue;
        }
        if !edges.insert((
            dependency.source_module.clone(),
            dependency.target_module.clone(),
        )) {
            continue;
        }
        *fan_out.entry(dependency.source_module.clone()).or_default() += 1;
        *fan_in.entry(dependency.target_module.clone()).or_default() += 1;
    }

    // Repository maxima for normalization (avoid division by zero).
    let max = |values: &dyn Fn(&str) -> f64| -> f64 {
        modules
            .iter()
            .map(|module| values(module))
            .fold(0.0_f64, f64::max)
            .max(1.0)
    };
    let churn_of = |m: &str| *churn.get(m).unwrap_or(&0.0);
    let fan_in_of = |m: &str| *fan_in.get(m).unwrap_or(&0) as f64;
    let fan_out_of = |m: &str| *fan_out.get(m).unwrap_or(&0) as f64;
    let coupling_of = |m: &str| fan_in_of(m) + fan_out_of(m);
    let violations_of = |m: &str| *violations.get(m).unwrap_or(&0) as f64;
    let complexity_of = |m: &str| *complexity.get(m).unwrap_or(&0.0);

    let max_churn = max(&churn_of);
    let max_fan_in = max(&fan_in_of);
    let max_fan_out = max(&fan_out_of);
    let max_coupling = max(&coupling_of);
    let max_violations = max(&violations_of);
    let max_complexity = max(&complexity_of);

    let mut hotspots: Vec<HotspotEntry> = modules
        .iter()
        .map(|module| {
            let frag = *fragmentation.get(module).unwrap_or(&0.0);
            // Weighted, normalized debt score. Per-function complexity (oxc) now
            // feeds it alongside churn and coupling: a module thick with complex
            // functions is a refactoring target even when it changes rarely.
            let score = (churn_of(module) / max_churn * 0.25
                + coupling_of(module) / max_coupling * 0.20
                + complexity_of(module) / max_complexity * 0.20
                + fan_in_of(module) / max_fan_in * 0.12
                + fan_out_of(module) / max_fan_out * 0.13
                + frag * 0.07
                + violations_of(module) / max_violations * 0.03)
                * 100.0;
            HotspotEntry {
                module: module.clone(),
                score,
                churn: churn_of(module),
                fan_in: *fan_in.get(module).unwrap_or(&0),
                fan_out: *fan_out.get(module).unwrap_or(&0),
                coupling: coupling_of(module) as usize,
                ownership_fragmentation: frag,
                violations: *violations.get(module).unwrap_or(&0),
                complexity: complexity_of(module),
                fix_history: fixes.get(module).cloned().unwrap_or_default(),
            }
        })
        .filter(|hotspot| hotspot.score > 0.0)
        .collect();
    hotspots.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.module.cmp(&b.module))
    });
    hotspots.truncate(limit);
    hotspots
}

/// Members of each strongly-connected component of size > 1 — the modules
/// caught in a dependency cycle. Each component's members are sorted,
/// and the components themselves are sorted, for deterministic findings.
pub fn strongly_connected_modules(
    modules: &[String],
    dependencies: &[DependencyRecord],
) -> Vec<Vec<String>> {
    let mut graph = DiGraph::<String, ()>::new();
    let mut node_by_module = HashMap::<String, NodeIndex>::new();
    for module in modules {
        let index = graph.add_node(module.clone());
        node_by_module.insert(module.clone(), index);
    }
    let mut seen = BTreeSet::<(String, String)>::new();
    for dependency in dependencies {
        if dependency.is_external || dependency.source_module == dependency.target_module {
            continue;
        }
        if !seen.insert((
            dependency.source_module.clone(),
            dependency.target_module.clone(),
        )) {
            continue;
        }
        if let (Some(source), Some(target)) = (
            node_by_module.get(&dependency.source_module),
            node_by_module.get(&dependency.target_module),
        ) {
            graph.add_edge(*source, *target, ());
        }
    }

    let mut components: Vec<Vec<String>> = kosaraju_scc(&graph)
        .into_iter()
        .filter(|component| component.len() > 1)
        .map(|component| {
            let mut members: Vec<String> = component
                .into_iter()
                .map(|index| graph[index].clone())
                .collect();
            members.sort();
            members
        })
        .collect();
    components.sort();
    components
}

struct ModuleAnalysis {
    cycle_count: usize,
    coupling_density: f64,
    hotspots: Vec<Hotspot>,
}

fn analyze_modules(modules: &[String], dependencies: &[DependencyRecord]) -> ModuleAnalysis {
    let mut graph = DiGraph::<String, ()>::new();
    let mut node_by_module = HashMap::<String, NodeIndex>::new();

    for module in modules {
        let index = graph.add_node(module.clone());
        node_by_module.insert(module.clone(), index);
    }

    let mut fan_in = HashMap::<String, usize>::new();
    let mut fan_out = HashMap::<String, usize>::new();
    let mut local_edges = BTreeSet::<(String, String)>::new();

    for dependency in dependencies {
        if dependency.is_external || dependency.source_module == dependency.target_module {
            continue;
        }
        if !local_edges.insert((
            dependency.source_module.clone(),
            dependency.target_module.clone(),
        )) {
            continue;
        }
        *fan_out.entry(dependency.source_module.clone()).or_default() += 1;
        *fan_in.entry(dependency.target_module.clone()).or_default() += 1;

        if let (Some(source), Some(target)) = (
            node_by_module.get(&dependency.source_module),
            node_by_module.get(&dependency.target_module),
        ) {
            graph.add_edge(*source, *target, ());
        }
    }

    let cycle_count = kosaraju_scc(&graph)
        .into_iter()
        .filter(|component| component.len() > 1)
        .count();
    let possible_edges = modules
        .len()
        .saturating_mul(modules.len().saturating_sub(1));
    let coupling_density = if possible_edges == 0 {
        0.0
    } else {
        local_edges.len() as f64 / possible_edges as f64
    };

    let mut hotspots = modules
        .iter()
        .map(|module| {
            let fan_in = *fan_in.get(module).unwrap_or(&0);
            let fan_out = *fan_out.get(module).unwrap_or(&0);
            Hotspot {
                module: module.clone(),
                score: fan_in * 2 + fan_out * 3,
                fan_in,
                fan_out,
                instability: instability(fan_in, fan_out),
            }
        })
        .filter(|hotspot| hotspot.score > 0)
        .collect::<Vec<_>>();
    hotspots.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.module.cmp(&right.module))
    });
    hotspots.truncate(10);

    ModuleAnalysis {
        cycle_count,
        coupling_density,
        hotspots,
    }
}

fn neighbors(
    current: &str,
    direction: ImpactDirection,
    dependencies: &[DependencyRecord],
) -> Vec<String> {
    let mut neighbors = BTreeSet::new();

    for dependency in dependencies {
        if dependency.is_external || dependency.source_module == dependency.target_module {
            continue;
        }
        if matches!(
            direction,
            ImpactDirection::Downstream | ImpactDirection::Both
        ) && dependency.target_module == current
        {
            neighbors.insert(dependency.source_module.clone());
        }
        if matches!(direction, ImpactDirection::Upstream | ImpactDirection::Both)
            && dependency.source_module == current
        {
            neighbors.insert(dependency.target_module.clone());
        }
    }

    neighbors.into_iter().collect()
}

fn summary_risk(
    cycle_count: usize,
    coupling_density: f64,
    top_hotspot: Option<&Hotspot>,
) -> RiskLevel {
    let hotspot_score = top_hotspot.map(|hotspot| hotspot.score).unwrap_or_default();
    match (cycle_count, coupling_density, hotspot_score) {
        (cycles, _, _) if cycles >= 3 => RiskLevel::Critical,
        (cycles, _, _) if cycles > 0 => RiskLevel::High,
        (_, density, _) if density >= 0.35 => RiskLevel::High,
        (_, density, score) if density >= 0.15 || score >= 10 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

fn impact_risk(affected_modules: usize, paths: usize) -> RiskLevel {
    match (affected_modules, paths) {
        (modules, _) if modules >= 20 => RiskLevel::Critical,
        (modules, _) if modules >= 10 => RiskLevel::High,
        (modules, path_count) if modules >= 4 || path_count >= 6 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

#[cfg(test)]
mod hotspot_tests {
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

    #[test]
    fn ranks_hotspots_by_weighted_score() {
        let modules = vec![
            "billing".to_string(),
            "user".to_string(),
            "util".to_string(),
        ];
        // billing depends on user and util (fan-out 2); user is depended on.
        let deps = vec![dep("billing", "user"), dep("billing", "util")];
        let churn = HashMap::from([("billing".to_string(), 50.0), ("user".to_string(), 5.0)]);
        let fragmentation = HashMap::from([("billing".to_string(), 0.8)]);
        let violations = HashMap::from([("billing".to_string(), 3usize)]);
        let complexity =
            HashMap::from([("billing".to_string(), 120.0), ("util".to_string(), 30.0)]);
        let fixes = HashMap::from([(
            "user".to_string(),
            FixHistory {
                fixes: 4,
                mass: 3.5,
                last_fix_at: Some("2026-07-30T12:00:00+00:00".to_string()),
            },
        )]);

        let hotspots = compute_hotspots(
            &modules,
            &deps,
            &churn,
            &fragmentation,
            &violations,
            &complexity,
            &fixes,
            10,
        );

        // billing dominates churn, fan-out, fragmentation, violations and
        // complexity, so it ranks first with the highest score.
        assert_eq!(hotspots[0].module, "billing");
        assert_eq!(hotspots[0].fan_out, 2);
        assert!((hotspots[0].ownership_fragmentation - 0.8).abs() < 1e-9);
        assert_eq!(hotspots[0].violations, 3);
        assert!((hotspots[0].complexity - 120.0).abs() < 1e-9);
        let billing_score = hotspots[0].score;
        assert!(hotspots[1..].iter().all(|h| h.score < billing_score));
        // Corrections are carried, not scored: user has them all and still ranks
        // below billing.
        let user = hotspots.iter().find(|h| h.module == "user").unwrap();
        assert_eq!(user.fix_history.fixes, 4);
        assert_eq!(hotspots[0].fix_history, FixHistory::default());
        // The limit is respected.
        assert_eq!(
            compute_hotspots(
                &modules,
                &deps,
                &churn,
                &fragmentation,
                &violations,
                &complexity,
                &fixes,
                1
            )
            .len(),
            1
        );
    }
}

#[cfg(test)]
mod analysis_tests {
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

    #[test]
    fn instability_follows_the_formula() {
        // No coupling => treated as maximally stable.
        assert_eq!(instability(0, 0), 0.0);
        // Only depended upon => stable (0.0); only depends on others => unstable (1.0).
        assert_eq!(instability(5, 0), 0.0);
        assert_eq!(instability(0, 5), 1.0);
        assert!((instability(1, 3) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn local_edges_drop_external_self_and_duplicates() {
        let mut external = dep("a", "lodash");
        external.is_external = true;
        let deps = vec![
            dep("a", "b"),
            dep("a", "b"), // duplicate, collapsed
            dep("a", "a"), // self-module, ignored
            external,      // external, ignored
        ];
        let edges = local_dependency_edges(&deps);
        assert_eq!(
            edges.into_iter().collect::<Vec<_>>(),
            vec![("a".to_string(), "b".to_string())]
        );
    }

    #[test]
    fn scc_detects_cycles_and_ignores_acyclic_graphs() {
        let modules = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        // a <-> b is a cycle; c hangs off acyclically.
        let cyclic = vec![dep("a", "b"), dep("b", "a"), dep("b", "c")];
        assert_eq!(
            strongly_connected_modules(&modules, &cyclic),
            vec![vec!["a".to_string(), "b".to_string()]]
        );

        let acyclic = vec![dep("a", "b"), dep("b", "c")];
        assert!(strongly_connected_modules(&modules, &acyclic).is_empty());
    }

    #[test]
    fn summarize_counts_cycles_and_coupling_density() {
        let modules = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        // 3 edges forming one 3-cycle: a -> b -> c -> a.
        let deps = vec![dep("a", "b"), dep("b", "c"), dep("c", "a")];
        let report = summarize("/repo".to_string(), None, 9, modules, &deps, 0, 0);

        assert_eq!(report.modules, 3);
        assert_eq!(report.dependencies, 3);
        assert_eq!(report.circular_dependencies, 1);
        // density = local_edges / (n * (n - 1)) = 3 / (3 * 2) = 0.5
        assert!((report.coupling_density - 0.5).abs() < 1e-9);
        // A cycle present => risk escalates to High (or Critical).
        assert!(matches!(
            report.risk_score,
            RiskLevel::High | RiskLevel::Critical
        ));
    }

    #[test]
    fn impact_matches_targets_and_walks_reverse_dependencies() {
        let modules = vec![
            "billing".to_string(),
            "user".to_string(),
            "report".to_string(),
        ];
        // billing depends on user; report depends on billing.
        let deps = vec![dep("billing", "user"), dep("report", "billing")];

        // Downstream of `user` = everything that (transitively) depends on it.
        let report = impact("user", ImpactDirection::Downstream, 10, &modules, &deps);
        assert_eq!(report.matched_module.as_deref(), Some("user"));
        assert!(report.affected_modules.contains(&"billing".to_string()));
        assert!(report.affected_modules.contains(&"report".to_string()));

        // Case-insensitive + substring matching still resolves the module.
        let by_substring = impact("BILL", ImpactDirection::Downstream, 10, &modules, &deps);
        assert_eq!(by_substring.matched_module.as_deref(), Some("billing"));

        // Unknown target => no match, empty impact, low risk.
        let miss = impact("nope", ImpactDirection::Both, 10, &modules, &deps);
        assert_eq!(miss.matched_module, None);
        assert!(miss.affected_modules.is_empty());
        assert!(matches!(miss.risk_score, RiskLevel::Low));
    }
}
