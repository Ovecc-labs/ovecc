use crate::model::{
    DependencyRecord, DriftTrend, Hotspot, ImpactDirection, ImpactReport, RiskLevel, SummaryReport,
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
        modules: modules.len(),
        dependencies: dependencies.len(),
        external_dependencies,
        circular_dependencies: analysis.cycle_count,
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

pub fn drift_trend(
    module_delta: isize,
    dependency_delta: isize,
    cycle_delta: isize,
    coupling_delta_percent: f64,
) -> DriftTrend {
    if module_delta == 0
        && dependency_delta == 0
        && cycle_delta == 0
        && coupling_delta_percent.abs() < 1.0
    {
        DriftTrend::Stable
    } else if cycle_delta > 0 || coupling_delta_percent > 10.0 || dependency_delta > 10 {
        DriftTrend::Worsening
    } else if cycle_delta < 0 || coupling_delta_percent < -10.0 || dependency_delta < -10 {
        DriftTrend::Improving
    } else {
        DriftTrend::Stable
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
