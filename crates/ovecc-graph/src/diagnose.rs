//! Deterministic architectural diagnosis.
//!
//! Turns the graph facts into named, evidence-backed findings, each mapped to an
//! established design principle and a known remediation. Detection is
//! deterministic and threshold-driven; the remediation text is a curated, static
//! catalogue (looked up, never invented).
//!
//! Granularity. ovecc's `module` is the top-level source directory, which on a
//! large repo collapses the whole tree into one catch-all module — too coarse to
//! see real cycles or hubs. So diagnosis runs at **component** granularity,
//! derived from the file→file dependency graph: a component is a directory (by
//! default the file's parent directory; `component_depth` truncates to the first
//! N path segments). This makes the structural detectors see the real
//! architecture, and makes `god_component` language-agnostic (size = file
//! count), so it works on Rust/C++ as well as TS/JS.
//!
//! See `docs/dev/DIAGNOSE.md` for the design and the research basis of each
//! detector.

use crate::instability;
use ovecc_core::facts::Severity;
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeMap, BTreeSet, HashMap};

// The configuration type lives in core so it can be parsed from
// `.ovecc/config.toml` as part of `OveccConfig`; diagnosis consumes it here.
pub use ovecc_core::config::DiagnoseConfig;
use ovecc_core::facts::FixSpec;

/// Whether a file path is excluded from diagnosis. A token containing `.`
/// matches the filename as a substring; otherwise it matches a whole path
/// segment. All case-insensitive.
fn is_excluded(path: &str, exclude: &[String]) -> bool {
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    let segments: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    let file = segments.last().copied().unwrap_or("");
    for token in exclude {
        let t = token.to_ascii_lowercase();
        if t.contains('.') {
            if file.contains(&t) {
                return true;
            }
        } else if segments.iter().any(|s| *s == t) {
            return true;
        }
    }
    false
}

/// The component a file belongs to. `depth == 0` => the parent directory;
/// `depth > 0` => the first `depth` path segments. Paths are normalised to
/// POSIX separators. A file at the repo root maps to `"<root>"`.
pub fn component_of(path: &str, depth: usize) -> String {
    let norm = path.replace('\\', "/");
    let segments: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    if depth == 0 {
        // Parent directory.
        if segments.len() <= 1 {
            "<root>".to_string()
        } else {
            segments[..segments.len() - 1].join("/")
        }
    } else {
        let take = depth.min(segments.len().saturating_sub(1)).max(1);
        if segments.len() <= 1 {
            "<root>".to_string()
        } else {
            segments[..take.min(segments.len())].join("/")
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiagEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub metric: String,
    pub value: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl DiagEvidence {
    fn metric(metric: &str, value: f64, threshold: f64) -> Self {
        Self {
            file: None,
            line: None,
            metric: metric.to_string(),
            value,
            threshold: Some(threshold),
        }
    }
    fn bare(metric: &str, value: f64) -> Self {
        Self {
            file: None,
            line: None,
            metric: metric.to_string(),
            value,
            threshold: None,
        }
    }
}

/// The curated remediation for a detector: an established principle and
/// refactoring, with optional per-language notes and a when-not-to-act caveat.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Remediation {
    pub summary: String,
    pub refactoring: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when_not_to_act: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub language_notes: BTreeMap<String, String>,
}

/// A named architectural finding with evidence, severity, deterministic
/// confidence, the principle it violates, and how to fix it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diagnosis {
    pub detector: String,
    pub title: String,
    /// structural | stability | size | evolutionary | conformance
    pub family: String,
    pub target_kind: String,
    pub target: String,
    pub evidence: Vec<DiagEvidence>,
    pub principle: String,
    pub severity: Severity,
    pub confidence: f64,
    pub remediation: Remediation,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiagnoseReport {
    pub components: usize,
    pub findings: Vec<Diagnosis>,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl DiagnoseReport {
    /// Sorts findings into a deterministic order and tallies per-severity counts.
    pub fn new(components: usize, mut findings: Vec<Diagnosis>) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then_with(|| a.detector.cmp(&b.detector))
                .then_with(|| a.target.cmp(&b.target))
        });
        let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
        DiagnoseReport {
            components,
            total: findings.len(),
            critical: count(Severity::Critical),
            high: count(Severity::High),
            medium: count(Severity::Medium),
            low: count(Severity::Low),
            findings,
        }
    }
}

/// Per-component structural metrics. Instability is Martin's `I = Ce/(Ca+Ce)`
/// with `Ca = fan_in`, `Ce = fan_out`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentMetric {
    pub component: String,
    pub files: usize,
    pub fan_in: usize,
    pub fan_out: usize,
    pub coupling: usize,
    pub instability: f64,
    /// Martin's Abstractness `A = abstract_types / total_types` (0 if no types).
    pub abstractness: f64,
    /// Distance from the main sequence `D = |A + I − 1|` (0 = balanced, 1 = far).
    pub distance: f64,
    pub complexity: f64,
    pub churn: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsReport {
    pub components: Vec<ComponentMetric>,
    pub coupling_density: f64,
}

/// The component graph: nodes, deduplicated inter-component edges, coupling, and
/// the per-component aggregates the detectors consume.
struct ComponentGraph {
    components: BTreeSet<String>,
    edges: BTreeSet<(String, String)>,
    fan_in: HashMap<String, usize>,
    fan_out: HashMap<String, usize>,
    files: HashMap<String, usize>,
    churn: HashMap<String, f64>,
    complexity: HashMap<String, f64>,
    /// Abstract type declarations (interfaces + traits) per component.
    abstract_types: HashMap<String, f64>,
    /// All type declarations (class/struct/enum/interface/trait) per component.
    total_types: HashMap<String, f64>,
}

impl ComponentGraph {
    /// Martin's Abstractness `A = abstract_types / total_types` for a component
    /// (0 when it declares no types).
    fn abstractness(&self, c: &str) -> f64 {
        let total = *self.total_types.get(c).unwrap_or(&0.0);
        if total <= 0.0 {
            0.0
        } else {
            (*self.abstract_types.get(c).unwrap_or(&0.0) / total).clamp(0.0, 1.0)
        }
    }
}

/// Aggregates the file-level facts to components at the configured granularity.
fn build_graph(
    files: &[String],
    file_deps: &[(String, String)],
    file_churn: &HashMap<String, f64>,
    file_complexity: &HashMap<String, f64>,
    file_abstractness: &HashMap<String, (f64, f64)>,
    config: &DiagnoseConfig,
) -> ComponentGraph {
    let depth = config.component_depth;
    let excluded = |path: &str| is_excluded(path, &config.exclude);
    let mut components = BTreeSet::<String>::new();
    let mut file_count = HashMap::<String, usize>::new();
    let mut churn = HashMap::<String, f64>::new();
    let mut complexity = HashMap::<String, f64>::new();
    let mut abstract_types = HashMap::<String, f64>::new();
    let mut total_types = HashMap::<String, f64>::new();

    for path in files {
        if excluded(path) {
            continue;
        }
        let c = component_of(path, depth);
        components.insert(c.clone());
        *file_count.entry(c.clone()).or_default() += 1;
        *churn.entry(c.clone()).or_default() += file_churn.get(path).copied().unwrap_or(0.0);
        *complexity.entry(c.clone()).or_default() +=
            file_complexity.get(path).copied().unwrap_or(0.0);
        if let Some((abs, tot)) = file_abstractness.get(path) {
            *abstract_types.entry(c.clone()).or_default() += *abs;
            *total_types.entry(c.clone()).or_default() += *tot;
        }
    }

    let mut edges = BTreeSet::<(String, String)>::new();
    for (src, tgt) in file_deps {
        if excluded(src) || excluded(tgt) {
            continue;
        }
        let cs = component_of(src, depth);
        let ct = component_of(tgt, depth);
        // Ensure endpoints exist even if they had no indexed files.
        components.insert(cs.clone());
        components.insert(ct.clone());
        if cs != ct {
            edges.insert((cs, ct));
        }
    }

    let mut fan_in = HashMap::<String, usize>::new();
    let mut fan_out = HashMap::<String, usize>::new();
    for (s, t) in &edges {
        *fan_out.entry(s.clone()).or_default() += 1;
        *fan_in.entry(t.clone()).or_default() += 1;
    }

    ComponentGraph {
        components,
        edges,
        fan_in,
        fan_out,
        files: file_count,
        churn,
        complexity,
        abstract_types,
        total_types,
    }
}

/// Strongly-connected components (size > 1) of a node/edge set — the cycles.
/// Members and components are sorted for deterministic output.
fn strongly_connected(
    nodes: &BTreeSet<String>,
    edges: &BTreeSet<(String, String)>,
) -> Vec<Vec<String>> {
    let mut graph = DiGraph::<String, ()>::new();
    let mut index = HashMap::<String, NodeIndex>::new();
    for n in nodes {
        let id = graph.add_node(n.clone());
        index.insert(n.clone(), id);
    }
    for (s, t) in edges {
        if let (Some(a), Some(b)) = (index.get(s), index.get(t)) {
            graph.add_edge(*a, *b, ());
        }
    }
    let mut out: Vec<Vec<String>> = kosaraju_scc(&graph)
        .into_iter()
        .filter(|c| c.len() > 1)
        .map(|c| {
            let mut m: Vec<String> = c.into_iter().map(|i| graph[i].clone()).collect();
            m.sort();
            m
        })
        .collect();
    out.sort();
    out
}

/// The p-th percentile (0..1), nearest-rank over non-zero values. 0 if empty.
fn percentile(values: &[f64], p: f64) -> f64 {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| *x > 0.0).collect();
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = (p * (v.len() as f64 - 1.0)).round() as usize;
    v[rank.min(v.len() - 1)]
}

/// Builds the per-component metrics report.
pub fn metrics(
    files: &[String],
    file_deps: &[(String, String)],
    file_churn: &HashMap<String, f64>,
    file_complexity: &HashMap<String, f64>,
    file_abstractness: &HashMap<String, (f64, f64)>,
    config: &DiagnoseConfig,
) -> MetricsReport {
    let g = build_graph(
        files,
        file_deps,
        file_churn,
        file_complexity,
        file_abstractness,
        config,
    );
    let mut out: Vec<ComponentMetric> = g
        .components
        .iter()
        .map(|c| {
            let fi = *g.fan_in.get(c).unwrap_or(&0);
            let fo = *g.fan_out.get(c).unwrap_or(&0);
            let inst = instability(fi, fo);
            let abst = g.abstractness(c);
            ComponentMetric {
                component: c.clone(),
                files: *g.files.get(c).unwrap_or(&0),
                fan_in: fi,
                fan_out: fo,
                coupling: fi + fo,
                instability: inst,
                abstractness: abst,
                distance: (abst + inst - 1.0).abs(),
                complexity: *g.complexity.get(c).unwrap_or(&0.0),
                churn: *g.churn.get(c).unwrap_or(&0.0),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.coupling
            .cmp(&a.coupling)
            .then_with(|| a.component.cmp(&b.component))
    });

    let n = g.components.len();
    let possible = n.saturating_mul(n.saturating_sub(1));
    let coupling_density = if possible == 0 {
        0.0
    } else {
        g.edges.len() as f64 / possible as f64
    };

    MetricsReport {
        components: out,
        coupling_density,
    }
}

/// Runs every enabled Phase-1 detector and returns a ranked report.
pub fn diagnose(
    files: &[String],
    file_deps: &[(String, String)],
    file_churn: &HashMap<String, f64>,
    file_complexity: &HashMap<String, f64>,
    file_abstractness: &HashMap<String, (f64, f64)>,
    co_change: &[(String, String, f64)],
    config: &DiagnoseConfig,
) -> DiagnoseReport {
    let g = build_graph(
        files,
        file_deps,
        file_churn,
        file_complexity,
        file_abstractness,
        config,
    );
    let mut findings: Vec<Diagnosis> = Vec::new();

    detect_cyclic_dependency(&g, &mut findings);
    detect_file_cycle(files, file_deps, config, &mut findings);
    detect_hub_like(&g, config, &mut findings);
    detect_unstable_dependency(&g, config, &mut findings);
    detect_zone_of_pain(&g, config, &mut findings);
    detect_god_component(&g, config, &mut findings);
    detect_dense_structure(&g, config, &mut findings);
    detect_hotspots(&g, config, &mut findings);
    // Evolutionary detectors (need git history; silent without it).
    detect_unstable_interface(&g, config, &mut findings);
    detect_change_coupling(&g, co_change, config, &mut findings);

    findings.retain(|f| f.confidence >= config.min_confidence);
    DiagnoseReport::new(g.components.len(), findings)
}

// --- detectors -------------------------------------------------------------

fn detect_cyclic_dependency(g: &ComponentGraph, out: &mut Vec<Diagnosis>) {
    for component in strongly_connected(&g.components, &g.edges) {
        let size = component.len();
        let severity = if size >= 3 {
            Severity::High
        } else {
            Severity::Medium
        };
        // A large strongly-connected cluster is one finding (a tangle), not a
        // 100-component line: anchor it on its first member and show the size.
        let target = if size <= 5 {
            component.join(" <-> ")
        } else {
            format!("{} … (+{} more components)", component[..4].join(" <-> "), size - 4)
        };
        out.push(Diagnosis {
            detector: "cyclic_dependency".to_string(),
            title: "Cyclic Dependency".to_string(),
            family: "structural".to_string(),
            target_kind: "component-group".to_string(),
            target,
            evidence: vec![DiagEvidence::metric("cycle_size", size as f64, 1.0)],
            principle: "Acyclic Dependencies Principle".to_string(),
            severity,
            confidence: 1.0,
            remediation: remediation("cyclic_dependency"),
            references: vec!["Martin ADP".to_string(), "Arcan CD".to_string()],
        });
    }
}

/// File-level cycles the component graph hides: a strongly-connected set of
/// files that all live in the *same* component — an intra-package import cycle.
/// Inter-component cycles are already reported by `cyclic_dependency`, so we emit
/// only the intra-component ones to avoid double-counting. This closes the
/// documented file→file gap (e.g. a Python intra-package import cycle).
/// Deterministic; full confidence (a cycle is a fact, not a heuristic).
fn detect_file_cycle(
    files: &[String],
    file_deps: &[(String, String)],
    config: &DiagnoseConfig,
    out: &mut Vec<Diagnosis>,
) {
    let _ = files; // cyclic files always appear as dependency endpoints.
    let depth = config.component_depth;
    let mut nodes = BTreeSet::<String>::new();
    let mut edges = BTreeSet::<(String, String)>::new();
    for (src, tgt) in file_deps {
        if src == tgt || is_excluded(src, &config.exclude) || is_excluded(tgt, &config.exclude) {
            continue;
        }
        nodes.insert(src.clone());
        nodes.insert(tgt.clone());
        edges.insert((src.clone(), tgt.clone()));
    }
    for scc in strongly_connected(&nodes, &edges) {
        let comp = component_of(&scc[0], depth);
        if !scc.iter().all(|f| component_of(f, depth) == comp) {
            continue; // inter-component cycle: already covered by cyclic_dependency.
        }
        let size = scc.len();
        let severity = if size >= 4 {
            Severity::High
        } else {
            Severity::Medium
        };
        let target = if size <= 5 {
            scc.join(" <-> ")
        } else {
            format!("{} … (+{} more files)", scc[..4].join(" <-> "), size - 4)
        };
        out.push(Diagnosis {
            detector: "file_cycle".to_string(),
            title: "File Cycle".to_string(),
            family: "structural".to_string(),
            target_kind: "file-group".to_string(),
            target,
            evidence: vec![DiagEvidence::metric("cycle_size", size as f64, 1.0)],
            principle: "Acyclic Dependencies Principle".to_string(),
            severity,
            confidence: 1.0,
            remediation: remediation("file_cycle"),
            references: vec![
                "Martin ADP".to_string(),
                "Cai 2019 (Cliques / Package Cycles)".to_string(),
            ],
        });
    }
}

fn detect_hub_like(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    let in_vals: Vec<f64> = g
        .components
        .iter()
        .map(|c| *g.fan_in.get(c).unwrap_or(&0) as f64)
        .collect();
    let out_vals: Vec<f64> = g
        .components
        .iter()
        .map(|c| *g.fan_out.get(c).unwrap_or(&0) as f64)
        .collect();
    let in_th = percentile(&in_vals, config.hub_percentile).max(3.0);
    let out_th = percentile(&out_vals, config.hub_percentile).max(3.0);

    for c in &g.components {
        let fi = *g.fan_in.get(c).unwrap_or(&0) as f64;
        let fo = *g.fan_out.get(c).unwrap_or(&0) as f64;
        if fi >= in_th && fo >= out_th {
            let confidence = (((fi / in_th) + (fo / out_th)) / 4.0).clamp(0.5, 0.99);
            out.push(Diagnosis {
                detector: "hub_like_dependency".to_string(),
                title: "Hub-Like Dependency (Crossing)".to_string(),
                family: "structural".to_string(),
                target_kind: "component".to_string(),
                target: c.clone(),
                evidence: vec![
                    DiagEvidence::metric("fan_in", fi, in_th),
                    DiagEvidence::metric("fan_out", fo, out_th),
                ],
                principle: "Single Responsibility; Stable Dependencies".to_string(),
                severity: Severity::High,
                confidence,
                remediation: remediation("hub_like_dependency"),
                references: vec!["Cai 2019 (Crossing)".to_string(), "Arcan HL".to_string()],
            });
        }
    }
}

fn detect_unstable_dependency(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    let inst = |c: &str| {
        instability(
            *g.fan_in.get(c).unwrap_or(&0),
            *g.fan_out.get(c).unwrap_or(&0),
        )
    };
    let mut targets_by_source: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (s, t) in &g.edges {
        targets_by_source
            .entry(s.clone())
            .or_default()
            .insert(t.clone());
    }
    for (source, targets) in &targets_by_source {
        let total = targets.len();
        if total == 0 {
            continue;
        }
        let source_i = inst(source);
        let uphill = targets.iter().filter(|t| inst(t) > source_i + 1e-9).count();
        let share = uphill as f64 / total as f64;
        if share >= config.unstable_doud && uphill >= 1 {
            out.push(Diagnosis {
                detector: "unstable_dependency".to_string(),
                title: "Unstable Dependency".to_string(),
                family: "stability".to_string(),
                target_kind: "component".to_string(),
                target: source.clone(),
                evidence: vec![
                    DiagEvidence::metric("uphill_share", share, config.unstable_doud),
                    DiagEvidence::bare("instability", source_i),
                ],
                principle: "Stable Dependencies Principle".to_string(),
                severity: Severity::Medium,
                confidence: (0.5 + share / 2.0).clamp(0.5, 0.95),
                remediation: remediation("unstable_dependency"),
                references: vec!["Martin SDP".to_string(), "Arcan UD".to_string()],
            });
        }
    }
}

/// Zone of Pain: a component far from Martin's main sequence on the rigid,
/// concrete side — low Abstractness, low Instability (many depend on it), so the
/// distance `D = |A + I − 1|` is high. Such a concrete core is painful to change:
/// inflexible *and* widely depended upon. Gated on a minimum number of type
/// declarations (so the Abstractness ratio is trustworthy) and on actually being
/// depended upon. The mirror "Zone of Uselessness" is deliberately left out for
/// now — high abstractness is idiomatic in Go/Rust, so it is too FP-prone to ship
/// on by default.
fn detect_zone_of_pain(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    for c in &g.components {
        let total = *g.total_types.get(c).unwrap_or(&0.0);
        if (total as usize) < config.zone_min_types {
            continue;
        }
        let fi = *g.fan_in.get(c).unwrap_or(&0);
        let fo = *g.fan_out.get(c).unwrap_or(&0);
        if fi < 3 {
            continue; // not actually depended upon → not painful.
        }
        let a = g.abstractness(c);
        let i = instability(fi, fo);
        let d = (a + i - 1.0).abs();
        if d >= config.zone_distance && a < 0.3 && i < 0.5 {
            let severity = if d >= 0.85 && fi >= 6 {
                Severity::High
            } else {
                Severity::Medium
            };
            out.push(Diagnosis {
                detector: "zone_of_pain".to_string(),
                title: "Zone of Pain".to_string(),
                family: "stability".to_string(),
                target_kind: "component".to_string(),
                target: c.clone(),
                evidence: vec![
                    DiagEvidence::metric("distance", d, config.zone_distance),
                    DiagEvidence::bare("abstractness", a),
                    DiagEvidence::bare("instability", i),
                    DiagEvidence::bare("fan_in", fi as f64),
                ],
                principle: "Stable Abstractions Principle (main sequence)".to_string(),
                severity,
                confidence: (0.5 + (d - config.zone_distance) * 1.5).clamp(0.5, 0.9),
                remediation: remediation("zone_of_pain"),
                references: vec!["Martin (OO Design Quality Metrics)".to_string()],
            });
        }
    }
}

/// God Component: a component whose file count is in the top percentile and over
/// an absolute floor. Size is file count, so this is language-agnostic.
fn detect_god_component(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    let counts: Vec<f64> = g.components.iter().map(|c| *g.files.get(c).unwrap_or(&0) as f64).collect();
    let threshold = percentile(&counts, config.god_percentile).max(config.god_min_files as f64);
    for c in &g.components {
        let n = *g.files.get(c).unwrap_or(&0) as f64;
        if n > threshold {
            let ratio = n / threshold;
            let severity = if ratio >= 2.0 {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut evidence = vec![DiagEvidence::metric("file_count", n, threshold)];
            let cx = *g.complexity.get(c).unwrap_or(&0.0);
            if cx > 0.0 {
                evidence.push(DiagEvidence::bare("aggregate_cognitive_complexity", cx));
            }
            out.push(Diagnosis {
                detector: "god_component".to_string(),
                title: "God Component".to_string(),
                family: "size".to_string(),
                target_kind: "component".to_string(),
                target: c.clone(),
                evidence,
                principle: "Single Responsibility Principle".to_string(),
                severity,
                confidence: (0.5 + (ratio - 1.0) / 4.0).clamp(0.5, 0.95),
                remediation: remediation("god_component"),
                references: vec!["Arcan GC".to_string(), "Fowler (Large Class)".to_string()],
            });
        }
    }
}

fn detect_dense_structure(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    let n = g.components.len();
    let possible = n.saturating_mul(n.saturating_sub(1));
    if possible == 0 {
        return;
    }
    let density = g.edges.len() as f64 / possible as f64;
    if density >= config.dense_medium {
        let severity = if density >= config.dense_high {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(Diagnosis {
            detector: "dense_structure".to_string(),
            title: "Dense Structure".to_string(),
            family: "structural".to_string(),
            target_kind: "repository".to_string(),
            target: "<repository>".to_string(),
            evidence: vec![DiagEvidence::metric(
                "coupling_density",
                density,
                config.dense_medium,
            )],
            principle: "Low Coupling".to_string(),
            severity,
            confidence: 0.8,
            remediation: remediation("dense_structure"),
            references: vec!["Arcan (Dense Structure)".to_string()],
        });
    }
}

/// Hotspot: a component that is both complex and frequently changed (Tornhill's
/// intersection). A prioritisation signal (low), not a defect in itself.
fn detect_hotspots(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    let max_churn = g.churn.values().copied().fold(0.0_f64, f64::max).max(1.0);
    let max_cx = g.complexity.values().copied().fold(0.0_f64, f64::max).max(1.0);
    let mut ranked: Vec<(String, f64, f64, f64)> = g
        .components
        .iter()
        .filter_map(|c| {
            let churn = *g.churn.get(c).unwrap_or(&0.0);
            let cx = *g.complexity.get(c).unwrap_or(&0.0);
            if churn <= 0.0 || cx <= 0.0 {
                return None;
            }
            let score = (churn / max_churn * 0.5 + cx / max_cx * 0.5) * 100.0;
            Some((c.clone(), score, churn, cx))
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    for (component, score, churn, cx) in ranked.into_iter().take(config.hotspot_limit) {
        if score < 10.0 {
            continue;
        }
        out.push(Diagnosis {
            detector: "hotspot".to_string(),
            title: "Hotspot".to_string(),
            family: "evolutionary".to_string(),
            target_kind: "component".to_string(),
            target: component,
            evidence: vec![
                DiagEvidence::bare("hotspot_score", score),
                DiagEvidence::bare("churn", churn),
                DiagEvidence::bare("complexity", cx),
            ],
            principle: "Pay down high-interest debt first".to_string(),
            severity: Severity::Low,
            confidence: 0.7,
            remediation: remediation("hotspot"),
            references: vec!["Tornhill (Your Code as a Crime Scene)".to_string()],
        });
    }
}

/// Unstable Interface: a widely-depended-on component that also changes
/// frequently — high fan-in ∧ high churn. Per Cai 2019, one of the two most
/// bug-correlated anti-patterns, so it starts High. Silent without git history.
fn detect_unstable_interface(g: &ComponentGraph, config: &DiagnoseConfig, out: &mut Vec<Diagnosis>) {
    let fins: Vec<f64> = g
        .components
        .iter()
        .map(|c| *g.fan_in.get(c).unwrap_or(&0) as f64)
        .collect();
    let churns: Vec<f64> = g.components.iter().map(|c| *g.churn.get(c).unwrap_or(&0.0)).collect();
    let in_th = percentile(&fins, config.hub_percentile).max(3.0);
    let ch_th = percentile(&churns, config.hub_percentile).max(1.0);
    for c in &g.components {
        let fi = *g.fan_in.get(c).unwrap_or(&0) as f64;
        let ch = *g.churn.get(c).unwrap_or(&0.0);
        if fi >= in_th && ch > 0.0 && ch >= ch_th {
            out.push(Diagnosis {
                detector: "unstable_interface".to_string(),
                title: "Unstable Interface".to_string(),
                family: "evolutionary".to_string(),
                target_kind: "component".to_string(),
                target: c.clone(),
                evidence: vec![
                    DiagEvidence::metric("fan_in", fi, in_th),
                    DiagEvidence::metric("churn", ch, ch_th),
                ],
                principle: "Stable Abstractions; keep widely-used APIs stable".to_string(),
                confidence: (((fi / in_th) + (ch / ch_th)) / 4.0).clamp(0.5, 0.99),
                severity: Severity::High,
                remediation: remediation("unstable_interface"),
                references: vec!["Cai 2019 (Unstable Interface)".to_string()],
            });
        }
    }
}

/// Change Coupling & Modularity Violation: components whose files repeatedly
/// change together. When the two components have **no** structural dependency,
/// the co-change is unexplained by the architecture — a Modularity Violation
/// (Wong & Cai / Clio), the higher-signal case. When a structural edge exists,
/// it is ordinary (lower-signal) change coupling. Silent without git history.
fn detect_change_coupling(
    g: &ComponentGraph,
    co_change: &[(String, String, f64)],
    config: &DiagnoseConfig,
    out: &mut Vec<Diagnosis>,
) {
    if co_change.is_empty() {
        return;
    }
    let depth = config.component_depth;
    let mut pairs: BTreeMap<(String, String), f64> = BTreeMap::new();
    for (a, b, n) in co_change {
        if is_excluded(a, &config.exclude) || is_excluded(b, &config.exclude) {
            continue;
        }
        let ca = component_of(a, depth);
        let cb = component_of(b, depth);
        if ca == cb {
            continue;
        }
        // Both endpoints must be real *source* components (i.e. directories that
        // hold indexed code). Co-change between non-source dirs — docs, `.github`
        // workflows, root metadata (CHANGES, pyproject) — is expected at release
        // time and is not an architectural modularity violation. Restricting to
        // source components is what keeps this detector precise.
        if !g.components.contains(&ca) || !g.components.contains(&cb) {
            continue;
        }
        let key = if ca < cb { (ca, cb) } else { (cb, ca) };
        *pairs.entry(key).or_default() += *n;
    }
    let min = config.change_coupling_min as f64;
    for ((ca, cb), n) in &pairs {
        if *n < min {
            continue;
        }
        let structural =
            g.edges.contains(&(ca.clone(), cb.clone())) || g.edges.contains(&(cb.clone(), ca.clone()));
        let target = format!("{ca} <-> {cb}");
        let evidence = vec![DiagEvidence::metric("co_changes", *n, min)];
        if structural {
            out.push(Diagnosis {
                detector: "change_coupling".to_string(),
                title: "Change Coupling".to_string(),
                family: "evolutionary".to_string(),
                target_kind: "component-pair".to_string(),
                target,
                evidence,
                principle: "Co-locate things that change together".to_string(),
                severity: Severity::Low,
                confidence: 0.6,
                remediation: remediation("change_coupling"),
                references: vec!["Tornhill (temporal coupling)".to_string()],
            });
        } else {
            let severity = if *n >= 2.0 * min {
                Severity::High
            } else {
                Severity::Medium
            };
            out.push(Diagnosis {
                detector: "modularity_violation".to_string(),
                title: "Modularity Violation".to_string(),
                family: "evolutionary".to_string(),
                target_kind: "component-pair".to_string(),
                target,
                evidence,
                principle: "The architecture should explain what changes together".to_string(),
                severity,
                confidence: (0.6 + n / (4.0 * min)).clamp(0.6, 0.95),
                remediation: remediation("modularity_violation"),
                references: vec![
                    "Wong & Cai (Modularity Violations)".to_string(),
                    "Tornhill".to_string(),
                ],
            });
        }
    }
}

// --- remediation catalogue -------------------------------------------------

fn lang(notes: &[(&str, &str)]) -> BTreeMap<String, String> {
    notes
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The curated smell → remediation mapping. Static and reviewed; never invented
/// at runtime.
fn remediation(detector: &str) -> Remediation {
    match detector {
        "cyclic_dependency" => Remediation {
            summary: "Break the cycle: invert one dependency or extract the shared core both sides depend on.".to_string(),
            refactoring: "Dependency Inversion / Extract shared module".to_string(),
            when_not_to_act: Some("Type-only/deferred imports are excluded; a tightly cohesive cluster may be intentional.".to_string()),
            language_notes: lang(&[
                ("ts", "Move shared types/contracts to a leaf module; `import type` drops type-only edges."),
                ("python", "An unconditional same-package import cycle is a real runtime crash — split the shared piece out."),
                ("go", "Introduce a small interface in the consumer package; the provider depends on it, not vice versa."),
                ("rust", "Move the shared types to a leaf module/crate; cycles between crates are forbidden anyway."),
            ]),
        },
        "file_cycle" => Remediation {
            summary: "Files in one component import each other in a loop: break it by extracting the shared piece into a leaf file, or invert one import.".to_string(),
            refactoring: "Extract shared module / Dependency Inversion".to_string(),
            when_not_to_act: Some("Type-only/deferred imports are excluded; a few mutually-recursive files in a cohesive unit may be acceptable.".to_string()),
            language_notes: lang(&[
                ("python", "An unconditional intra-package import cycle is a real `ImportError` risk — split the shared symbols into their own module."),
                ("ts", "`import type` removes type-only edges; otherwise move shared types to a leaf file."),
            ]),
        },
        "hub_like_dependency" => Remediation {
            summary: "Split the hub along its responsibilities and depend on abstractions, not on the hub.".to_string(),
            refactoring: "Extract Module / Dependency Inversion".to_string(),
            when_not_to_act: Some("A deliberate façade or composition root may legitimately fan out; judge intent.".to_string()),
            language_notes: lang(&[
                ("go", "Define narrow (one- or two-method) interfaces at the consumers; keep the hub's surface small."),
                ("rust", "Split by trait; let callers depend on the trait, not the concrete hub type."),
            ]),
        },
        "unstable_dependency" => Remediation {
            summary: "Don't depend on something more likely to change than you: invert the dependency or introduce a stable abstraction.".to_string(),
            refactoring: "Dependency Inversion / Introduce stable interface".to_string(),
            when_not_to_act: Some("Depending on a stable, well-versioned boundary is fine.".to_string()),
            language_notes: Default::default(),
        },
        "zone_of_pain" => Remediation {
            summary: "A rigid, concrete core that many components depend on: introduce abstractions (interfaces/traits) so dependents rely on a stable contract, not the implementation.".to_string(),
            refactoring: "Dependency Inversion / Introduce abstraction (Stable Abstractions Principle)".to_string(),
            when_not_to_act: Some("A stable, rarely-changing concrete core (e.g. mature value types) can sit in the Zone of Pain without harm; act when it changes often or blocks its dependents.".to_string()),
            language_notes: lang(&[
                ("go", "Define interfaces at the consumers and depend on them; the concrete core implements them."),
                ("rust", "Expose a trait for the stable surface; let dependents take `impl Trait`/`dyn Trait` instead of the concrete type."),
            ]),
        },
        "god_component" => Remediation {
            summary: "Split the component into cohesive sub-components, each with a single reason to change.".to_string(),
            refactoring: "Extract Module / Extract Class".to_string(),
            when_not_to_act: Some("Generated or vendored directories are excluded; a large directory behind a clean interface may be acceptable.".to_string()),
            language_notes: lang(&[
                ("go", "Split into packages grouped by responsibility."),
                ("rust", "Split into sub-modules; reconsider whether enums/typestate remove branching."),
            ]),
        },
        "dense_structure" => Remediation {
            summary: "Overall coupling is high: introduce clear layers/boundaries and reduce cross-component edges.".to_string(),
            refactoring: "Introduce layering / boundary rules".to_string(),
            when_not_to_act: Some("Small codebases are naturally dense; weigh against absolute size.".to_string()),
            language_notes: Default::default(),
        },
        "hotspot" => Remediation {
            summary: "Complex code that changes often is your highest-interest debt — prioritise refactoring here.".to_string(),
            refactoring: "Targeted refactor (reduce complexity where churn is highest)".to_string(),
            when_not_to_act: Some("High churn alone (e.g. a config file) is not debt without complexity.".to_string()),
            language_notes: Default::default(),
        },
        "unstable_interface" => Remediation {
            summary: "A widely-used API that keeps changing forces churn on every dependent: stabilise it behind a versioned contract before extending it.".to_string(),
            refactoring: "Extract stable interface / freeze the public contract".to_string(),
            when_not_to_act: Some("A young API still finding its shape will churn legitimately; this matters once it has many dependents.".to_string()),
            language_notes: Default::default(),
        },
        "change_coupling" => Remediation {
            summary: "These components change together and are coupled — confirm the coupling is intended and the boundary is in the right place.".to_string(),
            refactoring: "Review the boundary; co-locate or formalise the dependency".to_string(),
            when_not_to_act: Some("Coupled components changing together is often expected; treat as informational.".to_string()),
            language_notes: Default::default(),
        },
        "modularity_violation" => Remediation {
            summary: "These components keep changing together but have no dependency between them — a hidden coupling the architecture doesn't capture. Make the shared assumption explicit (extract it) or document the link.".to_string(),
            refactoring: "Extract the shared concept / introduce an explicit dependency".to_string(),
            when_not_to_act: Some("Coincidental co-change (e.g. a repo-wide rename) is not a real coupling.".to_string()),
            language_notes: Default::default(),
        },
        _ => Remediation {
            summary: "Review against the relevant design principle.".to_string(),
            refactoring: "See references".to_string(),
            when_not_to_act: None,
            language_notes: Default::default(),
        },
    }
}

/// The machine-actionable fix descriptor for a diagnose detector. Architectural
/// smells are never `auto_fixable` — breaking a cycle or splitting a hub is a
/// refactoring that needs judgement — so this hands the agent a stable action
/// `kind` plus the concrete refactoring to perform. Mirrors `FindingKind::fix_spec`.
pub fn fix_spec(detector: &str) -> FixSpec {
    let rem = remediation(detector);
    let kind = match detector {
        "cyclic_dependency" | "file_cycle" => "break_cycle",
        "hub_like_dependency" => "split_hub",
        "unstable_dependency" => "invert_dependency",
        "zone_of_pain" => "introduce_abstraction",
        "god_component" => "split_component",
        "dense_structure" => "introduce_layering",
        "hotspot" => "prioritize_refactor",
        "unstable_interface" => "stabilize_interface",
        "change_coupling" => "review_coupling",
        "modularity_violation" => "make_coupling_explicit",
        _ => "review",
    };
    FixSpec {
        kind: kind.to_string(),
        auto_fixable: false,
        instruction: rem.refactoring,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_of_uses_parent_dir_or_depth() {
        assert_eq!(component_of("src/vs/workbench/x.ts", 0), "src/vs/workbench");
        assert_eq!(component_of("src\\vs\\base\\y.ts", 0), "src/vs/base");
        assert_eq!(component_of("main.ts", 0), "<root>");
        assert_eq!(component_of("src/vs/workbench/x.ts", 2), "src/vs");
    }

    #[test]
    fn excludes_tests_and_generated_by_default() {
        let ex = DiagnoseConfig::default().exclude;
        assert!(is_excluded("src/foo/tests/bar.ts", &ex));
        assert!(is_excluded("src/foo/bar.spec.ts", &ex));
        assert!(is_excluded("dist/bundle.min.js", &ex));
        assert!(!is_excluded("src/foo/bar.ts", &ex));
        // A segment token must match a whole segment, not a substring.
        assert!(!is_excluded("src/latest/bar.ts", &ex));
    }

    #[test]
    fn detects_a_component_cycle_with_full_confidence() {
        let files = vec!["a/x.ts".to_string(), "b/y.ts".to_string()];
        let deps = vec![
            ("a/x.ts".to_string(), "b/y.ts".to_string()),
            ("b/y.ts".to_string(), "a/x.ts".to_string()),
        ];
        let report = diagnose(
            &files,
            &deps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &[],
            &DiagnoseConfig::default(),
        );
        let cycle = report
            .findings
            .iter()
            .find(|f| f.detector == "cyclic_dependency")
            .expect("cycle detected");
        assert_eq!(cycle.confidence, 1.0);
        assert!(!cycle.evidence.is_empty());
    }

    #[test]
    fn detects_an_intra_component_file_cycle() {
        // Two files in the SAME component importing each other: the component
        // graph collapses this (no inter-component edge), so only file_cycle
        // catches it.
        let files = vec!["pkg/a.py".to_string(), "pkg/b.py".to_string()];
        let deps = vec![
            ("pkg/a.py".to_string(), "pkg/b.py".to_string()),
            ("pkg/b.py".to_string(), "pkg/a.py".to_string()),
        ];
        let report = diagnose(
            &files,
            &deps,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
            &[],
            &DiagnoseConfig::default(),
        );
        assert!(report.findings.iter().any(|f| f.detector == "file_cycle"));
        // It is intra-component, so cyclic_dependency must NOT also fire.
        assert!(!report.findings.iter().any(|f| f.detector == "cyclic_dependency"));
    }

    #[test]
    fn metrics_report_abstractness_and_distance() {
        let files = vec!["core/a.ts".to_string()];
        let deps: Vec<(String, String)> = vec![];
        // 1 abstract type of 4 total → A = 0.25; no edges → I = 0 → D = |0.25+0-1| = 0.75.
        let abst: HashMap<String, (f64, f64)> =
            [("core/a.ts".to_string(), (1.0, 4.0))].into_iter().collect();
        let report = metrics(
            &files,
            &deps,
            &HashMap::new(),
            &HashMap::new(),
            &abst,
            &DiagnoseConfig::default(),
        );
        let core = report
            .components
            .iter()
            .find(|m| m.component == "core")
            .expect("core component");
        assert!((core.abstractness - 0.25).abs() < 1e-9);
        assert!((core.distance - 0.75).abs() < 1e-9);
    }

    #[test]
    fn detects_a_zone_of_pain() {
        // A concrete core (5 types, 0 abstract) that three components depend on
        // and that depends on nothing → A = 0, I = 0, D = 1: the pain corner.
        let files = vec![
            "core/a.ts".to_string(),
            "c1/x.ts".to_string(),
            "c2/x.ts".to_string(),
            "c3/x.ts".to_string(),
        ];
        let deps = vec![
            ("c1/x.ts".to_string(), "core/a.ts".to_string()),
            ("c2/x.ts".to_string(), "core/a.ts".to_string()),
            ("c3/x.ts".to_string(), "core/a.ts".to_string()),
        ];
        let abst: HashMap<String, (f64, f64)> =
            [("core/a.ts".to_string(), (0.0, 5.0))].into_iter().collect();
        let report = diagnose(
            &files,
            &deps,
            &HashMap::new(),
            &HashMap::new(),
            &abst,
            &[],
            &DiagnoseConfig::default(),
        );
        let pain = report
            .findings
            .iter()
            .find(|f| f.detector == "zone_of_pain")
            .expect("zone_of_pain detected");
        assert_eq!(pain.target, "core");
        assert!(pain.severity >= Severity::Medium);
    }

    #[test]
    fn is_deterministic() {
        let files = vec![
            "a/x.ts".to_string(),
            "b/y.ts".to_string(),
            "c/z.ts".to_string(),
        ];
        let deps = vec![
            ("a/x.ts".to_string(), "b/y.ts".to_string()),
            ("b/y.ts".to_string(), "a/x.ts".to_string()),
            ("c/z.ts".to_string(), "a/x.ts".to_string()),
        ];
        let cfg = DiagnoseConfig::default();
        let one = diagnose(&files, &deps, &HashMap::new(), &HashMap::new(), &HashMap::new(), &[], &cfg);
        let two = diagnose(&files, &deps, &HashMap::new(), &HashMap::new(), &HashMap::new(), &[], &cfg);
        assert_eq!(format!("{:?}", one.findings), format!("{:?}", two.findings));
    }
}
