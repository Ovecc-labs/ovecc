//! The architecture contract check: observed dependency edges diffed against
//! `.ovecc/architecture.toml`.
//!
//! Verdicts use the reflexion-model vocabulary (Murphy/Notkin/Sullivan): an
//! undeclared component-to-component edge is a divergence, a declared edge no
//! import implements is an absence. The contract's extras add two more: an
//! import that skips a component's declared interface files, and an external
//! package a component banned. Everything reads the edges handed to
//! [`RuleInput`], never the database, so the same check can judge unsaved
//! edits later.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use ovecc_core::architecture::{
    ArchitectureContract, EnforcementMode, UnassignedPolicy, baseline_entry, x_notation_allows,
};
use ovecc_core::facts::{
    CapabilityKind, CoChangedPair, EntityRef, Evidence, FindingKind, FindingRecord,
    FunctionMetricsRow, Severity,
};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_core::legacy::DependencyRecord;

use crate::{ContractInput, RuleInput, specifier_matches};

// Grouped like boundary rules: one finding per offending pair, every
// occurrence as evidence, so a hot edge does not flood the report.
type PairMap<'a> = BTreeMap<(&'a str, &'a str), Vec<&'a DependencyRecord>>;

/// One denied-capability use, whichever side witnessed it: an AST fact
/// (`Date.now` at a line) or an external import edge (`axios`).
struct CapabilityUse<'a> {
    file: &'a str,
    line: u32,
    api: &'a str,
    count: u32,
}

/// (component, capability) -> its denied uses.
type CapabilityMap<'a> = BTreeMap<(&'a str, &'a str), Vec<CapabilityUse<'a>>>;

/// (component, metric name) -> (function row, its budget).
type BudgetMap<'a> = BTreeMap<(&'a str, &'a str), Vec<(&'a FunctionMetricsRow, u32)>>;

/// (component, component), ordered, -> the coupled file pairs linking them.
type CouplingMap<'a> = BTreeMap<(&'a str, &'a str), Vec<&'a CoChangedPair>>;

/// Coupled file pairs two components must share before the deviation is
/// reported. One pair is an accident: a single shared constant, one commit that
/// happened to touch both sides. The published precision on this family of
/// finding sits between 40 and 66%, so the filter that costs the least recall
/// for the most precision is worth its price.
const MIN_COUPLED_FILE_PAIRS: usize = 2;

#[derive(Default)]
struct EdgeGroups<'a> {
    divergences: PairMap<'a>,
    bypasses: PairMap<'a>,
    deprecated: PairMap<'a>,
    banned: PairMap<'a>,
    /// Cross-slice imports inside a `slices = true` component, keyed by the
    /// qualified slice pair (`features/auth` -> `features/cart`).
    slices: PairMap<'a>,
    capabilities: CapabilityMap<'a>,
    budgets: BudgetMap<'a>,
    coupling: CouplingMap<'a>,
    observed: BTreeSet<(&'a str, &'a str)>,
}

pub(crate) fn contract_rules(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    let Some(architecture) = input.architecture else {
        return Vec::new();
    };
    let contract = architecture.contract;
    if contract.mode == EnforcementMode::Off {
        return Vec::new();
    }

    let mut groups = classify_edges(input, architecture);
    // The baseline is accepted debt, not a verdict change: entries vanish
    // from the report in new-violations mode and only there — strict means
    // the whole debt gates again.
    if contract.mode == EnforcementMode::NewViolations && !architecture.baseline.is_empty() {
        groups = prune_baselined(groups, architecture.baseline);
    }
    let mut findings = pair_findings(input, &groups);
    findings.extend(coupling_findings(input, &groups));
    findings.extend(absence_findings(input, contract, &groups.observed));
    findings.extend(unassigned_finding(input, architecture));

    // Warn mode reports everything but gates nothing: low is below every
    // gate's default threshold.
    if contract.mode == EnforcementMode::Warn {
        for finding in &mut findings {
            finding.severity = Severity::Low;
        }
    }
    findings
}

/// Every current violation as a baseline entry, grouped by source component.
/// Ignores the existing baseline on purpose: this is the full present debt,
/// what `--freeze` writes and what the ratchet intersects the store with.
pub(crate) fn violation_entries(input: &RuleInput<'_>) -> BTreeMap<String, BTreeSet<String>> {
    let Some(architecture) = input.architecture else {
        return BTreeMap::new();
    };
    if architecture.contract.mode == EnforcementMode::Off {
        return BTreeMap::new();
    }
    let groups = classify_edges(input, architecture);
    let sections: [(&str, &PairMap<'_>); 5] = [
        ("divergence", &groups.divergences),
        ("interface-bypass", &groups.bypasses),
        ("deprecated-use", &groups.deprecated),
        ("external-deny", &groups.banned),
        ("slice-isolation", &groups.slices),
    ];
    let mut entries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (slug, map) in sections {
        for (&(component, _), edges) in map.iter() {
            for dependency in edges {
                entries
                    .entry(component.to_string())
                    .or_default()
                    .insert(baseline_entry(
                        slug,
                        &dependency.source_file_path,
                        &dependency.specifier,
                    ));
            }
        }
    }
    for (&(component, _), uses) in &groups.capabilities {
        for use_ in uses {
            entries
                .entry(component.to_string())
                .or_default()
                .insert(baseline_entry("capability", use_.file, use_.api));
        }
    }
    for (&(component, _), rows) in &groups.budgets {
        for (row, _) in rows {
            entries
                .entry(component.to_string())
                .or_default()
                .insert(baseline_entry(
                    "complexity-budget",
                    &row.file_path,
                    &row.qualified_name,
                ));
        }
    }
    entries
}

fn prune_baselined<'a>(groups: EdgeGroups<'a>, baseline: &BTreeSet<String>) -> EdgeGroups<'a> {
    EdgeGroups {
        divergences: without_baselined(groups.divergences, "divergence", baseline),
        bypasses: without_baselined(groups.bypasses, "interface-bypass", baseline),
        deprecated: without_baselined(groups.deprecated, "deprecated-use", baseline),
        banned: without_baselined(groups.banned, "external-deny", baseline),
        slices: without_baselined(groups.slices, "slice-isolation", baseline),
        // Behavioral coupling has no baseline entry: it is advisory, so there
        // is nothing to accept as debt.
        coupling: groups.coupling,
        capabilities: groups
            .capabilities
            .into_iter()
            .filter_map(|(pair, uses)| {
                let kept: Vec<CapabilityUse<'_>> = uses
                    .into_iter()
                    .filter(|use_| {
                        !baseline.contains(&baseline_entry("capability", use_.file, use_.api))
                    })
                    .collect();
                (!kept.is_empty()).then_some((pair, kept))
            })
            .collect(),
        budgets: groups
            .budgets
            .into_iter()
            .filter_map(|(pair, rows)| {
                let kept: Vec<(&FunctionMetricsRow, u32)> = rows
                    .into_iter()
                    .filter(|(row, _)| {
                        !baseline.contains(&baseline_entry(
                            "complexity-budget",
                            &row.file_path,
                            &row.qualified_name,
                        ))
                    })
                    .collect();
                (!kept.is_empty()).then_some((pair, kept))
            })
            .collect(),
        observed: groups.observed,
    }
}

fn without_baselined<'a>(map: PairMap<'a>, slug: &str, baseline: &BTreeSet<String>) -> PairMap<'a> {
    map.into_iter()
        .filter_map(|(pair, edges)| {
            let kept: Vec<&DependencyRecord> = edges
                .into_iter()
                .filter(|dependency| {
                    !baseline.contains(&baseline_entry(
                        slug,
                        &dependency.source_file_path,
                        &dependency.specifier,
                    ))
                })
                .collect();
            (!kept.is_empty()).then_some((pair, kept))
        })
        .collect()
}

fn classify_edges<'a>(input: &RuleInput<'a>, architecture: ContractInput<'a>) -> EdgeGroups<'a> {
    let interfaces = declared_interfaces(architecture.contract);
    let mut groups = EdgeGroups::default();
    for dependency in input.dependencies {
        let source = architecture.component_of.get(&dependency.source_file_path);
        if dependency.is_external {
            if let Some(source) = source {
                classify_external(
                    architecture.contract,
                    source,
                    dependency,
                    &mut groups.banned,
                );
                classify_external_capability(architecture, source, dependency, &mut groups);
            }
        } else {
            classify_internal(architecture, &interfaces, source, dependency, &mut groups);
        }
    }
    classify_capability_facts(architecture, &mut groups);
    classify_budgets(architecture, &mut groups);
    classify_coupling(architecture, &mut groups);
    groups
}

/// Components the history ties together while the contract and the imports both
/// say they are strangers. Nothing static can see this: the only witness is that
/// the same commits keep touching both sides.
///
/// A pair is skipped as soon as something already explains it — a declared
/// dependency, or any observed import, which is either legal or already reported
/// as a divergence. What is left is coupling no one named.
fn classify_coupling<'a>(architecture: ContractInput<'a>, groups: &mut EdgeGroups<'a>) {
    let connected: BTreeSet<(&str, &str)> = groups
        .observed
        .iter()
        .chain(groups.divergences.keys())
        .chain(groups.bypasses.keys())
        .copied()
        .collect();
    let explained = |left: &str, right: &str| {
        connected.contains(&(left, right))
            || connected.contains(&(right, left))
            || architecture
                .contract
                .component(left)
                .is_some_and(|spec| spec.depends_on.iter().any(|on| on.component() == right))
            || architecture
                .contract
                .component(right)
                .is_some_and(|spec| spec.depends_on.iter().any(|on| on.component() == left))
    };

    for pair in architecture.co_changes {
        // Files outside every component glob (build output, assets, docs) carry
        // no architectural claim.
        let (Some(left), Some(right)) = (
            architecture.component_of.get(&pair.left),
            architecture.component_of.get(&pair.right),
        ) else {
            continue;
        };
        if left == right {
            continue;
        }
        let (left, right) = (left.as_str(), right.as_str());
        if explained(left, right) {
            continue;
        }
        let key = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        groups.coupling.entry(key).or_default().push(pair);
    }
    groups
        .coupling
        .retain(|_, pairs| pairs.len() >= MIN_COUPLED_FILE_PAIRS);
}

/// A denied ambient capability witnessed by an AST fact (`Date.now`,
/// `localStorage`, ...).
fn classify_capability_facts<'a>(architecture: ContractInput<'a>, groups: &mut EdgeGroups<'a>) {
    for (file, fact) in architecture.capability_uses {
        let Some(component) = architecture.component_of.get(file) else {
            continue;
        };
        let Some(spec) = architecture.contract.component(component) else {
            continue;
        };
        if spec.deny_capabilities.contains(&fact.capability) {
            groups
                .capabilities
                .entry((component.as_str(), fact.capability.as_str()))
                .or_default()
                .push(CapabilityUse {
                    file,
                    line: fact.line,
                    api: &fact.api,
                    count: fact.count,
                });
        }
    }
}

/// A denied ambient capability witnessed by an external import: `axios` is a
/// network capability whether or not the file ever calls it.
fn classify_external_capability<'a>(
    architecture: ContractInput<'a>,
    source: &'a str,
    dependency: &'a DependencyRecord,
    groups: &mut EdgeGroups<'a>,
) {
    let Some(kind) = CapabilityKind::of_module_specifier(&dependency.specifier) else {
        return;
    };
    let Some(spec) = architecture.contract.component(source) else {
        return;
    };
    if spec.deny_capabilities.contains(&kind) {
        groups
            .capabilities
            .entry((source, kind.as_str()))
            .or_default()
            .push(CapabilityUse {
                file: &dependency.source_file_path,
                line: dependency.evidence_line as u32,
                api: &dependency.specifier,
                count: 1,
            });
    }
}

/// Per-function budgets: every function a component owns must fit the
/// component's declared complexity ceilings.
fn classify_budgets<'a>(architecture: ContractInput<'a>, groups: &mut EdgeGroups<'a>) {
    for row in architecture.functions {
        let Some(component) = architecture.component_of.get(&row.file_path) else {
            continue;
        };
        let Some(spec) = architecture.contract.component(component) else {
            continue;
        };
        if let Some(budget) = spec.max_cyclomatic
            && row.cyclomatic > budget
        {
            groups
                .budgets
                .entry((component.as_str(), "cyclomatic"))
                .or_default()
                .push((row, budget));
        }
        if let Some(budget) = spec.max_cognitive
            && row.cognitive > budget
        {
            groups
                .budgets
                .entry((component.as_str(), "cognitive"))
                .or_default()
                .push((row, budget));
        }
    }
}

fn declared_interfaces(contract: &ArchitectureContract) -> BTreeMap<&str, BTreeSet<String>> {
    contract
        .components
        .iter()
        .filter(|component| !component.interface.is_empty())
        .map(|component| {
            (
                component.name.as_str(),
                component
                    .interface
                    .iter()
                    .map(|path| path.replace('\\', "/"))
                    .collect(),
            )
        })
        .collect()
}

fn classify_external<'a>(
    contract: &'a ArchitectureContract,
    source: &'a str,
    dependency: &'a DependencyRecord,
    banned: &mut PairMap<'a>,
) {
    let Some(spec) = contract.component(source) else {
        return;
    };
    for pattern in &spec.external_deny {
        if specifier_matches(&dependency.specifier, pattern) {
            banned
                .entry((source, pattern.as_str()))
                .or_default()
                .push(dependency);
        }
    }
}

fn classify_internal<'a>(
    architecture: ContractInput<'a>,
    interfaces: &BTreeMap<&str, BTreeSet<String>>,
    source: Option<&'a String>,
    dependency: &'a DependencyRecord,
    groups: &mut EdgeGroups<'a>,
) {
    let Some(target_path) = &dependency.target_file_path else {
        return;
    };
    let target = architecture.component_of.get(target_path);
    let (Some(source), Some(target)) = (source, target) else {
        return;
    };
    if source == target {
        // Inside one component the only possible verdict is a slice breach:
        // both files sit in a `slices = true` component, in different
        // slices, and the target is not an `@x` public API for the source.
        if let (Some(source_slice), Some(target_slice)) = (
            architecture.slice_of.get(&dependency.source_file_path),
            architecture.slice_of.get(target_path),
        ) && source_slice != target_slice
            && !x_notation_allows(source_slice, target_path)
        {
            groups
                .slices
                .entry((source_slice.as_str(), target_slice.as_str()))
                .or_default()
                .push(dependency);
        }
        return;
    }
    let pair = (source.as_str(), target.as_str());

    // The interface holds even for a declared dependency: the pair being
    // legal does not open the target's internals.
    if let Some(interface) = interfaces.get(pair.1)
        && !interface.contains(&target_path.replace('\\', "/"))
    {
        groups.bypasses.entry(pair).or_default().push(dependency);
    }

    let Some(spec) = architecture.contract.component(pair.0) else {
        return;
    };
    match spec
        .depends_on
        .iter()
        .find(|entry| entry.component() == pair.1)
    {
        None => groups.divergences.entry(pair).or_default().push(dependency),
        Some(entry) => {
            groups.observed.insert(pair);
            if entry.deprecated() {
                groups.deprecated.entry(pair).or_default().push(dependency);
            }
        }
    }
}

/// One finding per component pair, every coupled file pair as evidence with the
/// commits that witnessed it. Low by design: the deviation is a question for the
/// reader, not a verdict, and a hard gate on a signal this uncertain would be
/// dishonest.
fn coupling_findings(input: &RuleInput<'_>, groups: &EdgeGroups<'_>) -> Vec<FindingRecord> {
    groups
        .coupling
        .iter()
        .map(|(&(left, right), pairs)| FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "architecture",
                "behavioral-coupling",
                left,
                right,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::BehavioralCoupling,
            severity: Severity::Low,
            rule_name: Some("architecture/behavioral-coupling".to_string()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: left.to_string(),
            }),
            title: format!("{left} and {right} change together without depending on each other"),
            description: format!(
                "The history ties '{left}' to '{right}' across {} file pair(s), but neither \
                 the contract nor any import connects them. Either something they share \
                 belongs in one place, or the dependency is real and belongs in \
                 .ovecc/architecture.toml.",
                pairs.len()
            ),
            evidence: pairs
                .iter()
                .take(10)
                .map(|pair| Evidence {
                    file_path: pair.left.clone(),
                    line: None,
                    symbol: None,
                    detail: Some(format!(
                        "with {} in {} commits ({})",
                        pair.right,
                        pair.support,
                        pair.commits
                            .iter()
                            .map(|sha| &sha[..8.min(sha.len())])
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                })
                .collect(),
            created_at: Utc::now(),
        })
        .collect()
}

fn pair_findings(input: &RuleInput<'_>, groups: &EdgeGroups<'_>) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    for (&(source, target), edges) in &groups.divergences {
        findings.push(pair_finding(
            input,
            "divergence",
            Severity::High,
            (source, target),
            format!("{source} -> {target} is not in the contract"),
            format!(
                "'{source}' imports '{target}' ({} occurrence(s)) but the contract \
                 does not declare this dependency. Remove the imports, or declare \
                 '{target}' in '{source}'.depends_on.",
                edges.len()
            ),
            edges,
        ));
    }
    for (&(source, target), edges) in &groups.bypasses {
        findings.push(pair_finding(
            input,
            "interface-bypass",
            Severity::High,
            (source, target),
            format!("{source} bypasses the interface of {target}"),
            format!(
                "'{source}' imports internals of '{target}' ({} occurrence(s)) \
                 instead of its declared interface file(s). Import through the \
                 interface.",
                edges.len()
            ),
            edges,
        ));
    }
    for (&(source, target), edges) in &groups.deprecated {
        findings.push(pair_finding(
            input,
            "deprecated-use",
            Severity::Medium,
            (source, target),
            format!("{source} -> {target} is deprecated"),
            format!(
                "'{source}' still imports '{target}' ({} occurrence(s)); the \
                 contract marks this dependency deprecated. Migrate the imports \
                 so the entry can be dropped.",
                edges.len()
            ),
            edges,
        ));
    }
    for (&(component, pattern), edges) in &groups.banned {
        findings.push(pair_finding(
            input,
            "external-deny",
            Severity::Medium,
            (component, pattern),
            format!("{component} imports banned package '{pattern}'"),
            format!(
                "'{component}' imports an external package matching '{pattern}' \
                 ({} occurrence(s)), which its contract denies.",
                edges.len()
            ),
            edges,
        ));
    }
    for (&(source, target), edges) in &groups.slices {
        findings.push(pair_finding(
            input,
            "slice-isolation",
            Severity::High,
            (source, target),
            format!("{source} -> {target} breaks slice isolation"),
            format!(
                "'{source}' imports '{target}' ({} occurrence(s)) but their \
                 component isolates its slices. Move the shared code down a \
                 layer, or expose it as a '@x' public API for '{source}'.",
                edges.len()
            ),
            edges,
        ));
    }
    for (&(component, capability), uses) in &groups.capabilities {
        let occurrences: u32 = uses.iter().map(|use_| use_.count).sum();
        findings.push(FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "architecture",
                "capability",
                component,
                capability,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::ArchitectureViolation,
            severity: Severity::Medium,
            rule_name: Some("architecture/capability".to_string()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: component.to_string(),
            }),
            title: format!("{component} uses denied capability '{capability}'"),
            description: format!(
                "'{component}' denies the '{capability}' capability but uses \
                 it ({occurrences} occurrence(s)). Move the access behind a \
                 component that may hold it, or drop the denial."
            ),
            evidence: uses
                .iter()
                .take(10)
                .map(|use_| Evidence {
                    file_path: use_.file.to_string(),
                    line: Some(use_.line),
                    symbol: None,
                    detail: Some(if use_.count > 1 {
                        format!("{} ({} uses)", use_.api, use_.count)
                    } else {
                        use_.api.to_string()
                    }),
                })
                .collect(),
            created_at: Utc::now(),
        });
    }
    for (&(component, metric), rows) in &groups.budgets {
        findings.push(FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "architecture",
                "complexity-budget",
                component,
                metric,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::ArchitectureViolation,
            severity: Severity::Medium,
            rule_name: Some("architecture/complexity-budget".to_string()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: component.to_string(),
            }),
            title: format!(
                "{component}: {} function(s) over the {metric} budget",
                rows.len()
            ),
            description: format!(
                "'{component}' budgets its per-function {metric} complexity \
                 and {} function(s) exceed it. Split them, or raise the \
                 budget deliberately.",
                rows.len()
            ),
            evidence: rows
                .iter()
                .take(10)
                .map(|(row, budget)| {
                    let value = match metric {
                        "cyclomatic" => row.cyclomatic,
                        _ => row.cognitive,
                    };
                    Evidence {
                        file_path: row.file_path.clone(),
                        line: Some(row.line),
                        symbol: Some(row.qualified_name.clone()),
                        detail: Some(format!("{metric} {value} > {budget}")),
                    }
                })
                .collect(),
            created_at: Utc::now(),
        });
    }
    findings
}

// Absences never gate: a stale promise is contract hygiene, not a defect
// in the code.
fn absence_findings(
    input: &RuleInput<'_>,
    contract: &ArchitectureContract,
    observed: &BTreeSet<(&str, &str)>,
) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    for component in &contract.components {
        let source = component.name.as_str();
        for entry in &component.depends_on {
            let target = entry.component();
            if observed.contains(&(source, target)) {
                continue;
            }
            findings.push(FindingRecord {
                id: FindingId::from_parts(&[
                    input.repository_id,
                    "architecture",
                    "absence",
                    source,
                    target,
                ]),
                repository_id: RepositoryId::from_raw(input.repository_id),
                snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
                kind: FindingKind::ArchitectureViolation,
                severity: Severity::Low,
                rule_name: Some("architecture/absence".to_string()),
                target: Some(EntityRef {
                    kind: NodeKind::Module,
                    id: source.to_string(),
                }),
                title: format!("{source} -> {target} is declared but never used"),
                description: format!(
                    "The contract allows '{source}' -> '{target}' but no import \
                     implements it. Remove the entry so the contract keeps \
                     describing reality."
                ),
                evidence: vec![Evidence {
                    file_path: ".ovecc/architecture.toml".to_string(),
                    line: None,
                    symbol: None,
                    detail: Some(format!("{source}.depends_on: {target}")),
                }],
                created_at: Utc::now(),
            });
        }
    }
    findings
}

fn unassigned_finding(
    input: &RuleInput<'_>,
    architecture: ContractInput<'_>,
) -> Option<FindingRecord> {
    let contract = architecture.contract;
    if contract.unassigned == UnassignedPolicy::Ignore {
        return None;
    }
    let unassigned: Vec<&String> = architecture
        .files
        .iter()
        .filter(|file| !architecture.component_of.contains_key(*file))
        .collect();
    if unassigned.is_empty() {
        return None;
    }
    let severity = match contract.unassigned {
        UnassignedPolicy::Forbid => Severity::High,
        _ => Severity::Low,
    };
    Some(FindingRecord {
        id: FindingId::from_parts(&[input.repository_id, "architecture", "unassigned"]),
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
        kind: FindingKind::ArchitectureViolation,
        severity,
        rule_name: Some("architecture/unassigned".to_string()),
        target: None,
        title: format!("{} file(s) belong to no component", unassigned.len()),
        description: format!(
            "{} indexed file(s) match no component's paths, so no contract \
             protects their dependencies. Widen a component's paths or add \
             a component.",
            unassigned.len()
        ),
        evidence: unassigned
            .iter()
            .take(10)
            .map(|file| Evidence {
                file_path: (*file).clone(),
                line: None,
                symbol: None,
                detail: None,
            })
            .collect(),
        created_at: Utc::now(),
    })
}

fn pair_finding(
    input: &RuleInput<'_>,
    slug: &str,
    severity: Severity,
    pair: (&str, &str),
    title: String,
    description: String,
    edges: &[&DependencyRecord],
) -> FindingRecord {
    let (source, counterpart) = pair;
    // The id keys on the pair, not on the edges, so the finding survives new
    // occurrences of the same violation instead of multiplying.
    FindingRecord {
        id: FindingId::from_parts(&[
            input.repository_id,
            "architecture",
            slug,
            source,
            counterpart,
        ]),
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
        kind: FindingKind::ArchitectureViolation,
        severity,
        rule_name: Some(format!("architecture/{slug}")),
        target: Some(EntityRef {
            kind: NodeKind::Module,
            id: source.to_string(),
        }),
        title,
        description,
        evidence: edges
            .iter()
            .take(10)
            .map(|dependency| Evidence {
                file_path: dependency.source_file_path.clone(),
                line: Some(dependency.evidence_line as u32),
                symbol: None,
                detail: Some(dependency.specifier.clone()),
            })
            .collect(),
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::architecture::{ComponentSpec, DependsOn};
    use ovecc_core::config::RulesConfig;
    use ovecc_core::facts::CapabilityFact;

    fn component(name: &str, paths: &[&str]) -> ComponentSpec {
        ComponentSpec {
            name: name.to_string(),
            role: None,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            depends_on: Vec::new(),
            interface: Vec::new(),
            external_deny: Vec::new(),
            slices: false,
            deny_capabilities: Vec::new(),
            max_cyclomatic: None,
            max_cognitive: None,
        }
    }

    fn contract(components: Vec<ComponentSpec>) -> ArchitectureContract {
        ArchitectureContract {
            schema: 1,
            mode: EnforcementMode::NewViolations,
            unassigned: UnassignedPolicy::Ignore,
            components,
        }
    }

    fn edge(source: &str, target: &str, specifier: &str, line: usize) -> DependencyRecord {
        DependencyRecord {
            id: format!("dep:{source}:{target}:{line}"),
            repository_id: "repo:test".to_string(),
            source_file_id: "f".to_string(),
            target_file_id: Some("g".to_string()),
            source_file_path: source.to_string(),
            target_file_path: Some(target.to_string()),
            source_module_id: "m:src".to_string(),
            target_module_id: "m:tgt".to_string(),
            source_module: "src".to_string(),
            target_module: "tgt".to_string(),
            specifier: specifier.to_string(),
            dependency_kind: "static_import".to_string(),
            is_external: false,
            evidence_line: line,
        }
    }

    fn external(source: &str, specifier: &str) -> DependencyRecord {
        DependencyRecord {
            target_file_id: None,
            target_file_path: None,
            is_external: true,
            ..edge(source, "unused", specifier, 1)
        }
    }

    struct Fixture {
        contract: ArchitectureContract,
        component_of: std::collections::BTreeMap<String, String>,
        files: Vec<String>,
        dependencies: Vec<DependencyRecord>,
        baseline: BTreeSet<String>,
        slice_of: std::collections::BTreeMap<String, String>,
        capability_uses: Vec<(String, CapabilityFact)>,
        functions: Vec<FunctionMetricsRow>,
        co_changes: Vec<CoChangedPair>,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Fixture {
                contract: contract(Vec::new()),
                component_of: BTreeMap::new(),
                files: Vec::new(),
                dependencies: Vec::new(),
                baseline: BTreeSet::new(),
                slice_of: BTreeMap::new(),
                capability_uses: Vec::new(),
                functions: Vec::new(),
                co_changes: Vec::new(),
            }
        }
    }

    fn run(fixture: &Fixture) -> Vec<FindingRecord> {
        let config = RulesConfig::default();
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: Some("snap"),
            modules: &[],
            dependencies: &fixture.dependencies,
            config: &config,
            security_patterns: &[],
            architecture: Some(ContractInput {
                contract: &fixture.contract,
                component_of: &fixture.component_of,
                files: &fixture.files,
                baseline: &fixture.baseline,
                slice_of: &fixture.slice_of,
                capability_uses: &fixture.capability_uses,
                functions: &fixture.functions,
                co_changes: &fixture.co_changes,
            }),
        };
        contract_rules(&input)
    }

    fn entries(fixture: &Fixture) -> BTreeMap<String, BTreeSet<String>> {
        let config = RulesConfig::default();
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: Some("snap"),
            modules: &[],
            dependencies: &fixture.dependencies,
            config: &config,
            security_patterns: &[],
            architecture: Some(ContractInput {
                contract: &fixture.contract,
                component_of: &fixture.component_of,
                files: &fixture.files,
                baseline: &fixture.baseline,
                slice_of: &fixture.slice_of,
                capability_uses: &fixture.capability_uses,
                functions: &fixture.functions,
                co_changes: &fixture.co_changes,
            }),
        };
        violation_entries(&input)
    }

    fn assign(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(file, component)| (file.to_string(), component.to_string()))
            .collect()
    }

    fn coupled(left: &str, right: &str) -> CoChangedPair {
        CoChangedPair {
            left: left.to_string(),
            right: right.to_string(),
            support: 6,
            jaccard: 0.6,
            lift: 2.0,
            confidence_left_to_right: 0.8,
            confidence_right_to_left: 0.7,
            commits: vec!["c1".to_string(), "c2".to_string()],
        }
    }

    /// The signal no static analysis can produce: two components with nothing
    /// between them in the code, that the history keeps editing together.
    #[test]
    fn components_that_change_together_without_depending_on_each_other_are_flagged() {
        let fixture = Fixture {
            contract: contract(vec![
                component("billing", &["src/billing/**"]),
                component("shipping", &["src/shipping/**"]),
            ]),
            component_of: assign(&[
                ("src/billing/rates.ts", "billing"),
                ("src/billing/invoice.ts", "billing"),
                ("src/shipping/zones.ts", "shipping"),
                ("src/shipping/label.ts", "shipping"),
            ]),
            co_changes: vec![
                coupled("src/billing/rates.ts", "src/shipping/zones.ts"),
                coupled("src/billing/invoice.ts", "src/shipping/label.ts"),
            ],
            ..Fixture::default()
        };
        let findings = run(&fixture);
        assert_eq!(
            rules_of(&findings),
            vec!["architecture/behavioral-coupling"]
        );
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Low, "advisory, never a gate");
        assert_eq!(
            finding.evidence.len(),
            2,
            "both file pairs are the evidence"
        );
        assert!(
            finding.evidence[0]
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("6 commits") && detail.contains("c1")),
            "the commits are the proof: {:?}",
            finding.evidence[0]
        );
    }

    /// One shared file pair is an accident. CLIO's own filter is recurrence,
    /// and it is what keeps the precision of this family usable.
    #[test]
    fn a_single_coupled_pair_is_not_enough() {
        let fixture = Fixture {
            contract: contract(vec![
                component("billing", &["src/billing/**"]),
                component("shipping", &["src/shipping/**"]),
            ]),
            component_of: assign(&[
                ("src/billing/rates.ts", "billing"),
                ("src/shipping/zones.ts", "shipping"),
            ]),
            co_changes: vec![coupled("src/billing/rates.ts", "src/shipping/zones.ts")],
            ..Fixture::default()
        };
        assert!(run(&fixture).is_empty());
    }

    /// An import already explains the coupling, and it is already reported as a
    /// divergence. Reporting both would charge one deviation twice.
    #[test]
    fn coupling_an_import_already_explains_is_left_to_the_divergence() {
        let fixture = Fixture {
            contract: contract(vec![
                component("billing", &["src/billing/**"]),
                component("shipping", &["src/shipping/**"]),
            ]),
            component_of: assign(&[
                ("src/billing/rates.ts", "billing"),
                ("src/billing/invoice.ts", "billing"),
                ("src/shipping/zones.ts", "shipping"),
                ("src/shipping/label.ts", "shipping"),
            ]),
            dependencies: vec![edge(
                "src/billing/rates.ts",
                "src/shipping/zones.ts",
                "../shipping/zones",
                3,
            )],
            co_changes: vec![
                coupled("src/billing/rates.ts", "src/shipping/zones.ts"),
                coupled("src/billing/invoice.ts", "src/shipping/label.ts"),
            ],
            ..Fixture::default()
        };
        assert_eq!(rules_of(&run(&fixture)), vec!["architecture/divergence"]);
    }

    /// A declared dependency is the contract saying "these two belong together":
    /// the history agreeing with it is not a deviation.
    #[test]
    fn a_declared_dependency_explains_the_coupling() {
        let mut billing = component("billing", &["src/billing/**"]);
        billing.depends_on = vec![DependsOn::Name("shipping".to_string())];
        let fixture = Fixture {
            contract: contract(vec![billing, component("shipping", &["src/shipping/**"])]),
            component_of: assign(&[
                ("src/billing/rates.ts", "billing"),
                ("src/billing/invoice.ts", "billing"),
                ("src/shipping/zones.ts", "shipping"),
                ("src/shipping/label.ts", "shipping"),
            ]),
            co_changes: vec![
                coupled("src/billing/rates.ts", "src/shipping/zones.ts"),
                coupled("src/billing/invoice.ts", "src/shipping/label.ts"),
            ],
            ..Fixture::default()
        };
        assert!(
            rules_of(&run(&fixture))
                .iter()
                .all(|rule| *rule != "architecture/behavioral-coupling"),
            "{:?}",
            rules_of(&run(&fixture))
        );
    }

    fn rules_of(findings: &[FindingRecord]) -> Vec<&str> {
        findings
            .iter()
            .filter_map(|finding| finding.rule_name.as_deref())
            .collect()
    }

    #[test]
    fn undeclared_edge_diverges_and_declared_edge_converges() {
        let mut api = component("api", &["src/api/**"]);
        api.depends_on = vec![DependsOn::Name("core".to_string())];
        let fixture = Fixture {
            contract: contract(vec![
                api,
                component("core", &["src/core/**"]),
                component("db", &["src/db/**"]),
            ]),
            component_of: assign(&[
                ("src/api/routes.ts", "api"),
                ("src/core/logic.ts", "core"),
                ("src/db/pool.ts", "db"),
            ]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![
                edge("src/api/routes.ts", "src/core/logic.ts", "../core/logic", 2),
                edge("src/api/routes.ts", "src/db/pool.ts", "../db/pool", 9),
                edge("src/api/routes.ts", "src/db/pool.ts", "../db/pool", 14),
            ],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        let divergences: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_name.as_deref() == Some("architecture/divergence"))
            .collect();
        assert_eq!(divergences.len(), 1, "api->db only, api->core is declared");
        assert_eq!(divergences[0].severity, Severity::High);
        assert_eq!(divergences[0].evidence.len(), 2, "both offending imports");
        assert_eq!(divergences[0].evidence[0].line, Some(9));
        assert!(divergences[0].title.contains("api -> db"));
    }

    #[test]
    fn declared_pair_must_still_enter_through_the_interface() {
        let mut api = component("api", &["src/api/**"]);
        api.depends_on = vec![DependsOn::Name("core".to_string())];
        let mut core = component("core", &["src/core/**"]);
        core.interface = vec!["src/core/index.ts".to_string()];
        let fixture = Fixture {
            contract: contract(vec![api, core]),
            component_of: assign(&[
                ("src/api/routes.ts", "api"),
                ("src/core/index.ts", "core"),
                ("src/core/secret.ts", "core"),
            ]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![
                edge("src/api/routes.ts", "src/core/index.ts", "../core", 1),
                edge(
                    "src/api/routes.ts",
                    "src/core/secret.ts",
                    "../core/secret",
                    5,
                ),
            ],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        let rules = rules_of(&findings);
        assert_eq!(
            rules
                .iter()
                .filter(|r| **r == "architecture/interface-bypass")
                .count(),
            1,
            "only the internals import bypasses"
        );
        assert!(
            !rules.contains(&"architecture/divergence"),
            "the pair itself is declared"
        );
    }

    #[test]
    fn deprecated_edge_reports_medium_and_leaves_no_absence() {
        let mut api = component("api", &["src/api/**"]);
        api.depends_on = vec![DependsOn::Detailed {
            component: "legacy".to_string(),
            deprecated: true,
        }];
        let fixture = Fixture {
            contract: contract(vec![api, component("legacy", &["src/legacy/**"])]),
            component_of: assign(&[
                ("src/api/routes.ts", "api"),
                ("src/legacy/old.ts", "legacy"),
            ]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![edge(
                "src/api/routes.ts",
                "src/legacy/old.ts",
                "../legacy/old",
                3,
            )],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        let rules = rules_of(&findings);
        assert!(rules.contains(&"architecture/deprecated-use"));
        assert!(!rules.contains(&"architecture/divergence"));
        assert!(!rules.contains(&"architecture/absence"), "edge is observed");
    }

    #[test]
    fn a_declared_edge_nobody_implements_is_an_absence_at_low() {
        let mut api = component("api", &["src/api/**"]);
        api.depends_on = vec![DependsOn::Name("core".to_string())];
        let fixture = Fixture {
            contract: contract(vec![api, component("core", &["src/core/**"])]),
            component_of: assign(&[("src/api/routes.ts", "api")]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        assert_eq!(rules_of(&findings), vec!["architecture/absence"]);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].evidence[0].file_path,
            ".ovecc/architecture.toml"
        );
    }

    #[test]
    fn external_deny_matches_specifier_patterns() {
        let mut core = component("core", &["src/core/**"]);
        core.external_deny = vec!["pg*".to_string()];
        let fixture = Fixture {
            contract: contract(vec![core]),
            component_of: assign(&[("src/core/logic.ts", "core")]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![
                external("src/core/logic.ts", "pg-pool"),
                external("src/core/logic.ts", "lodash"),
            ],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        assert_eq!(rules_of(&findings), vec!["architecture/external-deny"]);
        assert_eq!(findings[0].evidence.len(), 1, "only pg-pool matches");
        assert_eq!(findings[0].evidence[0].detail.as_deref(), Some("pg-pool"));
    }

    #[test]
    fn unassigned_policy_scales_from_silence_to_high() {
        let base = Fixture {
            contract: contract(vec![component("api", &["src/api/**"])]),
            component_of: assign(&[("src/api/routes.ts", "api")]),
            files: vec!["src/api/routes.ts".to_string(), "src/stray.ts".to_string()],
            baseline: BTreeSet::new(),
            dependencies: vec![],
            ..Fixture::default()
        };

        let mut ignored = base;
        ignored.contract.unassigned = UnassignedPolicy::Ignore;
        assert!(run(&ignored).is_empty());

        ignored.contract.unassigned = UnassignedPolicy::Warn;
        let warned = run(&ignored);
        assert_eq!(rules_of(&warned), vec!["architecture/unassigned"]);
        assert_eq!(warned[0].severity, Severity::Low);
        assert_eq!(warned[0].evidence.len(), 1, "only the stray file");

        ignored.contract.unassigned = UnassignedPolicy::Forbid;
        assert_eq!(run(&ignored)[0].severity, Severity::High);
    }

    #[test]
    fn baselined_edges_vanish_in_new_violations_and_return_in_strict() {
        let mut fixture = Fixture {
            contract: contract(vec![
                component("api", &["src/api/**"]),
                component("db", &["src/db/**"]),
            ]),
            component_of: assign(&[("src/api/routes.ts", "api"), ("src/db/pool.ts", "db")]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![
                edge("src/api/routes.ts", "src/db/pool.ts", "../db/pool", 4),
                edge("src/api/new.ts", "src/db/pool.ts", "../db/pool", 9),
            ],
            ..Fixture::default()
        };
        fixture
            .component_of
            .insert("src/api/new.ts".to_string(), "api".to_string());
        fixture.baseline.insert(baseline_entry(
            "divergence",
            "src/api/routes.ts",
            "../db/pool",
        ));

        let findings = run(&fixture);
        let divergence = findings
            .iter()
            .find(|f| f.rule_name.as_deref() == Some("architecture/divergence"))
            .expect("the unbaselined edge still diverges");
        assert_eq!(divergence.evidence.len(), 1, "baselined edge subtracted");
        assert_eq!(divergence.evidence[0].file_path, "src/api/new.ts");

        fixture.contract.mode = EnforcementMode::Strict;
        let strict = run(&fixture);
        let divergence = strict
            .iter()
            .find(|f| f.rule_name.as_deref() == Some("architecture/divergence"))
            .unwrap();
        assert_eq!(divergence.evidence.len(), 2, "strict ignores the baseline");
    }

    #[test]
    fn violation_entries_list_the_full_debt_by_component() {
        let mut fixture = Fixture {
            contract: contract(vec![
                component("api", &["src/api/**"]),
                component("db", &["src/db/**"]),
            ]),
            component_of: assign(&[("src/api/routes.ts", "api"), ("src/db/pool.ts", "db")]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![edge("src/api/routes.ts", "src/db/pool.ts", "../db/pool", 4)],
            ..Fixture::default()
        };
        // The existing baseline never hides debt from the entry list: the
        // ratchet needs the full picture to know what is still real.
        fixture.baseline.insert(baseline_entry(
            "divergence",
            "src/api/routes.ts",
            "../db/pool",
        ));

        let debt = entries(&fixture);
        assert_eq!(debt.len(), 1);
        assert_eq!(
            debt["api"],
            BTreeSet::from([baseline_entry(
                "divergence",
                "src/api/routes.ts",
                "../db/pool"
            )])
        );
    }

    fn cap_fact(api: &str, capability: CapabilityKind, line: u32, count: u32) -> CapabilityFact {
        CapabilityFact {
            capability,
            api: api.to_string(),
            line,
            count,
        }
    }

    #[test]
    fn cross_slice_import_breaches_isolation_and_x_notation_is_allowed() {
        let mut features = component("features", &["src/features/**"]);
        features.slices = true;
        let mut fixture = Fixture {
            contract: contract(vec![features]),
            component_of: assign(&[
                ("src/features/auth/login.ts", "features"),
                ("src/features/cart/model.ts", "features"),
                ("src/features/cart/@x/auth.ts", "features"),
            ]),
            dependencies: vec![
                edge(
                    "src/features/auth/login.ts",
                    "src/features/cart/model.ts",
                    "../cart/model",
                    3,
                ),
                edge(
                    "src/features/auth/login.ts",
                    "src/features/cart/@x/auth.ts",
                    "../cart/@x/auth",
                    4,
                ),
            ],
            ..Fixture::default()
        };
        fixture.slice_of = [
            ("src/features/auth/login.ts", "features/auth"),
            ("src/features/cart/model.ts", "features/cart"),
            ("src/features/cart/@x/auth.ts", "features/cart"),
        ]
        .iter()
        .map(|(f, s)| (f.to_string(), s.to_string()))
        .collect();

        let findings = run(&fixture);
        let slice: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_name.as_deref() == Some("architecture/slice-isolation"))
            .collect();
        assert_eq!(slice.len(), 1, "the @x import is exempt");
        assert_eq!(slice[0].severity, Severity::High);
        assert_eq!(slice[0].evidence[0].line, Some(3));
        assert!(slice[0].title.contains("features/auth -> features/cart"));
    }

    #[test]
    fn denied_capability_fires_from_a_fact_and_from_an_external_import() {
        let mut domain = component("domain", &["src/domain/**"]);
        domain.deny_capabilities = vec![CapabilityKind::Time, CapabilityKind::Network];
        let fixture = Fixture {
            contract: contract(vec![domain]),
            component_of: assign(&[
                ("src/domain/clock.ts", "domain"),
                ("src/domain/http.ts", "domain"),
            ]),
            dependencies: vec![external("src/domain/http.ts", "axios")],
            capability_uses: vec![(
                "src/domain/clock.ts".to_string(),
                cap_fact("Date.now", CapabilityKind::Time, 7, 2),
            )],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        let rules = rules_of(&findings);
        assert_eq!(
            rules
                .iter()
                .filter(|r| **r == "architecture/capability")
                .count(),
            2,
            "one per denied capability: time (fact) and network (axios import)"
        );
        let time = findings
            .iter()
            .find(|f| f.title.contains("'time'"))
            .expect("time capability");
        assert_eq!(time.severity, Severity::Medium);
        assert_eq!(
            time.evidence[0].detail.as_deref(),
            Some("Date.now (2 uses)")
        );
    }

    #[test]
    fn a_capability_the_component_does_not_deny_stays_silent() {
        let domain = component("domain", &["src/domain/**"]);
        let fixture = Fixture {
            contract: contract(vec![domain]),
            component_of: assign(&[("src/domain/clock.ts", "domain")]),
            capability_uses: vec![(
                "src/domain/clock.ts".to_string(),
                cap_fact("Date.now", CapabilityKind::Time, 7, 1),
            )],
            ..Fixture::default()
        };
        assert!(run(&fixture).is_empty(), "no denial declared");
    }

    #[test]
    fn a_function_over_budget_reports_the_worst_metric() {
        let mut core = component("core", &["src/core/**"]);
        core.max_cyclomatic = Some(5);
        core.max_cognitive = Some(8);
        let fixture = Fixture {
            contract: contract(vec![core]),
            component_of: assign(&[("src/core/logic.ts", "core")]),
            functions: vec![
                FunctionMetricsRow {
                    file_path: "src/core/logic.ts".to_string(),
                    qualified_name: "tangle".to_string(),
                    line: 12,
                    cyclomatic: 9,
                    cognitive: 4,
                },
                FunctionMetricsRow {
                    file_path: "src/core/logic.ts".to_string(),
                    qualified_name: "simple".to_string(),
                    line: 40,
                    cyclomatic: 2,
                    cognitive: 3,
                },
            ],
            ..Fixture::default()
        };

        let findings = run(&fixture);
        let budget = findings
            .iter()
            .find(|f| f.rule_name.as_deref() == Some("architecture/complexity-budget"))
            .expect("budget finding");
        assert_eq!(budget.severity, Severity::Medium);
        assert!(budget.title.contains("cyclomatic"));
        assert_eq!(budget.evidence.len(), 1, "only tangle exceeds cyclomatic");
        assert_eq!(
            budget.evidence[0].detail.as_deref(),
            Some("cyclomatic 9 > 5")
        );
    }

    #[test]
    fn off_silences_everything_and_warn_caps_severity() {
        let fixture = Fixture {
            contract: contract(vec![
                component("api", &["src/api/**"]),
                component("db", &["src/db/**"]),
            ]),
            component_of: assign(&[("src/api/routes.ts", "api"), ("src/db/pool.ts", "db")]),
            files: vec![],
            baseline: BTreeSet::new(),
            dependencies: vec![edge("src/api/routes.ts", "src/db/pool.ts", "../db/pool", 4)],
            ..Fixture::default()
        };

        let mut off = fixture;
        off.contract.mode = EnforcementMode::Off;
        assert!(run(&off).is_empty());

        off.contract.mode = EnforcementMode::Warn;
        let warned = run(&off);
        assert_eq!(rules_of(&warned), vec!["architecture/divergence"]);
        assert_eq!(warned[0].severity, Severity::Low, "warn never gates");
    }
}
