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
use ovecc_core::coverage::CoverageTotals;
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

/// (component, required target) -> the component's files that reach neither.
type FileMap<'a> = BTreeMap<(&'a str, &'a str), Vec<&'a str>>;

/// (component, metric name) -> (function row, its budget).
type BudgetMap<'a> = BTreeMap<(&'a str, &'a str), Vec<(&'a FunctionMetricsRow, u32)>>;

/// (component, component), ordered, -> the coupled file pairs linking them.
type CouplingMap<'a> = BTreeMap<(&'a str, &'a str), Vec<&'a CoChangedPair>>;

/// component -> (its measured coverage, the floor it declared). Only components
/// under their floor are entered.
type CoverageMap<'a> = BTreeMap<&'a str, (CoverageTotals, f64)>;

/// Coupled file pairs two components must share before the deviation is
/// reported. One pair is an accident: a single shared constant, one commit that
/// happened to touch both sides. The published precision on this family of
/// finding sits between 40 and 66%, so the filter that costs the least recall
/// for the most precision is worth its price.
const MIN_COUPLED_FILE_PAIRS: usize = 2;

#[derive(Default)]
struct EdgeGroups<'a> {
    divergences: PairMap<'a>,
    /// Imports of a component whose `consumed_by` does not admit the importer.
    restricted: PairMap<'a>,
    /// Imports the source component's `cannot_depend_on` names outright.
    forbidden: PairMap<'a>,
    /// Files under a `must_depend_on` that import the target nowhere.
    required: FileMap<'a>,
    bypasses: PairMap<'a>,
    deprecated: PairMap<'a>,
    banned: PairMap<'a>,
    /// Cross-slice imports inside a `slices = true` component, keyed by the
    /// qualified slice pair (`features/auth` -> `features/cart`).
    slices: PairMap<'a>,
    capabilities: CapabilityMap<'a>,
    budgets: BudgetMap<'a>,
    coupling: CouplingMap<'a>,
    coverage: CoverageMap<'a>,
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
    if let Some(severity) = contract.coupling.severity() {
        findings.extend(coupling_findings(input, &groups, severity));
    }
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
    let sections: [(&str, &PairMap<'_>); 7] = [
        ("divergence", &groups.divergences),
        ("restricted-access", &groups.restricted),
        ("forbidden-dependency", &groups.forbidden),
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
    for (&(component, target), files) in &groups.required {
        for file in files {
            entries
                .entry(component.to_string())
                .or_default()
                .insert(baseline_entry("required-dependency", file, target));
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
    // Owned by the first component of the ordered pair, so the entry lands in
    // one file whichever side the reader looks from.
    for (&(component, _), pairs) in &groups.coupling {
        for pair in pairs {
            entries
                .entry(component.to_string())
                .or_default()
                .insert(baseline_entry(
                    "behavioral-coupling",
                    &pair.left,
                    &pair.right,
                ));
        }
    }
    entries
}

fn prune_baselined<'a>(groups: EdgeGroups<'a>, baseline: &BTreeSet<String>) -> EdgeGroups<'a> {
    EdgeGroups {
        divergences: without_baselined(groups.divergences, "divergence", baseline),
        restricted: without_baselined(groups.restricted, "restricted-access", baseline),
        forbidden: without_baselined(groups.forbidden, "forbidden-dependency", baseline),
        required: groups
            .required
            .into_iter()
            .filter_map(|(pair, files)| {
                let kept: Vec<&str> = files
                    .into_iter()
                    .filter(|file| {
                        !baseline.contains(&baseline_entry("required-dependency", file, pair.1))
                    })
                    .collect();
                (!kept.is_empty()).then_some((pair, kept))
            })
            .collect(),
        bypasses: without_baselined(groups.bypasses, "interface-bypass", baseline),
        deprecated: without_baselined(groups.deprecated, "deprecated-use", baseline),
        banned: without_baselined(groups.banned, "external-deny", baseline),
        slices: without_baselined(groups.slices, "slice-isolation", baseline),
        // Accepted one coupled file pair at a time, and the pair count filter
        // is not re-applied afterwards: it asks whether the coupling is real,
        // and a baselined pair is the answer that it is. So a team that has
        // read today's coupling and chosen to live with it still hears about
        // the next file that joins it.
        coupling: groups
            .coupling
            .into_iter()
            .filter_map(|(components, pairs)| {
                let kept: Vec<&CoChangedPair> = pairs
                    .into_iter()
                    .filter(|pair| {
                        !baseline.contains(&baseline_entry(
                            "behavioral-coupling",
                            &pair.left,
                            &pair.right,
                        ))
                    })
                    .collect();
                (!kept.is_empty()).then_some((components, kept))
            })
            .collect(),
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
        // Not baselineable, unlike everything above. A coverage floor is one
        // aggregate per component, so accepting it once accepts the whole
        // condition — which is what deleting the declaration already does.
        coverage: groups.coverage,
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
    classify_required(input, architecture, &mut groups);
    classify_capability_facts(architecture, &mut groups);
    classify_budgets(architecture, &mut groups);
    classify_coverage(architecture, &mut groups);
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
    if architecture.contract.coupling.severity().is_none() {
        return;
    }
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

/// Components whose measured line coverage sits under the floor they declared.
///
/// A component the tracefile does not mention at all is skipped rather than
/// reported at 0%: the tracefile may predate the component, cover another
/// language, or not have been produced at all, so what is known is that the
/// component is unmeasured, not that it is untested.
fn classify_coverage<'a>(architecture: ContractInput<'a>, groups: &mut EdgeGroups<'a>) {
    let floors: BTreeMap<&'a str, f64> = architecture
        .contract
        .components
        .iter()
        .filter_map(|spec| Some((spec.name.as_str(), spec.min_coverage?)))
        .collect();
    let mut measured: BTreeMap<&'a str, CoverageTotals> = BTreeMap::new();
    for file in architecture.coverage {
        let Some(component) = architecture.component_of.get(&file.path) else {
            continue;
        };
        if let Some((&name, _)) = floors.get_key_value(component.as_str()) {
            measured.entry(name).or_default().add(file);
        }
    }
    for (name, totals) in measured {
        if totals.lines_found > 0 && totals.line_rate() < floors[name] {
            groups.coverage.insert(name, (totals, floors[name]));
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

    // The two prohibitions come first and answer alone. Each one refines what
    // would otherwise be a divergence into a sharper verdict — the contract
    // forbids either form from overlapping a declared dependency — so an edge
    // still carries exactly one, and reporting the interface alongside a
    // prohibited import would only bury it.
    if architecture
        .contract
        .component(pair.1)
        .and_then(|spec| spec.consumed_by.as_deref())
        .is_some_and(|allowed| !allowed.iter().any(|name| name == pair.0))
    {
        groups.restricted.entry(pair).or_default().push(dependency);
        return;
    }
    let Some(spec) = architecture.contract.component(pair.0) else {
        return;
    };
    if spec.cannot_depend_on.iter().any(|name| name == pair.1) {
        groups.forbidden.entry(pair).or_default().push(dependency);
        return;
    }

    // The interface holds even for a declared dependency: the pair being
    // legal does not open the target's internals.
    if let Some(interface) = interfaces.get(pair.1)
        && !interface.contains(&target_path.replace('\\', "/"))
    {
        groups.bypasses.entry(pair).or_default().push(dependency);
    }

    match spec
        .depends_on
        .iter()
        .find(|entry| entry.component() == pair.1)
    {
        Some(entry) => {
            groups.observed.insert(pair);
            if entry.deprecated() {
                groups.deprecated.entry(pair).or_default().push(dependency);
            }
        }
        // A required dependency is permitted by being required: reporting the
        // very import the contract demands as undeclared would be absurd.
        None if spec.must_depend_on.iter().any(|name| name == pair.1) => {
            groups.observed.insert(pair);
        }
        None => groups.divergences.entry(pair).or_default().push(dependency),
    }
}

/// Files of a `must_depend_on` component that import the required target
/// nowhere.
///
/// Judged per file rather than per component, because the component-level
/// question — does anything here reach the target — is what `depends_on` plus
/// the absence verdict already answer. "Every route handler must depend on
/// auth" is a claim about each handler.
///
/// Only files that import something are judged. A file with no imports at all
/// is a leaf — constants, types, a stylesheet the indexer happened to claim —
/// and holding it to a mandatory dependency would turn the check into a
/// guess about which files are "real" code.
fn classify_required<'a>(
    input: &RuleInput<'a>,
    architecture: ContractInput<'a>,
    groups: &mut EdgeGroups<'a>,
) {
    let required: BTreeMap<&'a str, &'a [String]> = architecture
        .contract
        .components
        .iter()
        .filter(|spec| !spec.must_depend_on.is_empty())
        .map(|spec| (spec.name.as_str(), spec.must_depend_on.as_slice()))
        .collect();
    if required.is_empty() {
        return;
    }
    let mut importers: BTreeMap<&'a str, BTreeSet<&'a str>> = BTreeMap::new();
    for dependency in input.dependencies {
        let reached = importers
            .entry(dependency.source_file_path.as_str())
            .or_default();
        if let Some(target_path) = &dependency.target_file_path
            && let Some(component) = architecture.component_of.get(target_path)
        {
            reached.insert(component.as_str());
        }
    }
    for (file, component) in architecture.component_of {
        let Some((&component, targets)) = required.get_key_value(component.as_str()) else {
            continue;
        };
        let Some(reached) = importers.get(file.as_str()) else {
            continue;
        };
        for target in *targets {
            if !reached.contains(target.as_str()) {
                groups
                    .required
                    .entry((component, target.as_str()))
                    .or_default()
                    .push(file.as_str());
            }
        }
    }
}

/// One finding per component pair, every coupled file pair as evidence with the
/// commits that witnessed it. Low by design: the deviation is a question for the
/// reader, not a verdict, and a hard gate on a signal this uncertain would be
/// dishonest.
fn coupling_findings(
    input: &RuleInput<'_>,
    groups: &EdgeGroups<'_>,
    severity: Severity,
) -> Vec<FindingRecord> {
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
            severity,
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
    for (&(source, target), edges) in &groups.restricted {
        let allowed = input
            .architecture
            .and_then(|architecture| architecture.contract.component(target))
            .and_then(|spec| spec.consumed_by.clone())
            .unwrap_or_default();
        findings.push(pair_finding(
            input,
            "restricted-access",
            Severity::High,
            (source, target),
            format!("{source} imports {target}, which is closed to it"),
            format!(
                "'{source}' imports '{target}' ({} occurrence(s)), but the contract \
                 says '{target}' is consumed by {}. Reach it through {}, or open \
                 '{target}' to '{source}' deliberately.",
                edges.len(),
                if allowed.is_empty() {
                    "nothing".to_string()
                } else {
                    quoted(&allowed)
                },
                if allowed.is_empty() {
                    "another component".to_string()
                } else {
                    quoted(&allowed)
                }
            ),
            edges,
        ));
    }
    for (&(source, target), edges) in &groups.forbidden {
        findings.push(pair_finding(
            input,
            "forbidden-dependency",
            Severity::High,
            (source, target),
            format!("{source} -> {target} is forbidden by the contract"),
            format!(
                "'{source}' imports '{target}' ({} occurrence(s)), which its \
                 cannot_depend_on forbids outright. This is not an undeclared \
                 dependency: someone wrote down that it must not exist.",
                edges.len()
            ),
            edges,
        ));
    }
    for (&(source, target), files) in &groups.required {
        findings.push(FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "architecture",
                "required-dependency",
                source,
                target,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::ArchitectureViolation,
            severity: Severity::High,
            rule_name: Some("architecture/required-dependency".to_string()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: source.to_string(),
            }),
            title: format!(
                "{} file(s) of {source} never reach the required {target}",
                files.len()
            ),
            description: format!(
                "The contract requires every file of '{source}' to depend on \
                 '{target}', and {} file(s) import it nowhere. Add the \
                 dependency, or drop '{target}' from '{source}'.must_depend_on.",
                files.len()
            ),
            evidence: files
                .iter()
                .take(10)
                .map(|file| Evidence {
                    file_path: (*file).to_string(),
                    line: None,
                    symbol: None,
                    detail: Some(format!("no import of '{target}'")),
                })
                .collect(),
            created_at: Utc::now(),
        });
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
    for (&component, (totals, floor)) in &groups.coverage {
        findings.push(FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "architecture",
                "coverage-floor",
                component,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::ArchitectureViolation,
            severity: Severity::Medium,
            rule_name: Some("architecture/coverage-floor".to_string()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: component.to_string(),
            }),
            title: format!(
                "{component}: line coverage {:.0}% is under the declared {:.0}%",
                totals.line_rate() * 100.0,
                floor * 100.0
            ),
            description: format!(
                "'{component}' declares min_coverage = {floor}, and {} of its \
                 {} executable line(s) are not reached by any test. Cover them, \
                 or lower the floor deliberately.",
                totals.lines_missed(),
                totals.lines_found
            ),
            // The component is the subject; naming one of its files would
            // point at an arbitrary member of the set.
            evidence: Vec::new(),
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

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ")
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
    use ovecc_core::architecture::{ComponentSpec, CouplingPolicy, DependsOn};
    use ovecc_core::config::RulesConfig;
    use ovecc_core::coverage::FileCoverage;
    use ovecc_core::facts::CapabilityFact;

    fn component(name: &str, paths: &[&str]) -> ComponentSpec {
        ComponentSpec {
            name: name.to_string(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            ..ComponentSpec::default()
        }
    }

    fn contract(components: Vec<ComponentSpec>) -> ArchitectureContract {
        ArchitectureContract {
            unassigned: UnassignedPolicy::Ignore,
            components,
            ..ArchitectureContract::default()
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
        coverage: Vec<FileCoverage>,
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
                coverage: Vec::new(),
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
                coverage: &fixture.coverage,
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
                coverage: &fixture.coverage,
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

    /// Two components the contract keeps apart, coupled by two file pairs: the
    /// smallest history that clears the pair-count filter.
    fn coupled_fixture() -> Fixture {
        Fixture {
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
        }
    }

    /// The signal no static analysis can produce: two components with nothing
    /// between them in the code, that the history keeps editing together.
    #[test]
    fn components_that_change_together_without_depending_on_each_other_are_flagged() {
        let fixture = coupled_fixture();
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
        let mut fixture = coupled_fixture();
        fixture.dependencies = vec![edge(
            "src/billing/rates.ts",
            "src/shipping/zones.ts",
            "../shipping/zones",
            3,
        )];
        assert_eq!(rules_of(&run(&fixture)), vec!["architecture/divergence"]);
    }

    /// A declared dependency is the contract saying "these two belong together":
    /// the history agreeing with it is not a deviation.
    #[test]
    fn a_declared_dependency_explains_the_coupling() {
        let mut fixture = coupled_fixture();
        fixture.contract.components[0].depends_on = vec![DependsOn::Name("shipping".to_string())];
        assert!(
            rules_of(&run(&fixture))
                .iter()
                .all(|rule| *rule != "architecture/behavioral-coupling"),
            "{:?}",
            rules_of(&run(&fixture))
        );
    }

    /// `check --freeze` writes the coupling into the same store as the rest of
    /// the debt, one line per coupled file pair.
    #[test]
    fn coupling_joins_the_frozen_debt() {
        assert_eq!(
            entries(&coupled_fixture()).get("billing"),
            Some(&BTreeSet::from([
                baseline_entry(
                    "behavioral-coupling",
                    "src/billing/invoice.ts",
                    "src/shipping/label.ts"
                ),
                baseline_entry(
                    "behavioral-coupling",
                    "src/billing/rates.ts",
                    "src/shipping/zones.ts"
                ),
            ]))
        );
    }

    /// Accepted one pair at a time. The two pairs the team read and kept go
    /// quiet; the third still speaks, even though one pair alone would never
    /// have raised the finding — the baseline already answered that the
    /// coupling is real.
    #[test]
    fn a_baselined_pair_leaves_the_rest_of_the_coupling_visible() {
        let mut fixture = coupled_fixture();
        fixture
            .component_of
            .insert("src/billing/tax.ts".to_string(), "billing".to_string());
        fixture.component_of.insert(
            "src/shipping/carrier.ts".to_string(),
            "shipping".to_string(),
        );
        fixture
            .co_changes
            .push(coupled("src/billing/tax.ts", "src/shipping/carrier.ts"));
        for (left, right) in [
            ("src/billing/rates.ts", "src/shipping/zones.ts"),
            ("src/billing/invoice.ts", "src/shipping/label.ts"),
        ] {
            fixture
                .baseline
                .insert(baseline_entry("behavioral-coupling", left, right));
        }

        let findings = run(&fixture);
        assert_eq!(
            rules_of(&findings),
            vec!["architecture/behavioral-coupling"]
        );
        assert_eq!(findings[0].evidence.len(), 1, "only the pair nobody read");
        assert_eq!(findings[0].evidence[0].file_path, "src/billing/tax.ts");

        fixture.baseline.insert(baseline_entry(
            "behavioral-coupling",
            "src/billing/tax.ts",
            "src/shipping/carrier.ts",
        ));
        assert!(run(&fixture).is_empty(), "the whole coupling is accepted");
    }

    /// Low keeps the family under every gate's default threshold; a team that
    /// has checked a few and found them right raises it, one that has not
    /// turns it off.
    #[test]
    fn the_contract_sets_the_coupling_severity() {
        let mut fixture = coupled_fixture();
        fixture.contract.coupling = CouplingPolicy::High;
        assert_eq!(run(&fixture)[0].severity, Severity::High);

        fixture.contract.coupling = CouplingPolicy::Off;
        assert!(run(&fixture).is_empty());
        assert!(
            entries(&fixture).is_empty(),
            "nor is there anything to freeze"
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

    fn covered(path: &str, found: usize, hit: usize) -> FileCoverage {
        FileCoverage {
            path: path.to_string(),
            lines_found: found,
            lines_hit: hit,
            functions_found: 0,
            functions_hit: 0,
        }
    }

    fn coverage_floor_findings(coverage: Vec<FileCoverage>) -> Vec<FindingRecord> {
        let mut core = component("core", &["src/core/**"]);
        core.min_coverage = Some(0.8);
        let fixture = Fixture {
            contract: contract(vec![core]),
            component_of: assign(&[("src/core/logic.ts", "core"), ("src/core/util.ts", "core")]),
            coverage,
            ..Fixture::default()
        };
        run(&fixture)
            .into_iter()
            .filter(|f| f.rule_name.as_deref() == Some("architecture/coverage-floor"))
            .collect()
    }

    #[test]
    fn a_component_under_its_declared_coverage_is_a_verdict() {
        // 30 of 50 lines reached: 60%, under the declared 80%.
        let findings = coverage_floor_findings(vec![
            covered("src/core/logic.ts", 40, 30),
            covered("src/core/util.ts", 10, 0),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("60%"), "{}", findings[0].title);
        assert!(
            findings[0].description.contains("20 of"),
            "{}",
            findings[0].description
        );
    }

    #[test]
    fn a_component_at_or_over_its_floor_is_silent() {
        assert!(coverage_floor_findings(vec![covered("src/core/logic.ts", 10, 8)]).is_empty());
    }

    #[test]
    fn an_unmeasured_component_is_not_reported_as_untested() {
        // No tracefile at all, and a tracefile that covers other files only:
        // both leave the component unmeasured.
        assert!(coverage_floor_findings(Vec::new()).is_empty());
        assert!(coverage_floor_findings(vec![covered("src/web/page.ts", 10, 0)]).is_empty());
    }

    /// `api -> db` with `db` closed to everyone but `repository`: the rule the
    /// allow-list cannot state, because removing `db` from every other
    /// component's `depends_on` is an edit to every other component.
    fn restricted_fixture() -> Fixture {
        let mut db = component("db", &["src/db/**"]);
        db.consumed_by = Some(vec!["repository".to_string()]);
        Fixture {
            contract: contract(vec![
                component("api", &["src/api/**"]),
                component("repository", &["src/repository/**"]),
                db,
            ]),
            component_of: assign(&[
                ("src/api/routes.ts", "api"),
                ("src/repository/users.ts", "repository"),
                ("src/db/pool.ts", "db"),
            ]),
            dependencies: vec![edge("src/api/routes.ts", "src/db/pool.ts", "../db/pool", 4)],
            ..Fixture::default()
        }
    }

    #[test]
    fn an_import_the_target_does_not_admit_is_restricted_not_diverging() {
        let findings = run(&restricted_fixture());
        assert_eq!(
            rules_of(&findings),
            vec!["architecture/restricted-access"],
            "one verdict per edge: the sharper one, never both"
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert!(
            findings[0].description.contains("'repository'"),
            "the description names who may reach it: {}",
            findings[0].description
        );
        assert_eq!(findings[0].evidence[0].file_path, "src/api/routes.ts");
        assert_eq!(findings[0].evidence[0].line, Some(4));
    }

    #[test]
    fn a_component_its_target_admits_is_silent() {
        let mut fixture = restricted_fixture();
        fixture.dependencies = vec![edge(
            "src/repository/users.ts",
            "src/db/pool.ts",
            "../db/pool",
            2,
        )];
        // `repository` is admitted by `db` but declares no depends_on, so the
        // edge falls through to the ordinary allow-list verdict.
        assert_eq!(rules_of(&run(&fixture)), vec!["architecture/divergence"]);

        fixture.contract.components[1].depends_on = vec![DependsOn::Name("db".to_string())];
        assert!(run(&fixture).is_empty(), "admitted and declared: legal");
    }

    /// The strangler-fig rule: `consumed_by = []` says nothing may import the
    /// component, without naming a single consumer.
    #[test]
    fn an_empty_consumed_by_closes_a_component_to_everyone() {
        let mut legacy = component("legacy", &["src/legacy/**"]);
        legacy.consumed_by = Some(Vec::new());
        let fixture = Fixture {
            contract: contract(vec![component("api", &["src/api/**"]), legacy]),
            component_of: assign(&[
                ("src/api/routes.ts", "api"),
                ("src/legacy/store.ts", "legacy"),
            ]),
            dependencies: vec![edge(
                "src/api/routes.ts",
                "src/legacy/store.ts",
                "../legacy/store",
                7,
            )],
            ..Fixture::default()
        };
        let findings = run(&fixture);
        assert_eq!(rules_of(&findings), vec!["architecture/restricted-access"]);
        assert!(
            findings[0].description.contains("consumed by nothing"),
            "{}",
            findings[0].description
        );
    }

    #[test]
    fn a_forbidden_dependency_reads_as_forbidden_rather_than_undeclared() {
        let mut api = component("api", &["src/api/**"]);
        api.cannot_depend_on = vec!["legacy".to_string()];
        let fixture = Fixture {
            contract: contract(vec![api, component("legacy", &["src/legacy/**"])]),
            component_of: assign(&[
                ("src/api/routes.ts", "api"),
                ("src/legacy/store.ts", "legacy"),
            ]),
            dependencies: vec![edge(
                "src/api/routes.ts",
                "src/legacy/store.ts",
                "../legacy/store",
                9,
            )],
            ..Fixture::default()
        };
        let findings = run(&fixture);
        assert_eq!(
            rules_of(&findings),
            vec!["architecture/forbidden-dependency"]
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].evidence[0].line, Some(9));
    }

    /// Two handlers, one of which never imports `auth`. Judged per file: the
    /// component-level question is what `depends_on` and absence already
    /// answer.
    fn required_fixture() -> Fixture {
        let mut api = component("api", &["src/api/**"]);
        api.must_depend_on = vec!["auth".to_string()];
        api.depends_on = vec![DependsOn::Name("util".to_string())];
        Fixture {
            contract: contract(vec![
                api,
                component("auth", &["src/auth/**"]),
                component("util", &["src/util/**"]),
            ]),
            component_of: assign(&[
                ("src/api/orders.ts", "api"),
                ("src/api/prices.ts", "api"),
                ("src/auth/guard.ts", "auth"),
                ("src/util/log.ts", "util"),
            ]),
            dependencies: vec![
                edge("src/api/orders.ts", "src/auth/guard.ts", "../auth/guard", 1),
                edge("src/api/prices.ts", "src/util/log.ts", "../util/log", 1),
            ],
            ..Fixture::default()
        }
    }

    #[test]
    fn a_file_that_never_reaches_a_required_component_is_reported() {
        let findings = run(&required_fixture());
        let required: Vec<&FindingRecord> = findings
            .iter()
            .filter(|finding| {
                finding.rule_name.as_deref() == Some("architecture/required-dependency")
            })
            .collect();
        assert_eq!(required.len(), 1, "one finding per (component, target)");
        assert_eq!(required[0].severity, Severity::High);
        assert_eq!(
            required[0]
                .evidence
                .iter()
                .map(|item| item.file_path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/api/prices.ts"],
            "only the file missing the dependency"
        );
    }

    #[test]
    fn a_required_dependency_is_permitted_by_being_required() {
        let findings = run(&required_fixture());
        assert!(
            !rules_of(&findings).contains(&"architecture/divergence"),
            "the import must_depend_on demands is never also undeclared: {:?}",
            rules_of(&findings)
        );
        assert!(
            !rules_of(&findings).contains(&"architecture/absence"),
            "must_depend_on is not a depends_on entry to go stale"
        );
    }

    /// A file that imports nothing is a leaf — constants, types, a stylesheet
    /// the indexer claimed. Holding it to a mandatory dependency would make the
    /// check a guess about which files are real code.
    #[test]
    fn a_file_with_no_imports_at_all_is_not_held_to_a_required_dependency() {
        let mut fixture = required_fixture();
        fixture.dependencies.remove(1);
        let findings = run(&fixture);
        assert!(
            !rules_of(&findings).contains(&"architecture/required-dependency"),
            "{:?}",
            rules_of(&findings)
        );
    }

    #[test]
    fn every_new_form_freezes_and_the_baseline_silences_it() {
        for mut fixture in [restricted_fixture(), required_fixture(), {
            let mut api = component("api", &["src/api/**"]);
            api.cannot_depend_on = vec!["legacy".to_string()];
            Fixture {
                contract: contract(vec![api, component("legacy", &["src/legacy/**"])]),
                component_of: assign(&[
                    ("src/api/routes.ts", "api"),
                    ("src/legacy/store.ts", "legacy"),
                ]),
                dependencies: vec![edge(
                    "src/api/routes.ts",
                    "src/legacy/store.ts",
                    "../legacy/store",
                    9,
                )],
                ..Fixture::default()
            }
        }] {
            let frozen = entries(&fixture);
            assert!(!frozen.is_empty(), "the violation must be freezable");
            fixture.baseline = frozen.values().flatten().cloned().collect();
            let after = run(&fixture);
            assert!(
                !rules_of(&after).iter().any(|rule| {
                    matches!(
                        *rule,
                        "architecture/restricted-access"
                            | "architecture/forbidden-dependency"
                            | "architecture/required-dependency"
                    )
                }),
                "accepted debt must stop being reported: {:?}",
                rules_of(&after)
            );
        }
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
