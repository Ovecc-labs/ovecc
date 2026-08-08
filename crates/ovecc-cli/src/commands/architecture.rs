//! `ovecc architecture` — the contract loop. `init` bootstraps
//! `.ovecc/architecture.toml` from the observed graph, where every declared
//! edge mirrors a real import so day one has zero violations. `diff` reports
//! the reflexion verdicts (convergences, divergences, absences) between the
//! contract and the stored graph; `check` renders the same report and turns
//! it into an exit code for CI. Both re-read the contract file on every run,
//! so editing the contract never requires re-indexing.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use ovecc_core::architecture::{
    ArchitectureContract, EnforcementMode, assign_components, assign_slices, baseline_dir,
    load_baseline, recognize, save_baseline,
};
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::coverage::FileCoverage;
use ovecc_core::error::OveccError;
use ovecc_core::facts::FindingRecord;
use ovecc_core::facts::{CapabilityFact, CoChangedPair, FunctionMetricsRow};
use ovecc_core::legacy::DependencyRecord;
use ovecc_db::FileGraphRow;
use ovecc_rules::ContractInput;
use serde::Serialize;

use crate::cli::FailOn;
use crate::commands::findings::findings_exit;
use crate::commands::open_store;
use crate::render::{
    emit_json, emit_ndjson_meta, format_evidence, meta_for, ndjson_line, severity_tag,
};

/// The reflexion report `diff` and `check` share: every declared edge with its
/// observed occurrence count (0 = absence), plus the contract findings.
#[derive(Debug, Serialize)]
pub(crate) struct ArchitectureReport {
    pub(crate) mode: &'static str,
    pub(crate) components: usize,
    pub(crate) declared: Vec<DeclaredEdge>,
    /// Declared edges at least one import implements (the convergences).
    pub(crate) implemented: usize,
    /// Entries in the baseline store — accepted debt hidden from the
    /// findings in `new-violations` mode.
    pub(crate) baselined: usize,
    pub(crate) findings: Vec<FindingRecord>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeclaredEdge {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) occurrences: usize,
    pub(crate) deprecated: bool,
}

/// Human names for the finding groups, in report order: violations first,
/// contract hygiene last.
const VERDICTS: &[(&str, &str)] = &[
    ("architecture/divergence", "Divergences"),
    (
        "architecture/forbidden-dependency",
        "Forbidden dependencies",
    ),
    (
        "architecture/restricted-access",
        "Imports of a component closed to them",
    ),
    (
        "architecture/required-dependency",
        "Required dependencies missing",
    ),
    ("architecture/slice-isolation", "Slice isolation breaches"),
    ("architecture/interface-bypass", "Interface bypasses"),
    (
        "architecture/deprecated-use",
        "Deprecated dependencies still used",
    ),
    ("architecture/external-deny", "Banned external packages"),
    ("architecture/capability", "Denied capabilities used"),
    (
        "architecture/complexity-budget",
        "Complexity budgets exceeded",
    ),
    ("architecture/coverage-floor", "Coverage floors missed"),
    ("architecture/unassigned", "Files outside every component"),
    (
        "architecture/absence",
        "Absences (declared, never implemented)",
    ),
    (
        "architecture/behavioral-coupling",
        "Components that change together without depending on each other",
    ),
];

/// Everything `diff` and `check` need, loaded once: the contract plus the
/// stored graph it is judged against.
struct ArchitectureData {
    repository_id: String,
    contract: ArchitectureContract,
    files: Vec<String>,
    dependencies: Vec<DependencyRecord>,
    component_of: BTreeMap<String, String>,
    slice_of: BTreeMap<String, String>,
    capability_uses: Vec<(String, CapabilityFact)>,
    functions: Vec<FunctionMetricsRow>,
    co_changes: Vec<CoChangedPair>,
    coverage: Vec<FileCoverage>,
}

impl ArchitectureData {
    fn input<'a>(&'a self, baseline: &'a BTreeSet<String>) -> ContractInput<'a> {
        ContractInput {
            contract: &self.contract,
            component_of: &self.component_of,
            files: &self.files,
            baseline,
            slice_of: &self.slice_of,
            capability_uses: &self.capability_uses,
            functions: &self.functions,
            co_changes: &self.co_changes,
            coverage: &self.coverage,
        }
    }
}

fn load_architecture_data(paths: &ProjectPaths) -> Result<ArchitectureData> {
    let contract = ArchitectureContract::load(&paths.root)?.ok_or_else(|| OveccError::Usage {
        message: "no .ovecc/architecture.toml — run `ovecc architecture init` to draft one \
                  from the observed graph"
            .to_string(),
    })?;
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let files: Vec<String> = store
        .current_files(&repository_id)?
        .into_iter()
        .map(|file| file.path)
        .collect();
    let dependencies = store.current_dependencies(&repository_id)?;
    let component_of = assign_components(&contract, &files)?;
    let slice_of = assign_slices(&contract, &component_of);
    // Only load what a contract asks for: a capability/budget query on every
    // check would be wasted work for the common contract that declares
    // neither.
    let wants_capabilities = contract
        .components
        .iter()
        .any(|component| !component.deny_capabilities.is_empty());
    let wants_budgets = contract
        .components
        .iter()
        .any(|component| component.max_cyclomatic.is_some() || component.max_cognitive.is_some());
    let capability_uses = if wants_capabilities {
        store.current_capability_uses(&repository_id)?
    } else {
        Vec::new()
    };
    let functions = if wants_budgets {
        store.current_function_metrics(&repository_id)?
    } else {
        Vec::new()
    };
    let coverage = if contract
        .components
        .iter()
        .any(|component| component.min_coverage.is_some())
    {
        store.file_coverage(&repository_id)?
    } else {
        Vec::new()
    };
    // Read from the table the last index wrote: `check` judges the stored
    // graph, and the history behind it is just as stored.
    let co_changes = store.co_changes(&repository_id, 0.0)?;
    Ok(ArchitectureData {
        repository_id,
        contract,
        files,
        dependencies,
        component_of,
        slice_of,
        capability_uses,
        functions,
        co_changes,
        coverage,
    })
}

fn build_report(data: &ArchitectureData, baseline: &BTreeSet<String>) -> ArchitectureReport {
    let findings = ovecc_rules::contract_findings(
        &data.repository_id,
        &data.dependencies,
        data.input(baseline),
    );
    let declared = declared_edges(&data.contract, &data.component_of, &data.dependencies);
    let implemented = declared.iter().filter(|edge| edge.occurrences > 0).count();
    ArchitectureReport {
        mode: mode_label(data.contract.mode),
        components: data.contract.components.len(),
        declared,
        implemented,
        baselined: baseline.len(),
        findings,
    }
}

pub(crate) fn run_architecture_diff(paths: &ProjectPaths, format: OutputFormat) -> Result<u8> {
    let data = load_architecture_data(paths)?;
    let baseline = load_baseline(&paths.root)?;
    render_architecture_report(&build_report(&data, &baseline), format)?;
    Ok(0)
}

/// The CI side of the contract: `--freeze` accepts the whole present debt
/// into the baseline store; otherwise the ratchet drops corrected entries
/// from the store (it only ever shrinks), and the remaining findings decide
/// the exit code. Store messages go to stderr so stdout stays parseable.
pub(crate) fn run_architecture_check(
    paths: &ProjectPaths,
    format: OutputFormat,
    fail_on: FailOn,
    freeze: bool,
) -> Result<u8> {
    let data = load_architecture_data(paths)?;
    let empty = BTreeSet::new();
    let debt = ovecc_rules::contract_entries(&data.dependencies, data.input(&empty));
    let stored = load_baseline(&paths.root)?;
    if freeze {
        save_baseline(&paths.root, &debt)?;
        let frozen: usize = debt.values().map(BTreeSet::len).sum();
        eprintln!(
            "Froze {frozen} violation(s) into {}",
            baseline_dir(&paths.root).display()
        );
    } else if !stored.is_empty() {
        let kept = ratchet(&debt, &stored);
        let kept_count: usize = kept.values().map(BTreeSet::len).sum();
        if kept_count != stored.len() {
            save_baseline(&paths.root, &kept)?;
            eprintln!(
                "Ratchet: {} corrected violation(s) left the baseline",
                stored.len() - kept_count
            );
        }
    }
    let baseline = load_baseline(&paths.root)?;
    let report = build_report(&data, &baseline);
    render_architecture_report(&report, format)?;
    Ok(findings_exit(&report.findings, Some(fail_on)))
}

/// The stored entries still matching a present violation, regrouped by the
/// component that owns them today. Corrected entries drop out; new debt is
/// never added — the baseline only shrinks.
fn ratchet(
    debt: &BTreeMap<String, BTreeSet<String>>,
    stored: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    debt.iter()
        .map(|(component, lines)| {
            (
                component.clone(),
                lines
                    .iter()
                    .filter(|line| stored.contains(*line))
                    .cloned()
                    .collect::<BTreeSet<String>>(),
            )
        })
        .filter(|(_, lines)| !lines.is_empty())
        .collect()
}

fn mode_label(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Off => "off",
        EnforcementMode::Warn => "warn",
        EnforcementMode::NewViolations => "new-violations",
        EnforcementMode::Strict => "strict",
    }
}

/// Every declared pair with its observed occurrence count. Pure presentation:
/// the verdicts come from `contract_findings`, this only counts imports.
fn declared_edges(
    contract: &ArchitectureContract,
    component_of: &BTreeMap<String, String>,
    dependencies: &[DependencyRecord],
) -> Vec<DeclaredEdge> {
    let mut counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for dependency in dependencies {
        let Some(target_path) = &dependency.target_file_path else {
            continue;
        };
        let source = component_of.get(&dependency.source_file_path);
        let target = component_of.get(target_path);
        if let (Some(source), Some(target)) = (source, target)
            && source != target
        {
            *counts.entry((source, target)).or_default() += 1;
        }
    }
    contract
        .components
        .iter()
        .flat_map(|component| {
            component.depends_on.iter().map(|entry| DeclaredEdge {
                source: component.name.clone(),
                target: entry.component().to_string(),
                occurrences: counts
                    .get(&(component.name.as_str(), entry.component()))
                    .copied()
                    .unwrap_or(0),
                deprecated: entry.deprecated(),
            })
        })
        .collect()
}

pub(crate) fn render_architecture_report(
    report: &ArchitectureReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("architecture", report, meta_for("architecture"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("architecture", &meta_for("architecture"))?;
            for edge in &report.declared {
                println!("{}", ndjson_line("declared", edge)?);
            }
            for finding in &report.findings {
                println!("{}", ndjson_line("finding", finding)?);
            }
        }
        OutputFormat::Markdown => architecture_markdown(report),
        OutputFormat::Text => architecture_text(report),
    }
    Ok(())
}

fn verdict_groups(findings: &[FindingRecord]) -> Vec<(&'static str, Vec<&FindingRecord>)> {
    VERDICTS
        .iter()
        .map(|(rule, label)| {
            let group: Vec<&FindingRecord> = findings
                .iter()
                .filter(|finding| finding.rule_name.as_deref() == Some(*rule))
                .collect();
            (*label, group)
        })
        .filter(|(_, group)| !group.is_empty())
        .collect()
}

fn architecture_text(report: &ArchitectureReport) {
    println!(
        "Architecture contract: {} components, {}/{} declared dependencies implemented, mode {}{}",
        report.components,
        report.implemented,
        report.declared.len(),
        report.mode,
        baselined_note(report)
    );
    for (label, group) in verdict_groups(&report.findings) {
        println!();
        println!("{label} ({}):", group.len());
        for finding in group {
            anstream::println!("  {} {}", severity_tag(finding.severity), finding.title);
            for evidence in &finding.evidence {
                println!("    {}", format_evidence(evidence));
            }
        }
    }
    println!();
    if report.findings.is_empty() {
        println!("The code matches the contract.");
    } else {
        println!("{} finding(s).", report.findings.len());
    }
    let converging: Vec<&DeclaredEdge> = report
        .declared
        .iter()
        .filter(|edge| edge.occurrences > 0)
        .collect();
    if !converging.is_empty() {
        println!();
        println!("Convergences:");
        for edge in converging {
            let mark = if edge.deprecated { " (deprecated)" } else { "" };
            println!(
                "  {} -> {} ({} import(s)){mark}",
                edge.source, edge.target, edge.occurrences
            );
        }
    }
}

/// `, N baselined` when accepted debt exists, empty otherwise.
fn baselined_note(report: &ArchitectureReport) -> String {
    if report.baselined == 0 {
        String::new()
    } else {
        format!(", {} baselined", report.baselined)
    }
}

fn architecture_markdown(report: &ArchitectureReport) {
    println!("# Architecture contract");
    println!();
    println!(
        "{} components, {}/{} declared dependencies implemented, mode `{}`{}.",
        report.components,
        report.implemented,
        report.declared.len(),
        report.mode,
        baselined_note(report)
    );
    for (label, group) in verdict_groups(&report.findings) {
        println!();
        println!("## {label} ({})", group.len());
        println!();
        for finding in group {
            println!("- **{:?}** {}", finding.severity, finding.title);
            for evidence in &finding.evidence {
                println!("  - `{}`", format_evidence(evidence));
            }
        }
    }
    println!();
    if report.findings.is_empty() {
        println!("The code matches the contract.");
    }
    println!();
    println!("## Declared dependencies");
    println!();
    println!("| From | To | Imports | |");
    println!("|------|----|---------|-|");
    for edge in &report.declared {
        let note = match (edge.occurrences, edge.deprecated) {
            (0, _) => "absence",
            (_, true) => "deprecated",
            _ => "",
        };
        println!(
            "| {} | {} | {} | {note} |",
            edge.source, edge.target, edge.occurrences
        );
    }
}

/// The pre-edit question answered from the contract alone, no index needed:
/// which components own these paths, what may they import (and through which
/// interface files), what must they not. Without paths, the whole contract.
#[derive(Debug, Serialize)]
pub(crate) struct ContractView {
    pub(crate) mode: &'static str,
    pub(crate) components: Vec<ComponentView>,
    /// Queried paths no component claims.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) unassigned: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ComponentView {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) may_import: Vec<AllowedImport>,
    /// Components this one must never import.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) must_not_import: Vec<String>,
    /// Components every file of this one must import.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) must_import: Vec<String>,
    /// The only components allowed to import this one. `Some([])` closes it to
    /// everyone; `None` leaves it open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) importable_by: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) interface: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) external_deny: Vec<String>,
    /// Slice isolation is on (imports between sibling slices are forbidden).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) slices: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) deny_capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_cyclomatic: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_cognitive: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) min_coverage: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AllowedImport {
    pub(crate) component: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) deprecated: bool,
    /// The target's interface files — when non-empty, the only legal doors.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) via: Vec<String>,
}

pub(crate) fn run_architecture_show(
    paths: &ProjectPaths,
    format: OutputFormat,
    query: &[String],
) -> Result<u8> {
    let contract = ArchitectureContract::load(&paths.root)?.ok_or_else(|| OveccError::Usage {
        message: "no .ovecc/architecture.toml — run `ovecc architecture init` to draft one \
                  from the observed graph"
            .to_string(),
    })?;
    let view = contract_view(&contract, query)?;
    match format {
        OutputFormat::Text => show_text(&view),
        OutputFormat::Markdown => show_markdown(&view),
        _ => emit_json("architecture", &view, meta_for("architecture show"))?,
    }
    Ok(0)
}

fn contract_view(contract: &ArchitectureContract, query: &[String]) -> Result<ContractView> {
    let normalized: Vec<String> = query.iter().map(|path| path.replace('\\', "/")).collect();
    let mut unassigned = Vec::new();
    let selected: BTreeSet<&str> = if normalized.is_empty() {
        contract
            .components
            .iter()
            .map(|component| component.name.as_str())
            .collect()
    } else {
        let assignment = assign_components(contract, &normalized)?;
        for path in &normalized {
            if !assignment.contains_key(path) {
                unassigned.push(path.clone());
            }
        }
        contract
            .components
            .iter()
            .filter(|component| {
                assignment
                    .values()
                    .any(|component_name| *component_name == component.name)
            })
            .map(|component| component.name.as_str())
            .collect()
    };
    let components = contract
        .components
        .iter()
        .filter(|component| selected.contains(component.name.as_str()))
        .map(|component| ComponentView {
            name: component.name.clone(),
            role: component.role.clone(),
            paths: component.paths.clone(),
            may_import: component
                .depends_on
                .iter()
                .map(|entry| AllowedImport {
                    component: entry.component().to_string(),
                    deprecated: entry.deprecated(),
                    via: contract
                        .component(entry.component())
                        .map(|target| target.interface.clone())
                        .unwrap_or_default(),
                })
                .collect(),
            must_not_import: component.cannot_depend_on.clone(),
            must_import: component.must_depend_on.clone(),
            importable_by: component.consumed_by.clone(),
            interface: component.interface.clone(),
            external_deny: component.external_deny.clone(),
            slices: component.slices,
            deny_capabilities: component
                .deny_capabilities
                .iter()
                .map(|capability| capability.as_str().to_string())
                .collect(),
            max_cyclomatic: component.max_cyclomatic,
            max_cognitive: component.max_cognitive,
            min_coverage: component.min_coverage,
        })
        .collect();
    Ok(ContractView {
        mode: mode_label(contract.mode),
        components,
        unassigned,
    })
}

/// How a `show` renderer marks up the two kinds of name it prints. Plain text
/// marks neither; Markdown bolds component names and quotes literals.
#[derive(Clone, Copy)]
struct Style {
    names: &'static str,
    literals: &'static str,
}

const PLAIN: Style = Style {
    names: "",
    literals: "",
};

const MARKED: Style = Style {
    names: "**",
    literals: "`",
};

fn marked(items: &[String], mark: &str) -> String {
    items
        .iter()
        .map(|item| format!("{mark}{item}{mark}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every clause of a component's contract beyond its allow-list, as
/// `(label, value)`. One list for both renderers, so a form added to the
/// contract cannot land in one output and be forgotten in the other.
fn component_clauses(component: &ComponentView, style: Style) -> Vec<(&'static str, String)> {
    let mut clauses = Vec::new();
    if !component.must_import.is_empty() {
        clauses.push((
            "must import (every file)",
            marked(&component.must_import, style.names),
        ));
    }
    if !component.must_not_import.is_empty() {
        clauses.push((
            "must not import",
            marked(&component.must_not_import, style.names),
        ));
    }
    if let Some(consumers) = &component.importable_by {
        // An empty list is the whole point of the form: it must read as a
        // rule, not as a missing value.
        let value = if consumers.is_empty() {
            "nothing (no component may import it)".to_string()
        } else {
            format!("{} only", marked(consumers, style.names))
        };
        clauses.push(("importable by", value));
    }
    if !component.interface.is_empty() {
        clauses.push(("interface", marked(&component.interface, style.literals)));
    }
    if !component.external_deny.is_empty() {
        clauses.push((
            "external deny",
            marked(&component.external_deny, style.literals),
        ));
    }
    if component.slices {
        clauses.push((
            "slices",
            "isolated (no imports between sibling slices)".to_string(),
        ));
    }
    if !component.deny_capabilities.is_empty() {
        clauses.push((
            "deny capabilities",
            marked(&component.deny_capabilities, style.literals),
        ));
    }
    if let Some(budget) = budget_line(component) {
        clauses.push(("budget", budget));
    }
    clauses
}

/// Each declared dependency as `target (via interface) (deprecated)`.
fn allowed_imports(component: &ComponentView, style: Style) -> Vec<String> {
    component
        .may_import
        .iter()
        .map(|entry| {
            let mut text = format!("{0}{1}{0}", style.names, entry.component);
            if !entry.via.is_empty() {
                text.push_str(&format!(" (via {})", marked(&entry.via, style.literals)));
            }
            if entry.deprecated {
                text.push_str(" (deprecated)");
            }
            text
        })
        .collect()
}

fn show_text(view: &ContractView) {
    println!(
        "Contract mode {}, {} component(s):",
        view.mode,
        view.components.len()
    );
    for component in &view.components {
        println!();
        let role = component
            .role
            .as_deref()
            .map(|role| format!(" [{role}]"))
            .unwrap_or_default();
        println!("{}{role} ({})", component.name, component.paths.join(", "));
        let allowed = allowed_imports(component, PLAIN);
        if allowed.is_empty() {
            println!("  may import: nothing (no depends_on declared)");
        } else {
            println!("  may import: {}", allowed.join(", "));
        }
        for (label, value) in component_clauses(component, PLAIN) {
            println!("  {label}: {value}");
        }
    }
    if !view.unassigned.is_empty() {
        println!();
        println!(
            "{} path(s) match no component: {}",
            view.unassigned.len(),
            view.unassigned.join(", ")
        );
    }
}

fn show_markdown(view: &ContractView) {
    println!("# Architecture contract (mode `{}`)", view.mode);
    for component in &view.components {
        println!();
        println!("## {}", component.name);
        println!();
        if let Some(role) = &component.role {
            println!("- role: {role}");
        }
        println!("- paths: `{}`", component.paths.join("`, `"));
        for entry in allowed_imports(component, MARKED) {
            println!("- may import {entry}");
        }
        for (label, value) in component_clauses(component, MARKED) {
            println!("- {label}: {value}");
        }
    }
    if !view.unassigned.is_empty() {
        println!();
        println!(
            "{} path(s) match no component: `{}`",
            view.unassigned.len(),
            view.unassigned.join("`, `")
        );
    }
}

/// Human-readable per-function budget line for `show`, or `None` when the
/// component sets neither ceiling.
fn budget_line(component: &ComponentView) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(value) = component.max_cyclomatic {
        parts.push(format!("cyclomatic <= {value}"));
    }
    if let Some(value) = component.max_cognitive {
        parts.push(format!("cognitive <= {value}"));
    }
    if let Some(value) = component.min_coverage {
        parts.push(format!("coverage >= {:.0}%", value * 100.0));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// A built-in architecture template: a complete contract distilled from an
/// ecosystem's own published canon, shipped inside the binary. Unlike the
/// drafted contract, a template is the target, not a mirror: applying one is
/// expected to start with divergences, and that gap is the migration plan.
pub(crate) struct ArchitectureTemplate {
    pub name: &'static str,
    pub summary: &'static str,
    pub stacks: &'static str,
    pub source: &'static str,
    pub contents: &'static str,
}

pub(crate) const TEMPLATES: &[ArchitectureTemplate] = &[
    ArchitectureTemplate {
        name: "fsd",
        summary: "Feature-Sliced Design: six layers importing strictly downward \
                  (app > pages > widgets > features > entities > shared)",
        stacks: "JavaScript/TypeScript frontends",
        source: "https://feature-sliced.design",
        contents: include_str!("../../templates/fsd.toml"),
    },
    ArchitectureTemplate {
        name: "bulletproof-react",
        summary: "bulletproof-react: a unidirectional codebase, imports flow \
                  shared > features > app and features never import each other",
        stacks: "React / JavaScript / TypeScript apps",
        source: "https://github.com/alan2207/bulletproof-react",
        contents: include_str!("../../templates/bulletproof-react.toml"),
    },
    ArchitectureTemplate {
        name: "nx-workspace",
        summary: "Nx module boundaries by library type: \
                  app > feature > (ui, data-access) > util",
        stacks: "Nx monorepos (JavaScript/TypeScript)",
        source: "https://nx.dev",
        contents: include_str!("../../templates/nx-workspace.toml"),
    },
    ArchitectureTemplate {
        name: "clean-architecture",
        summary: "Clean/Hexagonal: dependencies point inward to a pure domain \
                  (presentation > application > domain, infrastructure implements the ports)",
        stacks: "TypeScript backends and libraries",
        source: "https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html",
        contents: include_str!("../../templates/clean-architecture.toml"),
    },
];

fn find_template(name: &str) -> Result<&'static ArchitectureTemplate> {
    TEMPLATES
        .iter()
        .find(|template| template.name == name)
        .ok_or_else(|| {
            let known: Vec<&str> = TEMPLATES.iter().map(|template| template.name).collect();
            OveccError::Usage {
                message: format!(
                    "unknown template \"{name}\" — available: {}",
                    known.join(", ")
                ),
            }
            .into()
        })
}

#[derive(Debug, Serialize)]
struct TemplateView {
    name: &'static str,
    summary: &'static str,
    stacks: &'static str,
    source: &'static str,
}

#[derive(Debug, Serialize)]
struct TemplateList {
    templates: Vec<TemplateView>,
}

pub(crate) fn run_architecture_templates(format: OutputFormat) -> Result<u8> {
    let views: Vec<TemplateView> = TEMPLATES
        .iter()
        .map(|template| TemplateView {
            name: template.name,
            summary: template.summary,
            stacks: template.stacks,
            source: template.source,
        })
        .collect();
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => emit_json(
            "architecture",
            &TemplateList { templates: views },
            meta_for("architecture"),
        )?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("architecture", &meta_for("architecture"))?;
            for view in &views {
                println!("{}", ndjson_line("template", view)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Architecture templates");
            for view in &views {
                println!();
                println!("## {}", view.name);
                println!();
                println!("- {} ({})", view.summary, view.stacks);
                println!("- Source: {}", view.source);
            }
            println!();
            println!(
                "Apply one with `ovecc architecture init --template <name>` (no index required)."
            );
        }
        OutputFormat::Text => {
            for view in &views {
                println!("{}  {} ({})", view.name, view.summary, view.stacks);
                println!("     source: {}", view.source);
            }
            println!();
            println!("Apply one: ovecc architecture init --template <name> (no index required).");
        }
    }
    Ok(0)
}

/// Below this fit, `suggest` calls it no match rather than pushing a template
/// the code does not really follow. Coverage x conformance: e.g. 0.7 coverage
/// at 0.71 conformance clears it, a half-matched or divergent repo does not.
const SUGGEST_THRESHOLD: f64 = 0.5;

#[derive(Debug, Serialize)]
struct Suggestion {
    template: &'static str,
    summary: &'static str,
    source: &'static str,
    score: f64,
    root: String,
    coverage: f64,
    conformance: f64,
    matched_components: usize,
    assigned_files: usize,
    source_files: usize,
    divergent_edges: usize,
    internal_edges: usize,
}

#[derive(Debug, Serialize)]
struct SuggestReport {
    /// The best template above the recognition threshold, if any.
    best: Option<String>,
    threshold: f64,
    suggestions: Vec<Suggestion>,
}

pub(crate) fn run_architecture_suggest(paths: &ProjectPaths, format: OutputFormat) -> Result<u8> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let files: Vec<String> = store
        .current_files(&repository_id)?
        .into_iter()
        .map(|file| file.path)
        .collect();
    if files.is_empty() {
        return Err(OveccError::Usage {
            message: "no indexed files — run `ovecc index .` before `architecture suggest`"
                .to_string(),
        }
        .into());
    }
    let internal_edges: Vec<(String, String)> = store
        .current_dependencies(&repository_id)?
        .into_iter()
        .filter(|dependency| !dependency.is_external)
        .filter_map(|dependency| {
            dependency
                .target_file_path
                .map(|target| (dependency.source_file_path, target))
        })
        .collect();

    let mut suggestions: Vec<Suggestion> = TEMPLATES
        .iter()
        .filter_map(|template| {
            let contract = ArchitectureContract::parse(template.contents).ok()?;
            let fit = recognize(&contract, &files, &internal_edges)?;
            Some(Suggestion {
                template: template.name,
                summary: template.summary,
                source: template.source,
                score: fit.score(),
                root: fit.root,
                coverage: fit.coverage,
                conformance: fit.conformance,
                matched_components: fit.matched_components,
                assigned_files: fit.assigned_files,
                source_files: fit.source_files,
                divergent_edges: fit.internal_edges - fit.allowed_edges,
                internal_edges: fit.internal_edges,
            })
        })
        .collect();
    // Highest fit first; a stable name tiebreak keeps the order deterministic.
    suggestions.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.template.cmp(b.template))
    });

    let best = suggestions
        .first()
        .filter(|suggestion| suggestion.score >= SUGGEST_THRESHOLD)
        .map(|suggestion| suggestion.template.to_string());
    let report = SuggestReport {
        best,
        threshold: SUGGEST_THRESHOLD,
        suggestions,
    };
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("architecture", &report, meta_for("architecture suggest"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("architecture", &meta_for("architecture suggest"))?;
            for suggestion in &report.suggestions {
                println!("{}", ndjson_line("suggestion", suggestion)?);
            }
        }
        OutputFormat::Markdown => suggest_markdown(&report),
        OutputFormat::Text => suggest_text(&report),
    }
    Ok(0)
}

fn pct(value: f64) -> String {
    format!("{:.0}%", value * 100.0)
}

fn root_label(root: &str) -> String {
    if root.is_empty() {
        "repository root".to_string()
    } else {
        root.to_string()
    }
}

fn suggest_text(report: &SuggestReport) {
    match &report.best {
        Some(name) => {
            let best = report
                .suggestions
                .iter()
                .find(|suggestion| suggestion.template == name)
                .expect("best is one of the suggestions");
            println!("Best match: {} (fit {:.2})", best.template, best.score);
            println!("  {}", best.summary);
            println!("  root: {}", root_label(&best.root));
            println!(
                "  coverage: {} ({}/{} source files, {} components)",
                pct(best.coverage),
                best.assigned_files,
                best.source_files,
                best.matched_components
            );
            println!(
                "  conformance: {} ({} divergent edge(s) of {})",
                pct(best.conformance),
                best.divergent_edges,
                best.internal_edges
            );
            println!(
                "  apply: ovecc architecture init --template {}",
                best.template
            );
        }
        None => {
            println!(
                "No template fits above {} — this repository does not clearly follow \
                 a built-in architecture.",
                pct(report.threshold)
            );
        }
    }
    let others: Vec<&Suggestion> = report
        .suggestions
        .iter()
        .filter(|suggestion| report.best.as_deref() != Some(suggestion.template))
        .collect();
    if !others.is_empty() {
        println!();
        println!("Other candidates:");
        for suggestion in others {
            println!(
                "  {:<20} fit {:.2}  (root {}, {} of {} edges allowed)",
                suggestion.template,
                suggestion.score,
                root_label(&suggestion.root),
                suggestion.internal_edges - suggestion.divergent_edges,
                suggestion.internal_edges
            );
        }
    }
}

fn suggest_markdown(report: &SuggestReport) {
    println!("# Architecture suggestion");
    println!();
    match &report.best {
        Some(name) => {
            let best = report
                .suggestions
                .iter()
                .find(|suggestion| suggestion.template == name)
                .expect("best is one of the suggestions");
            println!(
                "**Best match: `{}`** (fit {:.2})",
                best.template, best.score
            );
            println!();
            println!("- {}", best.summary);
            println!("- root: `{}`", root_label(&best.root));
            println!(
                "- coverage: {} ({}/{} source files, {} components)",
                pct(best.coverage),
                best.assigned_files,
                best.source_files,
                best.matched_components
            );
            println!(
                "- conformance: {} ({} divergent of {} edges)",
                pct(best.conformance),
                best.divergent_edges,
                best.internal_edges
            );
            println!(
                "- apply: `ovecc architecture init --template {}`",
                best.template
            );
        }
        None => println!(
            "No template fits above {}: this repository does not clearly follow a \
             built-in architecture.",
            pct(report.threshold)
        ),
    }
    println!();
    println!("| Template | Fit | Root | Coverage | Conformance |");
    println!("|----------|-----|------|----------|-------------|");
    for suggestion in &report.suggestions {
        println!(
            "| {} | {:.2} | {} | {} | {} |",
            suggestion.template,
            suggestion.score,
            root_label(&suggestion.root),
            pct(suggestion.coverage),
            pct(suggestion.conformance)
        );
    }
}

pub(crate) fn run_architecture_init(
    paths: &ProjectPaths,
    force: bool,
    template: Option<&str>,
) -> Result<u8> {
    let contract_path = paths.ovecc_dir.join("architecture.toml");
    if contract_path.exists() && !force {
        return Err(OveccError::Usage {
            message: format!(
                "{} already exists — pass --force to regenerate it from the current graph",
                contract_path.display()
            ),
        }
        .into());
    }
    // A template needs no index: the contract-first workflow starts on an
    // empty repository, and the code grows into the declared shape.
    if let Some(name) = template {
        let template = find_template(name)?;
        std::fs::create_dir_all(&paths.ovecc_dir)?;
        std::fs::write(&contract_path, template.contents)?;
        crate::commands::index::wire_gitignore(&paths.root)?;
        println!(
            "Wrote {} from template \"{}\" ({}).",
            contract_path.display(),
            template.name,
            template.stacks
        );
        println!();
        println!("A template is the target, not a mirror of today's code:");
        println!("  1. Rebind each component's paths if your layers live elsewhere.");
        println!("  2. `ovecc architecture diff` reports the gap — that is the migration plan.");
        println!("  3. Keep mode = \"warn\" while migrating; freeze and tighten once it settles.");
        return Ok(0);
    }
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let files = store.current_files(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    if files.is_empty() {
        return Err(OveccError::Usage {
            message: "the index has no files — run `ovecc index` first".to_string(),
        }
        .into());
    }
    let components = draft_components(&files, &dependencies);
    let declared: usize = components
        .iter()
        .map(|component| component.depends_on.len())
        .sum();
    std::fs::write(&contract_path, draft_toml(&components))?;
    // The contract is shared team state: make sure a blanket `.ovecc/`
    // ignore from an earlier version does not keep it out of git.
    crate::commands::index::wire_gitignore(&paths.root)?;
    println!(
        "Wrote {} ({} components, {} declared dependencies).",
        contract_path.display(),
        components.len(),
        declared
    );
    println!();
    println!("Every depends_on entry mirrors an import that exists today, so the");
    println!("contract starts with zero violations. To govern:");
    println!("  1. Delete the entries you regret — each deletion becomes a divergence.");
    println!("  2. Uncomment an interface line to close a component's internals.");
    println!("  3. Run `ovecc architecture diff`, then wire `check` into CI.");
    Ok(0)
}

struct DraftComponent {
    name: String,
    glob: String,
    depends_on: Vec<String>,
    /// `(file, incoming to that file, incoming total)` when one file already
    /// concentrates the component's incoming imports — the de facto interface.
    interface_hint: Option<(String, usize, usize)>,
}

fn draft_components(
    files: &[FileGraphRow],
    dependencies: &[DependencyRecord],
) -> Vec<DraftComponent> {
    let mut module_files: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut file_module: BTreeMap<&str, &str> = BTreeMap::new();
    for file in files {
        module_files
            .entry(file.module.as_str())
            .or_default()
            .push(file.path.as_str());
        file_module.insert(file.path.as_str(), file.module.as_str());
    }

    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut incoming: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    for dependency in dependencies {
        let Some(target_path) = &dependency.target_file_path else {
            continue;
        };
        let source = file_module.get(dependency.source_file_path.as_str());
        let target = file_module.get(target_path.as_str());
        let (Some(&source), Some(&target)) = (source, target) else {
            continue;
        };
        if source == target {
            continue;
        }
        edges.entry(source).or_default().insert(target);
        *incoming
            .entry(target)
            .or_default()
            .entry(target_path.as_str())
            .or_default() += 1;
    }

    module_files
        .into_iter()
        .map(|(module, paths)| DraftComponent {
            name: module.to_string(),
            glob: module_glob(&paths),
            depends_on: edges
                .get(module)
                .map(|targets| targets.iter().map(|target| target.to_string()).collect())
                .unwrap_or_default(),
            interface_hint: interface_hint(incoming.get(module), paths.len()),
        })
        .collect()
}

/// The narrowest glob covering every file of the module: its common directory
/// prefix plus `/**`, or `*` for files at the repository root.
fn module_glob(paths: &[&str]) -> String {
    let mut prefix: Option<Vec<&str>> = None;
    for path in paths {
        let dir: Vec<&str> = match path.rsplit_once('/') {
            Some((dir, _)) => dir.split('/').collect(),
            None => Vec::new(),
        };
        prefix = Some(match prefix {
            None => dir,
            Some(current) => {
                let shared = current.iter().zip(&dir).take_while(|(a, b)| a == b).count();
                current[..shared].to_vec()
            }
        });
    }
    match prefix {
        Some(parts) if !parts.is_empty() => format!("{}/**", parts.join("/")),
        _ => "*".to_string(),
    }
}

/// The de facto interface: one file receiving at least 80% of the component's
/// incoming imports, with enough traffic (3+) for the share to mean anything.
fn interface_hint(
    incoming: Option<&BTreeMap<&str, usize>>,
    file_count: usize,
) -> Option<(String, usize, usize)> {
    let incoming = incoming?;
    if file_count < 2 {
        return None;
    }
    let total: usize = incoming.values().sum();
    let (file, count) = incoming
        .iter()
        .max_by_key(|(file, count)| (**count, std::cmp::Reverse(*file)))?;
    (total >= 3 && count * 5 >= total * 4).then(|| (file.to_string(), *count, total))
}

fn draft_toml(components: &[DraftComponent]) -> String {
    let mut out = String::from(
        "# Architecture contract: the dependencies each component may have.\n\
         # Drafted by `ovecc architecture init` from the observed graph, so every\n\
         # depends_on entry mirrors an import that exists today and the contract\n\
         # starts with zero violations.\n\
         #\n\
         # Governance starts here: delete the entries you regret (each becomes a\n\
         # divergence), uncomment an interface to close a component's internals,\n\
         # then wire `ovecc architecture check` into CI.\n\n\
         schema = 1\n\n\
         # Enforcement: off | warn | new-violations | strict.\n\
         # warn reports everything at low severity and never gates.\n\
         mode = \"new-violations\"\n\n\
         # Files no component claims: ignore | warn | forbid.\n\
         unassigned = \"warn\"\n",
    );
    for component in components {
        out.push_str("\n[[component]]\n");
        out.push_str(&format!("name = \"{}\"\n", component.name));
        out.push_str(&format!("paths = [\"{}\"]\n", component.glob));
        if !component.depends_on.is_empty() {
            let quoted: Vec<String> = component
                .depends_on
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect();
            out.push_str(&format!("depends_on = [{}]\n", quoted.join(", ")));
        }
        if let Some((file, count, total)) = &component.interface_hint {
            out.push_str(&format!(
                "# Likely interface ({count} of {total} incoming imports); uncomment to enforce:\n\
                 # interface = [\"{file}\"]\n"
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, module: &str) -> FileGraphRow {
        FileGraphRow {
            path: path.to_string(),
            language: "typescript".to_string(),
            size_bytes: 1,
            module: module.to_string(),
        }
    }

    fn dependency(source: &str, target: &str) -> DependencyRecord {
        DependencyRecord {
            id: format!("dep:{source}:{target}"),
            repository_id: "repo:test".to_string(),
            source_file_id: "f".to_string(),
            target_file_id: Some("g".to_string()),
            source_file_path: source.to_string(),
            target_file_path: Some(target.to_string()),
            source_module_id: "m:src".to_string(),
            target_module_id: "m:tgt".to_string(),
            source_module: "src".to_string(),
            target_module: "tgt".to_string(),
            specifier: "spec".to_string(),
            dependency_kind: "static_import".to_string(),
            is_external: false,
            evidence_line: 1,
        }
    }

    #[test]
    fn draft_mirrors_observed_edges_only() {
        let files = vec![
            file("src/api/routes.ts", "api"),
            file("src/core/logic.ts", "core"),
            file("src/db/pool.ts", "db"),
        ];
        let dependencies = vec![dependency("src/api/routes.ts", "src/core/logic.ts")];
        let components = draft_components(&files, &dependencies);
        let api = components
            .iter()
            .find(|component| component.name == "api")
            .unwrap();
        assert_eq!(api.depends_on, vec!["core"]);
        assert_eq!(api.glob, "src/api/**");
        let db = components
            .iter()
            .find(|component| component.name == "db")
            .unwrap();
        assert!(db.depends_on.is_empty(), "no observed edge, none declared");
    }

    #[test]
    fn module_glob_narrows_to_the_common_directory() {
        assert_eq!(
            module_glob(&["src/api/a.ts", "src/api/sub/b.ts"]),
            "src/api/**"
        );
        assert_eq!(module_glob(&["src/api/a.ts", "src/core/b.ts"]), "src/**");
        assert_eq!(module_glob(&["a.ts", "b.ts"]), "*");
    }

    #[test]
    fn interface_hint_needs_a_dominant_file_with_traffic() {
        let mut incoming = BTreeMap::new();
        incoming.insert("src/core/index.ts", 4);
        incoming.insert("src/core/util.ts", 1);
        assert_eq!(
            interface_hint(Some(&incoming), 3),
            Some(("src/core/index.ts".to_string(), 4, 5))
        );

        let mut split = BTreeMap::new();
        split.insert("src/core/index.ts", 3);
        split.insert("src/core/util.ts", 3);
        assert_eq!(interface_hint(Some(&split), 3), None, "no 80% file");

        let mut quiet = BTreeMap::new();
        quiet.insert("src/core/index.ts", 2);
        assert_eq!(interface_hint(Some(&quiet), 3), None, "too little traffic");
    }

    #[test]
    fn ratchet_only_shrinks_and_regroups_by_current_component() {
        let mut debt: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        debt.entry("api".to_string())
            .or_default()
            .extend(["kept-entry".to_string(), "new-entry".to_string()]);
        let stored: BTreeSet<String> = ["kept-entry".to_string(), "corrected-entry".to_string()]
            .into_iter()
            .collect();

        let kept = ratchet(&debt, &stored);
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept["api"],
            BTreeSet::from(["kept-entry".to_string()]),
            "corrected entries drop out, new debt is never added"
        );
    }

    #[test]
    fn drafted_toml_parses_as_a_valid_contract() {
        let files = vec![
            file("src/api/routes.ts", "api"),
            file("src/core/logic.ts", "core"),
        ];
        let dependencies = vec![dependency("src/api/routes.ts", "src/core/logic.ts")];
        let toml_text = draft_toml(&draft_components(&files, &dependencies));
        let contract: ArchitectureContract = toml::from_str(&toml_text).unwrap();
        contract.validate().unwrap();
        assert_eq!(contract.components.len(), 2);
    }

    #[test]
    fn every_builtin_template_is_a_valid_contract_with_a_unique_name() {
        let mut names = BTreeSet::new();
        for template in TEMPLATES {
            let contract: ArchitectureContract = toml::from_str(template.contents)
                .unwrap_or_else(|error| panic!("template {}: {error}", template.name));
            contract
                .validate()
                .unwrap_or_else(|error| panic!("template {}: {error}", template.name));
            assert!(
                names.insert(template.name),
                "duplicate template name {}",
                template.name
            );
            assert!(
                contract
                    .components
                    .iter()
                    .all(|component| component.role.is_some()),
                "template {} must give every component a role — that is what \
                 makes it rebindable",
                template.name
            );
        }
    }

    #[test]
    fn every_template_declares_its_layers_top_down() {
        // A built-in template is a layered DAG: components are declared highest
        // layer first, so a legal dependency only ever names a component
        // declared lower down. That keeps `depends_on` acyclic by construction
        // and makes the file read like the layer diagram it encodes.
        for template in TEMPLATES {
            let contract: ArchitectureContract = toml::from_str(template.contents).unwrap();
            for (position, component) in contract.components.iter().enumerate() {
                let below: BTreeSet<&str> = contract.components[position + 1..]
                    .iter()
                    .map(|lower| lower.name.as_str())
                    .collect();
                for dependency in &component.depends_on {
                    assert!(
                        below.contains(dependency.component()),
                        "{}: {} must not depend on {} (declared at or above it)",
                        template.name,
                        component.name,
                        dependency.component()
                    );
                }
            }
            // The last-declared component is the sink: it depends on nothing.
            let sink = contract.components.last().unwrap();
            assert!(
                sink.depends_on.is_empty(),
                "{}: sink component {} must depend on nothing",
                template.name,
                sink.name
            );
        }
    }

    #[test]
    fn the_canon_ships_slice_isolation_and_a_pure_domain() {
        // The depth features are not just contract fields: they must be
        // exercised by the built-in canon, or a regression that stops parsing
        // them would pass every other test.
        let by_name = |name: &str| -> ArchitectureContract {
            let template = find_template(name).unwrap();
            toml::from_str(template.contents).unwrap()
        };

        let fsd = by_name("fsd");
        assert!(
            fsd.component("features").unwrap().slices,
            "FSD features must isolate their slices"
        );
        assert!(
            by_name("bulletproof-react")
                .component("features")
                .unwrap()
                .slices,
            "bulletproof features must isolate their slices"
        );

        let clean = by_name("clean-architecture");
        let domain = clean.component("domain").unwrap();
        assert_eq!(
            domain.deny_capabilities.len(),
            ovecc_core::facts::CapabilityKind::ALL.len(),
            "the clean-architecture domain denies every capability"
        );
        assert!(
            domain.max_cyclomatic.is_some(),
            "the domain carries a budget"
        );
    }
}
