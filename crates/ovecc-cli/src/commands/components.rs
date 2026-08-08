//! `components`: the subsystems ACDC recovers from the dependency graph, and
//! where they disagree with the directory layout that names ovecc's modules.
//!
//! The module heuristic reads structure off the folder tree. Clustering by
//! dominance answers the same question from the graph instead, and
//! `split_modules` names every directory module the graph pulls apart — where a
//! single module stands in for several independent subsystems.
//!
//! The two views are complementary, not ranked. Dominance groups everything
//! reachable through one entry point, so it sees a layered spine the folders
//! hide, and it misses a split the folders state plainly. Neither is the
//! ground truth; the disagreement is the reportable fact.

use super::diagnose::load_component_inputs;
use crate::render::{ndjson_line, render_report};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_graph::acdc::{self, AcdcConfig, Pattern};
use std::collections::{BTreeMap, BTreeSet};

/// One recovered subsystem, with the modules its files are spread across.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct SubsystemView {
    pub(crate) name: String,
    pub(crate) pattern: Pattern,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parent: Option<String>,
    pub(crate) children: Vec<String>,
    pub(crate) files: Vec<String>,
    /// The modules these files belong to. More than one means the subsystem
    /// crosses a directory boundary the module view treats as a wall.
    pub(crate) modules: Vec<String>,
    pub(crate) adopted: usize,
}

/// A module the recovered clustering pulls apart: one directory-derived module
/// standing in for several independent subsystems.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct SplitModule {
    pub(crate) module: String,
    pub(crate) subsystems: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ComponentsReport {
    pub(crate) subsystems: Vec<SubsystemView>,
    pub(crate) roots: Vec<String>,
    /// How many modules the directory heuristic named for the same files.
    pub(crate) modules: usize,
    pub(crate) skeleton_files: usize,
    pub(crate) adopted_files: usize,
    pub(crate) split_modules: Vec<SplitModule>,
}

pub(crate) fn load_components_report(
    paths: &ProjectPaths,
    config: &AcdcConfig,
    diagnose: &ovecc_graph::diagnose::DiagnoseConfig,
    target: Option<&str>,
) -> Result<ComponentsReport> {
    let (file_modules, file_deps) = load_component_inputs(paths)?;
    // The same precision-first exclusions `diagnose` applies, so the two
    // component views answer for one set of files rather than two.
    let keep = |path: &str| !ovecc_graph::diagnose::is_excluded(path, &diagnose.exclude);
    let file_modules: Vec<(String, String)> = file_modules
        .into_iter()
        .filter(|(path, _)| keep(path))
        .collect();
    let file_deps: Vec<ovecc_graph::diagnose::FileDep> = file_deps
        .into_iter()
        .filter(|dep| keep(&dep.source) && keep(&dep.target))
        .collect();
    let files: Vec<String> = file_modules.iter().map(|(path, _)| path.clone()).collect();
    let module_of: BTreeMap<String, String> = file_modules.into_iter().collect();

    let clustering = acdc::cluster(&files, &file_deps, config);
    let subsystems: Vec<SubsystemView> = clustering
        .subsystems
        .iter()
        .map(|subsystem| SubsystemView {
            name: subsystem.name.clone(),
            pattern: subsystem.pattern,
            parent: subsystem.parent.clone(),
            children: subsystem.children.clone(),
            modules: modules_spanned(&subsystem.files, &module_of),
            files: subsystem.files.clone(),
            adopted: subsystem.adopted,
        })
        .collect();
    let split_modules = split_modules(&clustering, &module_of);
    let modules: BTreeSet<&String> = module_of.values().collect();

    let report = ComponentsReport {
        roots: clustering.roots.clone(),
        modules: modules.len(),
        skeleton_files: clustering.skeleton_files,
        adopted_files: clustering.adopted_files,
        split_modules,
        subsystems,
    };
    Ok(scope(report, target))
}

fn modules_spanned(files: &[String], module_of: &BTreeMap<String, String>) -> Vec<String> {
    files
        .iter()
        .filter_map(|file| module_of.get(file).cloned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// Every module whose files the clustering assigns to more than one subsystem.
fn split_modules(
    clustering: &acdc::Clustering,
    module_of: &BTreeMap<String, String>,
) -> Vec<SplitModule> {
    let mut by_module = BTreeMap::<String, BTreeSet<String>>::new();
    for subsystem in &clustering.subsystems {
        for file in &subsystem.files {
            if let Some(module) = module_of.get(file) {
                by_module
                    .entry(module.clone())
                    .or_default()
                    .insert(subsystem.name.clone());
            }
        }
    }
    by_module
        .into_iter()
        .filter(|(_, subsystems)| subsystems.len() > 1)
        .map(|(module, subsystems)| SplitModule {
            module,
            subsystems: subsystems.into_iter().collect(),
        })
        .collect()
}

/// Narrows the report to the subsystems whose name, files, or modules mention
/// `target`. Counts stay whole-repository so the scoped view still says what it
/// is a slice of.
fn scope(mut report: ComponentsReport, target: Option<&str>) -> ComponentsReport {
    let Some(needle) = target.map(|t| t.replace('\\', "/").to_ascii_lowercase()) else {
        return report;
    };
    let matches = |text: &str| text.to_ascii_lowercase().contains(&needle);
    report.subsystems.retain(|subsystem| {
        matches(&subsystem.name)
            || subsystem.files.iter().any(|file| matches(file))
            || subsystem.modules.iter().any(|module| matches(module))
    });
    let kept: BTreeSet<&String> = report.subsystems.iter().map(|s| &s.name).collect();
    report.roots.retain(|name| kept.contains(name));
    report
        .split_modules
        .retain(|split| split.subsystems.iter().any(|name| kept.contains(name)));
    report
}

pub(crate) fn render_components(report: &ComponentsReport, format: OutputFormat) -> Result<()> {
    render_report(
        "components",
        report,
        format,
        || {
            for subsystem in &report.subsystems {
                println!("{}", ndjson_line("subsystem", subsystem)?);
            }
            for split in &report.split_modules {
                println!("{}", ndjson_line("split_module", split)?);
            }
            Ok(())
        },
        || components_markdown(report),
        || components_text(report),
    )
}

fn pattern_label(pattern: Pattern) -> &'static str {
    match pattern {
        Pattern::SubgraphDominator => "subgraph dominator",
        Pattern::SupportLibrary => "support library",
        Pattern::Directory => "directory",
    }
}

/// `4 files, 1 adopted, modules: a, b` — the one-line shape both renderers use.
fn subsystem_detail(subsystem: &SubsystemView) -> String {
    let mut detail = format!("{} file(s)", subsystem.files.len());
    if subsystem.adopted > 0 {
        detail.push_str(&format!(", {} adopted", subsystem.adopted));
    }
    if !subsystem.modules.is_empty() {
        detail.push_str(&format!(", modules: {}", subsystem.modules.join(", ")));
    }
    detail
}

fn components_text(report: &ComponentsReport) {
    println!(
        "Components: {} subsystem(s) recovered, {} module(s) named by directory",
        report.subsystems.len(),
        report.modules
    );
    println!(
        "  {} file(s) claimed by a pattern, {} adopted",
        report.skeleton_files, report.adopted_files
    );
    if !report.split_modules.is_empty() {
        println!();
        println!(
            "Modules the layout collapses ({}):",
            report.split_modules.len()
        );
        for split in &report.split_modules {
            println!(
                "  {} -> {} subsystems: {}",
                split.module,
                split.subsystems.len(),
                split.subsystems.join(", ")
            );
        }
    }
    for subsystem in &report.subsystems {
        println!();
        println!(
            "{}  [{}]  {}",
            subsystem.name,
            pattern_label(subsystem.pattern),
            subsystem_detail(subsystem)
        );
        if let Some(parent) = &subsystem.parent {
            println!("  inside: {parent}");
        }
        if !subsystem.children.is_empty() {
            println!("  contains: {}", subsystem.children.join(", "));
        }
    }
    if report.subsystems.is_empty() {
        println!("  (nothing to cluster)");
    }
}

fn components_markdown(report: &ComponentsReport) {
    println!("# Components ({} subsystems)", report.subsystems.len());
    println!();
    println!(
        "{} module(s) named by directory · {} file(s) claimed by a pattern · {} adopted",
        report.modules, report.skeleton_files, report.adopted_files
    );
    if !report.split_modules.is_empty() {
        println!();
        println!("## Modules the layout collapses");
        println!();
        println!("| Module | Subsystems |");
        println!("| --- | --- |");
        for split in &report.split_modules {
            println!("| `{}` | {} |", split.module, split.subsystems.len());
        }
    }
    println!();
    println!("| Subsystem | Pattern | Detail |");
    println!("| --- | --- | --- |");
    for subsystem in &report.subsystems {
        println!(
            "| `{}` | {} | {} |",
            subsystem.name,
            pattern_label(subsystem.pattern),
            subsystem_detail(subsystem)
        );
    }
}
