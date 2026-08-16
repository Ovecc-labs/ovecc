//! `ovecc summary` and `ovecc hotspots`: the repository-level overview.

use super::open_store;
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_header, ndjson_line, risk_tag};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::coverage::CoverageTotals;
use ovecc_core::facts::FindingKind;
use ovecc_core::legacy::{HotspotsReport, SummaryReport};
use ovecc_db::ArchitectureStore;
use ovecc_graph as graph;

pub(crate) fn load_hotspots(paths: &ProjectPaths, limit: usize) -> Result<HotspotsReport> {
    let store = open_store(paths)?;
    hotspots_with(&store, &paths.repository_id().0, limit)
}

/// The same ranking over a store the caller already holds: DuckDB permits one
/// connection per file per process, so a command that opened the store cannot
/// go through [`load_hotspots`].
pub(crate) fn hotspots_with(
    store: &ArchitectureStore,
    repository_id: &str,
    limit: usize,
) -> Result<HotspotsReport> {
    use std::collections::HashMap;
    let modules = store.current_modules(repository_id)?;
    let dependencies = store.current_dependencies(repository_id)?;
    let churn: HashMap<String, f64> = store.module_churn(repository_id)?.into_iter().collect();
    let file_modules: HashMap<String, String> =
        store.file_modules(repository_id)?.into_iter().collect();
    let fragmentation =
        ownership_fragmentation(&store.ownership_metrics(repository_id)?, &file_modules);
    // No ingested commits => no git history, so churn and ownership are
    // unavailable ("n/a"), not genuinely zero. `module_churn` can't be the
    // signal: it LEFT JOINs file_changes and returns a 0 row per module even
    // with no history.
    let has_git_history = store.count_rows("commits", repository_id)? > 0;
    let mut violations: HashMap<String, usize> = HashMap::new();
    for finding in store.findings(repository_id, None)? {
        if let Some(target) = &finding.target {
            *violations.entry(target.id.clone()).or_default() += 1;
        }
    }
    let complexity: HashMap<String, f64> = store
        .module_complexity(repository_id)?
        .into_iter()
        .collect();
    let fixes: HashMap<String, ovecc_core::legacy::FixHistory> = store
        .module_fix_history(repository_id, ovecc_db::FIX_HALF_LIFE_DAYS)?
        .into_iter()
        .collect();
    // Coverage arrives per file and the ranking is per module. A file the
    // tracefile covers but the index never saw is dropped: it would add
    // covered lines to a module whose size the ranking measures differently.
    let mut coverage: HashMap<String, CoverageTotals> = HashMap::new();
    for file in store.file_coverage(repository_id)? {
        if let Some(module) = file_modules.get(&file.path) {
            coverage.entry(module.clone()).or_default().add(&file);
        }
    }

    Ok(HotspotsReport {
        hotspots: graph::compute_hotspots(
            &modules,
            &dependencies,
            &churn,
            &fragmentation,
            &violations,
            &complexity,
            &fixes,
            &coverage,
            limit,
        ),
        has_git_history,
    })
}

/// Per module, the share of its files with no majority owner: nobody holds more
/// than half the commits. A file the index never assigned to a module is left
/// out, so the share is over the files the ranking actually covers.
fn ownership_fragmentation(
    ownership: &[ovecc_db::FileOwnership],
    file_modules: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, f64> {
    let mut fragmented: std::collections::HashMap<String, (usize, usize)> =
        std::collections::HashMap::new();
    for file in ownership {
        if let Some(module) = file_modules.get(&file.file_path) {
            let entry = fragmented.entry(module.clone()).or_insert((0, 0));
            entry.1 += 1;
            if file.ownership < 0.5 {
                entry.0 += 1;
            }
        }
    }
    fragmented
        .into_iter()
        .map(|(module, (low, total))| {
            let share = if total > 0 {
                low as f64 / total as f64
            } else {
                0.0
            };
            (module, share)
        })
        .collect()
}

/// A module's corrections as text: the count, then the age-weighted mass and
/// the last one, so the reader can weigh the number instead of taking a verdict.
fn fix_history(history: &ovecc_core::legacy::FixHistory) -> String {
    match &history.last_fix_at {
        Some(last) => format!(
            "{} (weight {:.1}, last {})",
            history.fixes,
            history.mass,
            &last[..10.min(last.len())]
        ),
        None => "0".to_string(),
    }
}

/// A module's coverage as text, or `None` when no tracefile was indexed.
fn coverage_cell(hotspot: &ovecc_core::legacy::HotspotEntry) -> Option<String> {
    let coverage = hotspot.coverage?;
    Some(format!(
        "{:.0}% ({} of {} lines uncovered)",
        coverage.line_rate() * 100.0,
        coverage.lines_missed(),
        coverage.lines_found,
    ))
}

/// The ranked hotspot the tests reach least. The cross is the whole point:
/// churn alone ranks the code that keeps moving, coverage alone ranks the code
/// nobody tests, and only together do they name where a change is most likely
/// to break something no test would catch. Chosen as the minimum over the list
/// already on screen rather than against a coverage bar — no published
/// threshold exists, and inventing one would be a constant to defend instead of
/// a measurement.
fn least_covered_hotspot(report: &HotspotsReport) -> Option<String> {
    let (rank, hotspot) = report
        .hotspots
        .iter()
        .enumerate()
        .filter(|(_, hotspot)| hotspot.coverage.is_some_and(|c| c.lines_found > 0))
        .min_by(|(_, a), (_, b)| {
            a.coverage
                .unwrap_or_default()
                .line_rate()
                .total_cmp(&b.coverage.unwrap_or_default().line_rate())
        })?;
    Some(format!(
        "Least covered of these: {} at {}, ranked {} by score.",
        hotspot.module,
        coverage_cell(hotspot)?,
        rank + 1,
    ))
}

pub(crate) fn render_hotspots(report: &HotspotsReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("hotspots", report, meta_for("hotspots"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("hotspots", &meta_for("hotspots"))?;
            for hotspot in &report.hotspots {
                println!("{}", ndjson_line("hotspot", hotspot)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Hotspots");
            println!();
            if !report.has_git_history {
                println!("> Churn and owner-fragmentation are **n/a** — no git history indexed.");
                println!();
            }
            println!(
                "| # | Module | Score | Churn | Corrections | Coverage | Coupling | Fan-in | Fan-out | Owner frag. | Violations |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for (rank, hotspot) in report.hotspots.iter().enumerate() {
                let churn = if report.has_git_history {
                    format!("{:.0}", hotspot.churn)
                } else {
                    "n/a".to_string()
                };
                let owner = if report.has_git_history {
                    format!("{:.0}%", hotspot.ownership_fragmentation * 100.0)
                } else {
                    "n/a".to_string()
                };
                let fixes = if report.has_git_history {
                    fix_history(&hotspot.fix_history)
                } else {
                    "n/a".to_string()
                };
                println!(
                    "| {} | {} | {:.0} | {} | {} | {} | {} | {} | {} | {} | {} |",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    churn,
                    fixes,
                    coverage_cell(hotspot).unwrap_or_else(|| "n/a".to_string()),
                    hotspot.coupling,
                    hotspot.fan_in,
                    hotspot.fan_out,
                    owner,
                    hotspot.violations
                );
            }
            if let Some(note) = least_covered_hotspot(report) {
                println!();
                println!("> {note}");
            }
        }
        OutputFormat::Text => {
            println!("Hotspots:");
            if !report.has_git_history {
                println!("  (churn and ownership: n/a — no git history indexed)");
            }
            for (rank, hotspot) in report.hotspots.iter().enumerate() {
                println!();
                println!("{}. {}", rank + 1, hotspot.module);
                println!("   Score: {:.0}", hotspot.score);
                if report.has_git_history {
                    println!("   Churn: {:.0}", hotspot.churn);
                    println!("   Corrections: {}", fix_history(&hotspot.fix_history));
                    println!(
                        "   Ownership fragmentation: {:.0}%",
                        hotspot.ownership_fragmentation * 100.0
                    );
                } else {
                    println!("   Churn: n/a (no git history)");
                    println!("   Ownership fragmentation: n/a (no git history)");
                }
                println!(
                    "   Coupling: {} (fan-in {}, fan-out {})",
                    hotspot.coupling, hotspot.fan_in, hotspot.fan_out
                );
                println!("   Complexity: {:.0} (cognitive)", hotspot.complexity);
                println!("   Violations: {}", hotspot.violations);
                if let Some(coverage) = coverage_cell(hotspot) {
                    println!("   Coverage: {coverage}");
                }
            }
            if let Some(note) = least_covered_hotspot(report) {
                println!();
                println!("{note}");
            }
            if report.hotspots.is_empty() {
                println!("  (none)");
            }
        }
    }
    Ok(())
}

pub(crate) fn load_summary(paths: &ProjectPaths) -> Result<SummaryReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let files = store.current_file_count(&repository_id)?;
    let snapshot_id = store
        .latest_snapshot(&repository_id)?
        .map(|snapshot| snapshot.id);
    let repository_root = store
        .repository_root(&repository_id)?
        .unwrap_or_else(|| paths.root_display());
    let boundary_violations = store
        .findings(&repository_id, None)?
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::CrossDomainDependency
                    | FindingKind::ForbiddenImport
                    | FindingKind::LayerViolation
            )
        })
        .count();

    // Recorded by `index` as a snapshot metric, so the failure outlives the run
    // that produced it: the numbers below are only as complete as the index.
    let parse_failures = store
        .metric_history(&repository_id, "parse_failures", 1)?
        .last()
        .map(|(_, _, _, value)| value.max(0.0) as usize)
        .unwrap_or(0);

    Ok(graph::summarize(
        repository_root,
        snapshot_id,
        files,
        modules,
        &dependencies,
        boundary_violations,
        parse_failures,
    ))
}

/// Warns that the index is missing files the last run found. Unreadable files
/// are not rare in the wild — cloud placeholders that never hydrated, a
/// permissions problem — and they shrink every number here, not the problem.
fn incomplete_index_note(report: &SummaryReport) -> Option<String> {
    (report.parse_failures > 0).then(|| {
        format!(
            "{} of {} files found were not indexed, so every count here covers the rest. \
             Re-run `ovecc index` to see which and why.",
            report.parse_failures,
            report.files + report.parse_failures,
        )
    })
}

fn intra_module_cycles_note(report: &SummaryReport) -> Option<String> {
    (report.intra_module_cycles > 0).then(|| {
        format!(
            "{} further cycle(s) run between sibling directories inside a single \
             module, which the module-level count above cannot represent. \
             `ovecc diagnose` lists them with file:line witnesses; raising \
             `[architecture] module_depth` makes those directories modules in \
             their own right and brings them into the count.",
            report.intra_module_cycles
        )
    })
}

/// Warns when no component imports another. Every relational metric is then 0
/// for want of edges, not for want of problems, and the summary reads as a clean
/// bill of health. A directory holding several unrelated projects lands here.
fn isolated_components_note(report: &SummaryReport) -> Option<String> {
    (report.modules > 1 && report.coupling_density < f64::EPSILON).then(|| {
        format!(
            "{} components, none importing another: cycles, boundary violations and \
             coupling density are 0 for want of edges, not for want of problems. \
             Independent projects in one directory read like this — index each on its own.",
            report.modules
        )
    })
}

/// Names the graph the density was measured over, and shows the fraction.
///
/// `metrics` reports a "coupling density" too, over `[diagnose]` components
/// rather than modules — a different partition with different excludes, so the
/// two numbers differ on the same snapshot. That reads as nondeterminism unless
/// each says what it counted, and determinism is the thing this tool sells.
fn coupling_density_line(report: &SummaryReport) -> String {
    let basis = if report.coupling_basis.is_empty() {
        "module"
    } else {
        report.coupling_basis.trim_end_matches('s')
    };
    let density = format!(
        "Coupling density ({basis}s): {:.2}%",
        report.coupling_density * 100.0
    );
    if report.coupling_possible_edges == 0 {
        return density;
    }
    format!(
        "{density} — {} of {} possible edges between {} {basis}s",
        report.coupling_edges, report.coupling_possible_edges, report.modules
    )
}

pub(crate) fn render_summary_report(report: &SummaryReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("summary", report, meta_for("summary"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("summary", &meta_for("summary"))?;
            println!("{}", ndjson_header("summary", report, &["hotspots"])?);
            for hotspot in &report.hotspots {
                println!("{}", ndjson_line("hotspot", hotspot)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Architecture summary");
            println!();
            // Ahead of the list, since it qualifies every figure in it.
            if let Some(note) = incomplete_index_note(report) {
                println!("> {note}");
                println!();
            }
            println!("- Repository: `{}`", report.repository_root);
            if let Some(snapshot_id) = &report.snapshot_id {
                println!("- Snapshot: `{snapshot_id}`");
            }
            println!("- Files: {}", report.files);
            println!("- Modules: {}", report.modules);
            println!("- Dependencies: {}", report.dependencies);
            println!("- External dependencies: {}", report.external_dependencies);
            println!(
                "- Cyclic module components: {}",
                report.circular_dependencies
            );
            println!("- Boundary violations: {}", report.boundary_violations);
            println!("- {}", coupling_density_line(report));
            println!("- Risk score: **{}**", report.risk_score.as_str());
            if let Some(note) = intra_module_cycles_note(report) {
                println!();
                println!("> {note}");
            }
            if let Some(note) = isolated_components_note(report) {
                println!();
                println!("> {note}");
            }
            if !report.hotspots.is_empty() {
                println!();
                println!("## Hotspots");
                println!();
                println!("| Module | Score | Fan-in | Fan-out | Instability |");
                println!("| --- | --- | --- | --- | --- |");
                for hotspot in &report.hotspots {
                    println!(
                        "| {} | {} | {} | {} | {:.2} |",
                        hotspot.module,
                        hotspot.score,
                        hotspot.fan_in,
                        hotspot.fan_out,
                        hotspot.instability
                    );
                }
            }
        }
        OutputFormat::Text => {
            println!("Repository: {}", report.repository_root);
            if let Some(snapshot_id) = &report.snapshot_id {
                println!("Snapshot: {snapshot_id}");
            }
            println!("Files: {}", report.files);
            if let Some(note) = incomplete_index_note(report) {
                println!("  Warning: {note}");
            }
            println!("Modules: {}", report.modules);
            println!("Dependencies: {}", report.dependencies);
            println!("External dependencies: {}", report.external_dependencies);
            println!("Cyclic module components: {}", report.circular_dependencies);
            if let Some(note) = intra_module_cycles_note(report) {
                println!("  ({note})");
            }
            println!("Boundary violations: {}", report.boundary_violations);
            println!("{}", coupling_density_line(report));
            anstream::println!("Risk score: {}", risk_tag(report.risk_score));
            if let Some(note) = isolated_components_note(report) {
                println!("  ({note})");
            }

            if !report.hotspots.is_empty() {
                println!();
                println!("Hotspots:");
                for hotspot in &report.hotspots {
                    println!(
                        "  {} (score {}, fan-in {}, fan-out {}, instability {:.2})",
                        hotspot.module,
                        hotspot.score,
                        hotspot.fan_in,
                        hotspot.fan_out,
                        hotspot.instability
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::legacy::RiskLevel;

    fn report(files: usize, parse_failures: usize, modules: usize, density: f64) -> SummaryReport {
        SummaryReport {
            repository_root: "/repo".to_string(),
            snapshot_id: None,
            files,
            parse_failures,
            modules,
            dependencies: 0,
            external_dependencies: 0,
            circular_dependencies: 0,
            intra_module_cycles: 0,
            boundary_violations: 0,
            coupling_density: density,
            coupling_basis: "modules".to_string(),
            coupling_edges: 0,
            coupling_possible_edges: 0,
            hotspots: Vec::new(),
            risk_score: RiskLevel::Low,
        }
    }

    #[test]
    fn an_incomplete_index_counts_the_files_it_never_saw() {
        assert!(incomplete_index_note(&report(36, 0, 4, 0.2)).is_none());
        let note = incomplete_index_note(&report(1, 35, 1, 0.0)).expect("35 files missing");
        assert!(note.starts_with("35 of 36 files"), "{note}");
    }

    #[test]
    fn a_cycle_the_module_view_cannot_show_is_stated_not_swallowed() {
        assert!(intra_module_cycles_note(&report(9, 0, 4, 0.2)).is_none());

        let mut hidden = report(9, 0, 4, 0.2);
        hidden.intra_module_cycles = 2;
        let note = intra_module_cycles_note(&hidden).expect("qualifies the count");
        assert!(note.starts_with("2 further cycle(s)"), "{note}");
        assert!(note.contains("ovecc diagnose"), "{note}");
        assert!(note.contains("module_depth"), "{note}");
    }

    #[test]
    fn coupling_density_names_the_graph_it_measured() {
        // `metrics` prints a "coupling density" over a different partition, so
        // the same snapshot yields two different numbers. Naming the basis and
        // showing the fraction is what keeps that from reading as a tool that
        // cannot make up its mind — which, for a tool that sells determinism,
        // costs more than the number is worth.
        let mut sized = report(57, 0, 15, 0.1238);
        sized.coupling_edges = 26;
        sized.coupling_possible_edges = 210;
        let line = coupling_density_line(&sized);
        assert!(line.contains("(modules)"), "{line}");
        assert!(line.contains("12.38%"), "{line}");
        assert!(
            line.contains("26 of 210 possible edges between 15 modules"),
            "{line}"
        );

        // A single module has no possible edge, so the fraction says nothing
        // and is left off rather than printed as "0 of 0".
        let lone = report(4, 0, 1, 0.0);
        let line = coupling_density_line(&lone);
        assert!(line.contains("(modules)"), "{line}");
        assert!(!line.contains("possible edges"), "{line}");
    }

    #[test]
    fn one_component_alone_earns_no_isolation_note() {
        // A lone module has nothing to import from, so its 0 density says nothing.
        assert!(isolated_components_note(&report(9, 0, 1, 0.0)).is_none());
        assert!(isolated_components_note(&report(9, 0, 4, 0.0)).is_some());
        assert!(isolated_components_note(&report(9, 0, 4, 0.05)).is_none());
    }
}
