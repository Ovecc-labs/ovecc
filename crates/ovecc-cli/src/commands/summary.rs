//! `ovecc summary` and `ovecc hotspots`: the repository-level overview.

use super::open_store;
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_header, ndjson_line, risk_tag};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::facts::FindingKind;
use ovecc_core::legacy::{HotspotsReport, SummaryReport};
use ovecc_graph as graph;

pub(crate) fn load_hotspots(paths: &ProjectPaths, limit: usize) -> Result<HotspotsReport> {
    use std::collections::HashMap;
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;

    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let churn: HashMap<String, f64> = store.module_churn(&repository_id)?.into_iter().collect();
    let file_modules: HashMap<String, String> =
        store.file_modules(&repository_id)?.into_iter().collect();
    let ownership_rows = store.ownership_metrics(&repository_id)?;
    // No ingested commits => no git history, so churn and ownership are
    // unavailable ("n/a"), not genuinely zero. `module_churn` can't be the
    // signal: it LEFT JOINs file_changes and returns a 0 row per module even
    // with no history.
    let has_git_history = store.count_rows("commits", &repository_id)? > 0;
    // Fragmentation per module: the share of its files with no majority owner
    // (highest single-author share below 50%).
    let mut fragmented: HashMap<String, (usize, usize)> = HashMap::new();
    for ownership in &ownership_rows {
        if let Some(module) = file_modules.get(&ownership.file_path) {
            let entry = fragmented.entry(module.clone()).or_insert((0, 0));
            entry.1 += 1;
            if ownership.ownership < 0.5 {
                entry.0 += 1;
            }
        }
    }
    let fragmentation: HashMap<String, f64> = fragmented
        .iter()
        .map(|(module, (low, total))| {
            (
                module.clone(),
                if *total > 0 {
                    *low as f64 / *total as f64
                } else {
                    0.0
                },
            )
        })
        .collect();
    let mut violations: HashMap<String, usize> = HashMap::new();
    for finding in store.findings(&repository_id, None)? {
        if let Some(target) = &finding.target {
            *violations.entry(target.id.clone()).or_default() += 1;
        }
    }
    let complexity: HashMap<String, f64> = store
        .module_complexity(&repository_id)?
        .into_iter()
        .collect();
    let fixes: HashMap<String, ovecc_core::legacy::FixHistory> = store
        .module_fix_history(&repository_id, ovecc_db::FIX_HALF_LIFE_DAYS)?
        .into_iter()
        .collect();

    Ok(HotspotsReport {
        hotspots: graph::compute_hotspots(
            &modules,
            &dependencies,
            &churn,
            &fragmentation,
            &violations,
            &complexity,
            &fixes,
            limit,
        ),
        has_git_history,
    })
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
                "| # | Module | Score | Churn | Corrections | Coupling | Fan-in | Fan-out | Owner frag. | Violations |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
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
                    "| {} | {} | {:.0} | {} | {} | {} | {} | {} | {} | {} |",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    churn,
                    fixes,
                    hotspot.coupling,
                    hotspot.fan_in,
                    hotspot.fan_out,
                    owner,
                    hotspot.violations
                );
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
            println!("- Circular dependencies: {}", report.circular_dependencies);
            println!("- Boundary violations: {}", report.boundary_violations);
            println!(
                "- Coupling density: {:.2}%",
                report.coupling_density * 100.0
            );
            println!("- Risk score: **{}**", report.risk_score.as_str());
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
            println!("Circular deps: {}", report.circular_dependencies);
            println!("Boundary violations: {}", report.boundary_violations);
            println!("Coupling density: {:.2}%", report.coupling_density * 100.0);
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
            boundary_violations: 0,
            coupling_density: density,
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
    fn one_component_alone_earns_no_isolation_note() {
        // A lone module has nothing to import from, so its 0 density says nothing.
        assert!(isolated_components_note(&report(9, 0, 1, 0.0)).is_none());
        assert!(isolated_components_note(&report(9, 0, 4, 0.0)).is_some());
        assert!(isolated_components_note(&report(9, 0, 4, 0.05)).is_none());
    }
}
