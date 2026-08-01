//! Snapshot comparison: `diff`, `drift`, and the count-based CI `gate`.

use super::review::{ChangeShapeView, load_change_shape, shape_summary_line};
use crate::cli::FailOn;
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_header, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::legacy::{DependencyEdge, DiffReport, DriftReport, RiskLevel};
use ovecc_db::ArchitectureStore;

#[derive(serde::Serialize)]
pub(crate) struct GateReport {
    base: String,
    head: String,
    pub(crate) verdict: String,
    new_cycles: i64,
    new_modules: usize,
    new_dependencies: usize,
    risk: String,
    signals: Vec<String>,
    /// How this change compares to the repository's own commits. Beside the
    /// verdict, not in it: no percentile fails the gate.
    shape: Option<ChangeShapeView>,
}

pub(crate) fn build_gate_report(
    paths: &ProjectPaths,
    store: &ArchitectureStore,
    base: &str,
    head: &str,
    fail_on: FailOn,
) -> Result<GateReport> {
    let repository_id = paths.repository_id().0;
    let diff = store.diff(&repository_id, base, head)?;
    let drift = store.drift(&repository_id, base, head)?;
    let new_cycles = i64::from(drift.circular_dependency_delta.max(0) as i32);
    let new_modules = diff.added_modules.len();
    let new_dependencies = diff.added_dependencies.len();

    let mut signals = Vec::new();
    if new_cycles > 0 {
        signals.push(format!("{new_cycles} new circular-dependency component(s)"));
    }
    let risk_fail = diff_crosses_threshold(&diff, fail_on);
    if risk_fail {
        signals.push(format!(
            "diff risk {} crosses --fail-on {:?}",
            diff.risk_score.as_str(),
            fail_on
        ));
    }
    if matches!(fail_on, FailOn::Any) {
        if new_modules > 0 {
            signals.push(format!("{new_modules} new module(s)"));
        }
        if new_dependencies > 0 {
            signals.push(format!("{new_dependencies} new dependency edge(s)"));
        }
    }
    // Any increase in one of these metrics fails the gate regardless of
    // --fail-on: a PR that adds a vulnerability, dead code, or complexity is
    // the case this gate exists for.
    const REGRESSION_METRICS: &[(&str, &str)] = &[
        ("security_findings", "security finding"),
        ("unused_exports", "unused export"),
        ("unused_files", "unused file"),
        ("high_complexity_functions", "high-complexity function"),
        ("boundary_violations", "boundary violation"),
        ("code_smells", "code smell"),
    ];
    let mut quality_regressed = false;
    for delta in &drift.metric_deltas {
        for (metric, label) in REGRESSION_METRICS {
            if delta.metric == *metric && delta.head > delta.base {
                let added = (delta.head - delta.base) as i64;
                signals.push(format!("{added} new {label}(s)"));
                quality_regressed = true;
            }
        }
    }
    let failed = new_cycles > 0
        || risk_fail
        || quality_regressed
        || (matches!(fail_on, FailOn::Any) && (new_modules > 0 || new_dependencies > 0));

    Ok(GateReport {
        base: diff.base.id,
        head: diff.head.id,
        verdict: if failed { "fail" } else { "pass" }.to_string(),
        new_cycles,
        new_modules,
        new_dependencies,
        risk: diff.risk_score.as_str().to_string(),
        signals,
        shape: load_change_shape(paths, store, base, head)?,
    })
}

pub(crate) fn render_gate(report: &GateReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json
        | OutputFormat::Ndjson
        | OutputFormat::Sarif
        | OutputFormat::Codeclimate => emit_json("gate", report, meta_for("gate"))?,
        OutputFormat::Markdown => {
            println!("# CI gate: {}", report.verdict.to_uppercase());
            println!();
            println!("- Base: `{}`", report.base);
            println!("- Head: `{}`", report.head);
            println!("- New cycles: {}", report.new_cycles);
            println!("- Risk: {}", report.risk);
            if let Some(shape) = &report.shape {
                println!("- Change shape: {}", shape_summary_line(shape));
            }
            if report.signals.is_empty() {
                println!("- No gating signals.");
            } else {
                println!();
                println!("## Signals");
                println!();
                for signal in &report.signals {
                    println!("- {signal}");
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Gate: {} ({} -> {})",
                report.verdict, report.base, report.head
            );
            println!(
                "New cycles: {}, new modules: {}, new deps: {}, risk: {}",
                report.new_cycles, report.new_modules, report.new_dependencies, report.risk
            );
            if let Some(shape) = &report.shape {
                println!("Change shape: {}", shape_summary_line(shape));
            }
            for signal in &report.signals {
                println!("  - {signal}");
            }
        }
    }
    Ok(())
}

pub(crate) fn diff_crosses_threshold(report: &DiffReport, fail_on: FailOn) -> bool {
    fn rank(level: RiskLevel) -> u8 {
        match level {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        }
    }
    match fail_on {
        FailOn::Any => {
            !(report.added_modules.is_empty()
                && report.removed_modules.is_empty()
                && report.added_dependencies.is_empty()
                && report.removed_dependencies.is_empty())
        }
        FailOn::Medium => rank(report.risk_score) >= 1,
        FailOn::High => rank(report.risk_score) >= 2,
    }
}

pub(crate) fn render_diff_report(report: &DiffReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("diff", report, meta_for("diff"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("diff", &meta_for("diff"))?;
            println!(
                "{}",
                ndjson_header(
                    "diff",
                    report,
                    &[
                        "added_modules",
                        "removed_modules",
                        "added_dependencies",
                        "removed_dependencies",
                    ],
                )?
            );
            for module in &report.added_modules {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"type": "added_module", "name": module})
                    )?
                );
            }
            for module in &report.removed_modules {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"type": "removed_module", "name": module})
                    )?
                );
            }
            for dependency in &report.added_dependencies {
                println!("{}", ndjson_line("added_dependency", dependency)?);
            }
            for dependency in &report.removed_dependencies {
                println!("{}", ndjson_line("removed_dependency", dependency)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Architecture diff: `{}` -> `{}`",
                report.base.id, report.head.id
            );
            println!();
            println!("- Added modules: {}", report.added_modules.len());
            println!("- Removed modules: {}", report.removed_modules.len());
            println!("- Added dependencies: {}", report.added_dependencies.len());
            println!(
                "- Removed dependencies: {}",
                report.removed_dependencies.len()
            );
            println!("- Risk: **{}**", report.risk_score.as_str());
            print_markdown_modules("New modules", &report.added_modules);
            print_markdown_modules("Removed modules", &report.removed_modules);
            print_markdown_dependencies("New dependencies", &report.added_dependencies);
            print_markdown_dependencies("Removed dependencies", &report.removed_dependencies);
        }
        OutputFormat::Text => {
            println!(
                "Architecture diff: {} -> {}",
                report.base.id, report.head.id
            );
            println!("Added modules: {}", report.added_modules.len());
            println!("Removed modules: {}", report.removed_modules.len());
            println!("Added dependencies: {}", report.added_dependencies.len());
            println!(
                "Removed dependencies: {}",
                report.removed_dependencies.len()
            );
            println!("Risk: {}", report.risk_score.as_str());

            print_modules("New modules", &report.added_modules);
            print_modules("Removed modules", &report.removed_modules);
            print_dependencies("New dependencies", &report.added_dependencies);
            print_dependencies("Removed dependencies", &report.removed_dependencies);
        }
    }
    Ok(())
}

pub(crate) fn render_drift_report(report: &DriftReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("drift", report, meta_for("drift"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("drift", &meta_for("drift"))?;
            println!("{}", ndjson_line("drift", report)?);
        }
        OutputFormat::Markdown => {
            println!("# Drift: `{}` -> `{}`", report.base.id, report.head.id);
            println!();
            println!("- Coupling: {:+.2}%", report.coupling_delta_percent);
            println!("- Trend: **{}**", report.trend.as_str());
            println!();
            println!("| Metric | Base | Head | Δ |");
            println!("| --- | --- | --- | --- |");
            for delta in &report.metric_deltas {
                println!(
                    "| {} | {} | {} | {:+} |",
                    delta.metric,
                    format_metric(delta.base),
                    format_metric(delta.head),
                    format_metric(delta.head - delta.base)
                );
            }
        }
        OutputFormat::Text => {
            println!("Drift: {} -> {}", report.base.id, report.head.id);
            println!("Coupling: {:+.2}%", report.coupling_delta_percent);
            println!("Trend: {}", report.trend.as_str());
            for delta in &report.metric_deltas {
                let change = delta.head - delta.base;
                if change != 0.0 {
                    println!(
                        "  {}: {} -> {} ({:+})",
                        delta.metric,
                        format_metric(delta.base),
                        format_metric(delta.head),
                        format_metric(change)
                    );
                }
            }
        }
    }
    Ok(())
}

fn format_metric(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value:.2}")
    }
}

fn print_modules(label: &str, modules: &[String]) {
    if modules.is_empty() {
        return;
    }
    println!();
    println!("{label}:");
    for module in modules {
        println!("  {module}");
    }
}

fn print_dependencies(label: &str, dependencies: &[DependencyEdge]) {
    if dependencies.is_empty() {
        return;
    }
    println!();
    println!("{label}:");
    for dependency in dependencies {
        println!(
            "  {} -> {} ({})",
            dependency.source_module, dependency.target_module, dependency.specifier
        );
    }
}

fn print_markdown_modules(label: &str, modules: &[String]) {
    if modules.is_empty() {
        return;
    }
    println!();
    println!("## {label}");
    println!();
    for module in modules {
        println!("- {module}");
    }
}

fn print_markdown_dependencies(label: &str, dependencies: &[DependencyEdge]) {
    if dependencies.is_empty() {
        return;
    }
    println!();
    println!("## {label}");
    println!();
    for dependency in dependencies {
        println!(
            "- `{} -> {}` ({})",
            dependency.source_module, dependency.target_module, dependency.specifier
        );
    }
}
