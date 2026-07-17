//! `ovecc conventions`: learned repository conventions and their deviations.

use super::open_store;
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::legacy::ConventionsReport;

pub(crate) fn load_conventions_report(paths: &ProjectPaths) -> Result<ConventionsReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let file_dependencies: Vec<(String, String)> = store
        .current_dependencies(&repository_id)?
        .into_iter()
        .filter(|dependency| !dependency.is_external)
        .filter_map(|dependency| {
            dependency
                .target_file_path
                .map(|target| (dependency.source_file_path, target))
        })
        .collect();
    let db_files = store.db_accessing_files(&repository_id)?;
    Ok(ovecc_graph::conventions::learn_conventions(
        &file_dependencies,
        &db_files,
    ))
}

pub(crate) fn render_conventions(report: &ConventionsReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("conventions", report, meta_for("conventions"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("conventions", &meta_for("conventions"))?;
            for convention in &report.conventions {
                println!("{}", ndjson_line("convention", convention)?);
            }
            for deviation in &report.deviations {
                println!("{}", ndjson_line("deviation", deviation)?);
            }
        }
        OutputFormat::Markdown => conventions_markdown(report),
        OutputFormat::Text => conventions_text(report),
    }
    Ok(())
}

fn conventions_markdown(report: &ConventionsReport) {
    println!("# Conventions");
    println!();
    for convention in &report.conventions {
        println!(
            "- **{}** (confidence {:.2}, {}/{})",
            convention.description, convention.confidence, convention.matching, convention.total
        );
    }
    if !report.deviations.is_empty() {
        println!();
        println!("## Deviations");
        println!();
        for deviation in &report.deviations {
            println!(
                "- [{}] {} — {}",
                deviation.severity, deviation.description, deviation.reason
            );
            if let Some(evidence) = &deviation.evidence {
                println!("  - Evidence: `{evidence}`");
            }
        }
    }
}

fn conventions_text(report: &ConventionsReport) {
    println!("Detected conventions:");
    for convention in &report.conventions {
        println!();
        println!("  {}", convention.description);
        println!(
            "    Confidence: {:.2} ({}/{})",
            convention.confidence, convention.matching, convention.total
        );
    }
    if report.conventions.is_empty() {
        println!("  (none with sufficient evidence)");
    }
    if !report.deviations.is_empty() {
        println!();
        println!("Deviations:");
        for deviation in &report.deviations {
            println!();
            println!("  [{}] {}", deviation.severity, deviation.description);
            println!("    Reason: {}", deviation.reason);
            if let Some(evidence) = &deviation.evidence {
                println!("    Evidence: {evidence}");
            }
        }
    }
}
