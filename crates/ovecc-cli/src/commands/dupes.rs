//! `ovecc dupes`: clone families over a normalized token stream.

use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, OveccConfig, ProjectPaths};

#[derive(serde::Serialize)]
pub(crate) struct DupesReport {
    files_scanned: usize,
    min_tokens: usize,
    min_lines: usize,
    clone_families: usize,
    duplicated_lines: u32,
    families: Vec<ovecc_graph::dupes::CloneFamily>,
}

pub(crate) fn load_dupes_report(
    paths: &ProjectPaths,
    config: &OveccConfig,
    min_tokens: usize,
    min_lines: usize,
    cross_file_only: bool,
) -> Result<DupesReport> {
    let files = ovecc_indexer::collect_file_tokens(paths, config)?;
    let families = ovecc_graph::dupes::detect(&files, min_tokens, min_lines, cross_file_only);
    let duplicated_lines: u32 = families.iter().map(|family| family.line_span).sum();
    Ok(DupesReport {
        files_scanned: files.len(),
        min_tokens,
        min_lines,
        clone_families: families.len(),
        duplicated_lines,
        families,
    })
}

pub(crate) fn render_dupes(report: &DupesReport, format: OutputFormat) -> Result<()> {
    let plural = |n: usize| if n == 1 { "y" } else { "ies" };
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("dupes", report, meta_for("dupes"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("dupes", &meta_for("dupes"))?;
            for family in &report.families {
                println!("{}", ndjson_line("clone_family", family)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Duplication ({} clone famil{})",
                report.clone_families,
                plural(report.clone_families)
            );
            println!();
            println!("- Files scanned: {}", report.files_scanned);
            println!(
                "- Thresholds: >= {} tokens, >= {} lines",
                report.min_tokens, report.min_lines
            );
            for (rank, family) in report.families.iter().enumerate() {
                println!();
                println!(
                    "## Clone {} ({} tokens, {} lines, {} copies)",
                    rank + 1,
                    family.token_length,
                    family.line_span,
                    family.instances.len()
                );
                for instance in &family.instances {
                    println!(
                        "- `{}:{}-{}`",
                        instance.path, instance.start_line, instance.end_line
                    );
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Duplication: {} clone famil{} (scanned {} files, >= {} tokens / {} lines)",
                report.clone_families,
                plural(report.clone_families),
                report.files_scanned,
                report.min_tokens,
                report.min_lines
            );
            for (rank, family) in report.families.iter().enumerate() {
                println!();
                println!(
                    "{}. {} tokens / {} lines, {} copies:",
                    rank + 1,
                    family.token_length,
                    family.line_span,
                    family.instances.len()
                );
                for instance in &family.instances {
                    println!(
                        "   {}:{}-{}",
                        instance.path, instance.start_line, instance.end_line
                    );
                }
            }
            if report.families.is_empty() {
                println!("  (no duplication above the threshold)");
            }
        }
    }
    Ok(())
}
