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
    let mut families = ovecc_graph::dupes::detect(&files, min_tokens, min_lines, cross_file_only);
    sink_test_only_families(&mut families);
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

/// Sinks clone families whose every instance is a test file below the
/// production ones. Repeated fixtures and boilerplate test setup are the
/// dominant duplication noise; kept in the totals, they just stop crowding
/// out production clones at the top of the `--limit` page. The sort is stable,
/// so detection's longest-run-first order is preserved within each group.
fn sink_test_only_families(families: &mut [ovecc_graph::dupes::CloneFamily]) {
    families.sort_by_key(|family| {
        family
            .instances
            .iter()
            .all(|instance| ovecc_core::util::is_test_path(&instance.path))
    });
}

/// `limit` cuts the families printed, never the counts. Detection sorts them
/// longest-run first, so the page is the duplication worth acting on; Django's
/// 1 597 families serialize to ~313k tokens whole, and the first twenty to
/// ~2.6k. `--limit 0` prints all of them.
pub(crate) fn render_dupes(report: &DupesReport, format: OutputFormat, limit: usize) -> Result<()> {
    let plural = |n: usize| if n == 1 { "y" } else { "ies" };
    let shown: &[ovecc_graph::dupes::CloneFamily] = match limit {
        0 => &report.families,
        n => &report.families[..n.min(report.families.len())],
    };
    let note = (shown.len() < report.families.len()).then(|| {
        format!(
            "Showing the {} longest of {} clone families. Raise --min-tokens to cut \
             the tail, or pass --limit 0 for all of them.",
            shown.len(),
            report.clone_families
        )
    });

    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => emit_json(
            "dupes",
            &serde_json::json!({
                "files_scanned": report.files_scanned,
                "min_tokens": report.min_tokens,
                "min_lines": report.min_lines,
                "clone_families": report.clone_families,
                "duplicated_lines": report.duplicated_lines,
                "shown": shown.len(),
                "families": shown,
                "note": note,
            }),
            meta_for("dupes"),
        )?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("dupes", &meta_for("dupes"))?;
            for family in shown {
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
            for (rank, family) in shown.iter().enumerate() {
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
            if let Some(note) = &note {
                println!();
                println!("{note}");
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
            for (rank, family) in shown.iter().enumerate() {
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
            if let Some(note) = &note {
                println!();
                println!("{note}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_graph::dupes::{CloneFamily, CloneInstance};

    fn family(paths: &[&str], token_length: usize) -> CloneFamily {
        CloneFamily {
            token_length,
            line_span: token_length as u32,
            instances: paths
                .iter()
                .map(|path| CloneInstance {
                    path: path.to_string(),
                    start_line: 1,
                    end_line: 10,
                    token_count: token_length,
                })
                .collect(),
        }
    }

    #[test]
    fn test_only_families_sink_below_production_ones() {
        // Detection order is longest-run first; the test-only family is longer
        // here, yet must still sink below the shorter production family.
        let mut families = vec![
            family(&["src/a.test.ts", "src/b.test.ts"], 200),
            family(&["src/service.ts", "src/handler.ts"], 120),
            family(&["src/util.ts", "src/util.test.ts"], 80),
        ];
        sink_test_only_families(&mut families);
        // Production and mixed families first (stable, so 120 before 80), the
        // all-test family last.
        assert_eq!(families[0].token_length, 120, "production family leads");
        assert_eq!(
            families[1].token_length, 80,
            "a mixed family stays production-side"
        );
        assert_eq!(families[2].token_length, 200, "the all-test family sinks");
    }
}
