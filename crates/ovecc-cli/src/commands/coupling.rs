//! `ovecc coupling`: the file pairs the history keeps changing together.

use super::open_store;
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::facts::CoChangedPair;

#[derive(serde::Serialize)]
pub(crate) struct CouplingReport {
    pairs: Vec<CoChangedPair>,
    min_confidence: f64,
    /// False when no git history was indexed: an empty result then means "no
    /// data", not "nothing is coupled".
    has_git_history: bool,
}

pub(crate) fn load_coupling(paths: &ProjectPaths, min_confidence: f64) -> Result<CouplingReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    Ok(CouplingReport {
        pairs: store.co_changes(&repository_id, min_confidence)?,
        min_confidence,
        has_git_history: store.count_rows("commits", &repository_id)? > 0,
    })
}

/// `limit` cuts the pairs printed, never the count.
pub(crate) fn render_coupling(
    report: &CouplingReport,
    format: OutputFormat,
    limit: usize,
) -> Result<()> {
    let shown: &[CoChangedPair] = match limit {
        0 => &report.pairs,
        n => &report.pairs[..n.min(report.pairs.len())],
    };

    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => emit_json(
            "coupling",
            &serde_json::json!({
                "pairs": shown,
                "total": report.pairs.len(),
                "min_confidence": report.min_confidence,
                "has_git_history": report.has_git_history,
            }),
            meta_for("coupling"),
        )?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("coupling", &meta_for("coupling"))?;
            for pair in shown {
                println!("{}", ndjson_line("co_change", pair)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Evolutionary coupling ({} pairs)", report.pairs.len());
            println!();
            if !report.has_git_history {
                println!("> No git history indexed.");
                println!();
            }
            println!("| Left | Right | Commits together | Jaccard | Lift | L→R | R→L |");
            println!("| --- | --- | --- | --- | --- | --- | --- |");
            for pair in shown {
                println!(
                    "| `{}` | `{}` | {} | {:.2} | {:.2} | {:.0}% | {:.0}% |",
                    pair.left,
                    pair.right,
                    pair.support,
                    pair.jaccard,
                    pair.lift,
                    pair.confidence_left_to_right * 100.0,
                    pair.confidence_right_to_left * 100.0
                );
            }
        }
        OutputFormat::Text => {
            println!("Evolutionary coupling:");
            if !report.has_git_history {
                println!("  (no git history indexed)");
            }
            for pair in shown {
                println!();
                println!("{} <-> {}", pair.left, pair.right);
                println!(
                    "   {} commits together, jaccard {:.2}, lift {:.2}",
                    pair.support, pair.jaccard, pair.lift
                );
                println!(
                    "   {:.0}% of changes to the first touch the second, {:.0}% the other way",
                    pair.confidence_left_to_right * 100.0,
                    pair.confidence_right_to_left * 100.0
                );
                if !pair.commits.is_empty() {
                    let shas: Vec<&str> = pair
                        .commits
                        .iter()
                        .map(|sha| &sha[..8.min(sha.len())])
                        .collect();
                    println!("   seen in {}", shas.join(", "));
                }
            }
            if report.pairs.is_empty() {
                println!("  (none)");
            }
        }
    }
    Ok(())
}
