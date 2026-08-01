//! `ovecc selfcheck`: how well each rule's findings track the repository's own
//! fix history.

use super::open_store;
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_header, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_graph::selfcheck::{self, SelfCheckReport};

pub(crate) fn load_selfcheck(paths: &ProjectPaths) -> Result<SelfCheckReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let files: Vec<(String, u64)> = store
        .current_files(&repository_id)?
        .into_iter()
        .map(|file| (file.path, file.size_bytes))
        .collect();
    let fix_mass: Vec<(String, f64)> = store
        .file_fix_history(&repository_id, ovecc_db::FIX_HALF_LIFE_DAYS)?
        .into_iter()
        .map(|history| (history.file_path, history.mass))
        .collect();
    let findings = store.findings(&repository_id, None)?;
    Ok(selfcheck::self_check(
        &files,
        &fix_mass,
        &findings,
        ovecc_db::FIX_HALF_LIFE_DAYS,
    ))
}

/// The caveat that belongs next to every number this command prints. Written
/// once so the text, markdown, and `report` renderings cannot drift apart.
pub(crate) const SELFCHECK_CAVEAT: &str = "Association, not proof: findings are computed on today's code, corrections \
     happened in the past, and a rule can be right about code nobody has got \
     round to fixing.";

/// One line for `ovecc report`, or `None` when there was nothing to measure —
/// no git history, or no rule fired on an indexed file. Rules arrive sorted by
/// lift, so the ends of the list are the range.
pub(crate) fn selfcheck_line(report: &SelfCheckReport) -> Option<String> {
    let (best, worst) = (report.rules.first()?, report.rules.last()?);
    Some(format!(
        "{} rule(s) measured against this repository's fix history: lift {:.2}-{:.2} over a \
         base of {:.2} fixes/KB. `ovecc selfcheck` breaks it down per rule.",
        report.rules.len(),
        worst.lift,
        best.lift,
        report.base_rate,
    ))
}

/// The share of the window's corrections that landed outside the index, or
/// `None` when there were none.
fn off_index_note(report: &SelfCheckReport) -> Option<String> {
    let total = report.fix_mass + report.fix_mass_off_index;
    (report.fix_mass_off_index > 0.0 && total > 0.0).then(|| {
        format!(
            "{:.0}% of the fix mass landed on paths the index does not hold — deleted files, \
             docs, unsupported languages — and is in neither rate.",
            report.fix_mass_off_index / total * 100.0
        )
    })
}

pub(crate) fn render_selfcheck(report: &SelfCheckReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("selfcheck", report, meta_for("selfcheck"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("selfcheck", &meta_for("selfcheck"))?;
            println!("{}", ndjson_header("selfcheck", report, &["rules"])?);
            for rule in &report.rules {
                println!("{}", ndjson_line("rule", rule)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Self-check against the fix history");
            println!();
            println!(
                "- Base rate: {:.2} fixes/KB over {} file(s), {:.1} KB",
                report.base_rate,
                report.files_evaluated,
                report.bytes_evaluated as f64 / 1024.0
            );
            println!("- Fix half-life: {:.0} days", report.half_life_days);
            if let Some(note) = off_index_note(report) {
                println!("- {note}");
            }
            println!();
            println!("| Rule | Files flagged | KB flagged | Fix mass | Rate | Lift |");
            println!("| --- | --- | --- | --- | --- | --- |");
            for rule in &report.rules {
                println!(
                    "| `{}` | {} | {:.1} | {:.2} | {:.2} | {:.2} |",
                    rule.rule,
                    rule.files_flagged,
                    rule.bytes_flagged as f64 / 1024.0,
                    rule.fix_mass,
                    rule.rate,
                    rule.lift
                );
            }
            println!();
            println!("> {SELFCHECK_CAVEAT}");
        }
        OutputFormat::Text => {
            println!(
                "Base rate: {:.2} fixes/KB over {} file(s), {:.1} KB (half-life {:.0} days)",
                report.base_rate,
                report.files_evaluated,
                report.bytes_evaluated as f64 / 1024.0,
                report.half_life_days
            );
            if let Some(note) = off_index_note(report) {
                println!("  {note}");
            }
            for rule in &report.rules {
                println!();
                println!("{} (lift {:.2})", rule.rule, rule.lift);
                println!(
                    "  {} file(s), {:.1} KB, fix mass {:.2} -> {:.2} fixes/KB",
                    rule.files_flagged,
                    rule.bytes_flagged as f64 / 1024.0,
                    rule.fix_mass,
                    rule.rate
                );
            }
            if report.rules.is_empty() {
                println!("  (no rule flagged an indexed file)");
            }
            println!();
            println!("{SELFCHECK_CAVEAT}");
        }
    }
    Ok(())
}
