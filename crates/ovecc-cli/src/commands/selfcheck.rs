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
    let has_git_history = store.count_rows("commits", &repository_id)? > 0;
    Ok(selfcheck::self_check(
        &files,
        &fix_mass,
        &findings,
        ovecc_db::FIX_HALF_LIFE_DAYS,
        has_git_history,
    ))
}

/// Why every lift is 0, when it is 0 for want of data rather than for want of
/// predictive power. Without this the table reads as a ruleset that predicts
/// nothing, which is the opposite of what an unmeasurable repository shows.
fn no_measurement_note(report: &SelfCheckReport) -> Option<String> {
    if !report.has_git_history {
        return Some(
            "No commits in the index, so there is nothing to measure against. The fix \
             history needs a git repository indexed without --no-git."
                .to_string(),
        );
    }
    (report.fix_mass + report.fix_mass_off_index == 0.0).then(|| {
        "No commit in the indexed history is classified as a fix, so there is nothing to \
         measure against."
            .to_string()
    })
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
    if no_measurement_note(report).is_some() {
        return None;
    }
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
            if let Some(note) = no_measurement_note(report) {
                println!("> {note}");
                println!();
            }
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
            if let Some(note) = no_measurement_note(report) {
                println!("{note}");
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_graph::selfcheck::RuleSelfCheck;

    fn report(has_git_history: bool, fix_mass: f64) -> SelfCheckReport {
        SelfCheckReport {
            has_git_history,
            half_life_days: 180.0,
            files_evaluated: 2,
            bytes_evaluated: 2048,
            fix_mass,
            fix_mass_off_index: 0.0,
            base_rate: fix_mass / 2.0,
            rules: vec![RuleSelfCheck {
                rule: "complexity".to_string(),
                files_flagged: 1,
                bytes_flagged: 1024,
                fix_mass,
                rate: fix_mass,
                lift: if fix_mass > 0.0 { 2.0 } else { 0.0 },
            }],
        }
    }

    #[test]
    fn the_report_line_stays_quiet_when_there_was_nothing_to_measure() {
        assert!(selfcheck_line(&report(false, 0.0)).is_none(), "no commits");
        assert!(selfcheck_line(&report(true, 0.0)).is_none(), "no fixes");

        let line = selfcheck_line(&report(true, 4.0)).expect("a measurable repository");
        assert!(line.contains("lift 2.00-2.00"), "{line}");
    }

    #[test]
    fn a_measurable_repository_needs_no_excuse() {
        assert!(no_measurement_note(&report(true, 4.0)).is_none());
        assert!(
            no_measurement_note(&report(false, 4.0))
                .expect("no commits")
                .contains("--no-git")
        );
    }
}
