//! The finding-bearing commands: `violations`, `security`, `audit`,
//! `health`, `deadcode`, and `fix` rendering, with the baseline and
//! `--changed-since` filters they share.

use super::open_store;
use crate::cli::FailOn;
use crate::render::{
    emit_codeclimate, emit_json, emit_json_with_fix, emit_ndjson_meta, emit_sarif, first_evidence,
    format_evidence, meta_for, ndjson_line, severity_tag,
};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::facts::{FindingKind, FindingRecord, Severity};

pub(crate) fn load_baseline(path: &std::path::Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<Vec<String>>(&content).ok())
        .map(|ids| ids.into_iter().collect())
        .unwrap_or_default()
}

/// Errors when the ref cannot be resolved — silently reporting the whole
/// backlog would defeat the flag.
pub(crate) fn filter_changed_since(
    findings: &mut Vec<FindingRecord>,
    root: &std::path::Path,
    reference: &str,
) -> Result<()> {
    let Some(changed) = ovecc_git::changed_files_since(root, reference) else {
        return Err(OveccError::Git {
            message: format!(
                "--changed-since: cannot resolve '{reference}' (not a git repository, or unknown ref)"
            ),
            source: None,
        }
        .into());
    };
    findings.retain(|finding| {
        finding
            .evidence
            .iter()
            .any(|evidence| changed.contains(&evidence.file_path))
    });
    Ok(())
}

/// Findings a list command prints before it cuts. Twenty keeps a full page
/// inside the 25k-token ceiling agents put on a tool result; the whole backlog
/// does not fit at any severity (Django's 1 825 findings serialize to ~470k
/// tokens, past the hard ceiling, so the call fails outright rather than
/// wasting context). `--limit 0` prints everything.
pub(crate) const DEFAULT_FINDING_LIMIT: usize = 20;

/// The `--offset`/`--limit` slice. A limit of 0 means no cut.
pub(crate) fn window(findings: &[FindingRecord], limit: usize, offset: usize) -> &[FindingRecord] {
    let rest = &findings[offset.min(findings.len())..];
    match limit {
        0 => rest,
        n => &rest[..n.min(rest.len())],
    }
}

/// Severity counts over the whole filtered set, so a cut list still reports
/// what it is a slice of.
fn severity_tally(findings: &[FindingRecord]) -> Vec<(&'static str, usize)> {
    [
        ("critical", Severity::Critical),
        ("high", Severity::High),
        ("medium", Severity::Medium),
        ("low", Severity::Low),
    ]
    .into_iter()
    .filter_map(|(label, severity)| {
        match findings.iter().filter(|f| f.severity == severity).count() {
            0 => None,
            n => Some((label, n)),
        }
    })
    .collect()
}

/// The rules carrying the backlog, most findings first. Which rule dominates is
/// the first thing a reader acts on and it is invisible from a truncated list.
fn rule_tally(findings: &[FindingRecord], top: usize) -> Vec<(String, usize)> {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for finding in findings {
        let rule = finding.rule_name.as_deref().unwrap_or("(no rule)");
        *counts.entry(rule).or_default() += 1;
    }
    let mut ranked: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(rule, n)| (rule.to_string(), n))
        .collect();
    // Count first, then name, so equal counts do not reorder between runs.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(top);
    ranked
}

fn tally_line(tally: &[(&'static str, usize)]) -> String {
    tally
        .iter()
        .map(|(label, n)| format!("{n} {label}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Tells the reader the list is a slice and how to move it. A silent cut would
/// read as "that is all there is". The ordering is worth stating: with the
/// highest severity first, a page can hold nothing but the top band, and
/// `--severity` (a floor, not a selection) then looks like it did nothing.
fn truncation_note(total: usize, shown: usize, offset: usize) -> Option<String> {
    (shown < total).then(|| {
        format!(
            "Showing {}-{} of {total}, highest severity first. Page with --offset, \
             raise the floor with --severity, or pass --limit 0 for the full list.",
            offset + 1,
            offset + shown,
        )
    })
}

pub(crate) fn findings_exit(findings: &[FindingRecord], fail_on: Option<FailOn>) -> u8 {
    let Some(fail_on) = fail_on else {
        return 0;
    };
    let triggered = match fail_on {
        FailOn::Any => !findings.is_empty(),
        FailOn::Medium => findings.iter().any(|f| f.severity >= Severity::Medium),
        FailOn::High => findings.iter().any(|f| f.severity >= Severity::High),
    };
    u8::from(triggered)
}

/// `limit`/`offset` cut the list the reader sees, never the set the counts and
/// the exit code are computed over. SARIF and Code Climate ignore them: those
/// feed CI ingestion, where a partial file is a wrong file.
pub(crate) fn render_violations(
    findings: &[FindingRecord],
    format: OutputFormat,
    limit: usize,
    offset: usize,
) -> Result<()> {
    let shown = window(findings, limit, offset);
    let total = findings.len();
    let severities = severity_tally(findings);
    let note = truncation_note(total, shown.len(), offset);

    match format {
        OutputFormat::Json => emit_json_with_fix(
            "violations",
            violations_json(findings, shown, offset, &note),
        )?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("violations", &meta_for("violations"))?;
            for finding in shown {
                println!("{}", ndjson_line("violation", finding)?);
            }
        }
        OutputFormat::Markdown => violations_markdown(shown, total, &severities, note.as_deref()),
        OutputFormat::Text => violations_text(findings, shown, total, &severities, note.as_deref()),
        OutputFormat::Sarif => emit_sarif(findings)?,
        OutputFormat::Codeclimate => emit_codeclimate(findings)?,
    }
    Ok(())
}

fn violations_json(
    findings: &[FindingRecord],
    shown: &[FindingRecord],
    offset: usize,
    note: &Option<String>,
) -> serde_json::Value {
    let by_severity = severity_tally(findings)
        .iter()
        .map(|(label, n)| (label.to_string(), serde_json::json!(n)))
        .collect::<serde_json::Map<String, serde_json::Value>>();
    let by_rule = rule_tally(findings, 10)
        .into_iter()
        .map(|(rule, n)| serde_json::json!({"rule": rule, "count": n}))
        .collect::<Vec<_>>();
    serde_json::json!({
        "total": findings.len(),
        "shown": shown.len(),
        "offset": offset,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "findings": shown,
        "note": note,
    })
}

fn violations_markdown(
    shown: &[FindingRecord],
    total: usize,
    severities: &[(&'static str, usize)],
    note: Option<&str>,
) {
    println!("# Violations ({total})");
    if !severities.is_empty() {
        println!();
        println!("{}", tally_line(severities));
    }
    for finding in shown {
        println!();
        println!("## [{:?}] {}", finding.severity, finding.title);
        if let Some(rule) = &finding.rule_name {
            println!("- Rule: `{rule}`");
        }
        println!("- Type: {:?}", finding.kind);
        println!("- {}", finding.description);
        for evidence in &finding.evidence {
            println!("- Evidence: `{}`", format_evidence(evidence));
        }
    }
    if let Some(note) = note {
        println!();
        println!("{note}");
    }
}

fn violations_text(
    findings: &[FindingRecord],
    shown: &[FindingRecord],
    total: usize,
    severities: &[(&'static str, usize)],
    note: Option<&str>,
) {
    print!("Violations: {total}");
    if severities.is_empty() {
        println!();
    } else {
        println!(" ({})", tally_line(severities));
    }
    let rules = rule_tally(findings, 3);
    if !rules.is_empty() && total > shown.len() {
        let joined = rules
            .iter()
            .map(|(rule, n)| format!("{rule} {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Top rules: {joined}");
    }
    for finding in shown {
        println!();
        anstream::println!("{} {}", severity_tag(finding.severity), finding.title);
        if let Some(rule) = &finding.rule_name {
            println!("  Rule: {rule}");
        }
        println!("  Type: {:?}", finding.kind);
        for evidence in &finding.evidence {
            println!("  Evidence: {}", format_evidence(evidence));
        }
    }
    if let Some(note) = note {
        println!();
        println!("{note}");
    }
}

fn is_security_kind(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::HardcodedSecret
            | FindingKind::InsecurePattern
            | FindingKind::WeakCrypto
            | FindingKind::PermissiveCors
            | FindingKind::TaintedFlow
    )
}

/// Grouped by category, with explicit per-category counts so a "0 findings"
/// result is stated rather than silent.
#[derive(serde::Serialize)]
pub(crate) struct SecurityReport {
    pub(crate) secrets: usize,
    pub(crate) insecure_patterns: usize,
    pub(crate) weak_crypto: usize,
    pub(crate) permissive_cors: usize,
    pub(crate) tainted_flows: usize,
    pub(crate) total: usize,
    pub(crate) findings: Vec<FindingRecord>,
}

pub(crate) fn build_security_report(
    all: &[FindingRecord],
    min_severity: Option<Severity>,
) -> SecurityReport {
    let findings: Vec<FindingRecord> = all
        .iter()
        .filter(|finding| is_security_kind(finding.kind))
        .filter(|finding| min_severity.is_none_or(|min| finding.severity >= min))
        .cloned()
        .collect();
    let count = |kind: FindingKind| findings.iter().filter(|f| f.kind == kind).count();
    SecurityReport {
        secrets: count(FindingKind::HardcodedSecret),
        insecure_patterns: count(FindingKind::InsecurePattern),
        weak_crypto: count(FindingKind::WeakCrypto),
        permissive_cors: count(FindingKind::PermissiveCors),
        tainted_flows: count(FindingKind::TaintedFlow),
        total: findings.len(),
        findings,
    }
}

pub(crate) fn render_security(report: &SecurityReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json_with_fix("security", report)?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("security", &meta_for("security"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("security_finding", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Security ({} finding(s))", report.total);
            println!();
            println!("- Hardcoded secrets: {}", report.secrets);
            println!(
                "- Insecure patterns (eval/exec): {}",
                report.insecure_patterns
            );
            println!("- Weak crypto: {}", report.weak_crypto);
            println!("- Permissive CORS: {}", report.permissive_cors);
            println!("- Tainted flows: {}", report.tainted_flows);
            for finding in &report.findings {
                println!();
                println!("## [{:?}] {}", finding.severity, finding.title);
                println!("- {}", finding.description);
                for evidence in &finding.evidence {
                    println!("- Evidence: `{}`", format_evidence(evidence));
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Security findings: {} (indexed sources plus every file Git tracks)",
                report.total
            );
            println!(
                "  secrets {}, insecure {}, weak-crypto {}, cors {}, tainted-flows {}",
                report.secrets,
                report.insecure_patterns,
                report.weak_crypto,
                report.permissive_cors,
                report.tainted_flows
            );
            // A repository that ships fixtures of fake leaked credentials to
            // exercise its own detection has every finding land in one. Without
            // the split the count reads as that many leaks.
            let downranked = report
                .findings
                .iter()
                .filter(|finding| finding.severity == Severity::Low)
                .count();
            if downranked > 0 {
                println!("  {downranked} of them in test or fixture files, ranked low");
            }
            for finding in &report.findings {
                println!();
                anstream::println!("{} {}", severity_tag(finding.severity), finding.title);
                for evidence in &finding.evidence {
                    println!("  Evidence: {}", format_evidence(evidence));
                }
            }
            if report.total == 0 {
                println!("  (no security findings)");
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(crate) struct AuditReport {
    packages_scanned: usize,
    advisories_loaded: usize,
    vulnerabilities: usize,
    /// Lockfiles present but unreadable. A scan of 0 packages means "nothing
    /// declares dependencies here" only while this is empty.
    unreadable_lockfiles: Vec<String>,
    pub(crate) findings: Vec<FindingRecord>,
}

pub(crate) fn load_audit_report(paths: &ProjectPaths, fetch: bool) -> Result<AuditReport> {
    let scan = ovecc_audit::discover_packages(&paths.root);
    if fetch {
        let (written, queried) =
            ovecc_audit::fetch_advisories(&scan.packages, &paths.ovecc_dir.join("osv")).map_err(
                |error| OveccError::Repository {
                    message: format!("audit --fetch failed: {error:#}"),
                },
            )?;
        eprintln!("Fetched {written} new advisory(ies) for {queried} package(s).");
    }
    let osv = ovecc_audit::load_osv_dir(&paths.ovecc_dir.join("osv"));
    let findings = ovecc_audit::audit(&paths.repository_id().0, None, &scan.packages, &osv);
    Ok(AuditReport {
        packages_scanned: scan.packages.len(),
        advisories_loaded: osv.len(),
        vulnerabilities: findings.len(),
        unreadable_lockfiles: scan.unreadable,
        findings,
    })
}

/// The one line worth adding under an audit that reported nothing. Ordered by
/// how badly it misleads: a lockfile that could not be read is a broken run, no
/// lockfile at all is a repository with nothing to audit, and an empty advisory
/// directory is the one case a single command fixes.
fn audit_note(report: &AuditReport) -> Option<String> {
    if let Some(first) = report.unreadable_lockfiles.first() {
        return Some(format!(
            "lockfile unreadable, so no dependency was audited — {first}"
        ));
    }
    if report.packages_scanned == 0 {
        return Some(
            "no package-lock.json at the repository root, the only lockfile format \
             audit reads today"
                .to_string(),
        );
    }
    if report.advisories_loaded == 0 {
        return Some(
            "no OSV database in .ovecc/osv/ — run `ovecc audit --fetch` once to download the \
             advisories for these packages"
                .to_string(),
        );
    }
    (report.vulnerabilities == 0).then(|| "no known vulnerabilities".to_string())
}

pub(crate) fn render_audit(report: &AuditReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("audit", report, meta_for("audit"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("audit", &meta_for("audit"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("vulnerability", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Dependency audit (OSV)");
            println!();
            println!("- Packages scanned: {}", report.packages_scanned);
            println!("- Advisories loaded: {}", report.advisories_loaded);
            println!("- Vulnerabilities: {}", report.vulnerabilities);
            if let Some(note) = audit_note(report) {
                println!();
                println!("> {note}");
            }
            for finding in &report.findings {
                println!();
                println!("## [{:?}] {}", finding.severity, finding.title);
                println!("- {}", finding.description);
            }
        }
        OutputFormat::Text => {
            println!(
                "Dependency audit (OSV): scanned {} package(s) against {} advisor(ies)",
                report.packages_scanned, report.advisories_loaded
            );
            println!("Vulnerabilities: {}", report.vulnerabilities);
            for finding in &report.findings {
                println!();
                anstream::println!("{} {}", severity_tag(finding.severity), finding.title);
            }
            if let Some(note) = audit_note(report) {
                println!("  ({note})");
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(crate) struct HealthReport {
    high_complexity_functions: usize,
    /// Long function / long parameter list — counted alongside complexity so
    /// "0 high-complexity" is never shown while size findings exist.
    oversized_units: usize,
    findings: Vec<FindingRecord>,
}

pub(crate) fn load_health_report(paths: &ProjectPaths) -> Result<HealthReport> {
    let store = open_store(paths)?;
    let mut findings: Vec<FindingRecord> = store
        .findings(&paths.repository_id().0, None)?
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::HighComplexity
                    | FindingKind::LongFunction
                    | FindingKind::LongParameterList
            )
        })
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
    });
    Ok(HealthReport {
        high_complexity_functions: findings
            .iter()
            .filter(|f| f.kind == FindingKind::HighComplexity)
            .count(),
        oversized_units: findings
            .iter()
            .filter(|f| {
                matches!(
                    f.kind,
                    FindingKind::LongFunction | FindingKind::LongParameterList
                )
            })
            .count(),
        findings,
    })
}

pub(crate) fn render_fix(report: &crate::fix::FixReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("fix", report, meta_for("fix"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("fix", &meta_for("fix"))?;
            for action in &report.actions {
                println!("{}", ndjson_line("fix", action)?);
            }
        }
        OutputFormat::Markdown | OutputFormat::Text => {
            let mode = if report.applied {
                "applied"
            } else {
                "dry-run (pass --apply to write)"
            };
            println!(
                "Fix {}: {} change(s), {} skipped — {}",
                if report.applied { "applied" } else { "plan" },
                report.fixed,
                report.skipped,
                mode
            );
            for action in &report.actions {
                println!();
                let location = match action.line {
                    Some(line) => format!("{}:{line}", action.file),
                    None => action.file.clone(),
                };
                println!(
                    "[{}] {} — {} ({})",
                    action.status, action.fix, location, action.rule
                );
                println!("    {}", action.detail);
            }
            if report.actions.is_empty() {
                println!("  (no auto-fixable findings — run `ovecc deadcode` to see candidates)");
            } else if report.applied && report.fixed > 0 {
                println!();
                println!("Re-run `ovecc index` to refresh the model.");
            }
        }
    }
    Ok(())
}

pub(crate) fn render_health(report: &HealthReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("health", report, meta_for("health"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("health", &meta_for("health"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("complexity", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Health: {} high-complexity function(s), {} oversized unit(s)",
                report.high_complexity_functions, report.oversized_units
            );
            println!();
            if report.findings.is_empty() {
                println!("_No functions over the complexity or size thresholds._");
            }
            for finding in &report.findings {
                println!(
                    "- [{:?}] {}{}",
                    finding.severity,
                    finding.title,
                    first_evidence(finding)
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "Code health: {} high-complexity function(s), {} oversized unit(s)",
                report.high_complexity_functions, report.oversized_units
            );
            for finding in &report.findings {
                println!();
                anstream::println!("{} {}", severity_tag(finding.severity), finding.title);
                for evidence in &finding.evidence {
                    println!("  {}", format_evidence(evidence));
                }
            }
            if report.findings.is_empty() {
                println!("  (no functions over the complexity or size thresholds)");
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(crate) struct DeadcodeReport {
    unused_exports: usize,
    unused_files: usize,
    unused_dependencies: usize,
    unlisted_dependencies: usize,
    entry_points: Option<usize>,
    export_analyzable_files: usize,
    pub(crate) findings: Vec<FindingRecord>,
}

pub(crate) fn load_deadcode_report(
    paths: &ProjectPaths,
    changed_since: Option<&str>,
) -> Result<DeadcodeReport> {
    let store = open_store(paths)?;
    let mut findings: Vec<FindingRecord> = store
        .findings(&paths.repository_id().0, None)?
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::UnusedExport
                    | FindingKind::UnusedFile
                    | FindingKind::UnusedDependency
                    | FindingKind::UnlistedDependency
            )
        })
        .collect();
    if let Some(reference) = changed_since {
        filter_changed_since(&mut findings, &paths.root, reference)?;
    }
    let repository_id = paths.repository_id().0;
    let entry_points = store
        .metric_history(&repository_id, "deadcode_entry_points", 1)?
        .first()
        .map(|(_, _, _, value)| *value as usize);
    let export_analyzable_files = store
        .current_files(&repository_id)?
        .iter()
        .filter(|file| {
            matches!(
                file.language.as_str(),
                "javascript" | "jsx" | "typescript" | "tsx"
            )
        })
        .count();
    Ok(DeadcodeReport {
        unused_exports: findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnusedExport)
            .count(),
        unused_files: findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnusedFile)
            .count(),
        unused_dependencies: findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnusedDependency)
            .count(),
        unlisted_dependencies: findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnlistedDependency)
            .count(),
        entry_points,
        export_analyzable_files,
        findings,
    })
}

fn deadcode_coverage_note(report: &DeadcodeReport) -> String {
    match report.entry_points {
        Some(0) => "analysis skipped: no entry points detected — declare a main/bin/exports \
                    entry in the package manifest"
            .to_string(),
        Some(count) if report.export_analyzable_files == 0 => format!(
            "none — file reachability checked from {count} entry point(s); unused-export \
             analysis needs JS/TS sources and none are indexed"
        ),
        Some(count) => format!(
            "none — {count} entry point(s), {} JS/TS file(s) analyzed",
            report.export_analyzable_files
        ),
        None => {
            "none — or no entry points detected; re-index to record analysis coverage".to_string()
        }
    }
}

pub(crate) fn render_deadcode(report: &DeadcodeReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json_with_fix("deadcode", report)?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("deadcode", &meta_for("deadcode"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("dead_code", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Dead code ({} unused export(s), {} unused file(s), {} unused dependency(ies), {} unlisted dependency(ies))",
                report.unused_exports,
                report.unused_files,
                report.unused_dependencies,
                report.unlisted_dependencies
            );
            println!();
            if report.findings.is_empty() {
                println!("_{}_", deadcode_coverage_note(report));
            }
            for finding in &report.findings {
                println!(
                    "- [{:?}] {}{}",
                    finding.severity,
                    finding.title,
                    first_evidence(finding)
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "Dead code: {} unused export(s), {} unused file(s), {} unused dependency(ies), {} unlisted dependency(ies)",
                report.unused_exports,
                report.unused_files,
                report.unused_dependencies,
                report.unlisted_dependencies
            );
            for finding in &report.findings {
                println!();
                anstream::println!("{} {}", severity_tag(finding.severity), finding.title);
                for evidence in &finding.evidence {
                    println!("  {}", format_evidence(evidence));
                }
            }
            if report.findings.is_empty() {
                println!("  ({})", deadcode_coverage_note(report));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadcode_note_states_what_was_analyzed() {
        let report = |entry_points, export_analyzable_files| DeadcodeReport {
            unused_exports: 0,
            unused_files: 0,
            unused_dependencies: 0,
            unlisted_dependencies: 0,
            entry_points,
            export_analyzable_files,
            findings: Vec::new(),
        };
        assert!(deadcode_coverage_note(&report(Some(0), 9)).starts_with("analysis skipped"));
        let rust_only = deadcode_coverage_note(&report(Some(3), 0));
        assert!(rust_only.contains("3 entry point(s)"), "{rust_only}");
        assert!(rust_only.contains("needs JS/TS sources"), "{rust_only}");
        let covered = deadcode_coverage_note(&report(Some(2), 14));
        assert!(covered.contains("2 entry point(s)"), "{covered}");
        assert!(covered.contains("14 JS/TS file(s)"), "{covered}");
        assert!(deadcode_coverage_note(&report(None, 5)).contains("re-index"));
    }

    fn finding(severity: Severity, rule: &str) -> FindingRecord {
        FindingRecord {
            id: ovecc_core::id::FindingId::from_raw("finding:1"),
            repository_id: ovecc_core::id::RepositoryId::from_raw("repo:1"),
            snapshot_id: None,
            kind: FindingKind::CircularDependency,
            severity,
            rule_name: Some(rule.to_string()),
            target: None,
            title: "t".to_string(),
            description: "d".to_string(),
            evidence: Vec::new(),
            created_at: Default::default(),
        }
    }

    #[test]
    fn window_pages_and_zero_limit_means_everything() {
        let findings: Vec<FindingRecord> = (0..5)
            .map(|_| finding(Severity::Low, "complexity"))
            .collect();

        assert_eq!(window(&findings, 2, 0).len(), 2);
        assert_eq!(window(&findings, 2, 4).len(), 1, "last page is short");
        assert_eq!(window(&findings, 0, 0).len(), 5, "limit 0 is the full set");
        // An offset past the end is empty, not a panic.
        assert!(window(&findings, 2, 99).is_empty());
        assert_eq!(window(&findings, 99, 0).len(), 5);
    }

    #[test]
    fn tallies_and_note_describe_the_whole_set_not_the_page() {
        let mut findings = vec![finding(Severity::High, "security/eval")];
        findings.extend((0..3).map(|_| finding(Severity::Low, "complexity")));

        assert_eq!(
            severity_tally(&findings),
            vec![("high", 1), ("low", 3)],
            "absent severities are dropped, order is worst-first"
        );
        assert_eq!(
            rule_tally(&findings, 3),
            vec![
                ("complexity".to_string(), 3),
                ("security/eval".to_string(), 1)
            ]
        );

        let note = truncation_note(4, 2, 0).expect("a cut list is announced");
        assert!(note.contains("Showing 1-2 of 4"), "{note}");
        assert!(
            note.contains("--limit 0"),
            "the way out is in the note: {note}"
        );
        assert!(
            truncation_note(4, 4, 0).is_none(),
            "a complete list says nothing"
        );
    }
}
