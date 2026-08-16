//! The diagnosis family: `diagnose`, `advise`, and `metrics`, plus the
//! SARIF / Code Climate emitters specific to diagnoses (which have no
//! persisted id, so location and fingerprint are derived here).

use super::open_store;
use crate::cli::{FailOn, GroupByArg};
use crate::render::{
    emit_json, emit_ndjson_meta, enrich_findings_with_fix, format_evidence, meta_for, ndjson_line,
    severity_tag,
};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, OveccConfig, ProjectPaths};
use ovecc_core::facts::{FindingRecord, Severity};

/// What the diagnosis engine consumes: files, file -> file edges, per-file
/// churn, per-file complexity, per-file (abstract_types, total_types), and
/// co-change pairs.
type DiagnoseInputs = (
    Vec<String>,
    Vec<ovecc_graph::diagnose::FileDep>,
    std::collections::HashMap<String, f64>,
    std::collections::HashMap<String, f64>,
    std::collections::HashMap<String, (f64, f64)>,
    Vec<(String, String, f64)>,
);

pub(crate) fn diagnose_config_for(
    paths: &ProjectPaths,
    config: &OveccConfig,
) -> ovecc_core::config::DiagnoseConfig {
    let mut diagnose = config.diagnose.clone();
    if diagnose.component_roots.is_empty() {
        diagnose.component_roots = ovecc_indexer::manifest_component_roots(&paths.root);
    }
    diagnose
}

/// Each indexed file with the module the directory heuristic named for it, and
/// the in-repository file→file import edges.
pub(crate) type ComponentInputs = (Vec<(String, String)>, Vec<ovecc_graph::diagnose::FileDep>);

/// The dependency graph every component-granularity view starts from.
pub(crate) fn load_component_inputs(paths: &ProjectPaths) -> Result<ComponentInputs> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    // Every indexed file, so components with no edges still count toward size.
    let file_modules = store.file_modules(&repository_id)?;
    let file_deps: Vec<ovecc_graph::diagnose::FileDep> = store
        .current_dependencies(&repository_id)?
        .into_iter()
        .filter(|dependency| !dependency.is_external)
        .filter_map(|dependency| {
            dependency
                .target_file_path
                .map(|target| ovecc_graph::diagnose::FileDep {
                    source: dependency.source_file_path,
                    target,
                    specifier: dependency.specifier,
                    line: dependency.evidence_line,
                    type_only: dependency.dependency_kind == "type_import",
                })
        })
        .collect();
    Ok((file_modules, file_deps))
}

fn load_diagnose_inputs(paths: &ProjectPaths) -> Result<DiagnoseInputs> {
    let (file_modules, file_deps) = load_component_inputs(paths)?;
    let files: Vec<String> = file_modules.into_iter().map(|(path, _)| path).collect();
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let churn: std::collections::HashMap<String, f64> =
        store.file_churn(&repository_id)?.into_iter().collect();
    let complexity: std::collections::HashMap<String, f64> =
        store.file_complexity(&repository_id)?.into_iter().collect();
    let abstractness: std::collections::HashMap<String, (f64, f64)> = store
        .file_abstractness(&repository_id)?
        .into_iter()
        .map(|(path, abs, tot)| (path, (abs, tot)))
        .collect();
    let co_change = store.co_change_pairs(&repository_id)?;
    Ok((files, file_deps, churn, complexity, abstractness, co_change))
}

pub(crate) fn run_diagnose(
    paths: &ProjectPaths,
    target: Option<&str>,
    min_severity: Option<Severity>,
    cfg: &ovecc_graph::diagnose::DiagnoseConfig,
) -> Result<ovecc_graph::diagnose::DiagnoseReport> {
    let (files, file_deps, churn, complexity, abstractness, co_change) =
        load_diagnose_inputs(paths)?;
    let report = ovecc_graph::diagnose::diagnose(
        &files,
        &file_deps,
        &churn,
        &complexity,
        &abstractness,
        &co_change,
        cfg,
    );
    let components = report.components;
    let mut findings = report.findings;
    if let Some(min) = min_severity {
        findings.retain(|finding| finding.severity >= min);
    }
    if let Some(needle) = target.map(normalize_target) {
        // A target names a component *or* a file inside one: matching the
        // evidence files too lets `--target src/foo.ts` surface the smells
        // whose evidence cites that file.
        findings.retain(|finding| {
            finding.target.to_ascii_lowercase().contains(&needle)
                || finding.evidence.iter().any(|evidence| {
                    evidence
                        .file
                        .as_deref()
                        .is_some_and(|file| file.to_ascii_lowercase().contains(&needle))
                })
        });
    }
    Ok(ovecc_graph::diagnose::DiagnoseReport::new(
        components, findings,
    ))
}

/// '/'-separated and lowercase, so Windows-style `src\utils\helpers.ts`
/// matches the stored '/'-normalized paths.
fn normalize_target(target: &str) -> String {
    target.replace('\\', "/").to_ascii_lowercase()
}

fn finding_touches(finding: &FindingRecord, needle: &str) -> bool {
    let matches = |text: &str| {
        text.replace('\\', "/")
            .to_ascii_lowercase()
            .contains(needle)
    };
    finding.evidence.iter().any(|evidence| {
        matches(&evidence.file_path) || evidence.symbol.as_deref().is_some_and(matches)
    }) || finding.target.as_ref().is_some_and(|t| matches(&t.id))
}

pub(crate) fn load_advise(
    paths: &ProjectPaths,
    cfg: &ovecc_graph::diagnose::DiagnoseConfig,
    target: &str,
) -> Result<(Vec<FindingRecord>, ovecc_graph::diagnose::DiagnoseReport)> {
    let store = open_store(paths)?;
    let needle = normalize_target(target);
    let findings: Vec<FindingRecord> = store
        .findings(&paths.repository_id().0, None)?
        .into_iter()
        .filter(|finding| finding_touches(finding, &needle))
        .collect();
    // run_diagnose reopens the database, and DuckDB allows only one open
    // handle per file — release this one first.
    drop(store);
    let report = run_diagnose(paths, Some(target), None, cfg)?;
    Ok((findings, report))
}

pub(crate) fn render_advise(
    target: &str,
    findings: &[FindingRecord],
    smells: &ovecc_graph::diagnose::DiagnoseReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        // SARIF/CodeClimate degrade to the JSON envelope: advise is the agent
        // surface, not a CI feed.
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            let mut findings_value =
                serde_json::to_value(findings).unwrap_or(serde_json::Value::Null);
            enrich_findings_with_fix(&mut findings_value);
            let smell_values: Vec<serde_json::Value> =
                smells.findings.iter().map(diagnosis_value).collect();
            let data = serde_json::json!({
                "target": target,
                "findings": findings_value,
                "smells": smell_values,
                "total": findings.len() + smells.findings.len(),
            });
            emit_json("advise", &data, meta_for("advise"))?;
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("advise", &meta_for("advise"))?;
            for finding in findings {
                println!("{}", ndjson_line("violation", finding)?);
            }
            for smell in &smells.findings {
                println!("{}", ndjson_line("diagnosis", &diagnosis_value(smell))?);
            }
        }
        OutputFormat::Markdown => advise_markdown(target, findings, smells),
        OutputFormat::Text => advise_text(target, findings, smells),
    }
    Ok(())
}

fn advise_markdown(
    target: &str,
    findings: &[FindingRecord],
    smells: &ovecc_graph::diagnose::DiagnoseReport,
) {
    println!("# Advise: `{target}`");
    println!();
    println!(
        "{} finding(s), {} design smell(s)",
        findings.len(),
        smells.findings.len()
    );
    for finding in findings {
        let fix = finding.kind.fix_spec();
        println!();
        println!("## [{:?}] {}", finding.severity, finding.title);
        if let Some(rule) = &finding.rule_name {
            println!("- Rule: `{rule}`");
        }
        println!("- {}", finding.description);
        for evidence in &finding.evidence {
            println!("- Evidence: `{}`", format_evidence(evidence));
        }
        println!(
            "- Fix: {} (`{}`, auto-fixable: {})",
            fix.instruction,
            fix.kind,
            if fix.auto_fixable { "yes" } else { "no" }
        );
    }
    for smell in &smells.findings {
        println!();
        println!(
            "## [{:?}] {} — `{}`",
            smell.severity, smell.title, smell.target
        );
        println!("- Principle: {}", smell.principle);
        for evidence in &smell.evidence {
            println!("- Evidence: `{}`", fmt_diag_evidence(evidence));
        }
        println!(
            "- Fix: {} ({})",
            smell.remediation.summary, smell.remediation.refactoring
        );
        if let Some(note) = &smell.remediation.when_not_to_act {
            println!("- When not to act: {note}");
        }
    }
    if findings.is_empty() && smells.findings.is_empty() {
        println!();
        println!("Nothing touches `{target}` — safe to edit.");
    }
}

fn advise_text(
    target: &str,
    findings: &[FindingRecord],
    smells: &ovecc_graph::diagnose::DiagnoseReport,
) {
    println!(
        "Advise for {target}: {} finding(s), {} design smell(s)",
        findings.len(),
        smells.findings.len()
    );
    for finding in findings {
        let fix = finding.kind.fix_spec();
        println!();
        anstream::println!("{} {}", severity_tag(finding.severity), finding.title);
        if let Some(rule) = &finding.rule_name {
            println!("  Rule: {rule}");
        }
        for evidence in &finding.evidence {
            println!("  Evidence: {}", format_evidence(evidence));
        }
        println!(
            "  Fix: {} (auto-fixable: {})",
            fix.instruction,
            if fix.auto_fixable { "yes" } else { "no" }
        );
    }
    for smell in &smells.findings {
        println!();
        anstream::println!(
            "{} {} — {}  (confidence {:.2})",
            severity_tag(smell.severity),
            smell.title,
            smell.target,
            smell.confidence
        );
        let evidence: Vec<String> = smell.evidence.iter().map(fmt_diag_evidence).collect();
        println!("  Evidence: {}", evidence.join(", "));
        println!(
            "  Fix: {} [{}]",
            smell.remediation.summary, smell.remediation.refactoring
        );
    }
    if findings.is_empty() && smells.findings.is_empty() {
        println!("  (nothing touches this target — safe to edit)");
    }
}

pub(crate) fn diagnose_exit(
    report: &ovecc_graph::diagnose::DiagnoseReport,
    fail_on: Option<FailOn>,
) -> u8 {
    let Some(fail_on) = fail_on else {
        return 0;
    };
    let triggered = match fail_on {
        FailOn::Any => !report.findings.is_empty(),
        FailOn::Medium => report
            .findings
            .iter()
            .any(|f| f.severity >= Severity::Medium),
        FailOn::High => report.findings.iter().any(|f| f.severity >= Severity::High),
    };
    u8::from(triggered)
}

fn fmt_num(value: f64) -> String {
    if value.fract().abs() < 1e-9 {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    }
}

fn fmt_diag_evidence(e: &ovecc_graph::diagnose::DiagEvidence) -> String {
    let mut text = String::new();
    if let Some(file) = &e.file {
        text.push_str(file);
        if let Some(line) = e.line {
            text.push_str(&format!(":{line}"));
        }
        text.push_str(" — ");
    }
    text.push_str(&format!("{}={}", e.metric, fmt_num(e.value)));
    if let Some(threshold) = e.threshold
        && threshold > 0.0
    {
        text.push_str(&format!(" (>= {})", fmt_num(threshold)));
    }
    if let Some(detail) = &e.detail {
        text.push_str(&format!(" ({detail})"));
    }
    text
}

fn diagnosis_value(finding: &ovecc_graph::diagnose::Diagnosis) -> serde_json::Value {
    let mut value = serde_json::to_value(finding).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &mut value {
        let fix = ovecc_graph::diagnose::fix_spec(&finding.detector);
        map.insert(
            "fix".to_string(),
            serde_json::to_value(fix).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn group_diagnoses(
    findings: &[ovecc_graph::diagnose::Diagnosis],
    group_by: Option<GroupByArg>,
) -> Vec<(String, Vec<&ovecc_graph::diagnose::Diagnosis>)> {
    let mut groups: Vec<(String, Vec<&ovecc_graph::diagnose::Diagnosis>)> = Vec::new();
    for finding in findings {
        let label = match group_by {
            None => String::new(),
            Some(GroupByArg::Family) => finding.family.clone(),
            Some(GroupByArg::Severity) => format!("{:?}", finding.severity),
            Some(GroupByArg::Component) => diagnose_location(finding).0,
        };
        match groups.iter_mut().find(|(existing, _)| *existing == label) {
            Some((_, bucket)) => bucket.push(finding),
            None => groups.push((label, vec![finding])),
        }
    }
    groups
}

pub(crate) fn render_diagnose(
    report: &ovecc_graph::diagnose::DiagnoseReport,
    format: OutputFormat,
    group_by: Option<GroupByArg>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let findings: Vec<serde_json::Value> =
                report.findings.iter().map(diagnosis_value).collect();
            let data = serde_json::json!({
                "components": report.components,
                "findings": findings,
                "total": report.total,
                "critical": report.critical,
                "high": report.high,
                "medium": report.medium,
                "low": report.low,
            });
            emit_json("diagnose", &data, meta_for("diagnose"))?
        }
        OutputFormat::Sarif => emit_diagnose_sarif(&report.findings)?,
        OutputFormat::Codeclimate => emit_diagnose_codeclimate(&report.findings)?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("diagnose", &meta_for("diagnose"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("diagnosis", &diagnosis_value(finding))?);
            }
        }
        OutputFormat::Markdown => diagnose_markdown(report, group_by),
        OutputFormat::Text => diagnose_text(report, group_by),
    }
    Ok(())
}

fn diagnose_markdown(report: &ovecc_graph::diagnose::DiagnoseReport, group_by: Option<GroupByArg>) {
    println!("# Diagnosis ({} finding(s))", report.total);
    println!();
    println!(
        "Critical: {} · High: {} · Medium: {} · Low: {}",
        report.critical, report.high, report.medium, report.low
    );
    for (label, bucket) in group_diagnoses(&report.findings, group_by) {
        if !label.is_empty() {
            println!();
            println!("# {} ({})", label, bucket.len());
        }
        for finding in bucket {
            diagnose_markdown_finding(finding);
        }
    }
}

fn diagnose_markdown_finding(finding: &ovecc_graph::diagnose::Diagnosis) {
    println!();
    println!(
        "## [{:?}] {} — `{}`",
        finding.severity, finding.title, finding.target
    );
    println!("- Principle: {}", finding.principle);
    println!("- Confidence: {:.2}", finding.confidence);
    for evidence in &finding.evidence {
        println!("- Evidence: `{}`", fmt_diag_evidence(evidence));
    }
    println!(
        "- Fix: {} ({})",
        finding.remediation.summary, finding.remediation.refactoring
    );
    let fix = ovecc_graph::diagnose::fix_spec(&finding.detector);
    println!(
        "- Action: `{}` (auto-fixable: {})",
        fix.kind,
        if fix.auto_fixable { "yes" } else { "no" }
    );
    if let Some(note) = &finding.remediation.when_not_to_act {
        println!("- When not to act: {note}");
    }
}

fn diagnose_text(report: &ovecc_graph::diagnose::DiagnoseReport, group_by: Option<GroupByArg>) {
    println!(
        "Diagnosis: {} finding(s) — critical {}, high {}, medium {}, low {}",
        report.total, report.critical, report.high, report.medium, report.low
    );
    for (label, bucket) in group_diagnoses(&report.findings, group_by) {
        if !label.is_empty() {
            println!();
            println!("== {} ({}) ==", label, bucket.len());
        }
        for finding in bucket {
            diagnose_text_finding(finding);
        }
    }
    if report.total == 0 {
        println!("  (no findings)");
    }
}

fn diagnose_text_finding(finding: &ovecc_graph::diagnose::Diagnosis) {
    println!();
    anstream::println!(
        "{} {} — {} {}  (confidence {:.2})",
        severity_tag(finding.severity),
        finding.title,
        finding.target_kind,
        finding.target,
        finding.confidence
    );
    println!("  Principle: {}", finding.principle);
    let evidence: Vec<String> = finding.evidence.iter().map(fmt_diag_evidence).collect();
    println!("  Evidence: {}", evidence.join(", "));
    println!(
        "  Fix: {} [{}]",
        finding.remediation.summary, finding.remediation.refactoring
    );
    let fix = ovecc_graph::diagnose::fix_spec(&finding.detector);
    println!(
        "  Action: {} (auto-fixable: {})",
        fix.kind,
        if fix.auto_fixable { "yes" } else { "no" }
    );
    if let Some(note) = &finding.remediation.when_not_to_act {
        println!("  When not to act: {note}");
    }
}

/// A best-effort file/path location for a diagnosis: the first evidence with a
/// concrete file, else a path extracted from the target (the first component of
/// a `a <-> b` pair/group; `.` for the whole-repository target).
fn diagnose_location(finding: &ovecc_graph::diagnose::Diagnosis) -> (String, u32) {
    if let Some(e) = finding.evidence.iter().find(|e| e.file.is_some()) {
        return (e.file.clone().unwrap(), e.line.unwrap_or(1).max(1));
    }
    if finding.target == "<repository>" {
        return (".".to_string(), 1);
    }
    let path = finding
        .target
        .split(" <-> ")
        .next()
        .unwrap_or(&finding.target)
        .split(" … ")
        .next()
        .unwrap_or(&finding.target)
        .trim()
        .to_string();
    (path, 1)
}

/// A stable fingerprint (FNV-1a over `detector|target`) so GitLab can diff a
/// diagnosis across pipelines even though diagnoses have no persisted id.
fn diagnose_fingerprint(finding: &ovecc_graph::diagnose::Diagnosis) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in format!("{}|{}", finding.detector, finding.target).bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// SARIF 2.1.0 (one rule per detector), so diagnoses flow into GitHub code
/// scanning.
fn emit_diagnose_sarif(findings: &[ovecc_graph::diagnose::Diagnosis]) -> Result<()> {
    use std::collections::BTreeMap;
    let mut rules: BTreeMap<String, (String, String)> = BTreeMap::new();
    for f in findings {
        rules
            .entry(f.detector.clone())
            .or_insert_with(|| (f.title.clone(), f.principle.clone()));
    }
    let rule_list: Vec<serde_json::Value> = rules
        .iter()
        .map(|(id, (title, principle))| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": title },
                "fullDescription": { "text": principle },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let (path, line) = diagnose_location(f);
            let message = format!(
                "{} — {}. Fix: {} [{}]",
                f.title, f.principle, f.remediation.summary, f.remediation.refactoring
            );
            serde_json::json!({
                "ruleId": f.detector,
                "level": level,
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": path },
                        "region": { "startLine": line },
                    }
                }],
                "properties": {
                    "family": f.family,
                    "confidence": f.confidence,
                    "target": f.target,
                    "fix": {
                        "kind": ovecc_graph::diagnose::fix_spec(&f.detector).kind,
                        "auto_fixable": ovecc_graph::diagnose::fix_spec(&f.detector).auto_fixable,
                    },
                },
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "ovecc",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Ovecc-labs/ovecc",
                "rules": rule_list,
            }},
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

/// Code Climate / GitLab Code Quality JSON for diagnoses.
fn emit_diagnose_codeclimate(findings: &[ovecc_graph::diagnose::Diagnosis]) -> Result<()> {
    let issues: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let severity = match f.severity {
                Severity::Critical => "blocker",
                Severity::High => "critical",
                Severity::Medium => "major",
                Severity::Low => "minor",
            };
            let (path, line) = diagnose_location(f);
            serde_json::json!({
                "type": "issue",
                "check_name": f.detector,
                "description": format!("{} ({})", f.title, f.target),
                "fingerprint": diagnose_fingerprint(f),
                "severity": severity,
                "location": { "path": path, "lines": { "begin": line } },
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&issues)?);
    Ok(())
}

/// Per-component metrics, optionally scoped to components whose name contains
/// `target`.
pub(crate) fn load_metrics_report(
    paths: &ProjectPaths,
    cfg: &ovecc_graph::diagnose::DiagnoseConfig,
    target: Option<&str>,
) -> Result<ovecc_graph::diagnose::MetricsReport> {
    let (files, file_deps, churn, complexity, abstractness, _co_change) =
        load_diagnose_inputs(paths)?;
    let mut report =
        ovecc_graph::diagnose::metrics(&files, &file_deps, &churn, &complexity, &abstractness, cfg);
    if let Some(t) = target {
        let needle = t.to_ascii_lowercase();
        report
            .components
            .retain(|m| m.component.to_ascii_lowercase().contains(&needle));
    }
    Ok(report)
}

/// Names the graph the density was measured over, and shows the fraction.
///
/// `summary` reports a "coupling density" too, over modules rather than
/// `[diagnose]` components — a different partition with different excludes, so
/// the two numbers differ on the same snapshot. That reads as nondeterminism
/// unless each says what it counted, and determinism is the thing this tool
/// sells.
fn coupling_density_line(report: &ovecc_graph::diagnose::MetricsReport) -> String {
    let basis = if report.coupling_basis.is_empty() {
        "component"
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
        report.coupling_edges,
        report.coupling_possible_edges,
        report.components.len()
    )
}

pub(crate) fn render_metrics(
    report: &ovecc_graph::diagnose::MetricsReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("metrics", report, meta_for("metrics"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("metrics", &meta_for("metrics"))?;
            for component in &report.components {
                println!("{}", ndjson_line("component_metric", component)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Metrics");
            println!();
            println!("{}", coupling_density_line(report));
            println!();
            println!(
                "| Component | Files | Fan-in | Fan-out | Coupling | Instability | Abstractness | Distance | Complexity | Churn |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for m in &report.components {
                println!(
                    "| {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.0} | {:.0} |",
                    m.component,
                    m.files,
                    m.fan_in,
                    m.fan_out,
                    m.coupling,
                    m.instability,
                    m.abstractness,
                    m.distance,
                    m.complexity,
                    m.churn
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "Metrics: {} component(s), {}",
                report.components.len(),
                coupling_density_line(report).to_lowercase()
            );
            for m in &report.components {
                println!();
                println!("{}", m.component);
                println!(
                    "  files {}, fan-in {}, fan-out {}, coupling {}, instability {:.2}",
                    m.files, m.fan_in, m.fan_out, m.coupling, m.instability
                );
                println!(
                    "  abstractness {:.2}, distance {:.2}, complexity {:.0}, churn {:.0}",
                    m.abstractness, m.distance, m.complexity, m.churn
                );
            }
        }
    }
    Ok(())
}
