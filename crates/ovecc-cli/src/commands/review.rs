//! `ovecc review` (the named defects a change introduced) and the one-shot
//! `ovecc report`.

use super::findings::{build_security_report, window};
use super::open_store;
use super::summary::{load_hotspots, load_summary};
use crate::cli::FailOn;
use crate::render::{emit_json, emit_ndjson_meta, first_evidence, meta_for, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, OveccConfig, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::facts::{FindingKind, FindingRecord, Severity};
use ovecc_core::legacy::RiskLevel;
use ovecc_core::report::ChangedFiles;
use ovecc_db::ArchitectureStore;
use ovecc_graph as graph;

/// The named defects a change introduced between two snapshots: the actionable,
/// change-scoped report that `gate` (counts only) cannot give.
#[derive(serde::Serialize)]
pub(crate) struct ReviewReport {
    base: String,
    head: String,
    /// `"pass"` or `"fail"` against `--fail-on`.
    pub(crate) verdict: String,
    /// Calibrated risk band: Low/Medium/High/Critical.
    risk: String,
    /// Human-readable reasons behind the verdict — the explanation `gate` lacks.
    rationale: Vec<String>,
    summary: ReviewSummary,
    /// Each new finding is a full, named record with file:line evidence.
    new_findings: Vec<FindingRecord>,
    /// New dependency cycles, each carrying the file-level witness edges that
    /// form it (so a consumer never has to guess — and mis-guess — the edges).
    new_cycles: Vec<graph::cycles::CycleWitness>,
    /// Clone families the change introduced (scoped to touched files), so new
    /// duplication is not buried under pre-existing repo-wide clones.
    new_duplications: Vec<graph::dupes::CloneFamily>,
    changed_files: ChangedFiles,
}

#[derive(serde::Serialize)]
struct ReviewSummary {
    files_added: usize,
    files_modified: usize,
    new_findings: usize,
    new_security: usize,
    new_dead_code: usize,
    new_complexity: usize,
    new_smells: usize,
    new_cycles: usize,
    new_duplications: usize,
    /// Findings present in base but gone in head — credit for fixes.
    resolved_findings: usize,
}

/// Assembles the change review from the snapshot-diff primitives in `ovecc-db`
/// (named finding diff, changed files) and the graph analyses (cycle witnesses,
/// change-scoped duplication). Head cycle/duplication evidence is drawn from the
/// current index, so this is most precise when `head` is `latest` (the gate
/// workflow: index base, apply change, index, review).
pub(crate) fn build_review_report(
    paths: &ProjectPaths,
    config: &OveccConfig,
    store: &ArchitectureStore,
    base: &str,
    head: &str,
    fail_on: FailOn,
) -> Result<ReviewReport> {
    let repository_id = paths.repository_id().0;

    let base_snapshot = store
        .resolve_snapshot(&repository_id, base)?
        .ok_or_else(|| OveccError::Index {
            message: format!(
                "could not resolve base snapshot '{base}'; index the repository at \
                 least twice (a baseline, then again after the change) so there is a \
                 base to compare against"
            ),
            source: None,
        })?;
    let head_snapshot = store
        .resolve_snapshot(&repository_id, head)?
        .ok_or_else(|| OveccError::Index {
            message: format!("could not resolve head snapshot '{head}'; run 'ovecc index' first"),
            source: None,
        })?;

    // Cycles are surfaced with their witness edges in `new_cycles` below, so
    // the plain CircularDependency findings are dropped here to avoid
    // double-reporting the same cycle.
    let finding_diff = store.finding_diff(&repository_id, &base_snapshot.id, &head_snapshot.id)?;
    let new_findings: Vec<FindingRecord> = finding_diff
        .new
        .into_iter()
        .filter(|finding| finding.kind != FindingKind::CircularDependency)
        .collect();

    let changed_files =
        store.changed_files(&repository_id, &base_snapshot.id, &head_snapshot.id)?;

    let head_modules = store.current_modules(&repository_id)?;
    let head_dependencies = store.current_dependencies(&repository_id)?;
    let base_cycles: std::collections::HashSet<Vec<String>> = graph::cycles::module_cycles(
        &store.snapshot_module_names(&base_snapshot.id)?,
        &store.snapshot_module_edges(&base_snapshot.id)?,
    )
    .into_iter()
    .collect();
    let new_cycles: Vec<graph::cycles::CycleWitness> =
        graph::cycles::elementary_cycles_with_witness(&head_modules, &head_dependencies)
            .into_iter()
            .filter(|cycle| !base_cycles.contains(&cycle.modules))
            .collect();

    // Duplication is scanned repo-wide (that is how a new block is matched
    // against an existing utility) but only families touching a changed file
    // are reported, so pre-existing clones do not drown out what THIS change
    // added.
    let touched: std::collections::HashSet<&str> =
        changed_files.touched().map(String::as_str).collect();
    let new_duplications: Vec<graph::dupes::CloneFamily> = if touched.is_empty() {
        Vec::new()
    } else {
        ovecc_indexer::collect_file_tokens(paths, config)
            // Same-file families count too: a PR that pastes a block twice
            // into one file is still introducing duplication.
            .map(|files| graph::dupes::detect(&files, 50, 5, false))
            .unwrap_or_default()
            .into_iter()
            .filter(|family| {
                family
                    .instances
                    .iter()
                    .any(|instance| touched.contains(instance.path.as_str()))
            })
            .collect()
    };

    let count_kinds = |kinds: &[FindingKind]| {
        new_findings
            .iter()
            .filter(|finding| kinds.contains(&finding.kind))
            .count()
    };
    let new_security = count_kinds(&[
        FindingKind::HardcodedSecret,
        FindingKind::InsecurePattern,
        FindingKind::WeakCrypto,
        FindingKind::PermissiveCors,
        FindingKind::VulnerableDependency,
        FindingKind::TaintedFlow,
    ]);
    let new_dead_code = count_kinds(&[
        FindingKind::UnusedExport,
        FindingKind::UnusedFile,
        FindingKind::UnusedDependency,
        FindingKind::UnlistedDependency,
    ]);
    let new_complexity = count_kinds(&[
        FindingKind::HighComplexity,
        FindingKind::LongFunction,
        FindingKind::LongParameterList,
    ]);
    let new_smells = count_kinds(&[
        FindingKind::FeatureEnvy,
        FindingKind::LargeClass,
        FindingKind::DataClumps,
    ]);
    let max_new_severity = new_findings.iter().map(|finding| finding.severity).max();

    let failed = review_crosses_threshold(
        fail_on,
        &new_findings,
        &new_cycles,
        &new_duplications,
        max_new_severity,
    );
    let risk = review_risk(max_new_severity, &new_cycles, &new_duplications);
    let rationale = review_rationale(
        &new_cycles,
        new_security,
        new_complexity,
        new_dead_code,
        new_smells,
        &new_duplications,
    );

    Ok(ReviewReport {
        base: base_snapshot.id,
        head: head_snapshot.id,
        verdict: if failed { "fail" } else { "pass" }.to_string(),
        risk: risk.as_str().to_string(),
        rationale,
        summary: ReviewSummary {
            files_added: changed_files.added.len(),
            files_modified: changed_files.modified.len(),
            new_findings: new_findings.len(),
            new_security,
            new_dead_code,
            new_complexity,
            new_smells,
            new_cycles: new_cycles.len(),
            new_duplications: new_duplications.len(),
            resolved_findings: finding_diff.resolved.len(),
        },
        new_findings,
        new_cycles,
        new_duplications,
        changed_files,
    })
}

/// A new cycle always fails (it is an architectural regression); findings
/// fail by severity; duplication only counts under `any`.
fn review_crosses_threshold(
    fail_on: FailOn,
    new_findings: &[FindingRecord],
    new_cycles: &[graph::cycles::CycleWitness],
    new_duplications: &[graph::dupes::CloneFamily],
    max_new_severity: Option<Severity>,
) -> bool {
    match fail_on {
        FailOn::Any => {
            !new_findings.is_empty() || !new_cycles.is_empty() || !new_duplications.is_empty()
        }
        FailOn::Medium => !new_cycles.is_empty() || max_new_severity >= Some(Severity::Medium),
        FailOn::High => !new_cycles.is_empty() || max_new_severity >= Some(Severity::High),
    }
}

fn review_risk(
    max_new_severity: Option<Severity>,
    new_cycles: &[graph::cycles::CycleWitness],
    new_duplications: &[graph::dupes::CloneFamily],
) -> RiskLevel {
    if max_new_severity == Some(Severity::Critical) {
        RiskLevel::Critical
    } else if !new_cycles.is_empty() || max_new_severity == Some(Severity::High) {
        RiskLevel::High
    } else if max_new_severity == Some(Severity::Medium) || !new_duplications.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn review_rationale(
    new_cycles: &[graph::cycles::CycleWitness],
    new_security: usize,
    new_complexity: usize,
    new_dead_code: usize,
    new_smells: usize,
    new_duplications: &[graph::dupes::CloneFamily],
) -> Vec<String> {
    let mut rationale = Vec::new();
    if !new_cycles.is_empty() {
        let names: Vec<String> = new_cycles
            .iter()
            .map(|cycle| format_cycle_path(&cycle.modules, " ↔ ", " → "))
            .collect();
        rationale.push(format!(
            "{} new dependency cycle(s): {}",
            new_cycles.len(),
            names.join("; ")
        ));
    }
    if new_security > 0 {
        rationale.push(format!("{new_security} new security finding(s)"));
    }
    if new_complexity > 0 {
        rationale.push(format!("{new_complexity} new high-complexity function(s)"));
    }
    if new_dead_code > 0 {
        rationale.push(format!("{new_dead_code} new dead-code finding(s)"));
    }
    if new_smells > 0 {
        rationale.push(format!(
            "{new_smells} new code smell(s) (feature envy / large class / data clumps)"
        ));
    }
    if !new_duplications.is_empty() {
        rationale.push(format!("{} new duplication(s)", new_duplications.len()));
    }
    if rationale.is_empty() {
        rationale.push("no new defects introduced by this change".to_string());
    }
    rationale
}

/// A 2-node loop is genuinely bidirectional (`a ↔ b`); a longer loop is
/// directed, so it reads as the path back to the start (`a → b → c → a`)
/// rather than a misleading `a ↔ b ↔ c`.
fn format_cycle_path(modules: &[String], bidi: &str, arrow: &str) -> String {
    match modules.first() {
        Some(first) if modules.len() >= 3 => {
            let mut path = modules.join(arrow);
            path.push_str(arrow);
            path.push_str(first);
            path
        }
        _ => modules.join(bidi),
    }
}

pub(crate) fn render_review(report: &ReviewReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("review", report, meta_for("review"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("review", &meta_for("review"))?;
            println!("{}", ndjson_line("review_summary", &report.summary)?);
            for finding in &report.new_findings {
                println!("{}", ndjson_line("new_finding", finding)?);
            }
            for cycle in &report.new_cycles {
                println!("{}", ndjson_line("new_cycle", cycle)?);
            }
            for family in &report.new_duplications {
                println!("{}", ndjson_line("new_duplication", family)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Change review: {}", report.verdict.to_uppercase());
            println!();
            println!("- Base: `{}`", report.base);
            println!("- Head: `{}`", report.head);
            println!("- Risk: **{}**", report.risk);
            println!(
                "- Files: +{} added, ~{} modified",
                report.summary.files_added, report.summary.files_modified
            );
            for reason in &report.rationale {
                println!("- {reason}");
            }

            println!();
            println!("## New dependency cycles ({})", report.new_cycles.len());
            if report.new_cycles.is_empty() {
                println!("_None._");
            }
            for cycle in &report.new_cycles {
                println!();
                println!("### {}", format_cycle_path(&cycle.modules, " ↔ ", " → "));
                for edge in &cycle.edges {
                    let target = edge.to_file.as_deref().unwrap_or(edge.to_module.as_str());
                    println!(
                        "- `{}:{}` imports `{}` → `{}`",
                        edge.from_file, edge.line, edge.specifier, target
                    );
                }
            }

            println!();
            println!("## New findings ({})", report.new_findings.len());
            if report.new_findings.is_empty() {
                println!("_None._");
            }
            for finding in &report.new_findings {
                let rule = finding.rule_name.as_deref().unwrap_or("-");
                let fix = finding.kind.fix_spec();
                let auto = if fix.auto_fixable {
                    ", auto-fixable"
                } else {
                    ""
                };
                println!(
                    "- **[{:?}] {:?}**{} — {} _(rule `{}`)_ · action: `{}`{}",
                    finding.severity,
                    finding.kind,
                    first_evidence(finding),
                    finding.title,
                    rule,
                    fix.kind,
                    auto
                );
            }

            println!();
            println!("## New duplications ({})", report.new_duplications.len());
            if report.new_duplications.is_empty() {
                println!("_None._");
            }
            for (rank, family) in report.new_duplications.iter().enumerate() {
                println!();
                println!(
                    "### Clone {} ({} tokens, {} lines, {} copies)",
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
                "Review: {} (risk {}) {} -> {}",
                report.verdict, report.risk, report.base, report.head
            );
            for reason in &report.rationale {
                println!("  - {reason}");
            }
            if !report.new_cycles.is_empty() {
                println!("New cycles:");
                for cycle in &report.new_cycles {
                    println!("  {}", format_cycle_path(&cycle.modules, " <-> ", " -> "));
                    for edge in &cycle.edges {
                        println!(
                            "    {}:{} imports {} -> {}",
                            edge.from_file,
                            edge.line,
                            edge.specifier,
                            edge.to_file.as_deref().unwrap_or(edge.to_module.as_str())
                        );
                    }
                }
            }
            if !report.new_findings.is_empty() {
                println!("New findings:");
                for finding in &report.new_findings {
                    println!(
                        "  [{:?}] {:?}{} {}",
                        finding.severity,
                        finding.kind,
                        first_evidence(finding),
                        finding.title
                    );
                }
            }
            if !report.new_duplications.is_empty() {
                println!("New duplications:");
                for family in &report.new_duplications {
                    println!(
                        "  {} tokens / {} lines / {} copies",
                        family.token_length,
                        family.line_span,
                        family.instances.len()
                    );
                    for instance in &family.instances {
                        println!(
                            "    {}:{}-{}",
                            instance.path, instance.start_line, instance.end_line
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// One-shot report stitching health, cycles, findings, security, and hotspots.
/// Markdown for humans; structured JSON for agents.
/// `limit` cuts the findings list; every count, the cycles, and the security
/// tallies stay whole. This is the surface agents call first, so the default
/// page has to leave room for the rest of their context: Django's report
/// serialized to ~404k tokens with the findings uncut.
pub(crate) fn render_full_report(
    paths: &ProjectPaths,
    format: OutputFormat,
    limit: usize,
) -> Result<()> {
    let repository_id = paths.repository_id().0;
    // `load_summary` and `load_hotspots` each open and release their own store,
    // so gather them before opening one here: DuckDB permits only one
    // connection per file per process.
    let summary = load_summary(paths)?;
    let hotspots = load_hotspots(paths, 10)?;

    let store = open_store(paths)?;
    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let cycles: Vec<Vec<String>> = ovecc_graph::cycles::elementary_cycles(&modules, &dependencies)
        .into_iter()
        .map(|mut members| {
            if let Some(first) = members.first().cloned() {
                members.push(first);
            }
            members
        })
        .collect();
    let mut findings = store.findings(&repository_id, None)?;
    drop(store);
    // Highest severity first, then stable by title, for deterministic output.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
    });
    let security = build_security_report(&findings, None);
    let shown = window(&findings, limit, 0);
    let note = (shown.len() < findings.len()).then(|| {
        format!(
            "Showing the {} highest-severity of {} findings. `ovecc violations \
             --severity high --limit 0` lists them.",
            shown.len(),
            findings.len()
        )
    });

    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            // Security findings are a subset of `findings`, so the list is left
            // out here rather than shipped twice; the tallies are the point, and
            // `ovecc security` has the records.
            let data = serde_json::json!({
                "summary": summary,
                "cycles": cycles,
                "total_findings": findings.len(),
                "shown_findings": shown.len(),
                "findings": shown,
                "security": {
                    "secrets": security.secrets,
                    "insecure_patterns": security.insecure_patterns,
                    "weak_crypto": security.weak_crypto,
                    "permissive_cors": security.permissive_cors,
                    "tainted_flows": security.tainted_flows,
                    "total": security.total,
                },
                "hotspots": hotspots,
                "note": note,
            });
            emit_json("report", &data, meta_for("report"))?;
        }
        _ => {
            println!("# Architecture report: {}", summary.repository_root);
            println!();
            println!("## Health");
            println!();
            println!(
                "- Files: {} · Modules: {} · Dependencies: {} ({} external)",
                summary.files, summary.modules, summary.dependencies, summary.external_dependencies
            );
            println!(
                "- Circular dependencies: {} · Coupling density: {:.2}% · Risk: **{}**",
                summary.circular_dependencies,
                summary.coupling_density * 100.0,
                summary.risk_score.as_str()
            );
            println!();
            println!("## Circular dependencies ({})", cycles.len());
            println!();
            if cycles.is_empty() {
                println!("_None._");
            }
            for cycle in &cycles {
                println!("- `{}`", cycle.join(" -> "));
            }
            println!();
            println!("## Findings ({})", findings.len());
            println!();
            if findings.is_empty() {
                println!("_None._");
            }
            for finding in shown {
                println!(
                    "- [{:?}] {}{}",
                    finding.severity,
                    finding.title,
                    first_evidence(finding)
                );
            }
            if let Some(note) = &note {
                println!();
                println!("{note}");
            }
            println!();
            println!("## Security");
            println!();
            println!(
                "- Secrets {}, insecure {}, weak-crypto {}, CORS {}, tainted-flows {} (total {})",
                security.secrets,
                security.insecure_patterns,
                security.weak_crypto,
                security.permissive_cors,
                security.tainted_flows,
                security.total
            );
            println!();
            println!("## Hotspots");
            println!();
            if hotspots.hotspots.is_empty() {
                println!("_None._");
            }
            for (rank, hotspot) in hotspots.hotspots.iter().enumerate() {
                println!(
                    "{}. {} (score {:.0}, fan-in {}, fan-out {})",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    hotspot.fan_in,
                    hotspot.fan_out
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cycle(a: &str, b: &str) -> graph::cycles::CycleWitness {
        graph::cycles::CycleWitness {
            modules: vec![a.to_string(), b.to_string()],
            edges: Vec::new(),
        }
    }

    fn clone_family() -> graph::dupes::CloneFamily {
        graph::dupes::CloneFamily {
            token_length: 60,
            line_span: 8,
            instances: Vec::new(),
        }
    }

    #[test]
    fn review_verdict_respects_fail_on_threshold() {
        // Nothing new → pass at any threshold.
        assert!(!review_crosses_threshold(FailOn::Any, &[], &[], &[], None));
        // A new cycle is an architectural regression: it fails at every level.
        assert!(review_crosses_threshold(
            FailOn::Any,
            &[],
            &[cycle("a", "b")],
            &[],
            None
        ));
        assert!(review_crosses_threshold(
            FailOn::High,
            &[],
            &[cycle("a", "b")],
            &[],
            None
        ));
        // Under `any`, a lone new duplication fails; under medium/high it does not.
        assert!(review_crosses_threshold(
            FailOn::Any,
            &[],
            &[],
            &[clone_family()],
            None
        ));
        assert!(!review_crosses_threshold(
            FailOn::Medium,
            &[],
            &[],
            &[clone_family()],
            None
        ));
        // Findings gate by severity.
        assert!(!review_crosses_threshold(
            FailOn::High,
            &[],
            &[],
            &[],
            Some(Severity::Medium)
        ));
        assert!(review_crosses_threshold(
            FailOn::High,
            &[],
            &[],
            &[],
            Some(Severity::High)
        ));
        assert!(review_crosses_threshold(
            FailOn::Medium,
            &[],
            &[],
            &[],
            Some(Severity::Medium)
        ));
    }

    #[test]
    fn review_risk_band_reflects_worst_signal() {
        assert_eq!(review_risk(None, &[], &[]).as_str(), "Low");
        assert_eq!(
            review_risk(Some(Severity::Medium), &[], &[]).as_str(),
            "Medium"
        );
        // A new duplication alone lifts risk to Medium.
        assert_eq!(review_risk(None, &[], &[clone_family()]).as_str(), "Medium");
        // A new cycle (or a High finding) is High.
        assert_eq!(review_risk(None, &[cycle("a", "b")], &[]).as_str(), "High");
        assert_eq!(review_risk(Some(Severity::High), &[], &[]).as_str(), "High");
        // A Critical finding dominates everything.
        assert_eq!(
            review_risk(Some(Severity::Critical), &[cycle("a", "b")], &[]).as_str(),
            "Critical"
        );
    }

    #[test]
    fn review_rationale_is_empty_message_when_clean() {
        let rationale = review_rationale(&[], 0, 0, 0, 0, &[]);
        assert_eq!(rationale.len(), 1);
        assert!(rationale[0].contains("no new defects"));
        // Populated signals are each spelled out for the verdict explanation.
        let rationale = review_rationale(&[cycle("alpha", "beta")], 2, 1, 3, 4, &[clone_family()]);
        assert!(rationale.iter().any(|r| r.contains("alpha ↔ beta")));
        assert!(rationale.iter().any(|r| r.contains("2 new security")));
        assert!(
            rationale
                .iter()
                .any(|r| r.contains("1 new high-complexity"))
        );
        assert!(rationale.iter().any(|r| r.contains("3 new dead-code")));
        assert!(rationale.iter().any(|r| r.contains("4 new code smell")));
        assert!(rationale.iter().any(|r| r.contains("1 new duplication")));
    }
}
