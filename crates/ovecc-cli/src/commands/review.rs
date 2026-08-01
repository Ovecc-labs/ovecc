//! `ovecc review` (the named defects a change introduced) and the one-shot
//! `ovecc report`.

use super::findings::{build_security_report, window};
use super::open_store;
use super::selfcheck::{SELFCHECK_CAVEAT, load_selfcheck, selfcheck_line};
use super::summary::{hotspots_with, load_hotspots, load_summary};
use crate::cli::FailOn;
use crate::render::{
    emit_json, emit_ndjson_meta, first_evidence, meta_for, ndjson_line, severity_tag,
};
use anyhow::Result;
use ovecc_core::architecture::{ArchitectureContract, assign_components};
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
    /// Clone families the change introduced (scoped to the tokens it touched
    /// when git attests the lines, else to touched files), so new duplication is
    /// not buried under pre-existing repo-wide clones.
    new_duplications: Vec<graph::dupes::CloneFamily>,
    /// What the change touches, ranked against the repository's own commits.
    /// `None` when it touches nothing.
    shape: Option<ChangeShapeView>,
    changed_files: ChangedFiles,
}

/// The size and reach of a change, each measurement next to its percentile
/// among the commits this repository has already made.
///
/// Reported beside the verdict and never inside it: "wider than 9 out of 10
/// commits here" is a reason to read a diff closely, not a defect, so nothing
/// in here moves `--fail-on`.
#[derive(serde::Serialize)]
pub(crate) struct ChangeShapeView {
    files: usize,
    /// Head lines touched, `None` when git cannot attest them. The rest is then
    /// measured over whole files, which stays true, just coarser.
    lines: Option<u32>,
    /// How evenly the touched lines spread over the touched files, 0 for one
    /// file carrying everything and 1 for an even split. `None` under two files.
    spread: Option<f64>,
    /// Contract components reached, `None` when the repository declares no
    /// contract: every change would otherwise reach zero of them and rank at
    /// the top of a column of zeros.
    components: Option<usize>,
    /// Touched modules the hotspot ranking lists, in its order.
    hotspots: Vec<String>,
    /// Share of the repository's age-weighted fix mass carried by the touched
    /// files, `None` when the history holds no fix to take a share of.
    fix_mass_share: Option<f64>,
    mean_age_days: Option<f64>,
    rank: graph::changeshape::ChangeRank,
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
    /// Reported new by the snapshot diff but living entirely on lines this
    /// change never touched: pre-existing findings whose id moved with a line
    /// shift. Not charged to the change.
    shifted_findings: usize,
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

    let change_ranges =
        attested_change_ranges(paths, &base_snapshot, &head_snapshot, &changed_files);
    let (new_findings, shifted_findings) =
        scope_to_touched_lines(store, &repository_id, change_ranges.as_ref(), new_findings)?;

    let shape = match changed_files.touched().next() {
        Some(_) => Some(build_change_shape(
            paths,
            store,
            &repository_id,
            &changed_files,
            change_ranges.as_ref(),
        )?),
        None => None,
    };

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
    // against an existing utility) but only families the change plausibly
    // introduced are reported: an instance must carry a token the change
    // touched when git attests the lines, or merely sit in a touched file when
    // it cannot. So pre-existing clones elsewhere in an edited file do not
    // drown out what THIS change added.
    let touched: std::collections::HashSet<&str> =
        changed_files.touched().map(String::as_str).collect();
    let new_duplications: Vec<graph::dupes::CloneFamily> = if touched.is_empty() {
        Vec::new()
    } else {
        let files = ovecc_indexer::collect_file_tokens(paths, config).unwrap_or_default();
        let token_lines: std::collections::HashMap<&str, &[u32]> = files
            .iter()
            .map(|file| (file.path.as_str(), file.token_lines.as_slice()))
            .collect();
        // Same-file families count too: a PR that pastes a block twice into
        // one file is still introducing duplication.
        graph::dupes::detect(&files, 100, 10, false)
            .into_iter()
            .filter(|family| {
                family
                    .instances
                    .iter()
                    .any(|instance| match &change_ranges {
                        Some(ranges) => holds_changed_token(&token_lines, ranges, instance),
                        None => touched.contains(instance.path.as_str()),
                    })
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
            shifted_findings,
        },
        new_findings,
        new_cycles,
        new_duplications,
        shape,
        changed_files,
    })
}

/// Measures the change against the indexed history and ranks it there.
///
/// `ranges` are the head lines git attests, or `None` to fall back to whole
/// files.
fn build_change_shape(
    paths: &ProjectPaths,
    store: &ArchitectureStore,
    repository_id: &str,
    changed_files: &ChangedFiles,
    ranges: Option<&std::collections::BTreeMap<String, Vec<(u32, u32)>>>,
) -> Result<ChangeShapeView> {
    let attested = ranges.is_some();
    // Whole files when git cannot attest the lines: an empty span list holds no
    // line, so the line count and the spread come back unmeasured while the
    // file, component, hotspot and age measurements still stand.
    let ranges: std::collections::BTreeMap<String, Vec<(u32, u32)>> = match ranges {
        Some(ranges) => ranges.clone(),
        None => changed_files
            .touched()
            .map(|path| (path.clone(), Vec::new()))
            .collect(),
    };

    let facts = ChangeFacts::load(paths, store, repository_id)?;
    let shape = graph::changeshape::change_shape(
        &ranges,
        &facts.component_of,
        &facts.module_of,
        &facts.hotspots,
        &facts.fix_mass,
        &facts.age_days,
    );

    let total_mass = facts
        .fix_mass
        .iter()
        .map(|(_, mass)| mass)
        .fold(0.0, |total, mass| total + mass);
    let mass_of: std::collections::BTreeMap<String, f64> = facts.fix_mass.into_iter().collect();
    let history: Vec<graph::changeshape::CommitShape> = store
        .commit_shapes(repository_id)?
        .iter()
        .map(|commit| {
            graph::changeshape::commit_shape(
                &commit.files,
                &facts.component_of,
                &mass_of,
                total_mass,
            )
        })
        .collect();
    let declares_components = !facts.component_of.is_empty();
    let mut rank = graph::changeshape::rank_change(&shape, &history);
    if !declares_components {
        rank.components = None;
    }

    Ok(ChangeShapeView {
        files: shape.files,
        lines: attested.then_some(shape.lines),
        spread: shape.spread,
        components: declares_components.then_some(shape.components),
        hotspots: shape.hotspots,
        fix_mass_share: (total_mass > 0.0).then_some(shape.fix_mass_share),
        mean_age_days: shape.mean_age_days,
        rank,
    })
}

/// The indexed facts a change is measured against, each keyed by file path.
struct ChangeFacts {
    /// Empty when the repository declares no contract.
    component_of: std::collections::BTreeMap<String, String>,
    module_of: std::collections::BTreeMap<String, String>,
    hotspots: Vec<String>,
    fix_mass: Vec<(String, f64)>,
    age_days: std::collections::BTreeMap<String, f64>,
}

impl ChangeFacts {
    fn load(
        paths: &ProjectPaths,
        store: &ArchitectureStore,
        repository_id: &str,
    ) -> Result<ChangeFacts> {
        let component_of = match ArchitectureContract::load(&paths.root)? {
            Some(contract) => {
                let files: Vec<String> = store
                    .current_files(repository_id)?
                    .into_iter()
                    .map(|file| file.path)
                    .collect();
                assign_components(&contract, &files)?
            }
            None => std::collections::BTreeMap::new(),
        };
        Ok(ChangeFacts {
            component_of,
            module_of: store.file_modules(repository_id)?.into_iter().collect(),
            // The ten `ovecc hotspots` prints by default, so a module named
            // beside a change is one the reader can go and look up.
            hotspots: hotspots_with(store, repository_id, 10)?
                .hotspots
                .into_iter()
                .map(|hotspot| hotspot.module)
                .collect(),
            fix_mass: store
                .file_fix_history(repository_id, ovecc_db::FIX_HALF_LIFE_DAYS)?
                .into_iter()
                .map(|file| (file.file_path, file.mass))
                .collect(),
            age_days: store.file_age_days(repository_id)?.into_iter().collect(),
        })
    }
}

/// The change shape for a caller that holds only the two refs, `gate` being the
/// one. `None` when either ref names no snapshot or the comparison moved no
/// file.
pub(crate) fn load_change_shape(
    paths: &ProjectPaths,
    store: &ArchitectureStore,
    base: &str,
    head: &str,
) -> Result<Option<ChangeShapeView>> {
    let repository_id = paths.repository_id().0;
    let (Some(base_snapshot), Some(head_snapshot)) = (
        store.resolve_snapshot(&repository_id, base)?,
        store.resolve_snapshot(&repository_id, head)?,
    ) else {
        return Ok(None);
    };
    let changed_files =
        store.changed_files(&repository_id, &base_snapshot.id, &head_snapshot.id)?;
    if changed_files.touched().next().is_none() {
        return Ok(None);
    }
    let ranges = attested_change_ranges(paths, &base_snapshot, &head_snapshot, &changed_files);
    build_change_shape(
        paths,
        store,
        &repository_id,
        &changed_files,
        ranges.as_ref(),
    )
    .map(Some)
}

/// The head lines this change touched, when git can attest them: both snapshots
/// carry commit shas and head is still what is checked out — otherwise the git
/// diff would not describe this comparison. Two snapshots on the same commit are
/// the index-edit-index loop, where the change is the uncommitted edit against
/// the working tree. Falling back to `None` there charged every finding and
/// every clone family in a touched file to the change.
fn attested_change_ranges(
    paths: &ProjectPaths,
    base_snapshot: &ovecc_core::legacy::SnapshotRecord,
    head_snapshot: &ovecc_core::legacy::SnapshotRecord,
    changed_files: &ChangedFiles,
) -> Option<std::collections::BTreeMap<String, Vec<(u32, u32)>>> {
    match (
        base_snapshot.commit_sha.as_deref(),
        head_snapshot.commit_sha.as_deref(),
    ) {
        (Some(base_sha), Some(head_sha))
            if ovecc_git::resolve_ref(&paths.root, "HEAD").as_deref() == Some(head_sha) =>
        {
            if base_sha == head_sha {
                let touched: Vec<String> = changed_files.touched().cloned().collect();
                ovecc_git::worktree_line_ranges(&paths.root, base_sha, &touched)
            } else {
                ovecc_git::changed_line_ranges(&paths.root, base_sha)
            }
        }
        _ => None,
    }
}

/// Whether the change reaches the code this clone instance is made of: one of
/// its tokens sits on a line git attests the change touched. Comments and blank
/// lines carry no token, so reflowing the prose around a clone leaves the family
/// exactly the code it was — the same reason `finding_identity` keys on content
/// and not on the line a finding sits at. Testing the instance's line span
/// instead charged every pre-existing clone in an edited region to the change.
fn holds_changed_token(
    token_lines: &std::collections::HashMap<&str, &[u32]>,
    ranges: &std::collections::BTreeMap<String, Vec<(u32, u32)>>,
    instance: &graph::dupes::CloneInstance,
) -> bool {
    let (Some(changed), Some(lines)) = (
        ranges.get(instance.path.as_str()),
        token_lines.get(instance.path.as_str()),
    ) else {
        return false;
    };
    lines.iter().any(|line| {
        *line >= instance.start_line
            && *line <= instance.end_line
            && changed
                .iter()
                .any(|(start, end)| start <= line && line <= end)
    })
}

/// Drops from `new_findings` the lexical findings that only moved: a finding id
/// embeds its evidence line, so an edit higher in a file renames every finding
/// below it and the snapshot diff reports pre-existing defects as new. When git
/// can say which head lines the change touched, a point/body finding whose lines
/// (or enclosing body) were never touched is not charged to the change. Cross-
/// file kinds (dead code, taint, advisories) keep the plain diff: their cause
/// can sit far from their evidence. Returns the kept findings and the count set
/// aside. Without attested ranges every finding stands.
fn scope_to_touched_lines(
    store: &ArchitectureStore,
    repository_id: &str,
    ranges: Option<&std::collections::BTreeMap<String, Vec<(u32, u32)>>>,
    new_findings: Vec<FindingRecord>,
) -> Result<(Vec<FindingRecord>, usize)> {
    let Some(ranges) = ranges else {
        return Ok((new_findings, 0));
    };

    let mut spans_by_file: std::collections::HashMap<String, Vec<(u32, u32)>> =
        std::collections::HashMap::new();
    for (path, start, end) in store.symbol_spans(repository_id)? {
        spans_by_file.entry(path).or_default().push((start, end));
    }
    // The diff cannot say which instance of a repeated pattern is the new one
    // (ordinals follow hashed ids, not lines), so point kinds are judged by
    // every current site sharing the finding's identity group: "one more of
    // these" is charged when any site is on a touched line.
    let mut point_groups: std::collections::HashMap<String, Vec<(String, Option<u32>)>> =
        std::collections::HashMap::new();
    for finding in store.findings(repository_id, None)? {
        if let Some(evidence) = finding
            .evidence
            .first()
            .filter(|_| point_scoped(finding.kind))
        {
            point_groups
                .entry(ovecc_db::finding_group_key(&finding))
                .or_default()
                .push((evidence.file_path.clone(), evidence.line));
        }
    }
    let (kept, shifted): (Vec<_>, Vec<_>) = new_findings
        .into_iter()
        .partition(|finding| charged_to_change(finding, ranges, &spans_by_file, &point_groups));
    Ok((kept, shifted.len()))
}

/// Finding kinds whose defect lives on the exact evidence line.
fn point_scoped(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::HardcodedSecret
            | FindingKind::InsecurePattern
            | FindingKind::WeakCrypto
            | FindingKind::PermissiveCors
            | FindingKind::StaleSuppression
    )
}

/// Finding kinds that describe a whole body (a function or a type), where an
/// edit anywhere inside the enclosing span can have introduced the defect
/// even though the evidence anchors at the declaration line.
fn body_scoped(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::HighComplexity
            | FindingKind::LongFunction
            | FindingKind::LongParameterList
            | FindingKind::FeatureEnvy
            | FindingKind::LargeClass
            | FindingKind::DataClumps
    )
}

/// Whether the change can have introduced this finding. Kinds outside the two
/// scoped families are always charged, as is evidence git knows nothing about
/// (no line, or no recorded span to widen a body kind with). A file absent
/// from `ranges` is untouched, so nothing in it came from this change.
fn charged_to_change(
    finding: &FindingRecord,
    ranges: &std::collections::BTreeMap<String, Vec<(u32, u32)>>,
    spans_by_file: &std::collections::HashMap<String, Vec<(u32, u32)>>,
    point_groups: &std::collections::HashMap<String, Vec<(String, Option<u32>)>>,
) -> bool {
    let line_touched = |path: &str, line: Option<u32>, span: Option<(u32, u32)>| -> bool {
        let Some(changed) = ranges.get(path) else {
            return false;
        };
        let Some(line) = line else {
            return true;
        };
        let (start, end) = span.unwrap_or((line, line));
        changed
            .iter()
            .any(|(changed_start, changed_end)| *changed_start <= end && start <= *changed_end)
    };

    if point_scoped(finding.kind)
        && let Some(sites) = point_groups.get(&ovecc_db::finding_group_key(finding))
    {
        return sites
            .iter()
            .any(|(path, line)| line_touched(path, *line, None));
    }
    if !point_scoped(finding.kind) && !body_scoped(finding.kind) {
        return true;
    }
    if finding.evidence.is_empty() {
        return true;
    }
    finding.evidence.iter().any(|evidence| {
        let span = evidence.line.and_then(|line| {
            body_scoped(finding.kind)
                .then(|| enclosing_span(spans_by_file, &evidence.file_path, line))
                .flatten()
        });
        line_touched(&evidence.file_path, evidence.line, span)
    })
}

/// Smallest recorded symbol span containing `line` in `path` — the method
/// rather than the class it sits in.
fn enclosing_span(
    spans_by_file: &std::collections::HashMap<String, Vec<(u32, u32)>>,
    path: &str,
    line: u32,
) -> Option<(u32, u32)> {
    spans_by_file
        .get(path)?
        .iter()
        .filter(|(start, end)| *start <= line && line <= *end)
        .min_by_key(|(start, end)| end - start)
        .copied()
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
        rationale.push(format!(
            "{new_complexity} new complexity finding(s) (high complexity / long function / long parameter list)"
        ));
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
            if let Some(shape) = &report.shape {
                println!("{}", ndjson_line("change_shape", shape)?);
            }
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
        OutputFormat::Markdown => review_markdown(report),
        OutputFormat::Text => review_text(report),
    }
    Ok(())
}

fn review_markdown(report: &ReviewReport) {
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
    if let Some(shape) = &report.shape {
        review_markdown_shape(shape);
    }
    review_markdown_cycles(report);
    review_markdown_findings(report);
    review_markdown_duplications(report);
}

/// A measurement carrying its percentile when the history could give one:
/// `7 files (p91)`.
fn ranked(measurement: String, percentile: Option<f64>) -> String {
    match percentile {
        Some(percentile) => format!("{measurement} (p{:.0})", percentile * 100.0),
        None => measurement,
    }
}

/// The measurements, in the order a reader weighs them: how big, then how far
/// it reaches, then what it lands on. An axis the index cannot speak to is left
/// out rather than shown as zero.
fn shape_cells(shape: &ChangeShapeView) -> Vec<String> {
    let mut cells = vec![ranked(format!("{} files", shape.files), shape.rank.files)];
    match shape.lines {
        Some(lines) => cells.push(format!("{lines} lines")),
        None => cells.push("lines not attested by git".to_string()),
    }
    if let Some(components) = shape.components {
        cells.push(ranked(
            format!("{components} components"),
            shape.rank.components,
        ));
    }
    if let Some(spread) = shape.spread {
        cells.push(format!("spread {spread:.2}"));
    }
    if let Some(share) = shape.fix_mass_share {
        cells.push(ranked(
            format!("{:.0}% of the fix mass", share * 100.0),
            shape.rank.fix_mass_share,
        ));
    }
    if let Some(age) = shape.mean_age_days {
        cells.push(ranked(
            format!("mean age {age:.0}d"),
            shape.rank.mean_age_days,
        ));
    }
    cells
}

/// The one-line form `gate` prints beside its counts.
pub(crate) fn shape_summary_line(shape: &ChangeShapeView) -> String {
    shape_cells(shape).join(", ")
}

/// What the percentiles are measured against, or why there are none.
fn shape_basis(shape: &ChangeShapeView) -> String {
    if shape.rank.commits < graph::changeshape::MIN_RANKED_COMMITS {
        format!(
            "no percentiles: {} indexed commit(s), under the {} a rank needs",
            shape.rank.commits,
            graph::changeshape::MIN_RANKED_COMMITS
        )
    } else {
        format!("percentiles against {} indexed commits", shape.rank.commits)
    }
}

fn review_markdown_shape(shape: &ChangeShapeView) {
    println!();
    println!("## Change shape");
    println!();
    for cell in shape_cells(shape) {
        println!("- {cell}");
    }
    if !shape.hotspots.is_empty() {
        println!("- Hotspots touched: {}", quoted(&shape.hotspots));
    }
    println!();
    println!("_{}. These do not affect the verdict._", shape_basis(shape));
}

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn review_markdown_cycles(report: &ReviewReport) {
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
}

fn review_markdown_findings(report: &ReviewReport) {
    println!();
    println!("## New findings ({})", report.new_findings.len());
    if report.new_findings.is_empty() {
        println!("_None._");
    }
    if report.summary.shifted_findings > 0 {
        println!(
            "_{} pre-existing finding(s) moved with a line shift and are not \
             charged to this change._",
            report.summary.shifted_findings
        );
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
}

fn review_markdown_duplications(report: &ReviewReport) {
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

fn review_text(report: &ReviewReport) {
    println!(
        "Review: {} (risk {}) {} -> {}",
        report.verdict, report.risk, report.base, report.head
    );
    for reason in &report.rationale {
        println!("  - {reason}");
    }
    if let Some(shape) = &report.shape {
        println!("Change shape: {}", shape_summary_line(shape));
        if !shape.hotspots.is_empty() {
            println!("  hotspots touched: {}", shape.hotspots.join(", "));
        }
        println!("  {}", shape_basis(shape));
    }
    review_text_cycles(report);
    review_text_findings(report);
    review_text_duplications(report);
}

fn review_text_cycles(report: &ReviewReport) {
    if report.new_cycles.is_empty() {
        return;
    }
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

fn review_text_findings(report: &ReviewReport) {
    if !report.new_findings.is_empty() {
        println!("New findings:");
        for finding in &report.new_findings {
            anstream::println!(
                "  {} {:?}{} {}",
                severity_tag(finding.severity),
                finding.kind,
                first_evidence(finding),
                finding.title
            );
        }
    }
    if report.summary.shifted_findings > 0 {
        println!(
            "({} pre-existing finding(s) moved with a line shift; not charged \
             to this change)",
            report.summary.shifted_findings
        );
    }
}

fn review_text_duplications(report: &ReviewReport) {
    if report.new_duplications.is_empty() {
        return;
    }
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
    let selfcheck = load_selfcheck(paths)?;

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
                "selfcheck": selfcheck,
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
                    "{}. {} (score {:.0}, fan-in {}, fan-out {}, {} fix commit{})",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    hotspot.fan_in,
                    hotspot.fan_out,
                    hotspot.fix_history.fixes,
                    if hotspot.fix_history.fixes == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
            }
            if let Some(line) = selfcheck_line(&selfcheck) {
                println!();
                println!("## Self-check");
                println!();
                println!("- {line}");
                println!();
                println!("_{SELFCHECK_CAVEAT}_");
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
                .any(|r| r.contains("1 new complexity finding"))
        );
        assert!(rationale.iter().any(|r| r.contains("3 new dead-code")));
        assert!(rationale.iter().any(|r| r.contains("4 new code smell")));
        assert!(rationale.iter().any(|r| r.contains("1 new duplication")));
    }

    #[test]
    fn a_measured_change_carries_its_percentiles() {
        let cells = shape_cells(&ChangeShapeView {
            files: 7,
            lines: Some(214),
            spread: Some(0.62),
            components: Some(3),
            hotspots: vec!["api".to_string()],
            fix_mass_share: Some(0.123),
            mean_age_days: Some(84.0),
            rank: graph::changeshape::ChangeRank {
                commits: 1204,
                files: Some(0.91),
                components: Some(0.88),
                fix_mass_share: Some(0.74),
                mean_age_days: Some(0.6),
            },
        });

        assert_eq!(cells[0], "7 files (p91)");
        assert_eq!(cells[1], "214 lines");
        assert_eq!(cells[2], "3 components (p88)");
        assert_eq!(cells[4], "12% of the fix mass (p74)");
    }

    #[test]
    fn an_unmeasured_axis_is_left_out_rather_than_shown_as_zero() {
        let shape = ChangeShapeView {
            files: 1,
            lines: None,
            spread: None,
            components: None,
            hotspots: Vec::new(),
            fix_mass_share: None,
            mean_age_days: None,
            rank: graph::changeshape::ChangeRank {
                commits: 12,
                ..graph::changeshape::ChangeRank::default()
            },
        };
        let cells = shape_cells(&shape);

        assert_eq!(cells[0], "1 files", "no history to rank one file against");
        assert_eq!(cells[1], "lines not attested by git");
        assert_eq!(cells.len(), 2, "nothing else was measured: {cells:?}");
        assert!(
            shape_basis(&shape).contains("12 indexed commit(s), under the 100"),
            "{}",
            shape_basis(&shape)
        );
    }
}
