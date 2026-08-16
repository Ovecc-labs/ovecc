// SPDX-License-Identifier: MIT
//! Dead-code analysis: unused exports and unused files.
//!
//! Language-neutral analysis over resolved facts — exports (with re-export
//! provenance), resolved import edges (carrying the imported names), and a set
//! of entry-point files. It computes the reachable set from entry points, the
//! per-export reference set, and flags exports referenced by no reachable
//! importer and files reachable from nothing. Deliberately **high-precision**:
//! it skips entry points, re-export forwards, `default`, declaration/config
//! files, and barrels with reachable sources, and reports nothing at all when no
//! entry points are detected — better silent than crying wolf.
//!
//! **The unreachable verdict is ternary.** "No import reaches it" is not "no
//! one runs it": a task runner, a container command, or a path handed to
//! `readFile` names its target as a string and leaves no edge. So a file some
//! *literal* names is reported as `possibly-unused-file`, quoting the literal
//! and where it was seen, and is withheld from `fix --delete-files`; only a file
//! nothing references at all is reported as `unused-file`. The direction of the
//! bias is deliberate: a missed dead file is cruft, a live file called dead is
//! a deletion.
//!
//! ## Limitations
//!
//! - A specifier assembled at runtime (`` `./${name}.ts` ``, a path read from
//!   config) is invisible to both halves. Neither the import graph nor the
//!   literal backstop can see it, and neither pretends to.
//! - The literal backstop matches on a file's name plus a trailing run of its
//!   directories, not on a resolved path — two files with the same name in
//!   different directories are not told apart. It over-matches by design.
//! - A file named only from *outside* the index (a Dockerfile `CMD`, a
//!   deployment manifest) still reads as unreferenced. The `unused-file`
//!   description says so rather than implying the check was exhaustive.
//!
//! Ported from fallow (crates/{graph/src/graph/reachability.rs,
//! graph/src/graph/re_exports, core/src/analyze/unused_exports.rs,
//! unused_files.rs}), MIT (c) 2026 Bart Waardenburg. See THIRD-PARTY-NOTICES.md.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::Utc;
use ovecc_core::facts::{
    EntityRef, Evidence, ExportFact, FindingKind, FindingRecord, PathLiteralFact, Severity,
};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};

/// One resolved internal import edge and the names it pulls from the target.
pub struct ImportEdge {
    pub source_file: String,
    pub target_file: String,
    /// Named imports; empty for a side-effect import.
    pub imported_names: Vec<String>,
    /// `import *` / `require(...)` — credits every export of the target as used.
    pub is_namespace: bool,
}

/// Neutral input for dead-code analysis.
pub struct DeadCodeInput<'a> {
    pub repository_id: &'a str,
    pub snapshot_id: Option<&'a str>,
    /// Every indexed source file (repo-relative path).
    pub files: &'a [String],
    /// Files that anchor reachability (package.json entries, index/main, tests).
    pub entry_points: &'a HashSet<String>,
    /// `(file_path, export)` for every export of every file.
    pub exports: &'a [(String, ExportFact)],
    /// Resolved internal import edges (including re-export forwards).
    pub imports: &'a [ImportEdge],
    /// `(file_path, literal)` for every file-shaped string literal in the
    /// index. A file no import reaches but some literal names is *not* known to
    /// be dead — see [`literal_reference`].
    pub path_literals: &'a [(String, PathLiteralFact)],
    /// `(file_path, type_name)` for every type named inside an exported
    /// declaration. Such a type is public surface even though nothing imports
    /// it by name, so it is not an unused export.
    pub signature_types: &'a [(String, String)],
}

/// A re-export forward hop: `(from_file, name) -> (to_file, name)`. Usage flows
/// along these edges without a plain import crediting the source as consumed.
type Forward<'a> = ((&'a str, &'a str), (&'a str, &'a str));

/// Analyzes dead code, returning `UnusedExport` and `UnusedFile` findings. Empty
/// when no entry points are known (avoids flagging an entire tree).
pub fn analyze(input: &DeadCodeInput<'_>) -> Vec<FindingRecord> {
    if input.entry_points.is_empty() {
        return Vec::new();
    }

    let exports_by_file = index_exports_by_file(input.exports);
    let out_edges = build_out_edges(input.imports);
    let reachable = bfs_reachable(input.entry_points, &out_edges);
    let reexport_names = collect_reexport_names(input.exports);

    // `used` holds every (file, export) reached from a real consumer or the
    // public (entry-point) surface; `forwards` carries the re-export hops along
    // which that usage propagates.
    let mut used: HashSet<(&str, &str)> = HashSet::new();
    let mut worklist: Vec<(&str, &str)> = Vec::new();
    seed_public_surface(input, &mut used, &mut worklist);
    let forwards = seed_from_imports(
        input,
        &reachable,
        &exports_by_file,
        &reexport_names,
        &mut used,
        &mut worklist,
    );
    propagate_forwards(&forwards, &mut used, &mut worklist);

    let mut findings = Vec::new();
    flag_unused_exports(input, &reachable, &used, &mut findings);
    flag_unused_files(input, &reachable, &exports_by_file, &mut findings);
    // Sort by id, then drop any exact-id duplicates. The id carries the source
    // location, so genuinely distinct declarations (a name exported twice in one
    // file via TypeScript declaration merging or overloads) keep distinct ids and
    // survive; this only removes a finding the analysis emitted twice (e.g. a
    // duplicated export fact). Sorting first lets `dedup_by` remove ALL
    // duplicates, not just adjacent ones, and guarantees the returned set is what
    // gets persisted — so the `unused_exports`/`unused_files` metrics can never
    // disagree with what `deadcode`/`violations` actually report.
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings.dedup_by(|a, b| a.id.0 == b.id.0);
    findings
}

fn index_exports_by_file(exports: &[(String, ExportFact)]) -> HashMap<&str, Vec<&ExportFact>> {
    let mut by_file: HashMap<&str, Vec<&ExportFact>> = HashMap::new();
    for (file, export) in exports {
        by_file.entry(file.as_str()).or_default().push(export);
    }
    by_file
}

/// Out-edges for reachability (importer -> imported internal files).
fn build_out_edges(imports: &[ImportEdge]) -> HashMap<&str, Vec<&str>> {
    let mut out_edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in imports {
        out_edges
            .entry(edge.source_file.as_str())
            .or_default()
            .push(edge.target_file.as_str());
    }
    out_edges
}

/// The names each file re-exports. A re-exported name is "used" only when
/// something downstream actually consumes it. Crediting a re-export *forward* as
/// a use outright (the way a plain consuming import is credited) hides dead code
/// mechanically forwarded through a barrel: `index` imports `a` from a barrel
/// that `export {a, b}`s from a leaf, and `b` — forwarded the whole way but
/// never consumed — looks used. So forwards are separated from real uses and
/// usage propagates along the re-export chain to a fixpoint.
fn collect_reexport_names(exports: &[(String, ExportFact)]) -> HashMap<&str, HashSet<&str>> {
    let mut names: HashMap<&str, HashSet<&str>> = HashMap::new();
    for (file, export) in exports {
        if export.re_export.is_some() {
            names
                .entry(file.as_str())
                .or_default()
                .insert(export.name.as_str());
        }
    }
    names
}

/// Every export of an entry-point file is a usage root, so a library barrel that
/// re-exports its API never flags that API as dead.
fn seed_public_surface<'a>(
    input: &'a DeadCodeInput<'a>,
    used: &mut HashSet<(&'a str, &'a str)>,
    worklist: &mut Vec<(&'a str, &'a str)>,
) {
    for (file, export) in input.exports {
        if input.entry_points.contains(file) {
            let key = (file.as_str(), export.name.as_str());
            if used.insert(key) {
                worklist.push(key);
            }
        }
    }
}

/// Credits every consuming import against its target's exports and returns the
/// re-export forward hops, along which usage still has to propagate.
fn seed_from_imports<'a>(
    input: &'a DeadCodeInput<'a>,
    reachable: &HashSet<&str>,
    exports_by_file: &HashMap<&'a str, Vec<&'a ExportFact>>,
    reexport_names: &HashMap<&str, HashSet<&str>>,
    used: &mut HashSet<(&'a str, &'a str)>,
    worklist: &mut Vec<(&'a str, &'a str)>,
) -> Vec<Forward<'a>> {
    let mut forwards: Vec<Forward<'a>> = Vec::new();
    for edge in input.imports {
        // An import from an unreachable file is itself dead; it cannot keep
        // anything alive (its target is reachable iff its source is).
        if !reachable.contains(edge.source_file.as_str()) {
            continue;
        }
        let exported = exports_by_file.get(edge.target_file.as_str());
        if edge.is_namespace {
            // `import *` (or an un-named `export *`): credit every export of the
            // target outright. That is the conservative choice — it can only miss
            // dead code, never invent a false positive.
            for export in exported.into_iter().flatten() {
                let key = (edge.target_file.as_str(), export.name.as_str());
                if used.insert(key) {
                    worklist.push(key);
                }
            }
            continue;
        }
        let forwarded_here = reexport_names.get(edge.source_file.as_str());
        for name in &edge.imported_names {
            let exports_name =
                exported.is_some_and(|exports| exports.iter().any(|e| &e.name == name));
            if !exports_name {
                continue;
            }
            if forwarded_here.is_some_and(|set| set.contains(name.as_str())) {
                // A re-export forward: usage flows *through* it, it does not
                // create it. (An aliased `export { a as b }` falls through to the
                // real-use arm instead, which only ever over-credits — safe.)
                forwards.push((
                    (edge.source_file.as_str(), name.as_str()),
                    (edge.target_file.as_str(), name.as_str()),
                ));
            } else {
                let key = (edge.target_file.as_str(), name.as_str());
                if used.insert(key) {
                    worklist.push(key);
                }
            }
        }
    }
    forwards
}

/// Propagates usage across re-export hops until it stops spreading.
fn propagate_forwards<'a>(
    forwards: &[Forward<'a>],
    used: &mut HashSet<(&'a str, &'a str)>,
    worklist: &mut Vec<(&'a str, &'a str)>,
) {
    let mut forward_index: HashMap<(&str, &str), Vec<(&str, &str)>> = HashMap::new();
    for &(from, to) in forwards {
        forward_index.entry(from).or_default().push(to);
    }
    while let Some(key) = worklist.pop() {
        if let Some(targets) = forward_index.get(&key) {
            for &target in targets {
                if used.insert(target) {
                    worklist.push(target);
                }
            }
        }
    }
}

fn bfs_reachable<'a>(
    entry_points: &'a HashSet<String>,
    out_edges: &HashMap<&'a str, Vec<&'a str>>,
) -> HashSet<&'a str> {
    let mut reachable: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for entry in entry_points {
        if reachable.insert(entry.as_str()) {
            queue.push_back(entry.as_str());
        }
    }
    while let Some(file) = queue.pop_front() {
        if let Some(targets) = out_edges.get(file) {
            for &target in targets {
                if reachable.insert(target) {
                    queue.push_back(target);
                }
            }
        }
    }
    reachable
}

fn flag_unused_exports(
    input: &DeadCodeInput<'_>,
    reachable: &HashSet<&str>,
    used: &HashSet<(&str, &str)>,
    out: &mut Vec<FindingRecord>,
) {
    let signature_types: HashSet<(&str, &str)> = input
        .signature_types
        .iter()
        .map(|(file, name)| (file.as_str(), name.as_str()))
        .collect();

    for (file, export) in input.exports {
        // High-precision skips: entry points (public surface), re-export
        // forwards, the default export, and unreachable modules (covered by
        // unused-file).
        if input.entry_points.contains(file)
            || export.re_export.is_some()
            || export.name == "default"
            || !reachable.contains(file.as_str())
        {
            continue;
        }
        if used.contains(&(file.as_str(), export.name.as_str())) {
            continue;
        }
        // A type named in an exported declaration's signature is public surface
        // reached *through* that declaration, not by name — the options type of
        // an exported function, its return type, the element type of what it
        // returns. Reachability cannot see that, so it called each one unused
        // and `fix` planned to drop the `export`, leaving callers unable to
        // annotate a value the module had just handed them. The rule was
        // technically right and the remedy was backwards.
        if export.is_type_only && signature_types.contains(&(file.as_str(), export.name.as_str())) {
            continue;
        }
        // Type-only exports are reported under the same `UnusedExport` kind (so
        // counts, gate, and baselines are unchanged) but carry the `unused-type`
        // rule and a `type-only` detail so callers can filter them — and an
        // unused type is even safer to drop than a value (no runtime effect).
        let (title, description, rule, detail) = if export.is_type_only {
            (
                format!("Unused type export: {} in {file}", export.name),
                format!(
                    "type '{}' is exported from {file} but never imported by a reachable \
                     module. Safe to remove — types have no runtime effect.",
                    export.name
                ),
                "unused-type",
                Some("type-only"),
            )
        } else {
            (
                format!("Unused export: {} in {file}", export.name),
                format!(
                    "'{}' is exported from {file} but never imported by a reachable module. \
                     Candidate for removal (verify it is not a public API surface).",
                    export.name
                ),
                "unused-export",
                None,
            )
        };
        out.push(finding(
            input,
            FindingKind::UnusedExport,
            Severity::Low,
            file,
            export.line,
            title,
            description,
            Some(export.name.clone()),
            rule,
            detail,
        ));
    }
}

fn flag_unused_files(
    input: &DeadCodeInput<'_>,
    reachable: &HashSet<&str>,
    exports_by_file: &HashMap<&str, Vec<&ExportFact>>,
    out: &mut Vec<FindingRecord>,
) {
    // Reverse edges: who imports each file.
    let mut importers_of: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in input.imports {
        importers_of
            .entry(edge.target_file.as_str())
            .or_default()
            .push(edge.source_file.as_str());
    }
    let literals_by_name = index_literals_by_name(input.path_literals);

    for file in input.files {
        let path = file.as_str();
        if reachable.contains(path) || input.entry_points.contains(file) {
            continue;
        }
        if is_declaration_file(path) || is_config_file(path) {
            continue;
        }
        if is_barrel_with_reachable_sources(path, exports_by_file, reachable, input) {
            continue;
        }
        // Imported by any reachable file? (would have been reachable, but guard anyway)
        let imported_by_reachable = importers_of.get(path).is_some_and(|importers| {
            importers
                .iter()
                .any(|importer| reachable.contains(importer))
        });
        if imported_by_reachable {
            continue;
        }
        // Absence is ternary here, and collapsing it is what lets an agent
        // delete live code: "no import reaches it" and "nothing references it"
        // are different claims, and only the second justifies a deletion.
        let (title, description, rule, detail) = match literal_reference(
            &literals_by_name,
            reachable,
            path,
        ) {
            Some(reference) => (
                format!("Possibly unused file: {file}"),
                format!(
                    "No import reaches {file}, but {} names \"{}\" at line {}. A task runner, a \
                     config, or a path passed as a string leaves no import edge, so this file may \
                     well be live — confirm before removing it. `fix --delete-files` will not \
                     touch it.",
                    reference.file, reference.literal.value, reference.literal.line
                ),
                "possibly-unused-file",
                Some("referenced-by-literal"),
            ),
            None => (
                format!("Unused file: {file}"),
                format!(
                    "Nothing in the index references {file}: no import reaches it and no string \
                     literal names it. Verify nothing outside the index runs it (a CI step, a \
                     container command) before removing it."
                ),
                "unused-file",
                None,
            ),
        };
        out.push(finding(
            input,
            FindingKind::UnusedFile,
            Severity::Low,
            file,
            1,
            title,
            description,
            None,
            rule,
            detail,
        ));
    }
}

/// One file naming another by string literal.
struct LiteralReference<'a> {
    file: &'a str,
    literal: &'a PathLiteralFact,
}

/// The literal, if any, by which some *other* indexed file names `path`.
///
/// The match is on the file's name plus any trailing run of its directories
/// (`worker.ts`, `workers/worker.ts`, …), which is what a literal actually
/// spells — `"./workers/worker.ts"` and `"src/workers/worker.ts"` both name the
/// same file from different roots, and neither is a path this analysis can
/// resolve. Over-matching only costs a finding demoted to "possibly unused";
/// under-matching costs a live file called dead, so the bias is deliberate.
///
/// A file naming itself proves nothing, and is excluded. Among several
/// referencing files the reachable ones sort first — a literal in live code is
/// the stronger witness — then by file and line, so the answer is deterministic.
fn literal_reference<'a>(
    literals_by_name: &HashMap<&'a str, Vec<(&'a str, &'a PathLiteralFact)>>,
    reachable: &HashSet<&str>,
    path: &str,
) -> Option<LiteralReference<'a>> {
    let mut best: Option<((bool, &str, u32), &PathLiteralFact)> = None;
    for (holder, literal) in literals_by_name.get(file_name(path))?.iter().copied() {
        if holder == path || !names_file(&literal.value, path) {
            continue;
        }
        let rank = (!reachable.contains(holder), holder, literal.line);
        if best.is_none_or(|(current, _)| rank < current) {
            best = Some((rank, literal));
        }
    }
    best.map(|((_, file, _), literal)| LiteralReference { file, literal })
}

/// Literals bucketed by the file name they end in, so a candidate is checked
/// against the handful of literals that could possibly name it rather than
/// against every literal in the repository. `names_file` still decides each
/// match; this only narrows what it is asked about, keeping the pass linear in
/// the number of literals instead of quadratic against the file list.
fn index_literals_by_name(
    literals: &[(String, PathLiteralFact)],
) -> HashMap<&str, Vec<(&str, &PathLiteralFact)>> {
    let mut by_name: HashMap<&str, Vec<(&str, &PathLiteralFact)>> = HashMap::new();
    for (holder, literal) in literals {
        by_name
            .entry(file_name(&literal.value))
            .or_default()
            .push((holder.as_str(), literal));
    }
    by_name
}

/// The last `/`- or `\`-delimited segment of a path or literal.
fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// True when `literal` spells `path`'s file name, optionally with some of its
/// leading directories. Leading `./` and `/` are stripped, and comparison is on
/// '/'-separated segments so `worker.ts` never matches `my-worker.ts`.
fn names_file(literal: &str, path: &str) -> bool {
    let literal = literal.replace('\\', "/");
    let literal = literal.trim_start_matches("./").trim_start_matches('/');
    if literal.is_empty() {
        return false;
    }
    path == literal || path.ends_with(&format!("/{literal}"))
}

/// A barrel (re-export-only file) whose re-export targets are reachable is kept
/// even if the barrel itself is not directly imported.
fn is_barrel_with_reachable_sources(
    file: &str,
    exports_by_file: &HashMap<&str, Vec<&ExportFact>>,
    reachable: &HashSet<&str>,
    input: &DeadCodeInput<'_>,
) -> bool {
    let Some(exports) = exports_by_file.get(file) else {
        return false;
    };
    if exports.is_empty() || !exports.iter().all(|export| export.re_export.is_some()) {
        return false;
    }
    // Any re-export target reachable? Resolve via the import edges from this file.
    input
        .imports
        .iter()
        .filter(|edge| edge.source_file == file)
        .any(|edge| reachable.contains(edge.target_file.as_str()))
}

fn is_declaration_file(path: &str) -> bool {
    path.ends_with(".d.ts")
}

fn is_config_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.ends_with(".config.ts")
        || name.ends_with(".config.js")
        || name.ends_with(".config.mjs")
        || matches!(
            name,
            "vite.config.ts" | "next.config.js" | "jest.config.js" | "rollup.config.js"
        )
}

#[allow(clippy::too_many_arguments)]
fn finding(
    input: &DeadCodeInput<'_>,
    kind: FindingKind,
    severity: Severity,
    file: &str,
    line: u32,
    title: String,
    description: String,
    symbol: Option<String>,
    rule: &str,
    detail: Option<&str>,
) -> FindingRecord {
    // The id slug is keyed on the kind (stable for baselines/fingerprints), even
    // when the displayed `rule` differs (e.g. an `unused-type` is still an
    // `UnusedExport`).
    let kind_slug = match kind {
        FindingKind::UnusedExport => "unused-export",
        _ => "unused-file",
    };
    // The line is part of the finding's identity: a single file can export the
    // same name more than once (TypeScript declaration merging, function
    // overloads). Without the location those distinct findings would share an id,
    // collide on the `findings.id` primary key, and be silently dropped on write.
    let line_str = line.to_string();
    FindingRecord {
        id: FindingId::from_parts(&[
            input.repository_id,
            "deadcode",
            kind_slug,
            file,
            symbol.as_deref().unwrap_or(""),
            &line_str,
        ]),
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
        kind,
        severity,
        rule_name: Some(rule.to_string()),
        target: Some(EntityRef {
            kind: NodeKind::File,
            id: file.to_string(),
        }),
        title,
        description,
        evidence: vec![Evidence {
            file_path: file.to_string(),
            line: Some(line),
            symbol,
            detail: detail.map(|d| d.to_string()),
        }],
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(name: &str) -> ExportFact {
        export_at(name, 1)
    }

    fn export_at(name: &str, line: u32) -> ExportFact {
        ExportFact {
            name: name.to_string(),
            local_name: None,
            is_type_only: false,
            line,
            re_export: None,
        }
    }

    fn unique_ids(findings: &[FindingRecord]) -> bool {
        let mut ids: Vec<&str> = findings.iter().map(|f| f.id.0.as_str()).collect();
        ids.sort_unstable();
        let total = ids.len();
        ids.dedup();
        ids.len() == total
    }

    fn entry(paths: &[&str]) -> HashSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn no_entry_points_reports_nothing() {
        let files = vec!["a.ts".to_string()];
        let exports = vec![("a.ts".to_string(), export("foo"))];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &HashSet::new(),
            exports: &exports,
            imports: &[],
            path_literals: &[],
            signature_types: &[],
        };
        assert!(analyze(&input).is_empty());
    }

    #[test]
    fn flags_unused_export_in_reachable_file() {
        // index imports `used` from util; `unused` is exported but never imported.
        let files = vec!["src/index.ts".to_string(), "src/util.ts".to_string()];
        let exports = vec![
            ("src/util.ts".to_string(), export("used")),
            ("src/util.ts".to_string(), export("unused")),
        ];
        let imports = vec![ImportEdge {
            source_file: "src/index.ts".to_string(),
            target_file: "src/util.ts".to_string(),
            imported_names: vec!["used".to_string()],
            is_namespace: false,
        }];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &imports,
            path_literals: &[],
            signature_types: &[],
        };
        let findings = analyze(&input);
        let unused: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnusedExport)
            .collect();
        assert_eq!(unused.len(), 1, "{findings:?}");
        assert!(unused[0].title.contains("unused"));
    }

    #[test]
    fn unused_type_export_is_tagged_unused_type_but_keeps_kind() {
        // A type-only export that's unused must stay `UnusedExport` (so counts,
        // gate, and baselines are unchanged) yet carry the `unused-type` rule and
        // a `type-only` detail so it is filterable as a distinct category.
        let files = vec!["src/index.ts".to_string(), "src/types.ts".to_string()];
        let mut type_export = export_at("Orphaned", 5);
        type_export.is_type_only = true;
        let exports = vec![
            ("src/types.ts".to_string(), export_at("used", 1)),
            ("src/types.ts".to_string(), type_export),
        ];
        let imports = vec![ImportEdge {
            source_file: "src/index.ts".to_string(),
            target_file: "src/types.ts".to_string(),
            imported_names: vec!["used".to_string()],
            is_namespace: false,
        }];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &imports,
            path_literals: &[],
            signature_types: &[],
        };
        let findings = analyze(&input);
        let found = findings
            .iter()
            .find(|f| f.title.contains("Orphaned"))
            .expect("unused type export flagged");
        assert_eq!(found.kind, FindingKind::UnusedExport);
        assert_eq!(found.rule_name.as_deref(), Some("unused-type"));
        assert!(found.title.contains("Unused type export"));
        assert_eq!(found.evidence[0].detail.as_deref(), Some("type-only"));
    }

    #[test]
    fn flags_unused_file() {
        let files = vec!["src/index.ts".to_string(), "src/orphan.ts".to_string()];
        let exports = vec![("src/orphan.ts".to_string(), export("thing"))];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &[],
            path_literals: &[],
            signature_types: &[],
        };
        let findings = analyze(&input);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == FindingKind::UnusedFile && f.title.contains("orphan")),
            "{findings:?}"
        );
    }

    fn literal(value: &str, line: u32) -> PathLiteralFact {
        PathLiteralFact {
            value: value.to_string(),
            line,
        }
    }

    #[test]
    fn a_type_in_an_exported_signature_is_public_surface_not_dead() {
        // `HttpApp` is the return type of the exported `createHttpServer`, so a
        // caller can hold one without ever importing the name. Reachability sees
        // no importer and used to call it unused, and `fix` planned to drop the
        // `export` — after which the caller could no longer annotate the value
        // it was handed. `Orphaned` names nothing and stays flagged.
        let files = vec!["src/index.ts".to_string(), "src/http.ts".to_string()];
        let mut public_type = export_at("HttpApp", 3);
        public_type.is_type_only = true;
        let mut orphan_type = export_at("Orphaned", 9);
        orphan_type.is_type_only = true;
        let exports = vec![
            ("src/http.ts".to_string(), export_at("createHttpServer", 1)),
            ("src/http.ts".to_string(), public_type),
            ("src/http.ts".to_string(), orphan_type),
        ];
        let imports = vec![ImportEdge {
            source_file: "src/index.ts".to_string(),
            target_file: "src/http.ts".to_string(),
            imported_names: vec!["createHttpServer".to_string()],
            is_namespace: false,
        }];
        let signature_types = vec![("src/http.ts".to_string(), "HttpApp".to_string())];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &imports,
            path_literals: &[],
            signature_types: &signature_types,
        };
        let findings = analyze(&input);

        assert!(
            !findings.iter().any(|f| f.title.contains("HttpApp")),
            "a type in an exported signature is not dead: {findings:?}"
        );
        let orphan = findings
            .iter()
            .find(|f| f.title.contains("Orphaned"))
            .expect("a type no signature names is still unused");
        assert_eq!(orphan.rule_name.as_deref(), Some("unused-type"));

        // The exemption is type-only: an exported *value* sharing a name with a
        // signature type is still judged on whether anything imports it.
        let mut value_exports = exports.clone();
        value_exports.push(("src/http.ts".to_string(), export_at("HttpApp", 20)));
        let with_value = DeadCodeInput {
            exports: &value_exports,
            ..input
        };
        assert!(
            analyze(&with_value)
                .iter()
                .any(|f| f.title.starts_with("Unused export: HttpApp")),
            "the value export must still be judged"
        );
    }

    #[test]
    fn a_file_named_by_a_literal_is_only_possibly_unused() {
        // The failure that costs a user source: a task runner names its script
        // as a string, no import edge exists, and the file reads as dead. It
        // must be reported — but as a question, not a verdict, naming the
        // literal that raised it.
        let files = vec![
            "src/index.ts".to_string(),
            "tasks/build.ts".to_string(),
            "src/orphan.ts".to_string(),
        ];
        let path_literals = vec![
            ("src/index.ts".to_string(), literal("tasks/build.ts", 7)),
            // A file naming itself proves nothing.
            ("src/orphan.ts".to_string(), literal("src/orphan.ts", 2)),
        ];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &[],
            imports: &[],
            path_literals: &path_literals,
            signature_types: &[],
        };
        let findings = analyze(&input);

        let build = findings
            .iter()
            .find(|f| f.title.contains("tasks/build.ts"))
            .expect("a literal-named file is still reported");
        assert_eq!(build.kind, FindingKind::UnusedFile);
        assert_eq!(build.rule_name.as_deref(), Some("possibly-unused-file"));
        assert!(build.title.starts_with("Possibly unused file"));
        assert_eq!(
            build.evidence[0].detail.as_deref(),
            Some("referenced-by-literal")
        );
        assert!(
            build.description.contains("src/index.ts") && build.description.contains("line 7"),
            "the witness must be named: {}",
            build.description
        );

        // Nothing else names it, so the flat verdict survives — the backstop
        // must not swallow the true positive.
        let orphan = findings
            .iter()
            .find(|f| f.title.contains("src/orphan.ts"))
            .expect("a genuinely unreferenced file stays unused-file");
        assert_eq!(orphan.rule_name.as_deref(), Some("unused-file"));
        assert!(orphan.title.starts_with("Unused file"));
        assert!(orphan.evidence[0].detail.is_none());
    }

    #[test]
    fn a_literal_matches_a_file_by_name_and_trailing_directories() {
        // A literal spells a path from whatever root its reader uses, and none
        // of those roots is knowable here. Matching the name plus any trailing
        // run of directories covers them; matching a bare name substring would
        // let `worker.ts` claim `my-worker.ts`.
        assert!(names_file("worker.ts", "src/jobs/worker.ts"));
        assert!(names_file("jobs/worker.ts", "src/jobs/worker.ts"));
        assert!(names_file("./jobs/worker.ts", "src/jobs/worker.ts"));
        assert!(names_file("/src/jobs/worker.ts", "src/jobs/worker.ts"));
        assert!(names_file("src\\jobs\\worker.ts", "src/jobs/worker.ts"));
        assert!(names_file("src/jobs/worker.ts", "src/jobs/worker.ts"));
        // Not a segment boundary, and not the same file.
        assert!(!names_file("my-worker.ts", "src/jobs/worker.ts"));
        assert!(!names_file("worker.ts", "src/jobs/my-worker.ts"));
        assert!(!names_file("other/worker.ts", "src/jobs/worker.ts"));
        assert!(!names_file("", "src/jobs/worker.ts"));
    }

    #[test]
    fn a_live_witness_is_preferred_and_the_choice_is_stable() {
        // Several files can name the same target. A literal sitting in reachable
        // code is the stronger witness, and whichever is chosen must not depend
        // on iteration order.
        let files = vec![
            "src/index.ts".to_string(),
            "src/dead.ts".to_string(),
            "tasks/build.ts".to_string(),
        ];
        // `src/dead.ts` sorts before `src/index.ts`, so only the reachability
        // rank can put the live witness first.
        let path_literals = vec![
            ("src/dead.ts".to_string(), literal("tasks/build.ts", 1)),
            ("src/index.ts".to_string(), literal("tasks/build.ts", 9)),
        ];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &[],
            imports: &[],
            path_literals: &path_literals,
            signature_types: &[],
        };
        let description = analyze(&input)
            .into_iter()
            .find(|f| f.title.contains("tasks/build.ts"))
            .expect("reported")
            .description;
        assert!(
            description.contains("src/index.ts") && description.contains("line 9"),
            "the reachable witness must win: {description}"
        );
    }

    #[test]
    fn same_named_exports_on_different_lines_stay_distinct() {
        // A file exports `Widget` twice on different lines (declaration merging /
        // overloads). Both are unused and must survive as two distinct findings —
        // before the line entered the id they collided into one and were dropped.
        let files = vec!["src/index.ts".to_string(), "src/widget.ts".to_string()];
        let exports = vec![
            // `used` keeps widget.ts reachable so the unused-export rule fires.
            ("src/widget.ts".to_string(), export_at("used", 1)),
            ("src/widget.ts".to_string(), export_at("Widget", 10)),
            ("src/widget.ts".to_string(), export_at("Widget", 42)),
        ];
        let imports = vec![ImportEdge {
            source_file: "src/index.ts".to_string(),
            target_file: "src/widget.ts".to_string(),
            imported_names: vec!["used".to_string()],
            is_namespace: false,
        }];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &imports,
            path_literals: &[],
            signature_types: &[],
        };
        let findings = analyze(&input);
        let widgets = findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnusedExport && f.title.contains("Widget"))
            .count();
        assert_eq!(
            widgets, 2,
            "both same-named exports must be reported: {findings:?}"
        );
        assert!(
            unique_ids(&findings),
            "finding ids must be unique: {findings:?}"
        );
    }

    #[test]
    fn duplicate_export_facts_collapse_to_one_finding() {
        // Defensive: if the extractor ever emits the exact same export twice
        // (same file, name, and line), analyze() dedups it so the persisted
        // findings and the unused-export metric stay in lockstep.
        let files = vec!["src/index.ts".to_string(), "src/util.ts".to_string()];
        let exports = vec![
            ("src/util.ts".to_string(), export_at("used", 1)),
            ("src/util.ts".to_string(), export_at("dup", 7)),
            ("src/util.ts".to_string(), export_at("dup", 7)),
        ];
        let imports = vec![ImportEdge {
            source_file: "src/index.ts".to_string(),
            target_file: "src/util.ts".to_string(),
            imported_names: vec!["used".to_string()],
            is_namespace: false,
        }];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &imports,
            path_literals: &[],
            signature_types: &[],
        };
        let findings = analyze(&input);
        let dups = findings
            .iter()
            .filter(|f| f.kind == FindingKind::UnusedExport && f.title.contains("dup"))
            .count();
        assert_eq!(
            dups, 1,
            "identical export facts collapse to one finding: {findings:?}"
        );
        assert!(
            unique_ids(&findings),
            "finding ids must be unique: {findings:?}"
        );
    }

    #[test]
    fn namespace_import_credits_all_exports() {
        let files = vec!["src/index.ts".to_string(), "src/util.ts".to_string()];
        let exports = vec![
            ("src/util.ts".to_string(), export("a")),
            ("src/util.ts".to_string(), export("b")),
        ];
        let imports = vec![ImportEdge {
            source_file: "src/index.ts".to_string(),
            target_file: "src/util.ts".to_string(),
            imported_names: vec![],
            is_namespace: true,
        }];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &imports,
            path_literals: &[],
            signature_types: &[],
        };
        // `import *` uses the whole module, so neither export is unused.
        assert!(
            analyze(&input)
                .iter()
                .all(|f| f.kind != FindingKind::UnusedExport)
        );
    }
}
