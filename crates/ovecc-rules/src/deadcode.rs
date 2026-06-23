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
//! Ported from fallow (research/fallow/crates/{graph/src/graph/reachability.rs,
//! graph/src/graph/re_exports, core/src/analyze/unused_exports.rs,
//! unused_files.rs}), MIT (c) 2026 Bart Waardenburg. See THIRD-PARTY-NOTICES.md.

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::Utc;
use ovecc_core::facts::{
    EntityRef, Evidence, ExportFact, FindingKind, FindingRecord, Severity,
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
}

/// Analyzes dead code, returning `UnusedExport` and `UnusedFile` findings. Empty
/// when no entry points are known (avoids flagging an entire tree).
pub fn analyze(input: &DeadCodeInput<'_>) -> Vec<FindingRecord> {
    if input.entry_points.is_empty() {
        return Vec::new();
    }

    let mut exports_by_file: HashMap<&str, Vec<&ExportFact>> = HashMap::new();
    for (file, export) in input.exports {
        exports_by_file.entry(file.as_str()).or_default().push(export);
    }

    // Out-edges for reachability (importer -> imported internal files).
    let mut out_edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in input.imports {
        out_edges
            .entry(edge.source_file.as_str())
            .or_default()
            .push(edge.target_file.as_str());
    }
    let reachable = bfs_reachable(input.entry_points, &out_edges);

    // refs[(target_file, export_name)] = set of importer files.
    let mut refs: HashMap<(&str, String), HashSet<&str>> = HashMap::new();
    for edge in input.imports {
        let exported = exports_by_file.get(edge.target_file.as_str());
        if edge.is_namespace {
            if let Some(exports) = exported {
                for export in exports {
                    refs.entry((edge.target_file.as_str(), export.name.clone()))
                        .or_default()
                        .insert(edge.source_file.as_str());
                }
            }
        } else {
            for name in &edge.imported_names {
                let exports_name = exported.is_some_and(|exports| exports.iter().any(|e| &e.name == name));
                if exports_name {
                    refs.entry((edge.target_file.as_str(), name.clone()))
                        .or_default()
                        .insert(edge.source_file.as_str());
                }
            }
        }
    }

    let mut findings = Vec::new();
    flag_unused_exports(input, &reachable, &refs, &mut findings);
    flag_unused_files(input, &reachable, &exports_by_file, &mut findings);
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings
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
    refs: &HashMap<(&str, String), HashSet<&str>>,
    out: &mut Vec<FindingRecord>,
) {
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
        let referenced = refs
            .get(&(file.as_str(), export.name.clone()))
            .is_some_and(|importers| importers.iter().any(|importer| reachable.contains(importer)));
        if referenced {
            continue;
        }
        out.push(finding(
            input,
            FindingKind::UnusedExport,
            Severity::Low,
            file,
            export.line,
            format!("Unused export: {} in {file}", export.name),
            format!(
                "'{}' is exported from {file} but never imported by a reachable module. \
                 Candidate for removal (verify it is not a public API surface).",
                export.name
            ),
            Some(export.name.clone()),
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
        let imported_by_reachable = importers_of
            .get(path)
            .is_some_and(|importers| importers.iter().any(|importer| reachable.contains(importer)));
        if imported_by_reachable {
            continue;
        }
        out.push(finding(
            input,
            FindingKind::UnusedFile,
            Severity::Low,
            file,
            1,
            format!("Unused file: {file}"),
            format!("{file} is not reachable from any entry point and nothing imports it."),
            None,
        ));
    }
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
) -> FindingRecord {
    let kind_slug = match kind {
        FindingKind::UnusedExport => "unused-export",
        _ => "unused-file",
    };
    FindingRecord {
        id: FindingId::from_parts(&[
            input.repository_id,
            "deadcode",
            kind_slug,
            file,
            symbol.as_deref().unwrap_or(""),
        ]),
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
        kind,
        severity,
        rule_name: Some(kind_slug.to_string()),
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
            detail: None,
        }],
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(name: &str) -> ExportFact {
        ExportFact {
            name: name.to_string(),
            local_name: None,
            is_type_only: false,
            line: 1,
            re_export: None,
        }
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
    fn flags_unused_file() {
        let files = vec![
            "src/index.ts".to_string(),
            "src/orphan.ts".to_string(),
        ];
        let exports = vec![("src/orphan.ts".to_string(), export("thing"))];
        let input = DeadCodeInput {
            repository_id: "r",
            snapshot_id: None,
            files: &files,
            entry_points: &entry(&["src/index.ts"]),
            exports: &exports,
            imports: &[],
        };
        let findings = analyze(&input);
        assert!(
            findings.iter().any(|f| f.kind == FindingKind::UnusedFile
                && f.title.contains("orphan")),
            "{findings:?}"
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
        };
        // `import *` uses the whole module, so neither export is unused.
        assert!(analyze(&input)
            .iter()
            .all(|f| f.kind != FindingKind::UnusedExport));
    }
}
