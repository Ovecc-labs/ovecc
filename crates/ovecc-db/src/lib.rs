//! DuckDB persistence layer for the architecture index: versioned schema
//! migrations, differential sync of the extracted facts, the read queries,
//! and snapshot-scoped comparisons.
//!
//! Layering note: this crate never computes graph metrics or talks to Git.
//! Metric values and the commit SHA are computed upstream (indexer) and
//! passed in, so `ovecc-db` only depends on `ovecc-core`.

mod code_facts;
mod migrations;
mod queries;
mod replace;
mod runtime;
mod snapshots;
mod sync;

pub use migrations::LATEST_SCHEMA_VERSION;
pub use replace::finding_group_key;
pub use runtime::RouteRow;

use anyhow::{Context, Result};
use chrono::Utc;
use duckdb::{Connection, Transaction, params};
use ovecc_core::facts::{
    ApiRecord, CallRecord, CapabilityRecord, ComplexityRecord, Evidence, ExportRecord, FindingKind,
    FindingRecord, SchemaObjectRecord, Severity, SymbolRecord,
};
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use std::collections::HashSet;
use std::path::Path;

/// Resolved code-level facts persisted alongside the module-level index.
/// Borrowed slices of `ovecc-core` records produced by the indexer's
/// resolution layer.
#[derive(Default)]
pub struct ResolvedCode<'a> {
    pub symbols: &'a [SymbolRecord],
    pub calls: &'a [CallRecord],
    pub apis: &'a [ApiRecord],
    pub schema_objects: &'a [SchemaObjectRecord],
    /// `reads`/`writes` access edges (accessor symbol → table).
    pub schema_edges: &'a [SchemaEdge],
    /// Per-function complexity (oxc), persisted to the `complexity` table.
    pub complexity: &'a [ComplexityRecord],
    /// Per-file exports (oxc), persisted to the `exports` table.
    pub exports: &'a [ExportRecord],
    /// Ambient-capability uses (tree-sitter TS/JS), persisted to the
    /// `capability_uses` table.
    pub capability_uses: &'a [CapabilityRecord],
}

/// A dependency row for the OSV audit inventory.
#[derive(Debug, Clone)]
pub struct PackageRow {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    pub is_direct: bool,
}

/// A persisted `reads`/`writes` graph edge from an accessor symbol to a table.
#[derive(Debug, Clone)]
pub struct SchemaEdge {
    pub source_id: String,
    pub target_id: String,
    /// `"reads"` or `"writes"`.
    pub kind: String,
    pub evidence_json: String,
}

/// Per-file ownership measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct FileOwnership {
    pub file_path: String,
    /// Share of commits by the majority contributor, in `[0.0, 1.0]`.
    pub ownership: f64,
    /// Contributors with < 5% of the file's commits.
    pub minor_contributors: usize,
    /// Contributors with ≥ 5% of the file's commits.
    pub major_contributors: usize,
    pub total_commits: usize,
}

/// Half-life of a fix's weight, in days. Over the 365-day window the indexer
/// ingests, a one-year half-life separates almost nothing: the oldest commit
/// would still weigh 0.47. 180 days is a chosen compromise, not a measured
/// constant.
pub const FIX_HALF_LIFE_DAYS: f64 = 180.0;

/// Per-file fix history: how often bug-fix commits touched a file, and how
/// recent those fixes are.
#[derive(Debug, Clone, PartialEq)]
pub struct FileFixHistory {
    pub file_path: String,
    /// Fix commits that touched the file, unweighted.
    pub fixes: usize,
    /// The same fixes, each weighted by its age.
    pub mass: f64,
    /// RFC 3339 timestamp of the most recent fix.
    pub last_fix_at: String,
}

/// One commit as [`ArchitectureStore::commit_shapes`] reads it: the files it
/// touched, each with the days it had gone untouched when the commit landed.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitShapeRow {
    pub sha: String,
    /// Commit time in epoch seconds, for ordering.
    pub at: f64,
    pub files: Vec<(String, Option<f64>)>,
}

/// Differential statistics returned by [`ArchitectureStore::sync_current_index`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStats {
    pub files_added: usize,
    pub files_updated: usize,
    pub files_removed: usize,
    pub modules_added: usize,
    pub modules_removed: usize,
    pub dependencies_added: usize,
    pub dependencies_removed: usize,
    pub symbols_added: usize,
    pub symbols_removed: usize,
    pub calls_added: usize,
    pub calls_removed: usize,
    pub apis_added: usize,
    pub apis_removed: usize,
    pub schema_objects_added: usize,
    pub schema_objects_removed: usize,
}

/// Serializes a unit serde enum (`#[serde(rename_all = "snake_case")]`) to its
/// string form for storage, e.g. `SymbolKind::Function` → `"function"`.
pub(crate) fn enum_str<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        _ => String::new(),
    }
}

/// Inverse of [`enum_str`]: parses a stored string back into a unit serde enum.
pub(crate) fn parse_enum<T: serde::de::DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value.to_string())).ok()
}

/// Raw `findings` row, reconstructed into a [`FindingRecord`] on load.
struct FindingRow {
    id: String,
    snapshot_id: Option<String>,
    kind: String,
    severity: String,
    rule_name: Option<String>,
    target_id: Option<String>,
    title: String,
    description: String,
    evidence_json: Option<String>,
    created_at: String,
}

impl FindingRow {
    fn into_record(self, repository_id: &str) -> FindingRecord {
        use ovecc_core::facts::EntityRef;
        use ovecc_core::graph::NodeKind;

        let evidence: Vec<Evidence> = self
            .evidence_json
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();
        let created_at = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| chrono::DateTime::from_timestamp(0, 0).expect("epoch"));
        FindingRecord {
            id: FindingId::from_raw(self.id),
            repository_id: RepositoryId::from_raw(repository_id),
            snapshot_id: self.snapshot_id.map(SnapshotId::from_raw),
            // The target node kind is not stored; default to Module (only the
            // id is shown). Unknown enum strings fall back conservatively.
            kind: parse_enum::<FindingKind>(&self.kind).unwrap_or(FindingKind::ConventionDeviation),
            severity: parse_enum::<Severity>(&self.severity).unwrap_or(Severity::Low),
            rule_name: self.rule_name,
            target: self.target_id.map(|id| EntityRef {
                kind: NodeKind::Module,
                id,
            }),
            title: self.title,
            description: self.description,
            evidence,
            created_at,
        }
    }
}

impl SyncStats {
    /// True when the run changed nothing besides the appended snapshot.
    pub fn is_noop(&self) -> bool {
        *self == Self::default()
    }
}

pub struct ArchitectureStore {
    conn: Connection,
}

impl ArchitectureStore {
    /// Opens the database. DuckDB admits one writer per file per process, so a
    /// second open while another [`ArchitectureStore`] is alive fails here
    /// rather than deadlocking later — drop the first, or thread it through.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: Connection::open(path)
                .with_context(|| format!("failed to open DuckDB database {}", path.display()))?,
        })
    }
}

/// IDs of every row of `table` already persisted for the repository.
pub(crate) fn existing_ids(
    tx: &Transaction<'_>,
    table: &str,
    repository_id: &str,
) -> Result<HashSet<String>> {
    let mut statement = tx.prepare(&format!("SELECT id FROM {table} WHERE repository_id = ?"))?;
    let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
    Ok(collect_rows::<String>(rows)?.into_iter().collect())
}

pub(crate) fn collect_rows<T>(rows: impl Iterator<Item = duckdb::Result<T>>) -> Result<Vec<T>> {
    rows.collect::<duckdb::Result<Vec<_>>>().map_err(Into::into)
}

/// One `ovecc history` data point: (snapshot id, commit sha, created_at, value).
pub type MetricPoint = (String, Option<String>, String, f64);

/// One indexed file as `export graph` consumes it.
#[derive(Debug, Clone)]
pub struct FileGraphRow {
    pub path: String,
    pub language: String,
    pub size_bytes: u64,
    pub module: String,
}

/// One symbol definition site, as `read` and `grep` consume it: enough to name
/// the element and slice its source from disk without opening the whole file.
#[derive(Debug, Clone)]
pub struct SymbolDef {
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[cfg(test)]
mod testutil {
    use crate::ArchitectureStore;
    use chrono::Utc;
    use duckdb::params;
    use ovecc_core::facts::FindingRecord;
    use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
    use ovecc_core::legacy::{DependencyRecord, FileRecord, ModuleRecord, SourceLanguage};
    use ovecc_core::util::stable_id;

    pub(crate) fn temp_store() -> (tempfile::TempDir, ArchitectureStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ArchitectureStore::open(&dir.path().join("graph.db")).expect("open store");
        (dir, store)
    }

    pub(crate) fn table_exists(store: &ArchitectureStore, table: &str) -> bool {
        let count: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM information_schema.tables WHERE table_name = ?",
                params![table],
                |row| row.get(0),
            )
            .expect("query information_schema");
        count > 0
    }

    pub(crate) fn sample_finding(
        snapshot: &str,
        kind: ovecc_core::facts::FindingKind,
        path: &str,
        line: u32,
        symbol: &str,
        severity: ovecc_core::facts::Severity,
    ) -> FindingRecord {
        use ovecc_core::facts::Evidence;
        FindingRecord {
            id: FindingId::from_raw(format!("{snapshot}:{path}:{symbol}")),
            repository_id: RepositoryId::from_raw("repo:test"),
            snapshot_id: Some(SnapshotId::from_raw(snapshot)),
            kind,
            severity,
            rule_name: Some("r".to_string()),
            target: None,
            title: format!("{symbol} issue"),
            description: "d".to_string(),
            evidence: vec![Evidence {
                file_path: path.to_string(),
                line: Some(line),
                symbol: Some(symbol.to_string()),
                detail: None,
            }],
            created_at: Utc::now(),
        }
    }

    pub(crate) fn sample_module(repo: &str, name: &str) -> ModuleRecord {
        ModuleRecord {
            id: stable_id("module", &[repo, name]),
            repository_id: repo.to_string(),
            name: name.to_string(),
            path_prefix: format!("src/{name}"),
        }
    }

    pub(crate) fn sample_file(
        repo: &str,
        path: &str,
        hash: &str,
        module: &ModuleRecord,
    ) -> FileRecord {
        FileRecord {
            id: stable_id("file", &[repo, path]),
            repository_id: repo.to_string(),
            path: path.to_string(),
            absolute_path: std::path::PathBuf::from(path),
            language: SourceLanguage::TypeScript,
            content_hash: hash.to_string(),
            size_bytes: 10,
            module_id: module.id.clone(),
            module_name: module.name.clone(),
        }
    }

    pub(crate) fn sample_dependency(
        repo: &str,
        source: &FileRecord,
        target: &FileRecord,
        specifier: &str,
        line: usize,
    ) -> DependencyRecord {
        DependencyRecord {
            id: stable_id(
                "dependency",
                &[
                    repo,
                    &source.path,
                    specifier,
                    &target.module_name,
                    &line.to_string(),
                ],
            ),
            repository_id: repo.to_string(),
            source_file_id: source.id.clone(),
            target_file_id: Some(target.id.clone()),
            source_file_path: source.path.clone(),
            target_file_path: Some(target.path.clone()),
            source_module_id: source.module_id.clone(),
            target_module_id: target.module_id.clone(),
            source_module: source.module_name.clone(),
            target_module: target.module_name.clone(),
            specifier: specifier.to_string(),
            dependency_kind: "static_import".to_string(),
            is_external: false,
            evidence_line: line,
        }
    }

    pub(crate) fn count(store: &ArchitectureStore, sql: &str) -> i64 {
        store.conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }
}
