//! DuckDB persistence layer, carried over from
//! the MVP. The complete database schema and versioned migrations land in the
//! database roadmap step.
//!
//! Layering note: this crate never computes graph metrics or talks to Git.
//! Metric values and the commit SHA are computed upstream (indexer) and
//! passed in, so `ovecc-db` only depends on `ovecc-core`.

use anyhow::{Context, Result};
use chrono::Utc;
use duckdb::{Connection, Transaction, params};
use ovecc_core::facts::{
    ApiRecord, CallRecord, CommitRecord, ComplexityRecord, Evidence, ExportRecord,
    FileChangeRecord, FindingKind, FindingRecord, SchemaObjectRecord, Severity, SymbolRecord,
};
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_core::legacy::{
    DependencyEdge, DependencyRecord, DiffReport, DriftReport, FileRecord, MetricDelta,
    ModuleRecord, RiskLevel, SnapshotRecord, drift_trend,
};
use ovecc_core::report::{ChangedFiles, FindingDiff};
use ovecc_core::util::stable_id;
use std::collections::{BTreeSet, HashMap, HashSet};
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
fn enum_str<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        _ => String::new(),
    }
}

/// Inverse of [`enum_str`]: parses a stored string back into a unit serde enum.
fn parse_enum<T: serde::de::DeserializeOwned>(value: &str) -> Option<T> {
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

/// Stable, snapshot-independent content identity of a finding, so the *same*
/// defect in two snapshots collapses to one key and a set-difference yields the
/// genuinely new ones. Keyed by kind + first-evidence location (path, then the
/// enclosing symbol when known, else the pattern detail, else the line) + rule
/// — stable across unrelated edits elsewhere in the repo, where the volatile
/// per-run `FindingId` is not. Line numbers are the locator of last resort:
/// identifying by line blames a finding that merely *moved* (an edit above it)
/// on the change under review. `ordinal` disambiguates several otherwise
/// identical findings (e.g. two `eval` calls in one file), so only the extra
/// occurrence reads as new.
fn finding_identity(finding: &FindingRecord, ordinal: usize) -> String {
    let kind = enum_str(&finding.kind);
    let rule = finding.rule_name.clone().unwrap_or_default();
    let (path, locator) = match finding.evidence.first() {
        Some(evidence) => {
            let locator = evidence
                .symbol
                .clone()
                .or_else(|| evidence.detail.clone())
                .or_else(|| evidence.line.map(|line| line.to_string()))
                .unwrap_or_default();
            (evidence.file_path.clone(), locator)
        }
        // Evidence-free findings (rare) fall back to target id + title.
        None => (
            finding
                .target
                .as_ref()
                .map(|target| target.id.clone())
                .unwrap_or_default(),
            finding.title.clone(),
        ),
    };
    stable_id(
        "finding-identity",
        &[&kind, &path, &locator, &rule, &ordinal.to_string()],
    )
}

/// IDs of every row of `table` already persisted for the repository.
fn existing_ids(tx: &Transaction<'_>, table: &str, repository_id: &str) -> Result<HashSet<String>> {
    let mut statement = tx.prepare(&format!("SELECT id FROM {table} WHERE repository_id = ?"))?;
    let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
    Ok(collect_rows::<String>(rows)?.into_iter().collect())
}

impl SyncStats {
    /// True when the run changed nothing besides the appended snapshot.
    pub fn is_noop(&self) -> bool {
        *self == Self::default()
    }
}

/// Stable ID of a module→file `contains` edge (must match the insert path).
fn contains_edge_id(repository_id: &str, module_id: &str, file_id: &str) -> String {
    stable_id("edge", &[repository_id, module_id, file_id, "contains"])
}

/// Stable ID of a code-fact edge, derived solely from the owning fact's ID and
/// the edge kind so deletes (which know only the fact ID) can recompute it.
fn code_edge_id(repository_id: &str, fact_id: &str, kind: &str) -> String {
    stable_id("edge", &[repository_id, fact_id, kind])
}

/// Human-readable label for an API node, e.g. `GET /users/:id`.
fn api_label(api: &ApiRecord) -> String {
    let method = api.method.as_deref().unwrap_or("");
    let path = api.path.as_deref().or(api.name.as_deref()).unwrap_or("");
    format!("{method} {path}").trim().to_string()
}

/// Stable ID of a module→module `depends_on` edge (must match the insert path).
fn depends_on_edge_id(
    repository_id: &str,
    source_module_id: &str,
    target_module_id: &str,
    dependency_id: &str,
) -> String {
    stable_id(
        "edge",
        &[
            repository_id,
            source_module_id,
            target_module_id,
            dependency_id,
        ],
    )
}

/// Stable ID of a file→file `depends_on` edge. Derived from the owning
/// dependency's ID alone (like `code_edge_id`) so the delete path — which knows
/// only the dependency ID — can recompute it. These edges let blast/impact reach
/// a file's direct dependents, which the coarser module→module edge can't express.
fn depends_on_file_edge_id(repository_id: &str, dependency_id: &str) -> String {
    stable_id("edge", &[repository_id, dependency_id, "depends_on_file"])
}

/// One versioned schema migration. Migrations are append-only:
/// never edit a shipped migration, add a new version instead.
struct SchemaMigration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// Baseline schema carried over from the MVP (kept `IF NOT EXISTS` so that
/// databases created before the migration framework are stamped cleanly).
const MIGRATION_V1_MVP_BASELINE: &str = r#"
            CREATE TABLE IF NOT EXISTS repositories (
                id TEXT PRIMARY KEY,
                root_path TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                path TEXT NOT NULL,
                language TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                size_bytes BIGINT NOT NULL,
                module_id TEXT NOT NULL,
                module_name TEXT NOT NULL,
                last_indexed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS modules (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                name TEXT NOT NULL,
                path_prefix TEXT NOT NULL,
                module_kind TEXT,
                detected_layer TEXT,
                detected_domain TEXT
            );

            CREATE TABLE IF NOT EXISTS dependencies (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                source_file_id TEXT NOT NULL,
                target_file_id TEXT,
                source_file_path TEXT NOT NULL,
                target_file_path TEXT,
                source_module_id TEXT NOT NULL,
                target_module_id TEXT NOT NULL,
                source_module TEXT NOT NULL,
                target_module TEXT NOT NULL,
                specifier TEXT NOT NULL,
                dependency_kind TEXT NOT NULL,
                is_external BOOLEAN NOT NULL,
                evidence_line INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                node_kind TEXT NOT NULL,
                label TEXT NOT NULL,
                properties_json TEXT
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                edge_kind TEXT NOT NULL,
                weight DOUBLE,
                evidence_json TEXT
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                commit_sha TEXT,
                created_at TEXT NOT NULL,
                summary_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshot_modules (
                snapshot_id TEXT NOT NULL,
                module_name TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshot_dependencies (
                snapshot_id TEXT NOT NULL,
                source_module TEXT NOT NULL,
                target_module TEXT NOT NULL,
                specifier TEXT NOT NULL,
                is_external BOOLEAN NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshot_metrics (
                snapshot_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                value DOUBLE NOT NULL
            );
            "#;

/// Full architecture schema: symbols, calls, APIs,
/// database schema objects, repository migrations, ownership, Git facts,
/// scoped metrics, and findings. `evidence_json` columns stay TEXT so the
/// schema does not depend on the DuckDB JSON extension being loaded.
const MIGRATION_V2_FULL_SCHEMA: &str = r#"
            CREATE TABLE IF NOT EXISTS symbols (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                module_id TEXT,
                language TEXT NOT NULL,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                qualified_name TEXT NOT NULL,
                start_line INTEGER,
                end_line INTEGER,
                visibility TEXT,
                type_signature TEXT
            );

            CREATE TABLE IF NOT EXISTS calls (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                caller_symbol_id TEXT NOT NULL,
                callee_symbol_id TEXT,
                callee_name TEXT,
                call_kind TEXT NOT NULL,
                evidence_file_id TEXT,
                evidence_line INTEGER
            );

            CREATE TABLE IF NOT EXISTS apis (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                module_id TEXT,
                api_kind TEXT NOT NULL,
                method TEXT,
                path TEXT,
                name TEXT,
                handler_symbol_id TEXT,
                request_type TEXT,
                response_type TEXT,
                evidence_file_id TEXT,
                evidence_line INTEGER
            );

            CREATE TABLE IF NOT EXISTS schema_objects (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                schema_kind TEXT NOT NULL,
                name TEXT NOT NULL,
                parent_schema_id TEXT,
                evidence_file_id TEXT,
                evidence_line INTEGER
            );

            CREATE TABLE IF NOT EXISTS migrations (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                path TEXT NOT NULL,
                migration_name TEXT,
                sequence_number TEXT,
                created_at TEXT,
                content_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ownership (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                owner TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                source TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS commits (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                sha TEXT NOT NULL,
                parent_shas TEXT,
                author_name TEXT,
                author_email TEXT,
                committed_at TEXT NOT NULL,
                message TEXT
            );

            CREATE TABLE IF NOT EXISTS file_changes (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                commit_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                change_kind TEXT NOT NULL,
                additions INTEGER,
                deletions INTEGER
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_scope TEXT NOT NULL,
                target_id TEXT,
                value DOUBLE NOT NULL,
                unit TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                snapshot_id TEXT,
                finding_kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT,
                target_id TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_repo_path ON files (repository_id, path);
            CREATE INDEX IF NOT EXISTS idx_symbols_repo ON symbols (repository_id);
            CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols (file_id);
            CREATE INDEX IF NOT EXISTS idx_dependencies_repo ON dependencies (repository_id);
            CREATE INDEX IF NOT EXISTS idx_calls_repo ON calls (repository_id);
            CREATE INDEX IF NOT EXISTS idx_apis_repo ON apis (repository_id);
            CREATE INDEX IF NOT EXISTS idx_commits_repo_sha ON commits (repository_id, sha);
            CREATE INDEX IF NOT EXISTS idx_file_changes_commit ON file_changes (commit_id);
            CREATE INDEX IF NOT EXISTS idx_metrics_snapshot ON metrics (snapshot_id);
            CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings (repository_id);
            "#;

/// Dependency inventory for the OSV audit.
const MIGRATION_V3_PACKAGES: &str = r#"
            CREATE TABLE IF NOT EXISTS packages (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                manifest_path TEXT,
                is_direct BOOLEAN
            );

            CREATE INDEX IF NOT EXISTS idx_packages_repo ON packages (repository_id);
            "#;

/// First-class per-function complexity and per-file exports, so they are
/// queryable as data (not just transient findings) and back dead-code and
/// code-health inspection over the architecture database.
const MIGRATION_V4_CODE_HEALTH: &str = r#"
            CREATE TABLE IF NOT EXISTS complexity (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                qualified_name TEXT NOT NULL,
                line INTEGER NOT NULL,
                cyclomatic INTEGER NOT NULL,
                cognitive INTEGER NOT NULL,
                line_count INTEGER NOT NULL,
                param_count INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_complexity_repo ON complexity (repository_id);

            CREATE TABLE IF NOT EXISTS exports (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                name TEXT NOT NULL,
                line INTEGER NOT NULL,
                is_type_only BOOLEAN NOT NULL,
                re_export_source TEXT,
                re_export_name TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_exports_repo ON exports (repository_id);
            "#;

/// Per-snapshot retention of findings and file hashes. The base schema only
/// snapshots modules/dependencies/metrics (so drift could trend *counts*); this
/// retains the findings themselves and the file content hashes, so a change
/// between two snapshots can be reported as the **named** new defects and scoped
/// to the files it touched. Append-only, exactly like `snapshot_modules`.
const MIGRATION_V5_SNAPSHOT_RETENTION: &str = r#"
            CREATE TABLE IF NOT EXISTS snapshot_findings (
                snapshot_id TEXT NOT NULL,
                identity TEXT NOT NULL,
                id TEXT NOT NULL,
                finding_kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT,
                target_id TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_json TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshot_findings_snap ON snapshot_findings (snapshot_id);

            CREATE TABLE IF NOT EXISTS snapshot_files (
                snapshot_id TEXT NOT NULL,
                path TEXT NOT NULL,
                content_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshot_files_snap ON snapshot_files (snapshot_id);
            "#;

const SCHEMA_MIGRATIONS: &[SchemaMigration] = &[
    SchemaMigration {
        version: 1,
        name: "mvp_baseline",
        sql: MIGRATION_V1_MVP_BASELINE,
    },
    SchemaMigration {
        version: 2,
        name: "full_architecture_schema",
        sql: MIGRATION_V2_FULL_SCHEMA,
    },
    SchemaMigration {
        version: 3,
        name: "packages",
        sql: MIGRATION_V3_PACKAGES,
    },
    SchemaMigration {
        version: 4,
        name: "code_health",
        sql: MIGRATION_V4_CODE_HEALTH,
    },
    SchemaMigration {
        version: 5,
        name: "snapshot_retention",
        sql: MIGRATION_V5_SNAPSHOT_RETENTION,
    },
];

pub struct ArchitectureStore {
    conn: Connection,
}

impl ArchitectureStore {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            conn: Connection::open(path)
                .with_context(|| format!("failed to open DuckDB database {}", path.display()))?,
        })
    }

    /// Current schema version, or `None` for a database that predates the
    /// migration framework (or a brand-new file).
    pub fn schema_version(&self) -> Result<Option<i64>> {
        let table_count: i64 = self.conn.query_row(
            "SELECT count(*) FROM information_schema.tables WHERE table_name = 'ovecc_schema'",
            [],
            |row| row.get(0),
        )?;
        if table_count == 0 {
            return Ok(None);
        }
        let version: Option<i64> =
            self.conn
                .query_row("SELECT max(version) FROM ovecc_schema", [], |row| {
                    row.get(0)
                })?;
        Ok(version)
    }

    /// Applies pending migrations in order, each in its own transaction, and
    /// records them in `ovecc_schema`. Idempotent.
    pub fn migrate_to_latest(&mut self) -> Result<i64> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ovecc_schema (
                version BIGINT NOT NULL,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );",
        )?;
        let current = self.schema_version()?.unwrap_or(0);

        let mut latest = current;
        for migration in SCHEMA_MIGRATIONS {
            if migration.version <= current {
                continue;
            }
            let now = Utc::now().to_rfc3339();
            let tx = self.conn.transaction().with_context(|| {
                format!(
                    "failed to start transaction for migration v{}",
                    migration.version
                )
            })?;
            tx.execute_batch(migration.sql).with_context(|| {
                format!(
                    "migration v{} ({}) failed",
                    migration.version, migration.name
                )
            })?;
            tx.execute(
                "INSERT INTO ovecc_schema (version, name, applied_at) VALUES (?, ?, ?)",
                params![migration.version, migration.name, now],
            )?;
            tx.commit()?;
            latest = migration.version;
        }
        Ok(latest)
    }

    /// Backwards-compatible entry point used by the indexer and CLI.
    pub fn initialize_schema(&mut self) -> Result<()> {
        self.migrate_to_latest().map(|_| ())
    }

    /// Synchronizes the persisted index with the freshly extracted state.
    ///
    /// Replaces the MVP "delete everything, reinsert everything" strategy
    /// (groundwork for incremental indexing): rows are diffed by their
    /// stable IDs, only added/changed/removed facts touch the
    /// database, and everything runs in one transaction with reused prepared
    /// statements. Append-only snapshot rows go through the DuckDB appender.
    ///
    /// Known limit (until the incremental indexer lands): a dependency whose
    /// resolved target file changes within the same module keeps its stable
    /// ID and is not rewritten.
    #[allow(clippy::too_many_arguments)]
    pub fn sync_current_index(
        &mut self,
        repository_id: &str,
        repository_root: &str,
        modules: &[ModuleRecord],
        files: &[FileRecord],
        dependencies: &[DependencyRecord],
        snapshot_id: &str,
        commit_sha: Option<&str>,
        metrics: &[(String, f64)],
        code: &ResolvedCode<'_>,
    ) -> Result<SyncStats> {
        let now = Utc::now().to_rfc3339();
        let mut stats = SyncStats::default();
        let tx = self.conn.transaction()?;

        let prof = std::env::var_os("OVECC_PERSIST_PROFILE").is_some();
        let prof_t0 = std::time::Instant::now();
        let mark = |label: &str| {
            if prof {
                eprintln!(
                    "[persist] {label:<14} +{} ms",
                    prof_t0.elapsed().as_millis()
                );
            }
        };

        // Repository upsert: created_at survives re-indexing.
        let updated = tx.execute(
            "UPDATE repositories SET root_path = ?, name = ?, updated_at = ? WHERE id = ?",
            params![
                repository_root,
                repository_name(repository_root),
                now,
                repository_id
            ],
        )?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO repositories (id, root_path, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                params![repository_id, repository_root, repository_name(repository_root), now, now],
            )?;
        }

        // ---- persisted state, keyed by stable IDs ----
        let existing_files: HashMap<String, (String, String)> = {
            let mut statement = tx
                .prepare("SELECT id, content_hash, module_id FROM files WHERE repository_id = ?")?;
            let rows = statement.query_map(params![repository_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
                ))
            })?;
            collect_rows(rows)?.into_iter().collect()
        };
        let existing_modules: HashMap<String, String> = {
            let mut statement =
                tx.prepare("SELECT id, path_prefix FROM modules WHERE repository_id = ?")?;
            let rows = statement.query_map(params![repository_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            collect_rows(rows)?.into_iter().collect()
        };
        let existing_dependencies: HashMap<String, (String, String)> = {
            let mut statement = tx.prepare(
                "SELECT id, source_module_id, target_module_id FROM dependencies WHERE repository_id = ?",
            )?;
            let rows = statement.query_map(params![repository_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
                ))
            })?;
            collect_rows(rows)?.into_iter().collect()
        };

        // ---- diff by stable IDs ----
        let new_file_ids: HashSet<&str> = files.iter().map(|file| file.id.as_str()).collect();
        let new_module_ids: HashSet<&str> =
            modules.iter().map(|module| module.id.as_str()).collect();

        let mut new_dependency_ids = HashSet::new();
        let mut dependencies_to_add = Vec::new();
        for dependency in dependencies {
            // In-batch dedup: stable IDs must stay unique per run.
            if !new_dependency_ids.insert(dependency.id.as_str()) {
                continue;
            }
            if !existing_dependencies.contains_key(&dependency.id) {
                dependencies_to_add.push(dependency);
            }
        }

        let files_to_remove: Vec<(String, String)> = existing_files
            .iter()
            .filter(|(id, _)| !new_file_ids.contains(id.as_str()))
            .map(|(id, (_, module_id))| (id.clone(), module_id.clone()))
            .collect();
        let mut files_to_add = Vec::new();
        let mut files_to_update = Vec::new();
        for file in files {
            match existing_files.get(&file.id) {
                None => files_to_add.push(file),
                Some((hash, module_id))
                    if *hash != file.content_hash || *module_id != file.module_id =>
                {
                    files_to_update.push((file, module_id.clone()));
                }
                Some(_) => {}
            }
        }

        let modules_to_remove: Vec<String> = existing_modules
            .keys()
            .filter(|id| !new_module_ids.contains(id.as_str()))
            .cloned()
            .collect();
        let mut modules_to_add = Vec::new();
        let mut modules_to_reprefix = Vec::new();
        for module in modules {
            match existing_modules.get(&module.id) {
                None => modules_to_add.push(module),
                Some(prefix) if *prefix != module.path_prefix => modules_to_reprefix.push(module),
                Some(_) => {}
            }
        }

        let dependencies_to_remove: Vec<(String, String, String)> = existing_dependencies
            .iter()
            .filter(|(id, _)| !new_dependency_ids.contains(id.as_str()))
            .map(|(id, (source, target))| (id.clone(), source.clone(), target.clone()))
            .collect();

        // ---- targeted deletes ----
        {
            let mut delete_file = tx.prepare("DELETE FROM files WHERE id = ?")?;
            let mut delete_module = tx.prepare("DELETE FROM modules WHERE id = ?")?;
            let mut delete_dependency = tx.prepare("DELETE FROM dependencies WHERE id = ?")?;
            let mut delete_node = tx.prepare("DELETE FROM graph_nodes WHERE id = ?")?;
            let mut delete_edge = tx.prepare("DELETE FROM graph_edges WHERE id = ?")?;

            for (file_id, module_id) in &files_to_remove {
                delete_file.execute(params![file_id])?;
                delete_node.execute(params![file_id])?;
                delete_edge.execute(params![contains_edge_id(
                    repository_id,
                    module_id,
                    file_id
                )])?;
                stats.files_removed += 1;
            }
            for (file, old_module_id) in &files_to_update {
                delete_file.execute(params![file.id])?;
                if *old_module_id != file.module_id {
                    delete_edge.execute(params![contains_edge_id(
                        repository_id,
                        old_module_id,
                        &file.id
                    )])?;
                }
                stats.files_updated += 1;
            }
            for (dependency_id, source_module_id, target_module_id) in &dependencies_to_remove {
                delete_dependency.execute(params![dependency_id])?;
                delete_edge.execute(params![depends_on_edge_id(
                    repository_id,
                    source_module_id,
                    target_module_id,
                    dependency_id
                )])?;
                // Mirror of the file→file edge added on insert (no-op if absent).
                delete_edge.execute(params![depends_on_file_edge_id(
                    repository_id,
                    dependency_id
                )])?;
                stats.dependencies_removed += 1;
            }
            for module_id in &modules_to_remove {
                delete_module.execute(params![module_id])?;
                delete_node.execute(params![module_id])?;
                stats.modules_removed += 1;
            }
            for module in &modules_to_reprefix {
                tx.execute(
                    "UPDATE modules SET path_prefix = ? WHERE id = ?",
                    params![module.path_prefix, module.id],
                )?;
            }
        }

        // ---- inserts ----
        // New rows go through the columnar appender rather than per-row prepared
        // statements: on large repos the `dependencies`/`files` inserts (tens to
        // hundreds of thousands of rows, each a round-trip) were the dominant
        // persist cost. Each table gets its own scoped appender; ids are
        // deduplicated first because the appender fails silently on a duplicate
        // primary key. Updated files keep the prepared-statement path — a small
        // set, and a re-insert rather than an append.
        {
            let mut modules = tx.appender("modules")?;
            for module in &modules_to_add {
                modules.append_row(params![
                    module.id,
                    module.repository_id,
                    module.name,
                    module.path_prefix,
                    "inferred",
                    Option::<String>::None,
                    Option::<String>::None
                ])?;
                stats.modules_added += 1;
            }
        }
        {
            let mut files = tx.appender("files")?;
            for file in &files_to_add {
                files.append_row(params![
                    file.id,
                    file.repository_id,
                    file.path,
                    file.language.as_str(),
                    file.content_hash,
                    file.size_bytes as i64,
                    file.module_id,
                    file.module_name,
                    now
                ])?;
                stats.files_added += 1;
            }
        }
        {
            let mut deps = tx.appender("dependencies")?;
            let mut seen = HashSet::new();
            for dependency in &dependencies_to_add {
                if !seen.insert(dependency.id.as_str()) {
                    continue;
                }
                deps.append_row(params![
                    dependency.id,
                    dependency.repository_id,
                    dependency.source_file_id,
                    dependency.target_file_id,
                    dependency.source_file_path,
                    dependency.target_file_path,
                    dependency.source_module_id,
                    dependency.target_module_id,
                    dependency.source_module,
                    dependency.target_module,
                    dependency.specifier,
                    dependency.dependency_kind,
                    dependency.is_external,
                    dependency.evidence_line as i32,
                    now
                ])?;
                stats.dependencies_added += 1;
            }
        }
        {
            let mut nodes = tx.appender("graph_nodes")?;
            for module in &modules_to_add {
                nodes.append_row(params![
                    module.id,
                    repository_id,
                    "module",
                    module.name,
                    "{}"
                ])?;
            }
            for file in &files_to_add {
                nodes.append_row(params![file.id, repository_id, "file", file.path, "{}"])?;
            }
        }
        {
            let mut edges = tx.appender("graph_edges")?;
            let mut seen = HashSet::new();
            for file in &files_to_add {
                let edge_id = contains_edge_id(repository_id, &file.module_id, &file.id);
                if !seen.insert(edge_id.clone()) {
                    continue;
                }
                edges.append_row(params![
                    edge_id,
                    repository_id,
                    file.module_id,
                    file.id,
                    "contains",
                    1.0_f64,
                    "{}"
                ])?;
            }
            for dependency in &dependencies_to_add {
                // File→file edge first: lets blast/impact reach a file's direct
                // dependents (the module→module edge alone hides intra-module
                // coupling). Only internal deps carry a target file node; skip
                // self-loops.
                if let Some(target_file_id) = dependency.target_file_id.as_deref()
                    && !dependency.is_external
                    && !target_file_id.is_empty()
                    && dependency.source_file_id != target_file_id
                {
                    let file_edge_id = depends_on_file_edge_id(repository_id, &dependency.id);
                    if seen.insert(file_edge_id.clone()) {
                        edges.append_row(params![
                            file_edge_id,
                            repository_id,
                            dependency.source_file_id,
                            target_file_id,
                            "depends_on",
                            1.0_f64,
                            format!(
                                r#"{{"file":"{}","line":{},"specifier":"{}"}}"#,
                                dependency.source_file_path,
                                dependency.evidence_line,
                                dependency.specifier
                            )
                        ])?;
                    }
                }
                let edge_id = depends_on_edge_id(
                    repository_id,
                    &dependency.source_module_id,
                    &dependency.target_module_id,
                    &dependency.id,
                );
                if !seen.insert(edge_id.clone()) {
                    continue;
                }
                edges.append_row(params![
                    edge_id,
                    repository_id,
                    dependency.source_module_id,
                    dependency.target_module_id,
                    "depends_on",
                    1.0_f64,
                    format!(
                        r#"{{"file":"{}","line":{},"specifier":"{}"}}"#,
                        dependency.source_file_path, dependency.evidence_line, dependency.specifier
                    )
                ])?;
            }
        }
        // Updated files: re-insert the row and re-link the module edge when the
        // module changed. Prepared statements, scoped after the appenders so the
        // connection is free.
        {
            let mut insert_file = tx.prepare(
                "INSERT INTO files (id, repository_id, path, language, content_hash, size_bytes, module_id, module_name, last_indexed_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            let mut insert_edge = tx.prepare(
                "INSERT INTO graph_edges (id, repository_id, source_id, target_id, edge_kind, weight, evidence_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            for (file, old_module_id) in &files_to_update {
                insert_file.execute(params![
                    file.id,
                    file.repository_id,
                    file.path,
                    file.language.as_str(),
                    file.content_hash,
                    file.size_bytes as i64,
                    file.module_id,
                    file.module_name,
                    now
                ])?;
                if *old_module_id != file.module_id {
                    insert_edge.execute(params![
                        contains_edge_id(repository_id, &file.module_id, &file.id),
                        repository_id,
                        file.module_id,
                        file.id,
                        "contains",
                        1.0_f64,
                        "{}"
                    ])?;
                }
            }
        }

        mark("graph+rows");
        // ---- code-level facts: symbols, calls, APIs, schema objects ----
        Self::sync_code_facts(&tx, repository_id, code, &mut stats)?;

        // ---- reads/writes access edges, diffed by their own ID ----
        Self::sync_schema_access_edges(&tx, repository_id, code)?;

        mark("code-facts");
        // ---- code-health facts: complexity + exports (full replace) ----
        Self::replace_health_facts(&tx, repository_id, code)?;

        mark("v4-health");
        // ---- snapshot rows (append-only; bulk via the DuckDB appender) ----
        let circular_dependencies = metrics
            .iter()
            .find(|(name, _)| name == "circular_dependencies")
            .map(|(_, value)| *value as i64)
            .unwrap_or(0);
        let summary_hash = stable_id(
            "summary",
            &[
                repository_id,
                &modules.len().to_string(),
                &dependencies.len().to_string(),
                &circular_dependencies.to_string(),
            ],
        );

        tx.execute(
            "INSERT INTO snapshots (id, repository_id, commit_sha, created_at, summary_hash) VALUES (?, ?, ?, ?, ?)",
            params![snapshot_id, repository_id, commit_sha, now, summary_hash],
        )?;

        {
            let mut appender = tx.appender("snapshot_modules")?;
            for module in modules {
                appender.append_row(params![snapshot_id, module.name])?;
            }
        }
        {
            let mut appender = tx.appender("snapshot_dependencies")?;
            for dependency in dependencies {
                appender.append_row(params![
                    snapshot_id,
                    dependency.source_module,
                    dependency.target_module,
                    dependency.specifier,
                    dependency.is_external
                ])?;
            }
        }
        {
            let mut appender = tx.appender("snapshot_metrics")?;
            for (name, value) in metrics {
                appender.append_row(params![snapshot_id, name, value])?;
            }
        }
        {
            // Retain per-file content hashes so a later review can tell exactly
            // which files a change added/modified (and scope clone detection to
            // them). Append-only, like the other snapshot_* tables.
            let mut appender = tx.appender("snapshot_files")?;
            for file in files {
                appender.append_row(params![snapshot_id, file.path, file.content_hash])?;
            }
        }

        mark("snapshot");
        tx.commit()?;
        mark("commit");
        Ok(stats)
    }

    /// Diffs and persists the code-level facts (symbols, calls, APIs, schema
    /// objects) plus the graph nodes/edges mirroring them. Diffed by stable ID
    /// like the module-level tables: unchanged files keep identical IDs (same
    /// content -> same spans), so re-indexing them is a no-op; a changed file
    /// replaces only its own rows.
    fn sync_code_facts(
        tx: &Transaction<'_>,
        repository_id: &str,
        code: &ResolvedCode<'_>,
        stats: &mut SyncStats,
    ) -> Result<()> {
        let prior_symbols = existing_ids(tx, "symbols", repository_id)?;
        let prior_calls = existing_ids(tx, "calls", repository_id)?;
        let prior_apis = existing_ids(tx, "apis", repository_id)?;
        let prior_schema = existing_ids(tx, "schema_objects", repository_id)?;

        let new_symbols: HashSet<&str> = code.symbols.iter().map(|s| s.id.as_str()).collect();
        let new_calls: HashSet<&str> = code.calls.iter().map(|c| c.id.as_str()).collect();
        let new_apis: HashSet<&str> = code.apis.iter().map(|a| a.id.as_str()).collect();
        let new_schema: HashSet<&str> = code.schema_objects.iter().map(|s| s.id.as_str()).collect();

        // edges.
        // Scoped so these prepared statements drop before the bulk appenders
        // below claim the connection.
        {
            let mut delete_edge = tx.prepare("DELETE FROM graph_edges WHERE id = ?")?;
            let mut delete_node = tx.prepare("DELETE FROM graph_nodes WHERE id = ?")?;
            for (table, prior, current) in [
                ("symbols", &prior_symbols, &new_symbols),
                ("calls", &prior_calls, &new_calls),
                ("apis", &prior_apis, &new_apis),
                ("schema_objects", &prior_schema, &new_schema),
            ] {
                let mut delete = tx.prepare(&format!("DELETE FROM {table} WHERE id = ?"))?;
                let removed = prior
                    .iter()
                    .filter(|id| !current.contains(id.as_str()))
                    .count();
                for id in prior.iter().filter(|id| !current.contains(id.as_str())) {
                    delete.execute(params![id])?;
                    match table {
                        "symbols" => {
                            delete_edge.execute(params![code_edge_id(
                                repository_id,
                                id,
                                "declares"
                            )])?;
                            delete_node.execute(params![id])?;
                        }
                        "calls" => {
                            delete_edge.execute(params![code_edge_id(
                                repository_id,
                                id,
                                "calls"
                            )])?;
                        }
                        "apis" => {
                            delete_edge.execute(params![code_edge_id(
                                repository_id,
                                id,
                                "exposes"
                            )])?;
                            delete_edge.execute(params![code_edge_id(
                                repository_id,
                                id,
                                "handles"
                            )])?;
                            delete_node.execute(params![id])?;
                        }
                        "schema_objects" => {
                            delete_node.execute(params![id])?;
                        }
                        _ => {}
                    }
                }
                match table {
                    "symbols" => stats.symbols_removed = removed,
                    "calls" => stats.calls_removed = removed,
                    "apis" => stats.apis_removed = removed,
                    _ => stats.schema_objects_removed = removed,
                }
            }
        }

        // Bulk inserts via DuckDB appenders: one columnar append per
        // table is far cheaper than per-row INSERTs for the high-volume code
        // facts (symbols, calls, and their graph nodes/edges). Each appender
        // is scoped so it flushes (on drop) before the next one opens — only
        // one may borrow the connection at a time. `start_line`/`end_line`/
        // `evidence_line` are INTEGER, so they are appended as `i32`.
        let mut seen_symbols = HashSet::new();
        let mut seen_calls = HashSet::new();
        let mut seen_apis = HashSet::new();
        let mut seen_schema = HashSet::new();
        {
            let mut symbols = tx.appender("symbols")?;
            for symbol in code.symbols {
                if prior_symbols.contains(symbol.id.as_str())
                    || !seen_symbols.insert(symbol.id.as_str())
                {
                    continue;
                }
                let (start_line, end_line) = match symbol.span {
                    Some(span) => (Some(span.start_line as i32), Some(span.end_line as i32)),
                    None => (None, None),
                };
                symbols.append_row(params![
                    symbol.id.as_str(),
                    symbol.repository_id.as_str(),
                    symbol.file_id.as_str(),
                    symbol.module_id.as_ref().map(|m| m.as_str()),
                    symbol.language.as_str(),
                    enum_str(&symbol.kind),
                    symbol.name,
                    symbol.qualified_name,
                    start_line,
                    end_line,
                    symbol.visibility.as_ref().map(enum_str),
                    symbol.type_signature,
                ])?;
                stats.symbols_added += 1;
            }
        }
        {
            let mut calls = tx.appender("calls")?;
            for call in code.calls {
                if prior_calls.contains(call.id.as_str()) || !seen_calls.insert(call.id.as_str()) {
                    continue;
                }
                calls.append_row(params![
                    call.id.as_str(),
                    call.repository_id.as_str(),
                    call.caller_symbol_id.as_str(),
                    call.callee_symbol_id.as_ref().map(|s| s.as_str()),
                    call.callee_name,
                    enum_str(&call.kind),
                    Option::<&str>::None,
                    call.evidence
                        .as_ref()
                        .and_then(|e| e.line)
                        .map(|l| l as i32),
                ])?;
                stats.calls_added += 1;
            }
        }
        {
            let mut apis = tx.appender("apis")?;
            for api in code.apis {
                if prior_apis.contains(api.id.as_str()) || !seen_apis.insert(api.id.as_str()) {
                    continue;
                }
                apis.append_row(params![
                    api.id.as_str(),
                    api.repository_id.as_str(),
                    api.module_id.as_ref().map(|m| m.as_str()),
                    enum_str(&api.kind),
                    api.method,
                    api.path,
                    api.name,
                    api.handler_symbol_id.as_ref().map(|s| s.as_str()),
                    api.request_type,
                    api.response_type,
                    Option::<&str>::None,
                    api.evidence.as_ref().and_then(|e| e.line).map(|l| l as i32),
                ])?;
                stats.apis_added += 1;
            }
        }
        {
            let mut schema = tx.appender("schema_objects")?;
            for object in code.schema_objects {
                if prior_schema.contains(object.id.as_str())
                    || !seen_schema.insert(object.id.as_str())
                {
                    continue;
                }
                schema.append_row(params![
                    object.id.as_str(),
                    object.repository_id.as_str(),
                    enum_str(&object.kind),
                    object.name,
                    object.parent_id.as_ref().map(|p| p.as_str()),
                    Option::<&str>::None,
                    object
                        .evidence
                        .as_ref()
                        .and_then(|e| e.line)
                        .map(|l| l as i32),
                ])?;
                stats.schema_objects_added += 1;
            }
        }
        // Graph nodes mirror the code facts (symbols, APIs, tables) so
        // blast analysis can classify and label traversed ids.
        {
            let mut nodes = tx.appender("graph_nodes")?;
            let mut seen_nodes = HashSet::new();
            for symbol in code.symbols {
                if prior_symbols.contains(symbol.id.as_str())
                    || !seen_nodes.insert(symbol.id.as_str())
                {
                    continue;
                }
                nodes.append_row(params![
                    symbol.id.as_str(),
                    repository_id,
                    "symbol",
                    symbol.qualified_name,
                    "{}"
                ])?;
            }
            for api in code.apis {
                if prior_apis.contains(api.id.as_str()) || !seen_nodes.insert(api.id.as_str()) {
                    continue;
                }
                nodes.append_row(params![
                    api.id.as_str(),
                    repository_id,
                    "api",
                    api_label(api),
                    "{}"
                ])?;
            }
            for object in code.schema_objects {
                if prior_schema.contains(object.id.as_str())
                    || !seen_nodes.insert(object.id.as_str())
                {
                    continue;
                }
                nodes.append_row(params![
                    object.id.as_str(),
                    repository_id,
                    enum_str(&object.kind),
                    object.name,
                    "{}"
                ])?;
            }
        }
        // Graph edges derived from the code facts: a file
        // `declares` each symbol, a caller `calls` each resolved callee, and
        // a module `exposes`/`handles` each API.
        {
            let mut edges = tx.appender("graph_edges")?;
            let mut seen_edges = HashSet::new();
            for symbol in code.symbols {
                if prior_symbols.contains(symbol.id.as_str()) {
                    continue;
                }
                let edge_id = code_edge_id(repository_id, symbol.id.as_str(), "declares");
                if !seen_edges.insert(edge_id.clone()) {
                    continue;
                }
                edges.append_row(params![
                    edge_id,
                    repository_id,
                    symbol.file_id.as_str(),
                    symbol.id.as_str(),
                    "declares",
                    1.0_f64,
                    "{}"
                ])?;
            }
            for call in code.calls {
                if prior_calls.contains(call.id.as_str()) {
                    continue;
                }
                // Only resolved calls carry an edge.
                if let Some(callee) = &call.callee_symbol_id {
                    let edge_id = code_edge_id(repository_id, call.id.as_str(), "calls");
                    if !seen_edges.insert(edge_id.clone()) {
                        continue;
                    }
                    edges.append_row(params![
                        edge_id,
                        repository_id,
                        call.caller_symbol_id.as_str(),
                        callee.as_str(),
                        "calls",
                        1.0_f64,
                        "{}"
                    ])?;
                }
            }
            for api in code.apis {
                if prior_apis.contains(api.id.as_str()) {
                    continue;
                }
                if let Some(module) = &api.module_id {
                    let edge_id = code_edge_id(repository_id, api.id.as_str(), "exposes");
                    if seen_edges.insert(edge_id.clone()) {
                        edges.append_row(params![
                            edge_id,
                            repository_id,
                            module.as_str(),
                            api.id.as_str(),
                            "exposes",
                            1.0_f64,
                            "{}"
                        ])?;
                    }
                }
                if let Some(handler) = &api.handler_symbol_id {
                    let edge_id = code_edge_id(repository_id, api.id.as_str(), "handles");
                    if seen_edges.insert(edge_id.clone()) {
                        edges.append_row(params![
                            edge_id,
                            repository_id,
                            api.id.as_str(),
                            handler.as_str(),
                            "handles",
                            1.0_f64,
                            "{}"
                        ])?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads/writes access edges (symbol -> table), diffed by their own ID.
    fn sync_schema_access_edges(
        tx: &Transaction<'_>,
        repository_id: &str,
        code: &ResolvedCode<'_>,
    ) -> Result<()> {
        let prior: HashSet<String> = {
            let mut statement = tx.prepare(
                "SELECT id FROM graph_edges WHERE repository_id = ? AND edge_kind IN ('reads', 'writes')",
            )?;
            let rows =
                statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
            collect_rows::<String>(rows)?.into_iter().collect()
        };
        let mut new_ids: HashSet<String> = HashSet::new();
        let mut insert_access = tx.prepare(
            "INSERT INTO graph_edges (id, repository_id, source_id, target_id, edge_kind, weight, evidence_json)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )?;
        for edge in code.schema_edges {
            let id = stable_id(
                "edge",
                &[repository_id, &edge.source_id, &edge.target_id, &edge.kind],
            );
            if !new_ids.insert(id.clone()) || prior.contains(&id) {
                continue;
            }
            insert_access.execute(params![
                id,
                repository_id,
                edge.source_id,
                edge.target_id,
                edge.kind,
                1.0_f64,
                edge.evidence_json,
            ])?;
        }
        let mut delete_access = tx.prepare("DELETE FROM graph_edges WHERE id = ?")?;
        for id in prior.iter().filter(|id| !new_ids.contains(id.as_str())) {
            delete_access.execute(params![id])?;
        }
        Ok(())
    }

    /// Code-health facts: per-function complexity and per-file exports. These
    /// are derived current-state, recomputed every run, so a full replace per
    /// repository is simpler than a differential sync. `line` columns are
    /// INTEGER, hence the i32 casts. Ids are deduplicated before the appender,
    /// which would otherwise fail silently on a duplicate PK.
    fn replace_health_facts(
        tx: &Transaction<'_>,
        repository_id: &str,
        code: &ResolvedCode<'_>,
    ) -> Result<()> {
        tx.execute(
            "DELETE FROM complexity WHERE repository_id = ?",
            params![repository_id],
        )?;
        tx.execute(
            "DELETE FROM exports WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut seen = HashSet::new();
            let mut appender = tx.appender("complexity")?;
            for record in code.complexity {
                if !seen.insert(record.id.as_str()) {
                    continue;
                }
                appender.append_row(params![
                    record.id.as_str(),
                    record.repository_id.as_str(),
                    record.file_id.as_str(),
                    record.qualified_name,
                    record.line as i32,
                    record.cyclomatic as i32,
                    record.cognitive as i32,
                    record.line_count as i32,
                    record.param_count as i32,
                ])?;
            }
        }
        {
            let mut seen = HashSet::new();
            let mut appender = tx.appender("exports")?;
            for record in code.exports {
                if !seen.insert(record.id.as_str()) {
                    continue;
                }
                appender.append_row(params![
                    record.id.as_str(),
                    record.repository_id.as_str(),
                    record.file_id.as_str(),
                    record.name,
                    record.line as i32,
                    record.is_type_only,
                    record.re_export_source.as_deref(),
                    record.re_export_name.as_deref(),
                ])?;
            }
        }
        Ok(())
    }

    pub fn repository_root(&self, repository_id: &str) -> Result<Option<String>> {
        optional_string(
            &self.conn,
            "SELECT root_path FROM repositories WHERE id = ?",
            repository_id,
        )
    }

    pub fn current_modules(&self, repository_id: &str) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT name FROM modules WHERE repository_id = ? ORDER BY name")?;
        let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    pub fn current_dependencies(&self, repository_id: &str) -> Result<Vec<DependencyRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, repository_id, source_file_id, target_file_id, source_file_path, target_file_path,
                    source_module_id, target_module_id, source_module, target_module, specifier,
                    dependency_kind, is_external, evidence_line
             FROM dependencies
             WHERE repository_id = ?
             ORDER BY source_file_path, evidence_line, specifier",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(DependencyRecord {
                id: row.get(0)?,
                repository_id: row.get(1)?,
                source_file_id: row.get(2)?,
                target_file_id: row.get(3)?,
                source_file_path: row.get(4)?,
                target_file_path: row.get(5)?,
                source_module_id: row.get(6)?,
                target_module_id: row.get(7)?,
                source_module: row.get(8)?,
                target_module: row.get(9)?,
                specifier: row.get(10)?,
                dependency_kind: row.get(11)?,
                is_external: row.get(12)?,
                evidence_line: row.get::<_, i64>(13)? as usize,
            })
        })?;
        collect_rows(rows)
    }

    pub fn current_file_count(&self, repository_id: &str) -> Result<usize> {
        self.count_rows("files", repository_id)
    }

    /// Ingests Git commits and per-file change events. Commits are
    /// immutable by SHA, so this is an idempotent insert keyed by stable ID:
    /// re-indexing ingests only commits not already stored. Returns the number
    /// of newly ingested commits.
    pub fn upsert_git_facts(
        &mut self,
        repository_id: &str,
        commits: &[CommitRecord],
        changes: &[FileChangeRecord],
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let known_commits = existing_ids(&tx, "commits", repository_id)?;
        let known_changes = existing_ids(&tx, "file_changes", repository_id)?;

        let mut ingested = 0;
        {
            let mut insert_commit = tx.prepare(
                "INSERT INTO commits (id, repository_id, sha, parent_shas, author_name, author_email, committed_at, message)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            for commit in commits {
                if known_commits.contains(commit.id.as_str()) {
                    continue;
                }
                insert_commit.execute(params![
                    commit.id.as_str(),
                    commit.repository_id.as_str(),
                    commit.sha,
                    commit.parent_shas.join(","),
                    commit.author_name,
                    commit.author_email,
                    commit.committed_at.to_rfc3339(),
                    commit.message,
                ])?;
                ingested += 1;
            }

            let mut insert_change = tx.prepare(
                "INSERT INTO file_changes (id, repository_id, commit_id, file_path, change_kind, additions, deletions)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            for change in changes {
                if known_changes.contains(change.id.as_str()) {
                    continue;
                }
                insert_change.execute(params![
                    change.id.as_str(),
                    change.repository_id.as_str(),
                    change.commit_id.as_str(),
                    change.file_path,
                    enum_str(&change.kind),
                    change.additions.map(|v| v as i64),
                    change.deletions.map(|v| v as i64),
                ])?;
            }
        }

        tx.commit()?;
        Ok(ingested)
    }

    /// Replaces the repository's current findings. Findings are
    /// recomputed every index run, so a full per-repository replace is correct
    /// and simpler than a diff. Evidence is stored as JSON text.
    pub fn replace_findings(
        &mut self,
        repository_id: &str,
        findings: &[FindingRecord],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM findings WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO findings (id, repository_id, snapshot_id, finding_kind, severity, rule_name, target_id, title, description, evidence_json, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            for finding in findings {
                let evidence_json = serde_json::to_string(&finding.evidence).unwrap_or_default();
                insert.execute(params![
                    finding.id.as_str(),
                    finding.repository_id.as_str(),
                    finding.snapshot_id.as_ref().map(|s| s.as_str()),
                    enum_str(&finding.kind),
                    enum_str(&finding.severity),
                    finding.rule_name,
                    finding.target.as_ref().map(|t| t.id.clone()),
                    finding.title,
                    finding.description,
                    evidence_json,
                    finding.created_at.to_rfc3339(),
                ])?;
            }
        }
        {
            // Retain each finding under its snapshot (append-only) so a change
            // review can diff base→head findings by stable identity and report
            // the *named* new ones, not just a count delta. The current-state
            // `findings` table above still backs the point-in-time commands.
            // Ordinals count repeated content identities within the snapshot
            // (findings arrive in deterministic order), so duplicates stay
            // distinct without falling back to volatile line numbers.
            let mut appender = tx.appender("snapshot_findings")?;
            let mut identity_counts: HashMap<String, usize> = HashMap::new();
            for finding in findings {
                let Some(snapshot_id) = finding.snapshot_id.as_ref() else {
                    continue;
                };
                let base_identity = finding_identity(finding, 0);
                let seen = identity_counts.entry(base_identity.clone()).or_insert(0);
                let identity = if *seen == 0 {
                    base_identity
                } else {
                    finding_identity(finding, *seen)
                };
                *seen += 1;
                let evidence_json = serde_json::to_string(&finding.evidence).unwrap_or_default();
                appender.append_row(params![
                    snapshot_id.as_str(),
                    identity,
                    finding.id.as_str(),
                    enum_str(&finding.kind),
                    enum_str(&finding.severity),
                    finding.rule_name,
                    finding.target.as_ref().map(|t| t.id.clone()),
                    finding.title,
                    finding.description,
                    evidence_json,
                    finding.created_at.to_rfc3339(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Loads the repository's findings, optionally filtered to a minimum
    /// severity, ordered by severity (most severe first) then title.
    pub fn findings(
        &self,
        repository_id: &str,
        min_severity: Option<Severity>,
    ) -> Result<Vec<FindingRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, snapshot_id, finding_kind, severity, rule_name, target_id, title, description, evidence_json, created_at
             FROM findings WHERE repository_id = ?",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(FindingRow {
                id: row.get(0)?,
                snapshot_id: row.get(1)?,
                kind: row.get(2)?,
                severity: row.get(3)?,
                rule_name: row.get(4)?,
                target_id: row.get(5)?,
                title: row.get(6)?,
                description: row.get(7)?,
                evidence_json: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut findings: Vec<FindingRecord> = collect_rows::<FindingRow>(rows)?
            .into_iter()
            .map(|row| row.into_record(repository_id))
            .filter(|finding| match min_severity {
                Some(min) => finding.severity >= min,
                None => true,
            })
            .collect();
        // Most severe first, then stable by title.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.title.cmp(&b.title))
        });
        Ok(findings)
    }

    /// Replaces the repository's package inventory. Recomputed each
    /// index run, so a full per-repository replace is correct.
    pub fn replace_packages(&mut self, repository_id: &str, packages: &[PackageRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM packages WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO packages (id, repository_id, ecosystem, name, version, manifest_path, is_direct)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            let mut seen = HashSet::new();
            for package in packages {
                let id = stable_id(
                    "package",
                    &[
                        repository_id,
                        &package.ecosystem,
                        &package.name,
                        &package.version,
                    ],
                );
                if !seen.insert(id.clone()) {
                    continue;
                }
                insert.execute(params![
                    id,
                    repository_id,
                    package.ecosystem,
                    package.name,
                    package.version,
                    package.manifest_path,
                    package.is_direct,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Per-file ownership metrics: the majority contributor's share, and the
    /// count of major (≥5%) and minor (<5%) contributors. Computed in DuckDB
    /// over the ingested Git history.
    pub fn ownership_metrics(&self, repository_id: &str) -> Result<Vec<FileOwnership>> {
        let mut statement = self.conn.prepare(
            "WITH per_author AS (
                 SELECT fc.file_path AS file_path, c.author_email AS author_email,
                        COUNT(*) AS author_commits
                 FROM file_changes fc
                 JOIN commits c ON fc.commit_id = c.id
                 WHERE fc.repository_id = ?
                 GROUP BY fc.file_path, c.author_email
             ),
             totals AS (
                 SELECT file_path, SUM(author_commits) AS total_commits
                 FROM per_author GROUP BY file_path
             ),
             shares AS (
                 SELECT p.file_path AS file_path,
                        CAST(p.author_commits AS DOUBLE) / t.total_commits AS share
                 FROM per_author p JOIN totals t USING (file_path)
             )
             SELECT s.file_path,
                    MAX(s.share) AS ownership,
                    COUNT(*) FILTER (WHERE s.share < 0.05) AS minor_contributors,
                    COUNT(*) FILTER (WHERE s.share >= 0.05) AS major_contributors,
                    t.total_commits
             FROM shares s JOIN totals t USING (file_path)
             GROUP BY s.file_path, t.total_commits
             ORDER BY ownership ASC, total_commits DESC",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(FileOwnership {
                file_path: row.get(0)?,
                ownership: row.get(1)?,
                minor_contributors: row.get::<_, i64>(2)? as usize,
                major_contributors: row.get::<_, i64>(3)? as usize,
                total_commits: row.get::<_, i64>(4)? as usize,
            })
        })?;
        collect_rows(rows)
    }

    /// Number of persisted rows of a code-fact table for a repository. The
    /// table name is a fixed internal literal (never user input).
    pub fn count_rows(&self, table: &str, repository_id: &str) -> Result<usize> {
        let count = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE repository_id = ?"),
            params![repository_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as usize)
    }

    /// module's files.
    pub fn module_churn(&self, repository_id: &str) -> Result<Vec<(String, f64)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.module_name, COUNT(fc.id)
             FROM files f
             LEFT JOIN file_changes fc
               ON fc.file_path = f.path AND fc.repository_id = f.repository_id
             WHERE f.repository_id = ?
             GROUP BY f.module_name",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as f64))
        })?;
        collect_rows(rows)
    }

    /// (a `reads`/`writes` edge from one of their symbols), for the
    /// database-access convention.
    pub fn db_accessing_files(&self, repository_id: &str) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT f.path
             FROM graph_edges e
             JOIN symbols s ON s.id = e.source_id
             JOIN files f ON f.id = s.file_id
             WHERE e.repository_id = ? AND e.edge_kind IN ('reads', 'writes')",
        )?;
        let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    /// `path → module` for every indexed file, to attribute per-file metrics
    /// (ownership, churn) to modules.
    /// Total cognitive complexity per module, aggregated from the per-function
    /// `complexity` table (oxc). Feeds the hotspot debt score so a module heavy
    /// with complex functions ranks higher even with low churn/coupling.
    pub fn module_complexity(&self, repository_id: &str) -> Result<Vec<(String, f64)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.module_name, SUM(c.cognitive)::BIGINT
             FROM complexity c
             JOIN files f ON c.file_id = f.id AND c.repository_id = f.repository_id
             WHERE c.repository_id = ?
             GROUP BY f.module_name",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as f64))
        })?;
        collect_rows(rows)
    }

    pub fn file_modules(&self, repository_id: &str) -> Result<Vec<(String, String)>> {
        let mut statement = self
            .conn
            .prepare("SELECT path, module_name FROM files WHERE repository_id = ?")?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        collect_rows(rows)
    }

    /// Everything `export graph` needs per file: path, language, size, module.
    pub fn current_files(&self, repository_id: &str) -> Result<Vec<FileGraphRow>> {
        let mut statement = self.conn.prepare(
            "SELECT path, language, size_bytes, module_name
             FROM files WHERE repository_id = ? ORDER BY path",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(FileGraphRow {
                path: row.get::<_, String>(0)?,
                language: row.get::<_, String>(1)?,
                size_bytes: row.get::<_, i64>(2)? as u64,
                module: row.get::<_, String>(3)?,
            })
        })?;
        collect_rows(rows)
    }

    /// Commits touching each file (per-file churn), so callers can aggregate
    /// churn to any component granularity (e.g. directories), not just modules.
    pub fn file_churn(&self, repository_id: &str) -> Result<Vec<(String, f64)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.path, COUNT(fc.id)
             FROM files f
             LEFT JOIN file_changes fc
               ON fc.file_path = f.path AND fc.repository_id = f.repository_id
             WHERE f.repository_id = ?
             GROUP BY f.path",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as f64))
        })?;
        collect_rows(rows)
    }

    /// Total cognitive complexity per file (oxc), for per-component aggregation.
    pub fn file_complexity(&self, repository_id: &str) -> Result<Vec<(String, f64)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.path, SUM(c.cognitive)::BIGINT
             FROM complexity c
             JOIN files f ON c.file_id = f.id AND c.repository_id = f.repository_id
             WHERE c.repository_id = ?
             GROUP BY f.path",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as f64))
        })?;
        collect_rows(rows)
    }

    /// Per-file `(abstract_types, total_types)` for Martin's Abstractness
    /// `A = abstract / total`. Abstract types are interfaces and traits; the
    /// denominator counts the type-defining symbols (class, struct, enum,
    /// interface, trait), not functions or variables. Files with no type
    /// declarations are omitted. Feeds the `metrics` report and the
    /// `zone_of_pain` detector.
    pub fn file_abstractness(&self, repository_id: &str) -> Result<Vec<(String, f64, f64)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.path,
                    SUM(CASE WHEN s.kind IN ('interface','trait') THEN 1 ELSE 0 END)::BIGINT,
                    COUNT(*)::BIGINT
             FROM symbols s
             JOIN files f ON s.file_id = f.id AND s.repository_id = f.repository_id
             WHERE s.repository_id = ?
               AND s.kind IN ('class','struct','enum','interface','trait')
             GROUP BY f.path",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as f64,
                row.get::<_, i64>(2)? as f64,
            ))
        })?;
        collect_rows(rows)
    }

    /// Pairs of files that changed together in the same commit, with how many
    /// times — the evolutionary "change coupling" signal. Bulk commits (more
    /// than 30 files: merges, mass reformats) are excluded as noise, and only
    /// pairs that co-changed at least 3 times are returned. Empty without git
    /// history. Feeds the `change_coupling` and `modularity_violation`
    /// detectors.
    pub fn co_change_pairs(&self, repository_id: &str) -> Result<Vec<(String, String, f64)>> {
        let mut statement = self.conn.prepare(
            "WITH sized AS (
                 SELECT commit_id
                 FROM file_changes
                 WHERE repository_id = ?
                 GROUP BY commit_id
                 HAVING COUNT(*) BETWEEN 2 AND 30
             )
             SELECT a.file_path, b.file_path, COUNT(*)
             FROM file_changes a
             JOIN file_changes b
               ON a.commit_id = b.commit_id
              AND a.repository_id = b.repository_id
              AND a.file_path < b.file_path
             WHERE a.repository_id = ?
               AND a.commit_id IN (SELECT commit_id FROM sized)
             GROUP BY a.file_path, b.file_path
             HAVING COUNT(*) >= 3
             ORDER BY a.file_path, b.file_path",
        )?;
        let rows = statement.query_map(params![repository_id, repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as f64,
            ))
        })?;
        collect_rows(rows)
    }

    /// Number of persisted graph edges of a given kind for a repository.
    pub fn count_edges(&self, repository_id: &str, edge_kind: &str) -> Result<usize> {
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM graph_edges WHERE repository_id = ? AND edge_kind = ?",
            params![repository_id, edge_kind],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as usize)
    }

    /// Loads every graph node as `(id, node_kind, label)` for in-memory
    /// reconstruction of a graph view.
    pub fn graph_nodes(&self, repository_id: &str) -> Result<Vec<(String, String, String)>> {
        let mut statement = self.conn.prepare(
            "SELECT id, node_kind, label FROM graph_nodes WHERE repository_id = ? ORDER BY id",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        collect_rows(rows)
    }

    /// Loads every graph edge as `(source_id, target_id, edge_kind)`.
    pub fn graph_edges(&self, repository_id: &str) -> Result<Vec<(String, String, String)>> {
        let mut statement = self.conn.prepare(
            "SELECT source_id, target_id, edge_kind FROM graph_edges WHERE repository_id = ? ORDER BY source_id, target_id",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        collect_rows(rows)
    }

    pub fn latest_snapshot(&self, repository_id: &str) -> Result<Option<SnapshotRecord>> {
        self.resolve_snapshot(repository_id, "latest")
    }

    pub fn resolve_snapshot(
        &self,
        repository_id: &str,
        reference: &str,
    ) -> Result<Option<SnapshotRecord>> {
        let normalized = reference.strip_prefix("snapshot:").unwrap_or(reference);
        let query = match normalized {
            "latest" | "HEAD" => {
                "SELECT id, commit_sha, created_at FROM snapshots WHERE repository_id = ? ORDER BY created_at DESC LIMIT 1"
            }
            "previous" | "base" => {
                "SELECT id, commit_sha, created_at FROM snapshots WHERE repository_id = ? ORDER BY created_at DESC LIMIT 1 OFFSET 1"
            }
            _ => {
                // Pass the ORIGINAL reference (not the stripped form): snapshot
                // ids are stored with their `snapshot:` prefix, so resolution
                // must stay idempotent for an already-resolved id.
                return self.resolve_named_snapshot(repository_id, reference);
            }
        };

        optional_snapshot(&self.conn, query, repository_id)
    }

    pub fn diff(&self, repository_id: &str, base: &str, head: &str) -> Result<DiffReport> {
        let base = self
            .resolve_snapshot(repository_id, base)?
            .ok_or_else(|| unresolved_snapshot("base", base))?;
        let head = self
            .resolve_snapshot(repository_id, head)?
            .ok_or_else(|| unresolved_snapshot("head", head))?;

        let base_modules = self.snapshot_modules(&base.id)?;
        let head_modules = self.snapshot_modules(&head.id)?;
        let base_dependencies = self.snapshot_dependency_edges(&base.id)?;
        let head_dependencies = self.snapshot_dependency_edges(&head.id)?;

        let added_modules = difference(&head_modules, &base_modules);
        let removed_modules = difference(&base_modules, &head_modules);
        let added_dependencies = dependency_difference(&head_dependencies, &base_dependencies);
        let removed_dependencies = dependency_difference(&base_dependencies, &head_dependencies);
        let risk_score = if added_dependencies.len() >= 10 {
            RiskLevel::High
        } else if !added_dependencies.is_empty() || !removed_dependencies.is_empty() {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        Ok(DiffReport {
            base,
            head,
            added_modules,
            removed_modules,
            added_dependencies,
            removed_dependencies,
            risk_score,
        })
    }

    /// Architecture drift between two snapshots. `base`/`head` accept the
    /// snapshot keywords (`previous`/`latest`), a snapshot ID, or a commit SHA
    /// (a Git ref resolved upstream).
    pub fn drift(&self, repository_id: &str, base: &str, head: &str) -> Result<DriftReport> {
        // The generic message covers both real causes: only one snapshot so
        // far, or a `--since` ref that no indexed snapshot matches.
        let base = self
            .resolve_snapshot(repository_id, base)?
            .ok_or_else(|| unresolved_snapshot("base", base))?;
        let head = self
            .resolve_snapshot(repository_id, head)?
            .ok_or_else(|| unresolved_snapshot("head", head))?;

        let base_modules = self.snapshot_metric_or(&base.id, "modules", 0.0) as isize;
        let head_modules = self.snapshot_metric_or(&head.id, "modules", 0.0) as isize;
        let base_dependencies = self.snapshot_metric_or(&base.id, "dependencies", 0.0) as isize;
        let head_dependencies = self.snapshot_metric_or(&head.id, "dependencies", 0.0) as isize;
        let base_cycles = self.snapshot_metric_or(&base.id, "circular_dependencies", 0.0) as isize;
        let head_cycles = self.snapshot_metric_or(&head.id, "circular_dependencies", 0.0) as isize;
        let base_coupling = self.snapshot_metric_or(&base.id, "coupling_density", 0.0);
        let head_coupling = self.snapshot_metric_or(&head.id, "coupling_density", 0.0);

        let coupling_delta_percent = if base_coupling == 0.0 {
            if head_coupling == 0.0 { 0.0 } else { 100.0 }
        } else {
            ((head_coupling - base_coupling) / base_coupling) * 100.0
        };
        let module_delta = head_modules - base_modules;
        let dependency_delta = head_dependencies - base_dependencies;
        let circular_dependency_delta = head_cycles - base_cycles;
        let trend = drift_trend(
            module_delta,
            dependency_delta,
            circular_dependency_delta,
            coupling_delta_percent,
        );

        // Extended drift metrics: every tracked snapshot metric, base→head.
        const TRACKED: &[&str] = &[
            "modules",
            "dependencies",
            "external_dependencies",
            "circular_dependencies",
            "coupling_density",
            "boundary_violations",
            "security_findings",
            "dependency_advisories",
            "ownership_fragmented_files",
            "max_file_churn",
            "symbols",
            "calls",
            "apis",
            "tables",
            // Code-health and dead-code aggregates (oxc): trend complexity creep
            // and dead-code growth over time.
            "functions",
            "max_cyclomatic",
            "max_cognitive",
            "total_cognitive",
            "high_complexity_functions",
            "unused_exports",
            "unused_files",
        ];
        let metric_deltas = TRACKED
            .iter()
            .map(|metric| MetricDelta {
                metric: (*metric).to_string(),
                base: self.snapshot_metric_or(&base.id, metric, 0.0),
                head: self.snapshot_metric_or(&head.id, metric, 0.0),
            })
            .filter(|delta| delta.base != 0.0 || delta.head != 0.0)
            .collect();

        Ok(DriftReport {
            base,
            head,
            module_delta,
            dependency_delta,
            circular_dependency_delta,
            coupling_delta_percent,
            metric_deltas,
            trend,
        })
    }

    /// The findings a change introduced (`new`) or removed (`resolved`) between
    /// two snapshots, computed from the retained per-snapshot findings by stable
    /// content identity. Unlike [`drift`](Self::drift) (which trends *counts*),
    /// this returns the **named** findings with their `file:line` evidence — the
    /// core of `ovecc review`. A finding is "new" when its identity is present in
    /// `head` but absent from `base`.
    pub fn finding_diff(&self, repository_id: &str, base: &str, head: &str) -> Result<FindingDiff> {
        let base = self
            .resolve_snapshot(repository_id, base)?
            .ok_or_else(|| unresolved_snapshot("base", base))?;
        let head = self
            .resolve_snapshot(repository_id, head)?
            .ok_or_else(|| unresolved_snapshot("head", head))?;
        Ok(FindingDiff {
            new: self.snapshot_findings_minus(repository_id, &head.id, &base.id)?,
            resolved: self.snapshot_findings_minus(repository_id, &base.id, &head.id)?,
        })
    }

    /// Findings retained in `snapshot_id` whose identity is absent from
    /// `other_snapshot_id`, reconstructed as full records, most-severe first then
    /// by title (deterministic).
    fn snapshot_findings_minus(
        &self,
        repository_id: &str,
        snapshot_id: &str,
        other_snapshot_id: &str,
    ) -> Result<Vec<FindingRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, snapshot_id, finding_kind, severity, rule_name, target_id, title, description, evidence_json, created_at
             FROM snapshot_findings
             WHERE snapshot_id = ?
               AND identity NOT IN (SELECT identity FROM snapshot_findings WHERE snapshot_id = ?)",
        )?;
        let rows = statement.query_map(params![snapshot_id, other_snapshot_id], |row| {
            Ok(FindingRow {
                id: row.get(0)?,
                snapshot_id: row.get(1)?,
                kind: row.get(2)?,
                severity: row.get(3)?,
                rule_name: row.get(4)?,
                target_id: row.get(5)?,
                title: row.get(6)?,
                description: row.get(7)?,
                evidence_json: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut findings: Vec<FindingRecord> = collect_rows::<FindingRow>(rows)?
            .into_iter()
            .map(|row| row.into_record(repository_id))
            .collect();
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.title.cmp(&b.title))
        });
        Ok(findings)
    }

    /// Files added/modified/removed between two snapshots, by content hash, so a
    /// review can scope per-file analyses (e.g. duplication) to what changed.
    pub fn changed_files(
        &self,
        repository_id: &str,
        base: &str,
        head: &str,
    ) -> Result<ChangedFiles> {
        let base = self
            .resolve_snapshot(repository_id, base)?
            .ok_or_else(|| unresolved_snapshot("base", base))?;
        let head = self
            .resolve_snapshot(repository_id, head)?
            .ok_or_else(|| unresolved_snapshot("head", head))?;
        let base_files = self.snapshot_file_hashes(&base.id)?;
        let head_files = self.snapshot_file_hashes(&head.id)?;

        let mut changed = ChangedFiles::default();
        for (path, hash) in &head_files {
            match base_files.get(path) {
                None => changed.added.push(path.clone()),
                Some(base_hash) if base_hash != hash => changed.modified.push(path.clone()),
                Some(_) => {}
            }
        }
        for path in base_files.keys() {
            if !head_files.contains_key(path) {
                changed.removed.push(path.clone());
            }
        }
        changed.added.sort();
        changed.modified.sort();
        changed.removed.sort();
        Ok(changed)
    }

    fn snapshot_file_hashes(&self, snapshot_id: &str) -> Result<HashMap<String, String>> {
        let mut statement = self
            .conn
            .prepare("SELECT path, content_hash FROM snapshot_files WHERE snapshot_id = ?")?;
        let rows = statement.query_map(params![snapshot_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        Ok(collect_rows::<(String, String)>(rows)?
            .into_iter()
            .collect())
    }

    /// Module names recorded in a snapshot, as a vector (the cycle enumerators
    /// take `&[String]`). Mirrors the private set form used by `diff`.
    pub fn snapshot_module_names(&self, snapshot_id: &str) -> Result<Vec<String>> {
        Ok(self.snapshot_modules(snapshot_id)?.into_iter().collect())
    }

    /// In-repository module→module edges recorded in a snapshot, for enumerating
    /// that snapshot's cycle set (external edges never form a cycle).
    pub fn snapshot_module_edges(&self, snapshot_id: &str) -> Result<Vec<(String, String)>> {
        Ok(self
            .snapshot_dependency_edges(snapshot_id)?
            .into_iter()
            .filter(|edge| !edge.is_external)
            .map(|edge| (edge.source_module, edge.target_module))
            .collect())
    }

    fn resolve_named_snapshot(
        &self,
        repository_id: &str,
        reference: &str,
    ) -> Result<Option<SnapshotRecord>> {
        // Accept any of: a full snapshot id (`snapshot:abc…`), a bare hash
        // (`abc…`), a short prefix, or a commit SHA. Snapshot ids are stored
        // with their `snapshot:` prefix, so we match the raw reference *and* a
        // `snapshot:`-prefixed form (exact and as a prefix), which makes
        // resolution idempotent for an already-resolved id.
        let normalized = reference.strip_prefix("snapshot:").unwrap_or(reference);
        let prefixed = format!("snapshot:{normalized}");
        let mut statement = self.conn.prepare(
            "SELECT id, commit_sha, created_at
             FROM snapshots
             WHERE repository_id = ?
               AND (id = ? OR id = ? OR starts_with(id, ?)
                    OR commit_sha = ? OR starts_with(COALESCE(commit_sha, ''), ?))
             ORDER BY created_at DESC
             LIMIT 1",
        )?;
        let mut rows = statement.query(params![
            repository_id,
            reference,
            prefixed,
            prefixed,
            reference,
            reference
        ])?;
        if let Some(row) = rows.next()? {
            Ok(Some(SnapshotRecord {
                id: row.get(0)?,
                commit_sha: row.get(1)?,
                created_at: row.get(2)?,
            }))
        } else {
            Ok(None)
        }
    }

    fn snapshot_modules(&self, snapshot_id: &str) -> Result<BTreeSet<String>> {
        let mut statement = self.conn.prepare(
            "SELECT module_name FROM snapshot_modules WHERE snapshot_id = ? ORDER BY module_name",
        )?;
        let rows = statement.query_map(params![snapshot_id], |row| row.get::<_, String>(0))?;
        Ok(collect_rows::<String>(rows)?.into_iter().collect())
    }

    fn snapshot_dependency_edges(&self, snapshot_id: &str) -> Result<Vec<DependencyEdge>> {
        let mut statement = self.conn.prepare(
            "SELECT source_module, target_module, specifier, is_external
             FROM snapshot_dependencies
             WHERE snapshot_id = ?
             ORDER BY source_module, target_module, specifier",
        )?;
        let rows = statement.query_map(params![snapshot_id], |row| {
            Ok(DependencyEdge {
                source_module: row.get(0)?,
                target_module: row.get(1)?,
                specifier: row.get(2)?,
                is_external: row.get(3)?,
            })
        })?;
        collect_rows(rows)
    }

    /// Value of a snapshot metric, or `default` when the snapshot predates it
    /// (drift across versions must not fail on a newly-added metric).
    /// One metric's value across every snapshot, oldest first — the raw series
    /// behind `ovecc history`. `limit` keeps only the most recent N points
    /// (still returned oldest-first for rendering).
    pub fn metric_history(
        &self,
        repository_id: &str,
        metric_name: &str,
        limit: usize,
    ) -> Result<Vec<MetricPoint>> {
        let mut statement = self.conn.prepare(
            "SELECT s.id, s.commit_sha, s.created_at, m.value
             FROM snapshots s
             JOIN snapshot_metrics m ON m.snapshot_id = s.id
             WHERE s.repository_id = ? AND m.metric_name = ?
             ORDER BY s.created_at DESC, s.id DESC
             LIMIT ?",
        )?;
        let rows =
            statement.query_map(params![repository_id, metric_name, limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, f64>(3)?,
                ))
            })?;
        let mut points = collect_rows(rows)?;
        points.reverse(); // oldest first
        Ok(points)
    }

    /// Every metric name recorded for this repository, sorted — so `history`
    /// without an argument can list what is trendable.
    pub fn metric_names(&self, repository_id: &str) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT m.metric_name
             FROM snapshot_metrics m
             JOIN snapshots s ON s.id = m.snapshot_id
             WHERE s.repository_id = ?
             ORDER BY m.metric_name",
        )?;
        let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    fn snapshot_metric_or(&self, snapshot_id: &str, metric_name: &str, default: f64) -> f64 {
        self.conn
            .query_row(
                "SELECT value FROM snapshot_metrics WHERE snapshot_id = ? AND metric_name = ?",
                params![snapshot_id, metric_name],
                |row| row.get::<_, f64>(0),
            )
            .unwrap_or(default)
    }
}

fn optional_string(conn: &Connection, query: &str, repository_id: &str) -> Result<Option<String>> {
    let mut statement = conn.prepare(query)?;
    let mut rows = statement.query(params![repository_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

fn optional_snapshot(
    conn: &Connection,
    query: &str,
    repository_id: &str,
) -> Result<Option<SnapshotRecord>> {
    let mut statement = conn.prepare(query)?;
    let mut rows = statement.query(params![repository_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(SnapshotRecord {
            id: row.get(0)?,
            commit_sha: row.get(1)?,
            created_at: row.get(2)?,
        }))
    } else {
        Ok(None)
    }
}

fn collect_rows<T>(rows: impl Iterator<Item = duckdb::Result<T>>) -> Result<Vec<T>> {
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

/// A snapshot reference that resolved to nothing: the comparison needs both a
/// base and a head snapshot. Typed as an index error so the CLI exits 4
/// (index/db), not 7 (internal).
fn unresolved_snapshot(role: &str, reference: &str) -> anyhow::Error {
    ovecc_core::error::OveccError::Index {
        message: format!(
            "could not resolve {role} snapshot '{reference}'; run 'ovecc index' so both comparison ends exist"
        ),
        source: None,
    }
    .into()
}

fn difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}

fn dependency_difference(left: &[DependencyEdge], right: &[DependencyEdge]) -> Vec<DependencyEdge> {
    let right_set = right.iter().map(dependency_key).collect::<BTreeSet<_>>();
    left.iter()
        .filter(|dependency| !right_set.contains(&dependency_key(dependency)))
        .cloned()
        .collect()
}

fn dependency_key(edge: &DependencyEdge) -> (String, String, String, bool) {
    (
        edge.source_module.clone(),
        edge.target_module.clone(),
        edge.specifier.clone(),
        edge.is_external,
    )
}

fn repository_name(repository_root: &str) -> String {
    Path::new(repository_root)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("repository")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, ArchitectureStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ArchitectureStore::open(&dir.path().join("graph.db")).expect("open store");
        (dir, store)
    }

    fn table_exists(store: &ArchitectureStore, table: &str) -> bool {
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

    #[test]
    fn fresh_database_migrates_to_latest() {
        let (_dir, mut store) = temp_store();
        assert_eq!(store.schema_version().unwrap(), None);

        let version = store.migrate_to_latest().unwrap();

        assert_eq!(version, 5);
        assert_eq!(store.schema_version().unwrap(), Some(5));
        for table in [
            "repositories",
            "files",
            "modules",
            "dependencies",
            "graph_nodes",
            "graph_edges",
            "snapshots",
            "symbols",
            "calls",
            "apis",
            "schema_objects",
            "migrations",
            "ownership",
            "commits",
            "file_changes",
            "metrics",
            "findings",
            "packages",
            "complexity",
            "exports",
            "snapshot_findings",
            "snapshot_files",
        ] {
            assert!(table_exists(&store, table), "missing table {table}");
        }
    }

    #[test]
    fn migrate_is_idempotent() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        store.migrate_to_latest().unwrap();

        assert_eq!(store.schema_version().unwrap(), Some(5));
        let applied: i64 = store
            .conn
            .query_row("SELECT count(*) FROM ovecc_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(applied, 5, "each migration must be recorded exactly once");
    }

    use ovecc_core::legacy::SourceLanguage;

    fn sample_finding(
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

    #[test]
    fn finding_diff_reports_named_new_and_resolved_findings() {
        use ovecc_core::facts::{FindingKind, Severity};
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let module = sample_module(repo, "billing");
        let file = sample_file(repo, "src/billing/a.ts", "h", &module);
        let index = |store: &mut ArchitectureStore, snap: &str| {
            store
                .sync_current_index(
                    repo,
                    "/tmp/repo",
                    std::slice::from_ref(&module),
                    std::slice::from_ref(&file),
                    &[],
                    snap,
                    None,
                    &[],
                    &ResolvedCode::default(),
                )
                .unwrap();
        };

        // Base: one pre-existing complexity finding.
        index(&mut store, "snap-base");
        store
            .replace_findings(
                repo,
                &[sample_finding(
                    "snap-base",
                    FindingKind::HighComplexity,
                    "src/billing/a.ts",
                    10,
                    "oldFn",
                    Severity::Medium,
                )],
            )
            .unwrap();

        // Head: the SAME complexity finding (new snapshot id, identical identity)
        // plus a genuinely new hardcoded secret.
        index(&mut store, "snap-head");
        store
            .replace_findings(
                repo,
                &[
                    sample_finding(
                        "snap-head",
                        FindingKind::HighComplexity,
                        "src/billing/a.ts",
                        10,
                        "oldFn",
                        Severity::Medium,
                    ),
                    sample_finding(
                        "snap-head",
                        FindingKind::HardcodedSecret,
                        "src/billing/a.ts",
                        3,
                        "TOKEN",
                        Severity::Critical,
                    ),
                ],
            )
            .unwrap();

        // Only the secret is new; the unchanged complexity finding is not.
        let diff = store.finding_diff(repo, "snap-base", "snap-head").unwrap();
        assert_eq!(diff.new.len(), 1, "only the genuinely new finding");
        assert_eq!(diff.new[0].kind, FindingKind::HardcodedSecret);
        assert_eq!(diff.new[0].evidence[0].file_path, "src/billing/a.ts");
        assert_eq!(diff.new[0].evidence[0].line, Some(3));
        assert!(diff.resolved.is_empty(), "nothing was removed base->head");

        // Reversed direction: the secret reads as "resolved", nothing new.
        let reversed = store.finding_diff(repo, "snap-head", "snap-base").unwrap();
        assert!(reversed.new.is_empty());
        assert_eq!(reversed.resolved.len(), 1);
        assert_eq!(reversed.resolved[0].kind, FindingKind::HardcodedSecret);
    }

    #[test]
    fn changed_files_classifies_added_modified_removed() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let module = sample_module(repo, "billing");
        let a = sample_file(repo, "src/a.ts", "h1", &module);
        let shared = sample_file(repo, "src/shared.ts", "hX", &module);
        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&module),
                &[a.clone(), shared.clone()],
                &[],
                "snap-base",
                None,
                &[],
                &ResolvedCode::default(),
            )
            .unwrap();

        // Head: a.ts removed, shared.ts modified (hX -> hY), new.ts added.
        let shared_v2 = sample_file(repo, "src/shared.ts", "hY", &module);
        let new = sample_file(repo, "src/new.ts", "h2", &module);
        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&module),
                &[shared_v2, new],
                &[],
                "snap-head",
                None,
                &[],
                &ResolvedCode::default(),
            )
            .unwrap();

        let changed = store.changed_files(repo, "snap-base", "snap-head").unwrap();
        assert_eq!(changed.added, vec!["src/new.ts".to_string()]);
        assert_eq!(changed.modified, vec!["src/shared.ts".to_string()]);
        assert_eq!(changed.removed, vec!["src/a.ts".to_string()]);
        assert_eq!(
            changed.touched().count(),
            2,
            "added + modified are 'touched'"
        );
    }

    #[test]
    fn resolve_snapshot_is_idempotent_for_a_full_id() {
        // A real snapshot id is `snapshot:<hash>` (see `stable_id`). Resolving a
        // keyword like `latest` returns that full id; feeding it straight back
        // must round-trip — otherwise change-scoped commands that resolve, then
        // re-resolve the resulting id (review/diff) break.
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let module = sample_module(repo, "billing");
        let file = sample_file(repo, "src/billing/a.ts", "h", &module);
        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&module),
                std::slice::from_ref(&file),
                &[],
                "snapshot:abcdef123456",
                None,
                &[],
                &ResolvedCode::default(),
            )
            .unwrap();

        let latest = store.resolve_snapshot(repo, "latest").unwrap().unwrap();
        assert_eq!(latest.id, "snapshot:abcdef123456");
        let by_full_id = store.resolve_snapshot(repo, &latest.id).unwrap();
        assert_eq!(by_full_id.map(|s| s.id), Some(latest.id.clone()));
        // A bare hash and a short prefix (with or without the keyword) also work.
        let bare = store.resolve_snapshot(repo, "abcdef123456").unwrap();
        assert_eq!(bare.map(|s| s.id), Some(latest.id.clone()));
        let short = store.resolve_snapshot(repo, "snapshot:abcdef").unwrap();
        assert_eq!(short.map(|s| s.id), Some(latest.id));
    }

    fn sample_module(repo: &str, name: &str) -> ModuleRecord {
        ModuleRecord {
            id: stable_id("module", &[repo, name]),
            repository_id: repo.to_string(),
            name: name.to_string(),
            path_prefix: format!("src/{name}"),
        }
    }

    fn sample_file(repo: &str, path: &str, hash: &str, module: &ModuleRecord) -> FileRecord {
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

    fn sample_dependency(
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

    fn count(store: &ArchitectureStore, sql: &str) -> i64 {
        store.conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn sync_dedups_duplicate_code_facts() {
        use ovecc_core::facts::{CallKind, CallRecord, SymbolKind, SymbolRecord};
        use ovecc_core::id::{CallId, FileId, ModuleId, RepositoryId, SymbolId};
        use ovecc_core::lang::SourceLanguage as CoreLang;

        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let module = sample_module(repo, "billing");
        let file = sample_file(repo, "src/billing/service.ts", "h", &module);

        // An over-eager adapter can emit the same symbol/call id twice within a
        // batch (seen on large repos like django/abseil). The columnar appender
        // would otherwise hit a PRIMARY KEY violation that surfaces only on
        // drop, poisoning the whole transaction. The persistence layer must
        // dedup defensively so this never crashes.
        let make_symbol = || SymbolRecord {
            id: SymbolId::from_raw("symbol:dup"),
            repository_id: RepositoryId::from_raw(repo),
            file_id: FileId::from_raw(file.id.as_str()),
            module_id: Some(ModuleId::from_raw(module.id.as_str())),
            language: CoreLang::TypeScript,
            kind: SymbolKind::Function,
            name: "f".to_string(),
            qualified_name: "f".to_string(),
            span: None,
            visibility: None,
            type_signature: None,
        };
        let make_call = || CallRecord {
            id: CallId::from_raw("call:dup"),
            repository_id: RepositoryId::from_raw(repo),
            caller_symbol_id: SymbolId::from_raw("symbol:dup"),
            callee_symbol_id: None,
            callee_name: Some("g".to_string()),
            kind: CallKind::Direct,
            evidence: None,
        };
        let symbols = vec![make_symbol(), make_symbol()];
        let calls = vec![make_call(), make_call()];
        let code = ResolvedCode {
            symbols: &symbols,
            calls: &calls,
            apis: &[],
            schema_objects: &[],
            schema_edges: &[],
            complexity: &[],
            exports: &[],
        };

        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&module),
                std::slice::from_ref(&file),
                &[],
                "snap-1",
                None,
                &[],
                &code,
            )
            .expect("duplicate code-fact ids must not crash the appender");

        // Each duplicate collapsed to a single persisted row.
        assert_eq!(count(&store, "SELECT count(*) FROM symbols"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM calls"), 1);
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM graph_nodes WHERE node_kind = 'symbol'"
            ),
            1
        );
    }

    #[test]
    fn sync_is_differential_and_idempotent() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let billing = sample_module(repo, "billing");
        let user = sample_module(repo, "user");
        let f1 = sample_file(repo, "src/billing/service.ts", "hash-a", &billing);
        let f2 = sample_file(repo, "src/user/model.ts", "hash-b", &user);
        let dep = sample_dependency(repo, &f1, &f2, "../user/model", 1);
        let modules = [billing.clone(), user.clone()];
        let metrics = vec![("circular_dependencies".to_string(), 0.0)];

        let first = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &[f1.clone(), f2.clone()],
                std::slice::from_ref(&dep),
                "snap-1",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert_eq!(first.files_added, 2);
        assert_eq!(first.modules_added, 2);
        assert_eq!(first.dependencies_added, 1);

        // Same state again: only the snapshot is appended.
        let second = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &[f1.clone(), f2.clone()],
                std::slice::from_ref(&dep),
                "snap-2",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert!(
            second.is_noop(),
            "unchanged input must be a no-op: {second:?}"
        );
        assert_eq!(count(&store, "SELECT count(*) FROM files"), 2);
        assert_eq!(count(&store, "SELECT count(*) FROM snapshots"), 2);
        // 2 contains edges + 1 module depends_on + 1 file→file depends_on edge
        assert_eq!(count(&store, "SELECT count(*) FROM graph_edges"), 4);

        // Changed content hash: file row is rewritten, nothing duplicated.
        let mut f1_changed = f1.clone();
        f1_changed.content_hash = "hash-a2".to_string();
        let third = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &[f1_changed, f2.clone()],
                std::slice::from_ref(&dep),
                "snap-3",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert_eq!(third.files_updated, 1);
        assert_eq!(third.files_added, 0);
        assert_eq!(count(&store, "SELECT count(*) FROM files"), 2);

        // Removing a file, its module, and the dependency cascades precisely.
        let fourth = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&billing),
                std::slice::from_ref(&f1),
                &[],
                "snap-4",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert_eq!(fourth.files_removed, 1);
        assert_eq!(fourth.modules_removed, 1);
        assert_eq!(fourth.dependencies_removed, 1);
        assert_eq!(count(&store, "SELECT count(*) FROM files"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM dependencies"), 0);
        // billing module node + f1 file node
        assert_eq!(count(&store, "SELECT count(*) FROM graph_nodes"), 2);
        // billing contains f1
        assert_eq!(count(&store, "SELECT count(*) FROM graph_edges"), 1);
        // history is preserved
        assert_eq!(count(&store, "SELECT count(*) FROM snapshots"), 4);
    }

    #[test]
    fn pre_framework_database_is_stamped_cleanly() {
        // Simulates a database created by the step-2 code: v1 tables exist
        // but ovecc_schema does not.
        let (_dir, mut store) = temp_store();
        store.conn.execute_batch(MIGRATION_V1_MVP_BASELINE).unwrap();
        assert_eq!(store.schema_version().unwrap(), None);

        let version = store.migrate_to_latest().unwrap();

        assert_eq!(version, 5);
        assert!(table_exists(&store, "findings"));
        assert!(table_exists(&store, "packages"));
        assert!(table_exists(&store, "complexity"));
        assert!(table_exists(&store, "exports"));
        assert!(table_exists(&store, "snapshot_findings"));
        assert!(table_exists(&store, "snapshot_files"));
    }

    #[test]
    fn ingests_git_facts_and_computes_ownership() {
        use ovecc_core::facts::{ChangeKind, CommitRecord, FileChangeRecord};
        use ovecc_core::id::{CommitId, FileChangeId, RepositoryId};

        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";

        // f1: author A x3, author B x1 → ownership 0.75; f2: author A x1.
        let plan = [
            ("c1", "a@x", "f1.ts"),
            ("c2", "a@x", "f1.ts"),
            ("c3", "a@x", "f1.ts"),
            ("c4", "b@x", "f1.ts"),
            ("c5", "a@x", "f2.ts"),
        ];
        let mut commits = Vec::new();
        let mut changes = Vec::new();
        for (i, (sha, email, path)) in plan.iter().enumerate() {
            commits.push(CommitRecord {
                id: CommitId::from_parts(&[repo, sha]),
                repository_id: RepositoryId::from_raw(repo),
                sha: sha.to_string(),
                parent_shas: Vec::new(),
                author_name: Some("A".to_string()),
                author_email: Some(email.to_string()),
                committed_at: chrono::DateTime::from_timestamp(1_700_000_000 + i as i64, 0)
                    .unwrap(),
                message: Some(format!("commit {sha}")),
            });
            changes.push(FileChangeRecord {
                id: FileChangeId::from_parts(&[repo, sha, path]),
                repository_id: RepositoryId::from_raw(repo),
                commit_id: CommitId::from_parts(&[repo, sha]),
                file_path: path.to_string(),
                kind: ChangeKind::Modified,
                additions: None,
                deletions: None,
            });
        }

        let ingested = store.upsert_git_facts(repo, &commits, &changes).unwrap();
        assert_eq!(ingested, 5);
        // Re-ingesting the same history adds nothing (idempotent by SHA).
        let again = store.upsert_git_facts(repo, &commits, &changes).unwrap();
        assert_eq!(again, 0);
        assert_eq!(store.count_rows("commits", repo).unwrap(), 5);

        let ownership = store.ownership_metrics(repo).unwrap();
        let f1 = ownership.iter().find(|o| o.file_path == "f1.ts").unwrap();
        assert!(
            (f1.ownership - 0.75).abs() < 1e-9,
            "f1 ownership: {}",
            f1.ownership
        );
        assert_eq!(f1.major_contributors, 2);
        assert_eq!(f1.minor_contributors, 0);
        assert_eq!(f1.total_commits, 4);

        let f2 = ownership.iter().find(|o| o.file_path == "f2.ts").unwrap();
        assert!((f2.ownership - 1.0).abs() < 1e-9);
        assert_eq!(f2.total_commits, 1);
    }
}
