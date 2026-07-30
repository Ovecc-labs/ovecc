//! Versioned schema migrations, applied in order inside their own
//! transactions and recorded in `ovecc_schema`.

use crate::ArchitectureStore;
use anyhow::{Context, Result};
use chrono::Utc;
use duckdb::params;

/// One versioned schema migration. Migrations are append-only:
/// never edit a shipped migration, add a new version instead.
struct SchemaMigration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// Baseline schema, kept `IF NOT EXISTS` so that databases created before
/// the migration framework are stamped cleanly.
const MIGRATION_V1_BASELINE: &str = r#"
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

/// Full architecture schema. `evidence_json` columns stay TEXT so the schema
/// does not depend on the DuckDB JSON extension being loaded.
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

/// Per-function complexity and per-file exports as first-class rows, queryable
/// instead of surfacing only as transient findings.
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

/// Per-snapshot retention of findings and file hashes. The base schema
/// snapshots counts only, which can trend a change but never name the defects
/// behind it or the files it touched.
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

/// Ambient-capability uses (network, storage, clock, ...), one row per file
/// and API, judged by the architecture contract's `deny_capabilities`.
const MIGRATION_V6_CAPABILITIES: &str = r#"
            CREATE TABLE IF NOT EXISTS capability_uses (
                id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                api TEXT NOT NULL,
                line INTEGER NOT NULL,
                occurrence_count INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_capability_uses_repo ON capability_uses (repository_id);
            "#;

/// Whether each commit subject describes a bug fix. `NULL` marks a commit
/// ingested before the classifier existed; the indexer backfills those.
const MIGRATION_V7_FIX_CLASSIFICATION: &str = r#"
            ALTER TABLE commits ADD COLUMN IF NOT EXISTS is_fix BOOLEAN;
            ALTER TABLE commits ADD COLUMN IF NOT EXISTS fix_confidence DOUBLE;
            "#;

const SCHEMA_MIGRATIONS: &[SchemaMigration] = &[
    SchemaMigration {
        version: 1,
        name: "baseline",
        sql: MIGRATION_V1_BASELINE,
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
    SchemaMigration {
        version: 6,
        name: "capabilities",
        sql: MIGRATION_V6_CAPABILITIES,
    },
    SchemaMigration {
        version: 7,
        name: "fix_classification",
        sql: MIGRATION_V7_FIX_CLASSIFICATION,
    },
];

impl ArchitectureStore {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn fresh_database_migrates_to_latest() {
        let (_dir, mut store) = temp_store();
        assert_eq!(store.schema_version().unwrap(), None);

        let version = store.migrate_to_latest().unwrap();

        assert_eq!(version, 7);
        assert_eq!(store.schema_version().unwrap(), Some(7));
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
            "capability_uses",
        ] {
            assert!(table_exists(&store, table), "missing table {table}");
        }
    }

    #[test]
    fn migrate_is_idempotent() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        store.migrate_to_latest().unwrap();

        assert_eq!(store.schema_version().unwrap(), Some(7));
        let applied: i64 = store
            .conn
            .query_row("SELECT count(*) FROM ovecc_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(applied, 7, "each migration must be recorded exactly once");
    }

    #[test]
    fn pre_framework_database_is_stamped_cleanly() {
        // Simulates a database from before the migration framework: v1 tables
        // exist but ovecc_schema does not.
        let (_dir, mut store) = temp_store();
        store.conn.execute_batch(MIGRATION_V1_BASELINE).unwrap();
        assert_eq!(store.schema_version().unwrap(), None);

        let version = store.migrate_to_latest().unwrap();

        assert_eq!(version, 7);
        assert!(table_exists(&store, "findings"));
        assert!(table_exists(&store, "packages"));
        assert!(table_exists(&store, "complexity"));
        assert!(table_exists(&store, "exports"));
        assert!(table_exists(&store, "snapshot_findings"));
        assert!(table_exists(&store, "snapshot_files"));
        assert!(table_exists(&store, "capability_uses"));
    }
}
