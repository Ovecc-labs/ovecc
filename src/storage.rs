use crate::config::stable_id;
use crate::graph;
use crate::model::{
    DependencyEdge, DependencyRecord, DiffReport, DriftReport, ModuleRecord, RiskLevel,
    SnapshotRecord,
};
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use duckdb::{Connection, params};
use std::collections::BTreeSet;
use std::path::Path;

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

    pub fn initialize_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
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
            "#,
        )?;
        Ok(())
    }

    pub fn replace_current_index(
        &mut self,
        repository_id: &str,
        repository_root: &str,
        modules: &[ModuleRecord],
        files: &[crate::model::FileRecord],
        dependencies: &[DependencyRecord],
        snapshot_id: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "DELETE FROM repositories WHERE id = ?",
            params![repository_id],
        )?;
        self.conn.execute(
            "INSERT INTO repositories (id, root_path, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            params![repository_id, repository_root, repository_name(repository_root), now, now],
        )?;

        for table in [
            "files",
            "modules",
            "dependencies",
            "graph_nodes",
            "graph_edges",
        ] {
            self.conn.execute(
                &format!("DELETE FROM {table} WHERE repository_id = ?"),
                params![repository_id],
            )?;
        }

        for module in modules {
            self.conn.execute(
                "INSERT INTO modules (id, repository_id, name, path_prefix, module_kind, detected_layer, detected_domain)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    module.id,
                    module.repository_id,
                    module.name,
                    module.path_prefix,
                    "inferred",
                    Option::<String>::None,
                    Option::<String>::None
                ],
            )?;
            self.conn.execute(
                "INSERT INTO graph_nodes (id, repository_id, node_kind, label, properties_json)
                 VALUES (?, ?, ?, ?, ?)",
                params![module.id, repository_id, "module", module.name, "{}"],
            )?;
        }

        for file in files {
            self.conn.execute(
                "INSERT INTO files (id, repository_id, path, language, content_hash, size_bytes, module_id, module_name, last_indexed_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    file.id,
                    file.repository_id,
                    file.path,
                    file.language.as_str(),
                    file.content_hash,
                    file.size_bytes as i64,
                    file.module_id,
                    file.module_name,
                    now
                ],
            )?;
            self.conn.execute(
                "INSERT INTO graph_nodes (id, repository_id, node_kind, label, properties_json)
                 VALUES (?, ?, ?, ?, ?)",
                params![file.id, repository_id, "file", file.path, "{}"],
            )?;
            self.conn.execute(
                "INSERT INTO graph_edges (id, repository_id, source_id, target_id, edge_kind, weight, evidence_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    stable_id("edge", &[repository_id, &file.module_id, &file.id, "contains"]),
                    repository_id,
                    file.module_id,
                    file.id,
                    "contains",
                    1.0_f64,
                    "{}"
                ],
            )?;
        }

        for dependency in dependencies {
            self.conn.execute(
                "INSERT INTO dependencies (
                    id, repository_id, source_file_id, target_file_id, source_file_path, target_file_path,
                    source_module_id, target_module_id, source_module, target_module, specifier,
                    dependency_kind, is_external, evidence_line, created_at
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
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
                    dependency.evidence_line as i64,
                    now
                ],
            )?;
            self.conn.execute(
                "INSERT INTO graph_edges (id, repository_id, source_id, target_id, edge_kind, weight, evidence_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    stable_id(
                        "edge",
                        &[repository_id, &dependency.source_module_id, &dependency.target_module_id, &dependency.id]
                    ),
                    repository_id,
                    dependency.source_module_id,
                    dependency.target_module_id,
                    "depends_on",
                    1.0_f64,
                    format!(
                        r#"{{"file":"{}","line":{},"specifier":"{}"}}"#,
                        dependency.source_file_path, dependency.evidence_line, dependency.specifier
                    )
                ],
            )?;
        }

        let module_names = modules
            .iter()
            .map(|module| module.name.clone())
            .collect::<Vec<_>>();
        let circular_dependencies = graph::cycle_count(&module_names, dependencies);
        let local_edges = graph::local_dependency_edges(dependencies);
        let possible_edges = module_names
            .len()
            .saturating_mul(module_names.len().saturating_sub(1));
        let coupling_density = if possible_edges == 0 {
            0.0
        } else {
            local_edges.len() as f64 / possible_edges as f64
        };
        let summary_hash = stable_id(
            "summary",
            &[
                repository_id,
                &module_names.len().to_string(),
                &dependencies.len().to_string(),
                &circular_dependencies.to_string(),
            ],
        );

        self.conn.execute(
            "INSERT INTO snapshots (id, repository_id, commit_sha, created_at, summary_hash) VALUES (?, ?, ?, ?, ?)",
            params![snapshot_id, repository_id, current_git_sha().ok(), now, summary_hash],
        )?;

        for module_name in &module_names {
            self.conn.execute(
                "INSERT INTO snapshot_modules (snapshot_id, module_name) VALUES (?, ?)",
                params![snapshot_id, module_name],
            )?;
        }

        for dependency in dependencies {
            self.conn.execute(
                "INSERT INTO snapshot_dependencies (snapshot_id, source_module, target_module, specifier, is_external)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    snapshot_id,
                    dependency.source_module,
                    dependency.target_module,
                    dependency.specifier,
                    dependency.is_external
                ],
            )?;
        }

        for (name, value) in [
            ("modules", module_names.len() as f64),
            ("files", files.len() as f64),
            ("dependencies", dependencies.len() as f64),
            (
                "external_dependencies",
                dependencies
                    .iter()
                    .filter(|dependency| dependency.is_external)
                    .count() as f64,
            ),
            ("circular_dependencies", circular_dependencies as f64),
            ("coupling_density", coupling_density),
        ] {
            self.conn.execute(
                "INSERT INTO snapshot_metrics (snapshot_id, metric_name, value) VALUES (?, ?, ?)",
                params![snapshot_id, name, value],
            )?;
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
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM files WHERE repository_id = ?",
            params![repository_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count as usize)
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
                return self.resolve_named_snapshot(repository_id, normalized);
            }
        };

        optional_snapshot(&self.conn, query, repository_id)
    }

    pub fn diff(&self, repository_id: &str, base: &str, head: &str) -> Result<DiffReport> {
        let base = self
            .resolve_snapshot(repository_id, base)?
            .ok_or_else(|| anyhow!("could not resolve base snapshot '{base}'"))?;
        let head = self
            .resolve_snapshot(repository_id, head)?
            .ok_or_else(|| anyhow!("could not resolve head snapshot '{head}'"))?;

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

    pub fn drift(&self, repository_id: &str) -> Result<DriftReport> {
        let base = self
            .resolve_snapshot(repository_id, "previous")?
            .ok_or_else(|| {
                anyhow!("drift requires at least two snapshots; run 'ovecc index' after a change")
            })?;
        let head = self
            .resolve_snapshot(repository_id, "latest")?
            .ok_or_else(|| anyhow!("no latest snapshot found; run 'ovecc index' first"))?;

        let base_modules = self.snapshot_metric(&base.id, "modules")? as isize;
        let head_modules = self.snapshot_metric(&head.id, "modules")? as isize;
        let base_dependencies = self.snapshot_metric(&base.id, "dependencies")? as isize;
        let head_dependencies = self.snapshot_metric(&head.id, "dependencies")? as isize;
        let base_cycles = self.snapshot_metric(&base.id, "circular_dependencies")? as isize;
        let head_cycles = self.snapshot_metric(&head.id, "circular_dependencies")? as isize;
        let base_coupling = self.snapshot_metric(&base.id, "coupling_density")?;
        let head_coupling = self.snapshot_metric(&head.id, "coupling_density")?;

        let coupling_delta_percent = if base_coupling == 0.0 {
            if head_coupling == 0.0 { 0.0 } else { 100.0 }
        } else {
            ((head_coupling - base_coupling) / base_coupling) * 100.0
        };
        let module_delta = head_modules - base_modules;
        let dependency_delta = head_dependencies - base_dependencies;
        let circular_dependency_delta = head_cycles - base_cycles;
        let trend = graph::drift_trend(
            module_delta,
            dependency_delta,
            circular_dependency_delta,
            coupling_delta_percent,
        );

        Ok(DriftReport {
            base,
            head,
            module_delta,
            dependency_delta,
            circular_dependency_delta,
            coupling_delta_percent,
            trend,
        })
    }

    fn resolve_named_snapshot(
        &self,
        repository_id: &str,
        reference: &str,
    ) -> Result<Option<SnapshotRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, commit_sha, created_at
             FROM snapshots
             WHERE repository_id = ?
               AND (id = ? OR commit_sha = ? OR starts_with(id, ?) OR starts_with(COALESCE(commit_sha, ''), ?))
             ORDER BY created_at DESC
             LIMIT 1",
        )?;
        let mut rows = statement.query(params![
            repository_id,
            reference,
            reference,
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

    fn snapshot_metric(&self, snapshot_id: &str, metric_name: &str) -> Result<f64> {
        self.conn
            .query_row(
                "SELECT value FROM snapshot_metrics WHERE snapshot_id = ? AND metric_name = ?",
                params![snapshot_id, metric_name],
                |row| row.get::<_, f64>(0),
            )
            .with_context(|| format!("missing metric '{metric_name}' for snapshot {snapshot_id}"))
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

fn current_git_sha() -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!("git rev-parse failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
