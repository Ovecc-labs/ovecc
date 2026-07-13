//! Read queries over the current state: modules, dependencies, findings,
//! code facts, ownership, and the metric history.

use crate::{
    ArchitectureStore, FileGraphRow, FileOwnership, FindingRow, MetricPoint, collect_rows,
};
use anyhow::Result;
use duckdb::{Connection, params};
use ovecc_core::facts::{FindingRecord, Severity};
use ovecc_core::legacy::DependencyRecord;

impl ArchitectureStore {
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

    /// Commits touching each module's files (module churn).
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

    /// Files that access the database
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

    /// `path → module` for every indexed file, to attribute per-file metrics
    /// (ownership, churn) to modules.
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

    /// Source anchors `(node_id, file_path, line)` for graph nodes that have a
    /// single definition site: symbols (their file + start line), apis and
    /// schema objects (their evidence file + line). Modules and files are
    /// absent. A read-time join, so anchors need no reindex to appear.
    pub fn node_source_locations(
        &self,
        repository_id: &str,
    ) -> Result<Vec<(String, String, i64)>> {
        let mut statement = self.conn.prepare(
            "SELECT s.id, f.path, s.start_line \
               FROM symbols s JOIN files f ON f.id = s.file_id \
              WHERE s.repository_id = ? AND s.start_line IS NOT NULL \
             UNION ALL \
             SELECT a.id, f.path, a.evidence_line \
               FROM apis a JOIN files f ON f.id = a.evidence_file_id \
              WHERE a.repository_id = ? AND a.evidence_line IS NOT NULL \
             UNION ALL \
             SELECT o.id, f.path, o.evidence_line \
               FROM schema_objects o JOIN files f ON f.id = o.evidence_file_id \
              WHERE o.repository_id = ? AND o.evidence_line IS NOT NULL",
        )?;
        let rows = statement.query_map(
            params![repository_id, repository_id, repository_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
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
