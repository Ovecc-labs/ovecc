//! Read queries over the current state of the index.

use crate::{
    ArchitectureStore, FileFixHistory, FileGraphRow, FileOwnership, FindingRow, MetricPoint,
    SymbolDef, collect_rows,
};
use anyhow::Result;
use duckdb::{Connection, params};
use ovecc_core::facts::{
    CapabilityFact, CapabilityKind, CommitFiles, FindingRecord, FunctionMetricsRow, Severity,
};
use ovecc_core::legacy::{DependencyRecord, FixHistory};

/// Resolves every path the history mentions to the name it ends up under, by
/// following rename records forward. Prefix of the queries that roll a file's
/// history up; it binds the repository id twice, before their own parameters.
///
/// Two limits it cannot lift. A file that was *split* keeps only the history of
/// the part that kept its path: git records the other part as a plain addition.
/// And a path that is renamed away and later reused by a new file hands its
/// successor's history to that new file.
const CANONICAL_PATHS: &str = "WITH RECURSIVE renames AS (
             SELECT DISTINCT previous_path, file_path
             FROM file_changes
             WHERE repository_id = ?
               AND previous_path IS NOT NULL
               AND previous_path <> file_path
         ),
         walk(path, current_path, depth) AS (
             SELECT DISTINCT file_path, file_path, 0
             FROM file_changes WHERE repository_id = ?
             UNION ALL
             SELECT w.path, r.file_path, w.depth + 1
             FROM walk w JOIN renames r ON r.previous_path = w.current_path
             WHERE w.depth < 20
         ),
         canonical AS (
             SELECT path, arg_max(current_path, depth) AS current_path
             FROM walk GROUP BY path
         )";

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

    /// The repository's findings, optionally filtered to a minimum severity,
    /// most severe first then stable by title.
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
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.title.cmp(&b.title))
        });
        Ok(findings)
    }

    /// Per-file ownership: the majority contributor's share, and the count of
    /// major (≥5%) and minor (<5%) contributors.
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

    /// Commits with no fix classification yet, as `(id, message)`. Classifying
    /// them is the caller's job: this crate cannot reach the classifier.
    pub fn unclassified_commits(&self, repository_id: &str) -> Result<Vec<(String, String)>> {
        let mut statement = self.conn.prepare(
            "SELECT id, COALESCE(message, '')
             FROM commits
             WHERE repository_id = ? AND is_fix IS NULL",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        collect_rows(rows)
    }

    /// Commits touching each module's files (module churn), renames followed.
    pub fn module_churn(&self, repository_id: &str) -> Result<Vec<(String, f64)>> {
        self.churn_by("f.module_name", repository_id)
    }

    /// Files that access the database: a symbol with a `reads`/`writes` edge.
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

    /// Ambient-capability uses joined to file paths, for the contract's
    /// `deny_capabilities` check without a re-parse.
    pub fn current_capability_uses(
        &self,
        repository_id: &str,
    ) -> Result<Vec<(String, CapabilityFact)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.path, c.capability, c.api, c.line, c.occurrence_count
             FROM capability_uses c
             JOIN files f ON c.file_id = f.id AND c.repository_id = f.repository_id
             WHERE c.repository_id = ?
             ORDER BY f.path, c.line, c.api",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let raw: Vec<(String, String, String, i64, i64)> = collect_rows(rows)?;
        Ok(raw
            .into_iter()
            .filter_map(|(path, capability, api, line, count)| {
                // An unknown capability name means the row was written by a
                // newer build; skip it rather than misjudge it.
                let capability = CapabilityKind::parse(&capability)?;
                Some((
                    path,
                    CapabilityFact {
                        capability,
                        api,
                        line: line as u32,
                        count: count as u32,
                    },
                ))
            })
            .collect())
    }

    /// Per-function complexity joined to file paths, for the contract's budget
    /// check.
    pub fn current_function_metrics(&self, repository_id: &str) -> Result<Vec<FunctionMetricsRow>> {
        let mut statement = self.conn.prepare(
            "SELECT f.path, c.qualified_name, c.line, c.cyclomatic, c.cognitive
             FROM complexity c
             JOIN files f ON c.file_id = f.id AND c.repository_id = f.repository_id
             WHERE c.repository_id = ?
             ORDER BY f.path, c.line, c.qualified_name",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(FunctionMetricsRow {
                file_path: row.get(0)?,
                qualified_name: row.get(1)?,
                line: row.get::<_, i64>(2)? as u32,
                cyclomatic: row.get::<_, i64>(3)? as u32,
                cognitive: row.get::<_, i64>(4)? as u32,
            })
        })?;
        collect_rows(rows)
    }

    /// Total cognitive complexity per module. Feeds the hotspot score, so a
    /// module full of complex functions ranks high even with low churn.
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

    /// `(path, start, end)` for every symbol with a recorded span, so review
    /// can tell whether a change touched a finding's enclosing body.
    pub fn symbol_spans(&self, repository_id: &str) -> Result<Vec<(String, u32, u32)>> {
        let mut statement = self.conn.prepare(
            "SELECT f.path, s.start_line, s.end_line
             FROM symbols s
             JOIN files f ON f.id = s.file_id AND f.repository_id = s.repository_id
             WHERE s.repository_id = ?
               AND s.start_line IS NOT NULL AND s.end_line IS NOT NULL",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u32,
                row.get::<_, i64>(2)? as u32,
            ))
        })?;
        collect_rows(rows)
    }

    /// Every symbol definition with a recorded span, joined to its file path.
    /// Ranking (exact, suffix, substring) happens in Rust: no SQL LIKE
    /// expresses those tiers.
    pub fn symbol_defs(&self, repository_id: &str) -> Result<Vec<SymbolDef>> {
        let mut statement = self.conn.prepare(
            "SELECT s.name, s.qualified_name, s.kind, f.path, s.start_line, s.end_line
             FROM symbols s
             JOIN files f ON f.id = s.file_id AND f.repository_id = s.repository_id
             WHERE s.repository_id = ?
               AND s.start_line IS NOT NULL AND s.end_line IS NOT NULL
             ORDER BY f.path, s.start_line",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(SymbolDef {
                name: row.get::<_, String>(0)?,
                qualified_name: row.get::<_, String>(1)?,
                kind: row.get::<_, String>(2)?,
                path: row.get::<_, String>(3)?,
                start_line: row.get::<_, i64>(4)? as u32,
                end_line: row.get::<_, i64>(5)? as u32,
            })
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

    /// Commits touching each file, so callers can aggregate churn at any
    /// granularity, not just modules. Renames followed.
    pub fn file_churn(&self, repository_id: &str) -> Result<Vec<(String, f64)>> {
        self.churn_by("f.path", repository_id)
    }

    /// Commits per file grouped by one of the `files` columns. Distinct commits
    /// rather than change rows, so the commit that renames a file and the one
    /// that edits it count the same.
    fn churn_by(&self, group: &str, repository_id: &str) -> Result<Vec<(String, f64)>> {
        let mut statement = self.conn.prepare(&format!(
            "{CANONICAL_PATHS}
             SELECT {group}, COUNT(DISTINCT fc.commit_id)
             FROM files f
             LEFT JOIN canonical c ON c.current_path = f.path
             LEFT JOIN file_changes fc
               ON fc.file_path = c.path AND fc.repository_id = f.repository_id
             WHERE f.repository_id = ?
             GROUP BY {group}"
        ))?;
        let rows = statement.query_map(
            params![repository_id, repository_id, repository_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as f64)),
        )?;
        collect_rows(rows)
    }

    /// Per-file fix history, weighted so that an old correction counts for less
    /// than a recent one: each fix contributes `0.5 ^ (age / half_life_days)`.
    /// Age is measured from the newest commit in the index rather than from the
    /// clock, so two runs over the same database agree.
    ///
    /// A file no fix touched is absent, not zero. Renames are followed, so a
    /// moved file keeps the corrections it earned under its old name. Paths come
    /// from the history, like [`Self::ownership_metrics`]: a fix that only
    /// edited documentation lands on a path nothing ranks.
    pub fn file_fix_history(
        &self,
        repository_id: &str,
        half_life_days: f64,
    ) -> Result<Vec<FileFixHistory>> {
        // Anything under a day leaves every older fix weightless, and zero
        // divides by zero. One row per (commit, file) so that a commit reaching
        // a file under two of its names weighs once.
        let half_life_seconds = half_life_days.max(1.0) * 86_400.0;
        // `committed_at` is RFC 3339 in UTC, so its first 19 characters are a
        // plain timestamp and both its lexical and chronological order agree.
        // Casting to TIMESTAMPTZ instead aborts the process: the bundled DuckDB
        // ships without ICU.
        let mut statement = self.conn.prepare(&format!(
            "{CANONICAL_PATHS},
             fixes AS (
                 SELECT DISTINCT c.id AS commit_id,
                        canonical.current_path AS file_path,
                        c.committed_at AS committed_at,
                        epoch(CAST(substr(c.committed_at, 1, 19) AS TIMESTAMP)) AS at
                 FROM file_changes fc
                 JOIN commits c ON fc.commit_id = c.id
                 JOIN canonical ON canonical.path = fc.file_path
                 WHERE fc.repository_id = ? AND c.is_fix
             ),
             newest AS (
                 SELECT MAX(epoch(CAST(substr(committed_at, 1, 19) AS TIMESTAMP))) AS at
                 FROM commits WHERE repository_id = ?
             )
             SELECT f.file_path,
                    COUNT(*)::BIGINT,
                    SUM(POWER(0.5, (n.at - f.at) / CAST(? AS DOUBLE))),
                    MAX(f.committed_at)
             FROM fixes f, newest n
             GROUP BY f.file_path
             ORDER BY 3 DESC, 1"
        ))?;
        let rows = statement.query_map(
            params![
                repository_id,
                repository_id,
                repository_id,
                repository_id,
                half_life_seconds
            ],
            |row| {
                Ok(FileFixHistory {
                    file_path: row.get(0)?,
                    fixes: row.get::<_, i64>(1)? as usize,
                    mass: row.get(2)?,
                    last_fix_at: row.get(3)?,
                })
            },
        )?;
        collect_rows(rows)
    }

    /// The indexed files each commit touched, newest commit first, under their
    /// current names. The raw material of evolutionary coupling.
    ///
    /// Only files the index knows are returned: a lockfile or a CI config rides
    /// along with everything and would pair with everything, and dropping them
    /// also measures the size of a commit by the code it changed.
    pub fn commit_file_sets(&self, repository_id: &str) -> Result<Vec<CommitFiles>> {
        let mut statement = self.conn.prepare(&format!(
            "{CANONICAL_PATHS}
             SELECT c.sha, canonical.current_path
             FROM file_changes fc
             JOIN commits c ON fc.commit_id = c.id
             JOIN canonical ON canonical.path = fc.file_path
             JOIN files f
               ON f.path = canonical.current_path AND f.repository_id = fc.repository_id
             WHERE fc.repository_id = ?
             GROUP BY c.sha, c.committed_at, canonical.current_path
             ORDER BY c.committed_at DESC, c.sha, canonical.current_path"
        ))?;
        let rows = statement.query_map(
            params![repository_id, repository_id, repository_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut commits: Vec<CommitFiles> = Vec::new();
        for (sha, path) in collect_rows::<(String, String)>(rows)? {
            match commits.last_mut() {
                Some(last) if last.sha == sha => last.files.push(path),
                _ => commits.push(CommitFiles {
                    sha,
                    files: vec![path],
                }),
            }
        }
        Ok(commits)
    }

    /// The same weighting as [`Self::file_fix_history`], rolled up to the module
    /// each file belongs to. A module with no correction is absent.
    pub fn module_fix_history(
        &self,
        repository_id: &str,
        half_life_days: f64,
    ) -> Result<Vec<(String, FixHistory)>> {
        let half_life_seconds = half_life_days.max(1.0) * 86_400.0;
        let mut statement = self.conn.prepare(&format!(
            "{CANONICAL_PATHS},
             fixes AS (
                 SELECT DISTINCT c.id AS commit_id, f.module_name AS module_name,
                        c.committed_at AS committed_at,
                        epoch(CAST(substr(c.committed_at, 1, 19) AS TIMESTAMP)) AS at
                 FROM file_changes fc
                 JOIN commits c ON fc.commit_id = c.id
                 JOIN canonical ON canonical.path = fc.file_path
                 JOIN files f
                   ON f.path = canonical.current_path AND f.repository_id = fc.repository_id
                 WHERE fc.repository_id = ? AND c.is_fix
             ),
             newest AS (
                 SELECT MAX(epoch(CAST(substr(committed_at, 1, 19) AS TIMESTAMP))) AS at
                 FROM commits WHERE repository_id = ?
             )
             SELECT f.module_name,
                    COUNT(*)::BIGINT,
                    SUM(POWER(0.5, (n.at - f.at) / CAST(? AS DOUBLE))),
                    MAX(f.committed_at)
             FROM fixes f, newest n
             GROUP BY f.module_name"
        ))?;
        let rows = statement.query_map(
            params![
                repository_id,
                repository_id,
                repository_id,
                repository_id,
                half_life_seconds
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    FixHistory {
                        fixes: row.get::<_, i64>(1)? as usize,
                        mass: row.get(2)?,
                        last_fix_at: row.get(3)?,
                    },
                ))
            },
        )?;
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
    /// `A = abstract / total`. Files declaring no type are omitted.
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
    /// times. Bulk commits are excluded as noise (merges, mass reformats).
    /// Empty without git history.
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

    /// Source anchors for graph nodes with a single definition site: symbols,
    /// apis, and schema objects. Modules and files are absent. A read-time
    /// join, so anchors need no reindex.
    pub fn node_source_locations(&self, repository_id: &str) -> Result<Vec<(String, String, i64)>> {
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

    /// One metric's value across every snapshot, oldest first. `limit` keeps
    /// the most recent N points, still returned oldest-first.
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

    /// Every metric name recorded for this repository, sorted.
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
