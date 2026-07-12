//! Snapshot resolution and snapshot-scoped comparisons: `diff`, `drift`, the
//! named finding diff behind `review`, and changed-file classification.

use crate::{ArchitectureStore, FindingRow, collect_rows};
use anyhow::Result;
use duckdb::{Connection, params};
use ovecc_core::facts::FindingRecord;
use ovecc_core::legacy::{
    DependencyEdge, DiffReport, DriftReport, MetricDelta, RiskLevel, SnapshotRecord, drift_trend,
};
use ovecc_core::report::{ChangedFiles, FindingDiff};
use std::collections::{BTreeSet, HashMap};

impl ArchitectureStore {
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
        let added_dependencies = without_self_edges(dependency_difference(
            &head_dependencies,
            &base_dependencies,
        ));
        let removed_dependencies = without_self_edges(dependency_difference(
            &base_dependencies,
            &head_dependencies,
        ));
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
            "code_smells",
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

// Intra-module imports read as `billing -> billing` at module granularity;
// reporting them as added/removed dependencies would make every file move
// look like an architecture change.
fn without_self_edges(edges: Vec<DependencyEdge>) -> Vec<DependencyEdge> {
    edges
        .into_iter()
        .filter(|edge| edge.is_external || edge.source_module != edge.target_module)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolvedCode;
    use crate::testutil::*;

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
    fn diff_ignores_module_self_edges() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let billing = sample_module(repo, "billing");
        let user = sample_module(repo, "user");
        let modules = [billing.clone(), user.clone()];
        let a = sample_file(repo, "src/billing/a.ts", "h1", &billing);
        let b = sample_file(repo, "src/billing/b.ts", "h2", &billing);
        let u = sample_file(repo, "src/user/u.ts", "h3", &user);
        let files = [a.clone(), b.clone(), u.clone()];

        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &files,
                &[],
                "snap-base",
                None,
                &[],
                &ResolvedCode::default(),
            )
            .unwrap();

        let intra = sample_dependency(repo, &a, &b, "./b", 1);
        let cross = sample_dependency(repo, &a, &u, "../user/u", 2);
        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &files,
                &[intra, cross],
                "snap-head",
                None,
                &[],
                &ResolvedCode::default(),
            )
            .unwrap();

        let diff = store.diff(repo, "snap-base", "snap-head").unwrap();
        assert_eq!(
            diff.added_dependencies.len(),
            1,
            "intra-module edge must not surface: {:?}",
            diff.added_dependencies
        );
        assert_eq!(diff.added_dependencies[0].source_module, "billing");
        assert_eq!(diff.added_dependencies[0].target_module, "user");

        let reversed = store.diff(repo, "snap-head", "snap-base").unwrap();
        assert_eq!(
            reversed.removed_dependencies.len(),
            1,
            "removed side must skip self-edges too: {:?}",
            reversed.removed_dependencies
        );
        assert_eq!(reversed.removed_dependencies[0].target_module, "user");
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
}
