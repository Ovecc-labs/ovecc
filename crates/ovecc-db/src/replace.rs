//! Per-run replacement writes: findings, Git facts, packages, coverage.

use crate::{ArchitectureStore, PackageRow, enum_str, existing_ids};
use anyhow::Result;
use duckdb::params;
use ovecc_core::coverage::FileCoverage;
use ovecc_core::facts::{CoChangedPair, CommitRecord, FileChangeRecord, FindingRecord};
use ovecc_core::util::stable_id;
use std::collections::{HashMap, HashSet};

/// The ordinal-0 identity, shared by every instance of a repeated pattern in
/// one file: the diff cannot tell them apart, so review charges the group.
pub fn finding_group_key(finding: &FindingRecord) -> String {
    finding_identity(finding, 0)
}

/// Content identity of a finding, stable across snapshots where the per-run
/// `FindingId` is not, so a set difference yields the genuinely new ones. The
/// line comes last: identifying by line blames a finding that an edit above it
/// merely moved. Severity is part of the key, so a function pushed from medium
/// to high complexity reads as one new finding and one resolved.
fn finding_identity(finding: &FindingRecord, ordinal: usize) -> String {
    let kind = enum_str(&finding.kind);
    let severity = enum_str(&finding.severity);
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
        &[
            &kind,
            &severity,
            &path,
            &locator,
            &rule,
            &ordinal.to_string(),
        ],
    )
}

impl ArchitectureStore {
    /// Ingests commits and per-file change events, returning how many commits
    /// were new. Commits are immutable by SHA, so the insert is idempotent.
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
                "INSERT INTO commits (id, repository_id, sha, parent_shas, author_name, author_email, committed_at, message, is_fix, fix_confidence)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    commit.is_fix,
                    commit.fix_confidence as f64,
                ])?;
                ingested += 1;
            }

            let mut insert_change = tx.prepare(
                "INSERT INTO file_changes (id, repository_id, commit_id, file_path, change_kind, previous_path, additions, deletions)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
                    change.previous_path,
                    change.additions.map(|v| v as i64),
                    change.deletions.map(|v| v as i64),
                ])?;
            }
        }

        tx.commit()?;
        Ok(ingested)
    }

    /// Swaps in the coverage from one tracefile. Wholesale: a file that
    /// disappeared from the tracefile has no coverage any more, and keeping the
    /// old row would report a deleted test suite as still passing over it.
    pub fn replace_coverage(
        &mut self,
        repository_id: &str,
        coverage: &[FileCoverage],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM coverage WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO coverage (id, repository_id, file_path, lines_found, lines_hit, functions_found, functions_hit)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            for file in coverage {
                insert.execute(params![
                    stable_id("coverage", &[repository_id, &file.path]),
                    repository_id,
                    file.path,
                    file.lines_found as i64,
                    file.lines_hit as i64,
                    file.functions_found as i64,
                    file.functions_hit as i64,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces the repository's co-change pairs. They are recomputed from the
    /// whole commit walk on every index, so a full replace is what keeps them
    /// honest: a pair that stopped meeting has to disappear.
    pub fn replace_co_changes(
        &mut self,
        repository_id: &str,
        pairs: &[CoChangedPair],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM co_changes WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO co_changes (id, repository_id, left_path, right_path, support, jaccard, lift, confidence_left, confidence_right, commit_shas)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            for pair in pairs {
                insert.execute(params![
                    stable_id("co-change", &[repository_id, &pair.left, &pair.right]),
                    repository_id,
                    pair.left,
                    pair.right,
                    pair.support as i64,
                    pair.jaccard,
                    pair.lift,
                    pair.confidence_left_to_right,
                    pair.confidence_right_to_left,
                    pair.commits.join(","),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Backfills the fix classification of commits already stored.
    pub fn set_fix_classification(&mut self, rows: &[(String, bool, f64)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut update =
                tx.prepare("UPDATE commits SET is_fix = ?, fix_confidence = ? WHERE id = ?")?;
            for (id, is_fix, confidence) in rows {
                update.execute(params![is_fix, confidence, id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces the repository's findings. They are recomputed every index run,
    /// so a full replace is correct and simpler than a diff.
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
            // Retained per snapshot (append-only) so review can name the new
            // findings instead of counting them. Ordinals keep repeated
            // identities distinct without falling back to line numbers.
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

    /// Replaces the repository's package inventory: recomputed every index run.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn coverage(path: &str, found: usize, hit: usize) -> FileCoverage {
        FileCoverage {
            path: path.to_string(),
            lines_found: found,
            lines_hit: hit,
            functions_found: 1,
            functions_hit: usize::from(hit > 0),
        }
    }

    #[test]
    fn a_second_tracefile_replaces_the_first_rather_than_adding_to_it() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";

        store
            .replace_coverage(repo, &[coverage("a.ts", 10, 7), coverage("gone.ts", 4, 4)])
            .unwrap();
        // The suite covering gone.ts was deleted: keeping its row would report
        // a test that no longer exists as still passing over the file.
        store
            .replace_coverage(repo, &[coverage("a.ts", 10, 9)])
            .unwrap();

        let stored = store.file_coverage(repo).unwrap();
        assert_eq!(stored, vec![coverage("a.ts", 10, 9)]);
    }

    #[test]
    fn moved_finding_keeps_identity_when_anchored_to_a_symbol() {
        // Anchored on the enclosing symbol, not the line: an edit above a finding
        // that merely shifts its line must not make `review` report it as new.
        let before = sample_finding(
            "snap",
            ovecc_core::facts::FindingKind::TaintedFlow,
            "src/a.ts",
            10,
            "handler",
            ovecc_core::facts::Severity::High,
        );
        let after = sample_finding(
            "snap",
            ovecc_core::facts::FindingKind::TaintedFlow,
            "src/a.ts",
            42,
            "handler",
            ovecc_core::facts::Severity::High,
        );
        assert_eq!(finding_identity(&before, 0), finding_identity(&after, 0));
    }

    #[test]
    fn ordinal_disambiguates_otherwise_identical_findings() {
        // Two identical findings (e.g. two evals on one line): the ordinal keeps
        // the second one distinct without relying on a volatile line number.
        let f = sample_finding(
            "snap",
            ovecc_core::facts::FindingKind::InsecurePattern,
            "src/a.ts",
            7,
            "run",
            ovecc_core::facts::Severity::Medium,
        );
        assert_ne!(finding_identity(&f, 0), finding_identity(&f, 1));
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
                is_fix: false,
                fix_confidence: 0.0,
            });
            changes.push(FileChangeRecord {
                id: FileChangeId::from_parts(&[repo, sha, path]),
                repository_id: RepositoryId::from_raw(repo),
                commit_id: CommitId::from_parts(&[repo, sha]),
                file_path: path.to_string(),
                kind: ChangeKind::Modified,
                previous_path: None,
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

    /// One commit per entry of `(sha, days before the reference date, fix,
    /// path, renamed from)`, each touching its single file.
    fn ingest_history(
        store: &mut ArchitectureStore,
        repo: &str,
        plan: &[(&str, i64, bool, &str, Option<&str>)],
    ) {
        use ovecc_core::facts::{ChangeKind, CommitRecord, FileChangeRecord};
        use ovecc_core::id::{CommitId, FileChangeId, RepositoryId};

        let mut commits = Vec::new();
        let mut changes = Vec::new();
        for (sha, age_days, is_fix, path, renamed_from) in plan {
            let at = 1_700_000_000 - age_days * 86_400;
            commits.push(CommitRecord {
                id: CommitId::from_parts(&[repo, sha]),
                repository_id: RepositoryId::from_raw(repo),
                sha: sha.to_string(),
                parent_shas: Vec::new(),
                author_name: None,
                author_email: None,
                committed_at: chrono::DateTime::from_timestamp(at, 0).unwrap(),
                message: Some(format!("subject {sha}")),
                is_fix: *is_fix,
                fix_confidence: if *is_fix { 0.9 } else { 0.0 },
            });
            changes.push(FileChangeRecord {
                id: FileChangeId::from_parts(&[repo, sha, path]),
                repository_id: RepositoryId::from_raw(repo),
                commit_id: CommitId::from_parts(&[repo, sha]),
                file_path: path.to_string(),
                kind: match renamed_from {
                    Some(_) => ChangeKind::Renamed,
                    None => ChangeKind::Modified,
                },
                previous_path: renamed_from.map(str::to_string),
                additions: None,
                deletions: None,
            });
        }
        store.upsert_git_facts(repo, &commits, &changes).unwrap();
    }

    #[test]
    fn fix_mass_fades_with_the_age_of_each_fix() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";

        ingest_history(
            &mut store,
            repo,
            &[
                ("head", 0, false, "f1.ts", None),
                ("today", 0, true, "f1.ts", None),
                ("half", 180, true, "f1.ts", None),
                ("stale", 360, true, "f2.ts", None),
                ("chore", 10, false, "f3.ts", None),
            ],
        );

        let history = store.file_fix_history(repo, 180.0).unwrap();
        assert_eq!(
            history
                .iter()
                .map(|h| h.file_path.as_str())
                .collect::<Vec<_>>(),
            ["f1.ts", "f2.ts"],
            "a file no fix touched is absent, and the heaviest comes first"
        );

        let f1 = &history[0];
        assert_eq!(f1.fixes, 2, "the non-fix commit on f1 is not a correction");
        // One fix at the reference date and one a half-life old: 1 + 0.5.
        assert!((f1.mass - 1.5).abs() < 1e-9, "f1 mass: {}", f1.mass);
        assert!(
            f1.last_fix_at.starts_with("2023-11-14"),
            "{}",
            f1.last_fix_at
        );

        let f2 = &history[1];
        assert!(
            (f2.mass - 0.25).abs() < 1e-6,
            "two half-lives old weighs a quarter: {}",
            f2.mass
        );
    }

    #[test]
    fn a_renamed_file_keeps_the_history_of_its_old_names() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";

        // a.ts is fixed twice, moved to b.ts, then to c.ts, then fixed again.
        ingest_history(
            &mut store,
            repo,
            &[
                ("one", 0, true, "a.ts", None),
                ("two", 0, true, "a.ts", None),
                ("move", 0, false, "b.ts", Some("a.ts")),
                ("move-again", 0, false, "c.ts", Some("b.ts")),
                ("three", 0, true, "c.ts", None),
                ("other", 0, true, "z.ts", None),
            ],
        );

        let history = store.file_fix_history(repo, 180.0).unwrap();
        let c = history
            .iter()
            .find(|row| row.file_path == "c.ts")
            .expect("the file is reported under its current name");
        assert_eq!(c.fixes, 3, "two fixes under a.ts and one under c.ts");
        assert!(
            !history.iter().any(|row| row.file_path == "a.ts"),
            "the old name is gone: {history:?}"
        );

        store
            .conn
            .execute(
                "INSERT INTO files (id, repository_id, path, language, content_hash, size_bytes, module_id, module_name, last_indexed_at)
                 VALUES ('file:c', ?, 'c.ts', 'typescript', 'h', 1, 'module:src', 'src', '2023-11-14T00:00:00+00:00')",
                params![repo],
            )
            .unwrap();
        let churn: HashMap<String, f64> = store.file_churn(repo).unwrap().into_iter().collect();
        assert_eq!(
            churn.get("c.ts").copied(),
            Some(5.0),
            "every commit that touched the file under any of its names"
        );
    }

    #[test]
    fn fix_classification_round_trips_and_backfills() {
        use ovecc_core::facts::CommitRecord;
        use ovecc_core::id::{CommitId, RepositoryId};

        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";

        let commit = |sha: &str, is_fix: bool, confidence: f32| CommitRecord {
            id: CommitId::from_parts(&[repo, sha]),
            repository_id: RepositoryId::from_raw(repo),
            sha: sha.to_string(),
            parent_shas: Vec::new(),
            author_name: None,
            author_email: None,
            committed_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            message: Some(format!("subject {sha}")),
            is_fix,
            fix_confidence: confidence,
        };
        let commits = [commit("c1", true, 0.9), commit("c2", false, 0.0)];
        store.upsert_git_facts(repo, &commits, &[]).unwrap();

        let (is_fix, confidence): (bool, f64) = store
            .conn
            .query_row(
                "SELECT is_fix, fix_confidence FROM commits WHERE sha = 'c1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(is_fix);
        assert!((confidence - 0.9).abs() < 1e-6, "confidence: {confidence}");
        assert!(store.unclassified_commits(repo).unwrap().is_empty());

        // A row from a database indexed before the columns existed.
        store
            .conn
            .execute(
                "UPDATE commits SET is_fix = NULL, fix_confidence = NULL WHERE sha = 'c1'",
                [],
            )
            .unwrap();
        let pending = store.unclassified_commits(repo).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1, "subject c1");

        store
            .set_fix_classification(&[(pending[0].0.clone(), true, 0.9)])
            .unwrap();
        assert!(store.unclassified_commits(repo).unwrap().is_empty());
    }
}
