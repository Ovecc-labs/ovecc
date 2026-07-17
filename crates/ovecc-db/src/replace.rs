//! Per-run replacement writes: the findings (with their per-snapshot
//! retention), the Git facts, and the package inventory.

use crate::{ArchitectureStore, PackageRow, enum_str, existing_ids};
use anyhow::Result;
use duckdb::params;
use ovecc_core::facts::{CommitRecord, FileChangeRecord, FindingRecord};
use ovecc_core::util::stable_id;
use std::collections::{HashMap, HashSet};

/// The ordinal-0 identity: the key every instance of the same pattern in the
/// same file shares. Ordinals are assigned in the findings' persisted order,
/// which follows their hashed ids — not their lines — so the diff cannot say
/// *which* instance of a repeated pattern is the new one. Review therefore
/// charges the group as a unit, via this key.
pub fn finding_group_key(finding: &FindingRecord) -> String {
    finding_identity(finding, 0)
}

/// Stable, snapshot-independent content identity of a finding, so the *same*
/// defect in two snapshots collapses to one key and a set-difference yields the
/// genuinely new ones. Keyed by kind + severity + first-evidence location
/// (path, then the enclosing symbol when known, else the pattern detail, else
/// the line) + rule — stable across unrelated edits elsewhere in the repo,
/// where the volatile per-run `FindingId` is not. Line numbers are the locator
/// of last resort: identifying by line blames a finding that merely *moved*
/// (an edit above it) on the change under review. Severity is part of the
/// identity so a defect that crosses a band — a function pushed from medium to
/// high complexity — reads as a new fact (and the old band as resolved), not
/// as nothing. `ordinal` disambiguates several otherwise identical findings
/// (e.g. two `eval` calls in one file), so only the extra occurrence reads as
/// new.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

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
