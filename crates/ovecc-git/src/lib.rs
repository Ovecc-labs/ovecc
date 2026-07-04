//! Native Git history extraction via gitoxide.
//!
//! Replaces the temporary `git rev-parse` shell-out: commits, authors, and
//! per-commit changed files are read directly from the object database with
//! `gix`, with no child process.
//!
//! Scope is deliberately bounded for performance (research brief
//! `docs/research-code-churn-ownership.md`): recent history only, capped by a
//! day window and a maximum commit count — current ownership/churn does not
//! need a decade of history. Line-level additions/deletions are a later
//! refinement; this layer reports commit metadata and changed-file events,
//! which is all the ownership model needs (author commits per file).
//!
//! Extraction is resilient: a repository that cannot be opened (no `.git`)
//! yields an empty history rather than an error, and a commit that fails to
//! decode is skipped rather than aborting the run.

use anyhow::Result;

/// Kind of change a commit applied to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
}

impl GitChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::Renamed => "renamed",
            Self::Copied => "copied",
        }
    }
}

/// One file touched by a commit (path relative to the repository root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFileChange {
    pub path: String,
    pub kind: GitChangeKind,
}

/// A single commit with the files it changed against its first parent.
#[derive(Debug, Clone)]
pub struct GitCommit {
    pub sha: String,
    pub parent_shas: Vec<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    /// Committer time, seconds since the Unix epoch.
    pub committed_at: i64,
    pub message: Option<String>,
    pub changes: Vec<GitFileChange>,
}

/// Bounded recent Git history.
#[derive(Debug, Clone, Default)]
pub struct GitHistory {
    pub head_sha: Option<String>,
    pub commits: Vec<GitCommit>,
}

/// Collects recent commits reachable from `HEAD`.
///
/// - `window_days`: keep commits no older than this many days (`0` = no limit).
/// - `max_commits`: hard cap on commits inspected, bounding cost on large
///   repositories.
///
/// Returns an empty history (not an error) when `root` is not a Git working
/// tree or has no commits yet.
pub fn collect_history(
    root: &std::path::Path,
    window_days: u32,
    max_commits: usize,
) -> Result<GitHistory> {
    let Ok(repo) = gix::discover(root) else {
        return Ok(GitHistory::default());
    };
    let Ok(head) = repo.head_commit() else {
        return Ok(GitHistory::default());
    };
    let head_sha = head.id().to_string();

    let cutoff = if window_days == 0 {
        0
    } else {
        now_seconds().saturating_sub(i64::from(window_days) * 86_400)
    };

    let mut commits = Vec::new();
    let walk = repo.rev_walk(Some(head.id().detach())).all()?;
    for info in walk.take(max_commits) {
        let Ok(info) = info else { continue };
        let Ok(commit) = info.object() else { continue };
        let Some(git_commit) = decode_commit(&repo, &commit) else {
            continue;
        };
        if window_days != 0 && git_commit.committed_at < cutoff {
            continue;
        }
        commits.push(git_commit);
    }

    Ok(GitHistory {
        head_sha: Some(head_sha),
        commits,
    })
}

/// Resolves a Git revision (`main`, `HEAD`, `HEAD~1`, a tag, or a SHA prefix)
/// to its full commit SHA. Returns `None` outside a Git repository or
/// when the revision cannot be resolved.
pub fn resolve_ref(root: &std::path::Path, reference: &str) -> Option<String> {
    let repo = gix::discover(root).ok()?;
    let id = repo.rev_parse_single(reference).ok()?;
    Some(id.detach().to_string())
}

/// The set of repo-relative paths whose content differs between `reference`
/// and `HEAD` (tree-to-tree, so uncommitted working-tree edits are not
/// included). Returns `None` outside a Git repository or when the reference
/// does not resolve to a commit.
pub fn changed_files_since(
    root: &std::path::Path,
    reference: &str,
) -> Option<std::collections::BTreeSet<String>> {
    use gix::diff::tree_with_rewrites::Change;
    let repo = gix::discover(root).ok()?;
    let base_id = repo.rev_parse_single(reference).ok()?;
    let base_tree = repo.find_commit(base_id.detach()).ok()?.tree().ok()?;
    let head_tree = repo.head_commit().ok()?.tree().ok()?;
    let changes = repo
        .diff_tree_to_tree(
            Some(&base_tree),
            Some(&head_tree),
            gix::diff::Options::default(),
        )
        .ok()?;
    Some(
        changes
            .into_iter()
            .map(|change| match change {
                Change::Addition { location, .. }
                | Change::Deletion { location, .. }
                | Change::Modification { location, .. }
                | Change::Rewrite { location, .. } => location.to_string(),
            })
            .collect(),
    )
}

/// Decodes one commit's metadata and the files it changed against its first
/// parent. Returns `None` if the essential metadata cannot be read.
fn decode_commit(repo: &gix::Repository, commit: &gix::Commit<'_>) -> Option<GitCommit> {
    let sha = commit.id().to_string();
    let parent_shas: Vec<String> = commit.parent_ids().map(|id| id.to_string()).collect();
    let committed_at = commit.committer().map(|sig| sig.seconds()).ok()?;
    let (author_name, author_email) = match commit.author() {
        Ok(sig) => (Some(sig.name.to_string()), Some(sig.email.to_string())),
        Err(_) => (None, None),
    };
    let message = commit
        .message_raw()
        .ok()
        .map(|raw| raw.to_string().trim().to_string())
        .filter(|text| !text.is_empty());
    let changes = changed_files(repo, commit, &parent_shas);

    Some(GitCommit {
        sha,
        parent_shas,
        author_name,
        author_email,
        committed_at,
        message,
        changes,
    })
}

/// Diffs the commit's tree against its first parent (or the empty tree for a
/// root commit) and maps each entry to a [`GitFileChange`]. Best-effort: any
/// failure yields no changes for that commit rather than aborting.
fn changed_files(
    repo: &gix::Repository,
    commit: &gix::Commit<'_>,
    parent_shas: &[String],
) -> Vec<GitFileChange> {
    use gix::diff::tree_with_rewrites::Change;

    let Ok(new_tree) = commit.tree() else {
        return Vec::new();
    };
    // Root commit (no parent) → diff against the empty tree (all additions).
    let parent_tree = parent_shas.first().and_then(|sha| {
        let id = gix::ObjectId::from_hex(sha.as_bytes()).ok()?;
        repo.find_commit(id).ok()?.tree().ok()
    });

    let changes = repo.diff_tree_to_tree(
        parent_tree.as_ref(),
        Some(&new_tree),
        gix::diff::Options::default(),
    );
    let Ok(changes) = changes else {
        return Vec::new();
    };

    changes
        .into_iter()
        .map(|change| match change {
            Change::Addition { location, .. } => GitFileChange {
                path: location.to_string(),
                kind: GitChangeKind::Added,
            },
            Change::Deletion { location, .. } => GitFileChange {
                path: location.to_string(),
                kind: GitChangeKind::Deleted,
            },
            Change::Modification { location, .. } => GitFileChange {
                path: location.to_string(),
                kind: GitChangeKind::Modified,
            },
            Change::Rewrite { location, copy, .. } => GitFileChange {
                path: location.to_string(),
                kind: if copy {
                    GitChangeKind::Copied
                } else {
                    GitChangeKind::Renamed
                },
            },
        })
        .collect()
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &std::path::Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn extracts_commits_and_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "dev@example.com"]);
        git(root, &["config", "user.name", "Dev"]);

        std::fs::write(root.join("a.ts"), "export const a = 1;\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "c1"]);

        std::fs::write(root.join("a.ts"), "export const a = 2;\n").unwrap();
        std::fs::write(root.join("b.ts"), "export const b = 1;\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "c2"]);

        let history = collect_history(root, 0, 100).unwrap();
        assert!(history.head_sha.is_some());
        assert_eq!(history.commits.len(), 2, "expected two commits");

        let c2 = history
            .commits
            .iter()
            .find(|c| c.message.as_deref() == Some("c2"))
            .expect("c2 present");
        assert_eq!(c2.author_email.as_deref(), Some("dev@example.com"));
        assert_eq!(c2.parent_shas.len(), 1);
        let paths: Vec<_> = c2.changes.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"a.ts"), "a.ts modified in c2: {paths:?}");
        assert!(paths.contains(&"b.ts"), "b.ts added in c2: {paths:?}");
        assert_eq!(
            c2.changes.iter().find(|c| c.path == "b.ts").unwrap().kind,
            GitChangeKind::Added
        );
        assert_eq!(
            c2.changes.iter().find(|c| c.path == "a.ts").unwrap().kind,
            GitChangeKind::Modified
        );

        let c1 = history
            .commits
            .iter()
            .find(|c| c.message.as_deref() == Some("c1"))
            .expect("c1 present");
        assert!(c1.parent_shas.is_empty(), "c1 is the root commit");
        assert_eq!(
            c1.changes.iter().find(|c| c.path == "a.ts").unwrap().kind,
            GitChangeKind::Added
        );
    }

    #[test]
    fn resolves_refs_to_commit_sha() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "dev@example.com"]);
        git(root, &["config", "user.name", "Dev"]);
        std::fs::write(root.join("a.ts"), "export const a = 1;\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "c1"]);

        let head = collect_history(root, 0, 10).unwrap().head_sha.unwrap();
        assert_eq!(resolve_ref(root, "HEAD").as_deref(), Some(head.as_str()));
        // The default branch name resolves to the same commit.
        let branch = resolve_ref(root, "HEAD").unwrap();
        assert_eq!(branch, head);
        assert!(resolve_ref(root, "does-not-exist").is_none());
    }

    #[test]
    fn non_git_directory_yields_empty_history() {
        let dir = tempfile::tempdir().unwrap();
        let history = collect_history(dir.path(), 0, 100).unwrap();
        assert!(history.head_sha.is_none());
        assert!(history.commits.is_empty());
    }
}
