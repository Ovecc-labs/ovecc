//! Git history read from the object database with `gix`.

mod fix;

use anyhow::Result;

pub use fix::{FIX_CONFIDENCE_THRESHOLD, FixClassification, classify_fix_message};

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

/// Collects recent commits reachable from `HEAD`, at most `max_commits` of
/// them and none older than `window_days` (`0` = no age limit).
///
/// Returns an empty history, not an error, when `root` is not a Git working
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

/// Head-side line ranges (1-based, inclusive) that differ from `reference`,
/// keyed by repo-relative path. An added file maps to a single range spanning
/// the whole file. Renames are tracked at git's default 50% similarity, so a
/// pure `git mv` touches no line at the destination and a moved-and-edited
/// file carries only its edited lines. Tree-to-tree like
/// [`changed_files_since`], and `None` under the same conditions.
pub fn changed_line_ranges(
    root: &std::path::Path,
    reference: &str,
) -> Option<std::collections::BTreeMap<String, Vec<(u32, u32)>>> {
    let repo = gix::discover(root).ok()?;
    let base_id = repo.rev_parse_single(reference).ok()?;
    let base_tree = repo.find_commit(base_id.detach()).ok()?.tree().ok()?;
    let head_tree = repo.head_commit().ok()?.tree().ok()?;
    let mut options = gix::diff::Options::default();
    options.track_rewrites(Some(gix::diff::Rewrites::default()));
    let changes = repo
        .diff_tree_to_tree(Some(&base_tree), Some(&head_tree), options)
        .ok()?;

    let mut ranges: std::collections::BTreeMap<String, Vec<(u32, u32)>> =
        std::collections::BTreeMap::new();
    for change in changes {
        if let Some((path, hunks)) = change_head_ranges(&repo, change) {
            ranges.insert(path, hunks);
        }
    }
    Some(ranges)
}

fn blob(repo: &gix::Repository, id: gix::ObjectId) -> Option<Vec<u8>> {
    Some(repo.find_object(id).ok()?.data.clone())
}

/// Lines in a blob. A trailing newline closes the last line, it does not open
/// an empty one.
fn line_count(data: &[u8]) -> u32 {
    let newlines = data.iter().filter(|byte| **byte == b'\n').count() as u32;
    if data.last() == Some(&b'\n') {
        newlines.max(1)
    } else {
        newlines + 1
    }
}

/// Head-side 1-based line spans that differ between two blobs. `after` is a
/// 0-based half-open range of head lines; a pure deletion has an empty `after`
/// and touches no head line.
fn hunk_ranges(before: &[u8], after: &[u8]) -> Vec<(u32, u32)> {
    use gix::diff::blob::{Algorithm, Diff, InternedInput, sources::byte_lines};
    let input = InternedInput::new(byte_lines(before), byte_lines(after));
    Diff::compute(Algorithm::Histogram, &input)
        .hunks()
        .filter(|hunk| hunk.after.end > hunk.after.start)
        .map(|hunk| (hunk.after.start + 1, hunk.after.end))
        .collect()
}

/// The head path and its changed line spans for one tree change, or `None` when
/// the change touches no head line (a deletion, a pure rename) or is not a blob.
fn change_head_ranges(
    repo: &gix::Repository,
    change: gix::diff::tree_with_rewrites::Change,
) -> Option<(String, Vec<(u32, u32)>)> {
    use gix::diff::tree_with_rewrites::Change;
    let whole_file = |id| blob(repo, id).map(|data| vec![(1, line_count(&data).max(1))]);
    let edited = |before_id, after_id| -> Option<Vec<(u32, u32)>> {
        let hunks = hunk_ranges(&blob(repo, before_id)?, &blob(repo, after_id)?);
        (!hunks.is_empty()).then_some(hunks)
    };
    match change {
        Change::Addition {
            location,
            id,
            entry_mode,
            ..
        } if entry_mode.is_blob() => Some((location.to_string(), whole_file(id)?)),
        Change::Modification {
            location,
            previous_id,
            id,
            entry_mode,
            ..
        } if entry_mode.is_blob() => Some((location.to_string(), edited(previous_id, id)?)),
        // A copy's destination is all new content; a rewrite that changed the
        // blob carries its edited lines; a pure rename touches no head line.
        Change::Rewrite {
            source_id,
            id,
            location,
            entry_mode,
            copy,
            ..
        } if entry_mode.is_blob() => {
            let hunks = if copy {
                whole_file(id)?
            } else if source_id != id {
                edited(source_id, id)?
            } else {
                return None;
            };
            Some((location.to_string(), hunks))
        }
        _ => None,
    }
}

/// Head-side line ranges of a change that is not committed yet: the files on
/// disk against `reference`. `paths` bounds the walk to what the caller already
/// knows changed. A path absent from the base tree is new and maps to its whole
/// span; one absent from disk was deleted and touches no head line.
pub fn worktree_line_ranges(
    root: &std::path::Path,
    reference: &str,
    paths: &[String],
) -> Option<std::collections::BTreeMap<String, Vec<(u32, u32)>>> {
    let repo = gix::discover(root).ok()?;
    let workdir = repo.workdir()?.to_path_buf();
    let base_id = repo.rev_parse_single(reference).ok()?;
    let base_tree = repo.find_commit(base_id.detach()).ok()?.tree().ok()?;

    let mut ranges: std::collections::BTreeMap<String, Vec<(u32, u32)>> =
        std::collections::BTreeMap::new();
    for path in paths {
        let Ok(after) = std::fs::read(workdir.join(path)) else {
            continue;
        };
        let before = base_tree
            .lookup_entry_by_path(path)
            .ok()
            .flatten()
            .and_then(|entry| entry.object().ok())
            .map(|object| object.data.clone());
        let after = with_lf_endings(&after);
        let hunks = match before {
            Some(before) => hunk_ranges(&with_lf_endings(&before), &after),
            None => vec![(1, line_count(&after).max(1))],
        };
        if !hunks.is_empty() {
            ranges.insert(path.clone(), hunks);
        }
    }
    Some(ranges)
}

/// Drops the CR of every CRLF. Blobs hold LF; a checkout under `core.autocrlf`
/// or a `text` attribute writes CRLF, and diffing the raw bytes would report
/// every line of every file as changed. Line count is unaffected.
fn with_lf_endings(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (at, &byte) in data.iter().enumerate() {
        if byte != b'\r' || data.get(at + 1) != Some(&b'\n') {
            out.push(byte);
        }
    }
    out
}

/// `None` when the commit's essential metadata cannot be read, so a single
/// undecodable object does not abort the walk.
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

/// Best-effort: any diff failure yields no changes for that commit rather
/// than aborting.
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
        // A tree diff also reports every directory on the way to a changed file,
        // and a submodule as a commit entry. Only the blobs are files: without
        // this, `crates` and `crates/ovecc-cli/src` accumulate their subtree's
        // history as if they were source files.
        .filter(|change| change.entry_mode().is_blob_or_symlink())
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

    /// An empty repository with an identity set, so committing works whatever
    /// the machine's git config says.
    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["config", "user.email", "dev@example.com"]);
        git(dir.path(), &["config", "user.name", "Dev"]);
        dir
    }

    /// Writes each `(path, contents)` pair, creating parent directories, and
    /// commits them under `message`.
    fn commit(root: &std::path::Path, message: &str, files: &[(&str, &str)]) {
        for (path, contents) in files {
            let file = root.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, contents).unwrap();
        }
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", message]);
    }

    #[test]
    fn extracts_commits_and_changed_files() {
        let dir = repo();
        let root = dir.path();

        commit(root, "c1", &[("a.ts", "export const a = 1;\n")]);
        commit(
            root,
            "c2",
            &[
                ("a.ts", "export const a = 2;\n"),
                ("b.ts", "export const b = 1;\n"),
            ],
        );

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
    fn changed_files_are_leaves_not_the_directories_above_them() {
        let dir = repo();
        let root = dir.path();

        commit(root, "c1", &[("src/cli/main.ts", "const a = 1;\n")]);

        let history = collect_history(root, 0, 100).unwrap();
        let paths: Vec<_> = history.commits[0]
            .changes
            .iter()
            .map(|c| c.path.as_str())
            .collect();
        assert_eq!(
            paths,
            ["src/cli/main.ts"],
            "the tree diff walks src and src/cli on the way: {paths:?}"
        );
    }

    #[test]
    fn resolves_refs_to_commit_sha() {
        let dir = repo();
        let root = dir.path();
        commit(root, "c1", &[("a.ts", "export const a = 1;\n")]);

        let head = collect_history(root, 0, 10).unwrap().head_sha.unwrap();
        assert_eq!(resolve_ref(root, "HEAD").as_deref(), Some(head.as_str()));
        assert!(resolve_ref(root, "does-not-exist").is_none());
    }

    #[test]
    fn non_git_directory_yields_empty_history() {
        let dir = tempfile::tempdir().unwrap();
        let history = collect_history(dir.path(), 0, 100).unwrap();
        assert!(history.head_sha.is_none());
        assert!(history.commits.is_empty());
    }

    #[test]
    fn changed_line_ranges_report_only_the_edited_lines() {
        let dir = repo();
        let root = dir.path();
        commit(
            root,
            "base",
            &[
                ("a.ts", "one\ntwo\nthree\nfour\nfive\n"),
                ("keep.ts", "kept\n"),
            ],
        );
        let base = resolve_ref(root, "HEAD").unwrap();

        commit(
            root,
            "head",
            &[
                ("a.ts", "one\ntwo\nTHREE\nfour\nfive\n"),
                ("added.ts", "x\ny\n"),
            ],
        );

        let ranges = changed_line_ranges(root, &base).unwrap();
        assert_eq!(
            ranges.get("a.ts"),
            Some(&vec![(3, 3)]),
            "only line 3 changed"
        );
        assert_eq!(
            ranges.get("added.ts"),
            Some(&vec![(1, 2)]),
            "whole added file"
        );
        assert!(!ranges.contains_key("keep.ts"), "untouched file absent");
    }

    #[test]
    fn worktree_line_ranges_read_the_uncommitted_edit() {
        let dir = repo();
        let root = dir.path();
        commit(
            root,
            "base",
            &[
                ("src/a.ts", "one\ntwo\nthree\nfour\n"),
                ("src/b.ts", "alpha\nbeta\ngamma\n"),
            ],
        );
        let base = resolve_ref(root, "HEAD").unwrap();

        // CRLF on disk against an LF blob is what a checkout under
        // `core.autocrlf` leaves behind; only line 3 actually changed.
        std::fs::write(root.join("src/a.ts"), "one\r\ntwo\r\nTHREE\r\nfour\r\n").unwrap();
        std::fs::write(root.join("src/b.ts"), "alpha\ngamma\n").unwrap();
        std::fs::write(root.join("src/new.ts"), "x\ny\n").unwrap();

        let touched: Vec<String> = ["src/a.ts", "src/b.ts", "src/new.ts", "src/gone.ts"]
            .iter()
            .map(|path| path.to_string())
            .collect();
        let ranges = worktree_line_ranges(root, &base, &touched).unwrap();
        assert_eq!(
            ranges.get("src/a.ts"),
            Some(&vec![(3, 3)]),
            "only the rewritten line"
        );
        assert_eq!(
            ranges.get("src/new.ts"),
            Some(&vec![(1, 2)]),
            "a file absent from the base tree is all new"
        );
        assert!(
            !ranges.contains_key("src/b.ts"),
            "a deletion touches no head line"
        );
        assert!(
            !ranges.contains_key("src/gone.ts"),
            "a path that is not on disk touches no head line"
        );
    }

    #[test]
    fn changed_line_ranges_see_through_renames() {
        let dir = repo();
        let root = dir.path();
        commit(root, "base", &[("a.ts", "one\ntwo\nthree\nfour\nfive\n")]);
        let base = resolve_ref(root, "HEAD").unwrap();

        git(root, &["mv", "a.ts", "b.ts"]);
        git(root, &["commit", "-q", "-m", "move"]);
        let ranges = changed_line_ranges(root, &base).unwrap();
        assert!(
            ranges.is_empty(),
            "a pure rename touches no line: {ranges:?}"
        );

        std::fs::write(root.join("b.ts"), "one\ntwo\nTHREE\nfour\nfive\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["mv", "b.ts", "c.ts"]);
        git(root, &["commit", "-q", "-m", "move and edit"]);
        let ranges = changed_line_ranges(root, &base).unwrap();
        assert_eq!(
            ranges.get("c.ts"),
            Some(&vec![(3, 3)]),
            "only the edited line, under the new path: {ranges:?}"
        );
        assert!(!ranges.contains_key("a.ts") && !ranges.contains_key("b.ts"));
    }
}
