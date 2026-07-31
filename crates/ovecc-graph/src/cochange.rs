//! Evolutionary coupling: the file pairs that keep changing in the same commit,
//! whether or not anything in the code connects them.

pub use ovecc_core::facts::CommitFiles;
use std::collections::HashMap;

/// Two files that change together, with every measure behind the verdict so a
/// reader can disagree with the thresholds rather than with a bare pair.
#[derive(Debug, Clone, PartialEq)]
pub struct CoChangedPair {
    pub left: String,
    pub right: String,
    /// Commits that touched both.
    pub support: usize,
    /// `support / (commits touching either)`, the symmetric strength.
    pub jaccard: f64,
    /// How much more often the two meet than chance would give them. At or
    /// below 1 they are simply both busy.
    pub lift: f64,
    /// The chance the right one changes when the left does, and the reverse.
    /// Asymmetric on purpose: a test always following its subject is not the
    /// same relation as a subject always dragging its test along.
    pub confidence_left_to_right: f64,
    pub confidence_right_to_left: f64,
    /// A few commits where both changed, newest first, as evidence.
    pub commits: Vec<String>,
}

/// Commits touching more files than this say nothing about any particular pair:
/// a license-header sweep, a formatter run, a merge. Both of the studies this
/// draws on cut at the same place.
pub const MAX_COMMIT_FILES: usize = 30;

/// Commits that must have touched both files. An absolute count, not a ratio:
/// it reads the same in a repository of any size.
pub const MIN_SUPPORT: usize = 3;

/// Symmetric strength a pair must reach.
pub const MIN_JACCARD: f64 = 0.35;

/// Evidence commits kept per pair.
const MAX_EVIDENCE: usize = 5;

/// The pairs that change together, strongest first.
///
/// A commit counts only when it touched between two and [`MAX_COMMIT_FILES`]
/// files: one file says nothing about coupling and would only pad the
/// denominators. The measures are the classic four, all over that same window —
/// support, Jaccard, lift, and both directed confidences.
///
/// `commits` arrives newest first and stays that way in the evidence.
pub fn co_changed_pairs(
    commits: &[CommitFiles],
    min_support: usize,
    min_jaccard: f64,
) -> Vec<CoChangedPair> {
    let mut id_of: HashMap<&str, u32> = HashMap::new();
    let mut paths: Vec<&str> = Vec::new();
    let mut touched: Vec<usize> = Vec::new();
    let mut pairs: HashMap<(u32, u32), Vec<&str>> = HashMap::new();
    let mut window = 0_usize;

    for commit in commits {
        let mut files: Vec<&str> = commit.files.iter().map(String::as_str).collect();
        files.sort_unstable();
        files.dedup();
        if files.len() < 2 || files.len() > MAX_COMMIT_FILES {
            continue;
        }
        window += 1;
        let ids: Vec<u32> = files
            .iter()
            .map(|path| {
                *id_of.entry(path).or_insert_with(|| {
                    paths.push(path);
                    touched.push(0);
                    (paths.len() - 1) as u32
                })
            })
            .collect();
        for (rank, &left) in ids.iter().enumerate() {
            touched[left as usize] += 1;
            for &right in &ids[rank + 1..] {
                pairs.entry((left, right)).or_default().push(&commit.sha);
            }
        }
    }

    let mut coupled: Vec<CoChangedPair> = pairs
        .into_iter()
        .filter_map(|((left, right), witnesses)| {
            let support = witnesses.len();
            if support < min_support {
                return None;
            }
            let (both, left_total, right_total) = (
                support as f64,
                touched[left as usize] as f64,
                touched[right as usize] as f64,
            );
            let jaccard = both / (left_total + right_total - both);
            if jaccard < min_jaccard {
                return None;
            }
            let lift = both * window as f64 / (left_total * right_total);
            if lift <= 1.0 {
                return None;
            }
            Some(CoChangedPair {
                left: paths[left as usize].to_string(),
                right: paths[right as usize].to_string(),
                support,
                jaccard,
                lift,
                confidence_left_to_right: both / left_total,
                confidence_right_to_left: both / right_total,
                commits: witnesses
                    .into_iter()
                    .take(MAX_EVIDENCE)
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect();
    coupled.sort_by(|a, b| {
        b.support
            .cmp(&a.support)
            .then_with(|| {
                b.jaccard
                    .partial_cmp(&a.jaccard)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.left.cmp(&b.left))
            .then_with(|| a.right.cmp(&b.right))
    });
    coupled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(sha: &str, files: &[&str]) -> CommitFiles {
        CommitFiles {
            sha: sha.to_string(),
            files: files.iter().map(|path| path.to_string()).collect(),
        }
    }

    #[test]
    fn reports_files_that_always_travel_together() {
        let history = [
            commit("c4", &["a.ts", "b.ts"]),
            commit("c3", &["a.ts", "b.ts"]),
            commit("c2", &["a.ts", "b.ts"]),
            commit("c1", &["c.ts", "d.ts"]),
        ];
        let pairs = co_changed_pairs(&history, MIN_SUPPORT, MIN_JACCARD);
        assert_eq!(pairs.len(), 1, "{pairs:?}");
        let pair = &pairs[0];
        assert_eq!((pair.left.as_str(), pair.right.as_str()), ("a.ts", "b.ts"));
        assert_eq!(pair.support, 3);
        assert!((pair.jaccard - 1.0).abs() < 1e-9);
        assert!((pair.confidence_left_to_right - 1.0).abs() < 1e-9);
        assert!(pair.lift > 1.0, "lift: {}", pair.lift);
        assert_eq!(pair.commits, ["c4", "c3", "c2"], "newest first");
    }

    #[test]
    fn a_file_touched_by_everything_is_not_coupled_to_everything() {
        // changelog.md rides along in every commit, so meeting any given file is
        // exactly what chance predicts and lift stays at 1.
        let history: Vec<CommitFiles> = (0..6)
            .map(|i| {
                let other = if i % 2 == 0 { "a.ts" } else { "b.ts" };
                CommitFiles {
                    sha: format!("c{i}"),
                    files: vec!["changelog.md".to_string(), other.to_string()],
                }
            })
            .collect();
        let pairs = co_changed_pairs(&history, MIN_SUPPORT, MIN_JACCARD);
        assert!(pairs.is_empty(), "{pairs:?}");
    }

    #[test]
    fn sweeping_commits_and_single_file_commits_are_left_out() {
        let sweep: Vec<String> = (0..MAX_COMMIT_FILES + 1)
            .map(|i| format!("f{i}.ts"))
            .collect();
        let history = [
            CommitFiles {
                sha: "sweep".to_string(),
                files: sweep,
            },
            commit("solo", &["f0.ts"]),
            commit("c3", &["f0.ts", "f1.ts"]),
            commit("c2", &["f0.ts", "f1.ts"]),
            commit("c1", &["f0.ts", "f1.ts"]),
            // Unrelated work, so the pair is not the whole window.
            commit("b2", &["x.ts", "y.ts"]),
            commit("b1", &["x.ts", "y.ts"]),
        ];
        let pairs = co_changed_pairs(&history, MIN_SUPPORT, MIN_JACCARD);
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].support, 3,
            "the sweep does not add a fourth witness"
        );
        // The lone commit on f0 would have pushed its total to 4 and dragged
        // Jaccard down to 0.75.
        assert!((pairs[0].jaccard - 1.0).abs() < 1e-9, "{:?}", pairs[0]);
    }

    #[test]
    fn output_is_stable_whatever_the_map_iteration_order() {
        let mut history: Vec<CommitFiles> = (0..4)
            .map(|i| commit(&format!("c{i}"), &["a.ts", "b.ts", "c.ts"]))
            .collect();
        history.push(commit("b2", &["x.ts", "y.ts"]));
        history.push(commit("b1", &["x.ts", "y.ts"]));
        let first = co_changed_pairs(&history, MIN_SUPPORT, MIN_JACCARD);
        assert_eq!(first.len(), 3);
        for _ in 0..5 {
            assert_eq!(co_changed_pairs(&history, MIN_SUPPORT, MIN_JACCARD), first);
        }
    }
}
