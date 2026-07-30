//! Whether a commit message describes a bug fix.

/// A message scores at least this high to count as a fix.
pub const FIX_CONFIDENCE_THRESHOLD: f32 = 0.5;

/// How strongly a commit message reads as a bug fix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FixClassification {
    /// Arbitrary score in `[0.0, 1.0]`, not a probability.
    pub confidence: f32,
    pub is_fix: bool,
}

const FIX_TYPES: &[&str] = &["fix", "bugfix", "hotfix", "patch"];

/// The author already answered the question, so their type beats any keyword
/// further along the subject.
const NON_FIX_TYPES: &[&str] = &[
    "feat", "feature", "docs", "doc", "chore", "style", "refactor", "test", "tests", "build", "ci",
    "perf", "release", "deps", "wip",
];

const CORRECTION_WORDS: &[&str] = &[
    "fix",
    "fixes",
    "fixed",
    "fixing",
    "resolve",
    "resolves",
    "resolved",
    "correct",
    "corrects",
    "corrected",
    "repair",
    "repairs",
    "repaired",
    "patch",
    "patched",
    "workaround",
];

/// Limited to things that go wrong at runtime. `error`, `broken` and `failing`
/// belong here by their dictionary meaning but would let "typo in the error
/// message" and "broken readme link" through.
const DEFECT_WORDS: &[&str] = &[
    "bug",
    "bugs",
    "defect",
    "defects",
    "crash",
    "crashes",
    "regression",
    "regressions",
    "exception",
    "panic",
    "panics",
    "deadlock",
    "race",
    "leak",
    "leaks",
    "overflow",
    "underflow",
    "corruption",
    "hang",
    "freeze",
    "segfault",
    "fault",
    "misparse",
];

const HOUSEKEEPING_WORDS: &[&str] = &[
    "typo",
    "typos",
    "spelling",
    "grammar",
    "wording",
    "docs",
    "doc",
    "documentation",
    "readme",
    "changelog",
    "comment",
    "comments",
    "lint",
    "clippy",
    "fmt",
    "format",
    "formatting",
    "whitespace",
    "indentation",
    "build",
    "ci",
    "warning",
    "warnings",
    "version",
    "bump",
    "dependency",
    "dependencies",
    "deps",
    "test",
    "tests",
    "flaky",
    "release",
];

/// Scores the subject line of `message` on how strongly it reads as a bug fix.
///
/// Issue references are ignored: a squash merge appends `(#123)` to every
/// subject, fix or not.
pub fn classify_fix_message(message: &str) -> FixClassification {
    let subject = message
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let confidence = score(&subject);
    FixClassification {
        confidence,
        is_fix: confidence >= FIX_CONFIDENCE_THRESHOLD,
    }
}

fn score(subject: &str) -> f32 {
    let words = words(subject);
    if words.is_empty() {
        return 0.0;
    }

    // A revert undoes a fix, and a merge subject carries the keywords of every
    // commit it brings in.
    if words[0] == "revert" || words[0] == "merge" {
        return 0.0;
    }

    let has_defect = words.iter().any(|w| DEFECT_WORDS.contains(w));
    let has_correction = words.iter().any(|w| CORRECTION_WORDS.contains(w));

    let base: f32 = match conventional_type(subject) {
        Some(kind) if FIX_TYPES.contains(&kind) => 0.9,
        Some(kind) if NON_FIX_TYPES.contains(&kind) => return 0.0,
        _ => match (has_correction, has_defect) {
            (true, true) => 0.8,
            (true, false) => 0.6,
            // A defect named with no repair verb is a report or a test that
            // reproduces it, so this stays under the threshold.
            (false, true) => 0.4,
            (false, false) => return 0.0,
        },
    };

    if !has_defect && repairs_housekeeping(&words) {
        return (base - 0.5).max(0.0);
    }
    base
}

const HOUSEKEEPING_WINDOW: usize = 3;

/// Whether the repaired thing is housekeeping rather than a defect. Only the
/// words just after the verb count: a housekeeping word further along names a
/// location or a second clause, not what was repaired.
fn repairs_housekeeping(words: &[&str]) -> bool {
    let anchor = words
        .iter()
        .position(|w| CORRECTION_WORDS.contains(w))
        .unwrap_or(0);
    words
        .iter()
        .skip(anchor + 1)
        .take(HOUSEKEEPING_WINDOW)
        .any(|w| HOUSEKEEPING_WORDS.contains(w))
}

/// `fix(scope)!: subject` yields `fix`; a subject with no `type:` prefix
/// yields `None`.
fn conventional_type(subject: &str) -> Option<&str> {
    let (head, _) = subject.split_once(':')?;
    let head = head.trim();
    let kind = head
        .split_once('(')
        .map_or(head, |(kind, _)| kind)
        .trim_end_matches('!')
        .trim();
    if kind.is_empty() || !kind.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(kind)
}

fn words(subject: &str) -> Vec<&str> {
    subject
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_fix(message: &str) -> bool {
        classify_fix_message(message).is_fix
    }

    #[test]
    fn conventional_fix_prefixes_score_highest() {
        for message in [
            "fix: resolve the memory leak in the walker",
            "fix(indexer): stop dropping renamed paths",
            "fix!: reject malformed contracts",
            "bugfix: guard against an empty component list",
            "hotfix: restore the exit code on gate failure",
        ] {
            assert!(is_fix(message), "expected a fix: {message}");
        }
    }

    #[test]
    fn a_declared_type_outranks_keywords_in_the_subject() {
        for message in [
            "docs: fix the getting started guide",
            "test: cover the crash reported in #12",
            "chore: fix up the release script",
            "refactor: remove the workaround for the old resolver",
        ] {
            assert!(!is_fix(message), "declared non-fix type: {message}");
        }
    }

    #[test]
    fn plain_english_repairs_are_recognized() {
        for message in [
            "fix the resolver ordering on windows",
            "correct the off-by-one in the range mapper",
            "resolve a panic on an empty import list",
            "parser: fix the range mapper",
        ] {
            assert!(is_fix(message), "expected a fix: {message}");
        }
    }

    #[test]
    fn substrings_of_fix_are_not_fixes() {
        for message in [
            "prefix every finding with its rule name",
            "drop the suffix from generated file names",
            "add a fixture for the jvm sample repo",
            "rename postfix to trailing",
        ] {
            assert!(!is_fix(message), "substring only: {message}");
            assert_eq!(classify_fix_message(message).confidence, 0.0);
        }
    }

    #[test]
    fn housekeeping_repairs_are_not_defect_fixes() {
        for message in [
            "fix typo in the readme",
            "fix the docs",
            "fix build on windows",
            "fix clippy warnings",
            "fix: typo in the error message",
            "fix formatting in the summary table",
        ] {
            assert!(!is_fix(message), "housekeeping: {message}");
        }
    }

    #[test]
    fn a_housekeeping_word_late_in_the_subject_does_not_veto() {
        assert!(is_fix(
            "fix: diff no longer reports module self-edges as dependency changes"
        ));
        assert!(is_fix(
            "fix: human-readable history values and correct config doc reference"
        ));
    }

    #[test]
    fn a_named_defect_survives_a_housekeeping_word() {
        assert!(is_fix("fix the crash in the test runner"));
        assert!(is_fix("fix: panic when the build directory is missing"));
    }

    #[test]
    fn reverts_and_merges_are_rejected() {
        for message in [
            "Revert \"fix: resolve the memory leak\"",
            "revert the resolver change",
            "Merge pull request #12 from ovecc-labs/fix-resolver",
            "Merge branch 'main' into fix/parser",
        ] {
            assert!(!is_fix(message), "not a fix commit: {message}");
        }
    }

    #[test]
    fn a_defect_named_without_a_repair_stays_below_the_line() {
        let c = classify_fix_message("crash on an empty import list");
        assert!(!c.is_fix);
        assert!(c.confidence > 0.0, "still worth ranking above nothing");
    }

    #[test]
    fn only_the_subject_line_is_read() {
        let message = "add the coupling command\n\nThis also fixes the crash \
                       reported when a component has no files.";
        assert!(!is_fix(message), "the body must not decide");
    }

    #[test]
    fn empty_and_degenerate_messages_score_zero() {
        for message in ["", "   ", "\n\n", "...", "wip"] {
            assert_eq!(
                classify_fix_message(message).confidence,
                0.0,
                "no signal: {message:?}"
            );
        }
    }

    #[test]
    fn confidence_stays_within_range() {
        for message in [
            "fix: typo",
            "fix: resolve the memory leak",
            "crash",
            "Revert \"fix\"",
            "unrelated change",
        ] {
            let c = classify_fix_message(message).confidence;
            assert!((0.0..=1.0).contains(&c), "{message}: {c}");
        }
    }

    /// Real subjects from this repository's log.
    #[test]
    fn real_subjects_from_this_repository() {
        for message in [
            "fix bugs",
            "fix: strip Windows verbatim prefix from resolved paths",
            "fix: advise opened the database twice (DuckDB allows one handle)",
            "fix: type-only imports no longer witness dependency cycles",
            "fix(windows): work around GCC 16.1.0 libstdc++ multiple-definition bug",
            "resolve bare rust imports as external crates, not local modules",
        ] {
            assert!(is_fix(message), "expected a fix: {message}");
        }

        for message in [
            "chore(deps): bump peak_alloc from 0.2.1 to 0.3.0 (#21)",
            "feat: fix lint issues and enforce clippy in CI",
            "test: staged fixtures never inherit a local .ovecc index",
            "Merge pull request #5 from ovecc-labs/mvp",
            "unresolved targets get suggestions instead of empty results",
            "rust's ? operator no longer counts toward cyclomatic",
            "raise the build-test timeout so a cold cache can rewarm",
            "run rustfmt over the anchor and error-envelope changes",
            "don't block on lint issues",
            "split ovecc-db into store modules",
            "point public references at the ovecc-labs org",
        ] {
            assert!(!is_fix(message), "expected a non-fix: {message}");
        }
    }
}
