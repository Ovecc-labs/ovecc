//! Secret scanning over the files Git tracks but the source walk never reads.
//!
//! The walk respects `.gitignore`; a `.env` committed before that rule was
//! added stays tracked and invisible to it. Whatever Git tracks and the index
//! did not parse is scanned here with the provider patterns and entropy rules
//! of [`ovecc_parser::security`].

use ovecc_core::facts::{Evidence, FindingKind, FindingRecord, Severity};
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_parser::security::{is_secret_name, looks_like_high_entropy_secret, provider_secret};
use std::collections::HashSet;
use std::path::Path;

/// Larger than this is a lockfile, a binary, or a data fixture.
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// Per-file cap, so a key-per-line fixture cannot bury every other finding.
const MAX_HITS_PER_FILE: usize = 5;

/// Documentation carries realistic sample credentials by design: flask's docs
/// alone hold four `SECRET_KEY` values that clear the entropy floor.
const DOCUMENTATION_DIRS: &[&str] = &[
    "docs",
    "doc",
    "documentation",
    "examples",
    "example",
    "samples",
];

/// Prose formats. `.txt` is absent: `env.txt` is the case this scan exists for.
const DOCUMENTATION_EXTENSIONS: &[&str] = &["md", "mdx", "rst", "adoc", "asciidoc", "textile"];

fn is_documentation(relative: &str) -> bool {
    let mut segments: Vec<&str> = relative.split('/').collect();
    let Some(file) = segments.pop() else {
        return false;
    };
    if segments
        .iter()
        .any(|segment| DOCUMENTATION_DIRS.contains(&segment.to_ascii_lowercase().as_str()))
    {
        return true;
    }
    file.rsplit_once('.').is_some_and(|(_, extension)| {
        DOCUMENTATION_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

pub(crate) struct TrackedScan {
    pub(crate) findings: Vec<FindingRecord>,
    /// Git-tracked files the source walk never saw.
    pub(crate) files_scanned: usize,
}

/// Scans every Git-tracked path outside `indexed` for hardcoded credentials.
pub(crate) fn scan(
    root: &Path,
    repository_id: &str,
    snapshot_id: &str,
    indexed: &[String],
) -> TrackedScan {
    let already_read: HashSet<&str> = indexed.iter().map(String::as_str).collect();
    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    for relative in ovecc_git::tracked_files(root) {
        if already_read.contains(relative.as_str()) || is_documentation(&relative) {
            continue;
        }
        let absolute = root.join(&relative);
        let Ok(metadata) = std::fs::metadata(&absolute) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        // Not UTF-8: binary, nothing to read a credential out of.
        let Ok(contents) = std::fs::read_to_string(&absolute) else {
            continue;
        };
        files_scanned += 1;
        for (label, line) in scan_text(&contents).into_iter().take(MAX_HITS_PER_FILE) {
            findings.push(finding(repository_id, snapshot_id, &relative, line, &label));
        }
    }
    findings.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    TrackedScan {
        findings,
        files_scanned,
    }
}

/// The `(label, line)` of every credential in a plain-text file. A provider
/// pattern matches anywhere on the line; the entropy rule needs an assignment.
fn scan_text(contents: &str) -> Vec<(String, u32)> {
    let mut hits = Vec::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = index as u32 + 1;
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#') || text.starts_with("//") {
            continue;
        }
        if let Some(provider) = provider_secret(text) {
            hits.push((provider.to_string(), line));
            continue;
        }
        if let Some((name, value)) = assignment(text)
            && is_secret_name(name)
            && looks_like_high_entropy_secret(value)
        {
            hits.push((format!("high-entropy value assigned to {name}"), line));
        }
    }
    hits
}

/// Splits `NAME=value` or `name: value` at its first separator, dropping a
/// copied shell prompt, an `export`, and the quotes. `None` when the line binds
/// nothing.
fn assignment(text: &str) -> Option<(&str, &str)> {
    let bare = text.trim_start_matches(['$', '>']).trim_start();
    let text = bare.strip_prefix("export ").unwrap_or(bare);
    let separator = [text.find('='), text.find(':')]
        .into_iter()
        .flatten()
        .min()?;
    let name = text[..separator].trim().trim_matches(['"', '\'']);
    let value = text[separator + 1..]
        .trim()
        .trim_end_matches(',')
        .trim_matches(['"', '\'']);
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((name, value))
}

fn finding(
    repository_id: &str,
    snapshot_id: &str,
    path: &str,
    line: u32,
    label: &str,
) -> FindingRecord {
    FindingRecord {
        id: FindingId::from_parts(&[
            repository_id,
            "tracked-file-secret",
            path,
            &line.to_string(),
        ]),
        repository_id: RepositoryId::from_raw(repository_id),
        snapshot_id: Some(SnapshotId::from_raw(snapshot_id)),
        kind: FindingKind::HardcodedSecret,
        severity: Severity::Critical,
        rule_name: Some("tracked-file-secret".to_string()),
        target: None,
        title: format!("Hardcoded secret in a tracked non-source file: {label}"),
        description: format!(
            "{path}:{line} holds {label} and is tracked by Git, so it is in every clone \
             and in the history. Rotate the credential first, then remove the file with \
             `git rm --cached {path}` and keep it out of future commits."
        ),
        evidence: vec![Evidence {
            file_path: path.to_string(),
            line: Some(line),
            symbol: None,
            detail: Some(label.to_string()),
        }],
        created_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_provider_patterns_and_entropy_assignments_in_env_text() {
        let hits = scan_text(
            "# comment\n\
             PORT=3000\n\
             API_TOKEN=1234567890abcdef1234567890abcdef\n\
             GITHUB=ghp_1234567890abcdef1234567890abcdef1234\n\
             DATABASE_URL=postgres://user:pass@localhost/db\n\
             API_KEY=${MY_KEY}\n",
        );
        let lines: Vec<u32> = hits.iter().map(|(_, line)| *line).collect();
        assert_eq!(lines, vec![3, 4], "{hits:?}");
        assert!(hits[1].0.contains("GitHub"), "{hits:?}");
    }

    #[test]
    fn ignores_placeholders_and_env_references() {
        let hits = scan_text(
            "SESSION_SECRET=your-secret-here\n\
             API_TOKEN=$API_TOKEN\n\
             PASSWORD=changeme\n\
             CLIENT_SECRET=\n",
        );
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn parses_the_assignment_shapes_a_config_file_uses() {
        assert_eq!(assignment("KEY=value"), Some(("KEY", "value")));
        assert_eq!(assignment("export KEY=value"), Some(("KEY", "value")));
        assert_eq!(assignment("$ export KEY=value"), Some(("KEY", "value")));
        assert_eq!(assignment("  key: \"value\","), Some(("key", "value")));
        assert_eq!(assignment("no separator here"), None);
        assert_eq!(assignment("KEY="), None);
    }

    #[test]
    fn documentation_shows_credentials_rather_than_holding_them() {
        assert!(is_documentation("docs/config.rst"));
        assert!(is_documentation("docs/tutorial/deploy.rst"));
        assert!(is_documentation("README.md"));
        assert!(is_documentation("examples/app/settings.py"));
        // The shape this scan exists for: a `.env` committed under any name.
        assert!(!is_documentation("env.txt"));
        assert!(!is_documentation(".env.production"));
        assert!(!is_documentation("config/credentials.json"));
        assert!(!is_documentation("scripts/deploy.sh"));
    }

    #[test]
    fn scans_nothing_outside_a_git_working_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("env.txt"),
            "API_TOKEN=1234567890abcdef1234567890abcdef\n",
        )
        .unwrap();
        let scan = scan(root, "repo", "snap", &[]);
        assert!(scan.findings.is_empty());
        assert_eq!(scan.files_scanned, 0);
    }
}
