//! Secret scanning over the files Git tracks but the source walk never reads.
//!
//! The walk respects `.gitignore`; a `.env` committed before that rule was
//! added stays tracked and invisible to it. Those files are read here with the
//! provider patterns and entropy rules of [`ovecc_parser::security`].
//!
//! A file the walk did not parse is not automatically a file worth reading. The
//! walk also drops vendored, built, and generated sources, and Git tracks plenty
//! that no credential lives in: lockfiles, locale bundles, patches. [`scan_mode`]
//! decides from the path alone how much of each file to read.

use ovecc_core::facts::{Evidence, FindingKind, FindingRecord, Severity};
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_parser::security::{
    is_filler_name, is_secret_name, looks_like_high_entropy_secret, provider_secret,
};
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

/// Display strings, never credentials. Their keys read like secret bindings
/// (`forgotten_secret_description`, `oauth_client_client_secret_warning`)
/// because they label the screens where a user handles a credential.
const LOCALE_DIRS: &[&str] = &["locales", "locale", "i18n", "translations", "lang"];

/// Machine-written manifests: every value is a content hash or an integrity
/// digest, so entropy reads "secret" on every line. `lock` also covers the
/// translation manifests that pair each key with a digest of its source string.
const MANIFEST_EXTENSIONS: &[&str] = &["lock", "lockb", "sum", "patch", "diff", "snap"];

/// The two manifests no extension identifies.
const MANIFEST_NAMES: &[&str] = &["package-lock.json", "npm-shrinkwrap.json"];

/// A template ships so a newcomer can copy it, and its values are filler by
/// convention. The value check alone does not catch them: an `.env.example`
/// binding `CRON_API_KEY` to 32 hex characters names no placeholder word.
const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template", ".dist", ".tpl"];

/// Formats whose whole content is settings. A value here is written to be the
/// value the program runs with, which is what makes an unrecognized but
/// high-entropy string worth reporting.
const SETTINGS_EXTENSIONS: &[&str] = &[
    "env",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "properties",
    "tfvars",
    "pem",
    "key",
    "netrc",
    "npmrc",
];

/// Settings files no extension identifies.
const SETTINGS_NAMES: &[&str] = &["dockerfile", ".npmrc", ".netrc", ".pgpass", ".htpasswd"];

/// How much of a tracked file is worth scanning.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScanMode {
    /// Provider patterns and entropy.
    Full,
    /// Provider patterns only.
    ProvidersOnly,
    /// Provider patterns, minus the ones a page about the format spells out.
    Documentation,
    /// Not read at all.
    Skip,
}

/// How to read a tracked file, from its path alone.
///
/// The caller only knows which files the index *parsed*, so one the walk
/// deliberately dropped as vendored, built, or generated arrives here looking
/// merely unread. Reading it anyway undoes the walk's decision and turns a
/// generated client under `src/generated/` into a critical finding.
///
/// Entropy decides from a value's shape alone, and every opaque identifier in a
/// codebase has that shape, so it runs on settings files and nowhere else.
/// Everything else still worth reading keeps the provider patterns, which name
/// an issuer and do not guess. Documentation is separated from the rest of that
/// group only because a page explaining a key format prints the format.
fn scan_mode(relative: &str) -> ScanMode {
    let mut segments: Vec<&str> = relative.split('/').collect();
    let Some(file) = segments.pop() else {
        return ScanMode::Skip;
    };
    if segments.iter().any(|segment| is_skipped_dir(segment)) {
        return ScanMode::Skip;
    }
    let name = file.to_ascii_lowercase();
    let extension = name.rsplit_once('.').map(|(_, value)| value);
    if is_manifest(&name, extension) {
        return ScanMode::Skip;
    }
    if segments.iter().any(|segment| is_documentation_dir(segment))
        || is_documentation(&name, extension)
    {
        return ScanMode::Documentation;
    }
    if is_settings(&name, extension) {
        ScanMode::Full
    } else {
        ScanMode::ProvidersOnly
    }
}

/// A directory whose contents are never read: the source walk already drops it,
/// or it holds translations.
fn is_skipped_dir(segment: &str) -> bool {
    crate::discover::is_excluded_component(segment)
        || LOCALE_DIRS.contains(&segment.to_ascii_lowercase().as_str())
}

fn is_documentation_dir(segment: &str) -> bool {
    DOCUMENTATION_DIRS.contains(&segment.to_ascii_lowercase().as_str())
}

fn is_manifest(name: &str, extension: Option<&str>) -> bool {
    MANIFEST_NAMES.contains(&name)
        || extension.is_some_and(|value| MANIFEST_EXTENSIONS.contains(&value))
}

/// Prose, or a file shipped to be copied. Both hold credential-shaped values
/// that were written to be read rather than used.
fn is_documentation(name: &str, extension: Option<&str>) -> bool {
    extension.is_some_and(|value| DOCUMENTATION_EXTENSIONS.contains(&value))
        || TEMPLATE_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

/// `.env`, `.env.production`, `env.txt`: the extension is the wrong end of the
/// name to read, so the stem carries the signal. A name that says "credentials"
/// or "secrets" makes the same claim in any format.
fn is_settings(name: &str, extension: Option<&str>) -> bool {
    name.starts_with(".env")
        || name.starts_with("env.")
        || name.contains("credential")
        || name.contains("secret")
        || SETTINGS_NAMES.contains(&name)
        || extension.is_some_and(|value| SETTINGS_EXTENSIONS.contains(&value))
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
        if already_read.contains(relative.as_str()) {
            continue;
        }
        let mode = scan_mode(&relative);
        if mode == ScanMode::Skip {
            continue;
        }
        let absolute = root.join(&relative);
        let Ok(metadata) = std::fs::metadata(&absolute) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        // The walk's generated check, applied to the files it never reached.
        if crate::discover::looks_generated(&absolute) {
            continue;
        }
        // Not UTF-8: binary, nothing to read a credential out of.
        let Ok(contents) = std::fs::read_to_string(&absolute) else {
            continue;
        };
        files_scanned += 1;
        for (label, line) in scan_text(&contents, mode)
            .into_iter()
            .take(MAX_HITS_PER_FILE)
        {
            findings.push(finding(repository_id, snapshot_id, &relative, line, &label));
        }
    }
    findings.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    TrackedScan {
        findings,
        files_scanned,
    }
}

/// Whether a provider match is worth reporting.
///
/// Only the PEM header is conditional. Every other pattern matches an opaque
/// value, so the match itself is the evidence; a header is a format marker, and
/// what makes it a key is the body underneath. Documentation is the one surface
/// where a body underneath still proves nothing, because a page about the format
/// prints a whole key to show what one looks like.
fn reports(provider: &str, mode: ScanMode, lines: &[&str], index: usize) -> bool {
    if provider != ovecc_parser::security::PRIVATE_KEY_LABEL {
        return true;
    }
    mode != ScanMode::Documentation && pem_body_follows(lines, index)
}

/// True when a PEM header is followed by enough base64 to be key material,
/// either on the same line (an env file writes the key with `\n` escapes) or on
/// the next one.
fn pem_body_follows(lines: &[&str], index: usize) -> bool {
    // Shorter than any real key body and longer than the identifiers that share
    // a line with the header in a fixture.
    const MIN_BODY: usize = 40;
    let tail = lines[index]
        .rsplit_once("-----")
        .map_or("", |(_, after)| after);
    longest_base64_run(tail) >= MIN_BODY
        || lines
            .get(index + 1)
            .is_some_and(|next| longest_base64_run(next) >= MIN_BODY)
}

fn longest_base64_run(text: &str) -> usize {
    let mut longest = 0;
    let mut run = 0;
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=') {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    longest
}

/// The `(label, line)` of every credential in a plain-text file.
fn scan_text(contents: &str, mode: ScanMode) -> Vec<(String, u32)> {
    let lines: Vec<&str> = contents.lines().collect();
    (0..lines.len())
        .filter_map(|index| {
            secret_on_line(&lines, index, mode).map(|label| (label, index as u32 + 1))
        })
        .collect()
}

/// The label one line earns, if any. Takes the whole file because a PEM header
/// is only a key when its body follows.
///
/// When the line binds a name, both checks run against the value alone. Reading
/// a provider pattern off the whole line instead loses the name, and the name is
/// what says the value is filler: `placeholder="sk_live_…"` is a Stripe key by
/// shape and a label by intent. A line that binds nothing, a PEM header, is
/// still matched whole.
fn secret_on_line(lines: &[&str], index: usize, mode: ScanMode) -> Option<String> {
    let text = lines[index].trim();
    if text.is_empty() || text.starts_with('#') || text.starts_with("//") {
        return None;
    }
    let Some((name, value)) = assignment(text) else {
        let provider = provider_secret(text)?;
        return reports(provider, mode, lines, index).then(|| provider.to_string());
    };
    if is_filler_name(name) {
        return None;
    }
    if let Some(provider) = provider_secret(value) {
        return reports(provider, mode, lines, index).then(|| provider.to_string());
    }
    let entropy =
        mode == ScanMode::Full && is_secret_name(name) && looks_like_high_entropy_secret(value);
    entropy.then(|| format!("high-entropy value assigned to {name}"))
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
        .trim_end_matches([',', ';'])
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
            ScanMode::Full,
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
            ScanMode::Full,
        );
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn ignores_the_shapes_a_source_file_the_index_cannot_parse_offers() {
        // Every line here is from a `.vue` component, where the text scan runs
        // because no Vue grammar is linked in.
        let hits = scan_text(
            "placeholder=\"sk_live_abcdefghijklmnop\"\n\
             placeholder: `-----BEGIN PRIVATE KEY-----`\n\
             const noTokensImage = `${baseUrl}/images/pack.svg`\n\
             const token = readStoredAuthToken()\n\
             const isCredentialOnlyNode = props.node.type.startsWith(PREFIX);\n",
            ScanMode::Full,
        );
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn still_reports_a_credential_a_tracked_env_file_holds() {
        // The first shape is what a tracked `.env.production` holds; the second
        // is how a `key.pem` opens.
        let hits = scan_text(
            "VITE_APP_GOOGLE_API_KEY=AIzaSyD1234567890abcdefghijklmnopqrstuv\n\
             -----BEGIN RSA PRIVATE KEY-----\n\
             MIIEowIBAAKCAQEAvZ3xK8mQ4tR7nL2pD9sF6hJ1wX0cY5bT3gN8uV4eA7iO2kM6\n",
            ScanMode::Full,
        );
        let labels: Vec<&str> = hits.iter().map(|(label, _)| label.as_str()).collect();
        assert_eq!(labels, vec!["Google API key", "private key"], "{hits:?}");
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
    fn documentation_and_templates_keep_only_the_provider_patterns() {
        // These exist to show the shape of a credential, so entropy fires on
        // every invented value, but a real prefixed token in one is a leak.
        for path in [
            "docs/config.rst",
            "docs/tutorial/deploy.rst",
            "README.md",
            "examples/app/settings.py",
            ".env.example",
            "apps/api/.env.local.sample",
            "config/settings.yml.template",
        ] {
            assert_eq!(scan_mode(path), ScanMode::Documentation, "{path}");
        }
        // The shape this scan exists for: a `.env` committed under any name,
        // and the formats and names that make the same claim about their
        // contents.
        for path in [
            "env.txt",
            ".env.production",
            "config/credentials.json",
            "apps/web/calendso.yaml",
            "infra/terraform.tfvars",
            "Dockerfile",
        ] {
            assert_eq!(scan_mode(path), ScanMode::Full, "{path}");
        }
        // Entropy stays off everywhere else. A value in ordinary code is an
        // identifier far more often than a credential, and the provider
        // patterns still run.
        for path in [
            "scripts/deploy.sh",
            "frontend/src/mocks/handlers.ts",
            "src/fixtures/responses.json",
            "cmd/server/main.go",
        ] {
            assert_eq!(scan_mode(path), ScanMode::ProvidersOnly, "{path}");
        }
    }

    #[test]
    fn skips_what_the_source_walk_rejected_and_what_machines_wrote() {
        for path in [
            "node_modules/left-pad/index.js",
            "apps/web/dist/bundle.js",
            "vendor/github.com/pkg/errors/errors.go",
            // Integrity digests, one per line.
            "yarn.lock",
            "go.sum",
            "package-lock.json",
            "i18n.lock",
            "patches/@ai-sdk+google-vertex+3.0.81.patch",
            // Display strings under keys that read like secret bindings.
            "packages/i18n/locales/zh-CN/common.json",
        ] {
            assert_eq!(scan_mode(path), ScanMode::Skip, "{path}");
        }
        // A lockfile name is not a lockfile, and `i18n` in a filename is not a
        // locale bundle. Both are still read.
        assert_ne!(scan_mode("src/lockScreen.ts"), ScanMode::Skip);
        assert_ne!(scan_mode("src/i18nHelpers.ts"), ScanMode::Skip);
    }

    #[test]
    fn a_real_token_committed_into_a_template_still_counts() {
        let text = "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n\
                    CRON_API_KEY=1234567890abcdef1234567890abcdef\n";
        let full = scan_text(text, ScanMode::Full);
        assert_eq!(full.len(), 2, "{full:?}");
        let template = scan_text(text, ScanMode::Documentation);
        assert_eq!(template.len(), 1, "{template:?}");
        assert!(template[0].0.contains("GitHub"), "{template:?}");
    }

    #[test]
    fn a_pem_header_without_key_material_is_a_format_not_a_key() {
        // A self-hosting guide leaves the body as `...`, a workflow fixture
        // carries the header as a JSON string, a test asserts on it. None of
        // them hold a key.
        for text in [
            "DKIM_PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\\n...\\n\"\n",
            "        \"privateKey\": \"-----BEGIN PRIVATE KEY-----\",\n        },\n",
            "$this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $env);\n",
        ] {
            assert!(scan_text(text, ScanMode::Full).is_empty(), "{text}");
            assert!(
                scan_text(text, ScanMode::ProvidersOnly).is_empty(),
                "{text}"
            );
        }
        // The same header over a real body is a key wherever it sits, except on
        // the one surface that prints a whole key to explain the format.
        let key = "-----BEGIN PRIVATE KEY-----\n\
                   MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n";
        assert_eq!(scan_text(key, ScanMode::Full).len(), 1);
        assert_eq!(scan_text(key, ScanMode::ProvidersOnly).len(), 1);
        assert!(scan_text(key, ScanMode::Documentation).is_empty());
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
