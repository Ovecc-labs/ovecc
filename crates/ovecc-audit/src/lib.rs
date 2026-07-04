//! Offline dependency vulnerability audit.
//!
//! Cross-references the packages declared in a repository's lockfiles with a
//! local OSV database. The user syncs OSV JSON files (from <https://osv.dev>)
//! into `.ovecc/osv/` out of band; this crate parses them, matches versions
//! per the OSV schema (SEMVER `introduced`/`fixed` events), and emits
//! `VulnerableDependency` findings.

use std::path::Path;

use chrono::Utc;
use ovecc_core::facts::{Evidence, FindingKind, FindingRecord, Severity};
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use serde::Deserialize;

/// A resolved dependency from a lockfile.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    /// True for direct dependencies, false for transitive ones.
    pub is_direct: bool,
}

// ---- OSV schema (the subset we evaluate) ----

#[derive(Debug, Clone, Deserialize)]
pub struct OsvEntry {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: OsvPackage,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OsvPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type", default)]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
}

/// Parses an npm `package-lock.json` (lockfileVersion 2/3) into packages.
/// Each `node_modules/...` entry is one installed package; a key with a single
/// `node_modules/` segment is a direct dependency.
pub fn parse_npm_lockfile(content: &str, manifest_path: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let Some(packages) = json.get("packages").and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, entry) in packages {
        // The root project has an empty key; skip it.
        let Some(rest) = key.strip_prefix("node_modules/") else {
            continue;
        };
        // Nested installs (`a/node_modules/b`) are transitive; the package name
        // is the segment after the final `node_modules/`.
        let name = rest.rsplit("node_modules/").next().unwrap_or(rest);
        let is_direct = !rest.contains("node_modules/");
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        out.push(Package {
            ecosystem: "npm".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: manifest_path.to_string(),
            is_direct,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    out.dedup();
    out
}

/// Discovers packages from known lockfiles at the repository root. Currently
/// supports npm's `package-lock.json`.
pub fn discover_packages(root: &Path) -> Vec<Package> {
    let lockfile = root.join("package-lock.json");
    match std::fs::read_to_string(&lockfile) {
        Ok(content) => parse_npm_lockfile(&content, "package-lock.json"),
        Err(_) => Vec::new(),
    }
}

/// Downloads the OSV advisories affecting `packages` into `osv_dir` — the
/// ONLY ovecc code path that ever touches the network, and only behind the
/// explicit `audit --fetch` flag. One `querybatch` call per 500 packages,
/// then each advisory is fetched once; files already on disk are kept, so
/// re-runs are incremental. Returns (advisories written, packages queried).
pub fn fetch_advisories(packages: &[Package], osv_dir: &Path) -> anyhow::Result<(usize, usize)> {
    use serde_json::json;
    std::fs::create_dir_all(osv_dir)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();

    let mut ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for chunk in packages.chunks(500) {
        let queries: Vec<serde_json::Value> = chunk
            .iter()
            .map(|package| {
                json!({
                    "package": { "name": package.name, "ecosystem": package.ecosystem },
                    "version": package.version,
                })
            })
            .collect();
        let response: serde_json::Value = agent
            .post("https://api.osv.dev/v1/querybatch")
            .send_json(json!({ "queries": queries }))?
            .into_json()?;
        for result in response
            .get("results")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
        {
            for vuln in result
                .get("vulns")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(id) = vuln.get("id").and_then(|i| i.as_str()) {
                    ids.insert(id.to_string());
                }
            }
        }
    }

    let mut written = 0usize;
    for id in &ids {
        // Advisory ids are [A-Za-z0-9-]; guard anyway so a hostile response
        // can never write outside the OSV directory.
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            continue;
        }
        let path = osv_dir.join(format!("{id}.json"));
        if path.exists() {
            continue;
        }
        let body = agent
            .get(&format!("https://api.osv.dev/v1/vulns/{id}"))
            .call()?
            .into_string()?;
        std::fs::write(&path, body)?;
        written += 1;
    }
    Ok((written, packages.len()))
}

/// Loads every OSV JSON entry from a directory (non-recursive). Missing
/// directory or unreadable/invalid files yield no entries — the audit simply
/// finds nothing rather than failing.
pub fn load_osv_dir(dir: &Path) -> Vec<OsvEntry> {
    let mut entries = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return entries;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(osv) = serde_json::from_str::<OsvEntry>(&content)
        {
            entries.push(osv);
        }
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries
}

/// True when `version` is affected by an OSV `affected` block: matched by the
/// explicit versions list, or contained in a SEMVER range per the OSV event
/// algorithm (`introduced` turns affection on, `fixed`/`last_affected` off).
pub fn is_affected(version: &str, affected: &OsvAffected) -> bool {
    if affected.versions.iter().any(|v| v == version) {
        return true;
    }
    let Ok(parsed) = semver::Version::parse(version) else {
        return false;
    };
    affected
        .ranges
        .iter()
        .any(|range| version_in_semver_range(&parsed, range))
}

/// Sort key for an OSV range event: its version, plus a rank so that at an
/// equal version `introduced` (turns affection on) is applied before
/// `fixed`/`last_affected` (turn it off). An unparseable, non-`"0"` version
/// yields `None` and is pushed to the end, where it acts as a no-op.
fn event_sort_key(event: &OsvEvent) -> (Option<semver::Version>, u8) {
    if let Some(v) = &event.introduced {
        let version = if v == "0" {
            Some(semver::Version::new(0, 0, 0))
        } else {
            semver::Version::parse(v).ok()
        };
        return (version, 0);
    }
    if let Some(v) = &event.fixed {
        return (semver::Version::parse(v).ok(), 1);
    }
    if let Some(v) = &event.last_affected {
        return (semver::Version::parse(v).ok(), 1);
    }
    (None, 2)
}

fn version_in_semver_range(version: &semver::Version, range: &OsvRange) -> bool {
    if !range.range_type.eq_ignore_ascii_case("SEMVER") {
        return false;
    }
    // The OSV range algorithm is a state machine over events in ascending
    // version order. Sort first so a verdict never depends on the order events
    // happen to appear in the source JSON.
    let mut events: Vec<&OsvEvent> = range.events.iter().collect();
    events.sort_by(|a, b| {
        let (va, ra) = event_sort_key(a);
        let (vb, rb) = event_sort_key(b);
        match (va, vb) {
            (Some(x), Some(y)) => x.cmp(&y).then(ra.cmp(&rb)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => ra.cmp(&rb),
        }
    });

    let mut affected = false;
    for event in events {
        if let Some(introduced) = &event.introduced {
            // "0" denotes "from the beginning of time".
            let on = introduced == "0"
                || semver::Version::parse(introduced)
                    .map(|i| *version >= i)
                    .unwrap_or(false);
            if on {
                affected = true;
            }
        }
        if let Some(fixed) = &event.fixed
            && semver::Version::parse(fixed)
                .map(|f| *version >= f)
                .unwrap_or(false)
        {
            affected = false;
        }
        if let Some(last) = &event.last_affected
            && semver::Version::parse(last)
                .map(|l| *version > l)
                .unwrap_or(false)
        {
            affected = false;
        }
    }
    affected
}

/// Audits packages against the OSV entries, returning one finding per
/// (package, vulnerability) match.
pub fn audit(
    repository_id: &str,
    snapshot_id: Option<&str>,
    packages: &[Package],
    osv: &[OsvEntry],
) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    for package in packages {
        for entry in osv {
            for affected in &entry.affected {
                // Ecosystem is matched case-insensitively; the package name is
                // compared exactly, which is correct for npm (registry names are
                // lowercase). TODO(multi-ecosystem): canonicalize names per
                // ecosystem before this check when a second one is wired — e.g.
                // PyPI/PEP 503 (lowercase, collapse runs of -/_/. to a single -).
                if !affected
                    .package
                    .ecosystem
                    .eq_ignore_ascii_case(&package.ecosystem)
                    || affected.package.name != package.name
                {
                    continue;
                }
                if !is_affected(&package.version, affected) {
                    continue;
                }
                findings.push(finding(repository_id, snapshot_id, package, entry));
                break; // one finding per (package, advisory)
            }
        }
    }
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings
}

fn finding(
    repository_id: &str,
    snapshot_id: Option<&str>,
    package: &Package,
    entry: &OsvEntry,
) -> FindingRecord {
    let summary = entry
        .summary
        .clone()
        .or_else(|| entry.details.clone())
        .unwrap_or_else(|| "no description".to_string());
    FindingRecord {
        id: FindingId::from_parts(&[
            repository_id,
            "osv",
            &entry.id,
            &package.name,
            &package.version,
        ]),
        repository_id: RepositoryId::from_raw(repository_id),
        snapshot_id: snapshot_id.map(SnapshotId::from_raw),
        kind: FindingKind::VulnerableDependency,
        // Defaulting to High; CVSS-derived severity is a later refinement.
        severity: Severity::High,
        rule_name: Some("audit/osv".to_string()),
        target: None,
        title: format!(
            "Vulnerable dependency: {}@{} ({})",
            package.name, package.version, entry.id
        ),
        description: format!(
            "{} — {} {}@{} is affected by {}. {}",
            summary,
            if package.is_direct {
                "direct dependency"
            } else {
                "transitive dependency"
            },
            package.name,
            package.version,
            entry.id,
            package.manifest_path
        ),
        evidence: vec![Evidence {
            file_path: package.manifest_path.clone(),
            line: None,
            symbol: Some(format!("{}@{}", package.name, package.version)),
            detail: Some(entry.id.clone()),
        }],
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_lockfile_v3() {
        let lock = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.20" },
                "node_modules/express": { "version": "4.18.2" },
                "node_modules/express/node_modules/cookie": { "version": "0.4.0" }
            }
        }"#;
        let packages = parse_npm_lockfile(lock, "package-lock.json");
        let lodash = packages.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.20");
        assert!(lodash.is_direct);
        // Nested install is transitive and named by the final segment.
        let cookie = packages.iter().find(|p| p.name == "cookie").unwrap();
        assert_eq!(cookie.version, "0.4.0");
        assert!(!cookie.is_direct);
    }

    fn osv_lodash() -> OsvEntry {
        serde_json::from_str(
            r#"{
                "id": "GHSA-test-lodash",
                "summary": "Prototype pollution in lodash",
                "affected": [{
                    "package": { "ecosystem": "npm", "name": "lodash" },
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [{ "introduced": "0" }, { "fixed": "4.17.21" }]
                    }]
                }]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn matches_vulnerable_version_in_semver_range() {
        let entry = osv_lodash();
        assert!(
            is_affected("4.17.20", &entry.affected[0]),
            "below fixed → affected"
        );
        assert!(
            !is_affected("4.17.21", &entry.affected[0]),
            "at fixed → safe"
        );
        assert!(
            !is_affected("5.0.0", &entry.affected[0]),
            "above fixed → safe"
        );
    }

    #[test]
    fn audit_produces_finding_for_vulnerable_package() {
        let packages = vec![
            Package {
                ecosystem: "npm".into(),
                name: "lodash".into(),
                version: "4.17.20".into(),
                manifest_path: "package-lock.json".into(),
                is_direct: true,
            },
            Package {
                ecosystem: "npm".into(),
                name: "lodash".into(),
                version: "4.17.21".into(),
                manifest_path: "package-lock.json".into(),
                is_direct: true,
            },
        ];
        let osv = vec![osv_lodash()];
        let findings = audit("repo:test", Some("snap"), &packages, &osv);
        assert_eq!(findings.len(), 1, "only the 4.17.20 install is vulnerable");
        assert_eq!(findings[0].kind, FindingKind::VulnerableDependency);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("lodash@4.17.20"));
        assert!(findings[0].title.contains("GHSA-test-lodash"));
    }

    #[test]
    fn explicit_versions_list_matches() {
        let entry: OsvEntry = serde_json::from_str(
            r#"{"id":"X","affected":[{"package":{"ecosystem":"npm","name":"p"},"versions":["1.2.3"]}]}"#,
        )
        .unwrap();
        assert!(is_affected("1.2.3", &entry.affected[0]));
        assert!(!is_affected("1.2.4", &entry.affected[0]));
    }

    #[test]
    fn multi_window_range_skips_the_patched_gap() {
        // Vulnerable in [0,1.0.0) and again in [2.0.0,3.0.0): the events form
        // two affected windows with a safe gap between them.
        let entry: OsvEntry = serde_json::from_str(
            r#"{"id":"MULTI","affected":[{"package":{"ecosystem":"npm","name":"p"},
                "ranges":[{"type":"SEMVER","events":[
                    {"introduced":"0"},{"fixed":"1.0.0"},
                    {"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]}]}"#,
        )
        .unwrap();
        let a = &entry.affected[0];
        assert!(is_affected("0.9.0", a), "first window");
        assert!(!is_affected("1.0.0", a), "fixed");
        assert!(!is_affected("1.5.0", a), "patched gap is safe");
        assert!(is_affected("2.5.0", a), "re-introduced window");
        assert!(!is_affected("3.0.0", a), "fixed again");
    }

    #[test]
    fn last_affected_is_an_inclusive_upper_bound() {
        let entry: OsvEntry = serde_json::from_str(
            r#"{"id":"LA","affected":[{"package":{"ecosystem":"npm","name":"p"},
                "ranges":[{"type":"SEMVER","events":[
                    {"introduced":"1.0.0"},{"last_affected":"1.5.0"}]}]}]}"#,
        )
        .unwrap();
        let a = &entry.affected[0];
        assert!(!is_affected("0.9.0", a), "below introduced");
        assert!(is_affected("1.0.0", a));
        assert!(is_affected("1.5.0", a), "last_affected is inclusive");
        assert!(!is_affected("1.6.0", a), "above last_affected");
    }

    #[test]
    fn non_semver_range_type_is_ignored() {
        // Only SEMVER ranges are evaluated; ECOSYSTEM/GIT ranges are skipped.
        let entry: OsvEntry = serde_json::from_str(
            r#"{"id":"EC","affected":[{"package":{"ecosystem":"npm","name":"p"},
                "ranges":[{"type":"ECOSYSTEM","events":[
                    {"introduced":"0"},{"fixed":"9.9.9"}]}]}]}"#,
        )
        .unwrap();
        assert!(!is_affected("1.0.0", &entry.affected[0]));
    }

    #[test]
    fn unparseable_version_never_matches_a_range() {
        // A non-semver version can't be range-compared, so it is treated as
        // not affected (explicit version lists are the only escape hatch).
        assert!(!is_affected("not.a.version", &osv_lodash().affected[0]));
    }

    #[test]
    fn events_are_sorted_so_their_order_does_not_change_the_verdict() {
        // A single window [1.0.0, 2.0.0) with events given OUT OF ORDER. Without
        // sorting, 2.5.0 (above the fix) would be wrongly flagged as affected.
        let entry: OsvEntry = serde_json::from_str(
            r#"{"id":"ORD","affected":[{"package":{"ecosystem":"npm","name":"p"},
                "ranges":[{"type":"SEMVER","events":[
                    {"fixed":"2.0.0"},{"introduced":"1.0.0"}]}]}]}"#,
        )
        .unwrap();
        let a = &entry.affected[0];
        assert!(!is_affected("0.9.0", a), "below window");
        assert!(is_affected("1.5.0", a), "inside window");
        assert!(
            !is_affected("2.5.0", a),
            "above the fix must stay safe regardless of event order"
        );
    }

    #[test]
    fn audit_matches_ecosystem_case_insensitively() {
        let packages = vec![Package {
            ecosystem: "NPM".into(),
            name: "lodash".into(),
            version: "4.17.20".into(),
            manifest_path: "package-lock.json".into(),
            is_direct: true,
        }];
        let findings = audit("repo:test", None, &packages, &[osv_lodash()]);
        assert_eq!(findings.len(), 1, "NPM should match npm advisory");
    }
}
