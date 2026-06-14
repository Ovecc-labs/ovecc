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

fn version_in_semver_range(version: &semver::Version, range: &OsvRange) -> bool {
    if !range.range_type.eq_ignore_ascii_case("SEMVER") {
        return false;
    }
    let mut affected = false;
    for event in &range.events {
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
}
