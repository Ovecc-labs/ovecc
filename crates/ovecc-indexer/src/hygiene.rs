//! Dependency hygiene: unused dependencies (opt-in) and unlisted (phantom)
//! dependencies, from the package manifests and the import graph.

use crate::manifests::find_package_manifests;
use ovecc_core::facts::FindingKind;
use ovecc_core::id::RepositoryId;
use std::collections::HashSet;
use std::path::Path;

/// Normalizes a bare import specifier to its package root: `lodash/fp` →
/// `lodash`, `@scope/pkg/sub` → `@scope/pkg`. Returns `None` for relative
/// imports and Node built-ins (`node:fs`, `fs`), which are never npm deps.
pub(crate) fn external_package_root(specifier: &str) -> Option<String> {
    if specifier.starts_with('.') || specifier.starts_with('/') || specifier.starts_with("node:") {
        return None;
    }
    const BUILTINS: [&str; 40] = [
        "fs",
        "path",
        "os",
        "http",
        "https",
        "http2",
        "url",
        "util",
        "stream",
        "events",
        "crypto",
        "child_process",
        "process",
        "buffer",
        "assert",
        "zlib",
        "net",
        "tls",
        "dns",
        "querystring",
        "readline",
        "cluster",
        "worker_threads",
        "perf_hooks",
        "module",
        // Less common but real: any missing entry becomes a phantom-dependency
        // false positive in `unlisted-dependency`.
        "tty",
        "vm",
        "v8",
        "repl",
        "string_decoder",
        "async_hooks",
        "timers",
        "constants",
        "inspector",
        "dgram",
        "punycode",
        "domain",
        "trace_events",
        "wasi",
        "diagnostics_channel",
    ];
    let root = if let Some(rest) = specifier.strip_prefix('@') {
        let mut parts = rest.splitn(3, '/');
        let scope = parts.next()?;
        let name = parts.next()?;
        // `@/x` (empty scope) is the classic tsconfig root alias, never a
        // valid npm scope — flagging it as a phantom dependency was a false
        // positive (seen on zod's `@/.source`).
        if !is_plausible_npm_segment(scope) || !is_plausible_npm_segment(name) {
            return None;
        }
        format!("@{scope}/{name}")
    } else {
        let root = specifier.split('/').next()?.to_string();
        if !is_plausible_npm_segment(&root) {
            return None;
        }
        root
    };
    if BUILTINS.contains(&root.as_str()) {
        return None;
    }
    Some(root)
}

/// True for a plausible npm package-name segment: non-empty, starts with an
/// alphanumeric, and uses only URL-safe name characters. Alias-shaped
/// specifiers — `~/lib` (webpack/Nuxt), `#internal` (Node subpath imports),
/// `$lib` (SvelteKit), `_private` — all fail, so path aliases whose target is
/// missing or generated never surface as phantom dependencies.
fn is_plausible_npm_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// True when a file imports npm packages, the only kind a `package.json`
/// declares. A repository shipping a Python service or a Go binary beside its
/// Node packages still has one manifest at the root, and `import contextlib`
/// is not a phantom dependency there.
fn imports_npm_packages(path: &str) -> bool {
    path.rsplit_once('.')
        .and_then(|(_, extension)| ovecc_core::lang::SourceLanguage::from_extension(extension))
        .is_some_and(ovecc_core::lang::SourceLanguage::is_js_family)
}

/// Tokens a manifest `scripts` map invokes — the words of every script command.
/// A dependency whose name (or well-known binary) appears here is used even
/// without an import (`tsc`, `jest`, `eslint`, ...).
fn script_tokens(manifests: &[(String, serde_json::Value)]) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for (_, manifest) in manifests {
        let Some(scripts) = manifest.get("scripts").and_then(|value| value.as_object()) else {
            continue;
        };
        for value in scripts.values() {
            let Some(command) = value.as_str() else {
                continue;
            };
            for token in command
                .split(|c: char| c.is_whitespace() || "&|;()\"'".contains(c))
                .filter(|t| !t.is_empty())
            {
                tokens.insert(token.to_string());
            }
        }
    }
    tokens
}

/// Whether a declared dev-tooling package is plausibly used without an import:
/// via a script binary, a config-file plugin/preset convention, or as a types
/// package. Precision-first — when in doubt, treat it as used.
fn dev_dependency_plausibly_used(name: &str, script_tokens: &HashSet<String>) -> bool {
    if name.starts_with("@types/") || script_tokens.contains(name) {
        return true;
    }
    // Well-known binary -> package pairs (the bin name differs from the package).
    const BIN_TO_PACKAGE: [(&str, &str); 4] = [
        ("tsc", "typescript"),
        ("tsserver", "typescript"),
        ("wp", "webpack"),
        ("sb", "storybook"),
    ];
    for (bin, package) in BIN_TO_PACKAGE {
        if name == package && script_tokens.contains(bin) {
            return true;
        }
    }
    // Plugin/preset/config packages are loaded from config files (eslint,
    // babel, postcss, jest transforms, ...), invisible to the import graph.
    const CONFIG_LOADED_FRAGMENTS: [&str; 14] = [
        "eslint",
        "prettier",
        "babel",
        "postcss",
        "tailwind",
        "jest",
        "vitest",
        "husky",
        "lint-staged",
        "commitlint",
        "-plugin",
        "-preset",
        "-config",
        "-loader",
    ];
    CONFIG_LOADED_FRAGMENTS
        .iter()
        .any(|fragment| name.contains(fragment))
}

/// Flags packages declared in a `package.json` `dependencies` map that no
/// indexed file imports. Conservative: production deps only (not `devDeps`),
/// `@types/*` excluded (ambient), one finding per (manifest, package).
pub(crate) fn detect_unused_dependencies(
    root: &Path,
    repository_id: &str,
    snapshot_id: &str,
    imported_roots: &HashSet<String>,
) -> Vec<ovecc_core::facts::FindingRecord> {
    let mut findings = Vec::new();
    let manifests = find_package_manifests(root);
    let tokens = script_tokens(&manifests);
    // (manifest section, rule name, dev-tooling guards apply)
    const SECTIONS: [(&str, &str, bool); 3] = [
        ("dependencies", "unused-dependency", false),
        ("devDependencies", "unused-dev-dependency", true),
        ("optionalDependencies", "unused-optional-dependency", true),
    ];
    for (dir, manifest) in &manifests {
        let manifest_path = format!("{dir}package.json");
        for (section, rule_name, dev_guards) in SECTIONS {
            let Some(deps) = manifest.get(section).and_then(|value| value.as_object()) else {
                continue;
            };
            for name in deps.keys() {
                if name.starts_with("@types/")
                    || imported_roots.contains(name.as_str())
                    || tokens.contains(name.as_str())
                {
                    continue;
                }
                if dev_guards && dev_dependency_plausibly_used(name, &tokens) {
                    continue;
                }
                findings.push(ovecc_core::facts::FindingRecord {
                    id: ovecc_core::id::FindingId::from_parts(&[
                        repository_id,
                        "deadcode",
                        rule_name,
                        &manifest_path,
                        name,
                    ]),
                    repository_id: RepositoryId::from_raw(repository_id),
                    snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(snapshot_id)),
                    kind: FindingKind::UnusedDependency,
                    severity: ovecc_core::facts::Severity::Low,
                    rule_name: Some(rule_name.to_string()),
                    target: None,
                    title: format!("Unused dependency: {name}"),
                    description: format!(
                        "'{name}' is declared in {manifest_path} ({section}) but never imported \
                         by an indexed file or invoked by a script. Verify it is not used via \
                         config, CLI, or dynamic import before removing."
                    ),
                    evidence: vec![ovecc_core::facts::Evidence {
                        file_path: manifest_path.clone(),
                        line: Some(1),
                        symbol: Some(name.clone()),
                        detail: Some(section.to_string()),
                    }],
                    created_at: chrono::Utc::now(),
                });
            }
        }
    }
    findings
}

/// Phantom dependencies: packages imported by indexed JavaScript or TypeScript
/// but declared in no `package.json` section — they resolve only via hoisting
/// or a transitive install and break on a lockfile change. Precise by
/// construction (the import is a fact; the absent declaration is a fact), so
/// this runs unconditionally. Silent when the repo has no manifests at all
/// (non-Node repositories) and, within a repo that has one, silent about the
/// languages it does not govern.
pub(crate) fn detect_unlisted_dependencies(
    root: &Path,
    repository_id: &str,
    snapshot_id: &str,
    dependencies: &[ovecc_core::legacy::DependencyRecord],
) -> Vec<ovecc_core::facts::FindingRecord> {
    let manifests = find_package_manifests(root);
    if manifests.is_empty() {
        return Vec::new();
    }
    let declared = declared_packages(&manifests);
    first_import_sites(dependencies)
        .into_iter()
        .filter(|(package_root, _)| !declared.contains(package_root))
        .map(
            |(package_root, (file, line))| ovecc_core::facts::FindingRecord {
                id: ovecc_core::id::FindingId::from_parts(&[
                    repository_id,
                    "unlisted-dependency",
                    &package_root,
                ]),
                repository_id: RepositoryId::from_raw(repository_id),
                snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(snapshot_id)),
                kind: FindingKind::UnlistedDependency,
                severity: ovecc_core::facts::Severity::Medium,
                rule_name: Some("unlisted-dependency".to_string()),
                target: None,
                title: format!("Unlisted dependency: {package_root}"),
                description: format!(
                    "'{package_root}' is imported (first at {file}:{line}) but declared in no \
                 package.json — it resolves only via hoisting or a transitive install and can \
                 break on any lockfile change. Declare it explicitly."
                ),
                evidence: vec![ovecc_core::facts::Evidence {
                    file_path: file,
                    line: Some(line as u32),
                    symbol: Some(package_root.clone()),
                    detail: Some(dependency_import_detail(&package_root)),
                }],
                created_at: chrono::Utc::now(),
            },
        )
        .collect()
}

/// Every package name the manifests declare, from any section. A workspace
/// package's own name goes in too: it is importable inside the monorepo.
fn declared_packages(manifests: &[(String, serde_json::Value)]) -> HashSet<String> {
    let mut declared = HashSet::new();
    for (_, manifest) in manifests {
        for section in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            if let Some(deps) = manifest.get(section).and_then(|value| value.as_object()) {
                declared.extend(deps.keys().cloned());
            }
        }
        if let Some(name) = manifest.get("name").and_then(|value| value.as_str()) {
            declared.insert(name.to_string());
        }
    }
    declared
}

/// The first import site of every npm package root, as `(file, line)`. Ordered
/// and minimised so the reported site does not depend on walk order.
fn first_import_sites(
    dependencies: &[ovecc_core::legacy::DependencyRecord],
) -> std::collections::BTreeMap<String, (String, usize)> {
    let mut first_use = std::collections::BTreeMap::new();
    for dependency in dependencies {
        if !dependency.is_external_package() || !imports_npm_packages(&dependency.source_file_path)
        {
            continue;
        }
        let Some(package_root) = external_package_root(&dependency.specifier) else {
            continue;
        };
        let site = (
            dependency.source_file_path.clone(),
            dependency.evidence_line,
        );
        first_use
            .entry(package_root)
            .and_modify(|existing| {
                if site < *existing {
                    existing.clone_from(&site);
                }
            })
            .or_insert(site);
    }
    first_use
}

/// Evidence detail for an unlisted dependency.
fn dependency_import_detail(package_root: &str) -> String {
    format!("bare import of '{package_root}' with no manifest declaration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_external_package_roots() {
        assert_eq!(external_package_root("lodash").as_deref(), Some("lodash"));
        assert_eq!(
            external_package_root("lodash/fp").as_deref(),
            Some("lodash")
        );
        assert_eq!(
            external_package_root("@scope/pkg/sub").as_deref(),
            Some("@scope/pkg")
        );
        assert_eq!(
            external_package_root("@scope/pkg").as_deref(),
            Some("@scope/pkg")
        );
        // Relative imports and Node built-ins are not npm dependencies.
        assert_eq!(external_package_root("./local"), None);
        assert_eq!(external_package_root("../up"), None);
        assert_eq!(external_package_root("node:fs"), None);
        assert_eq!(external_package_root("fs"), None);
        assert_eq!(external_package_root("path"), None);
    }

    #[test]
    fn alias_specifiers_are_never_phantom_dependencies() {
        // tsconfig/webpack/SvelteKit/Node-subpath alias shapes.
        assert_eq!(external_package_root("@/.source"), None);
        assert_eq!(external_package_root("@/public"), None);
        assert_eq!(external_package_root("~/lib/util"), None);
        assert_eq!(external_package_root("#internal/config"), None);
        assert_eq!(external_package_root("$lib/stores"), None);
        assert_eq!(external_package_root("_private/mod"), None);
        // Real packages still normalize to their root.
        assert_eq!(
            external_package_root("@scope/pkg/sub"),
            Some("@scope/pkg".to_string())
        );
        assert_eq!(
            external_package_root("lodash/fp"),
            Some("lodash".to_string())
        );
        assert_eq!(external_package_root("node:fs"), None);
        assert_eq!(external_package_root("fs"), None);
    }
}
