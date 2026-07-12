//! Workspace manifest discovery (Cargo crate roots, npm package manifests),
//! shared by import resolution, entry-point detection, and dependency hygiene.

use crate::discover::is_excluded_component;
use ignore::WalkBuilder;
use std::collections::HashMap;
use std::path::Path;

/// Maps each workspace crate's import name (`ovecc_core`) to its source dir
/// (`crates/ovecc-core/src`), by locating every `Cargo.toml` that declares a
/// `[package]`. Hyphens normalize to underscores because that is how Cargo
/// exposes the crate to `use` paths.
pub(crate) fn find_cargo_crate_roots(root: &Path) -> HashMap<String, String> {
    let mut roots = HashMap::new();
    let mut builder = WalkBuilder::new(root);
    // Same stance as `find_package_manifests`: don't honour .gitignore (an
    // ignored manifest still names a real crate); prune via the built-in
    // excluded dirs (`target`, `node_modules`, …); workspace manifests live
    // near the top of the tree.
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .max_depth(Some(6));
    builder.filter_entry(|entry| {
        entry.depth() == 0
            || entry
                .file_name()
                .to_str()
                .map(|name| !is_excluded_component(name))
                .unwrap_or(true)
    });
    for entry in builder.build().flatten() {
        if entry.file_name() != "Cargo.toml" || !entry.path().is_file() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(manifest) = content.parse::<toml::Table>() else {
            continue;
        };
        let Some(name) = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(|name| name.as_str())
        else {
            continue; // virtual workspace root, no importable crate
        };
        let Some(dir) = entry
            .path()
            .parent()
            .and_then(|parent| parent.strip_prefix(root).ok())
        else {
            continue;
        };
        let posix = dir.to_string_lossy().replace('\\', "/");
        let src = if posix.is_empty() {
            "src".to_string()
        } else {
            format!("{posix}/src")
        };
        roots.insert(name.replace('-', "_"), src);
    }
    roots
}

/// Manifest directories (Cargo crates with a `[package]`, npm packages) —
/// the component roots `diagnose` aligns on so a crate's `build.rs` and its
/// `src/` land in one component. The repository root itself is excluded: a
/// root-level manifest would silently reshape every single-package repo's
/// components.
pub fn manifest_component_roots(root: &Path) -> Vec<String> {
    let mut roots: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for src in find_cargo_crate_roots(root).values() {
        if let Some(dir) = src.strip_suffix("/src")
            && !dir.is_empty()
        {
            roots.insert(dir.to_string());
        }
    }
    for (dir, _) in find_package_manifests(root) {
        let trimmed = dir.trim_end_matches('/');
        if !trimmed.is_empty() {
            roots.insert(trimmed.to_string());
        }
    }
    roots.into_iter().collect()
}

/// Locates every `package.json` in the tree (skipping the built-in excluded
/// dirs, so no `node_modules`), returning each one's repo-relative directory
/// (POSIX, trailing `/`, empty for root) and parsed contents. Shallow-bounded:
/// workspace manifests live near the top (`packages/*`, `apps/*`).
pub(crate) fn find_package_manifests(root: &Path) -> Vec<(String, serde_json::Value)> {
    let mut manifests = Vec::new();
    let mut builder = WalkBuilder::new(root);
    // Don't honour `.gitignore` here: a generated-but-ignored manifest still
    // declares the real public surface, and we already prune dependency/build
    // dirs via `is_excluded_component`. (The git-aware walker also skips some
    // tracked manifests on large trees.)
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .max_depth(Some(6));
    builder.filter_entry(|entry| {
        entry.depth() == 0
            || entry
                .file_name()
                .to_str()
                .map(|name| !is_excluded_component(name))
                .unwrap_or(true)
    });
    for entry in builder.build().flatten() {
        if entry.file_name() != "package.json" || !entry.path().is_file() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(manifest) =
            serde_json::from_str::<serde_json::Value>(content.trim_start_matches('\u{feff}'))
        else {
            continue;
        };
        let dir = entry
            .path()
            .parent()
            .and_then(|parent| parent.strip_prefix(root).ok())
            .map(|relative| {
                let posix = relative.to_string_lossy().replace('\\', "/");
                if posix.is_empty() {
                    posix
                } else {
                    format!("{posix}/")
                }
            })
            .unwrap_or_default();
        manifests.push((dir, manifest));
    }
    manifests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_cargo_crate_roots_in_a_workspace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("crates").join("my-core").join("src")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("crates").join("my-core").join("Cargo.toml"),
            "[package]\nname = \"my-core\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let roots = find_cargo_crate_roots(dir.path());
        // Hyphen normalizes to underscore; the virtual workspace root is skipped.
        assert_eq!(
            roots.get("my_core").map(String::as_str),
            Some("crates/my-core/src")
        );
        assert_eq!(roots.len(), 1);
    }
}
