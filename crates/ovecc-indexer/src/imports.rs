//! Import resolution: oxc_resolver for the JS/TS family (tsconfig aliases,
//! package `exports`, workspace packages), conservative suffix/dir matching
//! for Python, Rust, C++, and Go.

use crate::manifests::{find_cargo_crate_roots, find_package_manifests};
use ovecc_core::config::ProjectPaths;
use ovecc_core::legacy::{
    DependencyRecord, FileRecord, ImportFact, SourceLanguage, external_module_name,
    is_path_specifier, unindexed_module_name, unresolved_module_name,
};
use ovecc_core::util::stable_id;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

enum ImportTarget {
    Indexed(FileRecord),
    Unindexed,
    Unresolved,
}

pub(crate) fn resolve_dependencies(
    paths: &ProjectPaths,
    repository_id: &str,
    files: &[FileRecord],
    file_by_path: &HashMap<String, FileRecord>,
    parsed_imports: &HashMap<String, Vec<ImportFact>>,
) -> Vec<DependencyRecord> {
    let mut dependencies = Vec::new();

    // Path-suffix indexes let non-JS imports resolve to indexed files without
    // knowing source roots / manifests: a Python `user.account`, a Rust
    // `crate::billing::ledger`, or a C++ `"session.h"` becomes a candidate path
    // matched against every file's '/'-delimited tail. Resolution is
    // conservative — only a *unique* match links, otherwise the import is
    // external — which mirrors the precision-over-recall stance of call
    // resolution.
    let suffix_index = build_path_suffix_index(files);
    let dir_index = build_dir_suffix_index(files);
    // One shared oxc_resolver for the whole run (per-file tsconfig discovery is
    // internal); resolves relative, bare/package, and tsconfig-aliased JS/TS
    // imports — a strict superset of the old relative-only resolution.
    let js_resolver = create_js_resolver();
    // Cargo workspace map: `ovecc_core` -> `crates/ovecc-core/src`. Without it
    // every `use other_crate::…` in a Rust workspace reads as external and the
    // architecture graph of a Rust monorepo has no inter-crate edges at all.
    let cargo_crates = find_cargo_crate_roots(&paths.root);
    // npm workspace map: package name -> (dir, manifest). A freshly cloned
    // monorepo has no node_modules, so oxc cannot resolve `pkg-a` imports from
    // `pkg-b`; this map resolves them through the workspace manifests instead.
    let npm_workspace: HashMap<String, (String, serde_json::Value)> =
        find_package_manifests(&paths.root)
            .into_iter()
            .filter_map(|(dir, manifest)| {
                let name = manifest.get("name").and_then(|value| value.as_str())?;
                Some((
                    name.to_string(),
                    (dir.trim_end_matches('/').to_string(), manifest),
                ))
            })
            .collect();

    for file in files {
        let Some(imports) = parsed_imports.get(&file.path) else {
            continue;
        };

        for import in imports {
            let resolved = match file.language {
                SourceLanguage::JavaScript
                | SourceLanguage::Jsx
                | SourceLanguage::TypeScript
                | SourceLanguage::Tsx => {
                    let primary = resolve_js_ts_import(
                        &js_resolver,
                        &paths.root,
                        file,
                        &import.specifier,
                        file_by_path,
                    );
                    if matches!(primary, ImportTarget::Indexed(_)) {
                        primary
                    } else {
                        resolve_workspace_package_import(
                            &js_resolver,
                            &paths.root,
                            &npm_workspace,
                            &import.specifier,
                            file_by_path,
                        )
                        .map_or(primary, ImportTarget::Indexed)
                    }
                }
                SourceLanguage::Python => resolve_suffix_unique(
                    &python_import_candidates(&file.path, &import.specifier),
                    &suffix_index,
                    file_by_path,
                )
                .map_or(ImportTarget::Unresolved, ImportTarget::Indexed),
                SourceLanguage::Rust => {
                    resolve_rust_workspace_import(&cargo_crates, &import.specifier, file_by_path)
                        .or_else(|| {
                            resolve_most_specific(
                                &rust_import_candidates(&file.path, &import.specifier),
                                &suffix_index,
                                file_by_path,
                            )
                        })
                        .map_or(ImportTarget::Unresolved, ImportTarget::Indexed)
                }
                SourceLanguage::Cpp => resolve_suffix_unique(
                    &cpp_import_candidates(&file.path, &import.specifier),
                    &suffix_index,
                    file_by_path,
                )
                .map_or(ImportTarget::Unresolved, ImportTarget::Indexed),
                SourceLanguage::Go => resolve_go_package(
                    &go_import_candidates(&import.specifier),
                    &dir_index,
                    file_by_path,
                )
                .map_or(ImportTarget::Unresolved, ImportTarget::Indexed),
            };

            let (target_file_id, target_file_path, target_module_id, target_module, is_external) =
                match resolved {
                    ImportTarget::Indexed(target_file) => (
                        Some(target_file.id.clone()),
                        Some(target_file.path.clone()),
                        target_file.module_id.clone(),
                        target_file.module_name.clone(),
                        false,
                    ),
                    other => {
                        let name = unresolved_target_name(&import.specifier, &other);
                        (
                            None,
                            None,
                            stable_id("external", &[repository_id, &name]),
                            name,
                            true,
                        )
                    }
                };

            dependencies.push(DependencyRecord {
                id: stable_id(
                    "dependency",
                    &[
                        repository_id,
                        &file.path,
                        &import.specifier,
                        &target_module,
                        &import.line.to_string(),
                        // The kind participates in the identity so a change in
                        // resolution semantics (e.g. static -> type_import)
                        // refreshes the persisted row via differential sync
                        // even when the source file itself is unchanged.
                        import.import_kind.as_str(),
                    ],
                ),
                repository_id: repository_id.to_string(),
                source_file_id: file.id.clone(),
                target_file_id,
                source_file_path: file.path.clone(),
                target_file_path,
                source_module_id: file.module_id.clone(),
                target_module_id,
                source_module: file.module_name.clone(),
                target_module,
                specifier: import.specifier.clone(),
                dependency_kind: import.import_kind.as_str().to_string(),
                is_external,
                evidence_line: import.line,
            });
        }
    }

    dependencies.sort_by(|left, right| {
        left.source_file_path
            .cmp(&right.source_file_path)
            .then_with(|| left.evidence_line.cmp(&right.evidence_line))
            .then_with(|| left.specifier.cmp(&right.specifier))
    });
    dependencies
}

// --- oxc_resolver-backed JS/TS resolution ------------------------------------
//
// Portions adapted from fallow (crates/graph/src/resolve/specifier.rs),
// MIT (c) 2026 Bart Waardenburg. See THIRD-PARTY-NOTICES.md.
// SPDX-License-Identifier: MIT
//
// Real tsconfig paths/baseUrl, package `exports`, and extension/index fallbacks
// for the JS/TS family. Non-JS languages keep the suffix/dir resolvers. oxc is
// confined to this resolution seam — no oxc type crosses into the fact model.

/// JS/TS extensions to probe, TS family first so a `.ts` shadowing a built `.js`
/// wins (fallow `specifier.rs:34`). The declaration extensions trail their
/// implementation counterparts: `./x` prefers `x.ts` over `x.d.ts`, but a
/// specifier backed only by a declaration file still resolves instead of
/// reading as a broken import.
fn js_resolver_extensions() -> Vec<String> {
    [
        ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json", ".d.ts", ".d.mts",
        ".d.cts",
    ]
    .iter()
    .map(|extension| (*extension).to_string())
    .collect()
}

/// Package `exports`/`imports` condition names, highest priority first
/// (fallow `react_native.rs` baseline, minus the RN conditions).
fn js_resolver_conditions() -> Vec<String> {
    [
        "development",
        "import",
        "require",
        "default",
        "types",
        "node",
    ]
    .iter()
    .map(|condition| (*condition).to_string())
    .collect()
}

/// Builds one shared resolver for the whole index run; per-file tsconfig
/// discovery is internal (fallow `specifier.rs:33-60`).
fn create_js_resolver() -> oxc_resolver::Resolver {
    let mut options = oxc_resolver::ResolveOptions {
        extensions: js_resolver_extensions(),
        // `import './x.js'` resolves to `x.ts`/`x.tsx` (fallow `specifier.rs:36-51`).
        extension_alias: vec![
            (
                ".js".to_string(),
                vec![".ts".into(), ".tsx".into(), ".js".into()],
            ),
            (".jsx".to_string(), vec![".tsx".into(), ".jsx".into()]),
            (".mjs".to_string(), vec![".mts".into(), ".mjs".into()]),
            (".cjs".to_string(), vec![".cts".into(), ".cjs".into()]),
        ],
        condition_names: js_resolver_conditions(),
        main_fields: vec!["module".into(), "main".into()],
        ..Default::default()
    };
    options.tsconfig = Some(oxc_resolver::TsconfigDiscovery::Auto);
    oxc_resolver::Resolver::new(options)
}

/// True for errors raised while *loading a tsconfig* (vs. the specifier itself),
/// so a broken sibling tsconfig doesn't poison plain relative/bare resolution
/// (fallow `specifier.rs:74-83`).
fn is_tsconfig_error(error: &oxc_resolver::ResolveError) -> bool {
    use oxc_resolver::ResolveError;
    matches!(
        error,
        ResolveError::TsconfigNotFound(_)
            | ResolveError::TsconfigCircularExtend(_)
            | ResolveError::TsconfigSelfReference(_)
            | ResolveError::Json(_)
            | ResolveError::IOError(_)
    )
}

/// Resolves one JS/TS import specifier — relative, bare/package, OR
/// tsconfig-aliased — distinguishing three outcomes: an indexed
/// [`FileRecord`], a real file the index does not hold (`node_modules`, an
/// asset, a declaration file), or nothing at all. Only the third is a broken
/// import; the second is a genuine dependency ovecc simply does not model.
/// Strictly widens resolution over the old relative-only path (fallow
/// `specifier.rs:99-135`).
fn resolve_js_ts_import(
    resolver: &oxc_resolver::Resolver,
    root: &Path,
    file: &FileRecord,
    specifier: &str,
    file_by_path: &HashMap<String, FileRecord>,
) -> ImportTarget {
    // oxc_resolver wants a plain absolute path; strip the Windows verbatim
    // prefix that `std::fs::canonicalize` adds (oxc uses dunce-style paths),
    // or every resolve fails and falls through to external.
    let from_file = strip_verbatim_prefix(file.absolute_path.as_path());
    let resolved_abs = match resolver.resolve_file(&from_file, specifier) {
        Ok(resolution) => resolution.path().to_path_buf(),
        // A broken tsconfig: retry dir-based so relative/bare still resolve.
        Err(error) if is_tsconfig_error(&error) => {
            let dir = from_file.parent().unwrap_or(&from_file);
            match resolver.resolve(dir, specifier) {
                Ok(resolution) => resolution.path().to_path_buf(),
                Err(_) => return ImportTarget::Unresolved,
            }
        }
        Err(_) => return ImportTarget::Unresolved,
    };
    // Map the absolute resolution back to a repo-relative '/'-path and into the
    // indexed set; outside root or a miss (node_modules) is still a real file.
    let Some(relative) = repo_relative_path(root, &resolved_abs) else {
        return ImportTarget::Unindexed;
    };
    match file_by_path.get(&relative) {
        Some(target) => ImportTarget::Indexed(target.clone()),
        None => ImportTarget::Unindexed,
    }
}

/// Resolves a bare import naming a *workspace package* (`pkg-a`, `zod/v4`)
/// through the workspace manifests — the fallback when oxc found no
/// node_modules (a freshly cloned monorepo). Entry candidates come from the
/// package's own contract (`exports`, `module`, `main`, `types`), then the
/// `src/index` convention; each resolves via oxc from the package directory so
/// extension and index probing behave exactly like the primary path.
fn resolve_workspace_package_import(
    resolver: &oxc_resolver::Resolver,
    root: &Path,
    workspace: &HashMap<String, (String, serde_json::Value)>,
    specifier: &str,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    if specifier.starts_with('.') || specifier.starts_with('/') {
        return None;
    }
    let (name, subpath) = split_package_specifier(specifier)?;
    let (dir, manifest) = workspace.get(name)?;
    let package_dir = if dir.is_empty() {
        root.to_path_buf()
    } else {
        root.join(dir)
    };
    let package_dir = strip_verbatim_prefix(&package_dir);

    let mut candidates: Vec<String> = Vec::new();
    if subpath.is_empty() {
        if let Some(target) = exports_target(manifest, ".") {
            candidates.push(target);
        }
        for key in ["module", "main", "types"] {
            if let Some(entry) = manifest.get(key).and_then(|value| value.as_str()) {
                candidates.push(entry.to_string());
            }
        }
        candidates.push("./src/index".to_string());
        candidates.push("./index".to_string());
    } else {
        if let Some(target) = exports_target(manifest, &format!("./{subpath}")) {
            candidates.push(target);
        }
        candidates.push(format!("./{subpath}"));
        candidates.push(format!("./src/{subpath}"));
    }

    for candidate in candidates {
        let spec = if candidate.starts_with("./") || candidate.starts_with("../") {
            candidate
        } else {
            format!("./{candidate}")
        };
        if let Ok(resolution) = resolver.resolve(&package_dir, &spec)
            && let Some(relative) = repo_relative_path(root, resolution.path())
            && let Some(file) = file_by_path.get(&relative)
        {
            return Some(file.clone());
        }
    }
    None
}

/// Splits `@scope/pkg/sub/path` / `pkg/sub` into (package name, subpath).
fn split_package_specifier(specifier: &str) -> Option<(&str, &str)> {
    let mut slashes = specifier.match_indices('/');
    let name_end = if specifier.starts_with('@') {
        slashes.next()?; // scope separator
        slashes.next().map(|(i, _)| i)
    } else {
        slashes.next().map(|(i, _)| i)
    };
    match name_end {
        Some(end) => Some((&specifier[..end], &specifier[end + 1..])),
        None => Some((specifier, "")),
    }
}

/// Walks a manifest `exports` map to the concrete target for `key` (exact
/// match, then a `./*` wildcard), unwrapping condition objects through the
/// usual priorities. Returns a relative path string when one exists.
fn exports_target(manifest: &serde_json::Value, key: &str) -> Option<String> {
    fn unwrap_conditions(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::String(target) => Some(target.clone()),
            serde_json::Value::Object(map) => {
                for condition in ["import", "default", "node", "require", "types"] {
                    if let Some(inner) = map.get(condition)
                        && let Some(target) = unwrap_conditions(inner)
                    {
                        return Some(target);
                    }
                }
                None
            }
            _ => None,
        }
    }

    let exports = manifest.get("exports")?;
    // A bare-string `exports` is the "." target.
    if let serde_json::Value::String(target) = exports {
        return (key == ".").then(|| target.clone());
    }
    if let Some(value) = exports.get(key) {
        return unwrap_conditions(value);
    }
    // Single-star wildcard: `"./*": "./src/*.ts"` with key `./v4` -> `./src/v4.ts`.
    if let Some(stripped) = key.strip_prefix("./")
        && let Some(pattern_value) = exports.get("./*")
        && let Some(target) = unwrap_conditions(pattern_value)
    {
        return Some(target.replace('*', stripped));
    }
    None
}

/// Strips the Windows `\\?\` / `\\?\UNC\` verbatim prefix from an absolute path
/// (oxc_resolver does not understand verbatim paths).
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

/// Repo-relative '/'-normalized path of `abs` under `root`, compared on
/// normalized string forms (verbatim-prefix-stripped, forward slashes,
/// case-insensitive drive letter) so `canonicalize`'s `\\?\C:\…` and
/// oxc_resolver's plain `C:\…` still match. `None` when `abs` is outside `root`.
fn repo_relative_path(root: &Path, abs: &Path) -> Option<String> {
    let root_norm = ovecc_core::util::normalize_path(root);
    let abs_norm = ovecc_core::util::normalize_path(abs);
    if abs_norm.len() < root_norm.len()
        || !abs_norm[..root_norm.len()].eq_ignore_ascii_case(&root_norm)
    {
        return None;
    }
    Some(
        abs_norm[root_norm.len()..]
            .trim_start_matches('/')
            .to_string(),
    )
}

// --- non-JS import resolution -------------------------------------

/// Maps every '/'-delimited tail of each indexed file path back to that file,
/// so a language-specific import candidate resolves without knowing source
/// roots. `src/user/account.py` indexes `account.py`, `user/account.py`, and
/// `src/user/account.py`.
fn build_path_suffix_index(files: &[FileRecord]) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    for file in files {
        let segments: Vec<&str> = file.path.split('/').collect();
        for start in 0..segments.len() {
            index
                .entry(segments[start..].join("/"))
                .or_default()
                .push(file.path.clone());
        }
    }
    index
}

/// Like [`build_path_suffix_index`] but over each file's *directory*, for Go
/// where an import names a package (directory), not a file.
fn build_dir_suffix_index(files: &[FileRecord]) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    for file in files {
        let Some((dir, _)) = file.path.rsplit_once('/') else {
            continue;
        };
        let segments: Vec<&str> = dir.split('/').collect();
        for start in 0..segments.len() {
            index
                .entry(segments[start..].join("/"))
                .or_default()
                .push(file.path.clone());
        }
    }
    index
}

/// Resolves the first candidate that matches exactly one indexed file. If two
/// candidates match different files, or any candidate is itself ambiguous, the
/// import is left unresolved (external).
fn resolve_suffix_unique(
    candidates: &[String],
    suffix_index: &HashMap<String, Vec<String>>,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    let mut chosen: Option<String> = None;
    for candidate in candidates {
        let Some(paths) = suffix_index.get(candidate) else {
            continue;
        };
        let distinct: std::collections::BTreeSet<&String> = paths.iter().collect();
        if distinct.len() != 1 {
            return None; // ambiguous candidate
        }
        let path = paths[0].clone();
        match &chosen {
            Some(existing) if *existing != path => return None, // conflicting candidates
            _ => chosen = Some(path),
        }
    }
    chosen.and_then(|path| file_by_path.get(&path).cloned())
}

/// Resolves the first candidate that matches exactly one indexed file, for a
/// list already ordered from most to least specific.
///
/// Rust's fallback candidate is the parent module's own file, which usually
/// exists too, so [`resolve_suffix_unique`]'s all-must-agree rule discarded the
/// specific match along with it. C++ keeps that stricter rule: its two
/// candidates are different files an include path chooses between.
fn resolve_most_specific(
    candidates: &[String],
    suffix_index: &HashMap<String, Vec<String>>,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    for candidate in candidates {
        let Some(paths) = suffix_index.get(candidate) else {
            continue;
        };
        let distinct: std::collections::BTreeSet<&String> = paths.iter().collect();
        if distinct.len() != 1 {
            return None; // ambiguous at the most specific level that matched
        }
        return file_by_path.get(&paths[0]).cloned();
    }
    None
}

/// Resolves a Go import (a package directory) to a representative file in that
/// package, when the candidate matches files in exactly one directory.
fn resolve_go_package(
    candidates: &[String],
    dir_index: &HashMap<String, Vec<String>>,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    for candidate in candidates {
        let Some(paths) = dir_index.get(candidate) else {
            continue;
        };
        // A Go package is made of `.go` files; ignore co-located other-language
        // files so the package directory is identified unambiguously.
        let go_files: Vec<&String> = paths.iter().filter(|p| p.ends_with(".go")).collect();
        let dirs: std::collections::BTreeSet<&str> = go_files
            .iter()
            .filter_map(|path| path.rsplit_once('/').map(|(dir, _)| dir))
            .collect();
        if dirs.len() == 1 {
            // Deterministic representative: the lexicographically-first file.
            let representative = go_files.iter().min().map(|p| (*p).clone())?;
            return file_by_path.get(&representative).cloned();
        }
    }
    None
}

/// `pkg.mod` / `from . import x` -> candidate module file paths.
fn python_import_candidates(source_path: &str, specifier: &str) -> Vec<String> {
    let dots = specifier.chars().take_while(|c| *c == '.').count();
    let rest = &specifier[dots..];
    let segments: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split('.').filter(|s| !s.is_empty()).collect()
    };
    let base = if dots > 0 {
        // A leading dot means "this package"; each extra dot ascends one level.
        let dir = ascend(rel_parent(source_path), dots.saturating_sub(1));
        if segments.is_empty() {
            dir.to_string()
        } else {
            join_rel(dir, &segments.join("/"))
        }
    } else {
        segments.join("/")
    };
    let base = normalize_rel(&base);
    if base.is_empty() {
        return if dots > 0 {
            vec!["__init__.py".to_string()]
        } else {
            Vec::new()
        };
    }
    if segments.is_empty() {
        // Pure-package relative import (`from . import x`).
        vec![format!("{base}/__init__.py")]
    } else {
        vec![
            format!("{base}.py"),
            format!("{base}/__init__.py"),
            format!("{base}.pyi"),
        ]
    }
}

/// `crate::a::b` / `super::x` / `a::{b, c}` -> candidate module file paths.
fn rust_import_candidates(source_path: &str, specifier: &str) -> Vec<String> {
    // Drop a glob or group tail: `a::{b, c}` / `a::*` resolve at module `a`.
    let head = specifier.split(['{', '*']).next().unwrap_or(specifier);
    let mut segments: Vec<&str> = head
        .split("::")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let mut up = 0usize;
    let mut relative = false;
    let mut anchored = false;
    while let Some(&first) = segments.first() {
        match first {
            "crate" => {
                anchored = true;
                segments.remove(0); // crate root; suffix match finds it
                break;
            }
            "self" => {
                anchored = true;
                relative = true;
                segments.remove(0);
            }
            "super" => {
                anchored = true;
                relative = true;
                up += 1;
                segments.remove(0);
            }
            _ => break,
        }
    }
    // A bare path (`tracing::info`, `std::fs`) names an external crate in Rust
    // 2018+; only crate/self/super reach a local module. Workspace crates are
    // already resolved by name in `resolve_rust_workspace_import`, so a bare
    // path that falls through to here is external. Producing suffix candidates
    // for it would let an external crate name collide with a local file's tail
    // (a `tracing.rs` module) and resolve to a false internal edge — the source
    // of the phantom cycles seen on Rust monorepos.
    if !anchored || segments.is_empty() {
        return Vec::new();
    }
    let base_dir = if relative {
        ascend(rel_parent(source_path), up).to_string()
    } else {
        String::new()
    };
    let mut candidates = Vec::new();
    // The last segment may name a module (`mod ledger`) or an item inside its
    // parent module (`struct Ledger`), so try keeping and dropping it.
    for drop in [0usize, 1] {
        if segments.len() > drop {
            let joined = segments[..segments.len() - drop].join("/");
            let prefix = normalize_rel(&join_rel(&base_dir, &joined));
            if !prefix.is_empty() {
                candidates.push(format!("{prefix}.rs"));
                candidates.push(format!("{prefix}/mod.rs"));
            }
        }
    }
    candidates
}

/// Resolves `use other_crate::a::b` through the Cargo workspace map, trying the
/// most specific file first and walking up: `<src>/a/b.rs`, `<src>/a/b/mod.rs`,
/// then with the trailing segment dropped (an item, or a module nested inline
/// in its parent file), down to the crate root `lib.rs`/`main.rs`. Exact-path
/// lookups — no suffix ambiguity by construction. `None` when the first
/// segment names no workspace crate (external) so the caller can fall back.
fn resolve_rust_workspace_import(
    crate_roots: &HashMap<String, String>,
    specifier: &str,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    // Drop a glob or group tail: `a::{b, c}` / `a::*` resolve at module `a`.
    let head = specifier.split(['{', '*']).next().unwrap_or(specifier);
    let segments: Vec<&str> = head
        .split("::")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let src = crate_roots.get(*segments.first()?)?;
    let rest = &segments[1..];
    for drop in 0..=rest.len() {
        let kept = &rest[..rest.len() - drop];
        if kept.is_empty() {
            // The import lands on the crate root's public surface.
            for entry in ["lib.rs", "main.rs"] {
                if let Some(file) = file_by_path.get(&format!("{src}/{entry}")) {
                    return Some(file.clone());
                }
            }
        } else {
            let joined = kept.join("/");
            for candidate in [
                format!("{src}/{joined}.rs"),
                format!("{src}/{joined}/mod.rs"),
            ] {
                if let Some(file) = file_by_path.get(&candidate) {
                    return Some(file.clone());
                }
            }
        }
    }
    None
}

/// `#include "session.h"` / `<vector>` -> candidate file paths (system headers
/// simply never match an indexed file, so they stay external).
fn cpp_import_candidates(source_path: &str, specifier: &str) -> Vec<String> {
    let specifier = specifier.trim();
    if specifier.is_empty() {
        return Vec::new();
    }
    let mut candidates = vec![normalize_rel(specifier)];
    let dir = rel_parent(source_path);
    if !dir.is_empty() {
        candidates.push(normalize_rel(&join_rel(dir, specifier)));
    }
    candidates
}

/// A Go import path names a package directory; only module-qualified imports
/// (those with a `/`) can be local, so bare stdlib names stay external. Tails
/// are tried longest-first for precision.
fn go_import_candidates(specifier: &str) -> Vec<String> {
    if !specifier.contains('/') {
        return Vec::new();
    }
    let segments: Vec<&str> = specifier.split('/').filter(|s| !s.is_empty()).collect();
    (0..segments.len())
        .map(|start| segments[start..].join("/"))
        .collect()
}

/// The directory part of a repo-relative path (`""` for a top-level file).
fn rel_parent(path: &str) -> &str {
    path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("")
}

/// Ascends `n` directory levels.
fn ascend(mut dir: &str, n: usize) -> &str {
    for _ in 0..n {
        dir = rel_parent(dir);
    }
    dir
}

fn join_rel(dir: &str, tail: &str) -> String {
    if dir.is_empty() {
        tail.to_string()
    } else {
        format!("{dir}/{tail}")
    }
}

/// Collapses `.`/`..` segments and leading slashes in a repo-relative path.
fn normalize_rel(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out.join("/")
}

fn unresolved_target_name(specifier: &str, target: &ImportTarget) -> String {
    if !is_path_specifier(specifier) {
        return external_module_name(specifier);
    }
    match target {
        ImportTarget::Unindexed => unindexed_module_name(specifier),
        _ => unresolved_module_name(specifier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_language_specific_import_candidates() {
        assert_eq!(
            python_import_candidates("src/billing/invoice.py", "user.account"),
            vec![
                "user/account.py".to_string(),
                "user/account/__init__.py".to_string(),
                "user/account.pyi".to_string(),
            ]
        );
        // `from . import x` targets the current package's __init__.
        assert_eq!(
            python_import_candidates("src/billing/invoice.py", "."),
            vec!["src/billing/__init__.py".to_string()]
        );

        let rust = rust_import_candidates("src/main.rs", "crate::billing::ledger");
        assert!(rust.contains(&"billing/ledger.rs".to_string()), "{rust:?}");
        assert!(
            rust.contains(&"billing/ledger/mod.rs".to_string()),
            "{rust:?}"
        );
        // `super::` resolves relative to the source module's directory.
        let sup = rust_import_candidates("src/billing/mod.rs", "super::user");
        assert!(sup.contains(&"src/user.rs".to_string()), "{sup:?}");
        // A glob import resolves at the module, not the glob.
        let glob = rust_import_candidates("src/main.rs", "crate::user::*");
        assert!(glob.contains(&"user.rs".to_string()), "{glob:?}");

        // A bare path names an external crate (Rust 2018+), never a local file:
        // no candidates, so it can never suffix-match a homonymous local module.
        assert!(
            rust_import_candidates("src/main.rs", "tracing::info").is_empty(),
            "bare external crate must yield no local candidates"
        );
        assert!(rust_import_candidates("src/main.rs", "std::fs").is_empty());
        assert!(rust_import_candidates("src/main.rs", "serde::Deserialize").is_empty());

        assert!(
            cpp_import_candidates("src/user/session.cpp", "session.h")
                .contains(&"src/user/session.h".to_string())
        );

        assert_eq!(
            go_import_candidates("github.com/org/app/user"),
            vec![
                "github.com/org/app/user".to_string(),
                "org/app/user".to_string(),
                "app/user".to_string(),
                "user".to_string(),
            ]
        );
        // Bare stdlib imports are never local.
        assert!(go_import_candidates("fmt").is_empty());
    }

    #[test]
    fn resolves_internal_imports_by_unique_suffix() {
        let file = |path: &str, language: SourceLanguage| FileRecord {
            id: format!("f:{path}"),
            repository_id: "r".to_string(),
            path: path.to_string(),
            absolute_path: PathBuf::from(path),
            language,
            content_hash: "h".to_string(),
            size_bytes: 0,
            module_id: "m".to_string(),
            module_name: "m".to_string(),
        };
        let files = vec![
            file("src/billing/invoice.py", SourceLanguage::Python),
            file("src/user/account.py", SourceLanguage::Python),
            file("src/user/service.go", SourceLanguage::Go),
            file("src/user/model.go", SourceLanguage::Go),
        ];
        let by_path: HashMap<String, FileRecord> =
            files.iter().map(|f| (f.path.clone(), f.clone())).collect();
        let suffix = build_path_suffix_index(&files);
        let dirs = build_dir_suffix_index(&files);

        // Python: `user.account` -> the unique account.py.
        let resolved = resolve_suffix_unique(
            &python_import_candidates("src/billing/invoice.py", "user.account"),
            &suffix,
            &by_path,
        );
        assert_eq!(
            resolved.map(|f| f.path),
            Some("src/user/account.py".to_string())
        );

        // Go: a `.../user` import resolves to that single package directory.
        let pkg = resolve_go_package(&go_import_candidates("app/user"), &dirs, &by_path);
        assert!(
            pkg.as_ref()
                .map(|f| f.path.starts_with("src/user/"))
                .unwrap_or(false),
            "{pkg:?}"
        );

        // A non-existent module stays external.
        assert!(
            resolve_suffix_unique(
                &python_import_candidates("src/billing/invoice.py", "missing.mod"),
                &suffix,
                &by_path,
            )
            .is_none()
        );
    }

    #[test]
    fn extracts_scoped_external_package_name() {
        assert_eq!(
            external_module_name("@scope/pkg/path"),
            "external:@scope/pkg"
        );
        assert_eq!(external_module_name("react/jsx-runtime"), "external:react");
    }

    #[test]
    fn a_path_specifier_never_becomes_an_external_package() {
        let name =
            |specifier: &str, target: ImportTarget| unresolved_target_name(specifier, &target);

        assert_eq!(
            name("./missing", ImportTarget::Unresolved),
            "unresolved:./missing"
        );
        assert_eq!(
            name("../nowhere/deleted.ts", ImportTarget::Unresolved),
            "unresolved:../nowhere/deleted.ts"
        );
        assert_ne!(
            name("./missing", ImportTarget::Unresolved),
            name("./other", ImportTarget::Unresolved)
        );
        assert_eq!(
            name("./theme.css", ImportTarget::Unindexed),
            "unindexed:./theme.css"
        );
        assert_eq!(
            name("lodash/fp", ImportTarget::Unresolved),
            "external:lodash"
        );
        assert_eq!(name("lodash", ImportTarget::Unindexed), "external:lodash");
    }

    #[test]
    fn resolves_workspace_crate_imports_through_cargo_map() {
        let file = |path: &str| FileRecord {
            id: format!("f:{path}"),
            repository_id: "r".to_string(),
            path: path.to_string(),
            absolute_path: PathBuf::from(path),
            language: SourceLanguage::Rust,
            content_hash: "h".to_string(),
            size_bytes: 0,
            module_id: "m".to_string(),
            module_name: "m".to_string(),
        };
        let files = [
            file("crates/ovecc-core/src/lib.rs"),
            file("crates/ovecc-core/src/facts.rs"),
            file("crates/ovecc-core/src/id/mod.rs"),
            file("crates/ovecc-cli/src/main.rs"),
        ];
        let by_path: HashMap<String, FileRecord> =
            files.iter().map(|f| (f.path.clone(), f.clone())).collect();
        let mut crates = HashMap::new();
        crates.insert(
            "ovecc_core".to_string(),
            "crates/ovecc-core/src".to_string(),
        );
        crates.insert("ovecc_cli".to_string(), "crates/ovecc-cli/src".to_string());

        let path_of = |specifier: &str| {
            resolve_rust_workspace_import(&crates, specifier, &by_path).map(|f| f.path)
        };
        // Module file, most specific match.
        assert_eq!(
            path_of("ovecc_core::facts::FixSpec"),
            Some("crates/ovecc-core/src/facts.rs".to_string())
        );
        // `mod.rs` layout.
        assert_eq!(
            path_of("ovecc_core::id::FindingId"),
            Some("crates/ovecc-core/src/id/mod.rs".to_string())
        );
        // Group import resolves at the named module.
        assert_eq!(
            path_of("ovecc_core::facts::{FindingKind, Severity}"),
            Some("crates/ovecc-core/src/facts.rs".to_string())
        );
        // Item at the crate root lands on lib.rs; bin crates fall back to main.rs.
        assert_eq!(
            path_of("ovecc_core::OveccError"),
            Some("crates/ovecc-core/src/lib.rs".to_string())
        );
        assert_eq!(
            path_of("ovecc_cli::run"),
            Some("crates/ovecc-cli/src/main.rs".to_string())
        );
        // Unknown crates stay external for the caller's fallback.
        assert_eq!(path_of("serde::Deserialize"), None);
    }

    #[test]
    fn a_mod_declared_below_the_crate_root_reaches_its_child_file() {
        let file = |path: &str| FileRecord {
            id: format!("f:{path}"),
            repository_id: "r".to_string(),
            path: path.to_string(),
            absolute_path: PathBuf::from(path),
            language: SourceLanguage::Rust,
            content_hash: "h".to_string(),
            size_bytes: 0,
            module_id: "m".to_string(),
            module_name: "m".to_string(),
        };
        let files = [
            file("src/lib.rs"),
            file("src/tests.rs"),
            file("src/foo.rs"),
            file("src/foo/tests.rs"),
        ];
        let by_path: HashMap<String, FileRecord> =
            files.iter().map(|f| (f.path.clone(), f.clone())).collect();
        let suffixes = build_path_suffix_index(&files);
        let path_of = |source: &str, specifier: &str| {
            resolve_most_specific(
                &rust_import_candidates(source, specifier),
                &suffixes,
                &by_path,
            )
            .map(|f| f.path)
        };

        // `foo.rs` is also a candidate here, and it exists: the specific match
        // has to win rather than cancel it out.
        assert_eq!(
            path_of("src/foo.rs", "self::foo::tests"),
            Some("src/foo/tests.rs".to_string())
        );
        assert_eq!(
            path_of("src/lib.rs", "self::tests"),
            Some("src/tests.rs".to_string())
        );
        // An item imported from a sibling module still lands on that module.
        assert_eq!(
            path_of("src/lib.rs", "self::foo::helper"),
            Some("src/foo.rs".to_string())
        );
    }

    #[test]
    fn a_bare_external_crate_does_not_resolve_to_a_homonymous_local_file() {
        // The Turborepo regression: a crate ships a local `tracing.rs` module,
        // and other files `use tracing::…` the external crate. Neither the
        // workspace map (tracing is not a workspace crate) nor the suffix
        // fallback (bare paths yield no candidates now) may link them, or the
        // graph grows a phantom edge and, closing back, a phantom cycle.
        let file = |path: &str| FileRecord {
            id: format!("f:{path}"),
            repository_id: "r".to_string(),
            path: path.to_string(),
            absolute_path: PathBuf::from(path),
            language: SourceLanguage::Rust,
            content_hash: "h".to_string(),
            size_bytes: 0,
            module_id: "m".to_string(),
            module_name: "m".to_string(),
        };
        let files = [
            file("crates/telemetry/src/tracing.rs"),
            file("crates/telemetry/src/lib.rs"),
        ];
        let by_path: HashMap<String, FileRecord> =
            files.iter().map(|f| (f.path.clone(), f.clone())).collect();
        let suffix = build_path_suffix_index(&files);
        // No workspace crate named `tracing`.
        let crates: HashMap<String, String> = HashMap::new();

        let workspace =
            resolve_rust_workspace_import(&crates, "tracing::info", &by_path).map(|f| f.path);
        assert_eq!(workspace, None, "tracing is not a workspace crate");

        let fallback = resolve_suffix_unique(
            &rust_import_candidates("crates/telemetry/src/lib.rs", "tracing::info"),
            &suffix,
            &by_path,
        )
        .map(|f| f.path);
        assert_eq!(
            fallback, None,
            "the external use must not resolve to the local tracing.rs"
        );

        // A genuine local import still resolves.
        let local = resolve_suffix_unique(
            &rust_import_candidates("crates/telemetry/src/lib.rs", "crate::tracing"),
            &suffix,
            &by_path,
        )
        .map(|f| f.path);
        assert_eq!(local, Some("crates/telemetry/src/tracing.rs".to_string()));
    }

    #[test]
    fn splits_package_specifiers_and_walks_exports() {
        assert_eq!(split_package_specifier("zod"), Some(("zod", "")));
        assert_eq!(split_package_specifier("zod/v4"), Some(("zod", "v4")));
        assert_eq!(
            split_package_specifier("@scope/pkg/sub/deep"),
            Some(("@scope/pkg", "sub/deep"))
        );

        let manifest: serde_json::Value = serde_json::json!({
            "exports": {
                ".": { "import": "./src/index.ts" },
                "./v4": { "types": "./src/v4/index.d.ts", "import": "./src/v4/index.ts" },
                "./*": "./src/*.ts"
            }
        });
        assert_eq!(
            exports_target(&manifest, ".").as_deref(),
            Some("./src/index.ts")
        );
        assert_eq!(
            exports_target(&manifest, "./v4").as_deref(),
            Some("./src/v4/index.ts")
        );
        // Wildcard fallback for keys without an exact entry.
        assert_eq!(
            exports_target(&manifest, "./locales").as_deref(),
            Some("./src/locales.ts")
        );
    }
}
