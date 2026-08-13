//! Source-file discovery: the ignore-aware walk, built-in exclusions,
//! generated-file detection, and module-name inference.

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use ovecc_core::config::{
    ArchitectureConfig, DEFAULT_MAX_FILE_SIZE_BYTES, ModuleMapping, ModuleStrategy, OveccConfig,
};
use ovecc_core::legacy::SourceLanguage;
use std::path::{Path, PathBuf};

const SOURCE_EXTENSIONS: &[&str] = &[
    // JavaScript/TypeScript family.
    "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", // Python, Rust, Go.
    "py", "pyi", "rs", "go",
    // C/C++ sources and headers (the C++ grammar covers C declarations).
    "cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "h", "c", "cu", "cuh",
];

pub(crate) fn discover_source_files(root: &Path, config: &OveccConfig) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true);

    // Prune vendored/build/cache directories at walk time so we never descend
    // into them (e.g. a Python `.venv` with thousands of files). The root entry
    // (depth 0) is always kept so running inside a dir named `build`/`dist`
    // still works; `should_skip_path` is the post-filter backstop.
    builder.filter_entry(|entry| {
        entry.depth() == 0
            || entry
                .file_name()
                .to_str()
                .map(|name| !is_excluded_component(name))
                .unwrap_or(true)
    });

    // Include/exclude globs, on top of the built-in exclusions.
    if !config.index.include.is_empty() || !config.index.exclude.is_empty() {
        let mut overrides = OverrideBuilder::new(root);
        for pattern in &config.index.include {
            overrides
                .add(pattern)
                .with_context(|| format!("invalid include pattern '{pattern}'"))?;
        }
        for pattern in &config.index.exclude {
            overrides
                .add(&format!("!{pattern}"))
                .with_context(|| format!("invalid exclude pattern '{pattern}'"))?;
        }
        builder.overrides(overrides.build().context("failed to compile index globs")?);
    }

    for entry in builder.build() {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || should_skip_path(root, path) {
            continue;
        }
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !SOURCE_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()) {
            continue;
        }
        let Some(language) = language_for_path(path) else {
            continue;
        };
        if !config.language_enabled(config_language(language)) {
            continue;
        }
        // Skip oversized files. An unset limit is not "no limit": a huge file
        // is a generated blob whose AST parse is a memory/latency risk, so an
        // unconfigured repo still gets the built-in cap.
        let limit = config
            .index
            .max_file_size_bytes
            .unwrap_or(DEFAULT_MAX_FILE_SIZE_BYTES);
        if let Ok(metadata) = entry.metadata()
            && metadata.len() > limit
        {
            continue;
        }
        // Skip generated / vendored files unless explicitly opted in.
        if !config.index.index_generated && looks_generated(path) {
            continue;
        }
        files.push(path.to_path_buf());
    }

    files.sort();
    Ok(files)
}

/// Maps the parser-level language to the `[languages]` config key:
/// `jsx` falls under `javascript`, `tsx` under `typescript`.
fn config_language(language: SourceLanguage) -> ovecc_core::lang::SourceLanguage {
    use ovecc_core::lang::SourceLanguage as Core;
    match language {
        SourceLanguage::JavaScript | SourceLanguage::Jsx => Core::JavaScript,
        SourceLanguage::TypeScript | SourceLanguage::Tsx => Core::TypeScript,
        SourceLanguage::Python => Core::Python,
        SourceLanguage::Rust => Core::Rust,
        SourceLanguage::Go => Core::Go,
        SourceLanguage::Cpp => Core::Cpp,
    }
}

/// Directory/component names excluded from indexing by default: VCS metadata,
/// dependency/vendor trees, virtualenvs, and build/cache output across the JS,
/// Python, Rust, Go, and JVM ecosystems. This is the built-in baseline; users
/// add more via `[index] exclude` / `--exclude`. Kept deliberately
/// language-agnostic so a new language inherits sane defaults.
pub fn is_excluded_component(name: &str) -> bool {
    matches!(
        name,
        // VCS + ovecc's own state
        ".git" | ".hg" | ".svn" | ".ovecc"
        // JavaScript / TypeScript
        | "node_modules" | "bower_components" | ".next" | ".nuxt" | ".svelte-kit"
        | ".turbo" | ".angular" | ".parcel-cache" | ".yarn" | ".pnpm-store"
        // Python
        | ".venv" | "venv" | "__pycache__" | ".tox" | ".nox" | ".mypy_cache"
        | ".pytest_cache" | ".ruff_cache" | ".eggs"
        // Rust / Go / JVM / general build, cache, vendor, and editor metadata
        | "target" | "vendor" | "dist" | "build" | "coverage" | ".gradle"
        | ".cache" | ".idea" | ".vscode"
    )
}

/// Heuristic detection of generated / vendored source we should not treat as
/// first-class code: minified bundles, WASM/emscripten glue, and files that
/// announce themselves as generated. These are the dominant false-positive
/// source in complexity, dead-code, and security on real repositories, and
/// parsing machine-emitted blobs is wasteful. Deliberately conservative: it
/// keys off unambiguous signals (names, head markers, minification), never file
/// size alone, and reads only the head so a marker deep in a real file or a
/// mid-file `@ts-nocheck` never triggers.
fn looks_generated(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
        let lower = name.to_ascii_lowercase();
        if lower.contains(".min.") || lower.contains("-wasm.") || lower.contains(".wasm.") {
            return true;
        }
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 8192];
    let read = std::io::Read::read(&mut std::io::BufReader::new(file), &mut head).unwrap_or(0);
    if read == 0 {
        return false;
    }
    let text = String::from_utf8_lossy(&head[..read]);
    // Minified: a single very long line in the head (bundlers, base64 blobs).
    if text.split('\n').any(|line| line.len() > 5000) {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    // Generated-file banners live at the very top (Go's convention is even
    // line-anchored; `@ts-nocheck` only works before the first statement).
    // Scanning deeper turns files that merely *document* these markers — a
    // codegen tool's config, this very detector — into silently skipped
    // "generated" files. 1 KiB comfortably covers real banners, even behind
    // a license header.
    let mut banner_end = lower.len().min(1024);
    while !lower.is_char_boundary(banner_end) {
        banner_end -= 1;
    }
    let banner = &lower[..banner_end];
    const MARKERS: [&str; 6] = [
        "@generated",
        "do not edit",
        "code generated",
        "auto-generated",
        "autogenerated",
        "automatically generated",
    ];
    if MARKERS.iter().any(|marker| banner.contains(marker)) {
        return true;
    }
    // Whole-file opt-out combo emscripten/codegen emit and that hand-maintained
    // code virtually never carries.
    banner.contains("@ts-nocheck") && banner.contains("eslint-disable")
}

fn should_skip_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return true;
    };
    relative
        .components()
        .any(|component| is_excluded_component(&component.as_os_str().to_string_lossy()))
}

pub(crate) fn language_for_path(path: &Path) -> Option<SourceLanguage> {
    let extension = path.extension()?.to_str()?;
    SourceLanguage::from_extension(extension)
}

/// Directories that *contain* modules but are not themselves one — the module is
/// what lives inside them. A leading container is skipped when naming a module so
/// `src/billing/...` is `billing`, not `src`.
const MODULE_CONTAINERS: &[&str] = &["src", "app", "packages", "apps", "services", "crates"];

/// The module depth this layout needs, when the default of 1 would collapse it.
///
/// Depth 1 names a module after the first directory below the repository root,
/// which is right for `src/billing/...` and wrong for `backend/` + `frontend/`:
/// there, every file lands in one of two modules, no module imports another,
/// and cycles, boundary violations and coupling density all read 0 for want of
/// edges. The signal for that layout is two or more top-level directories that
/// hold source and are not themselves module containers. Returns `None` when
/// depth 1 already separates the code.
pub fn suggest_module_depth(root: &Path) -> Option<usize> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return None;
    };
    let mut source_dirs = 0usize;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || is_excluded_component(&name) {
            continue;
        }
        if MODULE_CONTAINERS.contains(&name.as_str()) {
            // `src/`, `packages/` and friends are already stepped over when a
            // module is named, so depth 1 reaches the right level under them.
            return None;
        }
        if contains_source(&entry.path(), 3) {
            source_dirs += 1;
        }
    }
    (source_dirs >= 2).then_some(2)
}

/// Whether a directory holds any source file within `depth` levels. Bounded so
/// the check stays a handful of `read_dir` calls on a large repository.
fn contains_source(dir: &Path, depth: usize) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut subdirectories = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if is_excluded_component(&name) {
            continue;
        }
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => subdirectories.push(path),
            Ok(_) if language_for_path(&path).is_some() => return true,
            _ => {}
        }
    }
    depth > 1
        && subdirectories
            .iter()
            .any(|child| contains_source(child, depth - 1))
}

/// The explicit `[[architecture.modules]]` mapping that governs `relative`, when
/// the `configured`/`hybrid` strategy is active. The longest matching
/// `path_prefix` wins so the most specific rule applies; ties break on name for
/// determinism.
fn configured_module<'a>(
    relative: &str,
    architecture: &'a ArchitectureConfig,
) -> Option<&'a ModuleMapping> {
    if matches!(architecture.module_strategy, ModuleStrategy::Auto) {
        return None;
    }
    architecture
        .modules
        .iter()
        .filter(|mapping| {
            !mapping.path_prefix.is_empty() && relative.starts_with(mapping.path_prefix.as_str())
        })
        .max_by(|a, b| {
            a.path_prefix
                .len()
                .cmp(&b.path_prefix.len())
                .then_with(|| b.name.cmp(&a.name))
        })
}

/// The directory segments that name a module for `relative`, honoring the
/// configured depth. Empty for a file that sits directly at the repository root.
fn auto_module_segments(relative: &str, depth: usize) -> Vec<&str> {
    let parts: Vec<&str> = relative
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() < 2 {
        return Vec::new(); // a file at the repo root has no module directory
    }
    let dirs = &parts[..parts.len() - 1]; // drop the file name
    let start = usize::from(MODULE_CONTAINERS.contains(&dirs[0]) && dirs.len() > 1);
    let end = start.saturating_add(depth.max(1)).min(dirs.len());
    dirs[start..end].to_vec()
}

/// Infers a module name from a repo-relative path. Explicit config mappings win;
/// otherwise the first `architecture.module_depth` segments below any source
/// container name the module (e.g. depth 2 → `vs/editor`).
pub(crate) fn infer_module_name(relative: &str, architecture: &ArchitectureConfig) -> String {
    if let Some(mapping) = configured_module(relative, architecture) {
        return mapping.name.clone();
    }
    let segments = auto_module_segments(relative, architecture.module_depth);
    if segments.is_empty() {
        return "root".to_string();
    }
    segments
        .iter()
        .map(|segment| normalize_module_name(segment))
        .collect::<Vec<_>>()
        .join("/")
}

/// The path prefix that all files of a module share — the container plus the
/// module's own segments, so it stays consistent with [`infer_module_name`].
pub(crate) fn infer_module_prefix(relative: &str, architecture: &ArchitectureConfig) -> String {
    if let Some(mapping) = configured_module(relative, architecture) {
        return mapping.path_prefix.clone();
    }
    let parts: Vec<&str> = relative
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() < 2 {
        return ".".to_string();
    }
    let dirs = &parts[..parts.len() - 1];
    let start = usize::from(MODULE_CONTAINERS.contains(&dirs[0]) && dirs.len() > 1);
    let end = start
        .saturating_add(architecture.module_depth.max(1))
        .min(dirs.len());
    dirs[..end].join("/")
}

fn normalize_module_name(raw: &str) -> String {
    raw.trim_matches(|character: char| {
        !character.is_alphanumeric() && character != '-' && character != '_'
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_markers_only_count_in_the_file_banner() {
        let dir = tempfile::tempdir().unwrap();
        // A marker in the banner: generated.
        let generated = dir.path().join("gen.rs");
        std::fs::write(
            &generated,
            "// Code generated by protoc. DO NOT EDIT.\npub struct G;\n",
        )
        .unwrap();
        assert!(looks_generated(&generated));
        // The same words deep in the file merely *document* the convention
        // (found dogfooding: ovecc-core's config.rs documents the
        // skip-generated option and was silently dropped from the index).
        let documenting = dir.path().join("config.rs");
        let filler = "// filler line to push the mention past the banner window.\n".repeat(40);
        std::fs::write(
            &documenting,
            format!("{filler}/// skips `@generated` / `DO NOT EDIT` markers\npub struct C;\n"),
        )
        .unwrap();
        assert!(!looks_generated(&documenting));
    }

    #[test]
    fn an_oversized_file_is_skipped_even_without_a_configured_limit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small.ts"), "export const x = 1;\n").unwrap();
        // Just over the built-in cap, with no `max_file_size_bytes` set.
        let big = vec![b'/'; (DEFAULT_MAX_FILE_SIZE_BYTES + 1) as usize];
        std::fs::write(dir.path().join("huge.ts"), big).unwrap();

        let config = OveccConfig::default();
        assert!(config.index.max_file_size_bytes.is_none());
        let found = discover_source_files(dir.path(), &config).unwrap();
        let names: Vec<String> = found
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert!(names.contains(&"small.ts".to_string()), "{names:?}");
        assert!(
            !names.contains(&"huge.ts".to_string()),
            "the oversized file must be skipped by the built-in default: {names:?}"
        );
    }

    #[test]
    fn infers_modules_from_common_layouts() {
        // Default depth (1) preserves the historical behavior.
        let arch = ArchitectureConfig::default();
        assert_eq!(
            infer_module_name("src/billing/service.ts", &arch),
            "billing"
        );
        assert_eq!(infer_module_name("packages/api/index.ts", &arch), "api");
        assert_eq!(infer_module_name("index.ts", &arch), "root");
        // A top-level non-container directory names the module after itself.
        assert_eq!(infer_module_name("cli/src/util/command.rs", &arch), "cli");
        // Prefix stays consistent with the name.
        assert_eq!(
            infer_module_prefix("src/billing/service.ts", &arch),
            "src/billing"
        );
        assert_eq!(infer_module_prefix("index.ts", &arch), ".");
    }

    #[test]
    fn module_depth_recovers_boundaries_in_nested_monorepos() {
        // The VS Code case: everything lives under `src/vs`, so depth 1 collapses
        // the repo into one `vs` module. Depth 2 recovers real boundaries.
        let depth1 = ArchitectureConfig::default();
        let depth2 = ArchitectureConfig {
            module_depth: 2,
            ..Default::default()
        };
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &depth1), "vs");
        assert_eq!(
            infer_module_name("src/vs/editor/foo.ts", &depth2),
            "vs/editor"
        );
        assert_eq!(
            infer_module_name("src/vs/workbench/x/y.ts", &depth2),
            "vs/workbench"
        );
        assert_eq!(
            infer_module_prefix("src/vs/editor/foo.ts", &depth2),
            "src/vs/editor"
        );
        // Depth never consumes the file name: a file directly under the module dir
        // keeps the module, not the file, as the last segment.
        assert_eq!(infer_module_name("src/vs/editor.ts", &depth2), "vs");
        // A depth larger than the available directories is clamped, not padded.
        let depth9 = ArchitectureConfig {
            module_depth: 9,
            ..Default::default()
        };
        assert_eq!(
            infer_module_name("src/vs/editor/foo.ts", &depth9),
            "vs/editor"
        );
        // 0 is treated as 1.
        let depth0 = ArchitectureConfig {
            module_depth: 0,
            ..Default::default()
        };
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &depth0), "vs");
    }

    #[test]
    fn explicit_module_mapping_overrides_inference() {
        let arch = ArchitectureConfig {
            module_strategy: ModuleStrategy::Hybrid,
            modules: vec![
                ModuleMapping {
                    name: "Editor".to_string(),
                    path_prefix: "src/vs/editor".to_string(),
                    layer: None,
                    domain: None,
                },
                // A shorter, less specific prefix that must lose to the one above.
                ModuleMapping {
                    name: "Core".to_string(),
                    path_prefix: "src/vs".to_string(),
                    layer: None,
                    domain: None,
                },
            ],
            ..Default::default()
        };
        // Longest matching prefix wins.
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &arch), "Editor");
        assert_eq!(
            infer_module_prefix("src/vs/editor/foo.ts", &arch),
            "src/vs/editor"
        );
        // Covered by the shorter prefix only.
        assert_eq!(infer_module_name("src/vs/base/bar.ts", &arch), "Core");
        // Unmapped file falls back to depth inference.
        assert_eq!(infer_module_name("packages/api/x.ts", &arch), "api");
        // `auto` strategy ignores explicit mappings entirely.
        let auto = ArchitectureConfig {
            modules: arch.modules.clone(),
            ..Default::default()
        };
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &auto), "vs");
    }

    #[test]
    fn detects_generated_and_vendored_files() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        // Name-based: minified bundles and wasm glue.
        assert!(looks_generated(&write(
            "bundle.min.js",
            "export const x = 1;\n"
        )));
        assert!(looks_generated(&write(
            "woff2-wasm.ts",
            "export default 1;\n"
        )));
        // Head markers.
        assert!(looks_generated(&write(
            "client.ts",
            "// Code generated by protoc. DO NOT EDIT.\nexport const x = 1;\n"
        )));
        assert!(looks_generated(&write(
            "schema.ts",
            "/** @generated */\nexport type T = number;\n"
        )));
        // Minified content even without a telltale name.
        let long = format!("const data = \"{}\";\n", "A".repeat(6000));
        assert!(looks_generated(&write("blob.ts", &long)));
        // Whole-file opt-out combo (emscripten bindings).
        assert!(looks_generated(&write(
            "bindings.ts",
            "/* eslint-disable */\n// @ts-nocheck\nexport function f() {}\n"
        )));
        // Hand-written code is not flagged, including a lone `@ts-nocheck`.
        assert!(!looks_generated(&write(
            "service.ts",
            "export function getUser(id: string): string {\n  return id;\n}\n"
        )));
        assert!(!looks_generated(&write(
            "legacy.ts",
            "// @ts-nocheck\nexport const x = 1;\n"
        )));
    }
}
