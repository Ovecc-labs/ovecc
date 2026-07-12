//! Entry points anchoring dead-code reachability: package manifests, framework
//! conventions, Cargo targets, and test/standalone files.

use crate::manifests::{find_cargo_crate_roots, find_package_manifests};
use ovecc_core::legacy::FileRecord;
use std::collections::HashSet;
use std::path::Path;

/// Entry points anchoring dead-code reachability. The public surface a tool can
/// never see as "imported" is declared in package manifests and framework
/// conventions, so seeding it well is what separates real dead code from a tree
/// that merely looks unreferenced. We seed from:
///
/// - **every `package.json` in the tree** (monorepo-aware), resolving `main`,
///   `module`, `types`/`typings`, the `exports` map (the modern public API), and
///   `bin` to indexed source — each relative to its own package directory;
/// - **framework entry files** the runtime loads rather than `import`s (Next.js
///   `app`/`pages` routes, `middleware`);
/// - **Cargo crate roots** — every crate's `src/main.rs`, `src/bin/*.rs`,
///   `build.rs` (invoked by Cargo, nothing imports them) and `src/lib.rs`:
///   cross-crate `use` edges resolve *through* the crate root straight to the
///   module file, so nothing points at `lib.rs` itself, and a library's public
///   API may be consumed outside the workspace anyway — intra-crate liveness
///   is rustc's `dead_code` lint's job, not reachability's;
/// - the conventional root / `src` `index`/`main`, and all test/spec files.
///
/// Modelled on knip's resolver and fallow's entry-point detection. Biased toward
/// precision: an over-credited entry only costs a missed finding, while a missed
/// entry floods the report with false "unreachable file" hits.
pub(crate) fn detect_entry_points(root: &Path, files: &[FileRecord]) -> HashSet<String> {
    let mut entries = HashSet::new();
    let file_paths: HashSet<&str> = files.iter().map(|file| file.path.as_str()).collect();

    for (dir, manifest) in find_package_manifests(root) {
        for spec in manifest_entry_specs(&manifest) {
            if let Some(resolved) = resolve_entry_spec(&dir, &spec, &file_paths) {
                entries.insert(resolved);
            }
        }
    }
    for src in find_cargo_crate_roots(root).values() {
        for root_file in ["main.rs", "lib.rs"] {
            let candidate = format!("{src}/{root_file}");
            if file_paths.contains(candidate.as_str()) {
                entries.insert(candidate);
            }
        }
        // `src` always ends with "src", so this yields the crate directory
        // ("crates/tool/" or "" for a root crate).
        let crate_dir = src.strip_suffix("src").unwrap_or_default();
        let build = format!("{crate_dir}build.rs");
        if file_paths.contains(build.as_str()) {
            entries.insert(build);
        }
        let bin_prefix = format!("{src}/bin/");
        for file in files {
            if file.path.starts_with(&bin_prefix) && file.path.ends_with(".rs") {
                entries.insert(file.path.clone());
            }
        }
    }
    for file in files {
        if is_default_entry(&file.path)
            || is_test_file(&file.path)
            || is_framework_entry(&file.path)
            || is_standalone_entry(&file.path)
        {
            entries.insert(file.path.clone());
        }
    }
    entries
}

/// True for files under conventional standalone directories — examples,
/// templates, fixtures, demos, playgrounds — that ship as copyable or runnable
/// code and are intentionally not imported by a package's own entry points.
/// Treating them as entries keeps both them and what they import reachable.
pub(crate) fn is_standalone_entry(path: &str) -> bool {
    const DIRS: [&str; 12] = [
        "examples/",
        "example/",
        "templates/",
        "template/",
        "fixtures/",
        "__fixtures__/",
        "demo/",
        "demos/",
        "playground/",
        "benches/", // Rust benchmark targets (run, not imported)
        "benchmarks/",
        "bench/",
    ];
    DIRS.iter()
        .any(|dir| path.starts_with(dir) || path.contains(&format!("/{dir}")))
}

/// Collects the entry specs a manifest declares: `main`/`module`/`types`/
/// `typings`, every path leaf of the `exports` map, and `bin`.
fn manifest_entry_specs(manifest: &serde_json::Value) -> Vec<String> {
    let mut specs = Vec::new();
    for key in ["main", "module", "types", "typings"] {
        if let Some(spec) = manifest.get(key).and_then(|value| value.as_str()) {
            specs.push(spec.to_string());
        }
    }
    if let Some(exports) = manifest.get("exports") {
        collect_relative_paths(exports, &mut specs);
    }
    if let Some(bin) = manifest.get("bin") {
        collect_relative_paths(bin, &mut specs);
    }
    specs
}

/// Recursively gathers relative-path string leaves (`"./..."`) from an `exports`
/// or `bin` value, descending condition maps, subpath maps, and arrays.
fn collect_relative_paths(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(string) if string.starts_with('.') => out.push(string.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_relative_paths(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for nested in map.values() {
                collect_relative_paths(nested, out);
            }
        }
        _ => {}
    }
}

/// Resolves a manifest entry spec (e.g. `"./dist/index.js"`) declared in package
/// directory `dir` to an indexed source file, mapping common build-output dirs
/// (`dist`, `build`, `lib`, `es`, `esm`, `out`) back to `src` and trying source
/// extensions / an `index` file.
fn resolve_entry_spec(dir: &str, spec: &str, file_paths: &HashSet<&str>) -> Option<String> {
    let cleaned = format!("{dir}{}", spec.trim_start_matches("./"));
    let mut bases = vec![cleaned.clone()];
    for build_dir in ["dist/", "build/", "lib/", "es/", "esm/", "out/"] {
        if cleaned.contains(build_dir) {
            bases.push(cleaned.replacen(build_dir, "src/", 1));
        }
    }
    for base in bases {
        if file_paths.contains(base.as_str()) {
            return Some(base);
        }
        let stem = base
            .trim_end_matches(".js")
            .trim_end_matches(".mjs")
            .trim_end_matches(".cjs")
            .trim_end_matches(".d.ts");
        for ext in ["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] {
            for candidate in [format!("{stem}.{ext}"), format!("{stem}/index.{ext}")] {
                if file_paths.contains(candidate.as_str()) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// True for the conventional root / `src` entry files (`index.*` / `main.*`).
fn is_default_entry(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    if !(name.starts_with("index.") || name.starts_with("main.")) {
        return false;
    }
    let depth = path.matches('/').count();
    depth == 0 || (path.starts_with("src/") && depth == 1)
}

/// True for files a framework loads by convention rather than by `import`, which
/// would otherwise look unreachable. Covers the Next.js App Router
/// (`app/**/{page,layout,route,...}`), the Pages Router (`pages/**`), and
/// `middleware`. The `app`/`pages` segment may sit under a monorepo package
/// (`apps/web/app/...`).
fn is_framework_entry(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.split('.').next().unwrap_or(name);
    let is_route_segment = |segment: &str| {
        path.starts_with(&format!("{segment}/")) || path.contains(&format!("/{segment}/"))
    };
    if is_route_segment("app")
        && matches!(
            stem,
            "page"
                | "layout"
                | "route"
                | "loading"
                | "error"
                | "template"
                | "default"
                | "not-found"
                | "global-error"
                | "sitemap"
                | "robots"
                | "opengraph-image"
        )
    {
        return true;
    }
    if is_route_segment("pages") {
        return true;
    }
    matches!(name, "middleware.ts" | "middleware.js" | "middleware.tsx")
}

/// True for test/spec/mock files; their imports keep targets reachable. Covers
/// the `__tests__`/`__mocks__` layout, `.test`/`.spec` files, and the tsd
/// type-test conventions (`test-d/`, `type-tests/`, `*.test-d.ts`).
pub(crate) fn is_test_file(path: &str) -> bool {
    ovecc_core::util::is_test_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_manifest_entries_for_monorepo_and_exports_map() {
        let files: HashSet<&str> = [
            "packages/zod/src/index.ts",
            "packages/zod/src/v4/index.ts",
            "apps/cli/src/main.ts",
        ]
        .into_iter()
        .collect();
        // exports points at the build output; we map dist/ -> src/ and add ext.
        assert_eq!(
            resolve_entry_spec("packages/zod/", "./dist/index.js", &files).as_deref(),
            Some("packages/zod/src/index.ts")
        );
        // subpath export, same package.
        assert_eq!(
            resolve_entry_spec("packages/zod/", "./dist/v4/index.js", &files).as_deref(),
            Some("packages/zod/src/v4/index.ts")
        );
        // bin entry relative to its package dir.
        assert_eq!(
            resolve_entry_spec("apps/cli/", "./src/main.ts", &files).as_deref(),
            Some("apps/cli/src/main.ts")
        );
        // a spec that resolves to nothing indexed.
        assert!(resolve_entry_spec("packages/zod/", "./dist/missing.js", &files).is_none());
    }

    #[test]
    fn collects_entry_specs_from_exports_and_bin() {
        let manifest = serde_json::json!({
            "main": "./dist/index.js",
            "exports": {
                ".": { "import": "./dist/index.js", "types": "./dist/index.d.ts" },
                "./feature": "./dist/feature.js"
            },
            "bin": { "mycli": "./dist/cli.js" }
        });
        let specs = manifest_entry_specs(&manifest);
        assert!(specs.contains(&"./dist/index.js".to_string()));
        assert!(specs.contains(&"./dist/feature.js".to_string()));
        assert!(specs.contains(&"./dist/cli.js".to_string()));
        assert!(specs.contains(&"./dist/index.d.ts".to_string()));
    }

    #[test]
    fn recognizes_framework_entry_files() {
        assert!(is_framework_entry("app/dashboard/page.tsx"));
        assert!(is_framework_entry("apps/web/app/layout.tsx"));
        assert!(is_framework_entry("src/pages/about.tsx"));
        assert!(is_framework_entry("middleware.ts"));
        // a regular component under app/ that is not a route file is not an entry.
        assert!(!is_framework_entry("app/components/button.tsx"));
        assert!(!is_framework_entry("src/lib/helpers.ts"));
    }

    #[test]
    fn detects_monorepo_subpath_export_entries_from_disk() {
        use ovecc_core::legacy::SourceLanguage;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("packages/foo/src/sub")).unwrap();
        // exports map with a custom "source" condition pointing straight at src,
        // exactly like zod's `@zod/source`.
        std::fs::write(
            root.join("packages/foo/package.json"),
            r#"{ "name": "foo", "version": "1.0.0",
                "exports": {
                    ".": { "source": "./src/index.ts", "import": "./dist/index.js" },
                    "./sub": { "source": "./src/sub/index.ts", "import": "./dist/sub/index.js" }
                } }"#,
        )
        .unwrap();
        let file = |path: &str| FileRecord {
            id: String::new(),
            repository_id: String::new(),
            path: path.to_string(),
            absolute_path: root.join(path),
            language: SourceLanguage::TypeScript,
            content_hash: String::new(),
            size_bytes: 0,
            module_id: String::new(),
            module_name: String::new(),
        };
        let files = vec![
            file("packages/foo/src/index.ts"),
            file("packages/foo/src/sub/index.ts"),
        ];
        let entries = detect_entry_points(root, &files);
        assert!(
            entries.contains("packages/foo/src/index.ts"),
            "main subpath export must be an entry: {entries:?}"
        );
        assert!(
            entries.contains("packages/foo/src/sub/index.ts"),
            "./sub subpath export must be an entry: {entries:?}"
        );
    }

    #[test]
    fn cargo_binaries_and_build_scripts_are_entry_points() {
        use ovecc_core::legacy::SourceLanguage;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("crates/tool/src/bin")).unwrap();
        std::fs::write(
            root.join("crates/tool/Cargo.toml"),
            "[package]\nname = \"tool\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let file = |path: &str| FileRecord {
            id: String::new(),
            repository_id: String::new(),
            path: path.to_string(),
            absolute_path: root.join(path),
            language: SourceLanguage::Rust,
            content_hash: String::new(),
            size_bytes: 0,
            module_id: String::new(),
            module_name: String::new(),
        };
        let files = vec![
            file("crates/tool/src/main.rs"),
            file("crates/tool/src/bin/extra.rs"),
            file("crates/tool/build.rs"),
            file("crates/tool/src/lib.rs"),
        ];
        let entries = detect_entry_points(root, &files);
        assert!(
            entries.contains("crates/tool/src/main.rs"),
            "crate binary must be an entry: {entries:?}"
        );
        assert!(
            entries.contains("crates/tool/src/bin/extra.rs"),
            "bin target must be an entry: {entries:?}"
        );
        assert!(
            entries.contains("crates/tool/build.rs"),
            "build script must be an entry: {entries:?}"
        );
        // Library roots too: cross-crate imports resolve through them to the
        // module files, so nothing ever imports lib.rs itself.
        assert!(
            entries.contains("crates/tool/src/lib.rs"),
            "lib.rs must be an entry: {entries:?}"
        );
    }

    #[test]
    fn recognizes_typetest_and_standalone_entries() {
        // tsd type-tests are a test convention, not dead code.
        assert!(is_test_file("test-d/absolute.ts"));
        assert!(is_test_file("source/test-d/internal/foo.ts"));
        assert!(is_test_file("types/string.test-d.ts"));
        // standalone copyable/runnable code.
        assert!(is_standalone_entry("templates/start-app/index.ts"));
        assert!(is_standalone_entry("examples/with-script/utils.ts"));
        assert!(is_standalone_entry("packages/x/__fixtures__/sample.ts"));
        // ordinary source is neither.
        assert!(!is_test_file("src/index.ts"));
        assert!(!is_standalone_entry("src/lib/templates.ts"));
    }
}
