//! Entry points anchoring dead-code reachability: package manifests, framework
//! conventions, Cargo targets, and test/standalone files.

use crate::manifests::{find_cargo_crate_roots, find_package_manifests};
use ignore::WalkBuilder;
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
/// - **files a command line runs** — `package.json` scripts and the `.github`
///   workflows and composite actions, where a script is named by path and
///   nothing ever imports it;
/// - **scripts an HTML page loads** — `<script src>`, which is how every
///   non-bundled page pulls in its JavaScript and leaves no import edge behind;
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

    collect_manifest_entries(root, &file_paths, &mut entries);
    collect_command_entries(root, &file_paths, &mut entries);
    collect_html_entries(root, &file_paths, &mut entries);
    collect_cargo_entries(root, files, &file_paths, &mut entries);
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

/// Entry files declared by package manifests (`package.json` main/bin/exports).
fn collect_manifest_entries(
    root: &Path,
    file_paths: &HashSet<&str>,
    entries: &mut HashSet<String>,
) {
    for (dir, manifest) in find_package_manifests(root) {
        for spec in manifest_entry_specs(&manifest) {
            if let Some(resolved) = resolve_entry_spec(&dir, &spec, file_paths) {
                entries.insert(resolved);
            }
        }
    }
}

/// Files a command line runs: `package.json` scripts, and the workflows and
/// composite actions under `.github`. `bun perf/scripts/check-size.ts` leaves no
/// import edge and no manifest entry, so reachability sees an orphan and `fix
/// --apply` deletes a file CI executes. A command names its script by path, so
/// the tokens that look like one are resolved against the index: exactly, then
/// by a `dir/file` suffix, since a step with a `working-directory` writes the
/// path relative to it. Requiring a directory component keeps a bare `index.ts`
/// in a command from crediting every `index.ts` in the tree.
fn collect_command_entries(root: &Path, file_paths: &HashSet<&str>, entries: &mut HashSet<String>) {
    let mut commands: Vec<String> = Vec::new();
    for (_, manifest) in find_package_manifests(root) {
        if let Some(scripts) = manifest
            .get("scripts")
            .and_then(serde_json::Value::as_object)
        {
            commands.extend(
                scripts
                    .values()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string),
            );
        }
    }
    for directory in [".github/workflows", ".github/actions"] {
        collect_yaml_text(&root.join(directory), &mut commands);
    }

    for command in &commands {
        for token in command.split(|c: char| c.is_whitespace() || "\"'`(),;:=".contains(c)) {
            let token = token.trim_start_matches("./");
            if token.len() < 3 || !has_source_extension(token) {
                continue;
            }
            if let Some(path) = file_paths.get(token) {
                entries.insert((*path).to_string());
                continue;
            }
            if let Some(&path) = file_paths
                .iter()
                .find(|path| path.ends_with(token) && token.contains('/'))
            {
                entries.insert(path.to_string());
            }
        }
    }
}

/// Scripts an HTML page loads. `<script type="module" src="/app.js">` is how a
/// page without a bundler pulls in its JavaScript: no import edge exists, so
/// reachability sees an orphan and `fix --delete-files` offers to delete a file
/// the page does not run without.
///
/// Only `<script src>` is read. A `<link href>` names a stylesheet or a
/// preload, and no stylesheet is in the graph to reach, so scanning for it would
/// add scope without adding an entry point.
///
/// The specifier is resolved against the page's *own* directory first, because
/// a `src` is a server path and the page's directory is what the server usually
/// roots: `viewer/index.html` loading `/app.js` means `viewer/app.js`.
fn collect_html_entries(root: &Path, file_paths: &HashSet<&str>, entries: &mut HashSet<String>) {
    for (dir, html) in find_html_pages(root) {
        for source in script_sources(&html) {
            // A remote script (`https:`, `//cdn`) is nothing this repository
            // holds, and a query or fragment is cache-busting, not the path.
            let spec = source
                .split(['?', '#'])
                .next()
                .unwrap_or_default()
                .trim_start_matches('/');
            // `//cdn/x.js` and `https://cdn/x.js` alike name a remote script.
            if spec.is_empty() || source.contains("//") {
                continue;
            }
            let anchored = collapse_relative(&format!("{dir}{spec}"));
            if let Some(resolved) = resolve_entry_spec("", &anchored, file_paths) {
                entries.insert(resolved);
            }
        }
    }
}

/// Every HTML page in the tree as `(its directory with a trailing slash, its
/// text)`. The walk mirrors source discovery — ignore-aware and pruning the
/// vendored directories — so a `node_modules` demo page cannot seed entries.
fn find_html_pages(root: &Path) -> Vec<(String, String)> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true);
    builder.filter_entry(|entry| {
        entry.depth() == 0
            || entry
                .file_name()
                .to_str()
                .map(|name| !crate::discover::is_excluded_component(name))
                .unwrap_or(true)
    });

    let mut pages = Vec::new();
    for entry in builder.build().flatten() {
        let path = entry.path();
        if !path.is_file()
            || !matches!(
                path.extension()
                    .and_then(|value| value.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("html") | Some("htm")
            )
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let dir = path
            .parent()
            .and_then(|parent| parent.strip_prefix(root).ok())
            .map(ovecc_core::util::normalize_path)
            .unwrap_or_default();
        pages.push((
            if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            },
            text,
        ));
    }
    // The walk yields in filesystem order; sorting keeps a repo with two pages
    // naming the same script from depending on it.
    pages.sort();
    pages
}

/// Collapses `.`/`..` segments in a repo-relative path, so a page loading
/// `../shared/app.js` still lands on an indexed file rather than silently
/// resolving to nothing — a missed entry point is the expensive direction here,
/// since it reads back as "unreachable file".
fn collapse_relative(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// The `src` of every `<script>` tag in `html`. A tolerant scan, not a parse:
/// the attribute is all that is wanted, and an HTML grammar would be a new
/// dependency and a new failure mode for a page that need not even be valid.
fn script_sources(html: &str) -> Vec<String> {
    // ASCII-lowercasing maps only ASCII bytes, so every offset below is still a
    // valid boundary in `html` itself even when the page holds UTF-8 text.
    let lower = html.to_ascii_lowercase();
    let mut sources = Vec::new();
    let mut cursor = 0usize;
    while let Some(offset) = lower[cursor..].find("<script") {
        let open = cursor + offset;
        let close = lower[open..]
            .find('>')
            .map_or(html.len(), |index| open + index);
        if let Some(source) = attribute_value(&html[open..close], "src") {
            sources.push(source);
        }
        cursor = close.max(open + 1);
    }
    sources
}

/// The value of attribute `name` in one tag's text, quoted or bare. `None` when
/// the tag does not carry it — a `<script>` with inline code, typically.
fn attribute_value(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(offset) = lower[cursor..].find(name) {
        let start = cursor + offset;
        cursor = start + name.len();
        // A whole attribute, not the tail of another one (`data-src`).
        if start == 0 || !lower.as_bytes()[start - 1].is_ascii_whitespace() {
            continue;
        }
        let Some(rest) = tag[cursor..].trim_start().strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(quote @ ('"' | '\'')) => rest[quote.len_utf8()..].split(quote).next(),
            // Bare values are legal HTML and end at the first whitespace.
            Some(_) => rest.split_whitespace().next(),
            None => None,
        };
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            return Some(value.to_string());
        }
    }
    None
}

/// Every YAML file under `directory`, read as raw text: a workflow's `run:`
/// blocks are what we are after, and parsing the schema to reach them would buy
/// nothing a token scan does not already give.
fn collect_yaml_text(directory: &Path, out: &mut Vec<String>) {
    let mut builder = WalkBuilder::new(directory);
    builder.hidden(false).git_ignore(false).max_depth(Some(4));
    for entry in builder.build().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml") | Some("yaml")
        ) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            out.push(text);
        }
    }
}

fn has_source_extension(token: &str) -> bool {
    matches!(
        token.rsplit_once('.').map(|(_, ext)| ext),
        Some(
            "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "mts" | "cts" | "py" | "rb" | "go" | "rs"
        )
    )
}

/// Cargo crate roots: `main.rs`/`lib.rs`, a `build.rs`, and every `src/bin/*.rs`.
fn collect_cargo_entries(
    root: &Path,
    files: &[FileRecord],
    file_paths: &HashSet<&str>,
    entries: &mut HashSet<String>,
) {
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

/// Recursively gathers the path string leaves of an `exports` or `bin` value,
/// descending condition maps, subpath maps, and arrays.
///
/// A leading `./` is not required: `exports` mandates one, `bin` does not, and
/// both spellings are common. Requiring it left the launcher of a published CLI
/// reading back as an unreachable file. Every leaf here is a path, and
/// `resolve_entry_spec` drops anything that names no indexed file.
fn collect_relative_paths(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(string) => out.push(string.clone()),
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

        // `bin` without a leading `./`, in both the map and shorthand forms.
        let bare = serde_json::json!({
            "main": "index.js",
            "bin": { "tool": "bin/tool.js" }
        });
        let specs = manifest_entry_specs(&bare);
        assert!(specs.contains(&"index.js".to_string()), "{specs:?}");
        assert!(specs.contains(&"bin/tool.js".to_string()), "{specs:?}");

        let shorthand = serde_json::json!({ "bin": "cli.js" });
        assert_eq!(manifest_entry_specs(&shorthand), ["cli.js"]);
    }

    #[test]
    fn reads_script_sources_out_of_a_page() {
        let html = r#"
<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="./styles.css">
    <script type="module" src="/app.js"></script>
    <script SRC='./legacy.js' defer></script>
    <script src=bare.js></script>
    <script data-src="./decoy.js"></script>
    <script>console.log("inline");</script>
    <script type="module" src="https://cdn.example.com/vendor.js"></script>
  </head>
  <body>é</body>
</html>
"#;
        assert_eq!(
            script_sources(html),
            vec![
                "/app.js".to_string(),
                "./legacy.js".to_string(),
                "bare.js".to_string(),
                "https://cdn.example.com/vendor.js".to_string(),
            ],
            "tag case, quote style, and bare values all count; \
             `data-src` and inline scripts do not"
        );
    }

    #[test]
    fn collapses_relative_page_paths() {
        assert_eq!(collapse_relative("viewer/app.js"), "viewer/app.js");
        assert_eq!(collapse_relative("viewer/./app.js"), "viewer/app.js");
        assert_eq!(
            collapse_relative("viewer/../shared/app.js"),
            "shared/app.js"
        );
        assert_eq!(collapse_relative("app.js"), "app.js");
    }

    #[test]
    fn html_script_tags_become_entry_points() {
        use ovecc_core::legacy::SourceLanguage;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("viewer")).unwrap();
        std::fs::create_dir_all(root.join("shared")).unwrap();
        // A `src` is a server path: the page's own directory is the server root,
        // so `/app.js` on `viewer/index.html` means `viewer/app.js`.
        std::fs::write(
            root.join("viewer/index.html"),
            "<script type=\"module\" src=\"/app.js\"></script>\n\
             <script src=\"../shared/util.js\"></script>\n\
             <script src=\"https://cdn.example.com/vendor.js\"></script>\n",
        )
        .unwrap();
        let file = |path: &str| FileRecord {
            id: String::new(),
            repository_id: String::new(),
            path: path.to_string(),
            absolute_path: root.join(path),
            language: SourceLanguage::JavaScript,
            content_hash: String::new(),
            size_bytes: 0,
            module_id: String::new(),
            module_name: String::new(),
        };
        let files = vec![
            file("viewer/app.js"),
            file("shared/util.js"),
            file("viewer/orphan.js"),
        ];
        let entries = detect_entry_points(root, &files);
        assert!(
            entries.contains("viewer/app.js"),
            "the page's script must be an entry: {entries:?}"
        );
        assert!(
            entries.contains("shared/util.js"),
            "a script above the page must resolve too: {entries:?}"
        );
        assert!(
            !entries.contains("viewer/orphan.js"),
            "no page loads it, so widening reachability must not credit it: {entries:?}"
        );
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
