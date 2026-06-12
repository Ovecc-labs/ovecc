use crate::config::{ProjectPaths, hash_bytes, relative_path, stable_id};
use crate::model::{DependencyRecord, FileRecord, IndexReport, ModuleRecord, SourceLanguage};
use crate::parser::extract_imports;
use crate::storage::ArchitectureStore;
use anyhow::{Context, Result};
use chrono::Utc;
use ignore::WalkBuilder;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const SOURCE_EXTENSIONS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];
const RESOLUTION_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

pub fn index_repository(paths: &ProjectPaths) -> Result<IndexReport> {
    paths.ensure_runtime_dirs()?;

    let repository_id = paths.repository_id();
    let mut store = ArchitectureStore::open(&paths.db_path)?;
    store.initialize_schema()?;

    let source_files = discover_source_files(&paths.root)?;
    let mut files = Vec::new();
    let mut modules = BTreeMap::<String, ModuleRecord>::new();
    let mut parsed_imports = HashMap::<String, Vec<crate::model::ImportFact>>::new();

    for source_file in &source_files {
        let bytes = std::fs::read(source_file)
            .with_context(|| format!("failed to read {}", source_file.display()))?;
        let source = String::from_utf8_lossy(&bytes);
        let relative = relative_path(&paths.root, source_file)?;
        let language =
            language_for_path(source_file).context("source file extension is unsupported")?;
        let module_name = infer_module_name(&relative);
        let module_id = stable_id("module", &[&repository_id, &module_name]);

        modules
            .entry(module_name.clone())
            .or_insert_with(|| ModuleRecord {
                id: module_id.clone(),
                repository_id: repository_id.clone(),
                name: module_name.clone(),
                path_prefix: infer_module_prefix(&relative),
            });

        let file = FileRecord {
            id: stable_id("file", &[&repository_id, &relative]),
            repository_id: repository_id.clone(),
            path: relative.clone(),
            absolute_path: source_file.clone(),
            language,
            content_hash: hash_bytes(&bytes),
            size_bytes: bytes.len() as u64,
            module_id,
            module_name,
        };

        let imports = extract_imports(&source, language)
            .with_context(|| format!("failed to parse imports in {relative}"))?;
        parsed_imports.insert(relative, imports);
        files.push(file);
    }

    let file_by_path: HashMap<String, FileRecord> = files
        .iter()
        .map(|file| (file.path.clone(), file.clone()))
        .collect();

    let dependencies = resolve_dependencies(
        paths,
        &repository_id,
        &files,
        &file_by_path,
        &parsed_imports,
    );
    let snapshot_id = stable_id(
        "snapshot",
        &[
            &repository_id,
            &Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .to_string(),
        ],
    );

    store.replace_current_index(
        &repository_id,
        &paths.root_display(),
        modules.values().cloned().collect::<Vec<_>>().as_slice(),
        &files,
        &dependencies,
        &snapshot_id,
    )?;

    Ok(IndexReport {
        repository_root: paths.root_display(),
        database_path: paths.db_path.to_string_lossy().to_string(),
        snapshot_id,
        files_scanned: source_files.len(),
        files_indexed: files.len(),
        modules: modules.len(),
        dependencies: dependencies.len(),
        external_dependencies: dependencies
            .iter()
            .filter(|dependency| dependency.is_external)
            .count(),
    })
}

fn discover_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true)
        .build();

    for entry in walker {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || should_skip_path(root, path) {
            continue;
        }
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if SOURCE_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()) {
            files.push(path.to_path_buf());
        }
    }

    files.sort();
    Ok(files)
}

fn should_skip_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return true;
    };
    relative.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        matches!(
            value.as_ref(),
            ".git"
                | ".ovecc"
                | "node_modules"
                | "target"
                | "dist"
                | "build"
                | "coverage"
                | ".next"
                | ".turbo"
                | "vendor"
        )
    })
}

fn language_for_path(path: &Path) -> Option<SourceLanguage> {
    let extension = path.extension()?.to_str()?;
    SourceLanguage::from_extension(extension)
}

fn infer_module_name(relative: &str) -> String {
    let parts = relative.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["src", module, ..] if !module.is_empty() => normalize_module_name(module),
        ["app", module, ..] if !module.is_empty() => normalize_module_name(module),
        ["packages", package, ..] if !package.is_empty() => normalize_module_name(package),
        ["apps", app, ..] if !app.is_empty() => normalize_module_name(app),
        ["services", service, ..] if !service.is_empty() => normalize_module_name(service),
        ["crates", crate_name, ..] if !crate_name.is_empty() => normalize_module_name(crate_name),
        [top, ..] if parts.len() > 1 && !top.is_empty() => normalize_module_name(top),
        _ => "root".to_string(),
    }
}

fn infer_module_prefix(relative: &str) -> String {
    let parts = relative.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["src", module, ..] => format!("src/{module}"),
        ["app", module, ..] => format!("app/{module}"),
        ["packages", package, ..] => format!("packages/{package}"),
        ["apps", app, ..] => format!("apps/{app}"),
        ["services", service, ..] => format!("services/{service}"),
        ["crates", crate_name, ..] => format!("crates/{crate_name}"),
        [top, ..] if parts.len() > 1 => (*top).to_string(),
        _ => ".".to_string(),
    }
}

fn normalize_module_name(raw: &str) -> String {
    raw.trim_matches(|character: char| {
        !character.is_alphanumeric() && character != '-' && character != '_'
    })
    .to_string()
}

fn resolve_dependencies(
    paths: &ProjectPaths,
    repository_id: &str,
    files: &[FileRecord],
    file_by_path: &HashMap<String, FileRecord>,
    parsed_imports: &HashMap<String, Vec<crate::model::ImportFact>>,
) -> Vec<DependencyRecord> {
    let mut dependencies = Vec::new();

    for file in files {
        let Some(imports) = parsed_imports.get(&file.path) else {
            continue;
        };

        for import in imports {
            let resolved = if is_relative_specifier(&import.specifier) {
                resolve_relative_import(&paths.root, &file.path, &import.specifier, file_by_path)
            } else {
                None
            };

            let (target_file_id, target_file_path, target_module_id, target_module, is_external) =
                if let Some(target_file) = resolved {
                    (
                        Some(target_file.id.clone()),
                        Some(target_file.path.clone()),
                        target_file.module_id.clone(),
                        target_file.module_name.clone(),
                        false,
                    )
                } else {
                    let external_name = external_module_name(&import.specifier);
                    (
                        None,
                        None,
                        stable_id("external", &[repository_id, &external_name]),
                        external_name,
                        true,
                    )
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

fn is_relative_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../")
}

fn resolve_relative_import(
    root: &Path,
    source_relative_path: &str,
    specifier: &str,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    let source_parent = Path::new(source_relative_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let base = root.join(source_parent).join(specifier);
    let mut candidates = Vec::new();
    candidates.push(base.clone());

    if base.extension().is_none() {
        for extension in RESOLUTION_EXTENSIONS {
            candidates.push(base.with_extension(extension));
        }
        for extension in RESOLUTION_EXTENSIONS {
            candidates.push(base.join(format!("index.{extension}")));
        }
    }

    candidates.into_iter().find_map(|candidate| {
        relative_path(root, &candidate)
            .ok()
            .and_then(|relative| file_by_path.get(&relative).cloned())
    })
}

fn external_module_name(specifier: &str) -> String {
    let parts = specifier.split('/').collect::<Vec<_>>();
    let package = if specifier.starts_with('@') && parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        parts.first().copied().unwrap_or(specifier).to_string()
    };
    format!("external:{package}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_modules_from_common_layouts() {
        assert_eq!(infer_module_name("src/billing/service.ts"), "billing");
        assert_eq!(infer_module_name("packages/api/index.ts"), "api");
        assert_eq!(infer_module_name("index.ts"), "root");
    }

    #[test]
    fn extracts_scoped_external_package_name() {
        assert_eq!(
            external_module_name("@scope/pkg/path"),
            "external:@scope/pkg"
        );
        assert_eq!(external_module_name("react/jsx-runtime"), "external:react");
    }
}
