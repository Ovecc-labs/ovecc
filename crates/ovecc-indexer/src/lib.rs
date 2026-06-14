//! Indexing pipeline orchestration, carried over from
//! the MVP. Incremental indexing, parse caching, parallel parsing, and the
//! full fact extraction land in the next roadmap steps.
//!
//! This crate owns the metric computation (via `ovecc-graph`) and the
//! temporary `git rev-parse` shell-out (replaced by `ovecc-git`/gitoxide in
//! the Git roadmap step), so `ovecc-db` stays free of sibling dependencies.

pub mod resolve;

use anyhow::{Context, Result};
use chrono::Utc;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use ovecc_core::config::{OveccConfig, ProjectPaths};
use ovecc_core::facts::{
    ChangeKind, CommitRecord, FileChangeRecord, FileFacts, FindingKind, ImportFactKind,
    ParseFailure, SourceFile,
};
use ovecc_core::id::{CommitId, FileChangeId, RepositoryId};
use ovecc_core::legacy::{
    DependencyRecord, FileRecord, ImportFact, ImportKind, IndexFailure, IndexReport, ModuleRecord,
    SourceLanguage,
};
use ovecc_core::traits::LanguageAdapter;
use ovecc_core::util::{hash_bytes, relative_path, stable_id};
use ovecc_db::{ArchitectureStore, ResolvedCode};
use ovecc_parser::{GenericAdapter, TypeScriptAdapter};
use rayon::prelude::*;
use resolve::{ImportBinding, ResolveUnit};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const SOURCE_EXTENSIONS: &[&str] = &[
    // JavaScript/TypeScript family.
    "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", // Python, Rust, Go.
    "py", "pyi", "rs", "go",
    // C/C++ sources and headers (the C++ grammar covers C declarations).
    "cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "h", "c", "cu", "cuh",
];
const RESOLUTION_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

/// `(variable, type)` bindings; older entries
/// miss and re-parse.
const PARSE_CACHE_VERSION: &str = "v8";

pub fn index_repository(
    paths: &ProjectPaths,
    config: &OveccConfig,
    skip_git: bool,
) -> Result<IndexReport> {
    // Phase instrumentation: measured unconditionally (negligible cost),
    // surfaced by `--stats`. Each `phase` records elapsed time since the last.
    let run_start = std::time::Instant::now();
    let mut timings = ovecc_core::report::IndexTimings::default();
    let mut phase_start = run_start;
    let mut phase = |slot: &mut u64| {
        let now = std::time::Instant::now();
        *slot += now.duration_since(phase_start).as_millis() as u64;
        phase_start = now;
    };

    paths.ensure_runtime_dirs()?;

    let repository_id = paths.repository_id().0;
    let mut store = ArchitectureStore::open(&paths.db_path)?;
    store.initialize_schema()?;
    // Loaded before the sync for retention: a file that fails to parse
    // keeps the dependencies recorded by its last successful run.
    let previous_dependencies = store.current_dependencies(&repository_id)?;

    let source_files = discover_source_files(&paths.root, config)?;
    let cache = ParseCache::new(paths.parse_cache_dir.join(PARSE_CACHE_VERSION));
    cache.ensure_dir()?;
    phase(&mut timings.discovery_ms);

    // Hashing and parsing are per-file and independent — parallelize.
    // Results keep the discovery order, so output stays deterministic.
    let processed: Vec<ProcessedFile> = source_files
        .par_iter()
        .map(|source_file| process_file(paths, &repository_id, &cache, source_file))
        .collect();
    phase(&mut timings.parse_ms);

    let mut files = Vec::new();
    let mut modules = BTreeMap::<String, ModuleRecord>::new();
    let mut parsed_imports = HashMap::<String, Vec<ImportFact>>::new();
    let mut file_facts = HashMap::<String, FileFacts>::new();
    let mut parse_failures = Vec::new();
    let mut files_parsed = 0_usize;
    let mut files_from_cache = 0_usize;

    for outcome in processed {
        let parse_failed = outcome.failure.is_some() && outcome.file.is_some();
        if let Some(failure) = outcome.failure {
            parse_failures.push(failure);
        }
        let Some(file) = outcome.file else {
            // Unreadable file: reported above, treated as absent.
            continue;
        };
        if outcome.parsed {
            files_parsed += 1;
        }
        if outcome.from_cache {
            files_from_cache += 1;
        }

        modules
            .entry(file.module_name.clone())
            .or_insert_with(|| ModuleRecord {
                id: file.module_id.clone(),
                repository_id: repository_id.clone(),
                name: file.module_name.clone(),
                path_prefix: infer_module_prefix(&file.path),
            });

        let imports = if parse_failed {
            // Do not pretend the file suddenly has zero dependencies.
            retained_imports(&previous_dependencies, &file.path)
        } else {
            outcome.imports
        };
        parsed_imports.insert(file.path.clone(), imports);
        // On parse failure `facts` is empty; code-level retention across a
        // failed re-parse is a later refinement (the module graph is retained
        // via `parsed_imports` above).
        file_facts.insert(file.path.clone(), outcome.facts);
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

    // Code-fact resolution: build per-file import bindings, then resolve
    // grammar-level facts into typed records with a linked call graph.
    let bindings_by_path: HashMap<String, Vec<ImportBinding>> = files
        .iter()
        .map(|file| {
            let bindings = file_facts
                .get(&file.path)
                .map(|facts| build_import_bindings(paths, file, facts, &file_by_path))
                .unwrap_or_default();
            (file.path.clone(), bindings)
        })
        .collect();
    let units: Vec<ResolveUnit<'_>> = files
        .iter()
        .filter_map(|file| {
            let facts = file_facts.get(&file.path)?;
            let bindings = bindings_by_path
                .get(&file.path)
                .map(|b| b.as_slice())
                .unwrap_or(&[]);
            Some(ResolveUnit {
                file_id: file.id.as_str(),
                repository_id: repository_id.as_str(),
                path: file.path.as_str(),
                module_id: file.module_id.as_str(),
                language: core_language(file.language),
                facts,
                import_bindings: bindings,
            })
        })
        .collect();
    let resolved = resolve::resolve_facts(&units);
    phase(&mut timings.resolve_ms);
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

    let module_records: Vec<ModuleRecord> = modules.values().cloned().collect();
    let mut metrics = compute_snapshot_metrics(&module_records, &files, &dependencies);
    // Surface parser failures and code-fact counts in the metrics.
    metrics.push(("parse_failures".to_string(), parse_failures.len() as f64));
    metrics.push(("symbols".to_string(), resolved.symbols.len() as f64));
    metrics.push(("calls".to_string(), resolved.calls.len() as f64));
    metrics.push(("apis".to_string(), resolved.apis.len() as f64));
    metrics.push(("tables".to_string(), resolved.schema_objects.len() as f64));
    // Native Git ingestion (replaces the `git rev-parse` shell-out): pull
    // recent commits + changed files, persist them, and derive ownership.
    let (commit_sha, commits_ingested) = if skip_git {
        (None, 0)
    } else {
        let (head_sha, ingested, ownership) = ingest_git(&mut store, &repository_id, &paths.root)?;
        // A file at risk has low majority ownership and several
        // minor contributors. Surface the count plus the worst churn.
        let fragmented = ownership
            .iter()
            .filter(|o| o.ownership < 0.5 && o.minor_contributors >= 3)
            .count();
        let max_churn = ownership.iter().map(|o| o.total_commits).max().unwrap_or(0);
        metrics.push(("ownership_fragmented_files".to_string(), fragmented as f64));
        metrics.push(("max_file_churn".to_string(), max_churn as f64));
        (head_sha, ingested)
    };
    metrics.push(("commits_ingested".to_string(), commits_ingested as f64));

    // Rule evaluation: turn the architecture into findings (boundary
    // violations, cycles), persisted for `summary`/`violations` to read.
    let module_names: Vec<String> = module_records
        .iter()
        .map(|module| module.name.clone())
        .collect();
    // Flatten the per-file security patterns the parser detected.
    let security_patterns: Vec<(String, ovecc_core::facts::SecurityPatternFact)> = file_facts
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .security_patterns
                .iter()
                .map(move |pattern| (path.clone(), pattern.clone()))
        })
        .collect();
    let mut findings = ovecc_rules::evaluate(&ovecc_rules::RuleInput {
        repository_id: &repository_id,
        snapshot_id: Some(&snapshot_id),
        modules: &module_names,
        dependencies: &dependencies,
        config: &config.rules,
        security_patterns: &security_patterns,
    });
    // Source→sink taint reachability over the code graph (SQL + eval/exec).
    let (flow_nodes, flow_edges) = build_flow_graph(&resolved);
    let dangerous_sinks: Vec<(String, String)> = resolved
        .dangerous_sinks
        .iter()
        .map(|sink| (sink.symbol_id.clone(), sink.label.clone()))
        .collect();
    findings.extend(ovecc_dataflow::analyze(
        &repository_id,
        Some(&snapshot_id),
        &flow_nodes,
        &flow_edges,
        &dangerous_sinks,
        ovecc_dataflow::DEFAULT_FLOW_DEPTH,
    ));

    // Offline OSV dependency audit: inventory packages from lockfiles,
    // persist them, and match against the local OSV database (.ovecc/osv/).
    let packages = ovecc_audit::discover_packages(&paths.root);
    let package_rows: Vec<ovecc_db::PackageRow> = packages
        .iter()
        .map(|package| ovecc_db::PackageRow {
            ecosystem: package.ecosystem.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            manifest_path: package.manifest_path.clone(),
            is_direct: package.is_direct,
        })
        .collect();
    store.replace_packages(&repository_id, &package_rows)?;
    let osv = ovecc_audit::load_osv_dir(&paths.ovecc_dir.join("osv"));
    findings.extend(ovecc_audit::audit(
        &repository_id,
        Some(&snapshot_id),
        &packages,
        &osv,
    ));

    // Drop findings explicitly suppressed by an inline `// ovecc-ignore`.
    let suppressions: HashMap<String, std::collections::HashSet<u32>> = file_facts
        .iter()
        .filter(|(_, facts)| !facts.suppressed_lines.is_empty())
        .map(|(path, facts)| {
            (
                path.clone(),
                facts.suppressed_lines.iter().copied().collect(),
            )
        })
        .collect();
    if !suppressions.is_empty() {
        findings.retain(|finding| {
            !finding.evidence.iter().any(|evidence| {
                evidence.line.is_some_and(|line| {
                    suppressions
                        .get(&evidence.file_path)
                        .is_some_and(|lines| lines.contains(&line))
                })
            })
        });
    }

    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    // A stable finding ID encodes the finding's identity (rule + target +
    // location), so two findings with the same ID are the same finding — e.g.
    // two same-kind security patterns on one line. Collapse them so the unique
    // `findings.id` primary key never collides on write.
    findings.dedup_by(|a, b| a.id.0 == b.id.0);
    let boundary_violations = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::CrossDomainDependency
                    | FindingKind::ForbiddenImport
                    | FindingKind::LayerViolation
            )
        })
        .count();
    let security_findings = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::HardcodedSecret
                    | FindingKind::InsecurePattern
                    | FindingKind::WeakCrypto
                    | FindingKind::PermissiveCors
                    | FindingKind::VulnerableDependency
                    | FindingKind::TaintedFlow
            )
        })
        .count();
    metrics.push((
        "boundary_violations".to_string(),
        boundary_violations as f64,
    ));
    metrics.push(("security_findings".to_string(), security_findings as f64));

    let external_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.is_external)
        .count();

    let schema_edges: Vec<ovecc_db::SchemaEdge> = resolved
        .schema_accesses
        .iter()
        .map(|access| ovecc_db::SchemaEdge {
            source_id: access.accessor_symbol_id.clone(),
            target_id: access.table_id.clone(),
            kind: access.kind.to_string(),
            evidence_json: format!(
                r#"{{"file":"{}","line":{}}}"#,
                access.evidence.file_path,
                access.evidence.line.unwrap_or(0)
            ),
        })
        .collect();
    let code = ResolvedCode {
        symbols: &resolved.symbols,
        calls: &resolved.calls,
        apis: &resolved.apis,
        schema_objects: &resolved.schema_objects,
        schema_edges: &schema_edges,
    };
    phase(&mut timings.analyze_ms);
    store.sync_current_index(
        &repository_id,
        &paths.root_display(),
        &module_records,
        &files,
        &dependencies,
        &snapshot_id,
        commit_sha.as_deref(),
        &metrics,
        &code,
    )?;
    store.replace_findings(&repository_id, &findings)?;
    phase(&mut timings.persist_ms);
    timings.total_ms = run_start.elapsed().as_millis() as u64;

    Ok(IndexReport {
        repository_root: paths.root_display(),
        database_path: paths.db_path.to_string_lossy().to_string(),
        snapshot_id,
        files_scanned: source_files.len(),
        files_indexed: files.len(),
        files_parsed,
        files_from_cache,
        modules: modules.len(),
        dependencies: dependencies.len(),
        external_dependencies,
        symbols: resolved.symbols.len(),
        calls: resolved.calls.len(),
        apis: resolved.apis.len(),
        tables: resolved.schema_objects.len(),
        commits_ingested,
        parse_failures,
        timings,
    })
}

/// Recent-history window and cap for Git ingestion: current ownership
/// does not need a decade of history). Configurable via `[analysis]` later.
const GIT_WINDOW_DAYS: u32 = 365;
const GIT_MAX_COMMITS: usize = 5000;

/// Pulls recent Git history, persists commits + file changes, and returns the
/// HEAD sha, the number of newly ingested commits, and per-file ownership.
fn ingest_git(
    store: &mut ArchitectureStore,
    repository_id: &str,
    root: &Path,
) -> Result<(Option<String>, usize, Vec<ovecc_db::FileOwnership>)> {
    let history = ovecc_git::collect_history(root, GIT_WINDOW_DAYS, GIT_MAX_COMMITS)?;
    let mut commits = Vec::new();
    let mut changes = Vec::new();
    for commit in &history.commits {
        let commit_id = CommitId::from_parts(&[repository_id, &commit.sha]);
        commits.push(CommitRecord {
            id: commit_id.clone(),
            repository_id: RepositoryId::from_raw(repository_id),
            sha: commit.sha.clone(),
            parent_shas: commit.parent_shas.clone(),
            author_name: commit.author_name.clone(),
            author_email: commit.author_email.clone(),
            committed_at: chrono::DateTime::from_timestamp(commit.committed_at, 0)
                .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).expect("epoch")),
            message: commit.message.clone(),
        });
        for change in &commit.changes {
            changes.push(FileChangeRecord {
                id: FileChangeId::from_parts(&[repository_id, &commit.sha, &change.path]),
                repository_id: RepositoryId::from_raw(repository_id),
                commit_id: commit_id.clone(),
                file_path: change.path.clone(),
                kind: map_change_kind(change.kind),
                additions: None,
                deletions: None,
            });
        }
    }
    let ingested = store.upsert_git_facts(repository_id, &commits, &changes)?;
    let ownership = store.ownership_metrics(repository_id)?;
    Ok((history.head_sha, ingested, ownership))
}

/// Builds the in-memory graph views (symbol/api/table nodes + handles/calls/
/// reads/writes edges) the taint analysis traverses, from the resolved facts.
fn build_flow_graph(
    resolved: &resolve::ResolvedFacts,
) -> (
    Vec<ovecc_graph::blast::BlastNode>,
    Vec<ovecc_graph::blast::BlastEdge>,
) {
    use ovecc_graph::blast::{BlastEdge, BlastNode};

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for symbol in &resolved.symbols {
        nodes.push(BlastNode {
            id: symbol.id.0.clone(),
            kind: "symbol".to_string(),
            label: symbol.qualified_name.clone(),
        });
    }
    for api in &resolved.apis {
        let label = format!(
            "{} {}",
            api.method.clone().unwrap_or_default(),
            api.path
                .clone()
                .or_else(|| api.name.clone())
                .unwrap_or_default()
        )
        .trim()
        .to_string();
        nodes.push(BlastNode {
            id: api.id.0.clone(),
            kind: "api".to_string(),
            label,
        });
        if let Some(handler) = &api.handler_symbol_id {
            edges.push(BlastEdge {
                source: api.id.0.clone(),
                target: handler.0.clone(),
                kind: "handles".to_string(),
            });
        }
    }
    for object in &resolved.schema_objects {
        nodes.push(BlastNode {
            id: object.id.0.clone(),
            kind: "table".to_string(),
            label: object.name.clone(),
        });
    }
    for call in &resolved.calls {
        if let Some(callee) = &call.callee_symbol_id {
            edges.push(BlastEdge {
                source: call.caller_symbol_id.0.clone(),
                target: callee.0.clone(),
                kind: "calls".to_string(),
            });
        }
    }
    for access in &resolved.schema_accesses {
        edges.push(BlastEdge {
            source: access.accessor_symbol_id.clone(),
            target: access.table_id.clone(),
            kind: access.kind.to_string(),
        });
    }
    (nodes, edges)
}

fn map_change_kind(kind: ovecc_git::GitChangeKind) -> ChangeKind {
    use ovecc_git::GitChangeKind as G;
    match kind {
        G::Added => ChangeKind::Added,
        G::Modified => ChangeKind::Modified,
        G::Deleted => ChangeKind::Deleted,
        G::Renamed => ChangeKind::Renamed,
        G::Copied => ChangeKind::Copied,
    }
}

/// Outcome of the per-file (parallel) hashing/parsing stage.
struct ProcessedFile {
    /// `None` when the file could not even be read: it is reported as a
    /// failure and treated as absent from the index.
    file: Option<FileRecord>,
    /// Legacy import facts, derived from `facts`, for module-level dependency
    /// resolution.
    imports: Vec<ImportFact>,
    /// Full grammar-level facts for code-fact resolution.
    facts: FileFacts,
    /// True when the file was parsed during this run (cache miss).
    parsed: bool,
    /// True when facts were served from the parse cache.
    from_cache: bool,
    failure: Option<IndexFailure>,
}

/// Hashes, caches, and parses one file. Never aborts the run: every error
/// becomes an `IndexFailure` carried in the outcome.
fn process_file(
    paths: &ProjectPaths,
    repository_id: &str,
    cache: &ParseCache,
    source_file: &Path,
) -> ProcessedFile {
    let unreadable = |path: String, message: String| ProcessedFile {
        file: None,
        imports: Vec::new(),
        facts: FileFacts::default(),
        parsed: false,
        from_cache: false,
        failure: Some(IndexFailure { path, message }),
    };

    let relative = match relative_path(&paths.root, source_file) {
        Ok(relative) => relative,
        Err(error) => {
            return unreadable(source_file.display().to_string(), format!("{error:#}"));
        }
    };
    let Some(language) = language_for_path(source_file) else {
        return unreadable(relative, "unsupported source extension".to_string());
    };
    let bytes = match std::fs::read(source_file) {
        Ok(bytes) => bytes,
        Err(error) => return unreadable(relative, format!("failed to read file: {error}")),
    };

    let module_name = infer_module_name(&relative);
    let file = FileRecord {
        id: stable_id("file", &[repository_id, &relative]),
        repository_id: repository_id.to_string(),
        path: relative.clone(),
        absolute_path: source_file.to_path_buf(),
        language,
        content_hash: hash_bytes(&bytes),
        size_bytes: bytes.len() as u64,
        module_id: stable_id("module", &[repository_id, &module_name]),
        module_name,
    };

    if let Some(facts) = cache.load(&file.content_hash) {
        return ProcessedFile {
            imports: legacy_imports(&facts),
            file: Some(file),
            facts,
            parsed: false,
            from_cache: true,
            failure: None,
        };
    }

    let core_lang = core_language(language);
    let source_input = SourceFile {
        path: relative.clone(),
        absolute_path: source_file.to_path_buf(),
        language: core_lang,
        contents: String::from_utf8_lossy(&bytes).into_owned(),
    };
    // The JS/TS family has a bespoke adapter; every other language goes through
    // the specification-driven `GenericAdapter`.
    let extracted = if core_lang.is_js_family() {
        TypeScriptAdapter.extract(&source_input)
    } else {
        match GenericAdapter::for_language(core_lang) {
            Some(adapter) => adapter.extract(&source_input),
            None => Err(ParseFailure {
                path: relative.clone(),
                message: format!("no adapter for {}", core_lang.as_str()),
            }),
        }
    };
    match extracted {
        Ok(facts) => {
            cache.store(&file.content_hash, &facts);
            ProcessedFile {
                imports: legacy_imports(&facts),
                file: Some(file),
                facts,
                parsed: true,
                from_cache: false,
                failure: None,
            }
        }
        Err(failure) => ProcessedFile {
            failure: Some(IndexFailure {
                path: relative,
                message: failure.message,
            }),
            file: Some(file),
            imports: Vec::new(),
            facts: FileFacts::default(),
            parsed: false,
            from_cache: false,
        },
    }
}

/// Maps the indexer's legacy language enum to the core language enum the
/// adapter and resolution layer use, preserving the jsx/tsx distinction.
fn core_language(language: SourceLanguage) -> ovecc_core::lang::SourceLanguage {
    use ovecc_core::lang::SourceLanguage as Core;
    match language {
        SourceLanguage::JavaScript => Core::JavaScript,
        SourceLanguage::Jsx => Core::Jsx,
        SourceLanguage::TypeScript => Core::TypeScript,
        SourceLanguage::Tsx => Core::Tsx,
        SourceLanguage::Python => Core::Python,
        SourceLanguage::Rust => Core::Rust,
        SourceLanguage::Go => Core::Go,
        SourceLanguage::Cpp => Core::Cpp,
    }
}

/// Projects the adapter's rich import facts onto the legacy `ImportFact` used
/// by module-level dependency resolution.
fn legacy_imports(facts: &FileFacts) -> Vec<ImportFact> {
    facts
        .imports
        .iter()
        .map(|import| ImportFact {
            specifier: import.specifier.clone(),
            line: import.line as usize,
            import_kind: match import.kind {
                ImportFactKind::Static | ImportFactKind::TypeOnly => ImportKind::Static,
                ImportFactKind::ReExport => ImportKind::Export,
                ImportFactKind::Require => ImportKind::Require,
                ImportFactKind::Dynamic => ImportKind::Dynamic,
            },
        })
        .collect()
}

/// Builds the imported-name → target-file bindings for one file, by resolving
/// each relative import to a known file and pairing it with its imported
/// names. Feeds cross-file callee resolution.
fn build_import_bindings(
    paths: &ProjectPaths,
    file: &FileRecord,
    facts: &FileFacts,
    file_by_path: &HashMap<String, FileRecord>,
) -> Vec<ImportBinding> {
    let mut bindings = Vec::new();
    for import in &facts.imports {
        if !is_relative_specifier(&import.specifier) {
            continue;
        }
        let Some(target) =
            resolve_relative_import(&paths.root, &file.path, &import.specifier, file_by_path)
        else {
            continue;
        };
        for name in &import.imported_names {
            bindings.push(ImportBinding {
                name: name.clone(),
                target_path: target.path.clone(),
            });
        }
    }
    bindings
}

/// Rebuilds the import facts a file had on its last successful run from the
/// persisted dependency rows (a parse failure must not erase facts).
fn retained_imports(previous: &[DependencyRecord], path: &str) -> Vec<ImportFact> {
    previous
        .iter()
        .filter(|dependency| dependency.source_file_path == path)
        .map(|dependency| ImportFact {
            specifier: dependency.specifier.clone(),
            line: dependency.evidence_line,
            import_kind: ImportKind::from_kind_str(&dependency.dependency_kind)
                .unwrap_or(ImportKind::Static),
        })
        .collect()
}

/// Content-addressed parse cache.
///
/// Entries are immutable (keyed by content hash) and path-independent, so
/// renames and branch switches still hit. Corrupted or unreadable entries
/// fall back to a re-parse. The cache is an optimization: writes are
/// best-effort and never fail the run.
struct ParseCache {
    dir: PathBuf,
}

impl ParseCache {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("failed to create parse cache {}", self.dir.display()))
    }

    fn entry_path(&self, content_hash: &str) -> PathBuf {
        self.dir.join(format!("{content_hash}.json"))
    }

    fn load(&self, content_hash: &str) -> Option<FileFacts> {
        let bytes = std::fs::read(self.entry_path(content_hash)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn store(&self, content_hash: &str, facts: &FileFacts) {
        let target = self.entry_path(content_hash);
        let Ok(json) = serde_json::to_vec(facts) else {
            return;
        };
        // Write-then-rename: concurrent writers of the same hash produce
        // identical bytes, so losing the race is harmless. Windows refuses to
        // rename over an existing file, so corrupted entries (the only way a
        // target can already exist here, since load() missed) are removed and
        // replaced — the cache self-heals.
        let temp = self.dir.join(format!(
            "{content_hash}.{}.{:?}.tmp",
            std::process::id(),
            std::thread::current().id()
        ));
        if std::fs::write(&temp, json).is_ok() && std::fs::rename(&temp, &target).is_err() {
            let _ = std::fs::remove_file(&target);
            if std::fs::rename(&temp, &target).is_err() {
                let _ = std::fs::remove_file(&temp);
            }
        }
    }
}

/// Snapshot metrics persisted with each index run. Computed here (with
/// `ovecc-graph`) and handed to the store as plain values.
fn compute_snapshot_metrics(
    modules: &[ModuleRecord],
    files: &[FileRecord],
    dependencies: &[DependencyRecord],
) -> Vec<(String, f64)> {
    let module_names: Vec<String> = modules.iter().map(|module| module.name.clone()).collect();
    let circular_dependencies = ovecc_graph::cycle_count(&module_names, dependencies);
    let local_edges = ovecc_graph::local_dependency_edges(dependencies);
    let possible_edges = module_names
        .len()
        .saturating_mul(module_names.len().saturating_sub(1));
    let coupling_density = if possible_edges == 0 {
        0.0
    } else {
        local_edges.len() as f64 / possible_edges as f64
    };
    let external_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.is_external)
        .count();

    vec![
        ("modules".to_string(), module_names.len() as f64),
        ("files".to_string(), files.len() as f64),
        ("dependencies".to_string(), dependencies.len() as f64),
        (
            "external_dependencies".to_string(),
            external_dependencies as f64,
        ),
        (
            "circular_dependencies".to_string(),
            circular_dependencies as f64,
        ),
        ("coupling_density".to_string(), coupling_density),
    ]
}

fn discover_source_files(root: &Path, config: &OveccConfig) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true);

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
        // Max file size bytes / size limit.
        if let Some(limit) = config.index.max_file_size_bytes
            && let Ok(metadata) = entry.metadata()
            && metadata.len() > limit
        {
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
                    if is_relative_specifier(&import.specifier) {
                        resolve_relative_import(
                            &paths.root,
                            &file.path,
                            &import.specifier,
                            file_by_path,
                        )
                    } else {
                        None
                    }
                }
                SourceLanguage::Python => resolve_suffix_unique(
                    &python_import_candidates(&file.path, &import.specifier),
                    &suffix_index,
                    file_by_path,
                ),
                SourceLanguage::Rust => resolve_suffix_unique(
                    &rust_import_candidates(&file.path, &import.specifier),
                    &suffix_index,
                    file_by_path,
                ),
                SourceLanguage::Cpp => resolve_suffix_unique(
                    &cpp_import_candidates(&file.path, &import.specifier),
                    &suffix_index,
                    file_by_path,
                ),
                SourceLanguage::Go => resolve_go_package(
                    &go_import_candidates(&import.specifier),
                    &dir_index,
                    file_by_path,
                ),
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
    while let Some(&first) = segments.first() {
        match first {
            "crate" => {
                segments.remove(0); // crate root; suffix match finds it
                break;
            }
            "self" => {
                relative = true;
                segments.remove(0);
            }
            "super" => {
                relative = true;
                up += 1;
                segments.remove(0);
            }
            _ => break,
        }
    }
    if segments.is_empty() {
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
    fn python_cross_file_imports_resolve_internally() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("user")).unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("billing")).unwrap();
        std::fs::write(
            dir.path().join("src").join("user").join("account.py"),
            "class Account:\n    def balance(self):\n        return 0\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src").join("billing").join("invoice.py"),
            "from user.account import Account\nimport os\n\ndef total():\n    return Account().balance()\n",
        )
        .unwrap();
        let paths = ProjectPaths::resolve(dir.path()).unwrap();
        let config = OveccConfig::default();

        let report = index_repository(&paths, &config, true).unwrap();
        // `user.account` resolves internally; `os` stays external.
        assert!(report.dependencies >= 2, "{report:?}");
        assert!(
            report.dependencies > report.external_dependencies,
            "at least one internal Python dependency must resolve: {report:?}"
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
    fn incremental_runs_hit_the_parse_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("billing")).unwrap();
        std::fs::write(
            dir.path().join("src").join("billing").join("a.ts"),
            "import { b } from \"./b\";\nexport const a = 1;\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src").join("billing").join("b.ts"),
            "export const b = 2;\n",
        )
        .unwrap();
        let paths = ProjectPaths::resolve(dir.path()).unwrap();
        let config = OveccConfig::default();

        let first = index_repository(&paths, &config, true).unwrap();
        assert_eq!(first.files_parsed, 2);
        assert_eq!(first.files_from_cache, 0);
        assert!(first.parse_failures.is_empty());

        // Unchanged repository: everything comes from the parse cache.
        let second = index_repository(&paths, &config, true).unwrap();
        assert_eq!(second.files_parsed, 0);
        assert_eq!(second.files_from_cache, 2);
        assert_eq!(second.dependencies, first.dependencies);

        // One modified file: exactly one re-parse.
        std::fs::write(
            dir.path().join("src").join("billing").join("b.ts"),
            "export const b = 3;\n",
        )
        .unwrap();
        let third = index_repository(&paths, &config, true).unwrap();
        assert_eq!(third.files_parsed, 1);
        assert_eq!(third.files_from_cache, 1);

        // Corrupted cache entries fall back to a clean re-parse.
        let cache_dir = paths.parse_cache_dir.join(PARSE_CACHE_VERSION);
        for entry in std::fs::read_dir(&cache_dir).unwrap() {
            std::fs::write(entry.unwrap().path(), b"not json").unwrap();
        }
        let fourth = index_repository(&paths, &config, true).unwrap();
        assert_eq!(fourth.files_parsed, 2);
        assert_eq!(fourth.files_from_cache, 0);
        assert_eq!(fourth.dependencies, first.dependencies);

        // ... and the re-parse repairs the corrupted entries.
        let fifth = index_repository(&paths, &config, true).unwrap();
        assert_eq!(fifth.files_from_cache, 2);
        assert_eq!(fifth.files_parsed, 0);
    }

    #[test]
    fn persists_code_facts_and_reindex_is_consistent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("user")).unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("billing")).unwrap();
        std::fs::write(
            dir.path().join("src").join("user").join("service.ts"),
            "export function getUser(id: string): string { return id; }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src").join("billing").join("service.ts"),
            r#"
import { getUser } from "../user/service";
import express from "express";
const app = express();
app.get("/invoices/:id", createInvoice);
export function createInvoice(id: string): string {
  return db.query("SELECT * FROM invoices") + getUser(id);
}
"#,
        )
        .unwrap();
        let paths = ProjectPaths::resolve(dir.path()).unwrap();
        let config = OveccConfig::default();

        let first = index_repository(&paths, &config, true).unwrap();
        assert!(
            first.symbols >= 3,
            "expected getUser, createInvoice, <module>: {}",
            first.symbols
        );
        assert!(first.calls >= 1, "expected at least the getUser call");
        assert_eq!(first.apis, 1, "the express route must be extracted");
        assert_eq!(first.tables, 1, "the invoices table must be extracted");

        // The rows are actually persisted (proves the INSERTs fired, not just
        // that resolution produced records).
        let repository_id = paths.repository_id().0;
        let store = ovecc_db::ArchitectureStore::open(&paths.db_path).unwrap();
        assert_eq!(
            store.count_rows("symbols", &repository_id).unwrap(),
            first.symbols
        );
        assert_eq!(
            store.count_rows("apis", &repository_id).unwrap(),
            first.apis
        );
        assert_eq!(
            store.count_rows("schema_objects", &repository_id).unwrap(),
            first.tables
        );
        // Graph edges: every symbol is declared; the route is exposed and
        // its resolved handler is wired; the cross-module call is linked.
        assert_eq!(
            store.count_edges(&repository_id, "declares").unwrap(),
            first.symbols,
            "one declares edge per symbol"
        );
        assert_eq!(store.count_edges(&repository_id, "exposes").unwrap(), 1);
        assert_eq!(store.count_edges(&repository_id, "handles").unwrap(), 1);
        assert!(
            store.count_edges(&repository_id, "calls").unwrap() >= 1,
            "the resolved getUser call must produce a calls edge"
        );
        assert_eq!(
            store.count_edges(&repository_id, "reads").unwrap(),
            1,
            "createInvoice reads the invoices table (reads edge)"
        );
        drop(store);

        // Re-indexing the unchanged repository must not error (the persistence
        // diff skips existing IDs rather than re-inserting duplicate keys) and
        // must keep the persisted row counts stable.
        let second = index_repository(&paths, &config, true).unwrap();
        assert_eq!(second.symbols, first.symbols);
        assert_eq!(second.calls, first.calls);
        assert_eq!(second.apis, first.apis);
        assert_eq!(second.tables, first.tables);
        let store = ovecc_db::ArchitectureStore::open(&paths.db_path).unwrap();
        assert_eq!(
            store.count_rows("symbols", &repository_id).unwrap(),
            first.symbols,
            "re-index must not duplicate persisted symbols"
        );
        assert_eq!(
            store.count_edges(&repository_id, "declares").unwrap(),
            first.symbols,
            "re-index must not duplicate graph edges"
        );
    }
}
