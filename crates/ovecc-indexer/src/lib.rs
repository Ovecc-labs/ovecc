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
use ovecc_core::config::{
    ArchitectureConfig, ModuleMapping, ModuleStrategy, OveccConfig, ProjectPaths,
};
use ovecc_core::facts::{
    ChangeKind, CommitRecord, ComplexityRecord, ExportRecord, FileChangeRecord, FileFacts,
    FindingKind, ImportFactKind, ParseFailure, SourceFile,
};
use ovecc_core::id::{CommitId, ComplexityId, ExportId, FileChangeId, FileId, RepositoryId};
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
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

const SOURCE_EXTENSIONS: &[&str] = &[
    // JavaScript/TypeScript family.
    "js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", // Python, Rust, Go.
    "py", "pyi", "rs", "go",
    // C/C++ sources and headers (the C++ grammar covers C declarations).
    "cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "h", "c", "cu", "cuh",
];

/// `(variable, type)` bindings; older entries
/// miss and re-parse.
const PARSE_CACHE_VERSION: &str = "v9";

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
        .map(|source_file| {
            process_file(
                paths,
                &repository_id,
                &cache,
                source_file,
                &config.architecture,
            )
        })
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
                path_prefix: infer_module_prefix(&file.path, &config.architecture),
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
    // Bindings reuse the already-resolved dependency edges (oxc_resolver), so
    // calls through aliased (`@/x`) and monorepo (`@scope/pkg`) imports link,
    // not just relative ones.
    let resolved_targets: HashMap<(String, String), String> = dependencies
        .iter()
        .filter(|dependency| !dependency.is_external)
        .filter_map(|dependency| {
            let target = dependency.target_file_path.clone()?;
            Some((
                (
                    dependency.source_file_path.clone(),
                    dependency.specifier.clone(),
                ),
                target,
            ))
        })
        .collect();
    let bindings_by_path: HashMap<String, Vec<ImportBinding>> = files
        .iter()
        .map(|file| {
            let bindings = file_facts
                .get(&file.path)
                .map(|facts| build_import_bindings(file, facts, &resolved_targets))
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

    // Complexity (oxc cyclomatic + cognitive) → repo metrics + HighComplexity
    // findings for functions over the maintainability thresholds.
    let (mut max_cyclomatic, mut max_cognitive, mut function_count) = (0u16, 0u16, 0usize);
    let mut total_cognitive: u64 = 0;
    let mut high_complexity_functions: usize = 0;
    for (path, facts) in &file_facts {
        for complexity in &facts.complexity {
            function_count += 1;
            max_cyclomatic = max_cyclomatic.max(complexity.cyclomatic);
            max_cognitive = max_cognitive.max(complexity.cognitive);
            total_cognitive += complexity.cognitive as u64;
            let severity = if complexity.cognitive >= 25 || complexity.cyclomatic >= 20 {
                ovecc_core::facts::Severity::High
            } else if complexity.cognitive >= 15 || complexity.cyclomatic >= 10 {
                ovecc_core::facts::Severity::Medium
            } else {
                continue;
            };
            high_complexity_functions += 1;
            findings.push(ovecc_core::facts::FindingRecord {
                id: ovecc_core::id::FindingId::from_parts(&[
                    &repository_id,
                    "complexity",
                    path,
                    &complexity.line.to_string(),
                    &complexity.qualified_name,
                ]),
                repository_id: RepositoryId::from_raw(&repository_id),
                snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(&snapshot_id)),
                kind: FindingKind::HighComplexity,
                severity,
                rule_name: Some("complexity".to_string()),
                target: None,
                title: format!(
                    "High complexity: {} (cyclomatic {}, cognitive {})",
                    complexity.qualified_name, complexity.cyclomatic, complexity.cognitive
                ),
                description: format!(
                    "{} at {}:{} has cyclomatic {} and cognitive {} complexity; consider refactoring.",
                    complexity.qualified_name,
                    path,
                    complexity.line,
                    complexity.cyclomatic,
                    complexity.cognitive
                ),
                evidence: vec![ovecc_core::facts::Evidence {
                    file_path: path.clone(),
                    line: Some(complexity.line),
                    symbol: Some(complexity.qualified_name.clone()),
                    detail: Some(format!(
                        "cyclomatic {}, cognitive {}",
                        complexity.cyclomatic, complexity.cognitive
                    )),
                }],
                created_at: chrono::Utc::now(),
            });
        }
    }
    metrics.push(("functions".to_string(), function_count as f64));
    metrics.push(("max_cyclomatic".to_string(), max_cyclomatic as f64));
    metrics.push(("max_cognitive".to_string(), max_cognitive as f64));
    metrics.push(("total_cognitive".to_string(), total_cognitive as f64));
    metrics.push((
        "high_complexity_functions".to_string(),
        high_complexity_functions as f64,
    ));

    // Dead-code analysis (unused exports/files) over the in-memory facts: oxc
    // exports + resolved internal import edges (carrying the imported names) +
    // detected entry points. Runs at index time and persists only findings.
    let all_files: Vec<String> = files.iter().map(|file| file.path.clone()).collect();
    let entry_points = detect_entry_points(&paths.root, &files);
    let export_facts: Vec<(String, ovecc_core::facts::ExportFact)> = file_facts
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .exports
                .iter()
                .map(move |export| (path.clone(), export.clone()))
        })
        .collect();
    let import_edges: Vec<ovecc_rules::deadcode::ImportEdge> = dependencies
        .iter()
        .filter_map(|dependency| {
            let target = dependency.target_file_path.clone()?;
            if dependency.is_external {
                return None;
            }
            let names: Vec<String> = file_facts
                .get(&dependency.source_file_path)
                .map(|facts| {
                    facts
                        .imports
                        .iter()
                        .filter(|import| import.specifier == dependency.specifier)
                        .flat_map(|import| import.imported_names.clone())
                        .collect()
                })
                .unwrap_or_default();
            Some(ovecc_rules::deadcode::ImportEdge {
                is_namespace: names.is_empty(),
                source_file: dependency.source_file_path.clone(),
                target_file: target,
                imported_names: names,
            })
        })
        .collect();
    let deadcode_findings = ovecc_rules::deadcode::analyze(&ovecc_rules::deadcode::DeadCodeInput {
        repository_id: &repository_id,
        snapshot_id: Some(&snapshot_id),
        files: &all_files,
        entry_points: &entry_points,
        exports: &export_facts,
        imports: &import_edges,
    });
    // Persist aggregate counts on the snapshot so `diff`/`drift` can trend them
    // ("dead code grew this quarter").
    let unused_exports = deadcode_findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::UnusedExport)
        .count();
    let unused_files = deadcode_findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::UnusedFile)
        .count();
    metrics.push(("unused_exports".to_string(), unused_exports as f64));
    metrics.push(("unused_files".to_string(), unused_files as f64));
    findings.extend(deadcode_findings);

    // Unused dependencies: packages declared in a `package.json` `dependencies`
    // map but never imported by an indexed file. Opt-in (`detect_unused_deps`):
    // real-repo measurement showed a high false-positive rate — config files,
    // `scripts` entries, side-effect imports, and test fixtures use a package
    // without an import the graph can see — so it is off by default.
    if config.index.detect_unused_deps {
        // Any bare-specifier import counts as using the package — including
        // workspace packages (`@scope/pkg`) that resolve to an internal file
        // (`is_external == false`), so monorepo packages are not falsely
        // flagged. `external_package_root` drops relative imports and built-ins.
        let imported_roots: HashSet<String> = dependencies
            .iter()
            .filter_map(|dependency| external_package_root(&dependency.specifier))
            .collect();
        let unused_dep_findings =
            detect_unused_dependencies(&paths.root, &repository_id, &snapshot_id, &imported_roots);
        metrics.push((
            "unused_dependencies".to_string(),
            unused_dep_findings.len() as f64,
        ));
        findings.extend(unused_dep_findings);
    }

    // Security findings in test, fixture, and example files are usually test
    // data or deliberate test scaffolding (fake secrets, an `eval` under test,
    // a weak hash in a vector), not production risk — the canonical
    // secret/SAST false positive. Down-rank them to Low so they stay visible in
    // `security` but do not trip a high-severity gate. Down-ranked, not dropped:
    // a real issue committed to a test file is still reported.
    for finding in &mut findings {
        let is_security = matches!(
            finding.kind,
            FindingKind::HardcodedSecret
                | FindingKind::InsecurePattern
                | FindingKind::WeakCrypto
        );
        if is_security
            && finding.severity != ovecc_core::facts::Severity::Low
            && finding.evidence.iter().any(|evidence| {
                is_test_file(&evidence.file_path) || is_standalone_entry(&evidence.file_path)
            })
        {
            finding.severity = ovecc_core::facts::Severity::Low;
        }
    }

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
    // First-class code-health facts (oxc): normalize per-function complexity and
    // per-file exports into persistable records keyed by file id.
    let mut complexity_records: Vec<ComplexityRecord> = Vec::new();
    let mut export_records: Vec<ExportRecord> = Vec::new();
    for (path, facts) in &file_facts {
        let Some(file) = file_by_path.get(path) else {
            continue;
        };
        let file_id = &file.id;
        for complexity in &facts.complexity {
            complexity_records.push(ComplexityRecord {
                id: ComplexityId::from_parts(&[
                    &repository_id,
                    file_id,
                    &complexity.qualified_name,
                    &complexity.line.to_string(),
                ]),
                repository_id: RepositoryId::from_raw(&repository_id),
                file_id: FileId::from_raw(file_id.clone()),
                qualified_name: complexity.qualified_name.clone(),
                line: complexity.line,
                cyclomatic: complexity.cyclomatic,
                cognitive: complexity.cognitive,
                line_count: complexity.line_count,
                param_count: complexity.param_count,
            });
        }
        for export in &facts.exports {
            export_records.push(ExportRecord {
                id: ExportId::from_parts(&[
                    &repository_id,
                    file_id,
                    &export.name,
                    &export.line.to_string(),
                ]),
                repository_id: RepositoryId::from_raw(&repository_id),
                file_id: FileId::from_raw(file_id.clone()),
                name: export.name.clone(),
                line: export.line,
                is_type_only: export.is_type_only,
                re_export_source: export.re_export.as_ref().map(|r| r.source_specifier.clone()),
                re_export_name: export.re_export.as_ref().map(|r| r.imported_name.clone()),
            });
        }
    }
    let code = ResolvedCode {
        symbols: &resolved.symbols,
        calls: &resolved.calls,
        apis: &resolved.apis,
        schema_objects: &resolved.schema_objects,
        schema_edges: &schema_edges,
        complexity: &complexity_records,
        exports: &export_records,
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
    architecture: &ArchitectureConfig,
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

    let module_name = infer_module_name(&relative, architecture);
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
        Ok(mut facts) => {
            // For the JS/TS family, enrich with oxc-computed exports + per-function
            // complexity — the semantically-hard facts tree-sitter cannot produce.
            // oxc is confined behind the parser boundary; only neutral facts return.
            if core_lang.is_js_family()
                && let Some((exports, complexity)) =
                    ovecc_parser::oxc_extractor::extract(&source_input.contents, core_lang)
            {
                facts.exports = exports;
                facts.complexity = complexity;
            }
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
    file: &FileRecord,
    facts: &FileFacts,
    resolved_targets: &HashMap<(String, String), String>,
) -> Vec<ImportBinding> {
    let mut bindings = Vec::new();
    for import in &facts.imports {
        // Use the dependency graph's resolution (oxc_resolver), which already
        // handled relative, alias, and monorepo specifiers alike.
        let Some(target_path) =
            resolved_targets.get(&(file.path.clone(), import.specifier.clone()))
        else {
            continue;
        };
        for name in &import.imported_names {
            bindings.push(ImportBinding {
                name: name.clone(),
                target_path: target_path.clone(),
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

/// Tokenizes every indexed source file into a normalized token stream for
/// clone detection. Reuses the same discovery and excludes as `index`, so
/// `dupes` sees exactly the indexed set. Parallel and best-effort: unreadable
/// or ungrammared files are skipped. Output keeps discovery order (sorted) for
/// determinism.
pub fn collect_file_tokens(
    paths: &ProjectPaths,
    config: &OveccConfig,
) -> Result<Vec<ovecc_graph::dupes::FileTokens>> {
    let files = discover_source_files(&paths.root, config)?;
    let tokens = files
        .par_iter()
        .filter_map(|path| {
            let bytes = std::fs::read(path).ok()?;
            let relative = relative_path(&paths.root, path).ok()?;
            let language = language_for_path(path)?;
            let (token_hashes, token_lines) = ovecc_parser::tokenize::tokenize(
                &String::from_utf8_lossy(&bytes),
                core_language(language),
            );
            if token_hashes.is_empty() {
                return None;
            }
            Some(ovecc_graph::dupes::FileTokens {
                path: relative,
                token_hashes,
                token_lines,
            })
        })
        .collect();
    Ok(tokens)
}

fn discover_source_files(root: &Path, config: &OveccConfig) -> Result<Vec<PathBuf>> {
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
        // Max file size bytes / size limit.
        if let Some(limit) = config.index.max_file_size_bytes
            && let Ok(metadata) = entry.metadata()
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
    const MARKERS: [&str; 6] = [
        "@generated",
        "do not edit",
        "code generated",
        "auto-generated",
        "autogenerated",
        "automatically generated",
    ];
    if MARKERS.iter().any(|marker| lower.contains(marker)) {
        return true;
    }
    // Whole-file opt-out combo emscripten/codegen emit and that hand-maintained
    // code virtually never carries.
    lower.contains("@ts-nocheck") && lower.contains("eslint-disable")
}

fn should_skip_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return true;
    };
    relative
        .components()
        .any(|component| is_excluded_component(&component.as_os_str().to_string_lossy()))
}

fn language_for_path(path: &Path) -> Option<SourceLanguage> {
    let extension = path.extension()?.to_str()?;
    SourceLanguage::from_extension(extension)
}

/// Directories that *contain* modules but are not themselves one — the module is
/// what lives inside them. A leading container is skipped when naming a module so
/// `src/billing/...` is `billing`, not `src`.
const MODULE_CONTAINERS: &[&str] = &["src", "app", "packages", "apps", "services", "crates"];

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
    let parts: Vec<&str> = relative.split('/').filter(|part| !part.is_empty()).collect();
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
fn infer_module_name(relative: &str, architecture: &ArchitectureConfig) -> String {
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
fn infer_module_prefix(relative: &str, architecture: &ArchitectureConfig) -> String {
    if let Some(mapping) = configured_module(relative, architecture) {
        return mapping.path_prefix.clone();
    }
    let parts: Vec<&str> = relative.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() < 2 {
        return ".".to_string();
    }
    let dirs = &parts[..parts.len() - 1];
    let start = usize::from(MODULE_CONTAINERS.contains(&dirs[0]) && dirs.len() > 1);
    let end = start.saturating_add(architecture.module_depth.max(1)).min(dirs.len());
    dirs[..end].join("/")
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
    // One shared oxc_resolver for the whole run (per-file tsconfig discovery is
    // internal); resolves relative, bare/package, and tsconfig-aliased JS/TS
    // imports — a strict superset of the old relative-only resolution.
    let js_resolver = create_js_resolver();

    for file in files {
        let Some(imports) = parsed_imports.get(&file.path) else {
            continue;
        };

        for import in imports {
            let resolved = match file.language {
                SourceLanguage::JavaScript
                | SourceLanguage::Jsx
                | SourceLanguage::TypeScript
                | SourceLanguage::Tsx => resolve_js_ts_import(
                    &js_resolver,
                    &paths.root,
                    file,
                    &import.specifier,
                    file_by_path,
                ),
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

// --- oxc_resolver-backed JS/TS resolution ------------------------------------
//
// Portions adapted from fallow (research/fallow/crates/graph/src/resolve/
// specifier.rs), MIT (c) 2026 Bart Waardenburg. See THIRD-PARTY-NOTICES.md.
// SPDX-License-Identifier: MIT
//
// Real tsconfig paths/baseUrl, package `exports`, and extension/index fallbacks
// for the JS/TS family. Non-JS languages keep the suffix/dir resolvers. oxc is
// confined to this resolution seam — no oxc type crosses into the fact model.

/// JS/TS extensions to probe, TS family first so a `.ts` shadowing a built `.js`
/// wins (fallow `specifier.rs:34`).
fn js_resolver_extensions() -> Vec<String> {
    [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json"]
        .iter()
        .map(|extension| (*extension).to_string())
        .collect()
}

/// Package `exports`/`imports` condition names, highest priority first
/// (fallow `react_native.rs` baseline, minus the RN conditions).
fn js_resolver_conditions() -> Vec<String> {
    ["development", "import", "require", "default", "types", "node"]
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
/// tsconfig-aliased — to an indexed [`FileRecord`], or `None` when it resolves
/// outside the indexed set (`node_modules`, `dist`, …) or cannot be resolved.
/// `None` makes the caller record it as external, exactly as before. Strictly
/// widens resolution over the old relative-only path (fallow `specifier.rs:99-135`).
fn resolve_js_ts_import(
    resolver: &oxc_resolver::Resolver,
    root: &Path,
    file: &FileRecord,
    specifier: &str,
    file_by_path: &HashMap<String, FileRecord>,
) -> Option<FileRecord> {
    // oxc_resolver wants a plain absolute path; strip the Windows verbatim
    // prefix that `std::fs::canonicalize` adds (oxc uses dunce-style paths),
    // or every resolve fails and falls through to external.
    let from_file = strip_verbatim_prefix(file.absolute_path.as_path());
    let resolved_abs = match resolver.resolve_file(&from_file, specifier) {
        Ok(resolution) => resolution.path().to_path_buf(),
        // A broken tsconfig: retry dir-based so relative/bare still resolve.
        Err(error) if is_tsconfig_error(&error) => {
            let dir = from_file.parent().unwrap_or(&from_file);
            resolver.resolve(dir, specifier).ok()?.path().to_path_buf()
        }
        Err(_) => return None,
    };
    // Map the absolute resolution back to a repo-relative '/'-path and into the
    // indexed set; outside root or a miss (node_modules) => external.
    let relative = repo_relative_path(root, &resolved_abs)?;
    file_by_path.get(&relative).cloned()
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
    Some(abs_norm[root_norm.len()..].trim_start_matches('/').to_string())
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
/// - the conventional root / `src` `index`/`main`, and all test/spec files.
///
/// Modelled on knip's resolver and fallow's entry-point detection. Biased toward
/// precision: an over-credited entry only costs a missed finding, while a missed
/// entry floods the report with false "unreachable file" hits.
fn detect_entry_points(root: &Path, files: &[FileRecord]) -> HashSet<String> {
    let mut entries = HashSet::new();
    let file_paths: HashSet<&str> = files.iter().map(|file| file.path.as_str()).collect();

    for (dir, manifest) in find_package_manifests(root) {
        for spec in manifest_entry_specs(&manifest) {
            if let Some(resolved) = resolve_entry_spec(&dir, &spec, &file_paths) {
                entries.insert(resolved);
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
fn is_standalone_entry(path: &str) -> bool {
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

/// Normalizes a bare import specifier to its package root: `lodash/fp` →
/// `lodash`, `@scope/pkg/sub` → `@scope/pkg`. Returns `None` for relative
/// imports and Node built-ins (`node:fs`, `fs`), which are never npm deps.
fn external_package_root(specifier: &str) -> Option<String> {
    if specifier.starts_with('.') || specifier.starts_with('/') || specifier.starts_with("node:") {
        return None;
    }
    const BUILTINS: [&str; 24] = [
        "fs", "path", "os", "http", "https", "url", "util", "stream", "events", "crypto", "child_process",
        "process", "buffer", "assert", "zlib", "net", "tls", "dns", "querystring", "readline", "cluster",
        "worker_threads", "perf_hooks", "module",
    ];
    let root = if let Some(rest) = specifier.strip_prefix('@') {
        let mut parts = rest.splitn(3, '/');
        let scope = parts.next()?;
        let name = parts.next()?;
        format!("@{scope}/{name}")
    } else {
        specifier.split('/').next()?.to_string()
    };
    if BUILTINS.contains(&root.as_str()) {
        return None;
    }
    Some(root)
}

/// Flags packages declared in a `package.json` `dependencies` map that no
/// indexed file imports. Conservative: production deps only (not `devDeps`),
/// `@types/*` excluded (ambient), one finding per (manifest, package).
fn detect_unused_dependencies(
    root: &Path,
    repository_id: &str,
    snapshot_id: &str,
    imported_roots: &HashSet<String>,
) -> Vec<ovecc_core::facts::FindingRecord> {
    let mut findings = Vec::new();
    for (dir, manifest) in find_package_manifests(root) {
        let Some(deps) = manifest.get("dependencies").and_then(|value| value.as_object()) else {
            continue;
        };
        let manifest_path = format!("{dir}package.json");
        for name in deps.keys() {
            if name.starts_with("@types/") || imported_roots.contains(name.as_str()) {
                continue;
            }
            findings.push(ovecc_core::facts::FindingRecord {
                id: ovecc_core::id::FindingId::from_parts(&[
                    repository_id,
                    "deadcode",
                    "unused-dependency",
                    &manifest_path,
                    name,
                ]),
                repository_id: RepositoryId::from_raw(repository_id),
                snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(snapshot_id)),
                kind: FindingKind::UnusedDependency,
                severity: ovecc_core::facts::Severity::Low,
                rule_name: Some("unused-dependency".to_string()),
                target: None,
                title: format!("Unused dependency: {name}"),
                description: format!(
                    "'{name}' is declared in {manifest_path} but never imported by an indexed \
                     file. Verify it is not used via config, CLI, or dynamic import before removing."
                ),
                evidence: vec![ovecc_core::facts::Evidence {
                    file_path: manifest_path.clone(),
                    line: Some(1),
                    symbol: Some(name.clone()),
                    detail: None,
                }],
                created_at: chrono::Utc::now(),
            });
        }
    }
    findings
}

/// Locates every `package.json` in the tree (skipping the built-in excluded
/// dirs, so no `node_modules`), returning each one's repo-relative directory
/// (POSIX, trailing `/`, empty for root) and parsed contents. Shallow-bounded:
/// workspace manifests live near the top (`packages/*`, `apps/*`).
fn find_package_manifests(root: &Path) -> Vec<(String, serde_json::Value)> {
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
        let Ok(manifest) = serde_json::from_str::<serde_json::Value>(content.trim_start_matches('\u{feff}')) else {
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
            "page" | "layout" | "route" | "loading" | "error" | "template" | "default"
                | "not-found" | "global-error" | "sitemap" | "robots" | "opengraph-image"
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
fn is_test_file(path: &str) -> bool {
    const TEST_DIRS: [&str; 7] = [
        "__tests__/",
        "__mocks__/",
        "test-d/",
        "type-tests/",
        "type-test/",
        "tests/", // Rust/Go/Python integration tests
        "test/",
    ];
    if TEST_DIRS
        .iter()
        .any(|dir| path.starts_with(dir) || path.contains(&format!("/{dir}")))
    {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    name.contains(".test.")
        || name.contains(".spec.")
        || name.ends_with(".test-d.ts")
        || name.ends_with("_test.go") // Go
        || name.ends_with("_test.py") // Python
        || name.ends_with("_test.rs") // Rust
        || name.starts_with("test_") // Python / pytest
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
    fn normalizes_external_package_roots() {
        assert_eq!(external_package_root("lodash").as_deref(), Some("lodash"));
        assert_eq!(external_package_root("lodash/fp").as_deref(), Some("lodash"));
        assert_eq!(
            external_package_root("@scope/pkg/sub").as_deref(),
            Some("@scope/pkg")
        );
        assert_eq!(external_package_root("@scope/pkg").as_deref(), Some("@scope/pkg"));
        // Relative imports and Node built-ins are not npm dependencies.
        assert_eq!(external_package_root("./local"), None);
        assert_eq!(external_package_root("../up"), None);
        assert_eq!(external_package_root("node:fs"), None);
        assert_eq!(external_package_root("fs"), None);
        assert_eq!(external_package_root("path"), None);
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

    #[test]
    fn infers_modules_from_common_layouts() {
        // Default depth (1) preserves the historical behavior.
        let arch = ArchitectureConfig::default();
        assert_eq!(infer_module_name("src/billing/service.ts", &arch), "billing");
        assert_eq!(infer_module_name("packages/api/index.ts", &arch), "api");
        assert_eq!(infer_module_name("index.ts", &arch), "root");
        // A top-level non-container directory names the module after itself.
        assert_eq!(infer_module_name("cli/src/util/command.rs", &arch), "cli");
        // Prefix stays consistent with the name.
        assert_eq!(infer_module_prefix("src/billing/service.ts", &arch), "src/billing");
        assert_eq!(infer_module_prefix("index.ts", &arch), ".");
    }

    #[test]
    fn module_depth_recovers_boundaries_in_nested_monorepos() {
        // The VS Code case: everything lives under `src/vs`, so depth 1 collapses
        // the repo into one `vs` module. Depth 2 recovers real boundaries.
        let depth1 = ArchitectureConfig::default();
        let depth2 = ArchitectureConfig { module_depth: 2, ..Default::default() };
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &depth1), "vs");
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &depth2), "vs/editor");
        assert_eq!(infer_module_name("src/vs/workbench/x/y.ts", &depth2), "vs/workbench");
        assert_eq!(infer_module_prefix("src/vs/editor/foo.ts", &depth2), "src/vs/editor");
        // Depth never consumes the file name: a file directly under the module dir
        // keeps the module, not the file, as the last segment.
        assert_eq!(infer_module_name("src/vs/editor.ts", &depth2), "vs");
        // A depth larger than the available directories is clamped, not padded.
        let depth9 = ArchitectureConfig { module_depth: 9, ..Default::default() };
        assert_eq!(infer_module_name("src/vs/editor/foo.ts", &depth9), "vs/editor");
        // 0 is treated as 1.
        let depth0 = ArchitectureConfig { module_depth: 0, ..Default::default() };
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
        assert_eq!(infer_module_prefix("src/vs/editor/foo.ts", &arch), "src/vs/editor");
        // Covered by the shorter prefix only.
        assert_eq!(infer_module_name("src/vs/base/bar.ts", &arch), "Core");
        // Unmapped file falls back to depth inference.
        assert_eq!(infer_module_name("packages/api/x.ts", &arch), "api");
        // `auto` strategy ignores explicit mappings entirely.
        let auto = ArchitectureConfig { modules: arch.modules.clone(), ..Default::default() };
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
        assert!(looks_generated(&write("bundle.min.js", "export const x = 1;\n")));
        assert!(looks_generated(&write("woff2-wasm.ts", "export default 1;\n")));
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
        // Code-health facts are persisted as first-class rows (v4 schema): a
        // complexity row per function and an exports row per exported name.
        let complexity_rows = store.count_rows("complexity", &repository_id).unwrap();
        let export_rows = store.count_rows("exports", &repository_id).unwrap();
        assert!(
            complexity_rows >= 2,
            "getUser and createInvoice must each get a complexity row: {complexity_rows}"
        );
        assert!(
            export_rows >= 2,
            "getUser and createInvoice are both exported: {export_rows}"
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
        // Full-replace persistence keeps the code-health row counts stable.
        assert_eq!(
            store.count_rows("complexity", &repository_id).unwrap(),
            complexity_rows,
            "re-index must not duplicate complexity rows"
        );
        assert_eq!(
            store.count_rows("exports", &repository_id).unwrap(),
            export_rows,
            "re-index must not duplicate exports rows"
        );
    }
}
