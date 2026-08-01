//! Indexing pipeline: discover source files, parse them in parallel through a
//! content-addressed cache, resolve imports and code facts, run the analyses,
//! and persist everything as one snapshot.

mod discover;
mod entrypoints;
mod hygiene;
mod imports;
mod manifests;
pub mod resolve;

pub use discover::is_excluded_component;
pub use manifests::manifest_component_roots;

use anyhow::{Context, Result};
use chrono::Utc;
use discover::{discover_source_files, infer_module_name, infer_module_prefix, language_for_path};
use entrypoints::{detect_entry_points, is_standalone_entry, is_test_file};
use hygiene::{detect_unlisted_dependencies, detect_unused_dependencies, external_package_root};
use imports::resolve_dependencies;
use ovecc_core::architecture::{ArchitectureContract, assign_components, assign_slices};
use ovecc_core::config::{
    ArchitectureConfig, DEFAULT_COVERAGE_PATHS, OveccConfig, ProjectPaths, RulesConfig,
};
use ovecc_core::coverage::{CoverageIngest, FileCoverage};
use ovecc_core::facts::{
    CapabilityRecord, ChangeKind, CommitRecord, ComplexityRecord, ExportRecord, FileChangeRecord,
    FileFacts, FindingKind, FindingRecord, ImportFactKind, ParseFailure, SecurityPatternFact,
    SourceFile,
};
use ovecc_core::id::{
    CapabilityUseId, CommitId, ComplexityId, ExportId, FileChangeId, FileId, RepositoryId,
};
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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

// Bump when the extracted fact shape changes, so older cache entries miss and
// re-parse instead of deserializing into wrong defaults.
// v12: `export type { X } from` is now classified TypeOnly (was ReExport), so
// cached facts from v11 would keep witnessing type-only cycles.
// v13: SecurityPatternFact gains `in_test_code` (Rust inline `#[cfg(test)]`
// scopes); serde would default old cached facts to `false`, which is wrong for
// test-scoped patterns, so force re-extraction.
// v14: Rust fully-qualified paths (`other_crate::item`) now emit import facts,
// so cached v13 facts would miss those dependency edges.
// v16: inline route handlers get a synthetic symbol + attributed body facts,
// and `setHeader("Access-Control-Allow-Origin", "*")` is now a CORS pattern;
// cached v15 facts would keep those routes disconnected from the taint graph.
// v17: complexity facts gain `param_names` (data-clumps detection); cached
// v16 facts would deserialize with empty names and silently skip clumps.
// v18: Rust `?` no longer counts toward cyclomatic; cached v17 facts would
// keep the inflated counts and their stale HighComplexity findings.
// v19: FileFacts gains `capability_uses`; cached v18 facts would deserialize
// empty and every deny_capabilities check would pass vacuously.
// v20: FileFacts gains `parse_errors`; cached v19 facts would deserialize
// `false` and hide the parse-error diagnostic on unchanged files.
const PARSE_CACHE_VERSION: &str = "v20";

pub fn index_repository(
    paths: &ProjectPaths,
    config: &OveccConfig,
    skip_git: bool,
) -> Result<IndexReport> {
    // Phase timings: measured unconditionally, surfaced by `--stats`.
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

    // Loaded before the parse so a broken contract fails in milliseconds,
    // not at the end of a cold index.
    let contract = ArchitectureContract::load(&paths.root)?;

    let source_files = discover_source_files(&paths.root, config)?;
    let cache = ParseCache::new(paths.parse_cache_dir.join(PARSE_CACHE_VERSION));
    cache.ensure_dir()?;
    phase(&mut timings.discovery_ms);

    // Per-file and independent; results keep discovery order for determinism.
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

    let parsed = collect_processed(
        processed,
        &previous_dependencies,
        &repository_id,
        &config.architecture,
    );
    let dependencies = resolve_dependencies(
        paths,
        &repository_id,
        &parsed.files,
        &parsed.by_path,
        &parsed.parsed_imports,
    );
    let resolved = resolve_code_facts(&repository_id, &parsed, &dependencies);
    phase(&mut timings.resolve_ms);

    let snapshot_id = new_snapshot_id(&repository_id);
    let module_records: Vec<ModuleRecord> = parsed.modules.values().cloned().collect();
    let mut metrics = compute_snapshot_metrics(&module_records, &parsed, &resolved, &dependencies);
    let (commit_sha, commits_ingested) = git_metrics(
        &mut store,
        &repository_id,
        &paths.root,
        skip_git,
        &mut metrics,
    )?;

    let entry_points = detect_entry_points(&paths.root, &parsed.files);
    let input = AnalysisInput {
        repository_id: &repository_id,
        snapshot_id: &snapshot_id,
        parsed: &parsed,
        dependencies: &dependencies,
        resolved: &resolved,
        entry_points: &entry_points,
    };
    let indexed_paths: Vec<String> = parsed.files.iter().map(|file| file.path.clone()).collect();
    let component_of = match &contract {
        Some(contract) => assign_components(contract, &indexed_paths)?,
        None => BTreeMap::new(),
    };
    let slice_of = match &contract {
        Some(contract) => assign_slices(contract, &component_of),
        None => BTreeMap::new(),
    };
    // Narrowed to the files this run indexed: a lockfile or a CI config travels
    // with everything and would pair with everything, and the per-commit cap
    // then measures a commit by the code it changed. Recomputed whole rather
    // than incrementally, since a new commit moves the denominator of every
    // pair it touches.
    let co_changes = {
        let indexed: std::collections::HashSet<&str> =
            indexed_paths.iter().map(String::as_str).collect();
        let commit_sets: Vec<ovecc_core::facts::CommitFiles> = store
            .commit_file_sets(&repository_id)?
            .into_iter()
            .map(|mut commit| {
                commit.files.retain(|path| indexed.contains(path.as_str()));
                commit
            })
            .collect();
        ovecc_graph::cochange::co_changed_pairs(
            &commit_sets,
            ovecc_graph::cochange::MIN_SUPPORT,
            ovecc_graph::cochange::MIN_JACCARD,
        )
    };
    // Straight from this run's parse: the `capability_uses`/`complexity` tables
    // are written afterwards, so a cold index would judge them empty.
    let capability_uses: Vec<(String, ovecc_core::facts::CapabilityFact)> = parsed
        .file_facts
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .capability_uses
                .iter()
                .map(move |use_| (path.clone(), use_.clone()))
        })
        .collect();
    let functions: Vec<ovecc_core::facts::FunctionMetricsRow> = parsed
        .file_facts
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .complexity
                .iter()
                .map(move |c| ovecc_core::facts::FunctionMetricsRow {
                    file_path: path.clone(),
                    qualified_name: c.qualified_name.clone(),
                    line: c.line,
                    cyclomatic: c.cyclomatic as u32,
                    cognitive: c.cognitive as u32,
                })
        })
        .collect();
    let baseline = ovecc_core::architecture::load_baseline(&paths.root)?;
    // Read before the rules run, not with the other writes: the contract's
    // `min_coverage` check is one of the rules.
    let coverage = read_coverage(paths, config);
    let coverage_files = coverage.as_ref().map_or(&[][..], |(_, files)| files);
    let architecture_input = contract
        .as_ref()
        .map(|contract| ovecc_rules::ContractInput {
            contract,
            component_of: &component_of,
            files: &indexed_paths,
            baseline: &baseline,
            slice_of: &slice_of,
            capability_uses: &capability_uses,
            functions: &functions,
            co_changes: &co_changes,
            coverage: coverage_files,
        });
    let (mut findings, security_patterns) =
        evaluate_rules(&input, &config.rules, architecture_input);
    findings.extend(taint_findings(&input));
    findings.extend(audit_findings(&mut store, paths, &input)?);
    findings.extend(complexity_findings(&input, &mut metrics));
    findings.extend(deadcode_findings(&input, &mut metrics));
    findings.extend(hygiene_findings(
        &paths.root,
        &input,
        config.index.detect_unused_deps,
        &mut metrics,
    ));
    findings.extend(smell_findings(&input, &mut metrics));
    downrank_test_security(&mut findings, &security_patterns);
    downrank_test_complexity(&mut findings);
    apply_suppressions(&mut findings, &input, &mut metrics);
    finalize_findings(&mut findings, &mut metrics);

    let external_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.is_external)
        .count();
    let (schema_edges, complexity_records, export_records, capability_records) =
        build_code_records(&input);
    let code = ResolvedCode {
        symbols: &resolved.symbols,
        calls: &resolved.calls,
        apis: &resolved.apis,
        schema_objects: &resolved.schema_objects,
        schema_edges: &schema_edges,
        complexity: &complexity_records,
        exports: &export_records,
        capability_uses: &capability_records,
    };
    phase(&mut timings.analyze_ms);
    store.sync_current_index(
        &repository_id,
        &paths.root_display(),
        &module_records,
        &parsed.files,
        &dependencies,
        &snapshot_id,
        commit_sha.as_deref(),
        &metrics,
        &code,
    )?;
    store.replace_co_changes(&repository_id, &co_changes)?;
    store.replace_findings(&repository_id, &findings)?;
    // A tracefile that could not be used leaves the previous run's coverage
    // alone: wiping it because today's read failed would report the tests as
    // gone rather than the file as unreadable.
    if let Some((_, files)) = coverage
        .as_ref()
        .filter(|(ingest, _)| ingest.error.is_none())
    {
        store.replace_coverage(&repository_id, files)?;
    }
    phase(&mut timings.persist_ms);
    timings.total_ms = run_start.elapsed().as_millis() as u64;

    Ok(IndexReport {
        repository_root: paths.root_display(),
        database_path: ovecc_core::util::normalize_path(&paths.db_path),
        snapshot_id,
        files_scanned: source_files.len(),
        files_indexed: parsed.files.len(),
        files_parsed: parsed.files_parsed,
        files_from_cache: parsed.files_from_cache,
        modules: parsed.modules.len(),
        dependencies: dependencies.len(),
        external_dependencies,
        symbols: resolved.symbols.len(),
        calls: resolved.calls.len(),
        apis: resolved.apis.len(),
        tables: resolved.schema_objects.len(),
        commits_ingested,
        files_with_parse_errors: parsed
            .file_facts
            .values()
            .filter(|facts| facts.parse_errors)
            .count(),
        parse_failures: parsed.parse_failures,
        coverage: coverage.map(|(ingest, _)| ingest),
        timings,
    })
}

/// The per-file parse outcomes folded into the index's working set: file and
/// module records, retained imports, and grammar-level facts.
struct ParsedFiles {
    files: Vec<FileRecord>,
    by_path: HashMap<String, FileRecord>,
    modules: BTreeMap<String, ModuleRecord>,
    parsed_imports: HashMap<String, Vec<ImportFact>>,
    file_facts: HashMap<String, FileFacts>,
    parse_failures: Vec<IndexFailure>,
    files_parsed: usize,
    files_from_cache: usize,
}

fn collect_processed(
    processed: Vec<ProcessedFile>,
    previous_dependencies: &[DependencyRecord],
    repository_id: &str,
    architecture: &ArchitectureConfig,
) -> ParsedFiles {
    let mut parsed = ParsedFiles {
        files: Vec::new(),
        by_path: HashMap::new(),
        modules: BTreeMap::new(),
        parsed_imports: HashMap::new(),
        file_facts: HashMap::new(),
        parse_failures: Vec::new(),
        files_parsed: 0,
        files_from_cache: 0,
    };
    for outcome in processed {
        let parse_failed = outcome.failure.is_some() && outcome.file.is_some();
        if let Some(failure) = outcome.failure {
            parsed.parse_failures.push(failure);
        }
        let Some(file) = outcome.file else {
            // Unreadable file: reported above, treated as absent.
            continue;
        };
        if outcome.parsed {
            parsed.files_parsed += 1;
        }
        if outcome.from_cache {
            parsed.files_from_cache += 1;
        }

        parsed
            .modules
            .entry(file.module_name.clone())
            .or_insert_with(|| ModuleRecord {
                id: file.module_id.clone(),
                repository_id: repository_id.to_string(),
                name: file.module_name.clone(),
                path_prefix: infer_module_prefix(&file.path, architecture),
            });

        let imports = if parse_failed {
            // Do not pretend the file suddenly has zero dependencies.
            retained_imports(previous_dependencies, &file.path)
        } else {
            outcome.imports
        };
        parsed.parsed_imports.insert(file.path.clone(), imports);
        // On parse failure `facts` is empty: only the module graph survives,
        // via `parsed_imports` above.
        parsed.file_facts.insert(file.path.clone(), outcome.facts);
        parsed.by_path.insert(file.path.clone(), file.clone());
        parsed.files.push(file);
    }
    parsed
}

/// Code-fact resolution: per-file import bindings, then grammar-level facts
/// into typed records with a linked call graph. Bindings reuse the resolved
/// dependency edges, so calls through aliased (`@/x`) and monorepo
/// (`@scope/pkg`) imports link too, not just relative ones.
fn resolve_code_facts(
    repository_id: &str,
    parsed: &ParsedFiles,
    dependencies: &[DependencyRecord],
) -> resolve::ResolvedFacts {
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
    let bindings_by_path: HashMap<String, Vec<ImportBinding>> = parsed
        .files
        .iter()
        .map(|file| {
            let bindings = parsed
                .file_facts
                .get(&file.path)
                .map(|facts| build_import_bindings(file, facts, &resolved_targets))
                .unwrap_or_default();
            (file.path.clone(), bindings)
        })
        .collect();
    let units: Vec<ResolveUnit<'_>> = parsed
        .files
        .iter()
        .filter_map(|file| {
            let facts = parsed.file_facts.get(&file.path)?;
            let bindings = bindings_by_path
                .get(&file.path)
                .map(|b| b.as_slice())
                .unwrap_or(&[]);
            Some(ResolveUnit {
                file_id: file.id.as_str(),
                repository_id,
                path: file.path.as_str(),
                module_id: file.module_id.as_str(),
                language: core_language(file.language),
                facts,
                import_bindings: bindings,
            })
        })
        .collect();
    resolve::resolve_facts(&units)
}

fn new_snapshot_id(repository_id: &str) -> String {
    stable_id(
        "snapshot",
        &[
            repository_id,
            &Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .to_string(),
        ],
    )
}

/// Native Git ingestion: pull recent commits + changed files, persist them,
/// and derive the ownership metrics.
fn git_metrics(
    store: &mut ArchitectureStore,
    repository_id: &str,
    root: &Path,
    skip_git: bool,
    metrics: &mut Vec<(String, f64)>,
) -> Result<(Option<String>, usize)> {
    let (commit_sha, commits_ingested) = if skip_git {
        (None, 0)
    } else {
        let (head_sha, ingested, ownership) = ingest_git(store, repository_id, root)?;
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
    Ok((commit_sha, commits_ingested))
}

/// Read-only inputs every finding phase shares: the snapshot identity plus
/// the parsed, resolved, and entry-point views of the repository.
struct AnalysisInput<'a> {
    repository_id: &'a str,
    snapshot_id: &'a str,
    parsed: &'a ParsedFiles,
    dependencies: &'a [DependencyRecord],
    resolved: &'a resolve::ResolvedFacts,
    entry_points: &'a HashSet<String>,
}

/// Turns the architecture into findings. Also returns the flattened per-file
/// security patterns, for the test-code down-ranking pass.
fn evaluate_rules(
    input: &AnalysisInput<'_>,
    config: &RulesConfig,
    architecture: Option<ovecc_rules::ContractInput<'_>>,
) -> (Vec<FindingRecord>, Vec<(String, SecurityPatternFact)>) {
    let module_names: Vec<String> = input.parsed.modules.keys().cloned().collect();
    let security_patterns: Vec<(String, SecurityPatternFact)> = input
        .parsed
        .file_facts
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .security_patterns
                .iter()
                .map(move |pattern| (path.clone(), pattern.clone()))
        })
        .collect();
    let findings = ovecc_rules::evaluate(&ovecc_rules::RuleInput {
        repository_id: input.repository_id,
        snapshot_id: Some(input.snapshot_id),
        modules: &module_names,
        dependencies: input.dependencies,
        config,
        security_patterns: &security_patterns,
        architecture,
    });
    (findings, security_patterns)
}

/// Source→sink taint reachability over the code graph (SQL + eval/exec),
/// with endpoint locations so findings cite real file:line evidence.
fn taint_findings(input: &AnalysisInput<'_>) -> Vec<FindingRecord> {
    let resolved = input.resolved;
    let (flow_nodes, flow_edges) = build_flow_graph(resolved);
    let dangerous_sinks: Vec<(String, String)> = resolved
        .dangerous_sinks
        .iter()
        .map(|sink| (sink.symbol_id.clone(), sink.label.clone()))
        .collect();
    let mut flow_locations = ovecc_dataflow::FlowLocations::default();
    for api in &resolved.apis {
        if let Some(evidence) = &api.evidence {
            flow_locations
                .apis
                .insert(api.id.0.clone(), evidence.clone());
        }
    }
    for access in &resolved.schema_accesses {
        flow_locations
            .db_accesses
            .entry((access.accessor_symbol_id.clone(), access.table_id.clone()))
            .or_insert_with(|| access.evidence.clone());
    }
    for sink in &resolved.dangerous_sinks {
        flow_locations
            .dangerous
            .entry(sink.symbol_id.clone())
            .or_insert_with(|| sink.evidence.clone());
    }
    ovecc_dataflow::analyze(
        input.repository_id,
        Some(input.snapshot_id),
        &flow_nodes,
        &flow_edges,
        &dangerous_sinks,
        &flow_locations,
        ovecc_dataflow::DEFAULT_FLOW_DEPTH,
    )
}

/// Offline OSV dependency audit: inventory packages from lockfiles, persist
/// them, and match against the local OSV database (`.ovecc/osv/`).
fn audit_findings(
    store: &mut ArchitectureStore,
    paths: &ProjectPaths,
    input: &AnalysisInput<'_>,
) -> Result<Vec<FindingRecord>> {
    let packages = ovecc_audit::discover_packages(&paths.root).packages;
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
    store.replace_packages(input.repository_id, &package_rows)?;
    let osv = ovecc_audit::load_osv_dir(&paths.ovecc_dir.join("osv"));
    Ok(ovecc_audit::audit(
        input.repository_id,
        Some(input.snapshot_id),
        &packages,
        &osv,
    ))
}

/// Complexity (oxc cyclomatic + cognitive) findings for functions over the
/// maintainability thresholds, plus the aggregate complexity metrics.
fn complexity_findings(
    input: &AnalysisInput<'_>,
    metrics: &mut Vec<(String, f64)>,
) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    let (mut max_cyclomatic, mut max_cognitive, mut function_count) = (0u16, 0u16, 0usize);
    let mut total_cognitive: u64 = 0;
    let mut high_complexity_functions: usize = 0;
    for (path, facts) in &input.parsed.file_facts {
        for complexity in &facts.complexity {
            function_count += 1;
            max_cyclomatic = max_cyclomatic.max(complexity.cyclomatic);
            max_cognitive = max_cognitive.max(complexity.cognitive);
            total_cognitive += complexity.cognitive as u64;
            findings.extend(long_function_finding(input, path, complexity));
            findings.extend(long_parameter_list_finding(input, path, complexity));
            if let Some(finding) = high_complexity_finding(input, path, complexity) {
                high_complexity_functions += 1;
                findings.push(finding);
            }
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
    findings
}

/// Unit size (Long Method), independent of the branching thresholds: a
/// linear-but-endless function is a maintainability risk too. Capped at Medium,
/// so it informs without tripping a high-severity gate.
fn long_function_finding(
    input: &AnalysisInput<'_>,
    path: &str,
    complexity: &ovecc_core::facts::ComplexityFact,
) -> Option<FindingRecord> {
    if complexity.line_count < 75 {
        return None;
    }
    let severity = if complexity.line_count >= 150 {
        ovecc_core::facts::Severity::Medium
    } else {
        ovecc_core::facts::Severity::Low
    };
    Some(function_metric_finding(
        input.repository_id,
        input.snapshot_id,
        path,
        complexity,
        ovecc_core::facts::FindingKind::LongFunction,
        "long-function",
        severity,
        format!(
            "Long function: {} ({} lines)",
            complexity.qualified_name, complexity.line_count
        ),
        format!(
            "{} at {}:{} spans {} source lines; extract cohesive sections into named helpers.",
            complexity.qualified_name, path, complexity.line, complexity.line_count
        ),
        format!("{} lines", complexity.line_count),
    ))
}

/// Long Parameter List — same shape: 7+ informs, 10+ is a real smell.
fn long_parameter_list_finding(
    input: &AnalysisInput<'_>,
    path: &str,
    complexity: &ovecc_core::facts::ComplexityFact,
) -> Option<FindingRecord> {
    if complexity.param_count < 7 {
        return None;
    }
    let severity = if complexity.param_count >= 10 {
        ovecc_core::facts::Severity::Medium
    } else {
        ovecc_core::facts::Severity::Low
    };
    Some(function_metric_finding(
        input.repository_id,
        input.snapshot_id,
        path,
        complexity,
        ovecc_core::facts::FindingKind::LongParameterList,
        "long-parameter-list",
        severity,
        format!(
            "Long parameter list: {} ({} parameters)",
            complexity.qualified_name, complexity.param_count
        ),
        format!(
            "{} at {}:{} takes {} parameters; group related ones into a typed options object.",
            complexity.qualified_name, path, complexity.line, complexity.param_count
        ),
        format!("{} parameters", complexity.param_count),
    ))
}

fn high_complexity_finding(
    input: &AnalysisInput<'_>,
    path: &str,
    complexity: &ovecc_core::facts::ComplexityFact,
) -> Option<FindingRecord> {
    // Severity follows cognitive complexity, not the branch count: a flat
    // exhaustive `match` has one path per arm yet nothing to track. Scoring
    // branches as High flagged our own dispatch and classifiers, long but not
    // complex. Cyclomatic still raises Medium, for a glance.
    let severity = if complexity.cognitive >= 25 {
        ovecc_core::facts::Severity::High
    } else if complexity.cognitive >= 15 || complexity.cyclomatic >= 10 {
        ovecc_core::facts::Severity::Medium
    } else {
        return None;
    };
    Some(FindingRecord {
        id: ovecc_core::id::FindingId::from_parts(&[
            input.repository_id,
            "complexity",
            path,
            &complexity.line.to_string(),
            &complexity.qualified_name,
        ]),
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(input.snapshot_id)),
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
            file_path: path.to_string(),
            line: Some(complexity.line),
            symbol: Some(complexity.qualified_name.clone()),
            detail: Some(format!(
                "cyclomatic {}, cognitive {}",
                complexity.cyclomatic, complexity.cognitive
            )),
        }],
        created_at: chrono::Utc::now(),
    })
}

/// Dead-code analysis (unused exports/files) over the in-memory facts: oxc
/// exports + resolved internal import edges (carrying the imported names) +
/// detected entry points.
fn deadcode_findings(
    input: &AnalysisInput<'_>,
    metrics: &mut Vec<(String, f64)>,
) -> Vec<FindingRecord> {
    let all_files: Vec<String> = input
        .parsed
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let export_facts: Vec<(String, ovecc_core::facts::ExportFact)> = input
        .parsed
        .file_facts
        .iter()
        .flat_map(|(path, facts)| {
            facts
                .exports
                .iter()
                .map(move |export| (path.clone(), export.clone()))
        })
        .collect();
    let import_edges: Vec<ovecc_rules::deadcode::ImportEdge> = input
        .dependencies
        .iter()
        .filter_map(|dependency| {
            let target = dependency.target_file_path.clone()?;
            if dependency.is_external {
                return None;
            }
            let names: Vec<String> = input
                .parsed
                .file_facts
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
    let findings = ovecc_rules::deadcode::analyze(&ovecc_rules::deadcode::DeadCodeInput {
        repository_id: input.repository_id,
        snapshot_id: Some(input.snapshot_id),
        files: &all_files,
        entry_points: input.entry_points,
        exports: &export_facts,
        imports: &import_edges,
    });
    let unused_exports = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::UnusedExport)
        .count();
    let unused_files = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::UnusedFile)
        .count();
    metrics.push(("unused_exports".to_string(), unused_exports as f64));
    metrics.push(("unused_files".to_string(), unused_files as f64));
    metrics.push((
        "deadcode_entry_points".to_string(),
        input.entry_points.len() as f64,
    ));
    findings
}

/// Dependency-hygiene findings. Unused dependencies are opt-in
/// (`detect_unused_deps`): measured false-positive rate is high, since config
/// files, `scripts` entries and test fixtures use a package without an import
/// the graph can see. Phantom dependencies are precise, so always on.
fn hygiene_findings(
    root: &Path,
    input: &AnalysisInput<'_>,
    detect_unused: bool,
    metrics: &mut Vec<(String, f64)>,
) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    if detect_unused {
        // Any bare-specifier import counts as using the package, including a
        // workspace package that resolves to an internal file, so monorepo
        // packages are not falsely flagged.
        let imported_roots: HashSet<String> = input
            .dependencies
            .iter()
            .filter_map(|dependency| external_package_root(&dependency.specifier))
            .collect();
        let unused = detect_unused_dependencies(
            root,
            input.repository_id,
            input.snapshot_id,
            &imported_roots,
        );
        metrics.push(("unused_dependencies".to_string(), unused.len() as f64));
        findings.extend(unused);
    }
    let unlisted = detect_unlisted_dependencies(
        root,
        input.repository_id,
        input.snapshot_id,
        input.dependencies,
    );
    metrics.push(("unlisted_dependencies".to_string(), unlisted.len() as f64));
    findings.extend(unlisted);
    findings
}

/// Code smells (feature envy, data clumps) over the resolved call graph and
/// the per-function parameter names.
fn smell_findings(
    input: &AnalysisInput<'_>,
    metrics: &mut Vec<(String, f64)>,
) -> Vec<FindingRecord> {
    let module_name_by_id: HashMap<String, String> = input
        .parsed
        .modules
        .values()
        .map(|module| (module.id.clone(), module.name.clone()))
        .collect();
    let path_by_file_id: HashMap<String, String> = input
        .parsed
        .files
        .iter()
        .map(|file| (file.id.clone(), file.path.clone()))
        .collect();
    let clump_functions: Vec<ovecc_rules::smells::ClumpFunction> = input
        .parsed
        .files
        .iter()
        .flat_map(|file| {
            let language = core_language(file.language);
            input
                .parsed
                .file_facts
                .get(&file.path)
                .into_iter()
                .flat_map(move |facts| {
                    facts.complexity.iter().map(move |complexity| {
                        ovecc_rules::smells::ClumpFunction {
                            path: file.path.clone(),
                            language,
                            qualified_name: complexity.qualified_name.clone(),
                            line: complexity.line,
                            param_names: complexity.param_names.clone(),
                        }
                    })
                })
        })
        .collect();
    let findings = ovecc_rules::smells::analyze(&ovecc_rules::smells::SmellsInput {
        repository_id: input.repository_id,
        snapshot_id: Some(input.snapshot_id),
        symbols: &input.resolved.symbols,
        calls: &input.resolved.calls,
        module_names: &module_name_by_id,
        file_paths: &path_by_file_id,
        entry_points: input.entry_points,
        functions: &clump_functions,
    });
    metrics.push(("code_smells".to_string(), findings.len() as f64));
    findings
}

/// Security findings in test, fixture, and example files are usually test data
/// or deliberate scaffolding: the canonical secret/SAST false positive. Down to
/// Low, not dropped. Rust's inline `#[cfg(test)]` scopes are invisible to the
/// path heuristics, so the parser stamps those (file, line) sites instead.
fn downrank_test_security(
    findings: &mut [FindingRecord],
    security_patterns: &[(String, SecurityPatternFact)],
) {
    let test_scoped_patterns: HashSet<(&str, u32)> = security_patterns
        .iter()
        .filter(|(_, pattern)| pattern.in_test_code)
        .map(|(path, pattern)| (path.as_str(), pattern.line))
        .collect();
    for finding in findings.iter_mut() {
        let is_security = matches!(
            finding.kind,
            FindingKind::HardcodedSecret | FindingKind::InsecurePattern | FindingKind::WeakCrypto
        );
        if is_security
            && finding.severity != ovecc_core::facts::Severity::Low
            && finding.evidence.iter().any(|evidence| {
                is_test_file(&evidence.file_path)
                    || is_standalone_entry(&evidence.file_path)
                    || evidence.line.is_some_and(|line| {
                        test_scoped_patterns.contains(&(evidence.file_path.as_str(), line))
                    })
            })
        {
            finding.severity = ovecc_core::facts::Severity::Low;
        }
    }
}

/// A long or complex test function is scaffolding, not production debt: a
/// table-driven test legitimately runs long. Down to Low, not dropped, so
/// `health` leads with production hotspots.
fn downrank_test_complexity(findings: &mut [FindingRecord]) {
    for finding in findings.iter_mut() {
        let is_code_health = matches!(
            finding.kind,
            FindingKind::HighComplexity
                | FindingKind::LongFunction
                | FindingKind::LongParameterList
        );
        if is_code_health
            && finding.severity != ovecc_core::facts::Severity::Low
            && finding
                .evidence
                .iter()
                .any(|evidence| is_test_file(&evidence.file_path))
        {
            finding.severity = ovecc_core::facts::Severity::Low;
        }
    }
}

/// Drops findings explicitly suppressed by an inline `// ovecc-ignore`
/// (`# ovecc-ignore` in Python) and surfaces the stale suppressions.
fn apply_suppressions(
    findings: &mut Vec<FindingRecord>,
    input: &AnalysisInput<'_>,
    metrics: &mut Vec<(String, f64)>,
) {
    // BTreeMap so the stale-suppression sweep below iterates deterministically.
    let suppressions: BTreeMap<String, BTreeSet<u32>> = input
        .parsed
        .file_facts
        .iter()
        .filter(|(_, facts)| !facts.suppressed_lines.is_empty())
        .map(|(path, facts)| {
            (
                path.clone(),
                facts.suppressed_lines.iter().copied().collect(),
            )
        })
        .collect();
    if suppressions.is_empty() {
        return;
    }
    let mut used: HashSet<(String, u32)> = HashSet::new();
    findings.retain(|finding| {
        let mut suppressed = false;
        for evidence in &finding.evidence {
            if let Some(line) = evidence.line
                && suppressions
                    .get(&evidence.file_path)
                    .is_some_and(|lines| lines.contains(&line))
            {
                used.insert((evidence.file_path.clone(), line));
                suppressed = true;
            }
        }
        !suppressed
    });
    // A suppression that silenced nothing is stale: it will swallow the next
    // real finding on its line.
    let mut stale = 0usize;
    for (path, lines) in &suppressions {
        for line in lines {
            if used.contains(&(path.clone(), *line)) {
                continue;
            }
            stale += 1;
            findings.push(stale_suppression_finding(input, path, *line));
        }
    }
    metrics.push(("stale_suppressions".to_string(), stale as f64));
}

fn stale_suppression_finding(input: &AnalysisInput<'_>, path: &str, line: u32) -> FindingRecord {
    FindingRecord {
        id: ovecc_core::id::FindingId::from_parts(&[
            input.repository_id,
            "stale-suppression",
            path,
            &line.to_string(),
        ]),
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(input.snapshot_id)),
        kind: FindingKind::StaleSuppression,
        severity: ovecc_core::facts::Severity::Low,
        rule_name: Some("stale-suppression".to_string()),
        target: None,
        title: format!("Stale suppression: {path}:{line}"),
        description: format!(
            "The ovecc-ignore targeting {path}:{line} suppresses no finding. \
             Delete it — a stale suppression silently swallows the next real \
             finding on that line."
        ),
        evidence: vec![ovecc_core::facts::Evidence {
            file_path: path.to_string(),
            line: Some(line),
            symbol: None,
            detail: Some("ovecc-ignore with no matching finding".to_string()),
        }],
        created_at: chrono::Utc::now(),
    }
}

/// A stable finding ID encodes rule + target + location, so two findings with
/// the same ID are the same finding. Collapse them: `findings.id` is a primary
/// key.
fn finalize_findings(findings: &mut Vec<FindingRecord>, metrics: &mut Vec<(String, f64)>) {
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
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
    // Code security only. Folding in OSV advisories would tie the trend to when
    // advisories were last fetched, so `drift` would report worsening on a
    // commit that merely ran `audit --fetch`.
    let security_findings = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::HardcodedSecret
                    | FindingKind::InsecurePattern
                    | FindingKind::WeakCrypto
                    | FindingKind::PermissiveCors
                    | FindingKind::TaintedFlow
            )
        })
        .count();
    let dependency_advisories = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::VulnerableDependency)
        .count();
    metrics.push((
        "boundary_violations".to_string(),
        boundary_violations as f64,
    ));
    metrics.push(("security_findings".to_string(), security_findings as f64));
    metrics.push((
        "dependency_advisories".to_string(),
        dependency_advisories as f64,
    ));
}

/// Persistence records derived from the resolved code facts: symbol→table
/// access edges, per-function complexity, per-file exports, keyed by file id.
fn build_code_records(
    input: &AnalysisInput<'_>,
) -> (
    Vec<ovecc_db::SchemaEdge>,
    Vec<ComplexityRecord>,
    Vec<ExportRecord>,
    Vec<CapabilityRecord>,
) {
    let schema_edges: Vec<ovecc_db::SchemaEdge> = input
        .resolved
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
    let mut complexity_records: Vec<ComplexityRecord> = Vec::new();
    let mut export_records: Vec<ExportRecord> = Vec::new();
    let mut capability_records: Vec<CapabilityRecord> = Vec::new();
    for (path, facts) in &input.parsed.file_facts {
        let Some(file) = input.parsed.by_path.get(path) else {
            continue;
        };
        let file_id = &file.id;
        for complexity in &facts.complexity {
            complexity_records.push(ComplexityRecord {
                id: ComplexityId::from_parts(&[
                    input.repository_id,
                    file_id,
                    &complexity.qualified_name,
                    &complexity.line.to_string(),
                ]),
                repository_id: RepositoryId::from_raw(input.repository_id),
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
                    input.repository_id,
                    file_id,
                    &export.name,
                    &export.line.to_string(),
                ]),
                repository_id: RepositoryId::from_raw(input.repository_id),
                file_id: FileId::from_raw(file_id.clone()),
                name: export.name.clone(),
                line: export.line,
                is_type_only: export.is_type_only,
                re_export_source: export
                    .re_export
                    .as_ref()
                    .map(|r| r.source_specifier.clone()),
                re_export_name: export.re_export.as_ref().map(|r| r.imported_name.clone()),
            });
        }
        for use_ in &facts.capability_uses {
            capability_records.push(CapabilityRecord {
                id: CapabilityUseId::from_parts(&[
                    input.repository_id,
                    file_id,
                    use_.capability.as_str(),
                    &use_.api,
                ]),
                repository_id: RepositoryId::from_raw(input.repository_id),
                file_id: FileId::from_raw(file_id.clone()),
                capability: use_.capability,
                api: use_.api.clone(),
                line: use_.line,
                count: use_.count,
            });
        }
    }
    (
        schema_edges,
        complexity_records,
        export_records,
        capability_records,
    )
}

/// Recent-history window and cap for Git ingestion: current ownership does not
/// need a decade of history.
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
        let fix = ovecc_git::classify_fix_message(commit.message.as_deref().unwrap_or(""));
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
            is_fix: fix.is_fix,
            fix_confidence: fix.confidence,
        });
        for change in &commit.changes {
            changes.push(FileChangeRecord {
                id: FileChangeId::from_parts(&[repository_id, &commit.sha, &change.path]),
                repository_id: RepositoryId::from_raw(repository_id),
                commit_id: commit_id.clone(),
                file_path: change.path.clone(),
                kind: map_change_kind(change.kind),
                previous_path: change.previous_path.clone(),
                additions: None,
                deletions: None,
            });
        }
    }
    let ingested = store.upsert_git_facts(repository_id, &commits, &changes)?;
    backfill_fix_classification(store, repository_id)?;
    let ownership = store.ownership_metrics(repository_id)?;
    Ok((history.head_sha, ingested, ownership))
}

/// Classifies commits stored before the `is_fix` columns existed, from the
/// persisted message. Only unclassified rows are touched: retuning the
/// classifier never restates an old verdict.
fn backfill_fix_classification(store: &mut ArchitectureStore, repository_id: &str) -> Result<()> {
    let pending = store.unclassified_commits(repository_id)?;
    if pending.is_empty() {
        return Ok(());
    }
    let classified: Vec<(String, bool, f64)> = pending
        .into_iter()
        .map(|(id, message)| {
            let fix = ovecc_git::classify_fix_message(&message);
            (id, fix.is_fix, fix.confidence as f64)
        })
        .collect();
    store.set_fix_classification(&classified)
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
            file: None,
            line: None,
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
            file: None,
            line: None,
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
            file: None,
            line: None,
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
    parsed: bool,
    from_cache: bool,
    failure: Option<IndexFailure>,
}

/// Reads line coverage for this run: the configured tracefile, or the first
/// conventional location that exists.
///
/// A missing tracefile is not an error — most repositories have none, and CI
/// that indexes before it tests has none yet — so auto-detection finding
/// nothing returns `None`. A tracefile that *was* named and cannot be used says
/// so, because a silent zero here reads as "the tests cover nothing".
fn read_coverage(
    paths: &ProjectPaths,
    config: &OveccConfig,
) -> Option<(CoverageIngest, Vec<FileCoverage>)> {
    let path = match config.index.coverage.as_deref() {
        Some(configured) => configured.to_string(),
        None => DEFAULT_COVERAGE_PATHS
            .iter()
            .find(|name| paths.root.join(name).is_file())?
            .to_string(),
    };
    let fail = |error: String| {
        Some((
            CoverageIngest {
                path: path.clone(),
                files: 0,
                error: Some(error),
            },
            Vec::new(),
        ))
    };
    let content = match std::fs::read_to_string(paths.root.join(&path)) {
        Ok(content) => content,
        Err(error) => return fail(format!("{error}")),
    };
    let files = ovecc_core::coverage::parse_lcov(&content, &paths.root);
    if files.is_empty() {
        return fail("no source file in the tracefile sits under this repository".to_string());
    }
    Some((
        CoverageIngest {
            path,
            files: files.len(),
            error: None,
        },
        files,
    ))
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
            // Exports and per-function complexity come from oxc: tree-sitter
            // cannot produce them. oxc stays behind the parser boundary.
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
                ImportFactKind::Static => ImportKind::Static,
                // Preserved as its own kind: type-only imports are erased at
                // runtime, so cycle detection must be able to exclude them.
                ImportFactKind::TypeOnly => ImportKind::Type,
                ImportFactKind::ReExport => ImportKind::Export,
                ImportFactKind::Require => ImportKind::Require,
                ImportFactKind::Dynamic => ImportKind::Dynamic,
            },
        })
        .collect()
}

/// Imported-name → target-file bindings for one file, for cross-file callee
/// resolution.
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
/// renames and branch switches still hit. Corrupted entries fall back to a
/// re-parse; writes are best-effort and never fail the run.
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
        // target can already exist here, since load() missed) are removed first.
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

/// Snapshot metrics persisted with each index run: the structural counts
/// (computed with `ovecc-graph`) plus the parser and code-fact counts.
fn compute_snapshot_metrics(
    modules: &[ModuleRecord],
    parsed: &ParsedFiles,
    resolved: &resolve::ResolvedFacts,
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
        ("files".to_string(), parsed.files.len() as f64),
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
        (
            "parse_failures".to_string(),
            parsed.parse_failures.len() as f64,
        ),
        ("symbols".to_string(), resolved.symbols.len() as f64),
        ("calls".to_string(), resolved.calls.len() as f64),
        ("apis".to_string(), resolved.apis.len() as f64),
        ("tables".to_string(), resolved.schema_objects.len() as f64),
    ]
}

/// Tokenizes every indexed source file into a normalized token stream for
/// clone detection. Same discovery and excludes as `index`, so `dupes` sees
/// exactly the indexed set. Best-effort: unreadable files are skipped.
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

/// One per-function metric finding (long function, long parameter list) with
/// the standard `file:line — symbol` evidence shape.
#[allow(clippy::too_many_arguments)] // flat finding fields; a builder would obscure it
fn function_metric_finding(
    repository_id: &str,
    snapshot_id: &str,
    path: &str,
    complexity: &ovecc_core::facts::ComplexityFact,
    kind: FindingKind,
    rule_name: &str,
    severity: ovecc_core::facts::Severity,
    title: String,
    description: String,
    detail: String,
) -> ovecc_core::facts::FindingRecord {
    ovecc_core::facts::FindingRecord {
        id: ovecc_core::id::FindingId::from_parts(&[
            repository_id,
            rule_name,
            path,
            &complexity.line.to_string(),
            &complexity.qualified_name,
        ]),
        repository_id: RepositoryId::from_raw(repository_id),
        snapshot_id: Some(ovecc_core::id::SnapshotId::from_raw(snapshot_id)),
        kind,
        severity,
        rule_name: Some(rule_name.to_string()),
        target: None,
        title,
        description,
        evidence: vec![ovecc_core::facts::Evidence {
            file_path: path.to_string(),
            line: Some(complexity.line),
            symbol: Some(complexity.qualified_name.clone()),
            detail: Some(detail),
        }],
        created_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_complexity_findings_are_downranked_to_low() {
        use ovecc_core::facts::{Evidence, Severity};
        let finding = |path: &str| FindingRecord {
            id: ovecc_core::id::FindingId::from_parts(&["r", "complexity", path]),
            repository_id: RepositoryId::from_raw("r"),
            snapshot_id: None,
            kind: FindingKind::HighComplexity,
            severity: Severity::High,
            rule_name: Some("complexity".to_string()),
            target: None,
            title: "High complexity".to_string(),
            description: String::new(),
            evidence: vec![Evidence {
                file_path: path.to_string(),
                line: Some(1),
                symbol: None,
                detail: None,
            }],
            created_at: chrono::Utc::now(),
        };
        let mut findings = vec![
            finding("src/billing/service.ts"),
            finding("src/billing/service.test.ts"),
        ];
        downrank_test_complexity(&mut findings);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "production stays High"
        );
        assert_eq!(
            findings[1].severity,
            Severity::Low,
            "a complex test function is scaffolding, down-ranked to Low"
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
    fn stale_suppressions_are_flagged_and_active_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        // Line 1 suppresses the real secret on line 2 (active). The trailing
        // ignore on line 3 suppresses nothing (stale).
        std::fs::write(
            dir.path().join("src").join("a.ts"),
            "// ovecc-ignore-next-line\nconst k = \"AKIAIOSFODNN7EXAMPLB\";\nconst x = 1; // ovecc-ignore\n",
        )
        .unwrap();
        let paths = ProjectPaths::resolve(dir.path()).unwrap();
        let config = OveccConfig::default();
        index_repository(&paths, &config, true).unwrap();

        let store = ovecc_db::ArchitectureStore::open(&paths.db_path).unwrap();
        let findings = store.findings(&paths.repository_id().0, None).unwrap();
        let stale: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_name.as_deref() == Some("stale-suppression"))
            .collect();
        assert_eq!(stale.len(), 1, "{findings:?}");
        assert_eq!(stale[0].evidence[0].line, Some(3));
        // The active suppression silenced the secret without going stale.
        assert!(
            findings
                .iter()
                .all(|f| f.kind != FindingKind::HardcodedSecret),
            "{findings:?}"
        );
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

    #[test]
    fn ingested_commits_carry_their_fix_classification() {
        fn git(root: &Path, args: &[&str]) {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .expect("run git");
            assert!(status.success(), "git {args:?}");
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "dev@example.com"]);
        git(root, &["config", "user.name", "Dev"]);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("a.ts"), "export const a = 1;\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "add the a module"]);
        std::fs::write(root.join("src").join("a.ts"), "export const a = 2;\n").unwrap();
        git(root, &["add", "."]);
        git(
            root,
            &["commit", "-q", "-m", "fix: a crashed on an empty input"],
        );

        let paths = ProjectPaths::resolve(root).unwrap();
        index_repository(&paths, &OveccConfig::default(), false).unwrap();

        let repository_id = paths.repository_id().0;
        let store = ovecc_db::ArchitectureStore::open(&paths.db_path).unwrap();
        assert_eq!(store.count_rows("commits", &repository_id).unwrap(), 2);
        assert!(
            store
                .unclassified_commits(&repository_id)
                .unwrap()
                .is_empty(),
            "indexing must classify every commit it ingests"
        );
    }
}
