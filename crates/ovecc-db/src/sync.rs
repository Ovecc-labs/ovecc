//! The write path: differential sync of the extracted facts keyed by stable
//! IDs, plus the per-run replacement of Git facts, findings, and packages.

use crate::{ArchitectureStore, PackageRow, ResolvedCode, SyncStats, collect_rows, enum_str};
use anyhow::Result;
use chrono::Utc;
use duckdb::{Transaction, params};
use ovecc_core::facts::{ApiRecord, CommitRecord, FileChangeRecord, FindingRecord};
use ovecc_core::legacy::{DependencyRecord, FileRecord, ModuleRecord};
use ovecc_core::util::stable_id;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Stable, snapshot-independent content identity of a finding, so the *same*
/// defect in two snapshots collapses to one key and a set-difference yields the
/// genuinely new ones. Keyed by kind + first-evidence location (path, then the
/// enclosing symbol when known, else the pattern detail, else the line) + rule
/// — stable across unrelated edits elsewhere in the repo, where the volatile
/// per-run `FindingId` is not. Line numbers are the locator of last resort:
/// identifying by line blames a finding that merely *moved* (an edit above it)
/// on the change under review. `ordinal` disambiguates several otherwise
/// identical findings (e.g. two `eval` calls in one file), so only the extra
/// occurrence reads as new.
fn finding_identity(finding: &FindingRecord, ordinal: usize) -> String {
    let kind = enum_str(&finding.kind);
    let rule = finding.rule_name.clone().unwrap_or_default();
    let (path, locator) = match finding.evidence.first() {
        Some(evidence) => {
            let locator = evidence
                .symbol
                .clone()
                .or_else(|| evidence.detail.clone())
                .or_else(|| evidence.line.map(|line| line.to_string()))
                .unwrap_or_default();
            (evidence.file_path.clone(), locator)
        }
        // Evidence-free findings (rare) fall back to target id + title.
        None => (
            finding
                .target
                .as_ref()
                .map(|target| target.id.clone())
                .unwrap_or_default(),
            finding.title.clone(),
        ),
    };
    stable_id(
        "finding-identity",
        &[&kind, &path, &locator, &rule, &ordinal.to_string()],
    )
}

/// IDs of every row of `table` already persisted for the repository.
fn existing_ids(tx: &Transaction<'_>, table: &str, repository_id: &str) -> Result<HashSet<String>> {
    let mut statement = tx.prepare(&format!("SELECT id FROM {table} WHERE repository_id = ?"))?;
    let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
    Ok(collect_rows::<String>(rows)?.into_iter().collect())
}

/// Stable ID of a module→file `contains` edge (must match the insert path).
fn contains_edge_id(repository_id: &str, module_id: &str, file_id: &str) -> String {
    stable_id("edge", &[repository_id, module_id, file_id, "contains"])
}

/// Stable ID of a code-fact edge, derived solely from the owning fact's ID and
/// the edge kind so deletes (which know only the fact ID) can recompute it.
fn code_edge_id(repository_id: &str, fact_id: &str, kind: &str) -> String {
    stable_id("edge", &[repository_id, fact_id, kind])
}

/// Human-readable label for an API node, e.g. `GET /users/:id`.
fn api_label(api: &ApiRecord) -> String {
    let method = api.method.as_deref().unwrap_or("");
    let path = api.path.as_deref().or(api.name.as_deref()).unwrap_or("");
    format!("{method} {path}").trim().to_string()
}

/// Stable ID of a module→module `depends_on` edge (must match the insert path).
fn depends_on_edge_id(
    repository_id: &str,
    source_module_id: &str,
    target_module_id: &str,
    dependency_id: &str,
) -> String {
    stable_id(
        "edge",
        &[
            repository_id,
            source_module_id,
            target_module_id,
            dependency_id,
        ],
    )
}

/// Stable ID of a file→file `depends_on` edge. Derived from the owning
/// dependency's ID alone (like `code_edge_id`) so the delete path — which knows
/// only the dependency ID — can recompute it. These edges let blast/impact reach
/// a file's direct dependents, which the coarser module→module edge can't express.
fn depends_on_file_edge_id(repository_id: &str, dependency_id: &str) -> String {
    stable_id("edge", &[repository_id, dependency_id, "depends_on_file"])
}

fn repository_name(repository_root: &str) -> String {
    Path::new(repository_root)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("repository")
        .to_string()
}

/// The differential between the persisted index and the freshly extracted
/// state, keyed by stable IDs. Removed entries carry the persisted values the
/// delete path needs to recompute derived edge IDs.
struct IndexDelta<'a> {
    files_to_add: Vec<&'a FileRecord>,
    /// (file, previously persisted module id).
    files_to_update: Vec<(&'a FileRecord, String)>,
    /// (file id, module id).
    files_to_remove: Vec<(String, String)>,
    modules_to_add: Vec<&'a ModuleRecord>,
    modules_to_reprefix: Vec<&'a ModuleRecord>,
    modules_to_remove: Vec<String>,
    dependencies_to_add: Vec<&'a DependencyRecord>,
    /// (dependency id, source module id, target module id).
    dependencies_to_remove: Vec<(String, String, String)>,
}

fn compute_index_delta<'a>(
    tx: &Transaction<'_>,
    repository_id: &str,
    modules: &'a [ModuleRecord],
    files: &'a [FileRecord],
    dependencies: &'a [DependencyRecord],
) -> Result<IndexDelta<'a>> {
    let (existing_files, existing_modules, existing_dependencies) =
        load_persisted_index(tx, repository_id)?;
    let (files_to_add, files_to_update, files_to_remove) = diff_files(files, &existing_files);
    let (modules_to_add, modules_to_reprefix, modules_to_remove) =
        diff_modules(modules, &existing_modules);
    let (dependencies_to_add, dependencies_to_remove) =
        diff_dependencies(dependencies, &existing_dependencies);
    Ok(IndexDelta {
        files_to_add,
        files_to_update,
        files_to_remove,
        modules_to_add,
        modules_to_reprefix,
        modules_to_remove,
        dependencies_to_add,
        dependencies_to_remove,
    })
}

type PersistedFiles = HashMap<String, (String, String)>;
type PersistedModules = HashMap<String, String>;
type PersistedDependencies = HashMap<String, (String, String)>;

/// Persisted state keyed by stable IDs: files as `id → (content_hash,
/// module_id)`, modules as `id → path_prefix`, dependencies as
/// `id → (source_module_id, target_module_id)`.
fn load_persisted_index(
    tx: &Transaction<'_>,
    repository_id: &str,
) -> Result<(PersistedFiles, PersistedModules, PersistedDependencies)> {
    let files: PersistedFiles = {
        let mut statement =
            tx.prepare("SELECT id, content_hash, module_id FROM files WHERE repository_id = ?")?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
            ))
        })?;
        collect_rows(rows)?.into_iter().collect()
    };
    let modules: PersistedModules = {
        let mut statement =
            tx.prepare("SELECT id, path_prefix FROM modules WHERE repository_id = ?")?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        collect_rows(rows)?.into_iter().collect()
    };
    let dependencies: PersistedDependencies = {
        let mut statement = tx.prepare(
            "SELECT id, source_module_id, target_module_id FROM dependencies WHERE repository_id = ?",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
            ))
        })?;
        collect_rows(rows)?.into_iter().collect()
    };
    Ok((files, modules, dependencies))
}

#[allow(clippy::type_complexity)] // the three delta buckets, named in IndexDelta
fn diff_files<'a>(
    files: &'a [FileRecord],
    existing: &PersistedFiles,
) -> (
    Vec<&'a FileRecord>,
    Vec<(&'a FileRecord, String)>,
    Vec<(String, String)>,
) {
    let new_ids: HashSet<&str> = files.iter().map(|file| file.id.as_str()).collect();
    let to_remove: Vec<(String, String)> = existing
        .iter()
        .filter(|(id, _)| !new_ids.contains(id.as_str()))
        .map(|(id, (_, module_id))| (id.clone(), module_id.clone()))
        .collect();
    let mut to_add = Vec::new();
    let mut to_update = Vec::new();
    for file in files {
        match existing.get(&file.id) {
            None => to_add.push(file),
            Some((hash, module_id))
                if *hash != file.content_hash || *module_id != file.module_id =>
            {
                to_update.push((file, module_id.clone()));
            }
            Some(_) => {}
        }
    }
    (to_add, to_update, to_remove)
}

fn diff_modules<'a>(
    modules: &'a [ModuleRecord],
    existing: &PersistedModules,
) -> (Vec<&'a ModuleRecord>, Vec<&'a ModuleRecord>, Vec<String>) {
    let new_ids: HashSet<&str> = modules.iter().map(|module| module.id.as_str()).collect();
    let to_remove: Vec<String> = existing
        .keys()
        .filter(|id| !new_ids.contains(id.as_str()))
        .cloned()
        .collect();
    let mut to_add = Vec::new();
    let mut to_reprefix = Vec::new();
    for module in modules {
        match existing.get(&module.id) {
            None => to_add.push(module),
            Some(prefix) if *prefix != module.path_prefix => to_reprefix.push(module),
            Some(_) => {}
        }
    }
    (to_add, to_reprefix, to_remove)
}

fn diff_dependencies<'a>(
    dependencies: &'a [DependencyRecord],
    existing: &PersistedDependencies,
) -> (Vec<&'a DependencyRecord>, Vec<(String, String, String)>) {
    let mut new_ids = HashSet::new();
    let mut to_add = Vec::new();
    for dependency in dependencies {
        // In-batch dedup: stable IDs must stay unique per run.
        if !new_ids.insert(dependency.id.as_str()) {
            continue;
        }
        if !existing.contains_key(&dependency.id) {
            to_add.push(dependency);
        }
    }
    let to_remove: Vec<(String, String, String)> = existing
        .iter()
        .filter(|(id, _)| !new_ids.contains(id.as_str()))
        .map(|(id, (source, target))| (id.clone(), source.clone(), target.clone()))
        .collect();
    (to_add, to_remove)
}

/// Repository upsert: created_at survives re-indexing.
fn upsert_repository(
    tx: &Transaction<'_>,
    repository_id: &str,
    repository_root: &str,
    now: &str,
) -> Result<()> {
    let updated = tx.execute(
        "UPDATE repositories SET root_path = ?, name = ?, updated_at = ? WHERE id = ?",
        params![
            repository_root,
            repository_name(repository_root),
            now,
            repository_id
        ],
    )?;
    if updated == 0 {
        tx.execute(
            "INSERT INTO repositories (id, root_path, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            params![repository_id, repository_root, repository_name(repository_root), now, now],
        )?;
    }
    Ok(())
}

/// Targeted deletes for everything the delta removed or is about to rewrite,
/// including the graph nodes/edges derived from each row.
fn apply_index_deletes(
    tx: &Transaction<'_>,
    repository_id: &str,
    delta: &IndexDelta<'_>,
    stats: &mut SyncStats,
) -> Result<()> {
    let mut delete_file = tx.prepare("DELETE FROM files WHERE id = ?")?;
    let mut delete_module = tx.prepare("DELETE FROM modules WHERE id = ?")?;
    let mut delete_dependency = tx.prepare("DELETE FROM dependencies WHERE id = ?")?;
    let mut delete_node = tx.prepare("DELETE FROM graph_nodes WHERE id = ?")?;
    let mut delete_edge = tx.prepare("DELETE FROM graph_edges WHERE id = ?")?;

    for (file_id, module_id) in &delta.files_to_remove {
        delete_file.execute(params![file_id])?;
        delete_node.execute(params![file_id])?;
        delete_edge.execute(params![contains_edge_id(repository_id, module_id, file_id)])?;
        stats.files_removed += 1;
    }
    for (file, old_module_id) in &delta.files_to_update {
        delete_file.execute(params![file.id])?;
        if *old_module_id != file.module_id {
            delete_edge.execute(params![contains_edge_id(
                repository_id,
                old_module_id,
                &file.id
            )])?;
        }
        stats.files_updated += 1;
    }
    for (dependency_id, source_module_id, target_module_id) in &delta.dependencies_to_remove {
        delete_dependency.execute(params![dependency_id])?;
        delete_edge.execute(params![depends_on_edge_id(
            repository_id,
            source_module_id,
            target_module_id,
            dependency_id
        )])?;
        // Mirror of the file→file edge added on insert (no-op if absent).
        delete_edge.execute(params![depends_on_file_edge_id(
            repository_id,
            dependency_id
        )])?;
        stats.dependencies_removed += 1;
    }
    for module_id in &delta.modules_to_remove {
        delete_module.execute(params![module_id])?;
        delete_node.execute(params![module_id])?;
        stats.modules_removed += 1;
    }
    for module in &delta.modules_to_reprefix {
        tx.execute(
            "UPDATE modules SET path_prefix = ? WHERE id = ?",
            params![module.path_prefix, module.id],
        )?;
    }
    Ok(())
}

/// New module/file/dependency rows, via the columnar appender rather than
/// per-row prepared statements: on large repos the `dependencies`/`files`
/// inserts (tens to hundreds of thousands of rows, each a round-trip) were
/// the dominant persist cost. Each table gets its own scoped appender; ids
/// are deduplicated first because the appender fails silently on a duplicate
/// primary key.
fn append_index_rows(
    tx: &Transaction<'_>,
    delta: &IndexDelta<'_>,
    now: &str,
    stats: &mut SyncStats,
) -> Result<()> {
    {
        let mut modules = tx.appender("modules")?;
        for module in &delta.modules_to_add {
            modules.append_row(params![
                module.id,
                module.repository_id,
                module.name,
                module.path_prefix,
                "inferred",
                Option::<String>::None,
                Option::<String>::None
            ])?;
            stats.modules_added += 1;
        }
    }
    {
        let mut files = tx.appender("files")?;
        for file in &delta.files_to_add {
            files.append_row(params![
                file.id,
                file.repository_id,
                file.path,
                file.language.as_str(),
                file.content_hash,
                file.size_bytes as i64,
                file.module_id,
                file.module_name,
                now
            ])?;
            stats.files_added += 1;
        }
    }
    {
        let mut deps = tx.appender("dependencies")?;
        let mut seen = HashSet::new();
        for dependency in &delta.dependencies_to_add {
            if !seen.insert(dependency.id.as_str()) {
                continue;
            }
            deps.append_row(params![
                dependency.id,
                dependency.repository_id,
                dependency.source_file_id,
                dependency.target_file_id,
                dependency.source_file_path,
                dependency.target_file_path,
                dependency.source_module_id,
                dependency.target_module_id,
                dependency.source_module,
                dependency.target_module,
                dependency.specifier,
                dependency.dependency_kind,
                dependency.is_external,
                dependency.evidence_line as i32,
                now
            ])?;
            stats.dependencies_added += 1;
        }
    }
    Ok(())
}

fn append_index_graph_nodes(
    tx: &Transaction<'_>,
    repository_id: &str,
    delta: &IndexDelta<'_>,
) -> Result<()> {
    let mut nodes = tx.appender("graph_nodes")?;
    for module in &delta.modules_to_add {
        nodes.append_row(params![
            module.id,
            repository_id,
            "module",
            module.name,
            "{}"
        ])?;
    }
    for file in &delta.files_to_add {
        nodes.append_row(params![file.id, repository_id, "file", file.path, "{}"])?;
    }
    Ok(())
}

fn append_index_graph_edges(
    tx: &Transaction<'_>,
    repository_id: &str,
    delta: &IndexDelta<'_>,
) -> Result<()> {
    let mut edges = tx.appender("graph_edges")?;
    let mut seen = HashSet::new();
    for file in &delta.files_to_add {
        let edge_id = contains_edge_id(repository_id, &file.module_id, &file.id);
        if !seen.insert(edge_id.clone()) {
            continue;
        }
        edges.append_row(params![
            edge_id,
            repository_id,
            file.module_id,
            file.id,
            "contains",
            1.0_f64,
            "{}"
        ])?;
    }
    for dependency in &delta.dependencies_to_add {
        // File→file edge first: lets blast/impact reach a file's direct
        // dependents (the module→module edge alone hides intra-module
        // coupling). Only internal deps carry a target file node; skip
        // self-loops.
        if let Some(target_file_id) = dependency.target_file_id.as_deref()
            && !dependency.is_external
            && !target_file_id.is_empty()
            && dependency.source_file_id != target_file_id
        {
            let file_edge_id = depends_on_file_edge_id(repository_id, &dependency.id);
            if seen.insert(file_edge_id.clone()) {
                edges.append_row(params![
                    file_edge_id,
                    repository_id,
                    dependency.source_file_id,
                    target_file_id,
                    "depends_on",
                    1.0_f64,
                    format!(
                        r#"{{"file":"{}","line":{},"specifier":"{}"}}"#,
                        dependency.source_file_path, dependency.evidence_line, dependency.specifier
                    )
                ])?;
            }
        }
        let edge_id = depends_on_edge_id(
            repository_id,
            &dependency.source_module_id,
            &dependency.target_module_id,
            &dependency.id,
        );
        if !seen.insert(edge_id.clone()) {
            continue;
        }
        edges.append_row(params![
            edge_id,
            repository_id,
            dependency.source_module_id,
            dependency.target_module_id,
            "depends_on",
            1.0_f64,
            format!(
                r#"{{"file":"{}","line":{},"specifier":"{}"}}"#,
                dependency.source_file_path, dependency.evidence_line, dependency.specifier
            )
        ])?;
    }
    Ok(())
}

/// Updated files: re-insert the row and re-link the module edge when the
/// module changed. Prepared statements, scoped after the appenders so the
/// connection is free.
fn reinsert_updated_files(
    tx: &Transaction<'_>,
    repository_id: &str,
    delta: &IndexDelta<'_>,
    now: &str,
) -> Result<()> {
    let mut insert_file = tx.prepare(
        "INSERT INTO files (id, repository_id, path, language, content_hash, size_bytes, module_id, module_name, last_indexed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut insert_edge = tx.prepare(
        "INSERT INTO graph_edges (id, repository_id, source_id, target_id, edge_kind, weight, evidence_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )?;
    for (file, old_module_id) in &delta.files_to_update {
        insert_file.execute(params![
            file.id,
            file.repository_id,
            file.path,
            file.language.as_str(),
            file.content_hash,
            file.size_bytes as i64,
            file.module_id,
            file.module_name,
            now
        ])?;
        if *old_module_id != file.module_id {
            insert_edge.execute(params![
                contains_edge_id(repository_id, &file.module_id, &file.id),
                repository_id,
                file.module_id,
                file.id,
                "contains",
                1.0_f64,
                "{}"
            ])?;
        }
    }
    Ok(())
}

/// Everything one appended snapshot records: its identity plus the state and
/// metrics it captures.
struct SnapshotRows<'a> {
    snapshot_id: &'a str,
    commit_sha: Option<&'a str>,
    modules: &'a [ModuleRecord],
    files: &'a [FileRecord],
    dependencies: &'a [DependencyRecord],
    metrics: &'a [(String, f64)],
}

/// Append-only snapshot rows, bulk via the DuckDB appender.
fn append_snapshot_rows(
    tx: &Transaction<'_>,
    repository_id: &str,
    snapshot: &SnapshotRows<'_>,
    now: &str,
) -> Result<()> {
    let circular_dependencies = snapshot
        .metrics
        .iter()
        .find(|(name, _)| name == "circular_dependencies")
        .map(|(_, value)| *value as i64)
        .unwrap_or(0);
    let summary_hash = stable_id(
        "summary",
        &[
            repository_id,
            &snapshot.modules.len().to_string(),
            &snapshot.dependencies.len().to_string(),
            &circular_dependencies.to_string(),
        ],
    );

    tx.execute(
        "INSERT INTO snapshots (id, repository_id, commit_sha, created_at, summary_hash) VALUES (?, ?, ?, ?, ?)",
        params![snapshot.snapshot_id, repository_id, snapshot.commit_sha, now, summary_hash],
    )?;

    {
        let mut appender = tx.appender("snapshot_modules")?;
        for module in snapshot.modules {
            appender.append_row(params![snapshot.snapshot_id, module.name])?;
        }
    }
    {
        let mut appender = tx.appender("snapshot_dependencies")?;
        for dependency in snapshot.dependencies {
            appender.append_row(params![
                snapshot.snapshot_id,
                dependency.source_module,
                dependency.target_module,
                dependency.specifier,
                dependency.is_external
            ])?;
        }
    }
    {
        let mut appender = tx.appender("snapshot_metrics")?;
        for (name, value) in snapshot.metrics {
            appender.append_row(params![snapshot.snapshot_id, name, value])?;
        }
    }
    {
        // Retain per-file content hashes so a later review can tell exactly
        // which files a change added/modified (and scope clone detection to
        // them). Append-only, like the other snapshot_* tables.
        let mut appender = tx.appender("snapshot_files")?;
        for file in snapshot.files {
            appender.append_row(params![snapshot.snapshot_id, file.path, file.content_hash])?;
        }
    }
    Ok(())
}

/// Persisted code-fact IDs per table, loaded before the diff.
struct PriorCodeIds {
    symbols: HashSet<String>,
    calls: HashSet<String>,
    apis: HashSet<String>,
    schema_objects: HashSet<String>,
}

fn load_prior_code_ids(tx: &Transaction<'_>, repository_id: &str) -> Result<PriorCodeIds> {
    Ok(PriorCodeIds {
        symbols: existing_ids(tx, "symbols", repository_id)?,
        calls: existing_ids(tx, "calls", repository_id)?,
        apis: existing_ids(tx, "apis", repository_id)?,
        schema_objects: existing_ids(tx, "schema_objects", repository_id)?,
    })
}

/// Deletes the rows whose stable ID vanished from the fresh extraction, with
/// the graph nodes/edges derived from them. Table-driven: each code-fact
/// table declares the edge kinds and node rows it owns.
fn delete_stale_code_facts(
    tx: &Transaction<'_>,
    repository_id: &str,
    prior: &PriorCodeIds,
    code: &ResolvedCode<'_>,
    stats: &mut SyncStats,
) -> Result<()> {
    let new_symbols: HashSet<&str> = code.symbols.iter().map(|s| s.id.as_str()).collect();
    let new_calls: HashSet<&str> = code.calls.iter().map(|c| c.id.as_str()).collect();
    let new_apis: HashSet<&str> = code.apis.iter().map(|a| a.id.as_str()).collect();
    let new_schema: HashSet<&str> = code.schema_objects.iter().map(|s| s.id.as_str()).collect();

    let mut delete_edge = tx.prepare("DELETE FROM graph_edges WHERE id = ?")?;
    let mut delete_node = tx.prepare("DELETE FROM graph_nodes WHERE id = ?")?;
    let tables = [
        (
            "symbols",
            &prior.symbols,
            &new_symbols,
            &["declares"][..],
            true,
            &mut stats.symbols_removed,
        ),
        (
            "calls",
            &prior.calls,
            &new_calls,
            &["calls"][..],
            false,
            &mut stats.calls_removed,
        ),
        (
            "apis",
            &prior.apis,
            &new_apis,
            &["exposes", "handles"][..],
            true,
            &mut stats.apis_removed,
        ),
        (
            "schema_objects",
            &prior.schema_objects,
            &new_schema,
            &[][..],
            true,
            &mut stats.schema_objects_removed,
        ),
    ];
    for (table, prior_ids, current, edge_kinds, has_node, removed) in tables {
        let mut delete = tx.prepare(&format!("DELETE FROM {table} WHERE id = ?"))?;
        for id in prior_ids.iter().filter(|id| !current.contains(id.as_str())) {
            delete.execute(params![id])?;
            for kind in edge_kinds {
                delete_edge.execute(params![code_edge_id(repository_id, id, kind)])?;
            }
            if has_node {
                delete_node.execute(params![id])?;
            }
            *removed += 1;
        }
    }
    Ok(())
}

fn append_symbol_rows(
    tx: &Transaction<'_>,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
    stats: &mut SyncStats,
) -> Result<()> {
    let mut seen = HashSet::new();
    let mut symbols = tx.appender("symbols")?;
    for symbol in code.symbols {
        if prior.symbols.contains(symbol.id.as_str()) || !seen.insert(symbol.id.as_str()) {
            continue;
        }
        let (start_line, end_line) = match symbol.span {
            Some(span) => (Some(span.start_line as i32), Some(span.end_line as i32)),
            None => (None, None),
        };
        symbols.append_row(params![
            symbol.id.as_str(),
            symbol.repository_id.as_str(),
            symbol.file_id.as_str(),
            symbol.module_id.as_ref().map(|m| m.as_str()),
            symbol.language.as_str(),
            enum_str(&symbol.kind),
            symbol.name,
            symbol.qualified_name,
            start_line,
            end_line,
            symbol.visibility.as_ref().map(enum_str),
            symbol.type_signature,
        ])?;
        stats.symbols_added += 1;
    }
    Ok(())
}

fn append_call_rows(
    tx: &Transaction<'_>,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
    stats: &mut SyncStats,
) -> Result<()> {
    let mut seen = HashSet::new();
    let mut calls = tx.appender("calls")?;
    for call in code.calls {
        if prior.calls.contains(call.id.as_str()) || !seen.insert(call.id.as_str()) {
            continue;
        }
        calls.append_row(params![
            call.id.as_str(),
            call.repository_id.as_str(),
            call.caller_symbol_id.as_str(),
            call.callee_symbol_id.as_ref().map(|s| s.as_str()),
            call.callee_name,
            enum_str(&call.kind),
            Option::<&str>::None,
            call.evidence
                .as_ref()
                .and_then(|e| e.line)
                .map(|l| l as i32),
        ])?;
        stats.calls_added += 1;
    }
    Ok(())
}

fn append_api_rows(
    tx: &Transaction<'_>,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
    stats: &mut SyncStats,
) -> Result<()> {
    let mut seen = HashSet::new();
    let mut apis = tx.appender("apis")?;
    for api in code.apis {
        if prior.apis.contains(api.id.as_str()) || !seen.insert(api.id.as_str()) {
            continue;
        }
        apis.append_row(params![
            api.id.as_str(),
            api.repository_id.as_str(),
            api.module_id.as_ref().map(|m| m.as_str()),
            enum_str(&api.kind),
            api.method,
            api.path,
            api.name,
            api.handler_symbol_id.as_ref().map(|s| s.as_str()),
            api.request_type,
            api.response_type,
            Option::<&str>::None,
            api.evidence.as_ref().and_then(|e| e.line).map(|l| l as i32),
        ])?;
        stats.apis_added += 1;
    }
    Ok(())
}

fn append_schema_object_rows(
    tx: &Transaction<'_>,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
    stats: &mut SyncStats,
) -> Result<()> {
    let mut seen = HashSet::new();
    let mut schema = tx.appender("schema_objects")?;
    for object in code.schema_objects {
        if prior.schema_objects.contains(object.id.as_str()) || !seen.insert(object.id.as_str()) {
            continue;
        }
        schema.append_row(params![
            object.id.as_str(),
            object.repository_id.as_str(),
            enum_str(&object.kind),
            object.name,
            object.parent_id.as_ref().map(|p| p.as_str()),
            Option::<&str>::None,
            object
                .evidence
                .as_ref()
                .and_then(|e| e.line)
                .map(|l| l as i32),
        ])?;
        stats.schema_objects_added += 1;
    }
    Ok(())
}

/// Graph nodes mirroring the code facts (symbols, APIs, tables) so blast
/// analysis can classify and label traversed ids.
fn append_code_graph_nodes(
    tx: &Transaction<'_>,
    repository_id: &str,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
) -> Result<()> {
    let mut nodes = tx.appender("graph_nodes")?;
    let mut seen = HashSet::new();
    for symbol in code.symbols {
        if prior.symbols.contains(symbol.id.as_str()) || !seen.insert(symbol.id.as_str()) {
            continue;
        }
        nodes.append_row(params![
            symbol.id.as_str(),
            repository_id,
            "symbol",
            symbol.qualified_name,
            "{}"
        ])?;
    }
    for api in code.apis {
        if prior.apis.contains(api.id.as_str()) || !seen.insert(api.id.as_str()) {
            continue;
        }
        nodes.append_row(params![
            api.id.as_str(),
            repository_id,
            "api",
            api_label(api),
            "{}"
        ])?;
    }
    for object in code.schema_objects {
        if prior.schema_objects.contains(object.id.as_str()) || !seen.insert(object.id.as_str()) {
            continue;
        }
        nodes.append_row(params![
            object.id.as_str(),
            repository_id,
            enum_str(&object.kind),
            object.name,
            "{}"
        ])?;
    }
    Ok(())
}

/// `declares` and `calls` edges derived from the code facts: a file declares
/// each of its symbols, a caller calls each resolved callee.
fn append_declaration_edges(
    tx: &Transaction<'_>,
    repository_id: &str,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
) -> Result<()> {
    let mut edges = tx.appender("graph_edges")?;
    let mut seen = HashSet::new();
    for symbol in code.symbols {
        if prior.symbols.contains(symbol.id.as_str()) {
            continue;
        }
        let edge_id = code_edge_id(repository_id, symbol.id.as_str(), "declares");
        if !seen.insert(edge_id.clone()) {
            continue;
        }
        edges.append_row(params![
            edge_id,
            repository_id,
            symbol.file_id.as_str(),
            symbol.id.as_str(),
            "declares",
            1.0_f64,
            "{}"
        ])?;
    }
    for call in code.calls {
        if prior.calls.contains(call.id.as_str()) {
            continue;
        }
        // Only resolved calls carry an edge.
        if let Some(callee) = &call.callee_symbol_id {
            let edge_id = code_edge_id(repository_id, call.id.as_str(), "calls");
            if !seen.insert(edge_id.clone()) {
                continue;
            }
            edges.append_row(params![
                edge_id,
                repository_id,
                call.caller_symbol_id.as_str(),
                callee.as_str(),
                "calls",
                1.0_f64,
                "{}"
            ])?;
        }
    }
    Ok(())
}

/// `exposes` and `handles` edges: a module exposes each API, an API is
/// handled by its resolved handler symbol.
fn append_api_edges(
    tx: &Transaction<'_>,
    repository_id: &str,
    code: &ResolvedCode<'_>,
    prior: &PriorCodeIds,
) -> Result<()> {
    let mut edges = tx.appender("graph_edges")?;
    let mut seen = HashSet::new();
    for api in code.apis {
        if prior.apis.contains(api.id.as_str()) {
            continue;
        }
        if let Some(module) = &api.module_id {
            let edge_id = code_edge_id(repository_id, api.id.as_str(), "exposes");
            if seen.insert(edge_id.clone()) {
                edges.append_row(params![
                    edge_id,
                    repository_id,
                    module.as_str(),
                    api.id.as_str(),
                    "exposes",
                    1.0_f64,
                    "{}"
                ])?;
            }
        }
        if let Some(handler) = &api.handler_symbol_id {
            let edge_id = code_edge_id(repository_id, api.id.as_str(), "handles");
            if seen.insert(edge_id.clone()) {
                edges.append_row(params![
                    edge_id,
                    repository_id,
                    api.id.as_str(),
                    handler.as_str(),
                    "handles",
                    1.0_f64,
                    "{}"
                ])?;
            }
        }
    }
    Ok(())
}

impl ArchitectureStore {
    /// Synchronizes the persisted index with the freshly extracted state.
    ///
    /// Differential, as groundwork for incremental indexing: rows are diffed
    /// by their stable IDs, only added/changed/removed facts touch the
    /// database, and everything runs in one transaction with reused prepared
    /// statements. Append-only snapshot rows go through the DuckDB appender.
    ///
    /// Known limit (until the incremental indexer lands): a dependency whose
    /// resolved target file changes within the same module keeps its stable
    /// ID and is not rewritten.
    #[allow(clippy::too_many_arguments)]
    pub fn sync_current_index(
        &mut self,
        repository_id: &str,
        repository_root: &str,
        modules: &[ModuleRecord],
        files: &[FileRecord],
        dependencies: &[DependencyRecord],
        snapshot_id: &str,
        commit_sha: Option<&str>,
        metrics: &[(String, f64)],
        code: &ResolvedCode<'_>,
    ) -> Result<SyncStats> {
        let now = Utc::now().to_rfc3339();
        let mut stats = SyncStats::default();
        let tx = self.conn.transaction()?;

        let prof = std::env::var_os("OVECC_PERSIST_PROFILE").is_some();
        let prof_t0 = std::time::Instant::now();
        let mark = |label: &str| {
            if prof {
                eprintln!(
                    "[persist] {label:<14} +{} ms",
                    prof_t0.elapsed().as_millis()
                );
            }
        };

        upsert_repository(&tx, repository_id, repository_root, &now)?;
        let delta = compute_index_delta(&tx, repository_id, modules, files, dependencies)?;
        apply_index_deletes(&tx, repository_id, &delta, &mut stats)?;
        append_index_rows(&tx, &delta, &now, &mut stats)?;
        append_index_graph_nodes(&tx, repository_id, &delta)?;
        append_index_graph_edges(&tx, repository_id, &delta)?;
        reinsert_updated_files(&tx, repository_id, &delta, &now)?;

        mark("graph+rows");
        Self::sync_code_facts(&tx, repository_id, code, &mut stats)?;
        Self::sync_schema_access_edges(&tx, repository_id, code)?;

        mark("code-facts");
        Self::replace_health_facts(&tx, repository_id, code)?;

        mark("v4-health");
        append_snapshot_rows(
            &tx,
            repository_id,
            &SnapshotRows {
                snapshot_id,
                commit_sha,
                modules,
                files,
                dependencies,
                metrics,
            },
            &now,
        )?;

        mark("snapshot");
        tx.commit()?;
        mark("commit");
        Ok(stats)
    }

    /// Diffs and persists the code-level facts (symbols, calls, APIs, schema
    /// objects) plus the graph nodes/edges mirroring them. Diffed by stable ID
    /// like the module-level tables: unchanged files keep identical IDs (same
    /// content -> same spans), so re-indexing them is a no-op; a changed file
    /// replaces only its own rows.
    fn sync_code_facts(
        tx: &Transaction<'_>,
        repository_id: &str,
        code: &ResolvedCode<'_>,
        stats: &mut SyncStats,
    ) -> Result<()> {
        let prior = load_prior_code_ids(tx, repository_id)?;
        delete_stale_code_facts(tx, repository_id, &prior, code, stats)?;
        // Bulk inserts via DuckDB appenders: one columnar append per table is
        // far cheaper than per-row INSERTs for the high-volume code facts.
        // Each appender lives in its own helper so it flushes (on drop) before
        // the next one opens — only one may borrow the connection at a time.
        // `start_line`/`end_line`/`evidence_line` are INTEGER, so they are
        // appended as `i32`.
        append_symbol_rows(tx, code, &prior, stats)?;
        append_call_rows(tx, code, &prior, stats)?;
        append_api_rows(tx, code, &prior, stats)?;
        append_schema_object_rows(tx, code, &prior, stats)?;
        append_code_graph_nodes(tx, repository_id, code, &prior)?;
        append_declaration_edges(tx, repository_id, code, &prior)?;
        append_api_edges(tx, repository_id, code, &prior)?;
        Ok(())
    }

    /// Reads/writes access edges (symbol -> table), diffed by their own ID.
    fn sync_schema_access_edges(
        tx: &Transaction<'_>,
        repository_id: &str,
        code: &ResolvedCode<'_>,
    ) -> Result<()> {
        let prior: HashSet<String> = {
            let mut statement = tx.prepare(
                "SELECT id FROM graph_edges WHERE repository_id = ? AND edge_kind IN ('reads', 'writes')",
            )?;
            let rows =
                statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
            collect_rows::<String>(rows)?.into_iter().collect()
        };
        let mut new_ids: HashSet<String> = HashSet::new();
        let mut insert_access = tx.prepare(
            "INSERT INTO graph_edges (id, repository_id, source_id, target_id, edge_kind, weight, evidence_json)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )?;
        for edge in code.schema_edges {
            let id = stable_id(
                "edge",
                &[repository_id, &edge.source_id, &edge.target_id, &edge.kind],
            );
            if !new_ids.insert(id.clone()) || prior.contains(&id) {
                continue;
            }
            insert_access.execute(params![
                id,
                repository_id,
                edge.source_id,
                edge.target_id,
                edge.kind,
                1.0_f64,
                edge.evidence_json,
            ])?;
        }
        let mut delete_access = tx.prepare("DELETE FROM graph_edges WHERE id = ?")?;
        for id in prior.iter().filter(|id| !new_ids.contains(id.as_str())) {
            delete_access.execute(params![id])?;
        }
        Ok(())
    }

    /// Code-health facts: per-function complexity and per-file exports. These
    /// are derived current-state, recomputed every run, so a full replace per
    /// repository is simpler than a differential sync. `line` columns are
    /// INTEGER, hence the i32 casts. Ids are deduplicated before the appender,
    /// which would otherwise fail silently on a duplicate PK.
    fn replace_health_facts(
        tx: &Transaction<'_>,
        repository_id: &str,
        code: &ResolvedCode<'_>,
    ) -> Result<()> {
        tx.execute(
            "DELETE FROM complexity WHERE repository_id = ?",
            params![repository_id],
        )?;
        tx.execute(
            "DELETE FROM exports WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut seen = HashSet::new();
            let mut appender = tx.appender("complexity")?;
            for record in code.complexity {
                if !seen.insert(record.id.as_str()) {
                    continue;
                }
                appender.append_row(params![
                    record.id.as_str(),
                    record.repository_id.as_str(),
                    record.file_id.as_str(),
                    record.qualified_name,
                    record.line as i32,
                    record.cyclomatic as i32,
                    record.cognitive as i32,
                    record.line_count as i32,
                    record.param_count as i32,
                ])?;
            }
        }
        {
            let mut seen = HashSet::new();
            let mut appender = tx.appender("exports")?;
            for record in code.exports {
                if !seen.insert(record.id.as_str()) {
                    continue;
                }
                appender.append_row(params![
                    record.id.as_str(),
                    record.repository_id.as_str(),
                    record.file_id.as_str(),
                    record.name,
                    record.line as i32,
                    record.is_type_only,
                    record.re_export_source.as_deref(),
                    record.re_export_name.as_deref(),
                ])?;
            }
        }
        Ok(())
    }

    /// Ingests Git commits and per-file change events. Commits are
    /// immutable by SHA, so this is an idempotent insert keyed by stable ID:
    /// re-indexing ingests only commits not already stored. Returns the number
    /// of newly ingested commits.
    pub fn upsert_git_facts(
        &mut self,
        repository_id: &str,
        commits: &[CommitRecord],
        changes: &[FileChangeRecord],
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let known_commits = existing_ids(&tx, "commits", repository_id)?;
        let known_changes = existing_ids(&tx, "file_changes", repository_id)?;

        let mut ingested = 0;
        {
            let mut insert_commit = tx.prepare(
                "INSERT INTO commits (id, repository_id, sha, parent_shas, author_name, author_email, committed_at, message)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            for commit in commits {
                if known_commits.contains(commit.id.as_str()) {
                    continue;
                }
                insert_commit.execute(params![
                    commit.id.as_str(),
                    commit.repository_id.as_str(),
                    commit.sha,
                    commit.parent_shas.join(","),
                    commit.author_name,
                    commit.author_email,
                    commit.committed_at.to_rfc3339(),
                    commit.message,
                ])?;
                ingested += 1;
            }

            let mut insert_change = tx.prepare(
                "INSERT INTO file_changes (id, repository_id, commit_id, file_path, change_kind, additions, deletions)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            for change in changes {
                if known_changes.contains(change.id.as_str()) {
                    continue;
                }
                insert_change.execute(params![
                    change.id.as_str(),
                    change.repository_id.as_str(),
                    change.commit_id.as_str(),
                    change.file_path,
                    enum_str(&change.kind),
                    change.additions.map(|v| v as i64),
                    change.deletions.map(|v| v as i64),
                ])?;
            }
        }

        tx.commit()?;
        Ok(ingested)
    }

    /// Replaces the repository's current findings. Findings are
    /// recomputed every index run, so a full per-repository replace is correct
    /// and simpler than a diff. Evidence is stored as JSON text.
    pub fn replace_findings(
        &mut self,
        repository_id: &str,
        findings: &[FindingRecord],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM findings WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO findings (id, repository_id, snapshot_id, finding_kind, severity, rule_name, target_id, title, description, evidence_json, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;
            for finding in findings {
                let evidence_json = serde_json::to_string(&finding.evidence).unwrap_or_default();
                insert.execute(params![
                    finding.id.as_str(),
                    finding.repository_id.as_str(),
                    finding.snapshot_id.as_ref().map(|s| s.as_str()),
                    enum_str(&finding.kind),
                    enum_str(&finding.severity),
                    finding.rule_name,
                    finding.target.as_ref().map(|t| t.id.clone()),
                    finding.title,
                    finding.description,
                    evidence_json,
                    finding.created_at.to_rfc3339(),
                ])?;
            }
        }
        {
            // Retain each finding under its snapshot (append-only) so a change
            // review can diff base→head findings by stable identity and report
            // the *named* new ones, not just a count delta. The current-state
            // `findings` table above still backs the point-in-time commands.
            // Ordinals count repeated content identities within the snapshot
            // (findings arrive in deterministic order), so duplicates stay
            // distinct without falling back to volatile line numbers.
            let mut appender = tx.appender("snapshot_findings")?;
            let mut identity_counts: HashMap<String, usize> = HashMap::new();
            for finding in findings {
                let Some(snapshot_id) = finding.snapshot_id.as_ref() else {
                    continue;
                };
                let base_identity = finding_identity(finding, 0);
                let seen = identity_counts.entry(base_identity.clone()).or_insert(0);
                let identity = if *seen == 0 {
                    base_identity
                } else {
                    finding_identity(finding, *seen)
                };
                *seen += 1;
                let evidence_json = serde_json::to_string(&finding.evidence).unwrap_or_default();
                appender.append_row(params![
                    snapshot_id.as_str(),
                    identity,
                    finding.id.as_str(),
                    enum_str(&finding.kind),
                    enum_str(&finding.severity),
                    finding.rule_name,
                    finding.target.as_ref().map(|t| t.id.clone()),
                    finding.title,
                    finding.description,
                    evidence_json,
                    finding.created_at.to_rfc3339(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Replaces the repository's package inventory. Recomputed each
    /// index run, so a full per-repository replace is correct.
    pub fn replace_packages(&mut self, repository_id: &str, packages: &[PackageRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM packages WHERE repository_id = ?",
            params![repository_id],
        )?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO packages (id, repository_id, ecosystem, name, version, manifest_path, is_direct)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            let mut seen = HashSet::new();
            for package in packages {
                let id = stable_id(
                    "package",
                    &[
                        repository_id,
                        &package.ecosystem,
                        &package.name,
                        &package.version,
                    ],
                );
                if !seen.insert(id.clone()) {
                    continue;
                }
                insert.execute(params![
                    id,
                    repository_id,
                    package.ecosystem,
                    package.name,
                    package.version,
                    package.manifest_path,
                    package.is_direct,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn moved_finding_keeps_identity_when_anchored_to_a_symbol() {
        // Anchored on the enclosing symbol, not the line: an edit above a finding
        // that merely shifts its line must not make `review` report it as new.
        let before = sample_finding(
            "snap",
            ovecc_core::facts::FindingKind::TaintedFlow,
            "src/a.ts",
            10,
            "handler",
            ovecc_core::facts::Severity::High,
        );
        let after = sample_finding(
            "snap",
            ovecc_core::facts::FindingKind::TaintedFlow,
            "src/a.ts",
            42,
            "handler",
            ovecc_core::facts::Severity::High,
        );
        assert_eq!(finding_identity(&before, 0), finding_identity(&after, 0));
    }

    #[test]
    fn ordinal_disambiguates_otherwise_identical_findings() {
        // Two identical findings (e.g. two evals on one line): the ordinal keeps
        // the second one distinct without relying on a volatile line number.
        let f = sample_finding(
            "snap",
            ovecc_core::facts::FindingKind::InsecurePattern,
            "src/a.ts",
            7,
            "run",
            ovecc_core::facts::Severity::Medium,
        );
        assert_ne!(finding_identity(&f, 0), finding_identity(&f, 1));
    }

    #[test]
    fn sync_dedups_duplicate_code_facts() {
        use ovecc_core::facts::{CallKind, CallRecord, SymbolKind, SymbolRecord};
        use ovecc_core::id::{CallId, FileId, ModuleId, RepositoryId, SymbolId};
        use ovecc_core::lang::SourceLanguage as CoreLang;

        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let module = sample_module(repo, "billing");
        let file = sample_file(repo, "src/billing/service.ts", "h", &module);

        // An over-eager adapter can emit the same symbol/call id twice within a
        // batch (seen on large repos like django/abseil). The columnar appender
        // would otherwise hit a PRIMARY KEY violation that surfaces only on
        // drop, poisoning the whole transaction. The persistence layer must
        // dedup defensively so this never crashes.
        let make_symbol = || SymbolRecord {
            id: SymbolId::from_raw("symbol:dup"),
            repository_id: RepositoryId::from_raw(repo),
            file_id: FileId::from_raw(file.id.as_str()),
            module_id: Some(ModuleId::from_raw(module.id.as_str())),
            language: CoreLang::TypeScript,
            kind: SymbolKind::Function,
            name: "f".to_string(),
            qualified_name: "f".to_string(),
            span: None,
            visibility: None,
            type_signature: None,
        };
        let make_call = || CallRecord {
            id: CallId::from_raw("call:dup"),
            repository_id: RepositoryId::from_raw(repo),
            caller_symbol_id: SymbolId::from_raw("symbol:dup"),
            callee_symbol_id: None,
            callee_name: Some("g".to_string()),
            kind: CallKind::Direct,
            evidence: None,
        };
        let symbols = vec![make_symbol(), make_symbol()];
        let calls = vec![make_call(), make_call()];
        let code = ResolvedCode {
            symbols: &symbols,
            calls: &calls,
            apis: &[],
            schema_objects: &[],
            schema_edges: &[],
            complexity: &[],
            exports: &[],
        };

        store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&module),
                std::slice::from_ref(&file),
                &[],
                "snap-1",
                None,
                &[],
                &code,
            )
            .expect("duplicate code-fact ids must not crash the appender");

        // Each duplicate collapsed to a single persisted row.
        assert_eq!(count(&store, "SELECT count(*) FROM symbols"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM calls"), 1);
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM graph_nodes WHERE node_kind = 'symbol'"
            ),
            1
        );
    }

    #[test]
    fn sync_is_differential_and_idempotent() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";
        let billing = sample_module(repo, "billing");
        let user = sample_module(repo, "user");
        let f1 = sample_file(repo, "src/billing/service.ts", "hash-a", &billing);
        let f2 = sample_file(repo, "src/user/model.ts", "hash-b", &user);
        let dep = sample_dependency(repo, &f1, &f2, "../user/model", 1);
        let modules = [billing.clone(), user.clone()];
        let metrics = vec![("circular_dependencies".to_string(), 0.0)];

        let first = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &[f1.clone(), f2.clone()],
                std::slice::from_ref(&dep),
                "snap-1",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert_eq!(first.files_added, 2);
        assert_eq!(first.modules_added, 2);
        assert_eq!(first.dependencies_added, 1);

        // Same state again: only the snapshot is appended.
        let second = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &[f1.clone(), f2.clone()],
                std::slice::from_ref(&dep),
                "snap-2",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert!(
            second.is_noop(),
            "unchanged input must be a no-op: {second:?}"
        );
        assert_eq!(count(&store, "SELECT count(*) FROM files"), 2);
        assert_eq!(count(&store, "SELECT count(*) FROM snapshots"), 2);
        // 2 contains edges + 1 module depends_on + 1 file→file depends_on edge
        assert_eq!(count(&store, "SELECT count(*) FROM graph_edges"), 4);

        // Changed content hash: file row is rewritten, nothing duplicated.
        let mut f1_changed = f1.clone();
        f1_changed.content_hash = "hash-a2".to_string();
        let third = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                &modules,
                &[f1_changed, f2.clone()],
                std::slice::from_ref(&dep),
                "snap-3",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert_eq!(third.files_updated, 1);
        assert_eq!(third.files_added, 0);
        assert_eq!(count(&store, "SELECT count(*) FROM files"), 2);

        // Removing a file, its module, and the dependency cascades precisely.
        let fourth = store
            .sync_current_index(
                repo,
                "/tmp/repo",
                std::slice::from_ref(&billing),
                std::slice::from_ref(&f1),
                &[],
                "snap-4",
                None,
                &metrics,
                &ResolvedCode::default(),
            )
            .unwrap();
        assert_eq!(fourth.files_removed, 1);
        assert_eq!(fourth.modules_removed, 1);
        assert_eq!(fourth.dependencies_removed, 1);
        assert_eq!(count(&store, "SELECT count(*) FROM files"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM dependencies"), 0);
        // billing module node + f1 file node
        assert_eq!(count(&store, "SELECT count(*) FROM graph_nodes"), 2);
        // billing contains f1
        assert_eq!(count(&store, "SELECT count(*) FROM graph_edges"), 1);
        // history is preserved
        assert_eq!(count(&store, "SELECT count(*) FROM snapshots"), 4);
    }

    #[test]
    fn ingests_git_facts_and_computes_ownership() {
        use ovecc_core::facts::{ChangeKind, CommitRecord, FileChangeRecord};
        use ovecc_core::id::{CommitId, FileChangeId, RepositoryId};

        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let repo = "repo:test";

        // f1: author A x3, author B x1 → ownership 0.75; f2: author A x1.
        let plan = [
            ("c1", "a@x", "f1.ts"),
            ("c2", "a@x", "f1.ts"),
            ("c3", "a@x", "f1.ts"),
            ("c4", "b@x", "f1.ts"),
            ("c5", "a@x", "f2.ts"),
        ];
        let mut commits = Vec::new();
        let mut changes = Vec::new();
        for (i, (sha, email, path)) in plan.iter().enumerate() {
            commits.push(CommitRecord {
                id: CommitId::from_parts(&[repo, sha]),
                repository_id: RepositoryId::from_raw(repo),
                sha: sha.to_string(),
                parent_shas: Vec::new(),
                author_name: Some("A".to_string()),
                author_email: Some(email.to_string()),
                committed_at: chrono::DateTime::from_timestamp(1_700_000_000 + i as i64, 0)
                    .unwrap(),
                message: Some(format!("commit {sha}")),
            });
            changes.push(FileChangeRecord {
                id: FileChangeId::from_parts(&[repo, sha, path]),
                repository_id: RepositoryId::from_raw(repo),
                commit_id: CommitId::from_parts(&[repo, sha]),
                file_path: path.to_string(),
                kind: ChangeKind::Modified,
                additions: None,
                deletions: None,
            });
        }

        let ingested = store.upsert_git_facts(repo, &commits, &changes).unwrap();
        assert_eq!(ingested, 5);
        // Re-ingesting the same history adds nothing (idempotent by SHA).
        let again = store.upsert_git_facts(repo, &commits, &changes).unwrap();
        assert_eq!(again, 0);
        assert_eq!(store.count_rows("commits", repo).unwrap(), 5);

        let ownership = store.ownership_metrics(repo).unwrap();
        let f1 = ownership.iter().find(|o| o.file_path == "f1.ts").unwrap();
        assert!(
            (f1.ownership - 0.75).abs() < 1e-9,
            "f1 ownership: {}",
            f1.ownership
        );
        assert_eq!(f1.major_contributors, 2);
        assert_eq!(f1.minor_contributors, 0);
        assert_eq!(f1.total_commits, 4);

        let f2 = ownership.iter().find(|o| o.file_path == "f2.ts").unwrap();
        assert!((f2.ownership - 1.0).abs() < 1e-9);
        assert_eq!(f2.total_commits, 1);
    }
}
