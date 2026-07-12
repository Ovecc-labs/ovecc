//! Differential sync of the module-level index: the persisted rows are
//! diffed by stable ID against the fresh extraction, so only what changed
//! touches the database.

use crate::{ArchitectureStore, ResolvedCode, SyncStats, collect_rows};
use anyhow::Result;
use chrono::Utc;
use duckdb::{Transaction, params};
use ovecc_core::legacy::{DependencyRecord, FileRecord, ModuleRecord};
use ovecc_core::util::stable_id;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Stable ID of a module→file `contains` edge (must match the insert path).
fn contains_edge_id(repository_id: &str, module_id: &str, file_id: &str) -> String {
    stable_id("edge", &[repository_id, module_id, file_id, "contains"])
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

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
}
