//! Sync of the code-level facts (symbols, calls, APIs, schema objects) and
//! the code-health tables, diffed by stable ID like the module-level rows.

use crate::{ArchitectureStore, ResolvedCode, SyncStats, collect_rows, enum_str, existing_ids};
use anyhow::Result;
use duckdb::{Transaction, params};
use ovecc_core::facts::ApiRecord;
use ovecc_core::util::stable_id;
use std::collections::HashSet;

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
    /// Diffs and persists the code-level facts (symbols, calls, APIs, schema
    /// objects) plus the graph nodes/edges mirroring them. Diffed by stable ID
    /// like the module-level tables: unchanged files keep identical IDs (same
    /// content -> same spans), so re-indexing them is a no-op; a changed file
    /// replaces only its own rows.
    pub(crate) fn sync_code_facts(
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
    pub(crate) fn sync_schema_access_edges(
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
    pub(crate) fn replace_health_facts(
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
        tx.execute(
            "DELETE FROM capability_uses WHERE repository_id = ?",
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
        {
            let mut seen = HashSet::new();
            let mut appender = tx.appender("capability_uses")?;
            for record in code.capability_uses {
                if !seen.insert(record.id.as_str()) {
                    continue;
                }
                appender.append_row(params![
                    record.id.as_str(),
                    record.repository_id.as_str(),
                    record.file_id.as_str(),
                    record.capability.as_str(),
                    record.api,
                    record.line as i32,
                    record.count as i32,
                ])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

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
            capability_uses: &[],
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
}
