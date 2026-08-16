//! Fact resolution: grammar-level [`FileFacts`] → typed `*Record`s.
//!
//! The language adapter (`ovecc-parser`) extracts within-file facts with no
//! identity. This layer assigns stable IDs, attaches each fact to its file and
//! module, and links the call graph:
//!
//! 1. **Symbol pass** — every [`SymbolFact`] becomes a [`SymbolRecord`] keyed
//!    by `symbol:{repo}:{lang}:{qualified_name}:{span}`. Two lookup tables are
//!    built: a per-file top-level name table (for local calls) and a per-file
//!    exported name table (for imported calls).
//! 2. **Link pass** — each [`CallFact`] is attributed to its enclosing symbol
//!    (caller) and its callee is resolved local-first, then through the
//!    imported-name bindings. Member calls are kept unresolved on purpose
//!    (precision over recall); an unresolved callee retains its name.
//!
//! Call resolution is intentionally conservative. Dynamic-property dispatch
//! (`api[name](...)`) and deeper indirection are out of scope here; they
//! belong to the dataflow engine.

use ovecc_core::facts::{
    ApiRecord, CallFact, CallKind, CallRecord, Evidence, FileFacts, SchemaAccess,
    SchemaObjectRecord, SecurityPatternKind, SymbolKind, SymbolRecord, Visibility,
};
use ovecc_core::id::{ApiId, CallId, FileId, ModuleId, RepositoryId, SchemaObjectId, SymbolId};
use ovecc_core::lang::SourceLanguage;
use std::collections::HashMap;

/// One file to resolve: its identity plus the raw facts the adapter produced.
pub struct ResolveUnit<'a> {
    pub file_id: &'a str,
    pub repository_id: &'a str,
    /// Repository-relative, '/'-normalized path.
    pub path: &'a str,
    pub module_id: &'a str,
    pub language: SourceLanguage,
    pub facts: &'a FileFacts,
    /// Imported-name → resolved target file, computed by the indexer's import
    /// resolution. Enables cross-file callee linking.
    pub import_bindings: &'a [ImportBinding],
}

/// Binds a locally-visible imported name to the file that exports it.
#[derive(Debug, Clone)]
pub struct ImportBinding {
    pub name: String,
    /// Repository-relative path of the resolved target file.
    pub target_path: String,
}

/// Resolved, persistable facts for a set of files.
#[derive(Debug, Clone, Default)]
pub struct ResolvedFacts {
    pub symbols: Vec<SymbolRecord>,
    pub calls: Vec<CallRecord>,
    pub apis: Vec<ApiRecord>,
    pub schema_objects: Vec<SchemaObjectRecord>,
    /// `reads`/`writes` edges: accessor symbol → table. The accessor
    /// is the enclosing symbol, or the file's `<module>` symbol when the SQL
    /// is at module level.
    pub schema_accesses: Vec<SchemaAccessEdge>,
    /// sinks for code/command injection.
    pub dangerous_sinks: Vec<DangerousSink>,
    /// Symbols that read something the client sends. A taint flow is only a
    /// flow if one of these sits on its path.
    pub client_inputs: Vec<String>,
}

/// A symbol that is a dangerous-call taint sink.
#[derive(Debug, Clone, PartialEq)]
pub struct DangerousSink {
    pub symbol_id: String,
    /// `"eval"` (code injection) or `"command"` (command injection).
    pub label: String,
    pub evidence: ovecc_core::facts::Evidence,
}

/// One resolved schema-access edge (a candidate SQL sink for taint).
#[derive(Debug, Clone, PartialEq)]
pub struct SchemaAccessEdge {
    pub accessor_symbol_id: String,
    pub table_id: String,
    /// `"reads"` or `"writes"`.
    pub kind: &'static str,
    pub evidence: ovecc_core::facts::Evidence,
}

/// Per-file name lookup tables built during the symbol pass.
#[derive(Default)]
struct SymbolIndex {
    /// (path, qualified_name) → symbol id, for caller attribution.
    by_qualified: HashMap<(String, String), String>,
    /// path → (top-level name → symbol id), for local call resolution.
    local_top: HashMap<String, HashMap<String, String>>,
    /// path → (exported name → symbol id), for imported call resolution.
    exported: HashMap<String, HashMap<String, String>>,
    /// `(language, bare name)` → symbol ids, for repository-wide dispatch
    /// resolution. Only a *unique* match is resolved to keep precision
    /// and avoid path explosion while linking distinctively-named methods.
    /// Keyed by language so a callee never resolves across language boundaries
    /// (e.g., a Rust `inv.total()` must not bind to a Python `Invoice.total`).
    by_name: HashMap<(SourceLanguage, String), Vec<String>>,
    /// `(language, qualified name)` → symbol ids, repository-wide, for
    /// receiver-typed dispatch (`v: T` / `new T()` → `v.m()` resolves to `T.m`).
    by_qualified_global: HashMap<(SourceLanguage, String), Vec<String>>,
}

/// The mutable accumulators threaded through the link pass, so each per-unit
/// step stays a small method instead of one long loop body. `module_init` and
/// `synthesized` are shared across units: a module-init symbol is synthesized
/// once and reused by every fact in that file with no enclosing symbol.
#[derive(Default)]
struct LinkState {
    calls: Vec<CallRecord>,
    apis: Vec<ApiRecord>,
    schema_objects: Vec<SchemaObjectRecord>,
    schema_accesses: Vec<SchemaAccessEdge>,
    dangerous_sinks: Vec<DangerousSink>,
    client_inputs: Vec<String>,
    seen_schema: HashMap<(String, String), ()>,
    seen_access: HashMap<(String, String, &'static str), ()>,
    module_init: HashMap<String, String>,
    synthesized: Vec<SymbolRecord>,
}

/// Resolves every unit into a single [`ResolvedFacts`] batch.
pub fn resolve_facts(units: &[ResolveUnit<'_>]) -> ResolvedFacts {
    // Symbol pass first (all files), so cross-file linking sees every symbol.
    let (mut symbols, index) = index_symbols(units);

    let mut state = LinkState::default();
    for unit in units {
        state.resolve_calls(unit, &index);
        state.resolve_apis(unit, &index);
        state.resolve_schema(unit, &index);
        state.resolve_sinks(unit, &index);
        state.resolve_client_inputs(unit, &index);
    }

    symbols.extend(state.synthesized);
    symbols.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    state.calls.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    state.apis.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    state.schema_objects.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    state.schema_accesses.sort_by(|a, b| {
        a.accessor_symbol_id
            .cmp(&b.accessor_symbol_id)
            .then_with(|| a.table_id.cmp(&b.table_id))
            .then_with(|| a.kind.cmp(b.kind))
    });
    state.dangerous_sinks.sort_by(|a, b| {
        a.symbol_id
            .cmp(&b.symbol_id)
            .then_with(|| a.label.cmp(&b.label))
    });
    state
        .dangerous_sinks
        .dedup_by(|a, b| a.symbol_id == b.symbol_id && a.label == b.label);
    state.client_inputs.sort();
    state.client_inputs.dedup();

    ResolvedFacts {
        symbols,
        calls: state.calls,
        apis: state.apis,
        schema_objects: state.schema_objects,
        schema_accesses: state.schema_accesses,
        dangerous_sinks: state.dangerous_sinks,
        client_inputs: state.client_inputs,
    }
}

/// Builds every [`SymbolRecord`] and the per-file/global lookup tables the link
/// pass resolves against.
fn index_symbols(units: &[ResolveUnit<'_>]) -> (Vec<SymbolRecord>, SymbolIndex) {
    let mut symbols = Vec::new();
    let mut index = SymbolIndex::default();
    for unit in units {
        for fact in &unit.facts.symbols {
            let span_key = format!("{}:{}", fact.span.start_line, fact.span.end_line);
            let id = SymbolId::from_parts(&[
                unit.repository_id,
                unit.path,
                unit.language.as_str(),
                &fact.qualified_name,
                &span_key,
            ]);
            index.by_qualified.insert(
                (unit.path.to_string(), fact.qualified_name.clone()),
                id.0.clone(),
            );
            // Top-level declarations have qualified_name == name (no nesting).
            if fact.qualified_name == fact.name {
                index
                    .local_top
                    .entry(unit.path.to_string())
                    .or_default()
                    .entry(fact.name.clone())
                    .or_insert_with(|| id.0.clone());
            }
            if matches!(fact.visibility, Some(Visibility::Public)) {
                index
                    .exported
                    .entry(unit.path.to_string())
                    .or_default()
                    .entry(fact.name.clone())
                    .or_insert_with(|| id.0.clone());
            }
            // Callable names feed repository-wide dispatch resolution.
            if matches!(fact.kind, SymbolKind::Function | SymbolKind::Method) {
                index
                    .by_name
                    .entry((unit.language, fact.name.clone()))
                    .or_default()
                    .push(id.0.clone());
                index
                    .by_qualified_global
                    .entry((unit.language, fact.qualified_name.clone()))
                    .or_default()
                    .push(id.0.clone());
            }
            symbols.push(SymbolRecord {
                id,
                repository_id: RepositoryId::from_raw(unit.repository_id),
                file_id: FileId::from_raw(unit.file_id),
                module_id: Some(ModuleId::from_raw(unit.module_id)),
                language: unit.language,
                kind: fact.kind,
                name: fact.name.clone(),
                qualified_name: fact.qualified_name.clone(),
                span: Some(fact.span),
                visibility: fact.visibility,
                type_signature: fact.type_signature.clone(),
            });
        }
    }
    (symbols, index)
}

impl LinkState {
    fn resolve_calls(&mut self, unit: &ResolveUnit<'_>, index: &SymbolIndex) {
        let local = index.local_top.get(unit.path);
        let var_types: HashMap<&str, &str> = unit
            .facts
            .local_types
            .iter()
            .map(|(name, type_name)| (name.as_str(), type_name.as_str()))
            .collect();
        let mut call_counts = HashMap::new();
        for call in &unit.facts.calls {
            let caller_id = match &call.caller_qualified_name {
                Some(qualified) => index
                    .by_qualified
                    .get(&(unit.path.to_string(), qualified.clone()))
                    .cloned(),
                None => None,
            }
            .unwrap_or_else(|| {
                ensure_module_init(unit, &mut self.module_init, &mut self.synthesized)
            });

            // Dispatch resolution. Method calls: `this.m()` resolves
            // precisely within the enclosing class (even when `m` is ambiguous
            // repository-wide), otherwise fall back to a unique repo-wide name.
            // Direct calls: local/import first, then the unique-name rule.
            let callee_id = match call.kind {
                CallKind::Method => resolve_method_callee(call, unit, index, &var_types),
                _ => resolve_callee(&call.callee_name, unit, local, &index.exported)
                    .or_else(|| resolve_unique_name(&call.callee_name, unit.language, index)),
            };

            let count = call_counts
                .entry((caller_id.clone(), call.callee_name.clone(), call.line))
                .or_insert(0);
            let id = CallId::from_parts(&[
                unit.repository_id,
                &caller_id,
                &call.callee_name,
                &call.line.to_string(),
                &count.to_string(),
            ]);
            *count += 1;

            self.calls.push(CallRecord {
                id,
                repository_id: RepositoryId::from_raw(unit.repository_id),
                caller_symbol_id: SymbolId::from_raw(caller_id),
                callee_symbol_id: callee_id.map(SymbolId::from_raw),
                callee_name: Some(call.callee_name.clone()),
                kind: call.kind,
                evidence: Some(Evidence {
                    file_path: unit.path.to_string(),
                    line: Some(call.line),
                    symbol: call.caller_qualified_name.clone(),
                    detail: None,
                }),
            });
        }
    }

    fn resolve_apis(&mut self, unit: &ResolveUnit<'_>, index: &SymbolIndex) {
        let local = index.local_top.get(unit.path);
        for api in &unit.facts.apis {
            let handler_id = api
                .handler_name
                .as_ref()
                .and_then(|name| resolve_callee(name, unit, local, &index.exported));
            let route_key = api
                .path
                .clone()
                .or_else(|| api.name.clone())
                .unwrap_or_default();
            let api_line_str = api.line.to_string();
            self.apis.push(ApiRecord {
                id: ApiId::from_parts(&[
                    unit.repository_id,
                    unit.path,
                    api.method.as_deref().unwrap_or(""),
                    &route_key,
                    &api_line_str,
                ]),
                repository_id: RepositoryId::from_raw(unit.repository_id),
                module_id: Some(ModuleId::from_raw(unit.module_id)),
                kind: api.kind,
                method: api.method.clone(),
                path: api.path.clone(),
                name: api.name.clone(),
                handler_symbol_id: handler_id.map(SymbolId::from_raw),
                request_type: api.request_type.clone(),
                response_type: api.response_type.clone(),
                evidence: Some(Evidence {
                    file_path: unit.path.to_string(),
                    line: Some(api.line),
                    symbol: None,
                    detail: None,
                }),
            });
        }
    }

    /// Schema objects are deduplicated repository-wide by (name, kind); each
    /// access becomes a reads/writes edge from the accessor symbol.
    fn resolve_schema(&mut self, unit: &ResolveUnit<'_>, index: &SymbolIndex) {
        for schema in &unit.facts.schema_refs {
            let table_id =
                SchemaObjectId::from_parts(&[unit.repository_id, "", &schema.object_name]).0;
            let object_key = (
                schema.object_name.clone(),
                format!("{:?}", schema.object_kind),
            );
            if self.seen_schema.insert(object_key, ()).is_none() {
                self.schema_objects.push(SchemaObjectRecord {
                    id: SchemaObjectId::from_raw(table_id.clone()),
                    repository_id: RepositoryId::from_raw(unit.repository_id),
                    kind: schema.object_kind,
                    name: schema.object_name.clone(),
                    parent_id: None,
                    evidence: Some(Evidence {
                        file_path: unit.path.to_string(),
                        line: Some(schema.line),
                        symbol: None,
                        detail: None,
                    }),
                });
            }

            // Accessor: the enclosing symbol, else the file's <module> symbol.
            let accessor_id = match &schema.caller_qualified_name {
                Some(qualified) => index
                    .by_qualified
                    .get(&(unit.path.to_string(), qualified.clone()))
                    .cloned(),
                None => None,
            }
            .unwrap_or_else(|| {
                ensure_module_init(unit, &mut self.module_init, &mut self.synthesized)
            });
            let kind = match schema.access {
                SchemaAccess::Read => "reads",
                SchemaAccess::Write | SchemaAccess::Define => "writes",
            };
            if self
                .seen_access
                .insert((accessor_id.clone(), table_id.clone(), kind), ())
                .is_none()
            {
                self.schema_accesses.push(SchemaAccessEdge {
                    accessor_symbol_id: accessor_id,
                    table_id,
                    kind,
                    evidence: Evidence {
                        file_path: unit.path.to_string(),
                        line: Some(schema.line),
                        symbol: schema.caller_qualified_name.clone(),
                        detail: None,
                    },
                });
            }
        }
    }

    /// Symbols that read client-sent request data, the taint sources.
    fn resolve_client_inputs(&mut self, unit: &ResolveUnit<'_>, index: &SymbolIndex) {
        for input in &unit.facts.request_inputs {
            if let Some(symbol_id) = index
                .by_qualified
                .get(&(unit.path.to_string(), input.caller_qualified_name.clone()))
            {
                self.client_inputs.push(symbol_id.clone());
            }
        }
    }

    /// Dangerous-call sinks (eval, command exec) attributed to their symbol.
    fn resolve_sinks(&mut self, unit: &ResolveUnit<'_>, index: &SymbolIndex) {
        for pattern in &unit.facts.security_patterns {
            if !pattern.kind.is_taint_sink() {
                continue;
            }
            let symbol_id = match &pattern.caller_qualified_name {
                Some(qualified) => index
                    .by_qualified
                    .get(&(unit.path.to_string(), qualified.clone()))
                    .cloned(),
                None => None,
            }
            .unwrap_or_else(|| {
                ensure_module_init(unit, &mut self.module_init, &mut self.synthesized)
            });
            let label = match pattern.kind {
                SecurityPatternKind::CommandExec => "command",
                _ => "eval",
            };
            self.dangerous_sinks.push(DangerousSink {
                symbol_id,
                label: label.to_string(),
                evidence: Evidence {
                    file_path: unit.path.to_string(),
                    line: Some(pattern.line),
                    symbol: pattern.caller_qualified_name.clone(),
                    detail: pattern.detail.clone(),
                },
            });
        }
    }
}

/// imported-name bindings. Returns `None` when neither matches.
fn resolve_callee(
    name: &str,
    unit: &ResolveUnit<'_>,
    local: Option<&HashMap<String, String>>,
    exported: &HashMap<String, HashMap<String, String>>,
) -> Option<String> {
    if let Some(id) = local.and_then(|table| table.get(name)) {
        return Some(id.clone());
    }
    for binding in unit.import_bindings {
        if binding.name == name
            && let Some(id) = exported.get(&binding.target_path).and_then(|t| t.get(name))
        {
            return Some(id.clone());
        }
    }
    None
}

/// repository bears that name. A unique match is a confident dispatch
/// target; several matches are ambiguous and left unresolved (no
/// over-approximation), and zero matches means an external/unknown callee.
fn resolve_unique_name(
    name: &str,
    language: SourceLanguage,
    index: &SymbolIndex,
) -> Option<String> {
    match index.by_name.get(&(language, name.to_string())) {
        Some(ids) if ids.len() == 1 => Some(ids[0].clone()),
        _ => None,
    }
}

/// Resolves a method-call callee. A `this.m()` (or `self.m()`) call is resolved
/// within the enclosing class — precise even when `m` is ambiguous repository-wide,
/// which the unique-name rule cannot do (no inheritance tracking yet). Any
/// other receiver falls back to the unique-name rule.
fn resolve_method_callee(
    call: &CallFact,
    unit: &ResolveUnit<'_>,
    index: &SymbolIndex,
    var_types: &HashMap<&str, &str>,
) -> Option<String> {
    // `this.m()` (or Python `self.m()`) → the enclosing class's method.
    if matches!(call.receiver.as_deref(), Some("this") | Some("self"))
        && let Some((class, _)) = call
            .caller_qualified_name
            .as_deref()
            .and_then(|caller| caller.rsplit_once('.'))
    {
        let qualified = format!("{class}.{}", call.callee_name);
        if let Some(id) = index.by_qualified.get(&(unit.path.to_string(), qualified)) {
            return Some(id.clone());
        }
    }
    // `v.m()` where `v: T` / `v = new T()` → `T.m`, when uniquely defined.
    if let Some(receiver) = &call.receiver
        && let Some(type_name) = var_types.get(receiver.as_str())
    {
        let qualified = format!("{type_name}.{}", call.callee_name);
        if let Some(ids) = index.by_qualified_global.get(&(unit.language, qualified))
            && ids.len() == 1
        {
            return Some(ids[0].clone());
        }
    }
    // Otherwise, a repository-wide unique name (within the same language).
    resolve_unique_name(&call.callee_name, unit.language, index)
}

/// Lazily synthesizes a `<module>` symbol to own module-level (top-level)
/// calls, which have no enclosing callable. This keeps `caller_symbol_id`
/// non-null and models module-load-time side effects (e.g. top-level
/// route registration) — relevant to later flow analysis.
fn ensure_module_init(
    unit: &ResolveUnit<'_>,
    module_init: &mut HashMap<String, String>,
    synthesized: &mut Vec<SymbolRecord>,
) -> String {
    if let Some(id) = module_init.get(unit.path) {
        return id.clone();
    }
    let id = SymbolId::from_parts(&[
        unit.repository_id,
        unit.language.as_str(),
        "<module>",
        unit.path,
    ]);
    synthesized.push(SymbolRecord {
        id: id.clone(),
        repository_id: RepositoryId::from_raw(unit.repository_id),
        file_id: FileId::from_raw(unit.file_id),
        module_id: Some(ModuleId::from_raw(unit.module_id)),
        language: unit.language,
        kind: SymbolKind::Function,
        name: "<module>".to_string(),
        qualified_name: format!("{}::<module>", unit.path),
        span: None,
        visibility: Some(Visibility::Internal),
        type_signature: None,
    });
    module_init.insert(unit.path.to_string(), id.0.clone());
    id.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::facts::SourceFile;
    use ovecc_core::traits::LanguageAdapter;
    use ovecc_parser::TypeScriptAdapter;
    use std::path::PathBuf;

    fn facts_of(path: &str, src: &str) -> FileFacts {
        let file = SourceFile {
            path: path.to_string(),
            absolute_path: PathBuf::from(path),
            language: SourceLanguage::TypeScript,
            contents: src.to_string(),
        };
        TypeScriptAdapter.extract(&file).expect("extraction")
    }

    fn symbol_id(facts: &ResolvedFacts, name: &str) -> String {
        facts
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("symbol {name} not found"))
            .id
            .0
            .clone()
    }

    fn unit<'a>(file_id: &'a str, path: &'a str, facts: &'a FileFacts) -> ResolveUnit<'a> {
        ResolveUnit {
            file_id,
            repository_id: "repo:test",
            path,
            module_id: "m",
            language: SourceLanguage::TypeScript,
            facts,
            import_bindings: &[],
        }
    }

    #[test]
    fn resolves_member_call_to_unique_named_method() {
        let repo = facts_of("repo.ts", "export class Repo { insert(d) { return d; } }\n");
        let svc = facts_of(
            "svc.ts",
            "function handler(req) { const r = new Repo(); r.insert(req.body); }\n",
        );
        let units = vec![
            unit("f:repo", "repo.ts", &repo),
            unit("f:svc", "svc.ts", &svc),
        ];
        let resolved = resolve_facts(&units);

        let insert_id = symbol_id(&resolved, "insert");
        let call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("insert"))
            .expect("the r.insert() member call");
        assert_eq!(
            call.callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&insert_id),
            "uniquely-named method must resolve via dispatch"
        );
    }

    #[test]
    fn calls_do_not_resolve_across_languages() {
        use ovecc_parser::GenericAdapter;

        let extract = |path: &str, language: SourceLanguage, src: &str| {
            let file = SourceFile {
                path: path.to_string(),
                absolute_path: PathBuf::from(path),
                language,
                contents: src.to_string(),
            };
            GenericAdapter::for_language(language)
                .expect("adapter")
                .extract(&file)
                .expect("extraction")
        };

        // Both define a callable `total`, but in different languages.
        let py = extract(
            "a.py",
            SourceLanguage::Python,
            "class Invoice:\n    def total(self):\n        return 1\n\ndef make():\n    inv = Invoice()\n    return inv.total()\n",
        );
        let rs = extract(
            "b.rs",
            SourceLanguage::Rust,
            "struct Ledger;\nimpl Ledger {\n    fn record(&self) {\n        let inv: Invoice = build();\n        inv.total();\n    }\n}\n",
        );

        let units = vec![
            ResolveUnit {
                file_id: "f:py",
                repository_id: "repo:test",
                path: "a.py",
                module_id: "m",
                language: SourceLanguage::Python,
                facts: &py,
                import_bindings: &[],
            },
            ResolveUnit {
                file_id: "f:rs",
                repository_id: "repo:test",
                path: "b.rs",
                module_id: "m",
                language: SourceLanguage::Rust,
                facts: &rs,
                import_bindings: &[],
            },
        ];
        let resolved = resolve_facts(&units);

        let total_id = symbol_id(&resolved, "total");
        let from = |file: &str| {
            resolved
                .calls
                .iter()
                .find(|c| {
                    c.callee_name.as_deref() == Some("total")
                        && c.evidence.as_ref().map(|e| e.file_path.as_str()) == Some(file)
                })
                .unwrap_or_else(|| panic!("`total` call in {file}"))
        };

        // Python `inv.total()` resolves to the Python method (same language).
        assert_eq!(
            from("a.py").callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&total_id),
            "same-language call must resolve"
        );
        // Rust `inv.total()` must NOT bind to the Python symbol.
        assert!(
            from("b.rs").callee_symbol_id.is_none(),
            "cross-language call must stay unresolved, got {:?}",
            from("b.rs").callee_symbol_id
        );
    }

    #[test]
    fn resolves_member_call_via_local_type() {
        // Repo.save.
        let repo = facts_of(
            "repo.ts",
            "export class Repo { save(d) { return d; } }\nexport class Other { save(d) { return d; } }\n",
        );
        let svc = facts_of(
            "svc.ts",
            "function handler(req) { const r = new Repo(); r.save(req.body); }\n",
        );
        let units = vec![
            unit("f:repo", "repo.ts", &repo),
            unit("f:svc", "svc.ts", &svc),
        ];
        let resolved = resolve_facts(&units);

        let repo_save = resolved
            .symbols
            .iter()
            .find(|s| s.qualified_name == "Repo.save")
            .unwrap()
            .id
            .0
            .clone();
        let call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("save"))
            .expect("the r.save() call");
        assert_eq!(
            call.callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&repo_save),
            "r.save() must resolve to Repo.save via the local type binding"
        );
    }

    #[test]
    fn resolves_this_call_within_enclosing_class() {
        // still bind to class A's helper.
        let a = facts_of(
            "a.ts",
            "export class A {\n  run() { this.helper(); }\n  helper() { return 1; }\n}\n",
        );
        let b = facts_of("b.ts", "export class B {\n  helper() { return 2; }\n}\n");
        let units = vec![unit("f:a", "a.ts", &a), unit("f:b", "b.ts", &b)];
        let resolved = resolve_facts(&units);

        let a_helper = resolved
            .symbols
            .iter()
            .find(|s| s.qualified_name == "A.helper")
            .unwrap()
            .id
            .0
            .clone();
        let call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("helper"))
            .expect("the this.helper() call");
        assert_eq!(
            call.callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&a_helper),
            "this.helper() must resolve within class A, not B"
        );
    }

    #[test]
    fn resolves_rust_self_call_within_enclosing_type() {
        use ovecc_parser::GenericAdapter;

        let file = SourceFile {
            path: "s.rs".to_string(),
            absolute_path: PathBuf::from("s.rs"),
            language: SourceLanguage::Rust,
            contents: "struct S;\nimpl S {\n    fn run(&self) { self.helper(); }\n    fn helper(&self) {}\n}\n\
                       struct T;\nimpl T {\n    fn helper(&self) {}\n}\n"
                .to_string(),
        };
        let facts = GenericAdapter::for_language(SourceLanguage::Rust)
            .expect("adapter")
            .extract(&file)
            .expect("extraction");
        let units = vec![ResolveUnit {
            file_id: "f:s",
            repository_id: "repo:test",
            path: "s.rs",
            module_id: "m",
            language: SourceLanguage::Rust,
            facts: &facts,
            import_bindings: &[],
        }];
        let resolved = resolve_facts(&units);

        let s_helper = resolved
            .symbols
            .iter()
            .find(|s| s.qualified_name == "S.helper")
            .unwrap()
            .id
            .0
            .clone();
        let call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("helper"))
            .expect("the self.helper() call");
        assert_eq!(
            call.callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&s_helper),
            "self.helper() must resolve inside S even though T also has helper()"
        );
    }

    #[test]
    fn ambiguous_member_call_stays_unresolved() {
        // Two methods named `save` → ambiguous → no over-approximation.
        let a = facts_of("a.ts", "export class A { save(d) { return d; } }\n");
        let b = facts_of("b.ts", "export class B { save(d) { return d; } }\n");
        let c = facts_of("c.ts", "function f(x) { x.save(1); }\n");
        let units = vec![
            unit("f:a", "a.ts", &a),
            unit("f:b", "b.ts", &b),
            unit("f:c", "c.ts", &c),
        ];
        let resolved = resolve_facts(&units);
        let call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("save"))
            .expect("the x.save() member call");
        assert!(
            call.callee_symbol_id.is_none(),
            "two save() methods are ambiguous and must stay unresolved"
        );
    }

    #[test]
    fn links_local_imported_and_unresolved_calls() {
        let user = facts_of(
            "user/service.ts",
            r#"
import { User } from "./model";
export function getUser(id: string): User { return { id }; }
"#,
        );
        let billing = facts_of(
            "billing/service.ts",
            r#"
import { getUser } from "../user/service";
import express from "express";
const app = express();
app.get("/invoices/:id", createInvoice);
export function createInvoice(id: string): string {
  const u = getUser(id);
  return helper(u);
}
function helper(u: any): string { return ""; }
"#,
        );

        let billing_bindings = vec![ImportBinding {
            name: "getUser".to_string(),
            target_path: "user/service.ts".to_string(),
        }];
        let units = vec![
            ResolveUnit {
                file_id: "f:user",
                repository_id: "repo:test",
                path: "user/service.ts",
                module_id: "m:user",
                language: SourceLanguage::TypeScript,
                facts: &user,
                import_bindings: &[],
            },
            ResolveUnit {
                file_id: "f:billing",
                repository_id: "repo:test",
                path: "billing/service.ts",
                module_id: "m:billing",
                language: SourceLanguage::TypeScript,
                facts: &billing,
                import_bindings: &billing_bindings,
            },
        ];

        let resolved = resolve_facts(&units);

        // Cross-file imported call resolves to the exported symbol.
        let get_user_id = symbol_id(&resolved, "getUser");
        let imported_call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("getUser"))
            .unwrap();
        assert_eq!(
            imported_call.callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&get_user_id)
        );
        assert_eq!(
            imported_call.caller_symbol_id.0,
            symbol_id(&resolved, "createInvoice")
        );

        // Local call resolves within the file.
        let helper_id = symbol_id(&resolved, "helper");
        let local_call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("helper"))
            .unwrap();
        assert_eq!(
            local_call.callee_symbol_id.as_ref().map(|id| &id.0),
            Some(&helper_id)
        );

        // Member call stays unresolved but keeps its name.
        let member_call = resolved
            .calls
            .iter()
            .find(|c| c.callee_name.as_deref() == Some("get"))
            .unwrap();
        assert!(member_call.callee_symbol_id.is_none());
        assert_eq!(member_call.kind, CallKind::Method);

        // Top-level calls are attributed to a synthesized <module> symbol.
        assert!(resolved.symbols.iter().any(|s| s.name == "<module>"));
        let module_id = symbol_id(&resolved, "<module>");
        assert_eq!(member_call.caller_symbol_id.0, module_id);

        // The route's handler resolves to the local function symbol.
        let route = resolved
            .apis
            .iter()
            .find(|a| a.path.as_deref() == Some("/invoices/:id"))
            .unwrap();
        assert_eq!(
            route.handler_symbol_id.as_ref().map(|id| &id.0),
            Some(&symbol_id(&resolved, "createInvoice"))
        );
    }

    #[test]
    fn deduplicates_schema_objects_repository_wide() {
        let a = facts_of(
            "a.ts",
            r#"function f(db) { return db.query("SELECT * FROM customers"); }"#,
        );
        let b = facts_of(
            "b.ts",
            r#"function g(db) { return db.query("select id from customers"); }"#,
        );
        let units = vec![
            ResolveUnit {
                file_id: "f:a",
                repository_id: "repo:test",
                path: "a.ts",
                module_id: "m:a",
                language: SourceLanguage::TypeScript,
                facts: &a,
                import_bindings: &[],
            },
            ResolveUnit {
                file_id: "f:b",
                repository_id: "repo:test",
                path: "b.ts",
                module_id: "m:b",
                language: SourceLanguage::TypeScript,
                facts: &b,
                import_bindings: &[],
            },
        ];

        let resolved = resolve_facts(&units);
        let customers: Vec<_> = resolved
            .schema_objects
            .iter()
            .filter(|s| s.name == "customers")
            .collect();
        assert_eq!(customers.len(), 1, "customers table must be deduplicated");
    }

    /// Regression: stable IDs must be unique so DuckDB primary keys never
    /// collide, even when the same-named symbol appears at the same span in
    /// two files, or the same call appears twice on one line.
    #[test]
    fn generates_unique_ids_across_files_and_repeated_calls() {
        use std::collections::HashSet;

        // Bug A: identical declaration (same name, same span) in two files.
        let a = facts_of("a.ts", "export const x = 1;\n");
        let b = facts_of("b.ts", "export const x = 1;\n");
        // Bug B: the same call twice on one line.
        let c = facts_of("c.ts", "function f() { g(); g(); }\nfunction g() {}\n");

        let units = vec![
            unit("f:a", "a.ts", &a),
            unit("f:b", "b.ts", &b),
            unit("f:c", "c.ts", &c),
        ];
        let resolved = resolve_facts(&units);

        // Both `x` constants exist and have distinct IDs (cross-file fix).
        let x_ids: Vec<_> = resolved
            .symbols
            .iter()
            .filter(|s| s.name == "x")
            .map(|s| s.id.0.clone())
            .collect();
        assert_eq!(x_ids.len(), 2);
        assert_ne!(
            x_ids[0], x_ids[1],
            "same-named symbols in different files must differ"
        );

        // Both `g()` calls exist and have distinct IDs (same-line fix).
        let g_ids: Vec<_> = resolved
            .calls
            .iter()
            .filter(|c| c.callee_name.as_deref() == Some("g"))
            .map(|c| c.id.0.clone())
            .collect();
        assert_eq!(g_ids.len(), 2);
        assert_ne!(g_ids[0], g_ids[1], "repeated calls on one line must differ");

        // Global invariant: every symbol/call ID is unique.
        let symbol_ids: HashSet<_> = resolved.symbols.iter().map(|s| s.id.0.clone()).collect();
        assert_eq!(
            symbol_ids.len(),
            resolved.symbols.len(),
            "symbol IDs must be unique"
        );
        let call_ids: HashSet<_> = resolved.calls.iter().map(|c| c.id.0.clone()).collect();
        assert_eq!(
            call_ids.len(),
            resolved.calls.len(),
            "call IDs must be unique"
        );
    }
}
