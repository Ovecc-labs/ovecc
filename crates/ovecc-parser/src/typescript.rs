//! TypeScript/JavaScript language adapter.
//!
//! One adapter handles the whole JS/TS family (js, jsx, ts, tsx); the grammar
//! is chosen from the file's language. A single recursive walk extracts every
//! fact kind so the AST is traversed once:
//!
//! - symbols (functions, classes, methods, interfaces, type aliases, enums,
//!   module-level constants/variables) with within-file qualified names;
//! - imports (static / re-export / require / dynamic / type-only) with the
//!   imported names when available;
//! - calls (direct, method, constructor) attributed to the enclosing callable;
//! - APIs (Express/Fastify/Koa-style HTTP routes);
//! - schema references (raw SQL embedded in string/template literals).
//!
//! Extraction never panics: malformed nodes are skipped, and the adapter
//! reports a [`ParseFailure`] only when the grammar cannot be loaded or the
//! tree cannot be produced.

use crate::security;
use ovecc_core::facts::{
    ApiFact, ApiKind, CallFact, CallKind, CapabilityFact, CapabilityKind, FileFacts, ImportFact,
    ImportFactKind, ParseFailure, SchemaAccess, SchemaObjectKind, SchemaRefFact,
    SecurityPatternFact, SourceFile, Span, SymbolFact, SymbolKind, Visibility,
};
use ovecc_core::lang::SourceLanguage;
use ovecc_core::traits::LanguageAdapter;
use tree_sitter::{Node, Parser};

/// Stateless adapter for the JavaScript/TypeScript family.
#[derive(Debug, Default, Clone, Copy)]
pub struct TypeScriptAdapter;

impl LanguageAdapter for TypeScriptAdapter {
    fn language(&self) -> SourceLanguage {
        SourceLanguage::TypeScript
    }

    fn detect(&self, file: &SourceFile) -> f32 {
        if file.language.is_js_family() {
            1.0
        } else {
            0.0
        }
    }

    fn extract(&self, file: &SourceFile) -> Result<FileFacts, ParseFailure> {
        let grammar = grammar_for(file.language).ok_or_else(|| ParseFailure {
            path: file.path.clone(),
            message: format!("{} is not a JS/TS language", file.language.as_str()),
        })?;

        let mut parser = Parser::new();
        parser
            .set_language(&grammar)
            .map_err(|error| ParseFailure {
                path: file.path.clone(),
                message: format!("failed to load grammar: {error}"),
            })?;
        let tree = parser
            .parse(file.contents.as_bytes(), None)
            .ok_or_else(|| ParseFailure {
                path: file.path.clone(),
                message: "tree-sitter returned no syntax tree".to_string(),
            })?;

        let mut extractor = Extractor::new(file.contents.as_bytes());
        extractor.visit(tree.root_node(), false);
        Ok(extractor.into_facts())
    }
}

fn grammar_for(language: SourceLanguage) -> Option<tree_sitter::Language> {
    match language {
        SourceLanguage::JavaScript | SourceLanguage::Jsx => {
            Some(tree_sitter_javascript::LANGUAGE.into())
        }
        SourceLanguage::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        SourceLanguage::Tsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

/// HTTP verbs recognized as route definitions on a router/app object.
const HTTP_VERBS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "options", "head", "all",
];

/// One enclosing scope on the qualified-name stack.
struct Frame {
    name: String,
    /// True for functions/methods (call attribution targets), false for
    /// classes/interfaces (they nest names but do not "call").
    callable: bool,
}

struct Extractor<'a> {
    source: &'a [u8],
    frames: Vec<Frame>,
    symbols: Vec<SymbolFact>,
    imports: Vec<ImportFact>,
    calls: Vec<CallFact>,
    apis: Vec<ApiFact>,
    schema_refs: Vec<SchemaRefFact>,
    security: Vec<SecurityPatternFact>,
    suppressed: Vec<u32>,
    local_types: Vec<(String, String)>,
    /// (capability, api) → (first line, occurrence count). One fact per
    /// distinct API keeps the facts bounded on files that touch the DOM in
    /// every function.
    capabilities: std::collections::BTreeMap<(CapabilityKind, String), (u32, u32)>,
    /// AST node id → synthetic handler name, for inline route handlers whose
    /// body must be visited inside its own callable frame.
    pending_handlers: std::collections::HashMap<usize, String>,
}

impl<'a> Extractor<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            frames: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            apis: Vec::new(),
            schema_refs: Vec::new(),
            security: Vec::new(),
            suppressed: Vec::new(),
            local_types: Vec::new(),
            capabilities: std::collections::BTreeMap::new(),
            pending_handlers: std::collections::HashMap::new(),
        }
    }

    fn into_facts(mut self) -> FileFacts {
        self.imports.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| a.specifier.cmp(&b.specifier))
        });
        self.symbols.sort_by(|a, b| {
            a.span
                .start_line
                .cmp(&b.span.start_line)
                .then_with(|| a.qualified_name.cmp(&b.qualified_name))
        });
        self.calls.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| a.callee_name.cmp(&b.callee_name))
        });
        self.apis
            .sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.path.cmp(&b.path)));
        self.schema_refs.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| a.object_name.cmp(&b.object_name))
        });
        self.security.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| (a.kind as u8).cmp(&(b.kind as u8)))
        });
        self.security.dedup();
        self.suppressed.sort_unstable();
        self.suppressed.dedup();
        let mut capability_uses: Vec<CapabilityFact> = self
            .capabilities
            .into_iter()
            .map(|((capability, api), (line, count))| CapabilityFact {
                capability,
                api,
                line,
                count,
            })
            .collect();
        capability_uses.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.api.cmp(&b.api)));
        FileFacts {
            symbols: self.symbols,
            imports: self.imports,
            calls: self.calls,
            apis: self.apis,
            schema_refs: self.schema_refs,
            security_patterns: self.security,
            suppressed_lines: self.suppressed,
            local_types: self.local_types,
            capability_uses,
            // complexity + exports are computed by the oxc extractor, not here.
            ..FileFacts::default()
        }
    }

    fn record_capability(&mut self, capability: CapabilityKind, api: String, line: u32) {
        let entry = self
            .capabilities
            .entry((capability, api))
            .or_insert((line, 0));
        entry.0 = entry.0.min(line);
        entry.1 += 1;
    }

    fn text(&self, node: Node<'_>) -> &str {
        node.utf8_text(self.source).unwrap_or("")
    }

    fn line(&self, node: Node<'_>) -> u32 {
        node.start_position().row as u32 + 1
    }

    fn span(&self, node: Node<'_>) -> Span {
        Span {
            start_line: node.start_position().row as u32 + 1,
            end_line: node.end_position().row as u32 + 1,
        }
    }

    /// Qualified name of `name` within the current scope (e.g. `Class.method`).
    fn qualified(&self, name: &str) -> String {
        if self.frames.is_empty() {
            return name.to_string();
        }
        let mut parts: Vec<&str> = self
            .frames
            .iter()
            .map(|frame| frame.name.as_str())
            .collect();
        parts.push(name);
        parts.join(".")
    }

    /// Qualified name of the nearest enclosing callable, for call attribution.
    fn current_caller(&self) -> Option<String> {
        let last = self.frames.iter().rposition(|frame| frame.callable)?;
        let parts: Vec<&str> = self.frames[..=last]
            .iter()
            .map(|frame| frame.name.as_str())
            .collect();
        Some(parts.join("."))
    }

    /// True when no enclosing callable scope is open (module or class level).
    /// Used to keep local variables out of the symbol table.
    fn at_declaration_level(&self) -> bool {
        !self.frames.iter().any(|frame| frame.callable)
    }

    fn visit(&mut self, node: Node<'_>, exported: bool) {
        // An inline route handler registered by `try_http_route`: visit its
        // body inside the synthetic callable frame so calls, SQL accesses,
        // and security sinks attribute to the handler, not the module scope.
        if let Some(name) = self.pending_handlers.remove(&node.id()) {
            self.recurse_pushed(node, &name, true);
            return;
        }
        match node.kind() {
            "export_statement" => {
                // A re-export `export { x } from './y'` / `export * from './y'`
                // depends on './y' and forwards usage to it. Record it as an
                // import edge so reachability and dead-code follow barrel chains.
                if node.child_by_field_name("source").is_some() {
                    self.extract_reexport(node);
                }
                // Mark direct declaration children as exported (public).
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    self.visit(child, true);
                }
                return;
            }
            "import_statement" => {
                self.extract_import(node);
                return;
            }
            "function_declaration" | "generator_function_declaration" => {
                self.extract_function(node, exported);
                return;
            }
            "class_declaration" | "abstract_class_declaration" => {
                self.extract_class(node, exported);
                return;
            }
            "method_definition" => {
                self.extract_method(node);
                return;
            }
            "interface_declaration" => {
                self.record_named_symbol(node, SymbolKind::Interface, exported);
            }
            "type_alias_declaration" => {
                self.record_named_symbol(node, SymbolKind::TypeAlias, exported);
            }
            "enum_declaration" => {
                self.record_named_symbol(node, SymbolKind::Enum, exported);
            }
            "lexical_declaration" | "variable_declaration" => {
                self.extract_variable_declaration(node, exported);
                return;
            }
            "call_expression" => {
                self.extract_call(node);
                // fall through to recurse into arguments (nested calls)
            }
            "new_expression" => {
                self.extract_new(node);
            }
            "member_expression" => {
                self.extract_member_capability(node);
            }
            "pair" => {
                self.extract_permissive_cors(node);
            }
            "comment" => {
                self.extract_suppression(node);
            }
            "string" | "template_string" => {
                self.extract_schema_ref(node);
                self.extract_secret(node);
            }
            // A callable named in value position (`pipe(fn)`, `{ key: handler }`,
            // a decorator, a returned function) is a real dependency the call
            // graph would otherwise miss. Member/type/property names are distinct
            // node kinds, so filtering to bare identifiers already excludes them.
            "identifier" => self.record_value_reference(node),
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit(child, false);
        }
    }

    fn extract_import(&mut self, node: Node<'_>) {
        let Some(source_node) = node.child_by_field_name("source") else {
            return;
        };
        let Some(specifier) = string_literal_value(self.text(source_node)) else {
            return;
        };
        // `import type ... ` → type-only dependency.
        let type_only = node
            .child(1)
            .map(|child| self.text(child) == "type")
            .unwrap_or(false);
        let imported_names = self.collect_imported_names(node);
        self.imports.push(ImportFact {
            specifier,
            line: self.line(node),
            kind: if type_only {
                ImportFactKind::TypeOnly
            } else {
                ImportFactKind::Static
            },
            imported_names,
        });
    }

    /// Records a re-export (`export ... from '...'`) as a forwarding import.
    /// `export *` carries no names, so it becomes a namespace edge that credits
    /// every export of the target.
    fn extract_reexport(&mut self, node: Node<'_>) {
        let Some(source_node) = node.child_by_field_name("source") else {
            return;
        };
        let Some(specifier) = string_literal_value(self.text(source_node)) else {
            return;
        };
        // `export type { X } from '...'` is erased at runtime, exactly like
        // `import type` — it must not witness a cycle. Dead-code forwarding is
        // unaffected: those edges are built from the dependency rows (any
        // kind) plus the export facts' own re-export provenance.
        let type_only = node
            .child(1)
            .map(|child| self.text(child) == "type")
            .unwrap_or(false);
        self.imports.push(ImportFact {
            specifier,
            line: self.line(node),
            kind: if type_only {
                ImportFactKind::TypeOnly
            } else {
                ImportFactKind::ReExport
            },
            imported_names: self.collect_imported_names(node),
        });
    }

    fn collect_imported_names(&self, node: Node<'_>) -> Vec<String> {
        let mut names = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // `import_clause` for imports, `export_clause` for `export { x } from`.
            if !matches!(child.kind(), "import_clause" | "export_clause") {
                continue;
            }
            collect_descendant_names(child, self.source, &mut names);
        }
        names.sort();
        names.dedup();
        names
    }

    fn extract_function(&mut self, node: Node<'_>, exported: bool) {
        let Some(name_node) = node.child_by_field_name("name") else {
            // anonymous: still recurse for inner facts
            self.recurse_pushed(node, "<anonymous>", true);
            return;
        };
        let name = self.text(name_node).to_string();
        self.symbols.push(SymbolFact {
            qualified_name: self.qualified(&name),
            name: name.clone(),
            kind: SymbolKind::Function,
            span: self.span(node),
            visibility: Some(if exported {
                Visibility::Public
            } else {
                Visibility::Internal
            }),
            type_signature: self.signature(node),
        });
        self.recurse_pushed(node, &name, true);
    }

    fn extract_class(&mut self, node: Node<'_>, exported: bool) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = self.text(name_node).to_string();
        self.symbols.push(SymbolFact {
            qualified_name: self.qualified(&name),
            name: name.clone(),
            kind: SymbolKind::Class,
            span: self.span(node),
            visibility: Some(if exported {
                Visibility::Public
            } else {
                Visibility::Internal
            }),
            type_signature: None,
        });
        self.recurse_pushed(node, &name, false);
    }

    fn extract_method(&mut self, node: Node<'_>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = self.text(name_node).to_string();
        self.symbols.push(SymbolFact {
            qualified_name: self.qualified(&name),
            name: name.clone(),
            kind: SymbolKind::Method,
            span: self.span(node),
            visibility: Some(self.method_visibility(node)),
            type_signature: self.signature(node),
        });
        self.recurse_pushed(node, &name, true);
    }

    fn extract_variable_declaration(&mut self, node: Node<'_>, exported: bool) {
        let is_const = node
            .child(0)
            .map(|child| self.text(child) == "const")
            .unwrap_or(false);

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            // Only simple identifiers; destructuring is skipped for now.
            if name_node.kind() != "identifier" {
                self.visit_children(child);
                continue;
            }
            let name = self.text(name_node).to_string();
            let value = child.child_by_field_name("value");
            self.record_local_type(child, &name, value);
            let is_function = value
                .map(|value| {
                    matches!(
                        value.kind(),
                        "arrow_function" | "function_expression" | "function"
                    )
                })
                .unwrap_or(false);

            if is_function {
                // `const handler = (req) => {...}` is a function symbol.
                self.symbols.push(SymbolFact {
                    qualified_name: self.qualified(&name),
                    name: name.clone(),
                    kind: SymbolKind::Function,
                    span: self.span(child),
                    visibility: Some(if exported {
                        Visibility::Public
                    } else {
                        Visibility::Internal
                    }),
                    type_signature: None,
                });
                if let Some(value) = value {
                    self.recurse_pushed(value, &name, true);
                }
            } else {
                // Record module/class-level constants and variables only,
                // not function-local ones.
                if self.at_declaration_level() {
                    self.symbols.push(SymbolFact {
                        qualified_name: self.qualified(&name),
                        name: name.clone(),
                        kind: if is_const {
                            SymbolKind::Constant
                        } else {
                            SymbolKind::Variable
                        },
                        span: self.span(child),
                        visibility: Some(if exported {
                            Visibility::Public
                        } else {
                            Visibility::Internal
                        }),
                        type_signature: None,
                    });
                }
                // Recurse the initializer for calls/routes (e.g. `app.get(...)`).
                self.visit_children(child);
            }
        }
    }

    /// Records an identifier read in value position. The name a binding
    /// introduces is not a reference to anything, so every parent below that
    /// makes this node a binding site bails out; what survives is a read, and
    /// the resolver's local/import/unique-name gate decides whether it names a
    /// callable. Reads that name nothing never reach the graph.
    fn record_value_reference(&mut self, node: Node<'_>) {
        let Some(parent) = node.parent() else {
            return;
        };
        let pk = parent.kind();

        // These two already produce a richer fact of their own, and a Reference
        // beside them would double-count the same edge.
        if pk == "call_expression" && parent.child_by_field_name("function") == Some(node) {
            return;
        }
        if pk == "new_expression" && parent.child_by_field_name("constructor") == Some(node) {
            return;
        }

        match pk {
            "function_declaration"
            | "generator_function_declaration"
            | "class_declaration"
            | "abstract_class_declaration"
            | "method_definition"
            | "public_field_definition"
            | "interface_declaration"
            | "type_alias_declaration"
            | "enum_declaration"
            | "enum_member"
            | "method_signature"
            | "property_signature" => return,
            "import_clause" | "import_specifier" | "namespace_import" | "export_specifier"
            | "export_clause" => return,
            "formal_parameters" | "required_parameter" | "optional_parameter" => return,
            // `x => x + 1` keeps its parameter directly under the arrow, so it
            // reaches none of the parameter kinds above.
            "arrow_function" if parent.child_by_field_name("parameter") == Some(node) => return,
            "catch_clause" if parent.child_by_field_name("parameter") == Some(node) => return,
            "variable_declarator" | "for_in_statement" | "assignment_expression"
                if parent.child_by_field_name("name") == Some(node)
                    || parent.child_by_field_name("left") == Some(node) =>
            {
                return;
            }
            _ => {}
        }

        let name = self.text(node).to_string();
        if name.is_empty() {
            return;
        }

        self.calls.push(CallFact {
            caller_qualified_name: self.current_caller(),
            callee_name: name,
            kind: CallKind::Reference,
            line: self.line(node),
            receiver: None,
        });
    }

    fn extract_call(&mut self, node: Node<'_>) {
        let Some(function_node) = node.child_by_field_name("function") else {
            return;
        };
        match function_node.kind() {
            "identifier" => {
                let callee = self.text(function_node).to_string();
                // Weak hash via a *destructured* import — `createHash("md5")` after
                // `import { createHash } from "crypto"` — at least as common as
                // the `crypto.createHash(...)` member form handled in
                // extract_member_call.
                if matches!(callee.as_str(), "createHash" | "createHmac")
                    && let Some(algo) = self
                        .first_string_argument(node)
                        .and_then(|value| security::weak_hash(&value))
                {
                    self.security
                        .push(security::weak_hash_fact(self.line(node), algo));
                }
                // require()/import() are imports, not architectural calls.
                match callee.as_str() {
                    "require" => self.push_call_import(node, ImportFactKind::Require),
                    "import" => self.push_call_import(node, ImportFactKind::Dynamic),
                    "eval" => {
                        let caller = self.current_caller();
                        self.security
                            .push(security::eval_fact(self.line(node), "eval", caller));
                    }
                    _ => {
                        if let Some(capability) = CapabilityKind::of_global_call(&callee) {
                            self.record_capability(capability, callee.clone(), self.line(node));
                        }
                        self.calls.push(CallFact {
                            caller_qualified_name: self.current_caller(),
                            callee_name: callee,
                            kind: CallKind::Direct,
                            line: self.line(node),
                            receiver: None,
                        });
                    }
                }
            }
            // Dynamic `import("…")`: tree-sitter parses the callee as the `import`
            // keyword node, not an `identifier`, so it never reaches the "import"
            // case above. Without this, dynamic imports (lazy loading, code
            // splitting) vanish from the graph — hiding cycles closed by a dynamic
            // import and, worse, flagging a module used only via `await import()`
            // as dead (a false positive).
            "import" => self.push_call_import(node, ImportFactKind::Dynamic),
            "member_expression" => {
                self.extract_member_call(node, function_node);
            }
            _ => {}
        }
    }

    fn extract_member_call(&mut self, call: Node<'_>, member: Node<'_>) {
        let property = member
            .child_by_field_name("property")
            .map(|property| self.text(property).to_string())
            .unwrap_or_default();
        let receiver = member
            .child_by_field_name("object")
            .map(|object| self.text(object).to_string());

        // Express/Fastify/Koa-style route: <object>.<verb>("/path", ..., handler)
        if HTTP_VERBS.contains(&property.as_str())
            && let Some(api) = self.try_http_route(call, &property)
        {
            self.apis.push(api);
            // A matched route is still recorded as a call for the graph.
        }

        // Weak hash: createHash("md5") / createHmac("sha1").
        if matches!(property.as_str(), "createHash" | "createHmac")
            && let Some(algo) = self
                .first_string_argument(call)
                .and_then(|value| security::weak_hash(&value))
        {
            self.security
                .push(security::weak_hash_fact(self.line(call), algo));
        }

        // Permissive CORS via a raw header write — the common no-middleware
        // form: `res.setHeader("Access-Control-Allow-Origin", "*")`, plus the
        // Express aliases `res.set(...)` / `res.header(...)`. The header name
        // is distinctive enough that no receiver check is needed.
        if matches!(property.as_str(), "setHeader" | "set" | "header") {
            let args = self.string_arguments(call);
            if args
                .first()
                .is_some_and(|name| name.eq_ignore_ascii_case("access-control-allow-origin"))
                && args.get(1).map(String::as_str) == Some("*")
            {
                self.security.push(security::cors_fact(
                    self.line(call),
                    "Access-Control-Allow-Origin: *",
                ));
            }
        }

        // OS command execution: `child_process.exec(...)` and friends. The
        // receiver must denote child_process so `regex.exec` is not flagged.
        if security::COMMAND_EXEC_METHODS.contains(&property.as_str()) {
            let object_is_cp = member
                .child_by_field_name("object")
                .filter(|object| object.kind() == "identifier")
                .map(|object| security::COMMAND_EXEC_OBJECTS.contains(&self.text(object)))
                .unwrap_or(false);
            if object_is_cp {
                let caller = self.current_caller();
                self.security.push(security::command_exec_fact(
                    self.line(call),
                    &property,
                    caller,
                ));
            }
        }

        if let Some(object) = receiver.as_deref()
            && let Some(capability) = CapabilityKind::of_method_call(object, &property)
        {
            self.record_capability(capability, format!("{object}.{property}"), self.line(call));
        }

        self.calls.push(CallFact {
            caller_qualified_name: self.current_caller(),
            callee_name: property,
            kind: CallKind::Method,
            line: self.line(call),
            receiver,
        });
    }

    /// Ambient-object member access outside a call: `process.env.NODE_ENV`,
    /// `document.cookie`, `localStorage.length`. Member calls are recorded by
    /// `extract_member_call`, so a node that is itself a call's callee is
    /// skipped to keep one logical use at one count. In a chain only the
    /// innermost member has the bare ambient identifier as its object, so a
    /// chain records once.
    fn extract_member_capability(&mut self, node: Node<'_>) {
        let Some(object) = node
            .child_by_field_name("object")
            .filter(|object| object.kind() == "identifier")
        else {
            return;
        };
        let Some(capability) = CapabilityKind::of_member_root(self.text(object)) else {
            return;
        };
        if let Some(parent) = node.parent()
            && parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(node)
        {
            return;
        }
        let property = node
            .child_by_field_name("property")
            .map(|property| self.text(property).to_string())
            .unwrap_or_default();
        let api = if property.is_empty() {
            self.text(object).to_string()
        } else {
            format!("{}.{property}", self.text(object))
        };
        self.record_capability(capability, api, self.line(node));
    }

    /// Value of the first string-literal argument of a call, if any.
    fn first_string_argument(&self, call: Node<'_>) -> Option<String> {
        self.string_arguments(call).into_iter().next()
    }

    /// Values of every string-literal argument of a call, in order
    /// (non-string arguments are skipped).
    fn string_arguments(&self, call: Node<'_>) -> Vec<String> {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut values = Vec::new();
        let mut cursor = arguments.walk();
        for child in arguments.children(&mut cursor) {
            if child.kind() == "string"
                && let Some(value) = string_literal_value(self.text(child))
            {
                values.push(value);
            }
        }
        values
    }

    fn try_http_route(&mut self, call: Node<'_>, verb: &str) -> Option<ApiFact> {
        let arguments = call.child_by_field_name("arguments")?;
        let mut args = Vec::new();
        let mut cursor = arguments.walk();
        for child in arguments.children(&mut cursor) {
            if child.is_named() {
                args.push(child);
            }
        }
        // A route needs at least a path and a handler.
        if args.len() < 2 {
            return None;
        }
        let path = string_literal_value(self.text(args[0]))?;
        if !path.starts_with('/') {
            return None;
        }
        // Handler = last named argument. A named identifier is referenced
        // directly; an inline function/arrow — the dominant Express style —
        // gets a synthetic handler symbol so the route stays connected to the
        // call graph (and therefore to taint analysis).
        let handler_name = args.last().and_then(|last| match last.kind() {
            "identifier" => Some(self.text(*last).to_string()),
            "arrow_function" | "function_expression" | "function" => {
                Some(self.synthesize_inline_handler(*last, verb, &path))
            }
            _ => None,
        });
        Some(ApiFact {
            kind: ApiKind::HttpRoute,
            method: Some(verb.to_ascii_uppercase()),
            path: Some(path),
            name: None,
            handler_name,
            request_type: None,
            response_type: None,
            line: self.line(call),
        })
    }

    /// Records an inline route handler (`app.get("/x", (req, res) => …)`) as
    /// a synthetic function symbol and schedules its body to be visited inside
    /// that callable frame. Returns the name the [`ApiFact`] links to.
    fn synthesize_inline_handler(&mut self, handler: Node<'_>, verb: &str, path: &str) -> String {
        let name = format!("<{} {} handler>", verb.to_ascii_uppercase(), path);
        self.symbols.push(SymbolFact {
            qualified_name: self.qualified(&name),
            name: name.clone(),
            kind: SymbolKind::Function,
            span: self.span(handler),
            visibility: Some(Visibility::Internal),
            type_signature: None,
        });
        self.pending_handlers.insert(handler.id(), name.clone());
        name
    }

    fn extract_new(&mut self, node: Node<'_>) {
        let Some(constructor) = node.child_by_field_name("constructor") else {
            return;
        };
        let callee_name = match constructor.kind() {
            "identifier" => self.text(constructor).to_string(),
            "member_expression" => constructor
                .child_by_field_name("property")
                .map(|property| self.text(property).to_string())
                .unwrap_or_default(),
            _ => return,
        };
        if callee_name.is_empty() {
            return;
        }
        // Dynamic code execution: `new Function("...")`.
        if callee_name == "Function" {
            let caller = self.current_caller();
            self.security
                .push(security::eval_fact(self.line(node), "new Function", caller));
        }
        let argless = node
            .child_by_field_name("arguments")
            .map(|arguments| arguments.named_child_count() == 0)
            .unwrap_or(true);
        if let Some(capability) = CapabilityKind::of_constructor(&callee_name, argless) {
            self.record_capability(capability, format!("new {callee_name}"), self.line(node));
        }
        self.calls.push(CallFact {
            caller_qualified_name: self.current_caller(),
            callee_name,
            kind: CallKind::Constructor,
            line: self.line(node),
            receiver: None,
        });
    }

    /// Hardcoded-secret detection on a string/template literal: provider
    /// patterns plus the high-entropy heuristic gated by the binding name.
    fn extract_secret(&mut self, node: Node<'_>) {
        let raw = self.text(node);
        let value = string_literal_value(raw).unwrap_or_else(|| raw.to_string());
        if let Some(label) = security::provider_secret(&value) {
            self.security
                .push(security::secret_fact(self.line(node), label));
            return;
        }
        if let Some(name) = self.binding_name(node)
            && security::is_secret_name(&name)
            && security::looks_like_high_entropy_secret(&value)
        {
            self.security
                .push(security::secret_fact(self.line(node), "high-entropy value"));
        }
    }

    /// Name a literal is bound to, for the secret heuristic: the property key,
    /// the declared variable, or the assignment target.
    fn binding_name(&self, node: Node<'_>) -> Option<String> {
        let parent = node.parent()?;
        match parent.kind() {
            "pair" => parent.child_by_field_name("key").map(|key| {
                string_literal_value(self.text(key)).unwrap_or_else(|| self.text(key).to_string())
            }),
            "variable_declarator" => parent
                .child_by_field_name("name")
                .map(|name| self.text(name).to_string()),
            "assignment_expression" => parent
                .child_by_field_name("left")
                .map(|left| self.text(left).to_string()),
            _ => None,
        }
    }

    /// from a `const v: T` annotation or a `const v = new T()`
    /// initializer. The type name is stripped of any namespace and generics.
    fn record_local_type(&mut self, declarator: Node<'_>, name: &str, value: Option<Node<'_>>) {
        if let Some(type_node) = declarator.child_by_field_name("type")
            && let Some(type_name) = self.annotation_type_name(type_node)
        {
            self.local_types.push((name.to_string(), type_name));
            return;
        }
        if let Some(value) = value
            && value.kind() == "new_expression"
            && let Some(constructor) = value.child_by_field_name("constructor")
            && constructor.kind() == "identifier"
        {
            self.local_types
                .push((name.to_string(), self.text(constructor).to_string()));
        }
    }

    /// Extracts the base type name from a `: Type` / `: Type<...>` annotation.
    fn annotation_type_name(&self, type_node: Node<'_>) -> Option<String> {
        let text = self.text(type_node).trim_start_matches([':', ' ', '\t']);
        let head: String = text
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        let base = head.rsplit('.').next().unwrap_or(&head);
        // Ignore primitive/built-in types — only class-like names dispatch.
        if base.is_empty() || base.chars().next().is_some_and(|c| c.is_lowercase()) {
            None
        } else {
            Some(base.to_string())
        }
    }

    /// Records an inline suppression comment. The marker must lead the
    /// comment (see [`crate::suppression_offset`]):
    /// `// ovecc-ignore-next-line` suppresses the following line, a bare
    /// `// ovecc-ignore` suppresses the comment's own line (trailing form).
    fn extract_suppression(&mut self, node: Node<'_>) {
        if let Some(offset) = crate::suppression_offset(self.text(node)) {
            self.suppressed.push(self.line(node) + offset);
        }
    }

    /// Permissive CORS: an object property `origin: "*"`.
    fn extract_permissive_cors(&mut self, node: Node<'_>) {
        let Some(key) = node.child_by_field_name("key") else {
            return;
        };
        let key_text =
            string_literal_value(self.text(key)).unwrap_or_else(|| self.text(key).to_string());
        if key_text != "origin" {
            return;
        }
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        if string_literal_value(self.text(value)).as_deref() == Some("*") {
            self.security
                .push(security::cors_fact(self.line(node), "origin: \"*\""));
        }
    }

    fn push_call_import(&mut self, call: Node<'_>, kind: ImportFactKind) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for child in arguments.children(&mut cursor) {
            if child.kind() == "string" {
                if let Some(specifier) = string_literal_value(self.text(child)) {
                    self.imports.push(ImportFact {
                        specifier,
                        line: self.line(call),
                        kind,
                        imported_names: Vec::new(),
                    });
                }
                break;
            }
        }
    }

    fn extract_schema_ref(&mut self, node: Node<'_>) {
        let raw = self.text(node);
        let inner = string_literal_value(raw).unwrap_or_else(|| raw.to_string());
        if let Some((object_name, object_kind, access)) = detect_sql(&inner) {
            self.schema_refs.push(SchemaRefFact {
                object_name,
                object_kind,
                access,
                line: self.line(node),
                caller_qualified_name: self.current_caller(),
            });
        }
    }

    /// Records a declaration that owns a `name` field and recurses its body
    /// without opening a new scope (interfaces, type aliases, enums).
    fn record_named_symbol(&mut self, node: Node<'_>, kind: SymbolKind, exported: bool) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = self.text(name_node).to_string();
            self.symbols.push(SymbolFact {
                qualified_name: self.qualified(&name),
                name,
                kind,
                span: self.span(node),
                visibility: Some(if exported {
                    Visibility::Public
                } else {
                    Visibility::Internal
                }),
                type_signature: None,
            });
        }
    }

    fn method_visibility(&self, node: Node<'_>) -> Visibility {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "accessibility_modifier" {
                return match self.text(child) {
                    "private" => Visibility::Private,
                    "protected" => Visibility::Protected,
                    _ => Visibility::Public,
                };
            }
        }
        Visibility::Public
    }

    /// First line of the declaration as a coarse signature (everything up to
    /// the body `{`), trimmed.
    fn signature(&self, node: Node<'_>) -> Option<String> {
        let text = self.text(node);
        let head = text.split('{').next().unwrap_or(text).trim();
        if head.is_empty() {
            None
        } else {
            Some(
                head.replace(['\n', '\r'], " ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        }
    }

    fn recurse_pushed(&mut self, node: Node<'_>, name: &str, callable: bool) {
        self.frames.push(Frame {
            name: name.to_string(),
            callable,
        });
        self.visit_children(node);
        self.frames.pop();
    }

    fn visit_children(&mut self, node: Node<'_>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit(child, false);
        }
    }
}

/// Strips matching surrounding quotes/backticks from a string literal token.
fn string_literal_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let first = trimmed.chars().next()?;
    let last = trimmed.chars().last()?;
    if trimmed.len() >= 2 && matches!(first, '\'' | '"' | '`') && first == last {
        Some(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        None
    }
}

/// Collects identifier names under an `import_clause` (default, namespace, and
/// named specifiers) for symbol-level dependency resolution.
fn collect_descendant_names(node: Node<'_>, source: &[u8], names: &mut Vec<String>) {
    match node.kind() {
        "identifier" => {
            if let Ok(text) = node.utf8_text(source) {
                names.push(text.to_string());
            }
        }
        "import_specifier" => {
            // Record BOTH the imported (source) name and the local alias — they
            // serve different consumers. Dead-code crediting needs the source
            // name (what the TARGET module exports); call-graph bindings need the
            // local name (what THIS file calls). For `import { a as b }`, `a` must
            // be credited as a use of the export *and* `b` must bind the local
            // call. Recording only the alias (the old behavior) made every
            // aliased import look like a use of a non-existent export, so the real
            // export was reported as dead — a false positive.
            for field in ["name", "alias"] {
                if let Some(part) = node.child_by_field_name(field)
                    && let Ok(text) = part.utf8_text(source)
                {
                    names.push(text.to_string());
                }
            }
            return;
        }
        "namespace_import" => {
            // `import * as ns`: pulls the WHOLE module. Recording the binding name
            // (`ns`) would make this look like a named import of `ns` and miss
            // that it uses every export of the target — flagging all of them as
            // dead (a false positive). Contribute no name so the indexer marks the
            // edge `is_namespace` and credits all of the target's exports.
            return;
        }
        "export_specifier" => {
            // For `export { a as b } from './x'`, credit the name in the source
            // module (`a`), not the re-exported alias (`b`).
            let target = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("alias"));
            if let Some(target) = target
                && let Ok(text) = target.utf8_text(source)
            {
                names.push(text.to_string());
            }
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_descendant_names(child, source, names);
    }
}

/// Detects raw SQL in a literal and returns the primary object touched, its
/// kind, and the access mode. Deterministic, dependency-free token scanner;
/// intentionally conservative to limit false positives (feeds database access facts and the
/// future taint sinks).
/// Where a statement's table name sits: after a clause keyword (`FROM`, `INTO`,
/// `TABLE`) or at a fixed token position (`UPDATE users`).
enum TableAt {
    After(&'static str),
    Token(usize),
}

/// `(uppercased statement prefix, where the table name is, access kind)`, tried
/// in order. Every match is a table access.
const SQL_STATEMENTS: &[(&str, TableAt, SchemaAccess)] = &[
    ("SELECT ", TableAt::After("FROM"), SchemaAccess::Read),
    ("INSERT ", TableAt::After("INTO"), SchemaAccess::Write),
    ("UPDATE ", TableAt::Token(1), SchemaAccess::Write),
    ("DELETE ", TableAt::After("FROM"), SchemaAccess::Write),
    (
        "CREATE TABLE",
        TableAt::After("TABLE"),
        SchemaAccess::Define,
    ),
    ("ALTER TABLE", TableAt::After("TABLE"), SchemaAccess::Define),
    ("DROP TABLE", TableAt::After("TABLE"), SchemaAccess::Define),
];

fn detect_sql(text: &str) -> Option<(String, SchemaObjectKind, SchemaAccess)> {
    let trimmed = text.trim();
    // Require a statement-shaped string: a SQL verb followed by whitespace.
    let upper = trimmed.to_ascii_uppercase();
    let tokens = sql_tokens(trimmed);
    if tokens.len() < 2 {
        return None;
    }
    let (_, table_at, access) = SQL_STATEMENTS
        .iter()
        .find(|(prefix, _, _)| upper.starts_with(prefix))?;
    let table = match table_at {
        TableAt::After(keyword) => table_after(&tokens, keyword),
        TableAt::Token(index) => token_at(&tokens, *index),
    }?;
    Some((table, SchemaObjectKind::Table, *access))
}

/// Splits SQL into bare tokens, breaking on whitespace and punctuation.
fn sql_tokens(sql: &str) -> Vec<String> {
    sql.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';'))
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

/// SQL keywords that may sit between a clause keyword and the table name
/// (e.g. `CREATE TABLE IF NOT EXISTS users`).
const SQL_NOISE: &[&str] = &["IF", "NOT", "EXISTS"];

fn table_after(tokens: &[String], keyword: &str) -> Option<String> {
    let index = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case(keyword))?;
    let mut next = index + 1;
    while let Some(token) = tokens.get(next) {
        if SQL_NOISE
            .iter()
            .any(|noise| token.eq_ignore_ascii_case(noise))
        {
            next += 1;
            continue;
        }
        return clean_identifier(token);
    }
    None
}

fn token_at(tokens: &[String], index: usize) -> Option<String> {
    tokens.get(index).and_then(|token| clean_identifier(token))
}

/// Strips quoting and a schema prefix from a SQL identifier (`"public"."u"` →
/// `u`). Returns `None` if nothing identifier-like remains.
fn clean_identifier(token: &str) -> Option<String> {
    let last_segment = token.rsplit('.').next().unwrap_or(token);
    let cleaned: String = last_segment
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn extract(source: &str, language: SourceLanguage) -> FileFacts {
        let file = SourceFile {
            path: "test.ts".to_string(),
            absolute_path: PathBuf::from("test.ts"),
            language,
            contents: source.to_string(),
        };
        TypeScriptAdapter.extract(&file).expect("extraction")
    }

    #[test]
    fn records_function_as_value_reference() {
        let facts = extract(
            r#"
import { purry } from "./purry";

function helper(x: number): number {
    return x;
}

export function run(items: number[]) {
    const alias = helper;
    const registry = { key: helper };
    return purry(alias, [items, registry]);
}
"#,
            SourceLanguage::TypeScript,
        );
        // `helper` aliased into a const and stored in a registry object: value
        // references the call graph would otherwise miss.
        let helper_refs = facts
            .calls
            .iter()
            .filter(|c| c.kind == CallKind::Reference && c.callee_name == "helper")
            .count();
        assert!(helper_refs >= 2, "{:?}", facts.calls);
        // The invoked `purry(...)` stays a Direct call, not a Reference.
        let purry = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "purry")
            .expect("purry call");
        assert_eq!(purry.kind, CallKind::Direct);
    }

    #[test]
    fn value_reference_skips_bindings_and_member_names() {
        let facts = extract(
            r#"
export function run(source: number[]) {
    const mapped = source.map((entry) => entry);
    let total = 0;
    total = mapped;
    for (const key in mapped) {
        drain(key);
    }
    try {
        risky();
    } catch (failure) {
        drain(failure);
    }
    return holder.mapped;
}
"#,
            SourceLanguage::TypeScript,
        );
        let refs = |name: &str| {
            facts
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Reference && c.callee_name == name)
                .count()
        };
        // A name a binding introduces is not a reference: each of these is read
        // exactly once besides the binding site, so a second hit means the
        // binding leaked in.
        assert_eq!(refs("entry"), 1, "arrow parameter bound, {:?}", facts.calls);
        assert_eq!(refs("key"), 1, "for-in binding, {:?}", facts.calls);
        assert_eq!(refs("failure"), 1, "catch parameter, {:?}", facts.calls);
        // `total = mapped` writes `total` and reads `mapped`.
        assert_eq!(refs("total"), 0, "assignment target, {:?}", facts.calls);
        // `holder.mapped` names a property, not the local `mapped`; the grammar
        // gives it a distinct kind, so the count stays at the two real reads.
        assert_eq!(
            refs("mapped"),
            2,
            "member property leaked, {:?}",
            facts.calls
        );
    }

    #[test]
    fn extracts_symbols_with_qualified_names_and_visibility() {
        let facts = extract(
            r#"
export class BillingService {
    private secret: string;
    public createInvoice(id: string): string {
        return id;
    }
}

function helper(): void {}

export const RATE = 0.2;
"#,
            SourceLanguage::TypeScript,
        );

        let names: Vec<_> = facts
            .symbols
            .iter()
            .map(|s| (s.qualified_name.as_str(), s.kind))
            .collect();
        assert!(names.contains(&("BillingService", SymbolKind::Class)));
        assert!(names.contains(&("BillingService.createInvoice", SymbolKind::Method)));
        assert!(names.contains(&("helper", SymbolKind::Function)));
        assert!(names.contains(&("RATE", SymbolKind::Constant)));

        let class = facts
            .symbols
            .iter()
            .find(|s| s.name == "BillingService")
            .unwrap();
        assert_eq!(class.visibility, Some(Visibility::Public));
        let method = facts
            .symbols
            .iter()
            .find(|s| s.name == "createInvoice")
            .unwrap();
        assert_eq!(method.visibility, Some(Visibility::Public));
    }

    #[test]
    fn does_not_record_function_local_variables() {
        let facts = extract(
            r#"
function run(): void {
    const local = 1;
    let other = 2;
}
"#,
            SourceLanguage::TypeScript,
        );
        assert!(facts.symbols.iter().all(|s| s.name != "local"));
        assert!(facts.symbols.iter().all(|s| s.name != "other"));
    }

    #[test]
    fn extracts_calls_attributed_to_enclosing_callable() {
        let facts = extract(
            r#"
function outer(): void {
    helper();
    obj.method();
    new Widget();
}
"#,
            SourceLanguage::TypeScript,
        );

        let helper = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "helper")
            .unwrap();
        assert_eq!(helper.kind, CallKind::Direct);
        assert_eq!(helper.caller_qualified_name.as_deref(), Some("outer"));

        let method = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "method")
            .unwrap();
        assert_eq!(method.kind, CallKind::Method);

        let widget = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "Widget")
            .unwrap();
        assert_eq!(widget.kind, CallKind::Constructor);
    }

    #[test]
    fn extracts_imports_with_names_and_kinds() {
        let facts = extract(
            r#"
import { a, b as c } from "./mod";
import type { T } from "./types";
const d = require("./legacy");
"#,
            SourceLanguage::TypeScript,
        );

        let m = facts
            .imports
            .iter()
            .find(|i| i.specifier == "./mod")
            .unwrap();
        assert_eq!(m.kind, ImportFactKind::Static);
        assert!(m.imported_names.contains(&"a".to_string()));
        assert!(m.imported_names.contains(&"c".to_string()));

        let types = facts
            .imports
            .iter()
            .find(|i| i.specifier == "./types")
            .unwrap();
        assert_eq!(types.kind, ImportFactKind::TypeOnly);

        let legacy = facts
            .imports
            .iter()
            .find(|i| i.specifier == "./legacy")
            .unwrap();
        assert_eq!(legacy.kind, ImportFactKind::Require);
    }

    #[test]
    fn re_exports_become_import_edges() {
        // Re-exports are dependencies on their source, forwarding usage — the
        // edges dead-code reachability follows through barrel chains.
        let facts = extract(
            "export { deep, a as b } from './feature';\nexport * from './all';\n",
            SourceLanguage::TypeScript,
        );
        let named = facts
            .imports
            .iter()
            .find(|i| i.specifier == "./feature")
            .expect("named re-export edge");
        assert_eq!(named.kind, ImportFactKind::ReExport);
        // The name credited is the source name `a`, not the alias `b`.
        assert!(named.imported_names.contains(&"deep".to_string()));
        assert!(named.imported_names.contains(&"a".to_string()));
        assert!(!named.imported_names.contains(&"b".to_string()));

        let star = facts
            .imports
            .iter()
            .find(|i| i.specifier == "./all")
            .expect("star re-export edge");
        assert_eq!(star.kind, ImportFactKind::ReExport);
        // `export *` carries no names → a namespace edge that credits all.
        assert!(star.imported_names.is_empty());
    }

    #[test]
    fn extracts_express_routes() {
        let facts = extract(
            r#"
import express from "express";
const app = express();
app.get("/users/:id", getUser);
app.post("/users", (req, res) => { res.send("ok"); });
"#,
            SourceLanguage::Jsx,
        );

        let get = facts
            .apis
            .iter()
            .find(|a| a.method.as_deref() == Some("GET"))
            .unwrap();
        assert_eq!(get.path.as_deref(), Some("/users/:id"));
        assert_eq!(get.handler_name.as_deref(), Some("getUser"));

        let post = facts
            .apis
            .iter()
            .find(|a| a.method.as_deref() == Some("POST"))
            .unwrap();
        assert_eq!(post.path.as_deref(), Some("/users"));
        // An anonymous handler gets a synthetic symbol so the route stays
        // connected to the call graph.
        assert_eq!(post.handler_name.as_deref(), Some("<POST /users handler>"));
    }

    #[test]
    fn detects_raw_sql_access() {
        assert_eq!(
            detect_sql("SELECT id FROM users WHERE id = 1"),
            Some((
                "users".to_string(),
                SchemaObjectKind::Table,
                SchemaAccess::Read
            ))
        );
        assert_eq!(
            detect_sql("insert into orders (id) values (1)"),
            Some((
                "orders".to_string(),
                SchemaObjectKind::Table,
                SchemaAccess::Write
            ))
        );
        assert_eq!(
            detect_sql("UPDATE customers SET name = 'x'"),
            Some((
                "customers".to_string(),
                SchemaObjectKind::Table,
                SchemaAccess::Write
            ))
        );
        assert_eq!(
            detect_sql("CREATE TABLE IF NOT EXISTS sessions (id TEXT)"),
            Some((
                "sessions".to_string(),
                SchemaObjectKind::Table,
                SchemaAccess::Define
            ))
        );
        assert_eq!(detect_sql("just a normal sentence"), None);
    }

    #[test]
    fn extracts_sql_schema_refs_from_source() {
        let facts = extract(
            r#"
function load(db) {
    return db.query("SELECT * FROM customers");
}
"#,
            SourceLanguage::JavaScript,
        );
        let reference = facts
            .schema_refs
            .iter()
            .find(|r| r.object_name == "customers")
            .unwrap();
        assert_eq!(reference.access, SchemaAccess::Read);
    }

    #[test]
    fn detects_command_exec_only_for_child_process() {
        use ovecc_core::facts::SecurityPatternKind;
        let facts = extract(
            r#"
import child_process from "child_process";
function run(cmd) { child_process.exec(cmd); }
function scan(re, s) { re.exec(s); }
"#,
            SourceLanguage::JavaScript,
        );
        let exec_sinks: Vec<_> = facts
            .security_patterns
            .iter()
            .filter(|p| p.kind == SecurityPatternKind::CommandExec)
            .collect();
        assert_eq!(
            exec_sinks.len(),
            1,
            "child_process.exec only, not regex.exec"
        );
        assert_eq!(exec_sinks[0].caller_qualified_name.as_deref(), Some("run"));
    }

    #[test]
    fn detects_inline_suppressions() {
        let facts = extract(
            "// ovecc-ignore-next-line\nconst apiKey = \"AKIAIOSFODNN7EXAMPLB\";\neval(x); // ovecc-ignore\n",
            SourceLanguage::TypeScript,
        );
        // next-line comment (line 1) suppresses the secret on line 2.
        assert!(
            facts.suppressed_lines.contains(&2),
            "{:?}",
            facts.suppressed_lines
        );
        // trailing comment suppresses its own line 3 (the eval).
        assert!(
            facts.suppressed_lines.contains(&3),
            "{:?}",
            facts.suppressed_lines
        );
    }

    #[test]
    fn detects_permissive_cors_via_raw_header_write() {
        use ovecc_core::facts::SecurityPatternKind;
        let facts = extract(
            r#"
function configure(res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.set("access-control-allow-origin", "*");
    res.header("Access-Control-Allow-Origin", "*");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Access-Control-Allow-Origin", "https://safe.example");
}
"#,
            SourceLanguage::JavaScript,
        );
        // The three wildcard writes fire (setHeader plus the set/header aliases,
        // header name case-insensitive); the unrelated header and the specific
        // origin do not.
        let cors = facts
            .security_patterns
            .iter()
            .filter(|p| p.kind == SecurityPatternKind::PermissiveCors)
            .count();
        assert_eq!(cors, 3, "{:?}", facts.security_patterns);
    }

    #[test]
    fn inline_route_handler_becomes_symbol_that_owns_its_calls() {
        let facts = extract(
            r#"
import express from "express";
const app = express();
app.post("/users", (req, res) => {
    db.run(req.body.name);
    res.send("ok");
});
"#,
            SourceLanguage::Jsx,
        );

        // The anonymous handler is materialised as a real function symbol...
        let handler = facts
            .symbols
            .iter()
            .find(|s| s.name == "<POST /users handler>")
            .expect("synthetic handler symbol");
        assert_eq!(handler.kind, SymbolKind::Function);

        // ...and the calls in its body are attributed to it, so taint reaches a
        // sink from the route through the call graph.
        let sink = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "run")
            .expect("call inside the inline handler");
        assert_eq!(
            sink.caller_qualified_name.as_deref(),
            Some("<POST /users handler>")
        );
    }

    fn capability(facts: &FileFacts, api: &str) -> Option<CapabilityFact> {
        facts
            .capability_uses
            .iter()
            .find(|use_| use_.api == api)
            .cloned()
    }

    #[test]
    fn records_capability_uses_once_per_api_with_first_line_and_count() {
        let facts = extract(
            r#"
export function load() {
    const seed = Math.random();
    const started = Date.now();
    const other = Date.now();
    return fetch("/api/items", { headers: { seed, started, other } });
}
"#,
            SourceLanguage::TypeScript,
        );
        let now = capability(&facts, "Date.now").expect("clock use");
        assert_eq!(now.capability, CapabilityKind::Time);
        assert_eq!(now.line, 4, "first occurrence");
        assert_eq!(now.count, 2, "both reads folded into one fact");
        assert_eq!(
            capability(&facts, "Math.random").unwrap().capability,
            CapabilityKind::Random
        );
        assert_eq!(
            capability(&facts, "fetch").unwrap().capability,
            CapabilityKind::Network
        );
    }

    #[test]
    fn ambient_members_count_once_whether_called_or_read() {
        let facts = extract(
            r#"
const theme = localStorage.getItem("theme");
const env = process.env.NODE_ENV;
document.title = env;
const socket = new WebSocket("wss://x");
const at = new Date(env);
"#,
            SourceLanguage::JavaScript,
        );
        assert_eq!(
            capability(&facts, "localStorage.getItem").unwrap().count,
            1,
            "the call path records it, the member path skips it"
        );
        assert_eq!(
            capability(&facts, "process.env").unwrap().capability,
            CapabilityKind::Process
        );
        assert_eq!(
            capability(&facts, "document.title").unwrap().capability,
            CapabilityKind::Dom
        );
        assert_eq!(
            capability(&facts, "new WebSocket").unwrap().capability,
            CapabilityKind::Network
        );
        assert!(
            capability(&facts, "new Date").is_none(),
            "new Date(value) converts, only the argless form reads the clock"
        );
    }

    #[test]
    fn pure_code_records_no_capability() {
        let facts = extract(
            r#"
export const total = (items: number[]) => items.reduce((sum, x) => sum + x, 0);
const label = ["a", "b"].join("-");
"#,
            SourceLanguage::TypeScript,
        );
        assert!(
            facts.capability_uses.is_empty(),
            "{:?}",
            facts.capability_uses
        );
    }
}
