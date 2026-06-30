//! Generic, specification-driven language adapter.
//!
//! Where [`crate::typescript`] is a bespoke walker for the JS/TS family, this
//! one factors the *shape* of fact extraction so a single recursive visitor
//! serves Python, Go, Rust, and C++. Each language differs only in:
//!
//! - which tree-sitter node kinds declare callables, types, calls, imports;
//! - how a declared name is read (a `name` field for most, a nested
//!   *declarator* for C++);
//! - how a call's callee/receiver and an import's specifier are spelled.
//!
//! The downstream pipeline is language-agnostic: it consumes [`FileFacts`]
//! (symbols, calls, imports) and never sees the grammar. So adding a language
//! is adding a branch here, not touching resolution, taint, graph, or rules.
//!
//! Qualified names are normalized to a single `.` separator across languages
//! (C++ `Foo::bar`, Go `Recv.Method`, Rust `impl Foo { fn bar }` all become
//! `Foo.bar`), which is exactly what the dispatch resolver expects.
//!
//! Like the TS adapter, extraction never panics: unnameable nodes are skipped
//! and a [`ParseFailure`] is returned only when the grammar or tree is missing.

use crate::security;
use ovecc_core::facts::{
    ApiFact, ApiKind, CallFact, CallKind, ComplexityFact, FileFacts, ImportFact, ImportFactKind,
    ParseFailure, SecurityPatternFact, SecurityPatternKind, SourceFile, Span, SymbolFact,
    SymbolKind,
};
use ovecc_core::lang::SourceLanguage;
use ovecc_core::traits::LanguageAdapter;
use tree_sitter::{Node, Parser};

/// Specification-driven adapter for one non-JS language.
#[derive(Debug, Clone, Copy)]
pub struct GenericAdapter {
    language: SourceLanguage,
}

impl GenericAdapter {
    /// Builds an adapter for `language`. Returns `None` for the JS/TS family
    /// (handled by [`crate::TypeScriptAdapter`]) and for non-code languages.
    pub fn for_language(language: SourceLanguage) -> Option<Self> {
        grammar_for(language).map(|_| Self { language })
    }
}

impl LanguageAdapter for GenericAdapter {
    fn language(&self) -> SourceLanguage {
        self.language
    }

    fn detect(&self, file: &SourceFile) -> f32 {
        if file.language == self.language {
            1.0
        } else {
            0.0
        }
    }

    fn extract(&self, file: &SourceFile) -> Result<FileFacts, ParseFailure> {
        let grammar = grammar_for(self.language).ok_or_else(|| ParseFailure {
            path: file.path.clone(),
            message: format!("{} has no generic grammar", self.language.as_str()),
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

        let mut walk = Walk::new(self.language, file.contents.as_bytes());
        walk.visit(tree.root_node());
        Ok(walk.into_facts())
    }
}

fn grammar_for(language: SourceLanguage) -> Option<tree_sitter::Language> {
    match language {
        SourceLanguage::Python => Some(tree_sitter_python::LANGUAGE.into()),
        SourceLanguage::Go => Some(tree_sitter_go::LANGUAGE.into()),
        SourceLanguage::Rust => Some(tree_sitter_rust::LANGUAGE.into()),
        SourceLanguage::Cpp => Some(tree_sitter_cpp::LANGUAGE.into()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Walk state
// ---------------------------------------------------------------------------

/// One enclosing scope on the qualified-name stack.
struct Frame {
    /// Name segment this scope contributes to qualified names.
    name: String,
    /// True when callables declared directly inside become methods (a class,
    /// struct, trait, or Rust `impl` block) rather than free functions.
    methods_here: bool,
}

/// The classified role of a syntax node, driving the visit.
enum Role {
    /// Function/method declaration: a symbol + a callable frame.
    Callable,
    /// Type declaration of the given kind: a symbol + a method-bearing frame.
    Type(SymbolKind),
    /// A naming scope that is not itself a symbol (Rust `impl`/`mod`, C++
    /// `namespace`). `methods_here` mirrors [`Frame::methods_here`].
    Container {
        methods_here: bool,
    },
    /// Module-level constant/static.
    Const(SymbolKind),
    Call,
    Import,
    /// A typed local binding (`let v: T`, `Foo v;`) feeding receiver-typed
    /// dispatch resolution.
    LocalType,
    Plain,
}

struct Walk<'a> {
    language: SourceLanguage,
    source: &'a [u8],
    frames: Vec<Frame>,
    /// Qualified names of enclosing callables, for call attribution.
    callables: Vec<String>,
    symbols: Vec<SymbolFact>,
    imports: Vec<ImportFact>,
    calls: Vec<CallFact>,
    local_types: Vec<(String, String)>,
    security: Vec<SecurityPatternFact>,
    apis: Vec<ApiFact>,
    complexity: Vec<ComplexityFact>,
    suppressed: Vec<u32>,
}

impl<'a> Walk<'a> {
    fn new(language: SourceLanguage, source: &'a [u8]) -> Self {
        Self {
            language,
            source,
            frames: Vec::new(),
            callables: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            local_types: Vec::new(),
            security: Vec::new(),
            apis: Vec::new(),
            complexity: Vec::new(),
            suppressed: Vec::new(),
        }
    }

    fn into_facts(mut self) -> FileFacts {
        self.symbols.sort_by(|a, b| {
            a.span
                .start_line
                .cmp(&b.span.start_line)
                .then_with(|| a.qualified_name.cmp(&b.qualified_name))
        });
        self.imports.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| a.specifier.cmp(&b.specifier))
        });
        self.calls.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| a.callee_name.cmp(&b.callee_name))
        });
        self.local_types.sort();
        self.local_types.dedup();
        self.security.sort_by(|a, b| {
            a.line
                .cmp(&b.line)
                .then_with(|| (a.kind as u8).cmp(&(b.kind as u8)))
        });
        self.apis.sort_by_key(|a| a.line);
        self.complexity.sort_by_key(|c| c.line);
        self.suppressed.sort_unstable();
        self.suppressed.dedup();
        // Rust's `Command::new` is ambiguous: `std::process::Command` executes an
        // OS command, but `clap::Command` (and many other crates) just build a
        // value. Without an import of `std::process::Command`, drop the
        // command-exec pattern — it is far more often a benign builder (clap
        // alone produced 1400+ false positives in large-scale testing).
        if self.language == SourceLanguage::Rust {
            let uses_process_command = self.imports.iter().any(|import| {
                import.specifier.contains("process::Command")
                    || import.specifier.contains("process::{")
            });
            if !uses_process_command {
                self.security.retain(|pattern| {
                    !(pattern.kind == SecurityPatternKind::CommandExec
                        && pattern.detail.as_deref() == Some("Command::new"))
                });
            }
        }
        FileFacts {
            symbols: self.symbols,
            imports: self.imports,
            calls: self.calls,
            local_types: self.local_types,
            security_patterns: self.security,
            apis: self.apis,
            complexity: self.complexity,
            suppressed_lines: self.suppressed,
            ..FileFacts::default()
        }
    }

    // -- traversal ---------------------------------------------------------

    fn visit(&mut self, node: Node<'a>) {
        // Scan string literals for provider-pattern secrets anywhere they
        // appear, then keep descending (a string nests nothing of interest).
        if is_string_literal(node.kind()) {
            self.scan_string_secret(node);
        }

        // An inline `// ovecc-ignore` (or `# ovecc-ignore` in Python)
        // suppresses findings on its line; `-next-line` on the line after.
        if is_comment(node.kind()) {
            self.extract_suppression(node);
        }

        // A Python route decorator (`@app.get("/x")`) marks the function
        // below it as an HTTP handler — a taint source. Detected here, then
        // normal visiting still extracts the function symbol and its calls.
        if self.language == SourceLanguage::Python && node.kind() == "decorated_definition" {
            self.detect_python_route(node);
        }
        // A Rust route attribute (`#[get("/x")]`, actix/rocket) marks the
        // function below it as an HTTP handler.
        if self.language == SourceLanguage::Rust && node.kind() == "function_item" {
            self.detect_rust_route(node);
        }

        // C++ declarations are overloaded (a method prototype, a free-function
        // prototype, or a typed variable), so they get a dedicated handler.
        if self.language == SourceLanguage::Cpp
            && matches!(node.kind(), "declaration" | "field_declaration")
        {
            return self.visit_cpp_declaration(node);
        }

        match self.role(node) {
            Role::Callable => return self.visit_callable(node),
            Role::Type(kind) => return self.visit_type(node, kind),
            Role::Container { methods_here } => return self.visit_container(node, methods_here),
            Role::Const(kind) => self.record_const(node, kind),
            Role::Call => self.record_call(node),
            Role::Import => {
                self.record_import(node);
                return; // imports nest nothing we extract
            }
            Role::LocalType => self.record_local_type(node),
            Role::Plain => {}
        }
        self.visit_children(node);
    }

    fn visit_children(&mut self, node: Node<'a>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'a>> = node.children(&mut cursor).collect();
        drop(cursor);
        for child in children {
            self.visit(child);
        }
    }

    fn visit_callable(&mut self, node: Node<'a>) {
        let Some((name, qualified, kind)) = self.callable_identity(node) else {
            return self.visit_children(node);
        };
        let short = last_segment(&name).to_string();
        self.push_symbol(node, short.clone(), qualified.clone(), kind);
        self.record_complexity(node, &qualified);
        self.frames.push(Frame {
            name: short,
            methods_here: false,
        });
        self.callables.push(qualified);
        self.visit_children(node);
        self.callables.pop();
        self.frames.pop();
    }

    // -- complexity --------------------------------------------------------

    /// Records cyclomatic + cognitive complexity for a callable by walking its
    /// body: cyclomatic counts decision points, cognitive weights them by
    /// control-flow nesting depth. Nested callables are skipped — each gets its
    /// own fact. A sensible cross-language approximation, consistent with the
    /// oxc TS extractor's values rather than SonarSource-exact.
    fn record_complexity(&mut self, node: Node<'a>, qualified: &str) {
        let span = span_of(node);
        let mut cyclomatic: u32 = 1;
        let mut cognitive: u32 = 0;
        self.walk_complexity(node, 0, &mut cyclomatic, &mut cognitive);
        self.complexity.push(ComplexityFact {
            qualified_name: qualified.to_string(),
            line: span.start_line,
            cyclomatic: cyclomatic.min(u16::MAX as u32) as u16,
            cognitive: cognitive.min(u16::MAX as u32) as u16,
            line_count: span.end_line.saturating_sub(span.start_line) + 1,
            param_count: self.count_params(node),
        });
    }

    fn walk_complexity(&self, node: Node<'a>, depth: u32, cyclo: &mut u32, cog: &mut u32) {
        let mut cursor = node.walk();
        let children: Vec<Node<'a>> = node.children(&mut cursor).collect();
        drop(cursor);
        for child in children {
            // A nested function/closure carries its own complexity fact.
            if matches!(self.role(child), Role::Callable) {
                continue;
            }
            let kind = child.kind();
            if decision_node(self.language, kind) {
                *cyclo += 1;
            }
            if is_logical_operator(child, self.source) {
                *cyclo += 1;
                *cog += 1;
            }
            if nesting_node(self.language, kind) {
                *cog += 1 + depth;
                self.walk_complexity(child, depth + 1, cyclo, cog);
            } else {
                self.walk_complexity(child, depth, cyclo, cog);
            }
        }
    }

    fn count_params(&self, node: Node<'a>) -> u8 {
        let Some(params) = node.child_by_field_name("parameters") else {
            return 0;
        };
        let mut cursor = params.walk();
        let count = params
            .named_children(&mut cursor)
            .filter(|child| child.kind() != "comment")
            .count();
        count.min(u8::MAX as usize) as u8
    }

    fn visit_type(&mut self, node: Node<'a>, kind: SymbolKind) {
        let Some(name) = field_text(node, "name", self.source) else {
            return self.visit_children(node);
        };
        let qualified = self.qualify(&name);
        self.push_symbol(node, name.clone(), qualified, kind);
        self.frames.push(Frame {
            name,
            methods_here: true,
        });
        self.visit_children(node);
        self.frames.pop();
    }

    fn visit_container(&mut self, node: Node<'a>, methods_here: bool) {
        let name = match node.kind() {
            // `impl Foo`/`impl Trait for Foo`: the implementing type names it.
            "impl_item" => field_text(node, "type", self.source).map(|t| clean_type(&t)),
            _ => field_text(node, "name", self.source),
        };
        match name {
            Some(name) if !name.is_empty() => {
                self.frames.push(Frame { name, methods_here });
                self.visit_children(node);
                self.frames.pop();
            }
            _ => self.visit_children(node),
        }
    }

    /// C++ `declaration`/`field_declaration`: a function prototype becomes a
    /// symbol; a simple typed variable becomes a local-type binding.
    fn visit_cpp_declaration(&mut self, node: Node<'a>) {
        if let Some(declarator) = node.child_by_field_name("declarator")
            && contains_function_declarator(declarator)
        {
            if let Some(raw) = self.cpp_declarator_name(declarator) {
                let name = raw.replace("::", ".");
                let qualified = self.qualify(&name);
                let kind = if name.contains('.') || self.in_type_scope() {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                };
                let short = last_segment(&name).to_string();
                self.push_symbol(node, short, qualified, kind);
            }
            return; // a prototype declares; it does not nest definitions
        }
        // Otherwise treat `T v;` / `T v = expr;` as a typed local binding, and
        // still descend so any initializer calls are recorded.
        self.record_local_type(node);
        self.visit_children(node);
    }

    // -- symbol identity ---------------------------------------------------

    fn callable_identity(&self, node: Node<'a>) -> Option<(String, String, SymbolKind)> {
        match self.language {
            // Go methods carry an explicit receiver: `func (s *Server) Start()`.
            SourceLanguage::Go if node.kind() == "method_declaration" => {
                let name = field_text(node, "name", self.source)?;
                let qualified = match self.go_receiver_type(node) {
                    Some(recv) => format!("{recv}.{name}"),
                    None => self.qualify(&name),
                };
                Some((name, qualified, SymbolKind::Method))
            }
            // C++ functions name themselves through a (possibly qualified,
            // possibly pointer-wrapped) declarator rather than a `name` field.
            SourceLanguage::Cpp => {
                let declarator = node.child_by_field_name("declarator")?;
                let name = self.cpp_declarator_name(declarator)?.replace("::", ".");
                let qualified = self.qualify(&name);
                let kind = if name.contains('.') || self.in_type_scope() {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                };
                Some((name, qualified, kind))
            }
            _ => {
                let name = field_text(node, "name", self.source)?;
                let kind = if self.in_type_scope() {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                };
                Some((name.clone(), self.qualify(&name), kind))
            }
        }
    }

    /// True when the innermost frame makes declared callables methods.
    fn in_type_scope(&self) -> bool {
        self.frames.last().map(|f| f.methods_here).unwrap_or(false)
    }

    fn qualify(&self, name: &str) -> String {
        if self.frames.is_empty() {
            return name.to_string();
        }
        let prefix = self
            .frames
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>()
            .join(".");
        format!("{prefix}.{name}")
    }

    fn push_symbol(&mut self, node: Node<'a>, name: String, qualified: String, kind: SymbolKind) {
        self.symbols.push(SymbolFact {
            name,
            qualified_name: qualified,
            kind,
            span: span_of(node),
            visibility: None,
            type_signature: None,
        });
    }

    fn record_const(&mut self, node: Node<'a>, kind: SymbolKind) {
        if let Some(name) = field_text(node, "name", self.source) {
            let qualified = self.qualify(&name);
            self.push_symbol(node, name, qualified, kind);
        }
    }

    // -- calls -------------------------------------------------------------

    fn record_call(&mut self, node: Node<'a>) {
        let Some((callee, receiver, kind)) = self.call_target(node) else {
            return;
        };
        if callee.is_empty() {
            return;
        }
        let line = span_of(node).start_line;
        // Classify dangerous sinks (eval/command-exec) and weak crypto from
        // the callee + receiver, attributing them to the enclosing symbol so the
        // taint engine can reach them.
        if let Some((kind, detail)) = dangerous_call(self.language, &callee, receiver.as_deref()) {
            self.security.push(SecurityPatternFact {
                kind,
                line,
                detail: Some(detail),
                caller_qualified_name: self.callables.last().cloned(),
            });
        }
        // A Go route registration (`http.HandleFunc("/x", h)`,
        // `r.GET("/x", h)`) makes its handler a taint source.
        if self.language == SourceLanguage::Go
            && let Some((method, path, handler)) = self.go_route(node, &callee)
        {
            self.apis.push(ApiFact {
                kind: ApiKind::HttpRoute,
                method: Some(method),
                path: Some(path),
                name: None,
                handler_name: handler,
                request_type: None,
                response_type: None,
                line,
            });
        }
        self.calls.push(CallFact {
            caller_qualified_name: self.callables.last().cloned(),
            callee_name: callee,
            kind,
            line,
            receiver: receiver.map(|r| self.normalize_receiver(r)),
        });
    }

    /// Extracts an HTTP route from a Python `decorated_definition`
    /// (`@app.get("/x")` / `@app.route("/x", methods=["POST"])`), attributing
    /// it to the decorated function as its handler (a taint source).
    fn detect_python_route(&mut self, node: Node<'a>) {
        let Some(func) = node
            .child_by_field_name("definition")
            .filter(|d| d.kind() == "function_definition")
        else {
            return;
        };
        let Some(handler) = field_text(func, "name", self.source) else {
            return;
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "decorator" {
                continue;
            }
            if let Some((method, path)) = self.python_route(child) {
                self.apis.push(ApiFact {
                    kind: ApiKind::HttpRoute,
                    method: Some(method),
                    path: Some(path),
                    name: None,
                    handler_name: Some(handler.clone()),
                    request_type: None,
                    response_type: None,
                    line: span_of(child).start_line,
                });
            }
        }
    }

    /// Parses one decorator into `(method, path)` when it is an HTTP route
    /// (`app.get`, `router.post`, `app.route(..., methods=[...])`, ...).
    fn python_route(&self, decorator: Node<'a>) -> Option<(String, String)> {
        // `@ <call>` — the decorator wraps a call expression.
        let mut cursor = decorator.walk();
        let call = decorator
            .children(&mut cursor)
            .find(|c| c.kind() == "call")?;
        let function = call.child_by_field_name("function")?;
        if function.kind() != "attribute" {
            return None;
        }
        let verb = field_text(function, "attribute", self.source)?;
        if !is_http_decorator(&verb) {
            return None;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let path = first_string_arg(arguments, self.source)?;
        let method = if verb == "route" {
            python_route_methods(arguments, self.source).unwrap_or_else(|| "GET".to_string())
        } else {
            verb.to_ascii_uppercase()
        };
        Some((method, path))
    }

    /// Parses a Go route registration call into `(method, path, handler)`:
    /// `http.HandleFunc("/x", h)` / `mux.Handle("/x", h)` (any method) or a gin/
    /// echo/chi verb call `r.GET("/x", h)`. The handler is the last identifier
    /// argument (the function reference).
    fn go_route(&self, node: Node<'a>, callee: &str) -> Option<(String, String, Option<String>)> {
        let method = match callee {
            "HandleFunc" | "Handle" => "ANY".to_string(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" | "Any" => {
                callee.to_ascii_uppercase()
            }
            _ => return None,
        };
        let arguments = node.child_by_field_name("arguments")?;
        let path = first_string_arg(arguments, self.source)?;
        let handler = last_identifier_arg(arguments, self.source);
        Some((method, path, handler))
    }

    /// Extracts an HTTP route from a Rust `function_item`'s attributes
    /// (`#[get("/x")]`, `#[post("/x")]`, actix/rocket), with the function as
    /// the handler.
    fn detect_rust_route(&mut self, node: Node<'a>) {
        let Some(handler) = field_text(node, "name", self.source) else {
            return;
        };
        // In tree-sitter-rust, attributes are sibling `attribute_item`s placed
        // immediately before the function, not children — walk back over the
        // contiguous run (skipping comments).
        let mut sibling = node.prev_sibling();
        while let Some(prev) = sibling {
            match prev.kind() {
                "attribute_item" => {
                    if let Some((method, path)) = rust_route_attribute(prev, self.source) {
                        self.apis.push(ApiFact {
                            kind: ApiKind::HttpRoute,
                            method: Some(method),
                            path: Some(path),
                            name: None,
                            handler_name: Some(handler.clone()),
                            request_type: None,
                            response_type: None,
                            line: span_of(prev).start_line,
                        });
                    }
                }
                "line_comment" | "block_comment" => {}
                _ => break,
            }
            sibling = prev.prev_sibling();
        }
    }

    /// Provider-pattern secret scan over a string literal (near-zero false
    /// positives — no name or entropy needed).
    fn scan_string_secret(&mut self, node: Node<'a>) {
        if let Some(text) = node_text(node, self.source)
            && let Some(label) = security::provider_secret(&text)
        {
            self.security
                .push(security::secret_fact(span_of(node).start_line, label));
        }
    }

    /// Records `ovecc-ignore` suppression lines from a comment. A bare
    /// `ovecc-ignore` suppresses the comment's own line (trailing form); an
    /// `ovecc-ignore-next-line` suppresses the line below.
    fn extract_suppression(&mut self, node: Node<'a>) {
        let Some(text) = node_text(node, self.source) else {
            return;
        };
        if !text.contains("ovecc-ignore") {
            return;
        }
        let line = span_of(node).start_line;
        if text.contains("ovecc-ignore-next-line") {
            self.suppressed.push(line + 1);
        } else {
            self.suppressed.push(line);
        }
    }

    /// `self`/`this` are spelled differently per language; normalize so the
    /// resolver's enclosing-class branch fires uniformly.
    fn normalize_receiver(&self, receiver: String) -> String {
        match self.language {
            SourceLanguage::Python | SourceLanguage::Rust if receiver == "self" => {
                "this".to_string()
            }
            _ => receiver,
        }
    }

    fn call_target(&self, node: Node<'a>) -> Option<(String, Option<String>, CallKind)> {
        // Rust macros (`println!`, `sqlx::query!`) read as calls for taint.
        if node.kind() == "macro_invocation" {
            let macro_node = node.child_by_field_name("macro")?;
            let name = last_segment(&node_text(macro_node, self.source)?).to_string();
            return Some((name, None, CallKind::Direct));
        }

        let function = node.child_by_field_name("function")?;
        match function.kind() {
            "identifier" | "field_identifier" => {
                Some((node_text(function, self.source)?, None, CallKind::Direct))
            }
            // Python `obj.method(...)`.
            "attribute" => {
                let method = field_text(function, "attribute", self.source)?;
                let receiver = field_text(function, "object", self.source);
                Some((method, receiver, CallKind::Method))
            }
            // Go `obj.Method(...)`.
            "selector_expression" => {
                let method = field_text(function, "field", self.source)?;
                let receiver = field_text(function, "operand", self.source);
                Some((method, receiver, CallKind::Method))
            }
            // Rust `obj.method(...)` and C++ `obj.method(...)` / `p->method(...)`.
            "field_expression" => {
                let method = field_text(function, "field", self.source)?;
                let receiver = field_text(function, "value", self.source)
                    .or_else(|| field_text(function, "argument", self.source));
                Some((method, receiver, CallKind::Method))
            }
            // `Type::assoc()` (Rust) / `ns::func()` (C++): the last segment is
            // the callee. The path is not a runtime receiver, but its tail (the
            // type/module) is kept as `receiver` so security classification can
            // see `Command::new`, `md5::compute`, etc. The kind stays `Direct`,
            // so dispatch resolution still ignores it (receiver drives only
            // `Method` calls).
            "scoped_identifier" | "qualified_identifier" => {
                let name = field_text(function, "name", self.source).unwrap_or_else(|| {
                    last_segment(&node_text(function, self.source).unwrap_or_default()).to_string()
                });
                let receiver = field_text(function, "path", self.source)
                    .or_else(|| field_text(function, "scope", self.source))
                    .map(|scope| last_segment(&scope).to_string());
                Some((name, receiver, CallKind::Direct))
            }
            "template_function" => {
                let name = field_text(function, "name", self.source)?;
                Some((name, None, CallKind::Direct))
            }
            _ => {
                let text = node_text(function, self.source)?;
                Some((last_segment(&text).to_string(), None, CallKind::Direct))
            }
        }
    }

    // -- imports -----------------------------------------------------------

    fn record_import(&mut self, node: Node<'a>) {
        let line = span_of(node).start_line;
        for specifier in self.import_specifiers(node) {
            if specifier.is_empty() {
                continue;
            }
            self.imports.push(ImportFact {
                specifier,
                line,
                kind: ImportFactKind::Static,
                imported_names: Vec::new(),
            });
        }
    }

    fn import_specifiers(&self, node: Node<'a>) -> Vec<String> {
        match self.language {
            SourceLanguage::Python => match node.kind() {
                // `from pkg.mod import a, b` -> the module path.
                "import_from_statement" => field_text(node, "module_name", self.source)
                    .into_iter()
                    .collect(),
                // `import a.b, c` -> each dotted module.
                _ => {
                    let mut out = Vec::new();
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        match child.kind() {
                            "dotted_name" => {
                                if let Some(text) = node_text(child, self.source) {
                                    out.push(text);
                                }
                            }
                            "aliased_import" => {
                                if let Some(name) = field_text(child, "name", self.source) {
                                    out.push(name);
                                }
                            }
                            _ => {}
                        }
                    }
                    out
                }
            },
            SourceLanguage::Go => {
                // One or many `import_spec`s, each with a quoted `path`.
                let mut out = Vec::new();
                collect_go_import_paths(node, self.source, &mut out);
                out
            }
            SourceLanguage::Rust => {
                // `use a::b::c;` -> the whole clause text, whitespace-normalized.
                field_text(node, "argument", self.source)
                    .map(|t| t.split_whitespace().collect::<String>())
                    .into_iter()
                    .collect()
            }
            SourceLanguage::Cpp => field_text(node, "path", self.source)
                .map(|p| strip_include(&p))
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    // -- local types -------------------------------------------------------

    fn record_local_type(&mut self, node: Node<'a>) {
        if let Some((var, ty)) = self.local_type_binding(node)
            && !var.is_empty()
            && !ty.is_empty()
        {
            self.local_types.push((var, ty));
        }
    }

    fn local_type_binding(&self, node: Node<'a>) -> Option<(String, String)> {
        match self.language {
            // `let v: T = ...;`
            SourceLanguage::Rust => {
                let var = field_text(node, "pattern", self.source)?;
                let ty = field_text(node, "type", self.source).map(|t| clean_type(&t))?;
                Some((var, ty))
            }
            // `T v;` / `ns::T v = expr;` (declarator is a plain identifier;
            // skip primitives and anything more structured than a named type).
            SourceLanguage::Cpp => {
                let ty_node = node.child_by_field_name("type")?;
                if !matches!(ty_node.kind(), "type_identifier" | "qualified_identifier") {
                    return None;
                }
                let ty = clean_type(&node_text(ty_node, self.source)?);
                let var = self.cpp_simple_var_name(node.child_by_field_name("declarator")?)?;
                Some((var, ty))
            }
            _ => None,
        }
    }

    // -- language helpers --------------------------------------------------

    fn role(&self, node: Node<'a>) -> Role {
        let kind = node.kind();
        match self.language {
            SourceLanguage::Python => match kind {
                "function_definition" => Role::Callable,
                "class_definition" => Role::Type(SymbolKind::Class),
                "call" => Role::Call,
                "import_statement" | "import_from_statement" => Role::Import,
                _ => Role::Plain,
            },
            SourceLanguage::Go => match kind {
                "function_declaration" | "method_declaration" => Role::Callable,
                "type_spec" => Role::Type(go_type_kind(node)),
                "call_expression" => Role::Call,
                "import_declaration" => Role::Import,
                "const_spec" => Role::Const(SymbolKind::Constant),
                _ => Role::Plain,
            },
            SourceLanguage::Rust => match kind {
                "function_item" => Role::Callable,
                "struct_item" => Role::Type(SymbolKind::Struct),
                "enum_item" => Role::Type(SymbolKind::Enum),
                "union_item" => Role::Type(SymbolKind::Struct),
                "trait_item" => Role::Type(SymbolKind::Trait),
                "type_item" => Role::Type(SymbolKind::TypeAlias),
                "impl_item" => Role::Container { methods_here: true },
                "mod_item" => Role::Container {
                    methods_here: false,
                },
                "call_expression" | "macro_invocation" => Role::Call,
                "use_declaration" => Role::Import,
                "const_item" | "static_item" => Role::Const(SymbolKind::Constant),
                "let_declaration" => Role::LocalType,
                _ => Role::Plain,
            },
            SourceLanguage::Cpp => match kind {
                "function_definition" => Role::Callable,
                "class_specifier" => Role::Type(SymbolKind::Class),
                "struct_specifier" => Role::Type(SymbolKind::Struct),
                "union_specifier" => Role::Type(SymbolKind::Struct),
                "enum_specifier" => Role::Type(SymbolKind::Enum),
                "namespace_definition" => Role::Container {
                    methods_here: false,
                },
                "call_expression" => Role::Call,
                "preproc_include" => Role::Import,
                _ => Role::Plain,
            },
            _ => Role::Plain,
        }
    }

    fn go_receiver_type(&self, node: Node<'a>) -> Option<String> {
        let receiver = node.child_by_field_name("receiver")?; // parameter_list
        let mut cursor = receiver.walk();
        for child in receiver.named_children(&mut cursor) {
            if child.kind() == "parameter_declaration"
                && let Some(ty) = child.child_by_field_name("type")
            {
                return node_text(ty, self.source).map(|t| clean_type(&t));
            }
        }
        None
    }

    /// Resolves a C++ declarator to its declared name, descending through
    /// pointer/reference/array/parenthesized/init wrappers.
    fn cpp_declarator_name(&self, node: Node<'a>) -> Option<String> {
        match node.kind() {
            "identifier"
            | "field_identifier"
            | "type_identifier"
            | "qualified_identifier"
            | "destructor_name"
            | "operator_name" => node_text(node, self.source),
            "function_declarator"
            | "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "array_declarator"
            | "init_declarator" => node
                .child_by_field_name("declarator")
                .and_then(|d| self.cpp_declarator_name(d)),
            "template_function" => field_text(node, "name", self.source),
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if let Some(name) = self.cpp_declarator_name(child) {
                        return Some(name);
                    }
                }
                None
            }
        }
    }

    /// The variable name of a plain C++ declarator (`v`, `*v`, `v = expr`),
    /// or `None` if it declares anything more structured (a function).
    fn cpp_simple_var_name(&self, node: Node<'a>) -> Option<String> {
        match node.kind() {
            "identifier" => node_text(node, self.source),
            "init_declarator" | "pointer_declarator" | "reference_declarator" => node
                .child_by_field_name("declarator")
                .and_then(|d| self.cpp_simple_var_name(d)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn span_of(node: Node<'_>) -> Span {
    Span {
        start_line: node.start_position().row as u32 + 1,
        end_line: node.end_position().row as u32 + 1,
    }
}

fn node_text(node: Node<'_>, source: &[u8]) -> Option<String> {
    node.utf8_text(source).ok().map(|s| s.to_string())
}

fn field_text(node: Node<'_>, field: &str, source: &[u8]) -> Option<String> {
    node.child_by_field_name(field)
        .and_then(|child| node_text(child, source))
}

/// The last `.`/`::`-separated segment of a (possibly qualified) name.
fn last_segment(name: &str) -> &str {
    name.rsplit("::")
        .next()
        .unwrap_or(name)
        .rsplit('.')
        .next()
        .unwrap_or(name)
}

/// Reduces a type expression to its base name: strips leading `&`/`*`/`mut`
/// and any generic/array suffix, so `&mut Server<T>` -> `Server`.
fn clean_type(raw: &str) -> String {
    let mut value = raw.trim();
    loop {
        let next = value
            .trim_start_matches('&')
            .trim_start_matches('*')
            .trim_start();
        let next = next.strip_prefix("mut ").unwrap_or(next).trim_start();
        if next == value {
            break;
        }
        value = next;
    }
    let end = value.find(['<', '[', ' ', '{', '(']).unwrap_or(value.len());
    last_segment(value[..end].trim()).to_string()
}

/// Strips the `<...>` or `"..."` around a C++ include path.
fn strip_include(raw: &str) -> String {
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    if trimmed.len() >= 2 {
        let first = bytes[0];
        let last = bytes[trimmed.len() - 1];
        if (first == b'<' && last == b'>') || (first == b'"' && last == b'"') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

/// True if a declarator chain ultimately declares a function (vs a variable).
fn contains_function_declarator(node: Node<'_>) -> bool {
    match node.kind() {
        "function_declarator" => true,
        "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "init_declarator" => node
            .child_by_field_name("declarator")
            .map(contains_function_declarator)
            .unwrap_or(false),
        _ => false,
    }
}

/// Maps a Go `type_spec`'s underlying type to a symbol kind.
fn go_type_kind(node: Node<'_>) -> SymbolKind {
    match node.child_by_field_name("type").map(|t| t.kind()) {
        Some("struct_type") => SymbolKind::Struct,
        Some("interface_type") => SymbolKind::Interface,
        _ => SymbolKind::TypeAlias,
    }
}

/// Collects quoted import paths from a Go `import_declaration` (one spec or a
/// parenthesized `import_spec_list`).
fn collect_go_import_paths(node: Node<'_>, source: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "import_spec" => {
            if let Some(path) = field_text(node, "path", source) {
                out.push(strip_quotes(&path));
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_go_import_paths(child, source, out);
            }
        }
    }
}

fn strip_quotes(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix(['"', '`'])
        .and_then(|s| s.strip_suffix(['"', '`']))
        .unwrap_or(trimmed)
        .to_string()
}

/// Classifies a call as a dangerous sink or weak-crypto use, by language, from
/// its callee and receiver (the object/module/type before the call: `os` in
/// `os.system`, `Command` in `Command::new`). Conservative — only well-known
/// stdlib/crypto entry points, so the taint engine gets real sinks.
fn dangerous_call(
    language: SourceLanguage,
    callee: &str,
    receiver: Option<&str>,
) -> Option<(SecurityPatternKind, String)> {
    use SecurityPatternKind::{CommandExec, DynamicEval, WeakHash};
    match language {
        SourceLanguage::Python => match (receiver, callee) {
            (None, "eval") | (None, "exec") => Some((DynamicEval, format!("{callee}()"))),
            (
                Some("os"),
                "system" | "popen" | "execl" | "execlp" | "execv" | "execvp" | "execve" | "spawnl"
                | "spawnv",
            ) => Some((CommandExec, format!("os.{callee}"))),
            (
                Some("subprocess"),
                "call" | "run" | "Popen" | "check_output" | "check_call" | "getoutput"
                | "getstatusoutput",
            ) => Some((CommandExec, format!("subprocess.{callee}"))),
            (Some("hashlib"), "md5") => Some((WeakHash, "MD5".to_string())),
            (Some("hashlib"), "sha1") => Some((WeakHash, "SHA-1".to_string())),
            _ => None,
        },
        SourceLanguage::Go => match (receiver, callee) {
            (Some("exec"), "Command" | "CommandContext") => {
                Some((CommandExec, format!("exec.{callee}")))
            }
            (Some("syscall"), "Exec") => Some((CommandExec, "syscall.Exec".to_string())),
            (Some("md5"), "New" | "Sum") => Some((WeakHash, "MD5".to_string())),
            (Some("sha1"), "New" | "Sum") => Some((WeakHash, "SHA-1".to_string())),
            _ => None,
        },
        SourceLanguage::Rust => match (receiver, callee) {
            (Some("Command"), "new") => Some((CommandExec, "Command::new".to_string())),
            (Some("Md5"), "new") | (Some("md5"), "compute") => Some((WeakHash, "MD5".to_string())),
            (Some("Sha1"), "new") => Some((WeakHash, "SHA-1".to_string())),
            _ => None,
        },
        SourceLanguage::Cpp => match (receiver, callee) {
            (
                None | Some("std"),
                "system" | "popen" | "_popen" | "execl" | "execlp" | "execle" | "execv" | "execvp"
                | "execve",
            ) => Some((CommandExec, format!("{callee}()"))),
            (None, "MD5") => Some((WeakHash, "MD5".to_string())),
            (None, "SHA1") => Some((WeakHash, "SHA-1".to_string())),
            _ => None,
        },
        _ => None,
    }
}

/// HTTP route decorator/method names (Flask, FastAPI, and friends).
fn is_http_decorator(verb: &str) -> bool {
    matches!(
        verb,
        "route" | "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "websocket"
    )
}

/// The first string-literal argument in an `argument_list`, unquoted.
fn first_string_arg(arguments: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        if is_string_literal(child.kind()) {
            return node_text(child, source).map(|t| unquote_string(&t));
        }
    }
    None
}

/// The last identifier/selector argument in an `argument_list` — a route's
/// handler reference (`getUser`, `handlers.GetUser`). Returns the last segment.
fn last_identifier_arg(arguments: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = arguments.walk();
    let mut last = None;
    for child in arguments.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "identifier" | "selector_expression" | "field_identifier"
        ) && let Some(text) = node_text(child, source)
        {
            last = Some(last_segment(&text).to_string());
        }
    }
    last
}

/// Parses a Rust `#[get("/x")]`-style route attribute into `(method, path)`.
fn rust_route_attribute(attribute_item: Node<'_>, source: &[u8]) -> Option<(String, String)> {
    // attribute_item -> attribute(identifier + token_tree(args)).
    let mut cursor = attribute_item.walk();
    let attribute = attribute_item
        .named_children(&mut cursor)
        .find(|c| c.kind() == "attribute")?;
    let verb = attribute
        .named_children(&mut attribute.walk())
        .find(|c| matches!(c.kind(), "identifier" | "scoped_identifier"))
        .and_then(|n| node_text(n, source))
        .map(|t| last_segment(&t).to_ascii_lowercase())?;
    if !matches!(
        verb.as_str(),
        "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "route"
    ) {
        return None;
    }
    // The path is the first string literal in the attribute's argument tree.
    let tokens = attribute
        .named_children(&mut attribute.walk())
        .find(|c| c.kind() == "token_tree")?;
    let path = first_string_arg(tokens, source)?;
    Some((verb.to_ascii_uppercase(), path))
}

/// Extracts the first HTTP verb from a Flask `methods=["GET", "POST"]` keyword
/// argument, uppercased.
fn python_route_methods(arguments: Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        if child.kind() != "keyword_argument" {
            continue;
        }
        if field_text(child, "name", source).as_deref() != Some("methods") {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        let mut list_cursor = value.walk();
        for item in value.named_children(&mut list_cursor) {
            if is_string_literal(item.kind()) {
                return node_text(item, source).map(|t| unquote_string(&t).to_ascii_uppercase());
            }
        }
    }
    None
}

/// Strips an optional string prefix (`f`/`r`/`b`/`u`) and one layer of matching
/// quotes (`'`, `"`, or `` ` ``) from a string-literal token.
fn unquote_string(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_prefix = trimmed.trim_start_matches(['f', 'r', 'b', 'u', 'F', 'R', 'B', 'U']);
    let bytes = without_prefix.as_bytes();
    if without_prefix.len() >= 2 {
        let first = bytes[0];
        let last = bytes[without_prefix.len() - 1];
        if (first == b'"' || first == b'\'' || first == b'`') && first == last {
            return without_prefix[1..without_prefix.len() - 1].to_string();
        }
    }
    without_prefix.to_string()
}

/// Comment node kinds across the supported grammars (for inline suppressions).
fn is_comment(kind: &str) -> bool {
    matches!(kind, "comment" | "line_comment" | "block_comment")
}

/// Decision-point node kinds for cyclomatic complexity (each adds one path),
/// per grammar. Boolean operators are counted separately by
/// [`is_logical_operator`]; nesting structures are also decisions and appear
/// here too.
fn decision_node(language: SourceLanguage, kind: &str) -> bool {
    match language {
        SourceLanguage::Python => matches!(
            kind,
            "if_statement"
                | "elif_clause"
                | "for_statement"
                | "while_statement"
                | "except_clause"
                | "conditional_expression"
                | "case_clause"
        ),
        SourceLanguage::Go => matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "expression_case"
                | "type_case"
                | "communication_case"
        ),
        SourceLanguage::Rust => matches!(
            kind,
            "if_expression"
                | "while_expression"
                | "for_expression"
                | "loop_expression"
                | "match_arm"
                | "try_expression"
        ),
        SourceLanguage::Cpp => matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "do_statement"
                | "case_statement"
                | "catch_clause"
                | "conditional_expression"
                | "for_range_loop"
        ),
        _ => false,
    }
}

/// Control-flow node kinds that increase cognitive nesting depth (and add
/// `1 + depth` to the cognitive score), per grammar.
fn nesting_node(language: SourceLanguage, kind: &str) -> bool {
    match language {
        SourceLanguage::Python => matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "conditional_expression"
                | "match_statement"
                | "except_clause"
        ),
        SourceLanguage::Go => matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
                | "select_statement"
        ),
        SourceLanguage::Rust => matches!(
            kind,
            "if_expression"
                | "while_expression"
                | "for_expression"
                | "loop_expression"
                | "match_expression"
        ),
        SourceLanguage::Cpp => matches!(
            kind,
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
                | "try_statement"
                | "conditional_expression"
                | "for_range_loop"
        ),
        _ => false,
    }
}

/// True for a short-circuiting boolean operator (`&&`/`||`, or Python's
/// `and`/`or` `boolean_operator` node) — each adds a path and a cognitive point.
fn is_logical_operator(node: Node<'_>, source: &[u8]) -> bool {
    match node.kind() {
        "boolean_operator" => true, // Python `and`/`or`
        "binary_expression" | "logical_expression" => node
            .child_by_field_name("operator")
            .and_then(|op| node_text(op, source))
            .map(|op| op == "&&" || op == "||")
            .unwrap_or(false),
        _ => false,
    }
}

/// String-literal node kinds across the supported grammars (for secret scans).
fn is_string_literal(kind: &str) -> bool {
    matches!(
        kind,
        "string"                            // Python
            | "string_literal"              // Rust, C++
            | "raw_string_literal"          // Rust, Go
            | "interpreted_string_literal" // Go
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(language: SourceLanguage, contents: &str) -> FileFacts {
        let adapter = GenericAdapter::for_language(language).expect("adapter");
        let file = SourceFile {
            path: format!("fixture.{}", language.as_str()),
            absolute_path: std::path::PathBuf::from("fixture"),
            language,
            contents: contents.to_string(),
        };
        adapter.extract(&file).expect("extraction")
    }

    fn qnames(facts: &FileFacts) -> Vec<String> {
        facts
            .symbols
            .iter()
            .map(|s| format!("{}:{}", s.qualified_name, kind_tag(s.kind)))
            .collect()
    }

    fn complexity_of<'b>(facts: &'b FileFacts, name: &str) -> &'b ComplexityFact {
        facts
            .complexity
            .iter()
            .find(|c| c.qualified_name == name || c.qualified_name.ends_with(name))
            .unwrap_or_else(|| panic!("no complexity for {name}: {:?}", facts.complexity))
    }

    #[test]
    fn python_complexity_counts_branches_and_nesting() {
        let facts = extract(
            SourceLanguage::Python,
            "def simple(x):\n    return x\n\n\
             def branchy(x):\n    if x and x > 0:\n        for i in range(x):\n            \
             if i % 2 == 0:\n                print(i)\n    return x\n",
        );
        let simple = complexity_of(&facts, "simple");
        assert_eq!(simple.cyclomatic, 1, "{simple:?}");
        assert_eq!(simple.cognitive, 0, "{simple:?}");
        assert_eq!(simple.param_count, 1);
        let branchy = complexity_of(&facts, "branchy");
        assert!(branchy.cyclomatic >= 4, "{branchy:?}");
        assert!(
            branchy.cognitive >= 5,
            "deep nesting must weigh: {branchy:?}"
        );
    }

    #[test]
    fn rust_complexity_counts_branches_and_nesting() {
        let facts = extract(
            SourceLanguage::Rust,
            "fn simple(x: i32) -> i32 { x }\n\
             fn branchy(x: i32) -> i32 {\n    if x > 0 && x < 10 {\n        for i in 0..x {\n            \
             match i { 0 => {}, _ => {} }\n        }\n    }\n    x\n}\n",
        );
        assert_eq!(complexity_of(&facts, "simple").cyclomatic, 1);
        let branchy = complexity_of(&facts, "branchy");
        assert!(branchy.cyclomatic >= 4, "{branchy:?}");
        assert!(branchy.cognitive >= 4, "{branchy:?}");
    }

    #[test]
    fn go_complexity_counts_branches_and_nesting() {
        let facts = extract(
            SourceLanguage::Go,
            "package main\nfunc simple(x int) int { return x }\n\
             func branchy(x int) int {\n    if x > 0 && x < 10 {\n        for i := 0; i < x; i++ {\n            \
             switch i {\n            case 0:\n            default:\n            }\n        }\n    }\n    return x\n}\n",
        );
        assert_eq!(complexity_of(&facts, "simple").cyclomatic, 1);
        let branchy = complexity_of(&facts, "branchy");
        assert!(branchy.cyclomatic >= 3, "{branchy:?}");
        assert!(branchy.cognitive >= 3, "{branchy:?}");
    }

    fn kind_tag(kind: SymbolKind) -> &'static str {
        match kind {
            SymbolKind::Function => "fn",
            SymbolKind::Method => "method",
            SymbolKind::Class => "class",
            SymbolKind::Struct => "struct",
            SymbolKind::Enum => "enum",
            SymbolKind::Interface => "iface",
            SymbolKind::Trait => "trait",
            SymbolKind::TypeAlias => "alias",
            SymbolKind::Constant => "const",
            SymbolKind::Variable => "var",
        }
    }

    fn callee_names(facts: &FileFacts) -> Vec<String> {
        facts.calls.iter().map(|c| c.callee_name.clone()).collect()
    }

    #[test]
    fn python_class_method_call_and_import() {
        let facts = extract(
            SourceLanguage::Python,
            r#"
import os
from billing.invoice import Invoice

class Greeter:
    def greet(self, name):
        return os.getenv(name)

def main():
    g = Greeter()
    return g.greet("hi")
"#,
        );
        let names = qnames(&facts);
        assert!(names.contains(&"Greeter:class".to_string()), "{names:?}");
        assert!(
            names.contains(&"Greeter.greet:method".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"main:fn".to_string()), "{names:?}");

        // The method call `g.greet(...)` is attributed to `main` with receiver `g`.
        let greet_call = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "greet")
            .expect("greet call");
        assert_eq!(greet_call.caller_qualified_name.as_deref(), Some("main"));
        assert_eq!(greet_call.receiver.as_deref(), Some("g"));

        let specs: Vec<_> = facts.imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specs.contains(&"os"), "{specs:?}");
        assert!(specs.contains(&"billing.invoice"), "{specs:?}");
    }

    #[test]
    fn go_struct_method_with_receiver_and_import() {
        let facts = extract(
            SourceLanguage::Go,
            r#"
package server

import (
    "fmt"
    "net/http"
)

type Server struct {
    addr string
}

func (s *Server) Start() error {
    fmt.Println(s.addr)
    return http.ListenAndServe(s.addr, nil)
}

func main() {
    s := Server{}
    s.Start()
}
"#,
        );
        let names = qnames(&facts);
        assert!(names.contains(&"Server:struct".to_string()), "{names:?}");
        // Method qualified by its receiver type, not the file.
        assert!(
            names.contains(&"Server.Start:method".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"main:fn".to_string()), "{names:?}");

        let start_call = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "Start")
            .expect("Start call");
        assert_eq!(start_call.caller_qualified_name.as_deref(), Some("main"));
        assert_eq!(start_call.receiver.as_deref(), Some("s"));

        let specs: Vec<_> = facts.imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specs.contains(&"fmt"), "{specs:?}");
        assert!(specs.contains(&"net/http"), "{specs:?}");
    }

    #[test]
    fn rust_impl_method_macro_and_use() {
        let facts = extract(
            SourceLanguage::Rust,
            r#"
use std::io::Write;

pub struct Server {
    port: u16,
}

impl Server {
    pub fn start(&self) {
        let handler: Handler = make();
        handler.handle();
        println!("on {}", self.port);
    }
}

fn main() {
    let s = Server { port: 8080 };
    s.start();
}
"#,
        );
        let names = qnames(&facts);
        assert!(names.contains(&"Server:struct".to_string()), "{names:?}");
        // Method qualified by the impl's type.
        assert!(
            names.contains(&"Server.start:method".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"main:fn".to_string()), "{names:?}");

        // `self.port` normalizes the receiver to `this` for dispatch.
        let println = facts.calls.iter().find(|c| c.callee_name == "println");
        assert!(
            println.is_some(),
            "macro call recorded: {:?}",
            callee_names(&facts)
        );

        // The typed `let handler: Handler` is captured for receiver typing.
        assert!(
            facts
                .local_types
                .iter()
                .any(|(v, t)| v == "handler" && t == "Handler"),
            "{:?}",
            facts.local_types
        );

        let specs: Vec<_> = facts.imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specs.iter().any(|s| s.contains("std::io")), "{specs:?}");
    }

    #[test]
    fn cpp_class_method_free_function_and_include() {
        let facts = extract(
            SourceLanguage::Cpp,
            r#"
#include <vector>
#include "calculator.h"

namespace math {

class Calculator {
public:
    int add(int a, int b);
    int total() {
        return add(1, 2);
    }
};

int Calculator::add(int a, int b) {
    return a + b;
}

}

int main() {
    math::Calculator calc;
    return calc.total();
}
"#,
        );
        let names = qnames(&facts);
        // Inline method, out-of-line definition, and class are all captured,
        // qualified through the namespace and class.
        assert!(
            names.iter().any(|n| n == "math.Calculator:class"),
            "{names:?}"
        );
        assert!(
            names.iter().any(|n| n == "math.Calculator.total:method"),
            "{names:?}"
        );
        assert!(
            names.iter().any(|n| n == "math.Calculator.add:method"),
            "{names:?}"
        );
        assert!(names.iter().any(|n| n == "main:fn"), "{names:?}");

        // `calc.total()` is a method call attributed to `main` with receiver.
        let total_call = facts
            .calls
            .iter()
            .find(|c| c.callee_name == "total")
            .expect("total call");
        assert_eq!(total_call.caller_qualified_name.as_deref(), Some("main"));
        assert_eq!(total_call.receiver.as_deref(), Some("calc"));

        // `math::Calculator calc;` is captured as a typed local binding.
        assert!(
            facts
                .local_types
                .iter()
                .any(|(v, t)| v == "calc" && t == "Calculator"),
            "{:?}",
            facts.local_types
        );

        let specs: Vec<_> = facts.imports.iter().map(|i| i.specifier.as_str()).collect();
        assert!(specs.contains(&"vector"), "{specs:?}");
        assert!(specs.contains(&"calculator.h"), "{specs:?}");
    }

    #[test]
    fn unsupported_language_has_no_adapter() {
        assert!(GenericAdapter::for_language(SourceLanguage::TypeScript).is_none());
        assert!(GenericAdapter::for_language(SourceLanguage::Sql).is_none());
    }

    fn security_kinds(facts: &FileFacts) -> Vec<SecurityPatternKind> {
        facts.security_patterns.iter().map(|p| p.kind).collect()
    }

    #[test]
    fn python_detects_eval_command_and_weak_hash() {
        let facts = extract(
            SourceLanguage::Python,
            r#"
import os, subprocess, hashlib

def run(cmd):
    eval(cmd)
    os.system(cmd)
    subprocess.run(cmd, shell=True)
    return hashlib.md5(b"x")
"#,
        );
        let kinds = security_kinds(&facts);
        assert!(
            kinds.contains(&SecurityPatternKind::DynamicEval),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&SecurityPatternKind::CommandExec),
            "{kinds:?}"
        );
        assert!(kinds.contains(&SecurityPatternKind::WeakHash), "{kinds:?}");
        // The eval/command sinks are attributed to their enclosing function so
        // taint can reach them.
        let eval = facts
            .security_patterns
            .iter()
            .find(|p| p.kind == SecurityPatternKind::DynamicEval)
            .unwrap();
        assert_eq!(eval.caller_qualified_name.as_deref(), Some("run"));
    }

    #[test]
    fn go_detects_exec_command() {
        let facts = extract(
            SourceLanguage::Go,
            r#"
package main

import "os/exec"

func run(name string) {
    exec.Command("sh", "-c", name)
}
"#,
        );
        assert!(
            security_kinds(&facts).contains(&SecurityPatternKind::CommandExec),
            "{:?}",
            facts.security_patterns
        );
    }

    #[test]
    fn rust_detects_command_new() {
        let facts = extract(
            SourceLanguage::Rust,
            r#"
use std::process::Command;

fn run(arg: &str) {
    Command::new("sh").arg("-c").arg(arg);
}
"#,
        );
        assert!(
            security_kinds(&facts).contains(&SecurityPatternKind::CommandExec),
            "{:?}",
            facts.security_patterns
        );
    }

    #[test]
    fn rust_command_new_without_process_import_is_not_command_exec() {
        // `clap::Command::new` builds a CLI definition, not an OS command. Without
        // an `std::process::Command` import it must not be flagged (clap alone
        // produced 1400+ false positives before this filter).
        let facts = extract(
            SourceLanguage::Rust,
            r#"
use clap::Command;

fn build() -> Command {
    Command::new("myapp").arg("input")
}
"#,
        );
        assert!(
            !security_kinds(&facts).contains(&SecurityPatternKind::CommandExec),
            "clap Command::new must not be a command-exec sink: {:?}",
            facts.security_patterns
        );
    }

    #[test]
    fn cpp_detects_system_call() {
        let facts = extract(
            SourceLanguage::Cpp,
            r#"
#include <cstdlib>
void run(const char* cmd) {
    system(cmd);
}
"#,
        );
        assert!(
            security_kinds(&facts).contains(&SecurityPatternKind::CommandExec),
            "{:?}",
            facts.security_patterns
        );
    }

    #[test]
    fn python_extracts_http_routes() {
        let facts = extract(
            SourceLanguage::Python,
            r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/users/{id}")
def get_user(id):
    return id

@app.route("/legacy", methods=["POST"])
def legacy(req):
    return 1
"#,
        );
        assert_eq!(facts.apis.len(), 2, "{:?}", facts.apis);
        let get = facts
            .apis
            .iter()
            .find(|a| a.handler_name.as_deref() == Some("get_user"))
            .expect("get_user route");
        assert_eq!(get.method.as_deref(), Some("GET"));
        assert_eq!(get.path.as_deref(), Some("/users/{id}"));
        let post = facts
            .apis
            .iter()
            .find(|a| a.handler_name.as_deref() == Some("legacy"))
            .expect("legacy route");
        assert_eq!(post.method.as_deref(), Some("POST"));
        assert_eq!(post.path.as_deref(), Some("/legacy"));
    }

    #[test]
    fn go_extracts_http_routes() {
        let facts = extract(
            SourceLanguage::Go,
            r#"
package main

import "net/http"

func main() {
    http.HandleFunc("/users", getUsers)
    r.GET("/items", listItems)
}
"#,
        );
        assert_eq!(facts.apis.len(), 2, "{:?}", facts.apis);
        assert!(
            facts
                .apis
                .iter()
                .any(|a| a.path.as_deref() == Some("/users")
                    && a.handler_name.as_deref() == Some("getUsers")),
            "{:?}",
            facts.apis
        );
        let get = facts
            .apis
            .iter()
            .find(|a| a.path.as_deref() == Some("/items"))
            .unwrap();
        assert_eq!(get.method.as_deref(), Some("GET"));
        assert_eq!(get.handler_name.as_deref(), Some("listItems"));
    }

    #[test]
    fn rust_extracts_route_attribute() {
        let facts = extract(
            SourceLanguage::Rust,
            r#"
#[get("/health")]
async fn health() -> &'static str {
    "ok"
}
"#,
        );
        assert_eq!(facts.apis.len(), 1, "{:?}", facts.apis);
        let route = &facts.apis[0];
        assert_eq!(route.method.as_deref(), Some("GET"));
        assert_eq!(route.path.as_deref(), Some("/health"));
        assert_eq!(route.handler_name.as_deref(), Some("health"));
    }

    #[test]
    fn extracts_inline_suppressions() {
        // Rust trailing + next-line forms.
        let rust = extract(
            SourceLanguage::Rust,
            "fn f() {\n    g(); // ovecc-ignore\n    // ovecc-ignore-next-line\n    h();\n}\n",
        );
        assert!(
            rust.suppressed_lines.contains(&2),
            "{:?}",
            rust.suppressed_lines
        );
        assert!(
            rust.suppressed_lines.contains(&4),
            "{:?}",
            rust.suppressed_lines
        );

        // Python uses `#` comments.
        let py = extract(
            SourceLanguage::Python,
            "def f():\n    eval(x)  # ovecc-ignore\n",
        );
        assert!(
            py.suppressed_lines.contains(&2),
            "{:?}",
            py.suppressed_lines
        );
    }

    #[test]
    fn provider_pattern_secret_in_any_language() {
        // A hardcoded AWS key in a Go string literal is caught by the
        // language-agnostic provider scan.
        let facts = extract(
            SourceLanguage::Go,
            r#"
package config

const Key = "AKIAIOSFODNN7EXAMPLE"
"#,
        );
        assert!(
            security_kinds(&facts).contains(&SecurityPatternKind::HardcodedSecret),
            "{:?}",
            facts.security_patterns
        );
    }
}
