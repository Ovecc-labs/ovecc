// SPDX-License-Identifier: MIT
//! oxc-based semantic extraction for the TypeScript/JavaScript family.
//!
//! Runs alongside the tree-sitter [`crate::typescript::TypeScriptAdapter`] and
//! supplies the two facts tree-sitter cannot compute well: a file's **exports**
//! (with re-export provenance, for dead-code analysis) and **per-function
//! complexity** (McCabe cyclomatic + SonarSource cognitive). oxc is confined to
//! this module behind the parser boundary; only neutral `ovecc_core::facts`
//! types cross out.
//!
//! Ported from fallow (crates/extract/src/{parse.rs, complexity.rs,
//! visitor/visit_impl.rs, visitor/declarations.rs}), MIT (c) 2026
//! Bart Waardenburg. See THIRD-PARTY-NOTICES.md.

use ovecc_core::facts::{ComplexityFact, ExportFact, ReExportFact};
use ovecc_core::lang::SourceLanguage;

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_semantic::ScopeFlags;
use oxc_span::{SourceType, Span as OxcSpan};

/// Extracts `(exports, complexity)` from one JS/TS source via oxc. Returns
/// `None` for non-JS languages or on a hard parser panic (the caller then keeps
/// the tree-sitter facts unchanged).
pub fn extract(
    source: &str,
    language: SourceLanguage,
) -> Option<(Vec<ExportFact>, Vec<ComplexityFact>)> {
    let source_type = match language {
        SourceLanguage::TypeScript => SourceType::ts(),
        SourceLanguage::Tsx => SourceType::tsx(),
        SourceLanguage::JavaScript => SourceType::mjs(),
        SourceLanguage::Jsx => SourceType::jsx(),
        _ => return None,
    };
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return None;
    }
    let line_offsets = compute_line_offsets(source);
    let mut walker = OxcWalk::new(&line_offsets);
    walker.visit_program(&parsed.program);
    walker
        .exports
        .sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.name.cmp(&b.name)));
    walker.complexity.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| a.qualified_name.cmp(&b.qualified_name))
    });
    Some((walker.exports, walker.complexity))
}

/// Byte offset of each line start (`offsets[0] == 0`).
fn compute_line_offsets(source: &str) -> Vec<u32> {
    let mut offsets = vec![0u32];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            offsets.push((index + 1) as u32);
        }
    }
    offsets
}

/// 1-based line for a byte offset (oxc spans are byte offsets).
fn line_of(offsets: &[u32], byte: u32) -> u32 {
    match offsets.binary_search(&byte) {
        Ok(index) => index as u32 + 1,
        Err(index) => index.saturating_sub(1) as u32 + 1,
    }
}

/// Per-function complexity accumulation frame.
struct FunctionFrame {
    name: String,
    span: OxcSpan,
    cyclomatic: u16,
    cognitive: u16,
    nesting: u16,
    params: u8,
    param_names: Vec<String>,
}

struct OxcWalk<'s> {
    offsets: &'s [u32],
    exports: Vec<ExportFact>,
    complexity: Vec<ComplexityFact>,
    stack: Vec<FunctionFrame>,
    /// Name carried from an enclosing method/variable/`export default` onto the
    /// next anonymous function frame.
    pending_name: Option<String>,
}

impl<'s> OxcWalk<'s> {
    fn new(offsets: &'s [u32]) -> Self {
        Self {
            offsets,
            exports: Vec::new(),
            complexity: Vec::new(),
            stack: Vec::new(),
            pending_name: None,
        }
    }

    // -- complexity counter helpers (port of complexity.rs:205-230) ----------

    fn cyc(&mut self) {
        if let Some(frame) = self.stack.last_mut() {
            frame.cyclomatic = frame.cyclomatic.saturating_add(1);
        }
    }

    fn cog_nested(&mut self) {
        let nesting = self.stack.last().map_or(0, |frame| frame.nesting);
        if let Some(frame) = self.stack.last_mut() {
            frame.cognitive = frame.cognitive.saturating_add(1 + nesting);
        }
    }

    fn cog_flat(&mut self) {
        if let Some(frame) = self.stack.last_mut() {
            frame.cognitive = frame.cognitive.saturating_add(1);
        }
    }

    fn nest_inc(&mut self) {
        if let Some(frame) = self.stack.last_mut() {
            frame.nesting = frame.nesting.saturating_add(1);
        }
    }

    fn nest_dec(&mut self) {
        if let Some(frame) = self.stack.last_mut() {
            frame.nesting = frame.nesting.saturating_sub(1);
        }
    }

    fn enter_function(
        &mut self,
        name: Option<String>,
        span: OxcSpan,
        params: &FormalParameters<'_>,
    ) {
        let resolved = name
            .or_else(|| self.pending_name.take())
            .unwrap_or_else(|| "<anonymous>".to_string());
        // A nested function adds one nesting level to its parent (cognitive).
        if !self.stack.is_empty() {
            self.nest_inc();
        }
        self.stack.push(FunctionFrame {
            name: resolved,
            span,
            cyclomatic: 1,
            cognitive: 0,
            nesting: 0,
            params: count_params(params),
            param_names: param_names(params),
        });
    }

    fn exit_function(&mut self) {
        if let Some(frame) = self.stack.pop() {
            let line = line_of(self.offsets, frame.span.start);
            let end_line = line_of(self.offsets, frame.span.end);
            self.complexity.push(ComplexityFact {
                qualified_name: frame.name,
                line,
                cyclomatic: frame.cyclomatic,
                cognitive: frame.cognitive,
                line_count: end_line.saturating_sub(line) + 1,
                param_count: frame.params,
                param_names: frame.param_names,
            });
        }
        if !self.stack.is_empty() {
            self.nest_dec();
        }
    }

    /// `if` / `else if` / `else` chain (port of complexity.rs:366-398).
    fn visit_if_chain(&mut self, stmt: &IfStatement<'s>, is_else_if: bool) {
        self.cyc();
        if is_else_if {
            self.cog_flat();
        } else {
            self.cog_nested();
        }
        self.visit_expression(&stmt.test);
        self.nest_inc();
        self.visit_statement(&stmt.consequent);
        self.nest_dec();
        if let Some(alternate) = &stmt.alternate {
            match alternate {
                Statement::IfStatement(else_if) => self.visit_if_chain(else_if, true),
                other => {
                    self.cog_flat();
                    self.nest_inc();
                    self.visit_statement(other);
                    self.nest_dec();
                }
            }
        }
    }
}

/// Parameter count (rest counts as one). Excludes nothing fancy for v1.
fn count_params(params: &FormalParameters<'_>) -> u8 {
    let count = params.items.len() + usize::from(params.rest.is_some());
    count.min(u8::MAX as usize) as u8
}

/// Binding names of the parameters; destructuring patterns yield no name.
fn param_names(params: &FormalParameters<'_>) -> Vec<String> {
    let mut names: Vec<String> = params
        .items
        .iter()
        .filter_map(|item| item.pattern.get_binding_identifier())
        .map(|ident| ident.name.to_string())
        .collect();
    if let Some(rest) = &params.rest
        && let Some(ident) = rest.rest.argument.get_binding_identifier()
    {
        names.push(ident.name.to_string());
    }
    names
}

/// Exported names declared by an `export <decl>` (name, is_type_only).
fn declaration_export_names(declaration: &Declaration<'_>) -> Vec<(String, bool)> {
    match declaration {
        Declaration::FunctionDeclaration(function) => function
            .id
            .as_ref()
            .map(|id| vec![(id.name.to_string(), false)])
            .unwrap_or_default(),
        Declaration::ClassDeclaration(class) => class
            .id
            .as_ref()
            .map(|id| vec![(id.name.to_string(), false)])
            .unwrap_or_default(),
        Declaration::VariableDeclaration(variable) => variable
            .declarations
            .iter()
            .filter_map(|declarator| {
                declarator
                    .id
                    .get_binding_identifier()
                    .map(|id| (id.name.to_string(), false))
            })
            .collect(),
        Declaration::TSTypeAliasDeclaration(alias) => vec![(alias.id.name.to_string(), true)],
        Declaration::TSInterfaceDeclaration(interface) => {
            vec![(interface.id.name.to_string(), true)]
        }
        Declaration::TSEnumDeclaration(enumeration) => {
            vec![(enumeration.id.name.to_string(), false)]
        }
        _ => Vec::new(),
    }
}

/// The textual name of a `ModuleExportName` (`a` in `a as b`, the string in
/// `"a" as b`).
fn module_export_name(name: &ModuleExportName<'_>) -> String {
    match name {
        ModuleExportName::IdentifierName(id) => id.name.to_string(),
        ModuleExportName::IdentifierReference(id) => id.name.to_string(),
        ModuleExportName::StringLiteral(literal) => literal.value.to_string(),
    }
}

/// The identifier a declarator binds, for `const X = ...` (not destructuring).
fn binding_name(declarator: &VariableDeclarator<'_>) -> Option<String> {
    declarator
        .id
        .get_binding_identifier()
        .map(|id| id.name.to_string())
}

/// Dotted path of a static member chain (`module.exports.handler`). A computed
/// access or a call breaks the chain and yields `None`.
fn member_path(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::ThisExpression(_) => Some("this".to_string()),
        Expression::StaticMemberExpression(member) => Some(format!(
            "{}.{}",
            member_path(&member.object)?,
            member.property.name
        )),
        _ => None,
    }
}

/// Name written by an assignment: the bare identifier, or the dotted path of a
/// static member target.
fn assignment_target_name(target: &AssignmentTarget<'_>) -> Option<String> {
    let path = match target {
        AssignmentTarget::AssignmentTargetIdentifier(id) => id.name.to_string(),
        AssignmentTarget::StaticMemberExpression(member) => {
            format!("{}.{}", member_path(&member.object)?, member.property.name)
        }
        _ => return None,
    };
    Some(strip_noise_segments(&path))
}

/// Drops the path segments that carry no information: `exports.handler` and
/// `module.exports.handler` are both `handler`, `Foo.prototype.bar` is `Foo.bar`.
/// Without this every CommonJS handler in a file would share the `exports.`
/// prefix, which is exactly the noise the qualified name exists to remove.
fn strip_noise_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('.').collect();
    let mut kept: Vec<&str> = Vec::with_capacity(segments.len());
    for (index, segment) in segments.iter().enumerate() {
        let leading = kept.is_empty();
        let noise = match *segment {
            "module" => leading && segments.get(index + 1) == Some(&"exports"),
            "exports" | "this" => leading,
            "prototype" => true,
            _ => false,
        };
        if !noise {
            kept.push(segment);
        }
    }
    if kept.is_empty() {
        path.to_string()
    } else {
        kept.join(".")
    }
}

/// True when an initializer *is* a function, or wraps one in a common React
/// higher-order call (`useCallback`, `useMemo`, `memo`, `forwardRef`,
/// `observer`) — so `const Foo = () => {}` and `const f = useCallback(() => {})`
/// name their frames `Foo`/`f` instead of `<anonymous>`.
fn initializer_is_function(expr: &Expression<'_>) -> bool {
    match expr {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
        Expression::CallExpression(call) => {
            let wraps = matches!(
                &call.callee,
                Expression::Identifier(id)
                    if matches!(
                        id.name.as_str(),
                        "useCallback" | "useMemo" | "memo" | "forwardRef" | "observer"
                    )
            );
            wraps
                && matches!(
                    call.arguments.first(),
                    Some(Argument::ArrowFunctionExpression(_))
                        | Some(Argument::FunctionExpression(_))
                )
        }
        _ => false,
    }
}

impl<'a> Visit<'a> for OxcWalk<'a> {
    // -- exports -------------------------------------------------------------

    fn visit_export_named_declaration(&mut self, decl: &ExportNamedDeclaration<'a>) {
        let line = line_of(self.offsets, decl.span.start);
        let type_only = decl.export_kind.is_type();
        if let Some(source) = &decl.source {
            for specifier in &decl.specifiers {
                self.exports.push(ExportFact {
                    name: module_export_name(&specifier.exported),
                    local_name: None,
                    is_type_only: type_only,
                    line,
                    re_export: Some(ReExportFact {
                        source_specifier: source.value.to_string(),
                        imported_name: module_export_name(&specifier.local),
                    }),
                });
            }
        } else if let Some(declaration) = &decl.declaration {
            for (name, is_type) in declaration_export_names(declaration) {
                self.exports.push(ExportFact {
                    name,
                    local_name: None,
                    is_type_only: type_only || is_type,
                    line,
                    re_export: None,
                });
            }
        } else {
            for specifier in &decl.specifiers {
                let exported = module_export_name(&specifier.exported);
                let local = module_export_name(&specifier.local);
                let local_name = (local != exported).then_some(local);
                self.exports.push(ExportFact {
                    name: exported,
                    local_name,
                    is_type_only: type_only,
                    line,
                    re_export: None,
                });
            }
        }
        walk::walk_export_named_declaration(self, decl);
    }

    fn visit_export_default_declaration(&mut self, decl: &ExportDefaultDeclaration<'a>) {
        self.exports.push(ExportFact {
            name: "default".to_string(),
            local_name: None,
            is_type_only: false,
            line: line_of(self.offsets, decl.span.start),
            re_export: None,
        });
        self.pending_name = Some("default".to_string());
        walk::walk_export_default_declaration(self, decl);
    }

    fn visit_export_all_declaration(&mut self, decl: &ExportAllDeclaration<'a>) {
        let name = decl
            .exported
            .as_ref()
            .map_or_else(|| "*".to_string(), module_export_name);
        self.exports.push(ExportFact {
            name,
            local_name: None,
            is_type_only: decl.export_kind.is_type(),
            line: line_of(self.offsets, decl.span.start),
            re_export: Some(ReExportFact {
                source_specifier: decl.source.value.to_string(),
                imported_name: "*".to_string(),
            }),
        });
        walk::walk_export_all_declaration(self, decl);
    }

    // -- complexity: function frames -----------------------------------------

    fn visit_function(&mut self, func: &Function<'a>, flags: ScopeFlags) {
        let name = func.id.as_ref().map(|id| id.name.to_string());
        self.enter_function(name, func.span, &func.params);
        walk::walk_function(self, func, flags);
        self.exit_function();
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        self.enter_function(None, arrow.span, &arrow.params);
        walk::walk_arrow_function_expression(self, arrow);
        self.exit_function();
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        // Name the upcoming function frame (method.value is a Function, so
        // visit_function fires for it and consumes pending_name).
        self.pending_name = method.key.static_name().map(|name| name.to_string());
        walk::walk_method_definition(self, method);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        // Name a function bound to a variable: `const Foo = () => {}` reports
        // its frame as `Foo`, not `<anonymous>` — the dominant React/TS shape
        // for components and handlers. The name is consumed by the arrow's
        // visit_arrow_function_expression as the walk descends into the init.
        if let Some(init) = &declarator.init
            && initializer_is_function(init)
        {
            self.pending_name = binding_name(declarator);
        }
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        // `module.exports = { getTrajets: async () => {} }`, and object
        // literals of handlers or of test cases.
        if initializer_is_function(&property.value)
            && let Some(name) = property.key.static_name()
        {
            self.pending_name = Some(name.to_string());
        }
        walk::walk_object_property(self, property);
    }

    // -- complexity: decision points -----------------------------------------

    fn visit_if_statement(&mut self, stmt: &IfStatement<'a>) {
        self.visit_if_chain(stmt, false);
    }

    fn visit_for_statement(&mut self, stmt: &ForStatement<'a>) {
        self.cyc();
        self.cog_nested();
        self.nest_inc();
        walk::walk_for_statement(self, stmt);
        self.nest_dec();
    }

    fn visit_for_in_statement(&mut self, stmt: &ForInStatement<'a>) {
        self.cyc();
        self.cog_nested();
        self.nest_inc();
        walk::walk_for_in_statement(self, stmt);
        self.nest_dec();
    }

    fn visit_for_of_statement(&mut self, stmt: &ForOfStatement<'a>) {
        self.cyc();
        self.cog_nested();
        self.nest_inc();
        walk::walk_for_of_statement(self, stmt);
        self.nest_dec();
    }

    fn visit_while_statement(&mut self, stmt: &WhileStatement<'a>) {
        self.cyc();
        self.cog_nested();
        self.nest_inc();
        walk::walk_while_statement(self, stmt);
        self.nest_dec();
    }

    fn visit_do_while_statement(&mut self, stmt: &DoWhileStatement<'a>) {
        self.cyc();
        self.cog_nested();
        self.nest_inc();
        walk::walk_do_while_statement(self, stmt);
        self.nest_dec();
    }

    fn visit_switch_statement(&mut self, stmt: &SwitchStatement<'a>) {
        self.cog_nested();
        self.nest_inc();
        walk::walk_switch_statement(self, stmt);
        self.nest_dec();
    }

    fn visit_switch_case(&mut self, case: &SwitchCase<'a>) {
        if case.test.is_some() {
            self.cyc();
        }
        walk::walk_switch_case(self, case);
    }

    fn visit_catch_clause(&mut self, clause: &CatchClause<'a>) {
        self.cyc();
        self.cog_nested();
        self.nest_inc();
        walk::walk_catch_clause(self, clause);
        self.nest_dec();
    }

    fn visit_conditional_expression(&mut self, expr: &ConditionalExpression<'a>) {
        self.cyc();
        self.cog_nested();
        walk::walk_conditional_expression(self, expr);
    }

    fn visit_logical_expression(&mut self, expr: &LogicalExpression<'a>) {
        self.cyc();
        self.cog_flat();
        walk::walk_logical_expression(self, expr);
    }

    fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
        if matches!(
            expr.operator,
            AssignmentOperator::LogicalAnd
                | AssignmentOperator::LogicalOr
                | AssignmentOperator::LogicalNullish
        ) {
            self.cyc();
        }
        // `exports.getTrajets = async (req, res) => {}` is the dominant Node
        // and Express handler shape; without this every one of them lands in
        // the complexity list as `<anonymous>`, unsortable and impossible to
        // follow across runs.
        if initializer_is_function(&expr.right)
            && let Some(name) = assignment_target_name(&expr.left)
        {
            self.pending_name = Some(name);
        }
        walk::walk_assignment_expression(self, expr);
    }

    fn visit_break_statement(&mut self, stmt: &BreakStatement<'a>) {
        if stmt.label.is_some() {
            self.cog_flat();
        }
        walk::walk_break_statement(self, stmt);
    }

    fn visit_continue_statement(&mut self, stmt: &ContinueStatement<'a>) {
        if stmt.label.is_some() {
            self.cog_flat();
        }
        walk::walk_continue_statement(self, stmt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_named_and_default_exports() {
        let (exports, _) = extract(
            "export const a = 1;\nexport function f() {}\nexport default class C {}\n",
            SourceLanguage::TypeScript,
        )
        .unwrap();
        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a"), "{names:?}");
        assert!(names.contains(&"f"), "{names:?}");
        assert!(names.contains(&"default"), "{names:?}");
    }

    #[test]
    fn extracts_re_exports() {
        let (exports, _) = extract(
            "export { x as y } from './m';\nexport * from './n';\n",
            SourceLanguage::TypeScript,
        )
        .unwrap();
        let reexport = exports.iter().find(|e| e.name == "y").unwrap();
        assert_eq!(reexport.re_export.as_ref().unwrap().source_specifier, "./m");
        assert_eq!(reexport.re_export.as_ref().unwrap().imported_name, "x");
        assert!(
            exports
                .iter()
                .any(|e| e.re_export.as_ref().is_some_and(|r| r.imported_name == "*"))
        );
    }

    #[test]
    fn names_functions_bound_to_a_variable() {
        // The dominant React/TS shape: arrow/function bound to a const, and the
        // common `useCallback`/`memo` higher-order wrappers. These must report
        // the binding name, not `<anonymous>`.
        let (_exports, complexity) = extract(
            "const Foo = () => { if (a) { b(); } };\n\
             const bar = useCallback(() => { while (c) {} }, []);\n\
             function baz() {}\n\
             serve(async () => { if (d) {} });\n",
            SourceLanguage::TypeScript,
        )
        .unwrap();
        let names: Vec<&str> = complexity
            .iter()
            .map(|c| c.qualified_name.as_str())
            .collect();
        assert!(names.contains(&"Foo"), "{names:?}");
        assert!(names.contains(&"bar"), "{names:?}");
        assert!(names.contains(&"baz"), "{names:?}");
        // The bare arrow passed to `serve(...)` has no binding — stays anonymous.
        assert!(names.contains(&"<anonymous>"), "{names:?}");
    }

    #[test]
    fn names_functions_bound_to_an_assignment_or_a_property() {
        let (_exports, complexity) = extract(
            "exports.getTrajets = async (req, res) => { if (a) { b(); } };\n\
             module.exports.stop = function () { while (c) {} };\n\
             Service.prototype.run = function () { if (d) {} };\n\
             module.exports = { create: () => { if (e) {} }, remove() { if (f) {} } };\n\
             app.use(() => { if (g) {} });\n",
            SourceLanguage::JavaScript,
        )
        .unwrap();
        let names: Vec<&str> = complexity
            .iter()
            .map(|c| c.qualified_name.as_str())
            .collect();
        assert!(names.contains(&"getTrajets"), "{names:?}");
        assert!(names.contains(&"stop"), "{names:?}");
        assert!(names.contains(&"Service.run"), "{names:?}");
        assert!(names.contains(&"create"), "{names:?}");
        assert!(names.contains(&"remove"), "{names:?}");
        // A callback with no binding still has no name to report.
        assert!(names.contains(&"<anonymous>"), "{names:?}");
    }

    #[test]
    fn strips_only_the_uninformative_path_segments() {
        assert_eq!(strip_noise_segments("exports.handler"), "handler");
        assert_eq!(strip_noise_segments("module.exports.handler"), "handler");
        assert_eq!(strip_noise_segments("this.handler"), "handler");
        assert_eq!(strip_noise_segments("Foo.prototype.bar"), "Foo.bar");
        // `exports` below a real object is a property like any other.
        assert_eq!(strip_noise_segments("api.exports.run"), "api.exports.run");
        assert_eq!(strip_noise_segments("controller.login"), "controller.login");
    }

    #[test]
    fn computes_complexity() {
        // cyclomatic = 1 + if + else-if + && = 4; an empty fn would be 1.
        let (_, complexity) = extract(
            "function f(x) {\n  if (x > 0 && x < 10) { return 1; }\n  else if (x < 0) { return -1; }\n  return 0;\n}\n",
            SourceLanguage::TypeScript,
        )
        .unwrap();
        let f = complexity.iter().find(|c| c.qualified_name == "f").unwrap();
        assert!(f.cyclomatic >= 4, "cyclomatic {}", f.cyclomatic);
        assert!(f.cognitive >= 2, "cognitive {}", f.cognitive);
        assert_eq!(f.param_count, 1);
    }

    #[test]
    fn param_names_keep_identifiers_and_defaults_but_skip_destructuring() {
        let (_, complexity) = extract(
            "function f(host, port = 8080, { deep }, [first], ...rest) { return host; }\n",
            SourceLanguage::TypeScript,
        )
        .unwrap();
        let f = complexity.iter().find(|c| c.qualified_name == "f").unwrap();
        assert_eq!(f.param_names, vec!["host", "port", "rest"]);
        assert_eq!(f.param_count, 5, "count still covers every parameter slot");
    }

    #[test]
    fn empty_function_is_cyclomatic_one() {
        let (_, complexity) = extract(
            "function plain() { return 1; }\n",
            SourceLanguage::TypeScript,
        )
        .unwrap();
        let f = complexity
            .iter()
            .find(|c| c.qualified_name == "plain")
            .unwrap();
        assert_eq!(f.cyclomatic, 1);
        assert_eq!(f.cognitive, 0);
    }

    #[test]
    fn non_js_returns_none() {
        assert!(extract("def f(): pass", SourceLanguage::Python).is_none());
    }
}
