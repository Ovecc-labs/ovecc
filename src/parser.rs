use crate::model::{ImportFact, ImportKind, SourceLanguage};
use anyhow::{Context, Result};
use tree_sitter::{Node, Parser};

pub fn extract_imports(source: &str, language: SourceLanguage) -> Result<Vec<ImportFact>> {
    let mut parser = Parser::new();
    let tree_sitter_language: tree_sitter::Language = match language {
        SourceLanguage::JavaScript | SourceLanguage::Jsx => tree_sitter_javascript::LANGUAGE.into(),
        SourceLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        SourceLanguage::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
    };
    parser
        .set_language(&tree_sitter_language)
        .context("failed to load tree-sitter language")?;

    let tree = parser
        .parse(source, None)
        .context("tree-sitter did not return a syntax tree")?;

    let mut imports = Vec::new();
    walk(tree.root_node(), source.as_bytes(), &mut imports);
    imports.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.specifier.cmp(&right.specifier))
    });
    imports.dedup_by(|left, right| {
        left.line == right.line
            && left.specifier == right.specifier
            && left.import_kind as u8 == right.import_kind as u8
    });
    Ok(imports)
}

fn walk(node: Node<'_>, source: &[u8], imports: &mut Vec<ImportFact>) {
    match node.kind() {
        "import_statement" => extract_import_like(node, source, ImportKind::Static, imports),
        "export_statement" => extract_import_like(node, source, ImportKind::Export, imports),
        "call_expression" => extract_call_import(node, source, imports),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, imports);
    }
}

fn extract_import_like(
    node: Node<'_>,
    source: &[u8],
    import_kind: ImportKind,
    imports: &mut Vec<ImportFact>,
) {
    let source_node = node
        .child_by_field_name("source")
        .or_else(|| first_string_child(node));
    if let Some(source_node) = source_node {
        push_string_import(source_node, source, import_kind, imports);
    }
}

fn extract_call_import(node: Node<'_>, source: &[u8], imports: &mut Vec<ImportFact>) {
    let Some(function_node) = node.child_by_field_name("function") else {
        return;
    };
    let Ok(function_text) = function_node.utf8_text(source) else {
        return;
    };
    let import_kind = match function_text {
        "require" => ImportKind::Require,
        "import" => ImportKind::Dynamic,
        _ => return,
    };
    let Some(arguments_node) = node.child_by_field_name("arguments") else {
        return;
    };
    if let Some(source_node) = first_string_child(arguments_node) {
        push_string_import(source_node, source, import_kind, imports);
    }
}

fn push_string_import(
    source_node: Node<'_>,
    source: &[u8],
    import_kind: ImportKind,
    imports: &mut Vec<ImportFact>,
) {
    let Ok(raw_text) = source_node.utf8_text(source) else {
        return;
    };
    if let Some(specifier) = strip_string_literal(raw_text) {
        imports.push(ImportFact {
            specifier,
            line: source_node.start_position().row + 1,
            import_kind,
        });
    }
}

fn first_string_child(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "string" {
        return Some(node);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string" {
            return Some(child);
        }
        if matches!(child.kind(), "_from_clause" | "arguments") {
            if let Some(found) = first_string_child(child) {
                return Some(found);
            }
        }
    }
    None
}

fn strip_string_literal(raw_text: &str) -> Option<String> {
    let trimmed = raw_text.trim();
    let mut chars = trimmed.chars();
    let first = chars.next()?;
    let last = trimmed.chars().last()?;
    if !matches!(first, '\'' | '"') || first != last {
        return None;
    }
    Some(trimmed[1..trimmed.len() - 1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_static_and_commonjs_imports() {
        let source = r#"
            import { a } from "./a";
            export { b } from "./b";
            const c = require("./c");
        "#;

        let imports = extract_imports(source, SourceLanguage::TypeScript).unwrap();

        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].specifier, "./a");
        assert_eq!(imports[1].specifier, "./b");
        assert_eq!(imports[2].specifier, "./c");
    }
}
