// SPDX-License-Identifier: MIT
//! Normalized token stream for clone detection.
//!
//! Reduces source to a sequence of `(token hash, line)` pairs by walking the
//! tree-sitter leaves: identifiers and literals are bucketed to canonical
//! sentinels (so renamed variables and changed constants still match), while
//! keywords, operators, and punctuation keep their identity. Comments are
//! dropped. This is the tree-sitter re-implementation of fallow's
//! duplication tokenizer (`core/src/duplicates/tokenize`/`normalize`); see
//! THIRD-PARTY-NOTICES.md.

use ovecc_core::lang::SourceLanguage;
use tree_sitter::{Node, Parser};

/// Canonical sentinels for normalized buckets (control chars never collide with
/// real keyword/operator text).
const IDENT: &str = "\u{1}id";
const NUM: &str = "\u{2}num";
const STR: &str = "\u{3}str";

/// Tokenizes `source` into parallel `(hashes, 1-based lines)` vectors. Returns
/// empty vectors when the language has no grammar or parsing fails.
pub fn tokenize(source: &str, language: SourceLanguage) -> (Vec<u64>, Vec<u32>) {
    let Some(grammar) = grammar_for(language) else {
        return (Vec::new(), Vec::new());
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return (Vec::new(), Vec::new());
    }
    let Some(tree) = parser.parse(source, None) else {
        return (Vec::new(), Vec::new());
    };
    let mut hashes = Vec::new();
    let mut lines = Vec::new();
    collect(tree.root_node(), source.as_bytes(), &mut hashes, &mut lines);
    (hashes, lines)
}

fn grammar_for(language: SourceLanguage) -> Option<tree_sitter::Language> {
    Some(match language {
        SourceLanguage::JavaScript | SourceLanguage::Jsx => tree_sitter_javascript::LANGUAGE.into(),
        SourceLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        SourceLanguage::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        SourceLanguage::Python => tree_sitter_python::LANGUAGE.into(),
        SourceLanguage::Go => tree_sitter_go::LANGUAGE.into(),
        SourceLanguage::Rust => tree_sitter_rust::LANGUAGE.into(),
        SourceLanguage::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        // SQL has no clone-detection grammar wired here.
        SourceLanguage::Sql => return None,
    })
}

fn collect(node: Node<'_>, source: &[u8], hashes: &mut Vec<u64>, lines: &mut Vec<u32>) {
    let kind = node.kind();
    if is_comment(kind) {
        return;
    }
    // A whole string/template/char literal is one STR token; do not descend
    // into its fragments or interpolations (interpolations rarely matter for
    // structural clones and keeping them out avoids tokenizer noise).
    if is_string_like(kind) {
        hashes.push(fnv1a(STR.as_bytes()));
        lines.push(node.start_position().row as u32 + 1);
        return;
    }
    if node.child_count() == 0 {
        if let Some(token) = normalized_leaf(kind, node, source) {
            hashes.push(fnv1a(token.as_bytes()));
            lines.push(node.start_position().row as u32 + 1);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect(child, source, hashes, lines);
    }
}

/// Maps a leaf node to its normalized token, or `None` to drop it.
fn normalized_leaf(kind: &str, node: Node<'_>, source: &[u8]) -> Option<String> {
    if kind.ends_with("identifier") {
        return Some(IDENT.to_string());
    }
    if kind.contains("number")
        || kind.contains("integer")
        || kind.contains("float")
        || kind == "int_literal"
        || kind == "imaginary_literal"
    {
        return Some(NUM.to_string());
    }
    let text = node.utf8_text(source).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    Some(text.to_string())
}

fn is_string_like(kind: &str) -> bool {
    kind.contains("string")
        || matches!(
            kind,
            "char_literal" | "char" | "rune_literal" | "template_string"
        )
}

fn is_comment(kind: &str) -> bool {
    matches!(
        kind,
        "comment" | "line_comment" | "block_comment" | "comment_block"
    )
}

/// FNV-1a 64-bit hash for stable, deterministic token identity.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_identifiers_and_literals() {
        // Two functions that differ only in names and constants tokenize
        // identically, so a clone detector will match them.
        let (a, _) = tokenize("function f(x){ return x + 1; }", SourceLanguage::TypeScript);
        let (b, _) = tokenize("function g(y){ return y + 2; }", SourceLanguage::TypeScript);
        assert!(!a.is_empty());
        assert_eq!(a, b, "renamed identifiers and changed literals must match");
    }

    #[test]
    fn distinct_structure_differs() {
        let (a, _) = tokenize("const x = 1;", SourceLanguage::TypeScript);
        let (b, _) = tokenize("function f(){}", SourceLanguage::TypeScript);
        assert_ne!(a, b);
    }

    #[test]
    fn lines_track_tokens() {
        let (hashes, lines) = tokenize("const a = 1;\nconst b = 2;\n", SourceLanguage::TypeScript);
        assert_eq!(hashes.len(), lines.len());
        assert!(lines.contains(&1));
        assert!(lines.contains(&2));
    }
}
