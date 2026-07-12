//! Tree-sitter based fact extraction, one adapter per language family:
//! [`typescript::TypeScriptAdapter`] for JS/TS and the specification-driven
//! [`generic::GenericAdapter`] for the other languages, both producing
//! [`FileFacts`] (symbols, imports, calls, APIs, schema refs, security
//! patterns).
//!
//! [`FileFacts`]: ovecc_core::facts::FileFacts

pub mod generic;
pub mod oxc_extractor;
pub mod security;
pub mod tokenize;
pub mod typescript;

pub use generic::GenericAdapter;
pub use typescript::TypeScriptAdapter;

/// Parses a comment's `ovecc-ignore` directive. The marker must LEAD the
/// comment — right after the comment leader (`//`, `///`, `#`, `/*`, …) and
/// whitespace. A comment that merely *mentions* the marker mid-sentence
/// (documentation about the feature, say) is not a directive; treating it as
/// one creates phantom suppressions that the stale-suppression sweep then
/// flags — and that `fix --apply` would strip out of real prose.
/// Returns the line offset the directive suppresses: `0` for the comment's
/// own line (trailing form), `1` for `-next-line`.
pub(crate) fn suppression_offset(comment_text: &str) -> Option<u32> {
    let body = comment_text.trim_start_matches(['/', '*', '!', '#', ' ', '\t']);
    if !body.starts_with("ovecc-ignore") {
        return None;
    }
    Some(if body.starts_with("ovecc-ignore-next-line") {
        1
    } else {
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppression_directives_must_lead_the_comment() {
        // Directive forms: line, doc, Python, block — with or without a reason.
        assert_eq!(suppression_offset("// ovecc-ignore"), Some(0));
        assert_eq!(suppression_offset("//ovecc-ignore"), Some(0));
        assert_eq!(suppression_offset("# ovecc-ignore: test vector"), Some(0));
        assert_eq!(suppression_offset("/* ovecc-ignore */"), Some(0));
        assert_eq!(suppression_offset("// ovecc-ignore-next-line"), Some(1));
        // Mentions mid-sentence are prose, not directives.
        assert_eq!(
            suppression_offset("// Stale ovecc-ignore comments, grouped per file."),
            None
        );
        assert_eq!(
            suppression_offset("// An inline `// ovecc-ignore` suppresses findings."),
            None
        );
        assert_eq!(suppression_offset("// nothing to see"), None);
    }
}
