//! Core contracts implemented by the specialized crates.

use crate::error::Result;
use crate::facts::{FileFacts, ParseFailure, SourceFile};
use crate::lang::SourceLanguage;
use crate::report::ContextSlice;

/// Language adapter contract, implemented in `ovecc-parser`.
///
/// The adapter owns its syntax tree internally (tree-sitter never crosses the
/// crate boundary). `extract` runs the full extraction pipeline — parse, then
/// extract symbols, imports, calls, APIs, and schema references — and returns
/// the combined raw facts for one file.
///
/// A failure is per-file and must NOT abort the index run: the indexer
/// records the `ParseFailure` and continues.
pub trait LanguageAdapter: Send + Sync {
    fn language(&self) -> SourceLanguage;

    /// Detection confidence in `[0.0, 1.0]` from path and contents.
    fn detect(&self, file: &SourceFile) -> f32;

    fn extract(&self, file: &SourceFile) -> std::result::Result<FileFacts, ParseFailure>;
}

/// Optional LLM integration: consumes a deterministic `ContextSlice`,
/// never scans the repository, and is never required for core operation.
/// `ovecc-ai` ships the offline implementation.
pub trait ExplanationProvider {
    fn name(&self) -> &str;

    fn explain(&self, context: &ContextSlice) -> Result<String>;
}
