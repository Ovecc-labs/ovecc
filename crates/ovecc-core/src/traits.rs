//! Core contracts implemented by the specialized crates.
//!
//! | Trait | Implemented in |
//! | --- | --- |
//! | `LanguageAdapter` | `ovecc-parser` |
//! | `GitProvider` | `ovecc-git` (gitoxide) |
//! | `ArchitectureStore` | `ovecc-db` (DuckDB) |
//! | `Rule`, `ConventionLearner` | `ovecc-rules` |
//! | `Renderable` | `ovecc-export` (per report type) |
//! | `ExplanationProvider` | `ovecc-ai` |

use crate::config::RulesConfig;
use crate::error::Result;
use crate::facts::{
    CommitRecord, FactBatch, FileChangeRecord, FileFacts, FindingRecord, MetricRecord,
    ModuleRecord, ParseFailure, RepositoryRecord, SnapshotRecord, SourceFile,
};
use crate::graph::{GraphEdge, GraphLayer, GraphNode, GraphSlice};
use crate::id::{RepositoryId, SnapshotId};
use crate::lang::SourceLanguage;
use crate::report::{ContextSlice, Convention};
use std::collections::BTreeMap;

/// Language adapter contract.
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

/// Native Git access. No shelling out to `git`.
pub trait GitProvider {
    /// SHA of `HEAD`, or `None` outside a Git repository.
    fn head_sha(&self) -> Result<Option<String>>;

    /// Resolves a branch, tag, SHA, or relative ref like `HEAD~1`.
    fn resolve_ref(&self, reference: &str) -> Result<String>;

    /// Commit history, newest first, optionally bounded.
    fn commits(&self, since_sha: Option<&str>, limit: Option<usize>) -> Result<Vec<CommitRecord>>;

    /// Per-file additions/deletions introduced by one commit.
    fn file_changes(&self, commit_sha: &str) -> Result<Vec<FileChangeRecord>>;

    /// `path -> additions + deletions` over a trailing window.
    fn churn(&self, window_days: u32) -> Result<BTreeMap<String, u64>>;

    /// File contents at a given ref, to index architectures across refs.
    fn read_file_at(&self, reference: &str, path: &str) -> Result<Option<Vec<u8>>>;

    /// Paths changed between two refs.
    fn changed_paths(&self, base: &str, head: &str) -> Result<Vec<String>>;
}

/// Persistence contract over the local architecture database.
///
/// History is preserved across indexing runs: facts are replaced per file,
/// never wholesale, and snapshots, metrics, and findings accumulate.
pub trait ArchitectureStore {
    // --- schema lifecycle ---

    /// Current schema version, `None` for a fresh database.
    fn schema_version(&self) -> Result<Option<u32>>;

    /// Applies pending versioned migrations; returns the resulting version.
    fn migrate_to_latest(&mut self) -> Result<u32>;

    // --- repository and incremental state ---

    fn upsert_repository(&mut self, repository: &RepositoryRecord) -> Result<()>;

    /// `path -> content_hash` of the last indexed state, for change detection.
    fn indexed_file_hashes(&self, repository: &RepositoryId) -> Result<BTreeMap<String, String>>;

    /// Replaces every fact derived from the files in the batch (the re-parsed
    /// set) in one transaction.
    fn replace_facts(&mut self, repository: &RepositoryId, batch: &FactBatch) -> Result<()>;

    /// Removes files and every fact derived from them (the deleted set).
    fn remove_files(&mut self, repository: &RepositoryId, paths: &[String]) -> Result<()>;

    // --- git facts ---

    fn upsert_commits(
        &mut self,
        commits: &[CommitRecord],
        changes: &[FileChangeRecord],
    ) -> Result<()>;

    /// SHA of the newest commit already ingested, to ingest only new ones.
    fn last_ingested_commit(&self, repository: &RepositoryId) -> Result<Option<String>>;

    // --- graph persistence ---

    fn replace_graph(
        &mut self,
        repository: &RepositoryId,
        nodes: &[GraphNode],
        edges: &[GraphEdge],
    ) -> Result<()>;

    /// Loads only the requested layer, not the whole graph.
    fn load_graph_layer(&self, repository: &RepositoryId, layer: GraphLayer) -> Result<GraphSlice>;

    // --- snapshots, metrics, findings ---

    fn create_snapshot(
        &mut self,
        snapshot: &SnapshotRecord,
        metrics: &[MetricRecord],
        findings: &[FindingRecord],
    ) -> Result<()>;

    /// Resolves `latest`, `previous`, a snapshot ID (or prefix), or a commit
    /// SHA to a stored snapshot.
    fn resolve_snapshot(
        &self,
        repository: &RepositoryId,
        reference: &str,
    ) -> Result<Option<SnapshotRecord>>;

    fn snapshot_metrics(&self, snapshot_id: &SnapshotId) -> Result<Vec<MetricRecord>>;

    fn findings(
        &self,
        repository: &RepositoryId,
        snapshot_id: Option<&SnapshotId>,
    ) -> Result<Vec<FindingRecord>>;
}

/// One architectural rule: explicit config rule, learned convention rule,
/// built-in generic rule, or framework-specific rule.
pub trait Rule: Send + Sync {
    /// Stable rule name, included in every finding it produces.
    fn name(&self) -> &str;

    fn evaluate(&self, ctx: &RuleContext<'_>) -> Result<Vec<FindingRecord>>;
}

/// Read-only context handed to rules and convention learners.
pub struct RuleContext<'a> {
    pub repository_id: &'a RepositoryId,
    pub graph: &'a GraphSlice,
    pub modules: &'a [ModuleRecord],
    pub config: &'a RulesConfig,
    /// Conventions already learned, so rules can check deviations.
    pub conventions: &'a [Convention],
}

/// Learns dominant repository conventions with confidence scores.
/// Conventions below `Confidence::REPORT_THRESHOLD` are discarded.
pub trait ConventionLearner {
    fn learn(&self, ctx: &RuleContext<'_>) -> Result<Vec<Convention>>;
}

/// Optional LLM integration: consumes a deterministic `ContextSlice`,
/// never scans the repository, and is never required for core operation.
pub trait ExplanationProvider {
    fn name(&self) -> &str;

    fn explain(&self, context: &ContextSlice) -> Result<String>;
}

/// Text and Markdown rendering for reports. JSON and NDJSON come from
/// `serde::Serialize` through the `VersionedReport` envelope.
pub trait Renderable {
    fn render_text(&self) -> String;

    fn render_markdown(&self) -> String;
}
