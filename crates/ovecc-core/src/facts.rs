//! Architecture facts.
//!
//! Two families of types live here:
//!
//! - Raw `*Fact` types: what a language adapter extracts from a single file,
//!   before any cross-file resolution (no stable IDs, no module attribution).
//! - Normalized `*Record` types: the resolved, persisted form, mirroring the
//!   database tables one to one.
//!
//! The indexer (`ovecc-indexer`) is the only component that converts facts
//! into records.

use crate::graph::NodeKind;
use crate::id::{
    ApiId, CallId, CapabilityUseId, CommitId, ComplexityId, DependencyId, ExportId, FileChangeId,
    FileId, FindingId, MetricId, MigrationId, ModuleId, OwnershipId, RepositoryId, SchemaObjectId,
    SnapshotId, SymbolId,
};
use crate::lang::SourceLanguage;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---- Shared value types ----

/// Severity grading shared by rules, findings, and risk mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence score in `[0.0, 1.0]` attached to inferred facts.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(pub f64);

impl Confidence {
    /// Below this threshold a convention is never reported.
    pub const REPORT_THRESHOLD: f64 = 0.70;
    /// Above this threshold a deviation is a violation, not a warning.
    pub const VIOLATION_THRESHOLD: f64 = 0.85;
}

/// Traceable evidence: every finding must point back to explicit facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Repository-relative, '/'-normalized path.
    pub file_path: String,
    pub line: Option<u32>,
    pub symbol: Option<String>,
    pub detail: Option<String>,
}

/// Inclusive line span of a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_line: u32,
    pub end_line: u32,
}

/// Typed reference to any graph entity. Used wherever an edge can point at
/// heterogeneous targets (dependencies, ownership, findings, metrics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    pub kind: NodeKind,
    pub id: String,
}

// ---- Normalized records (persisted; mirror database tables) ----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryRecord {
    pub id: RepositoryId,
    pub root_path: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: FileId,
    pub repository_id: RepositoryId,
    /// Repository-relative, '/'-normalized path.
    pub path: String,
    /// `None` for non-source files that are still indexed (configs, SQL, ...).
    pub language: Option<SourceLanguage>,
    pub content_hash: String,
    pub size_bytes: u64,
    pub module_id: Option<ModuleId>,
    pub last_indexed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub id: ModuleId,
    pub repository_id: RepositoryId,
    pub name: String,
    pub path_prefix: Option<String>,
    pub kind: ModuleKind,
    pub detected_layer: Option<String>,
    pub detected_domain: Option<String>,
    /// Module inference must be explainable: why this module exists and why
    /// files belong to it.
    pub inference_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    /// Inferred from directory boundaries (`src/billing/**`).
    PathInferred,
    /// Declared package (package.json, pyproject, go.mod).
    Package,
    /// Workspace member (Cargo workspace, pnpm/yarn workspace).
    WorkspaceMember,
    /// Language namespace.
    Namespace,
    /// Explicitly configured in `.ovecc/config.toml`.
    Configured,
    /// External package (npm, crates.io, ...) — not part of this repository.
    External,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub id: SymbolId,
    pub repository_id: RepositoryId,
    pub file_id: FileId,
    pub module_id: Option<ModuleId>,
    pub language: SourceLanguage,
    pub kind: SymbolKind,
    pub name: String,
    pub qualified_name: String,
    pub span: Option<Span>,
    pub visibility: Option<Visibility>,
    pub type_signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Struct,
    Enum,
    Interface,
    Trait,
    TypeAlias,
    Constant,
    Variable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Protected,
    Private,
    Crate,
    Internal,
}

/// A resolved dependency between two entities, at any level: file-to-file,
/// module-to-module, symbol-to-symbol, package-to-package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyRecord {
    pub id: DependencyId,
    pub repository_id: RepositoryId,
    pub source: EntityRef,
    pub target: EntityRef,
    pub kind: DependencyKind,
    pub is_external: bool,
    pub evidence: Option<Evidence>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    SourceImport,
    TypeImport,
    RuntimeImport,
    Framework,
    Database,
    Api,
    Event,
    Test,
}

/// An execution relationship. Unresolved calls keep the callee name and
/// evidence instead of being discarded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRecord {
    pub id: CallId,
    pub repository_id: RepositoryId,
    pub caller_symbol_id: SymbolId,
    /// `None` when the callee could not be resolved with confidence.
    pub callee_symbol_id: Option<SymbolId>,
    pub callee_name: Option<String>,
    pub kind: CallKind,
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Direct,
    Method,
    Constructor,
    Handler,
    Route,
    Rpc,
    Event,
    /// A callable named in value position (an argument, a registry entry, a
    /// decorator) rather than invoked. Not a call, but changing the callee's
    /// signature still breaks the reference site.
    Reference,
}

/// An exposed route, endpoint, RPC method, event, or CLI command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiRecord {
    pub id: ApiId,
    pub repository_id: RepositoryId,
    pub module_id: Option<ModuleId>,
    pub kind: ApiKind,
    pub method: Option<String>,
    pub path: Option<String>,
    pub name: Option<String>,
    pub handler_symbol_id: Option<SymbolId>,
    pub request_type: Option<String>,
    pub response_type: Option<String>,
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKind {
    HttpRoute,
    GraphqlOperation,
    RpcMethod,
    MessageHandler,
    EventProducer,
    EventConsumer,
    CliCommand,
}

/// A database object: table, view, column, index, foreign key, enum.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaObjectRecord {
    pub id: SchemaObjectId,
    pub repository_id: RepositoryId,
    pub kind: SchemaObjectKind,
    pub name: String,
    /// Column -> table, index -> table, etc.
    pub parent_id: Option<SchemaObjectId>,
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaObjectKind {
    Table,
    View,
    Column,
    Index,
    ForeignKey,
    Enum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub id: MigrationId,
    pub repository_id: RepositoryId,
    pub path: String,
    pub migration_name: Option<String>,
    pub sequence_number: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub content_hash: String,
}

/// Owner attached to a file or module, distinguishing explicit from inferred
/// ownership.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnershipRecord {
    pub id: OwnershipId,
    pub repository_id: RepositoryId,
    pub owner: String,
    pub target: EntityRef,
    pub source: OwnershipSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipSource {
    Codeowners,
    RepositoryConfig,
    GitHistory,
    PathConvention,
    ServiceMetadata,
}

impl OwnershipSource {
    /// Explicit (CODEOWNERS, repository config, declared service metadata) vs
    /// inferred (git history, path conventions).
    pub fn is_explicit(self) -> bool {
        matches!(
            self,
            Self::Codeowners | Self::RepositoryConfig | Self::ServiceMetadata
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub id: CommitId,
    pub repository_id: RepositoryId,
    pub sha: String,
    pub parent_shas: Vec<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub committed_at: DateTime<Utc>,
    pub message: Option<String>,
    pub is_fix: bool,
    /// Score behind `is_fix`, in `[0.0, 1.0]`. Ordinal, not a probability.
    pub fix_confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileChangeRecord {
    pub id: FileChangeId,
    pub repository_id: RepositoryId,
    pub commit_id: CommitId,
    pub file_path: String,
    pub kind: ChangeKind,
    /// The path this file was renamed or copied from, when it was.
    pub previous_path: Option<String>,
    pub additions: Option<u32>,
    pub deletions: Option<u32>,
}

/// The files one commit touched, under their current names. Lives here rather
/// than in `ovecc-graph` so that `ovecc-db` can produce it without depending on
/// the analysis crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitFiles {
    pub sha: String,
    pub files: Vec<String>,
}

/// Two files that keep changing in the same commit, with every measure behind
/// the verdict so a reader can disagree with the thresholds rather than with a
/// bare pair. Computed in `ovecc-graph`, persisted by `ovecc-db`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoChangedPair {
    pub left: String,
    pub right: String,
    /// Commits that touched both.
    pub support: usize,
    /// `support / (commits touching either)`, the symmetric strength.
    pub jaccard: f64,
    /// How much more often the two meet than chance would give them. At or
    /// below 1 they are simply both busy.
    pub lift: f64,
    /// The chance the right one changes when the left does, and the reverse.
    /// Asymmetric on purpose: a test always following its subject is not the
    /// same relation as a subject always dragging its test along.
    pub confidence_left_to_right: f64,
    pub confidence_right_to_left: f64,
    /// A few commits where both changed, newest first, as evidence.
    pub commits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
}

/// Point-in-time architecture state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: SnapshotId,
    pub repository_id: RepositoryId,
    pub commit_sha: Option<String>,
    pub created_at: DateTime<Utc>,
    pub summary_hash: String,
}

/// A computed architecture measurement attached to a snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricRecord {
    pub id: MetricId,
    pub repository_id: RepositoryId,
    pub snapshot_id: SnapshotId,
    pub name: String,
    pub scope: MetricScope,
    pub target: Option<EntityRef>,
    pub value: f64,
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricScope {
    Repository,
    Module,
    File,
    Symbol,
    Api,
    Schema,
}

/// A violation, drift warning, hotspot, or risk report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: FindingId,
    pub repository_id: RepositoryId,
    /// Volatile snapshot identity: kept out of the serialized payload so two
    /// indexes of the same content produce byte-identical output. It is still
    /// persisted (via explicit column writes) and available in `meta`.
    #[serde(skip_serializing)]
    pub snapshot_id: Option<SnapshotId>,
    pub kind: FindingKind,
    pub severity: Severity,
    /// Name of the rule that produced the finding, when rule-based.
    pub rule_name: Option<String>,
    pub target: Option<EntityRef>,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    /// Wall-clock index time. Skipped on serialize for the same determinism
    /// reason; the snapshot's time lives in `meta`.
    #[serde(skip_serializing)]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    CrossDomainDependency,
    LayerViolation,
    ForbiddenImport,
    DirectDatabaseAccess,
    CircularDependency,
    OwnershipBoundaryViolation,
    ConventionDeviation,
    Hotspot,
    DriftWarning,
    // Security findings.
    HardcodedSecret,
    InsecurePattern,
    WeakCrypto,
    PermissiveCors,
    VulnerableDependency,
    TaintedFlow,
    // Dead code & complexity.
    UnusedExport,
    UnusedFile,
    UnusedDependency,
    /// An imported package missing from every `package.json` (a phantom
    /// dependency that only works via hoisting or a transitive install).
    UnlistedDependency,
    HighComplexity,
    /// A function long enough (source lines) to be a maintainability risk.
    LongFunction,
    /// A function with too many parameters.
    LongParameterList,
    /// A function that uses another module's data more than its own.
    FeatureEnvy,
    /// A type that concentrates too much state and behavior.
    LargeClass,
    /// The same group of parameters recurring across signatures.
    DataClumps,
    /// An `ovecc-ignore` comment that suppresses no finding — it will silently
    /// swallow the next real finding on its line.
    StaleSuppression,
    /// The observed dependencies deviate from the intended architecture
    /// declared in `.ovecc/architecture.toml` (undeclared edge, bypassed
    /// interface, banned external import, deprecated edge still in use).
    ArchitectureViolation,
}

/// A fix descriptor attached to a finding so an agent can act without
/// re-deriving the remedy. `auto_fixable` only when a mechanical edit fully
/// resolves it; otherwise `instruction` is guidance for a human decision.
/// Derived from the finding kind, never invented at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixSpec {
    pub kind: String,
    pub auto_fixable: bool,
    pub instruction: String,
}

impl FixSpec {
    fn new(kind: &str, auto_fixable: bool, instruction: &str) -> Self {
        Self {
            kind: kind.to_string(),
            auto_fixable,
            instruction: instruction.to_string(),
        }
    }
}

impl FindingKind {
    /// Only the mechanical dead-code removals are `auto_fixable`.
    pub fn fix_spec(&self) -> FixSpec {
        match self {
            FindingKind::UnusedFile => FixSpec::new(
                "remove_unused_file",
                true,
                "Delete this unreachable file (no entry point reaches it).",
            ),
            FindingKind::UnusedExport => FixSpec::new(
                "remove_unused_export",
                true,
                "Drop the `export` keyword (or delete the symbol if it is unused internally too).",
            ),
            FindingKind::UnusedDependency => FixSpec::new(
                "remove_unused_dependency",
                true,
                "Remove this dependency from the manifest; no indexed file imports it.",
            ),
            FindingKind::UnlistedDependency => FixSpec::new(
                "declare_dependency",
                true,
                "Declare the package in the nearest manifest's dependencies, pinning the \
                 version the lockfile already resolves (it currently works only via \
                 hoisting or a transitive install).",
            ),
            FindingKind::HighComplexity => FixSpec::new(
                "reduce_complexity",
                false,
                "Extract functions and reduce nesting to lower cognitive complexity.",
            ),
            FindingKind::LongFunction => FixSpec::new(
                "split_long_function",
                false,
                "Extract cohesive sections into named helper functions.",
            ),
            FindingKind::LongParameterList => FixSpec::new(
                "reduce_parameters",
                false,
                "Group related parameters into a typed options object.",
            ),
            FindingKind::FeatureEnvy => FixSpec::new(
                "move_function",
                false,
                "Move the function into the module it predominantly calls, or extract \
                 the envious section and move that.",
            ),
            FindingKind::LargeClass => FixSpec::new(
                "split_class",
                false,
                "Split the class along its responsibilities; extract cohesive method \
                 groups into collaborating classes.",
            ),
            FindingKind::DataClumps => FixSpec::new(
                "introduce_parameter_object",
                false,
                "Introduce a parameter object for the recurring group and pass it \
                 instead of the individual values.",
            ),
            FindingKind::StaleSuppression => FixSpec::new(
                "remove_stale_suppression",
                true,
                "Delete the ovecc-ignore comment: it suppresses nothing and will \
                 silently swallow the next real finding on this line.",
            ),
            FindingKind::ArchitectureViolation => FixSpec::new(
                "restore_architecture_contract",
                false,
                "Route the dependency through the target component's interface or \
                 remove it; if the edge is intended, declare it in \
                 .ovecc/architecture.toml and let the review record the decision.",
            ),
            FindingKind::HardcodedSecret => FixSpec::new(
                "rotate_and_externalize_secret",
                false,
                "Remove the secret from source, rotate it, and load it from env / a secret manager.",
            ),
            FindingKind::WeakCrypto => FixSpec::new(
                "replace_weak_crypto",
                false,
                "Replace MD5/SHA-1 with SHA-256+ or a vetted KDF.",
            ),
            FindingKind::InsecurePattern => FixSpec::new(
                "remove_dynamic_eval",
                false,
                "Replace eval / dynamic execution with a safe, explicit alternative.",
            ),
            FindingKind::PermissiveCors => FixSpec::new(
                "restrict_cors",
                false,
                "Restrict the CORS origin to an explicit allow-list.",
            ),
            FindingKind::VulnerableDependency => FixSpec::new(
                "upgrade_dependency",
                false,
                "Upgrade to a fixed version, then re-run the test suite.",
            ),
            FindingKind::TaintedFlow => FixSpec::new(
                "sanitize_tainted_flow",
                false,
                "Validate or parameterize the input before it reaches the sink.",
            ),
            FindingKind::CircularDependency => FixSpec::new(
                "break_cycle",
                false,
                "Invert one dependency or extract the shared module both sides depend on.",
            ),
            FindingKind::LayerViolation
            | FindingKind::ForbiddenImport
            | FindingKind::CrossDomainDependency
            | FindingKind::DirectDatabaseAccess
            | FindingKind::OwnershipBoundaryViolation => FixSpec::new(
                "fix_boundary_violation",
                false,
                "Route through the allowed boundary or move the code to the correct layer/domain.",
            ),
            FindingKind::ConventionDeviation => FixSpec::new(
                "align_with_convention",
                false,
                "Bring the file in line with the dominant convention for its role.",
            ),
            FindingKind::Hotspot | FindingKind::DriftWarning => FixSpec::new(
                "review",
                false,
                "Informational: review and prioritise; no single mechanical fix.",
            ),
        }
    }
}

// ---- Raw extraction facts (language adapter output, pre-resolution) ----

/// In-memory source file handed to language adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    /// Repository-relative, '/'-normalized path.
    pub path: String,
    pub absolute_path: PathBuf,
    pub language: SourceLanguage,
    pub contents: String,
}

/// Everything one adapter extracted from one file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileFacts {
    pub symbols: Vec<SymbolFact>,
    pub imports: Vec<ImportFact>,
    pub calls: Vec<CallFact>,
    pub apis: Vec<ApiFact>,
    pub schema_refs: Vec<SchemaRefFact>,
    /// Deterministic security patterns detected during the AST pass.
    #[serde(default)]
    pub security_patterns: Vec<SecurityPatternFact>,
    /// 1-based lines suppressed by an inline `// ovecc-ignore` comment — a
    /// finding whose evidence lands on one is dropped.
    #[serde(default)]
    pub suppressed_lines: Vec<u32>,
    /// `(variable, type)` bindings from `const v = new T()` or `const v: T`,
    /// for receiver-typed dispatch resolution.
    #[serde(default)]
    pub local_types: Vec<(String, String)>,
    /// Per-function complexity (cyclomatic + cognitive). Populated by the oxc
    /// TS/JS extractor; empty for adapters that don't compute it.
    #[serde(default)]
    pub complexity: Vec<ComplexityFact>,
    /// Names this file exports (including re-exports). Populated by the oxc
    /// TS/JS extractor; feeds dead-code analysis.
    #[serde(default)]
    pub exports: Vec<ExportFact>,
    /// Ambient capability uses (network, storage, clock, ...), one entry per
    /// distinct API with its first line and occurrence count. Populated by
    /// the TS/JS extractor; judged by the architecture contract's
    /// `deny_capabilities`.
    #[serde(default)]
    pub capability_uses: Vec<CapabilityFact>,
    /// The parse tree contained `ERROR`/`MISSING` nodes: the file has syntax
    /// the grammar could not fully parse. Tree-sitter recovers and still
    /// yields facts, so this is the only signal that the extraction is partial.
    #[serde(default)]
    pub parse_errors: bool,
}

/// A security-relevant pattern found in source, classified into a finding by
/// `ovecc-rules`. Detection is deterministic and AST/literal-based.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPatternFact {
    pub kind: SecurityPatternKind,
    pub line: u32,
    /// Human-readable specifics, e.g. the provider name or weak algorithm.
    pub detail: Option<String>,
    /// Qualified name of the enclosing symbol, when known — lets the taint
    /// engine treat dangerous calls (`eval`, `exec`) as sinks.
    #[serde(default)]
    pub caller_qualified_name: Option<String>,
    /// True for Rust's inline `#[cfg(test)]` scaffolding, which the path-based
    /// heuristics cannot see. Down-ranks to Low like a test file.
    #[serde(default)]
    pub in_test_code: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPatternKind {
    /// A hardcoded credential (provider-pattern or high-entropy).
    HardcodedSecret,
    /// Dynamic code execution: `eval` / `new Function`.
    DynamicEval,
    /// OS command execution: `child_process.exec` / `execSync` / `spawn`.
    CommandExec,
    /// Obsolete hashing algorithm (MD5, SHA-1).
    WeakHash,
    /// Permissive CORS configuration (`origin: "*"`).
    PermissiveCors,
}

impl SecurityPatternKind {
    /// True for the kinds that are call sinks for taint analysis: untrusted
    /// input reaching them is code or command injection.
    pub fn is_taint_sink(self) -> bool {
        matches!(self, Self::DynamicEval | Self::CommandExec)
    }
}

/// A use of an ambient JS/TS capability: an API that performs I/O or draws on
/// a source of non-determinism. Detected unconditionally and deduplicated per
/// file and API, so the facts stay independent of the contract that judges
/// them (`deny_capabilities`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFact {
    pub capability: CapabilityKind,
    /// The concrete API as written, e.g. `fetch`, `Date.now`, `new WebSocket`.
    pub api: String,
    /// 1-based line of the first occurrence in the file.
    pub line: u32,
    /// Occurrences of this API in the file.
    pub count: u32,
}

/// The ambient capabilities the contract can deny per component. The API basket
/// per capability is closed, so a verdict always traces to a named API, never a
/// heuristic. Packages outside the basket are a job for `external_deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// `fetch`, `WebSocket`, `XMLHttpRequest`, `EventSource`,
    /// `navigator.sendBeacon`; node `http`/`https`/`http2`/`net`/`tls`/
    /// `dgram`/`dns`; `axios`, `node-fetch`, `undici`, `got`, `ky`.
    Network,
    /// node `fs`, `fs/promises`, `fs-extra`.
    Filesystem,
    /// `localStorage`, `sessionStorage`, `indexedDB`.
    Storage,
    /// `document.*` — any DOM access.
    Dom,
    /// `process.*` (env, exit, cwd); node `child_process`.
    Process,
    /// The ambient clock: `Date.now`, zero-argument `new Date`,
    /// `performance.now`.
    Time,
    /// `Math.random`, `crypto.getRandomValues` / `randomUUID` /
    /// `randomBytes` / `randomInt`.
    Random,
}

impl CapabilityKind {
    pub const ALL: &'static [CapabilityKind] = &[
        CapabilityKind::Network,
        CapabilityKind::Filesystem,
        CapabilityKind::Storage,
        CapabilityKind::Dom,
        CapabilityKind::Process,
        CapabilityKind::Time,
        CapabilityKind::Random,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityKind::Network => "network",
            CapabilityKind::Filesystem => "filesystem",
            CapabilityKind::Storage => "storage",
            CapabilityKind::Dom => "dom",
            CapabilityKind::Process => "process",
            CapabilityKind::Time => "time",
            CapabilityKind::Random => "random",
        }
    }

    /// Inverse of [`as_str`](Self::as_str), for rows read back from storage.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == name)
    }

    /// A bare-identifier call: `fetch(...)`.
    pub fn of_global_call(name: &str) -> Option<Self> {
        match name {
            "fetch" => Some(CapabilityKind::Network),
            _ => None,
        }
    }

    /// A method call `receiver.property(...)`. Ambient receivers (`process`,
    /// `document`, the storage globals) grant their capability whatever the
    /// method; the rest need the exact pair.
    pub fn of_method_call(receiver: &str, property: &str) -> Option<Self> {
        if let Some(kind) = Self::of_member_root(receiver) {
            return Some(kind);
        }
        match (receiver, property) {
            ("Date", "now") | ("performance", "now") => Some(CapabilityKind::Time),
            ("Math", "random") => Some(CapabilityKind::Random),
            ("crypto", "getRandomValues" | "randomUUID" | "randomBytes" | "randomInt") => {
                Some(CapabilityKind::Random)
            }
            ("navigator", "sendBeacon") => Some(CapabilityKind::Network),
            _ => None,
        }
    }

    /// A `new Name(...)` expression. `Date` counts only with zero arguments:
    /// an argless `new Date()` reads the clock, `new Date(value)` converts.
    pub fn of_constructor(name: &str, argless: bool) -> Option<Self> {
        match name {
            "WebSocket" | "XMLHttpRequest" | "EventSource" => Some(CapabilityKind::Network),
            "Date" if argless => Some(CapabilityKind::Time),
            _ => None,
        }
    }

    /// An ambient object where every member access carries the capability:
    /// `process.env`, `document.cookie`, `localStorage.length`.
    pub fn of_member_root(object: &str) -> Option<Self> {
        match object {
            "process" => Some(CapabilityKind::Process),
            "localStorage" | "sessionStorage" | "indexedDB" => Some(CapabilityKind::Storage),
            "document" => Some(CapabilityKind::Dom),
            _ => None,
        }
    }

    /// An import specifier: node builtins (with or without the `node:`
    /// prefix) plus the mainstream HTTP clients.
    pub fn of_module_specifier(specifier: &str) -> Option<Self> {
        let bare = specifier.strip_prefix("node:").unwrap_or(specifier);
        match bare {
            "fs" | "fs/promises" | "fs-extra" => Some(CapabilityKind::Filesystem),
            "http" | "https" | "http2" | "net" | "tls" | "dgram" | "dns" => {
                Some(CapabilityKind::Network)
            }
            "axios" | "node-fetch" | "undici" | "got" | "ky" => Some(CapabilityKind::Network),
            "child_process" | "process" => Some(CapabilityKind::Process),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolFact {
    pub name: String,
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub span: Span,
    pub visibility: Option<Visibility>,
    pub type_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFact {
    pub specifier: String,
    pub line: u32,
    pub kind: ImportFactKind,
    /// Imported names when available (enables symbol-level dependencies).
    pub imported_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFactKind {
    Static,
    ReExport,
    Require,
    Dynamic,
    TypeOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFact {
    /// Qualified name of the enclosing symbol, when known.
    pub caller_qualified_name: Option<String>,
    pub callee_name: String,
    pub kind: CallKind,
    pub line: u32,
    /// For a method call `obj.m()`, the receiver expression text (`this`, a
    /// variable name, ...) — drives receiver-typed dispatch resolution.
    #[serde(default)]
    pub receiver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFact {
    pub kind: ApiKind,
    pub method: Option<String>,
    pub path: Option<String>,
    pub name: Option<String>,
    pub handler_name: Option<String>,
    pub request_type: Option<String>,
    pub response_type: Option<String>,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaRefFact {
    pub object_name: String,
    pub object_kind: SchemaObjectKind,
    pub access: SchemaAccess,
    pub line: u32,
    /// Qualified name of the enclosing symbol, when known — the accessor that
    /// `reads`/`writes` the object. Becomes a candidate SQL sink.
    #[serde(default)]
    pub caller_qualified_name: Option<String>,
}

/// How code touches a schema object — becomes `reads`/`writes` edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaAccess {
    Read,
    Write,
    Define,
}

/// Per-function complexity metrics. Ported from fallow's `FunctionComplexity`
/// (crates/types/src/extract.rs), reduced to the
/// language-agnostic core (React-specific fields dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplexityFact {
    pub qualified_name: String,
    /// 1-based start line.
    pub line: u32,
    /// McCabe cyclomatic complexity (1 + decision points).
    pub cyclomatic: u16,
    /// SonarSource cognitive complexity (structural increments + nesting penalty).
    pub cognitive: u16,
    pub line_count: u32,
    /// Parameter count (excludes a TypeScript `this` parameter).
    pub param_count: u8,
    #[serde(default)]
    pub param_names: Vec<String>,
}

/// A name a file exports. `re_export` is `Some` for `export … from './src'`.
/// Mirrors fallow's `ExportInfo` + `ReExportInfo`; feeds dead-code analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFact {
    /// Exported name; `"default"` for the default export, `"*"` for `export *`.
    pub name: String,
    /// Local binding name when it differs (`export { a as b }` → `name="b"`,
    /// `local_name=Some("a")`).
    pub local_name: Option<String>,
    pub is_type_only: bool,
    /// 1-based line of the export declaration.
    pub line: u32,
    /// Re-export provenance; `None` for a local `export const x` / `export fn`.
    pub re_export: Option<ReExportFact>,
}

/// Re-export provenance for an [`ExportFact`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReExportFact {
    /// Raw specifier re-exported from (e.g. `"./x"`), resolved later.
    pub source_specifier: String,
    /// Name imported from the source; `"*"` for `export * from`.
    pub imported_name: String,
}

/// Persisted per-function complexity, keyed by file and qualified name, so the
/// `complexity` table can be queried like any other architecture fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplexityRecord {
    pub id: ComplexityId,
    pub repository_id: RepositoryId,
    pub file_id: FileId,
    pub qualified_name: String,
    pub line: u32,
    pub cyclomatic: u16,
    pub cognitive: u16,
    pub line_count: u32,
    pub param_count: u8,
}

/// Persisted ambient-capability use, one row per file and API, so the contract
/// check reads the current state without re-parsing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRecord {
    pub id: CapabilityUseId,
    pub repository_id: RepositoryId,
    pub file_id: FileId,
    pub capability: CapabilityKind,
    pub api: String,
    pub line: u32,
    pub count: u32,
}

/// One function's metrics as the contract's budget check consumes them: a
/// slim per-file view over [`ComplexityFact`] / the `complexity` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMetricsRow {
    pub file_path: String,
    pub qualified_name: String,
    pub line: u32,
    pub cyclomatic: u32,
    pub cognitive: u32,
}

/// Persisted export, with re-export provenance flattened, so the `exports`
/// table backs dead-code queries and public-surface inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportRecord {
    pub id: ExportId,
    pub repository_id: RepositoryId,
    pub file_id: FileId,
    pub name: String,
    pub line: u32,
    pub is_type_only: bool,
    /// Specifier a re-export forwards from (`export { x } from './y'`), else `None`.
    pub re_export_source: Option<String>,
    /// Name imported from that source (`"*"` for `export *`), else `None`.
    pub re_export_name: Option<String>,
}

/// Per-file parser failure. Must not abort the index run: it is recorded and
/// surfaced in the summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseFailure {
    pub path: String,
    pub message: String,
}

/// Batch of resolved records handed from the indexer to the store in one
/// write transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FactBatch {
    pub files: Vec<FileRecord>,
    pub modules: Vec<ModuleRecord>,
    pub symbols: Vec<SymbolRecord>,
    pub dependencies: Vec<DependencyRecord>,
    pub calls: Vec<CallRecord>,
    pub apis: Vec<ApiRecord>,
    pub schema_objects: Vec<SchemaObjectRecord>,
    pub migrations: Vec<MigrationRecord>,
    pub ownership: Vec<OwnershipRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_low_to_critical_and_serializes_lowercase() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn confidence_thresholds_are_ordered_constants() {
        const { assert!(Confidence::REPORT_THRESHOLD < Confidence::VIOLATION_THRESHOLD) };
        assert_eq!(Confidence::REPORT_THRESHOLD, 0.70);
        assert_eq!(Confidence::VIOLATION_THRESHOLD, 0.85);
    }

    #[test]
    fn ownership_source_explicit_vs_inferred() {
        assert!(OwnershipSource::Codeowners.is_explicit());
        assert!(OwnershipSource::RepositoryConfig.is_explicit());
        assert!(OwnershipSource::ServiceMetadata.is_explicit());
        assert!(!OwnershipSource::GitHistory.is_explicit());
        assert!(!OwnershipSource::PathConvention.is_explicit());
    }

    #[test]
    fn only_eval_and_command_exec_are_taint_sinks() {
        use SecurityPatternKind::*;
        assert!(DynamicEval.is_taint_sink());
        assert!(CommandExec.is_taint_sink());
        for k in [HardcodedSecret, WeakHash, PermissiveCors] {
            assert!(!k.is_taint_sink());
        }
    }
}
