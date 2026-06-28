//! Command result models.
//!
//! Every report serializes to JSON via `Serialize` and renders to
//! text/markdown through `traits::Renderable` (implemented in `ovecc-export`).

use crate::facts::{
    ApiRecord, Confidence, Evidence, FindingRecord, OwnershipRecord, ParseFailure,
    SchemaObjectRecord,
};
use crate::id::SnapshotId;
use crate::query::TargetSelector;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// SPDX-License-Identifier: MIT
// The envelope/Meta shapes below are adapted from fallow (github.com/fallow-rs/
// fallow), MIT (c) 2026 Bart Waardenburg — see THIRD-PARTY-NOTICES.md — switched
// to an integer schema_version and Ovecc's command vocabulary.

/// Integer version of the machine-readable output contract. Bump policy:
/// ADDITIVE changes (new optional fields, new array entries, new commands) do
/// NOT bump — consumers receive new keys without breaking, so detect new fields
/// by JSON-key presence, not by gating on this number. BREAKING changes (renamed
/// or removed fields, type or semantic changes) DO bump.
pub const SCHEMA_VERSION: u32 = 1;

/// The tool that produced an envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: "ovecc".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Stable, self-describing envelope wrapping every command's JSON output. The
/// `data` payload is byte-identical across runs for identical inputs; all
/// time/nondeterminism is confined to `meta.timing`, which is only present under
/// `--stats`.
#[derive(Serialize)]
pub struct Envelope<'a, T: Serialize + ?Sized> {
    pub schema_version: u32,
    pub tool: ToolInfo,
    pub command: &'a str,
    #[serde(skip_serializing_if = "Meta::is_empty")]
    pub meta: Meta,
    pub data: &'a T,
}

impl<'a, T: Serialize + ?Sized> Envelope<'a, T> {
    pub fn new(command: &'a str, data: &'a T, meta: Meta) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo::default(),
            command,
            meta,
            data,
        }
    }
}

/// Self-interpreting metadata so an agent or CI system can read a command's
/// output without consulting the docs site: field/metric/rule definitions plus
/// optional diagnostic timing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Documentation pointer for the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    /// Per-field definitions for the payload's fields.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub field_definitions: BTreeMap<String, String>,
    /// Per-metric definitions: what it measures, its range, how to read it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, MetaMetric>,
    /// Per-rule definitions for the finding kinds a command can surface.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, MetaRule>,
    /// Diagnostic wall-clock; present only under `--stats`, so default output
    /// stays byte-identical across runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,
}

impl Meta {
    pub fn is_empty(&self) -> bool {
        self.docs.is_none()
            && self.field_definitions.is_empty()
            && self.metrics.is_empty()
            && self.rules.is_empty()
            && self.timing.is_none()
    }
}

/// Single-metric definition inside [`Meta::metrics`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetaMetric {
    pub description: String,
    /// Valid value range, e.g. `"[0, 100]"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    /// How to read the value, e.g. `"lower is better"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<String>,
}

/// Single-rule definition inside [`Meta::rules`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetaRule {
    pub description: String,
    /// Default severity the rule emits at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// Diagnostic timing, emitted in `meta` only under `--stats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timing {
    /// RFC3339 generation time. Lives here (never in `data`) to preserve the
    /// byte-for-byte determinism of payloads.
    pub generated_at: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Numeric risk score with its severity mapping: 0-24 Low, 25-49 Medium,
/// 50-74 High, 75+ Critical.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    pub value: u32,
    pub level: RiskLevel,
}

impl RiskScore {
    /// Maps a raw score to its severity band: 0-24 Low, 25-49 Medium,
    /// 50-74 High, 75+ Critical. `value` is preserved as-is (callers cap it
    /// for display where appropriate); the band uses the uncapped score.
    pub fn from_value(value: u32) -> Self {
        let level = match value {
            0..=24 => RiskLevel::Low,
            25..=49 => RiskLevel::Medium,
            50..=74 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
        Self { value, level }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImpactDirection {
    Downstream,
    Upstream,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChurnLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriftTrend {
    Improving,
    Stable,
    Worsening,
    Unknown,
}

/// Lightweight snapshot reference embedded in reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub id: SnapshotId,
    pub commit_sha: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ovecc index
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexReport {
    pub repository_root: String,
    pub snapshot_id: SnapshotId,
    pub files_scanned: usize,
    pub files_parsed: usize,
    /// Files skipped because their content hash was unchanged.
    pub files_skipped_unchanged: usize,
    pub files_removed: usize,
    pub modules: usize,
    pub symbols: usize,
    pub dependencies: usize,
    pub calls: usize,
    pub apis: usize,
    pub tables: usize,
    pub commits_ingested: usize,
    /// Per-file parser failures surfaced instead of aborting.
    pub parse_failures: Vec<ParseFailure>,
    /// Present when `--stats` is set. See [`IndexTimings`].
    pub timings: Option<IndexTimings>,
}

// ---------------------------------------------------------------------------
// ovecc summary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    pub repository_root: String,
    pub snapshot: Option<SnapshotRef>,
    pub files: usize,
    pub modules: usize,
    pub dependencies: usize,
    pub circular_dependencies: usize,
    pub boundary_violations: usize,
    pub coupling_density: f64,
    pub hotspots: Vec<HotspotEntry>,
    pub drift_trend: DriftTrend,
    pub risk: RiskScore,
}

/// One hotspot with the explainable components of its score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotEntry {
    pub module: String,
    pub score: f64,
    pub churn: ChurnLevel,
    pub normalized_churn: f64,
    pub coupling: f64,
    pub fan_in: usize,
    pub fan_out: usize,
    pub owners: usize,
    pub violations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotsReport {
    pub hotspots: Vec<HotspotEntry>,
}

// ---------------------------------------------------------------------------
// ovecc impact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactReport {
    /// Raw target as typed by the user.
    pub target: String,
    /// Resolved target; `None` when nothing matched. Multiple matches require
    /// disambiguation unless `--json` is used.
    pub matched: Option<TargetSelector>,
    pub direction: ImpactDirection,
    pub impacted_modules: Vec<String>,
    pub impacted_symbols: Vec<String>,
    pub impacted_apis: Vec<String>,
    pub impacted_tables: Vec<String>,
    /// Ownership boundaries crossed by the impact.
    pub ownership_teams: Vec<String>,
    pub dependency_paths: Vec<Vec<String>>,
    pub historical_churn: Option<ChurnLevel>,
    pub risk: RiskScore,
}

// ---------------------------------------------------------------------------
// ovecc diff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub base: DiffSide,
    pub head: DiffSide,
    pub changes: Vec<ArchitectureChange>,
    pub blast_radius_deltas: Vec<BlastRadiusDelta>,
    pub risk: RiskScore,
}

/// One side of a diff: the user-supplied ref and its resolved snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSide {
    /// Commit SHA, branch, tag, snapshot ID, or relative ref.
    pub reference: String,
    pub snapshot: SnapshotRef,
}

/// Classified architectural change between two graph states.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArchitectureChange {
    AddedModule {
        name: String,
    },
    RemovedModule {
        name: String,
    },
    AddedDependency {
        source: String,
        target: String,
        evidence: Option<Evidence>,
    },
    RemovedDependency {
        source: String,
        target: String,
    },
    AddedApi {
        api: String,
    },
    RemovedApi {
        api: String,
    },
    ChangedApiOwner {
        api: String,
        from: Vec<String>,
        to: Vec<String>,
    },
    AddedSchemaObject {
        name: String,
    },
    ChangedSchemaObject {
        name: String,
    },
    AddedCycle {
        members: Vec<String>,
    },
    RemovedCycle {
        members: Vec<String>,
    },
    IncreasedFanOut {
        module: String,
        base: usize,
        head: usize,
    },
    IncreasedFanIn {
        module: String,
        base: usize,
        head: usize,
    },
    NewBoundaryViolation {
        finding: FindingRecord,
    },
    NewConventionDeviation {
        finding: FindingRecord,
    },
    OwnershipChanged {
        target: String,
        from: Vec<String>,
        to: Vec<String>,
    },
}

/// Reachable-impact size before and after a change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusDelta {
    pub target: String,
    pub base_size: usize,
    pub head_size: usize,
}

// ---------------------------------------------------------------------------
// ovecc drift
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub base: SnapshotRef,
    pub head: SnapshotRef,
    pub deltas: Vec<MetricDelta>,
    pub trend: DriftTrend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub metric: String,
    pub base: f64,
    pub head: f64,
    /// `None` when the base value is zero.
    pub delta_percent: Option<f64>,
}

// ---------------------------------------------------------------------------
// ovecc violations / conventions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationsReport {
    pub violations: Vec<FindingRecord>,
}

/// A learned repository convention with its confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Convention {
    pub kind: ConventionKind,
    /// Human-readable form, e.g. `controllers -> services -> repositories`.
    pub description: String,
    pub confidence: Confidence,
    pub matching_examples: usize,
    pub total_examples: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConventionKind {
    Layering,
    DependencyDirection,
    DomainBoundary,
    ApiHandlerPlacement,
    NamingPattern,
    DatabaseAccess,
    TestLocation,
    Ownership,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConventionsReport {
    pub conventions: Vec<Convention>,
    pub deviations: Vec<FindingRecord>,
}

/// Per-phase wall-clock breakdown of an indexing run, in milliseconds.
/// Always measured (the cost is negligible); surfaced by `--stats`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct IndexTimings {
    /// Walking the tree and applying include/exclude filters.
    pub discovery_ms: u64,
    /// Hashing + parsing + per-file fact extraction (parallel).
    pub parse_ms: u64,
    /// Import resolution + call-graph linking.
    pub resolve_ms: u64,
    /// Metrics, rules, taint, OSV audit, and Git ingestion.
    pub analyze_ms: u64,
    /// Writing the snapshot, graph, and findings to DuckDB.
    pub persist_ms: u64,
    /// End-to-end wall-clock for the whole run.
    pub total_ms: u64,
}

// ---------------------------------------------------------------------------
// ovecc review (change-scoped, named new defects)
// ---------------------------------------------------------------------------

/// Files that changed between two snapshots, classified by content hash. Lets
/// the change review scope analyses (e.g. duplication) to what a change touched.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedFiles {
    /// Present in head, absent in base.
    pub added: Vec<String>,
    /// Present in both, different content hash.
    pub modified: Vec<String>,
    /// Present in base, absent in head.
    pub removed: Vec<String>,
}

impl ChangedFiles {
    /// Paths that are new or edited in head (added ∪ modified) — the surface a
    /// change introduced, against which new findings/clones are attributed.
    pub fn touched(&self) -> impl Iterator<Item = &String> {
        self.added.iter().chain(self.modified.iter())
    }
}

/// The findings a change introduced (`new`) or removed (`resolved`), computed
/// as a set-difference of two snapshots' retained findings by stable content
/// identity. Each entry is a full, named [`FindingRecord`] with file:line
/// evidence — not a count.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingDiff {
    pub new: Vec<FindingRecord>,
    pub resolved: Vec<FindingRecord>,
}

// ---------------------------------------------------------------------------
// ovecc export context / explain
// ---------------------------------------------------------------------------

/// Compact deterministic architecture slice for external tools and optional
/// AI consumers. This is the ONLY input an LLM ever receives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextSlice {
    pub target: String,
    pub dependencies: Vec<String>,
    pub reverse_dependencies: Vec<String>,
    pub call_paths: Vec<Vec<String>>,
    pub apis: Vec<ApiRecord>,
    pub schemas: Vec<SchemaObjectRecord>,
    pub ownership: Vec<OwnershipRecord>,
    pub drift: Vec<MetricDelta>,
    pub findings: Vec<FindingRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_bands_match_documented_thresholds() {
        let band = |v| RiskScore::from_value(v).level;
        assert_eq!(band(0), RiskLevel::Low);
        assert_eq!(band(24), RiskLevel::Low);
        assert_eq!(band(25), RiskLevel::Medium);
        assert_eq!(band(49), RiskLevel::Medium);
        assert_eq!(band(50), RiskLevel::High);
        assert_eq!(band(74), RiskLevel::High);
        assert_eq!(band(75), RiskLevel::Critical);
        assert_eq!(band(10_000), RiskLevel::Critical);
        // from_value preserves the raw value; it does not cap it.
        assert_eq!(RiskScore::from_value(123).value, 123);
    }

    #[test]
    fn meta_is_empty_by_default_and_not_once_populated() {
        assert!(Meta::default().is_empty());
        let meta = Meta {
            docs: Some("d".into()),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn tool_info_default_is_ovecc_at_crate_version() {
        let tool = ToolInfo::default();
        assert_eq!(tool.name, "ovecc");
        assert_eq!(tool.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn envelope_omits_empty_meta_but_keeps_it_when_populated() {
        let data = serde_json::json!({ "k": 1 });

        let env = Envelope::new("summary", &data, Meta::default());
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["command"], "summary");
        assert_eq!(v["tool"]["name"], "ovecc");
        assert_eq!(v["data"]["k"], 1);
        assert!(v.get("meta").is_none(), "empty meta must be omitted");

        let meta = Meta {
            docs: Some("https://docs".into()),
            ..Default::default()
        };
        let env = Envelope::new("summary", &data, meta);
        let v = serde_json::to_value(&env).unwrap();
        assert!(v.get("meta").is_some(), "populated meta must be present");
    }
}
