//! Transitional record types from the engine's first iteration, each
//! scheduled for replacement by the richer `facts`/`report` models. Do not
//! add new features on top of these types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceLanguage {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Python,
    Rust,
    Go,
    Cpp,
}

impl SourceLanguage {
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "py" | "pyi" => Some(Self::Python),
            "rs" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "hh" | "hxx" | "h++" | "h" | "c" | "cu"
            | "cuh" => Some(Self::Cpp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Cpp => "cpp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFact {
    pub specifier: String,
    pub line: usize,
    pub import_kind: ImportKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ImportKind {
    Static,
    Export,
    Require,
    Dynamic,
    /// `import type` / `export type ... from` — erased at runtime, so it
    /// contributes coupling and reachability but can never form a runtime
    /// dependency cycle.
    Type,
}

impl ImportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static_import",
            Self::Export => "re_export",
            Self::Require => "require",
            Self::Dynamic => "dynamic_import",
            Self::Type => "type_import",
        }
    }

    /// Inverse of [`ImportKind::as_str`], used to reconstruct import facts
    /// from persisted dependency rows.
    pub fn from_kind_str(value: &str) -> Option<Self> {
        match value {
            "static_import" => Some(Self::Static),
            "re_export" => Some(Self::Export),
            "require" => Some(Self::Require),
            "dynamic_import" => Some(Self::Dynamic),
            "type_import" => Some(Self::Type),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: String,
    pub repository_id: String,
    pub path: String,
    pub absolute_path: PathBuf,
    pub language: SourceLanguage,
    pub content_hash: String,
    pub size_bytes: u64,
    pub module_id: String,
    pub module_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub id: String,
    pub repository_id: String,
    pub name: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRecord {
    pub id: String,
    pub repository_id: String,
    pub source_file_id: String,
    pub target_file_id: Option<String>,
    pub source_file_path: String,
    pub target_file_path: Option<String>,
    pub source_module_id: String,
    pub target_module_id: String,
    pub source_module: String,
    pub target_module: String,
    pub specifier: String,
    pub dependency_kind: String,
    pub is_external: bool,
    pub evidence_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexReport {
    pub repository_root: String,
    pub database_path: String,
    pub snapshot_id: String,
    pub files_scanned: usize,
    pub files_indexed: usize,
    /// Files actually parsed this run (parse-cache misses).
    pub files_parsed: usize,
    /// Files whose facts were served from the parse cache.
    pub files_from_cache: usize,
    pub modules: usize,
    pub dependencies: usize,
    pub external_dependencies: usize,
    /// Code facts persisted this run.
    pub symbols: usize,
    pub calls: usize,
    pub apis: usize,
    pub tables: usize,
    /// New Git commits ingested this run.
    pub commits_ingested: usize,
    /// Per-file failures that did not abort the run.
    pub parse_failures: Vec<IndexFailure>,
    /// Per-phase wall-clock breakdown, surfaced by `--stats`.
    #[serde(default)]
    pub timings: crate::report::IndexTimings,
}

/// A non-fatal per-file indexing failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexFailure {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    pub repository_root: String,
    /// Volatile snapshot identity, skipped on serialize so two indexes of the
    /// same content produce byte-identical payloads (the snapshot ref lives in
    /// `meta`). Still populated in-memory for callers that need it.
    #[serde(skip_serializing)]
    pub snapshot_id: Option<String>,
    pub files: usize,
    pub modules: usize,
    pub dependencies: usize,
    pub external_dependencies: usize,
    pub circular_dependencies: usize,
    pub boundary_violations: usize,
    pub coupling_density: f64,
    pub hotspots: Vec<Hotspot>,
    pub risk_score: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hotspot {
    pub module: String,
    pub score: usize,
    pub fan_in: usize,
    pub fan_out: usize,
    /// Module instability `fan_out / (fan_in + fan_out)`: near 0 =
    /// stable (depended upon), near 1 = unstable (depends on many).
    pub instability: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// A technical-debt hotspot with the explainable components of its score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotEntry {
    pub module: String,
    /// Weighted score on a 0–100 scale.
    pub score: f64,
    /// Raw churn (file-change events touching the module).
    pub churn: f64,
    pub fan_in: usize,
    pub fan_out: usize,
    pub coupling: usize,
    /// Fraction of the module's files with low majority ownership.
    pub ownership_fragmentation: f64,
    pub violations: usize,
    /// Total cognitive complexity of the module's functions (oxc).
    pub complexity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotsReport {
    pub hotspots: Vec<HotspotEntry>,
    /// False when no git history was indexed: the churn and ownership-
    /// fragmentation signals are then unavailable (rendered "n/a"), not
    /// genuinely zero. Lets agents distinguish "no data" from "0".
    #[serde(default)]
    pub has_git_history: bool,
}

/// A learned repository convention with its confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Convention {
    pub kind: String,
    /// Human-readable form, e.g. `controller -> service`.
    pub description: String,
    /// Ratio of conforming examples to total, in `[0,1]`.
    pub confidence: f64,
    pub matching: usize,
    pub total: usize,
}

/// A fact that contradicts a high-confidence convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deviation {
    pub description: String,
    pub reason: String,
    /// `"warning"` (confidence 0.70–0.85) or `"violation"` (> 0.85).
    pub severity: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConventionsReport {
    pub conventions: Vec<Convention>,
    pub deviations: Vec<Deviation>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ImpactDirection {
    Downstream,
    Upstream,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactReport {
    pub target: String,
    pub matched_module: Option<String>,
    pub direction: ImpactDirection,
    pub affected_modules: Vec<String>,
    pub dependency_paths: Vec<Vec<String>>,
    pub risk_score: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub id: String,
    pub commit_sha: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub source_module: String,
    pub target_module: String,
    pub specifier: String,
    pub is_external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub base: SnapshotRecord,
    pub head: SnapshotRecord,
    pub added_modules: Vec<String>,
    pub removed_modules: Vec<String>,
    pub added_dependencies: Vec<DependencyEdge>,
    pub removed_dependencies: Vec<DependencyEdge>,
    pub risk_score: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub base: SnapshotRecord,
    pub head: SnapshotRecord,
    pub module_delta: isize,
    pub dependency_delta: isize,
    pub circular_dependency_delta: isize,
    pub coupling_delta_percent: f64,
    /// Per-metric base→head deltas across the drift metrics.
    pub metric_deltas: Vec<MetricDelta>,
    pub trend: DriftTrend,
}

/// One architecture metric compared between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDelta {
    pub metric: String,
    pub base: f64,
    pub head: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DriftTrend {
    Improving,
    Stable,
    Worsening,
    Unknown,
}

impl DriftTrend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Improving => "improving",
            Self::Stable => "stable",
            Self::Worsening => "worsening",
            Self::Unknown => "unknown",
        }
    }
}

/// Pure trend classification on snapshot metric deltas. Lives here (not in
/// ovecc-graph) so ovecc-db can classify drift without depending on a sibling
/// crate.
pub fn drift_trend(
    module_delta: isize,
    dependency_delta: isize,
    cycle_delta: isize,
    coupling_delta_percent: f64,
) -> DriftTrend {
    if module_delta == 0
        && dependency_delta == 0
        && cycle_delta == 0
        && coupling_delta_percent.abs() < 1.0
    {
        DriftTrend::Stable
    } else if cycle_delta > 0 || coupling_delta_percent > 10.0 || dependency_delta > 10 {
        DriftTrend::Worsening
    } else if cycle_delta < 0 || coupling_delta_percent < -10.0 || dependency_delta < -10 {
        DriftTrend::Improving
    } else {
        DriftTrend::Stable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_trend_classifies_each_direction() {
        // No change at all (coupling within ±1%) is stable.
        assert_eq!(drift_trend(0, 0, 0, 0.0).as_str(), "stable");
        // A new cycle, coupling growth >10%, or >10 new deps all worsen.
        assert_eq!(drift_trend(0, 0, 1, 0.0).as_str(), "worsening");
        assert_eq!(drift_trend(0, 0, 0, 12.0).as_str(), "worsening");
        assert_eq!(drift_trend(0, 15, 0, 0.0).as_str(), "worsening");
        // A removed cycle, coupling drop, or >10 fewer deps all improve.
        assert_eq!(drift_trend(0, 0, -1, 0.0).as_str(), "improving");
        assert_eq!(drift_trend(0, 0, 0, -12.0).as_str(), "improving");
        assert_eq!(drift_trend(0, -15, 0, 0.0).as_str(), "improving");
    }

    #[test]
    fn drift_trend_worsening_takes_precedence_over_improving_signals() {
        // dep_delta -20 alone would improve, but a new cycle dominates.
        assert_eq!(drift_trend(0, -20, 1, 0.0).as_str(), "worsening");
    }

    #[test]
    fn drift_trend_small_or_boundary_changes_stay_stable() {
        // Non-zero but all sub-threshold (|coupling| ≤ 10, |dep| ≤ 10) → stable.
        assert_eq!(drift_trend(1, 2, 0, 3.0).as_str(), "stable");
        // Thresholds are strict: exactly +10% coupling / +10 deps is not yet worsening.
        assert_eq!(drift_trend(0, 0, 0, 10.0).as_str(), "stable");
        assert_eq!(drift_trend(0, 10, 0, 0.0).as_str(), "stable");
    }
}
