use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceLanguage {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
}

impl SourceLanguage {
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
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
}

impl ImportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static_import",
            Self::Export => "re_export",
            Self::Require => "require",
            Self::Dynamic => "dynamic_import",
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
    pub modules: usize,
    pub dependencies: usize,
    pub external_dependencies: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    pub repository_root: String,
    pub snapshot_id: Option<String>,
    pub files: usize,
    pub modules: usize,
    pub dependencies: usize,
    pub external_dependencies: usize,
    pub circular_dependencies: usize,
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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
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
    pub trend: DriftTrend,
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
