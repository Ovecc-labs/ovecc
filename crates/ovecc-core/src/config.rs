//! Repository-level configuration and runtime paths
//! Resolution order: CLI flags > environment variables >
//! `.ovecc/config.toml` > built-in defaults.

use crate::error::Result;
use crate::facts::Severity;
use crate::id::RepositoryId;
use crate::lang::SourceLanguage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Fully resolved configuration handed to every command.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OveccConfig {
    pub project: ProjectConfig,
    pub index: IndexConfig,
    /// Per-language enable switch, e.g. `typescript = true`.
    pub languages: BTreeMap<SourceLanguage, bool>,
    pub architecture: ArchitectureConfig,
    pub rules: RulesConfig,
    pub output: OutputConfig,
    pub diagnose: DiagnoseConfig,
}

impl OveccConfig {
    /// Loads `.ovecc/config.toml` if present, applies env vars
    /// (`OVECC_FORMAT`, `OVECC_COLOR`) then CLI overrides, and falls back to
    /// built-in defaults: flags > env > file > defaults.
    pub fn load(root: &Path, overrides: &ConfigOverrides) -> Result<Self> {
        let config_path = root.join(".ovecc").join("config.toml");
        let mut config = if config_path.is_file() {
            let text = std::fs::read_to_string(&config_path).map_err(|error| {
                crate::error::OveccError::Repository {
                    message: format!("failed to read {}: {error}", config_path.display()),
                }
            })?;
            toml::from_str::<OveccConfig>(&text).map_err(|error| {
                crate::error::OveccError::Repository {
                    message: format!("invalid configuration {}: {error}", config_path.display()),
                }
            })?
        } else {
            Self::default()
        };

        if let Ok(value) = std::env::var("OVECC_FORMAT") {
            config.output.default_format = value.parse()?;
        }
        if let Ok(value) = std::env::var("OVECC_COLOR") {
            config.output.color = value.parse()?;
        }

        if let Some(format) = overrides.format {
            config.output.default_format = format;
        }
        if let Some(color) = overrides.color {
            config.output.color = color;
        }
        if let Some(include) = &overrides.include {
            config.index.include = include.clone();
        }
        if let Some(exclude) = &overrides.exclude {
            config.index.exclude.extend(exclude.iter().cloned());
        }
        if let Some(coverage) = &overrides.coverage {
            config.index.coverage = Some(coverage.clone());
        }
        Ok(config)
    }

    /// True when the language is enabled for indexing. An absent or empty
    /// `[languages]` section means "all languages enabled".
    pub fn language_enabled(&self, language: SourceLanguage) -> bool {
        if self.languages.is_empty() {
            return true;
        }
        self.languages.get(&language).copied().unwrap_or(false)
    }
}

/// Overrides collected from CLI flags and environment variables.
#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub format: Option<OutputFormat>,
    pub color: Option<ColorMode>,
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub coverage: Option<String>,
    pub no_git: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IndexConfig {
    /// Glob patterns, e.g. `["src/**", "packages/**"]`.
    pub include: Vec<String>,
    /// Glob patterns added to the built-in exclusions.
    pub exclude: Vec<String>,
    /// Skip files larger than this many bytes. `None` applies
    /// [`DEFAULT_MAX_FILE_SIZE_BYTES`]: a file above it is almost always a
    /// generated or vendored blob, and parsing one into the AST is a memory
    /// and latency risk with no analysis value. Set an explicit value to
    /// override (a very large one effectively disables the cap).
    pub max_file_size_bytes: Option<u64>,
    /// Index files that look generated or vendored (minified bundles, WASM/
    /// emscripten glue, `@generated` / `DO NOT EDIT` markers). Off by default:
    /// such files are the dominant false-positive source in complexity,
    /// dead-code, and security, and parsing machine-emitted blobs is wasteful.
    pub index_generated: bool,
    /// Flag `package.json` dependencies that no indexed file imports. Off by
    /// default: a dependency can be used via tool config, a `scripts` entry, a
    /// side-effect import, or a test fixture — all invisible to the import
    /// graph — so the finding is false-positive-prone without framework-aware
    /// resolution. Opt in when those caveats are acceptable.
    pub detect_unused_deps: bool,
    /// LCOV tracefile to read line coverage from, relative to the repository
    /// root. Unset looks in the conventional places
    /// ([`DEFAULT_COVERAGE_PATHS`]); finding nothing there is not an error,
    /// just a run without coverage.
    pub coverage: Option<String>,
}

/// Where an LCOV tracefile is looked for when `[index] coverage` is unset:
/// where nyc, Jest and Vitest write by default, and the two names the Rust
/// coverage tools are usually pointed at.
pub const DEFAULT_COVERAGE_PATHS: [&str; 3] = ["coverage/lcov.info", "lcov.info", "coverage.lcov"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchitectureConfig {
    pub module_strategy: ModuleStrategy,
    /// How many path segments below a recognized source container (`src/`,
    /// `packages/`, `apps/`, ...) define a module. `1` (the default) groups
    /// `src/<name>/...` as `<name>`. Raise it for monorepos that nest the whole
    /// tree under one directory — e.g. VS Code keeps everything under `src/vs`,
    /// so depth `1` collapses the repo into a single `vs` module; depth `2`
    /// recovers real boundaries (`vs/editor`, `vs/workbench`, `vs/platform`).
    /// Values below `1` are treated as `1`.
    #[serde(default = "default_module_depth")]
    pub module_depth: usize,
    /// e.g. `["CODEOWNERS", ".github/CODEOWNERS"]`.
    pub ownership_sources: Vec<String>,
    /// Explicit module mapping, used when strategy is not pure `auto`.
    pub modules: Vec<ModuleMapping>,
}

/// Default cap for [`IndexConfig::max_file_size_bytes`] when unset (5 MiB).
/// Hand-written source almost never exceeds it; a file that does is a
/// generated bundle whose AST parse costs memory and time for no signal.
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024;

/// Default module-inference depth: one segment below the source container,
/// preserving the historical `src/<name>` → `<name>` behavior.
fn default_module_depth() -> usize {
    1
}

impl Default for ArchitectureConfig {
    fn default() -> Self {
        Self {
            module_strategy: ModuleStrategy::default(),
            module_depth: default_module_depth(),
            ownership_sources: Vec::new(),
            modules: Vec::new(),
        }
    }
}

/// Should module boundaries be inferred, configured, or both?
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleStrategy {
    #[default]
    Auto,
    Configured,
    Hybrid,
}

/// Explicit `path prefix -> module` rule from config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapping {
    pub name: String,
    pub path_prefix: String,
    pub layer: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub enable_convention_rules: bool,
    pub enable_layer_rules: bool,
    pub enable_domain_rules: bool,
    /// `[[rules.boundaries]]` entries.
    pub boundaries: Vec<BoundaryRuleConfig>,
    /// `[[rules.layers]]` entries.
    pub layers: Vec<LayerRuleConfig>,
    /// `[[rules.banned_imports]]` entries: a declarative rule pack banning
    /// imports of specifier patterns, evaluated over the neutral fact model so
    /// it works across every language.
    pub banned_imports: Vec<BannedImportRule>,
}

impl Default for RulesConfig {
    /// Rule families are enabled by default.
    fn default() -> Self {
        Self {
            enable_convention_rules: true,
            enable_layer_rules: true,
            enable_domain_rules: true,
            boundaries: Vec::new(),
            layers: Vec::new(),
            banned_imports: Vec::new(),
        }
    }
}

/// A declarative policy rule banning imports whose specifier matches a pattern,
/// e.g. `pattern = "lodash"`, `pattern = "@internal/*"`, or `pattern = "*legacy*"`.
/// Language-neutral: it matches the resolved import specifier, so it governs
/// JS/TS, Python, Go, Rust, and C++ imports alike.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannedImportRule {
    pub name: String,
    /// Specifier pattern: exact, `prefix*`, `*suffix`, or `*infix*`.
    pub pattern: String,
    /// Optional guidance surfaced in the finding (e.g. "use @scope/x instead").
    #[serde(default)]
    pub message: Option<String>,
    pub severity: Severity,
}

/// Explicit boundary rule, e.g. "Billing must not depend on User".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryRuleConfig {
    pub name: String,
    pub source: String,
    pub target: String,
    pub allowed: bool,
    pub severity: Severity,
}

/// Explicit layer rule, e.g. "controllers cannot access tables".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerRuleConfig {
    pub name: String,
    pub source_layer: String,
    pub target_kind: String,
    pub allowed: bool,
    pub severity: Severity,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub default_format: OutputFormat,
    pub color: ColorMode,
}

/// Thresholds and toggles for `ovecc diagnose` / `advise` / `metrics`. Tuned for
/// precision; override any field under `[diagnose]` in `.ovecc/config.toml`.
/// Detection runs at *component* (directory) granularity derived from the
/// file→file graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiagnoseConfig {
    /// Component granularity: 0 = the file's parent directory; N > 0 = truncate
    /// the path to its first N segments (coarser).
    pub component_depth: usize,
    /// Percentile (0..1) above which both fan-in and fan-out qualify as a hub.
    pub hub_percentile: f64,
    /// Min share of a component's out-edges to a less-stable component before it
    /// is an Unstable Dependency (Arcan DoUD).
    pub unstable_doud: f64,
    /// Percentile (0..1) of component size (file count) for a God Component.
    pub god_percentile: f64,
    /// Absolute minimum file count for a God Component.
    pub god_min_files: usize,
    /// Coupling-density thresholds for the repo-level Dense Structure finding.
    pub dense_medium: f64,
    pub dense_high: f64,
    /// How many top hotspots to surface.
    pub hotspot_limit: usize,
    /// Findings below this confidence are dropped.
    pub min_confidence: f64,
    /// Minimum co-change count for a Change Coupling / Modularity Violation.
    pub change_coupling_min: usize,
    /// Absolute churn floor for a Hotspot: a component below this many
    /// history-weighted file touches cannot be a hotspot, whatever its
    /// normalized score (relative normalization makes everything "hot" on a
    /// near-empty history).
    pub hotspot_min_churn: f64,
    /// Absolute complexity floor for a Hotspot (same rationale: a component
    /// with trivial complexity is not debt no matter how often it changes).
    pub hotspot_min_complexity: f64,
    /// Minimum total churn mass (sum of history-weighted file touches across
    /// the repo) before the evolutionary detectors (hotspot, unstable
    /// interface, change coupling) run at all. One or two commits of history
    /// cannot witness evolution; below this floor they stay silent.
    pub evolutionary_min_history: f64,
    /// Minimum component count before the repo-level Dense Structure finding
    /// can fire — tiny graphs are naturally dense and the density ratio is
    /// meaningless there.
    pub dense_min_components: usize,
    /// Minimum distance from the main sequence `D = |A + I − 1|` for a Zone of
    /// Pain finding (0..1).
    pub zone_distance: f64,
    /// Minimum number of type declarations a component must hold before its
    /// Abstractness is trusted enough to flag a Zone of Pain.
    pub zone_min_types: usize,
    /// Files to exclude (precision-first defaults: tests, fixtures, generated,
    /// vendored). A token with `.` matches the filename as a substring; else it
    /// matches a whole path segment. Case-insensitive.
    pub exclude: Vec<String>,
    /// Manifest directories (Cargo crates, npm packages) whose conventional
    /// `src/` segment is transparent for component derivation, so a crate's
    /// `build.rs` and its `src/` land in one component. Filled automatically
    /// from the repository's manifests; overridable here.
    pub component_roots: Vec<String>,
}

impl Default for DiagnoseConfig {
    fn default() -> Self {
        Self {
            component_depth: 0,
            hub_percentile: 0.90,
            unstable_doud: 0.30,
            god_percentile: 0.90,
            god_min_files: 8,
            dense_medium: 0.15,
            dense_high: 0.35,
            hotspot_limit: 10,
            hotspot_min_churn: 3.0,
            hotspot_min_complexity: 10.0,
            evolutionary_min_history: 30.0,
            dense_min_components: 10,
            min_confidence: 0.5,
            change_coupling_min: 4,
            zone_distance: 0.7,
            zone_min_types: 5,
            exclude: [
                "test",
                "tests",
                "__tests__",
                "__mocks__",
                "mocks",
                "fixtures",
                "fixture",
                "e2e",
                "generated",
                "node_modules",
                "dist",
                "build",
                "out",
                "coverage",
                "vendor",
                "vendored",
                "docs",
                "doc",
                "examples",
                "example",
                "samples",
                ".spec.",
                ".test.",
                ".min.",
                ".generated.",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            component_roots: Vec::new(),
        }
    }
}

/// Output formats every analysis command must support.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Markdown,
    /// SARIF 2.1.0 — for GitHub code scanning and CI security dashboards.
    Sarif,
    /// Code Climate / GitLab Code Quality JSON — for GitLab CI merge-request
    /// quality reports.
    Codeclimate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl std::str::FromStr for OutputFormat {
    type Err = crate::error::OveccError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "ndjson" => Ok(Self::Ndjson),
            "markdown" | "md" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            "codeclimate" | "code-climate" | "gitlab" => Ok(Self::Codeclimate),
            other => Err(crate::error::OveccError::Usage {
                message: format!(
                    "unknown output format '{other}' (expected text, json, ndjson, markdown, sarif, codeclimate)"
                ),
            }),
        }
    }
}

impl std::str::FromStr for ColorMode {
    type Err = crate::error::OveccError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(crate::error::OveccError::Usage {
                message: format!("unknown color mode '{other}' (expected auto, always, never)"),
            }),
        }
    }
}

/// Runtime layout of the `.ovecc/` directory.
#[derive(Debug, Clone)]
pub struct ProjectPaths {
    pub root: PathBuf,
    pub ovecc_dir: PathBuf,
    pub config_path: PathBuf,
    pub db_path: PathBuf,
    pub snapshots_dir: PathBuf,
    pub metrics_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub parse_cache_dir: PathBuf,
    pub git_cache_dir: PathBuf,
}

impl ProjectPaths {
    /// Canonicalizes the root and derives every `.ovecc/` path.
    pub fn resolve(root: impl AsRef<Path>) -> Result<Self> {
        let root = std::fs::canonicalize(root.as_ref()).map_err(|error| {
            crate::error::OveccError::Repository {
                message: format!(
                    "failed to resolve repository root {}: {error}",
                    root.as_ref().display()
                ),
            }
        })?;
        let root = crate::util::simplify_verbatim(&root).unwrap_or(root);
        let ovecc_dir = root.join(".ovecc");
        Ok(Self {
            config_path: ovecc_dir.join("config.toml"),
            db_path: ovecc_dir.join("graph.db"),
            snapshots_dir: ovecc_dir.join("snapshots"),
            metrics_dir: ovecc_dir.join("metrics"),
            exports_dir: ovecc_dir.join("exports"),
            parse_cache_dir: ovecc_dir.join("cache").join("parse"),
            git_cache_dir: ovecc_dir.join("cache").join("git"),
            ovecc_dir,
            root,
        })
    }

    /// Creates the runtime directories if missing.
    pub fn ensure_runtime_dirs(&self) -> Result<()> {
        for dir in [
            &self.ovecc_dir,
            &self.snapshots_dir,
            &self.metrics_dir,
            &self.exports_dir,
            &self.parse_cache_dir,
            &self.git_cache_dir,
        ] {
            std::fs::create_dir_all(dir).map_err(|error| crate::error::OveccError::Repository {
                message: format!("failed to create {}: {error}", dir.display()),
            })?;
        }
        Ok(())
    }

    /// Stable repository identifier derived from the normalized root path.
    pub fn repository_id(&self) -> RepositoryId {
        RepositoryId(format!(
            "repo:{}",
            crate::util::short_hash(&crate::util::normalize_path(&self.root), 16)
        ))
    }

    /// Normalized root path for display and persistence.
    pub fn root_display(&self) -> String {
        crate::util::normalize_path(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_rule_families() {
        let config = OveccConfig::default();
        assert!(config.rules.enable_convention_rules);
        assert!(config.rules.enable_layer_rules);
        assert!(config.rules.enable_domain_rules);
        assert_eq!(config.output.default_format, OutputFormat::Text);
    }

    #[test]
    fn module_depth_defaults_to_one_and_parses_from_config() {
        assert_eq!(OveccConfig::default().architecture.module_depth, 1);

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ovecc")).unwrap();
        std::fs::write(
            dir.path().join(".ovecc").join("config.toml"),
            "[architecture]\nmodule_depth = 2\n",
        )
        .unwrap();
        let config = OveccConfig::load(dir.path(), &ConfigOverrides::default()).unwrap();
        assert_eq!(config.architecture.module_depth, 2);

        // An [architecture] section that omits module_depth still yields the default.
        std::fs::write(
            dir.path().join(".ovecc").join("config.toml"),
            "[architecture]\nmodule_strategy = \"auto\"\n",
        )
        .unwrap();
        let config = OveccConfig::load(dir.path(), &ConfigOverrides::default()).unwrap();
        assert_eq!(config.architecture.module_depth, 1);
    }

    #[test]
    fn missing_file_yields_defaults_and_all_languages() {
        let dir = tempfile::tempdir().unwrap();
        let config = OveccConfig::load(dir.path(), &ConfigOverrides::default()).unwrap();
        assert_eq!(config.output.default_format, OutputFormat::Text);
        assert!(config.language_enabled(SourceLanguage::Rust));
        assert!(config.language_enabled(SourceLanguage::TypeScript));
    }

    #[test]
    fn file_then_cli_overrides_apply_in_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ovecc")).unwrap();
        std::fs::write(
            dir.path().join(".ovecc").join("config.toml"),
            r#"
[project]
name = "demo"

[index]
exclude = ["gen/**"]
max_file_size_bytes = 1000

[languages]
typescript = true
javascript = false

[rules]
enable_layer_rules = false

[output]
default_format = "json"
"#,
        )
        .unwrap();

        let config = OveccConfig::load(dir.path(), &ConfigOverrides::default()).unwrap();
        assert_eq!(config.project.name.as_deref(), Some("demo"));
        assert_eq!(config.output.default_format, OutputFormat::Json);
        assert_eq!(config.index.max_file_size_bytes, Some(1000));
        assert_eq!(config.index.exclude, vec!["gen/**".to_string()]);
        assert!(config.language_enabled(SourceLanguage::TypeScript));
        assert!(!config.language_enabled(SourceLanguage::JavaScript));
        // a populated [languages] section disables unlisted languages
        assert!(!config.language_enabled(SourceLanguage::Python));
        // partial [rules] section: present key applies, absent keys keep defaults
        assert!(!config.rules.enable_layer_rules);
        assert!(config.rules.enable_convention_rules);

        let overrides = ConfigOverrides {
            format: Some(OutputFormat::Markdown),
            exclude: Some(vec!["extra/**".to_string()]),
            ..Default::default()
        };
        let config = OveccConfig::load(dir.path(), &overrides).unwrap();
        assert_eq!(config.output.default_format, OutputFormat::Markdown);
        assert_eq!(
            config.index.exclude,
            vec!["gen/**".to_string(), "extra/**".to_string()]
        );
    }

    #[test]
    fn invalid_config_is_a_repository_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ovecc")).unwrap();
        std::fs::write(dir.path().join(".ovecc").join("config.toml"), "not [valid").unwrap();

        let error = OveccConfig::load(dir.path(), &ConfigOverrides::default()).unwrap_err();
        assert_eq!(error.exit_code(), crate::error::ExitCode::Repository);
    }
}
