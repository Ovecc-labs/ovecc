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
    pub max_file_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchitectureConfig {
    pub module_strategy: ModuleStrategy,
    /// e.g. `["CODEOWNERS", ".github/CODEOWNERS"]`.
    pub ownership_sources: Vec<String>,
    /// Explicit module mapping, used when strategy is not pure `auto`.
    pub modules: Vec<ModuleMapping>,
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
        }
    }
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

/// Output formats every analysis command must support.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Markdown,
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
            other => Err(crate::error::OveccError::Usage {
                message: format!(
                    "unknown output format '{other}' (expected text, json, ndjson, markdown)"
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
