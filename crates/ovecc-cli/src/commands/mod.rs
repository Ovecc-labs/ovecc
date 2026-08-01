//! One module per command family. Each module owns its report types, the
//! store queries that build them, and the per-format renderers; `cli::run`
//! only resolves arguments and dispatches here.

use crate::cli::FormatArg;
use anyhow::Result;
use ovecc_core::config::{ConfigOverrides, OutputFormat, OveccConfig, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_db::ArchitectureStore;

pub(crate) mod agent;
pub(crate) mod architecture;
pub(crate) mod capabilities;
pub(crate) mod conventions;
pub(crate) mod coupling;
pub(crate) mod diagnose;
pub(crate) mod diff;
pub(crate) mod dupes;
pub(crate) mod findings;
pub(crate) mod history;
pub(crate) mod index;
pub(crate) mod query;
pub(crate) mod review;
pub(crate) mod search;
pub(crate) mod selfcheck;
pub(crate) mod summary;

/// Resolves a CLI ref argument for `diff`/`drift`. Snapshot keywords
/// (`latest`/`previous`/`base`) and `snapshot:` IDs pass through unchanged;
/// anything else is resolved as a Git ref to its commit SHA, which
/// is then matched against the snapshot commits.
pub(crate) fn resolve_ref(root: &std::path::Path, reference: &str) -> String {
    if matches!(reference, "latest" | "previous" | "base") || reference.starts_with("snapshot:") {
        return reference.to_string();
    }
    ovecc_git::resolve_ref(root, reference).unwrap_or_else(|| reference.to_string())
}

pub(crate) fn load_config(paths: &ProjectPaths, format: Option<FormatArg>) -> Result<OveccConfig> {
    let overrides = ConfigOverrides {
        format: format.map(Into::into),
        ..Default::default()
    };
    Ok(OveccConfig::load(&paths.root, &overrides)?)
}

/// What a two-snapshot command needs before it can compare anything: the
/// resolved project, its config, one open store, and both refs turned into
/// snapshot selectors. `diff`, `gate` and `review` open exactly this.
pub(crate) struct Comparison {
    pub(crate) paths: ProjectPaths,
    pub(crate) config: OveccConfig,
    pub(crate) store: ArchitectureStore,
    pub(crate) base: String,
    pub(crate) head: String,
}

impl Comparison {
    pub(crate) fn resolve(
        repo: Option<std::path::PathBuf>,
        format: Option<FormatArg>,
        base: &str,
        head: &str,
    ) -> Result<Self> {
        let paths = ProjectPaths::resolve(repo.unwrap_or_else(|| std::path::PathBuf::from(".")))?;
        let config = load_config(&paths, format)?;
        let store = open_store(&paths)?;
        let base = resolve_ref(&paths.root, base);
        let head = resolve_ref(&paths.root, head);
        Ok(Self {
            paths,
            config,
            store,
            base,
            head,
        })
    }

    pub(crate) fn format(&self) -> OutputFormat {
        self.config.output.default_format
    }
}

pub(crate) fn open_store(paths: &ProjectPaths) -> Result<ArchitectureStore> {
    if !paths.db_path.exists() {
        return Err(OveccError::Index {
            message: format!(
                "architecture database does not exist at {}; run 'ovecc index' first",
                paths.db_path.display()
            ),
            source: None,
        }
        .into());
    }
    let mut store = ArchitectureStore::open(&paths.db_path)?;
    store.initialize_schema()?;
    Ok(store)
}
