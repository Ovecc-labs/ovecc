//! One module per command family. Each module owns its report types, the
//! store queries that build them, and the per-format renderers; `cli::run`
//! only resolves arguments and dispatches here.

use crate::cli::FormatArg;
use anyhow::Result;
use ovecc_core::config::{ConfigOverrides, OveccConfig, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_db::ArchitectureStore;

pub(crate) mod agent;
pub(crate) mod capabilities;
pub(crate) mod conventions;
pub(crate) mod diagnose;
pub(crate) mod diff;
pub(crate) mod dupes;
pub(crate) mod findings;
pub(crate) mod history;
pub(crate) mod index;
pub(crate) mod query;
pub(crate) mod review;
pub(crate) mod search;
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
