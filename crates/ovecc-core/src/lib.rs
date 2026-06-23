//! ovecc-core — shared domain types, stable identifiers, configuration,
//! errors, and the contracts implemented by every other Ovecc crate.
//!
//! This crate depends on no concrete tooling (tree-sitter, DuckDB, gitoxide):
//! it only defines the data model and the traits that the specialized crates
//! (`ovecc-parser`, `ovecc-db`, `ovecc-git`, `ovecc-graph`, `ovecc-rules`,
//! `ovecc-query`, `ovecc-export`, `ovecc-ai`) implement.

pub mod capabilities;
pub mod config;
pub mod error;
pub mod facts;
pub mod graph;
pub mod id;
pub mod lang;
pub mod legacy;
pub mod query;
pub mod report;
pub mod traits;
pub mod util;

pub use error::{ExitCode, OveccError, Result};
