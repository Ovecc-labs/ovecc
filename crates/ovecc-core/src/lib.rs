//! ovecc-core — shared domain types, stable identifiers, configuration,
//! errors, and the contracts the other Ovecc crates build on.
//!
//! It depends on no concrete tooling (tree-sitter, DuckDB, gitoxide), so
//! every other crate can depend on it without creating a cycle.

pub mod architecture;
pub mod capabilities;
pub mod config;
pub mod coverage;
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
