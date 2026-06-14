//! Error taxonomy and stable CLI exit codes.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, OveccError>;

/// Stable exit codes returned by every command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Success.
    Success = 0,
    /// Findings present when the command is used as a check (`--fail-on`).
    FindingsPresent = 1,
    /// CLI usage error.
    Usage = 2,
    /// Repository or configuration error.
    Repository = 3,
    /// Index/database error.
    Index = 4,
    /// Parser error.
    Parser = 5,
    /// Git error.
    Git = 6,
    /// Internal error.
    Internal = 7,
}

impl ExitCode {
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// Top-level error type; each variant maps to exactly one exit code so the
/// CLI never has to guess what to return.
#[derive(Debug, Error)]
pub enum OveccError {
    #[error("usage error: {message}")]
    Usage { message: String },

    #[error("repository or configuration error: {message}")]
    Repository { message: String },

    #[error("index or database error: {message}")]
    Index {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("parser error in {path}: {message}")]
    Parser { path: String, message: String },

    #[error("git error: {message}")]
    Git {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("internal error: {message}")]
    Internal { message: String },
}

impl OveccError {
    /// Maps the error to its stable exit code.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage { .. } => ExitCode::Usage,
            Self::Repository { .. } => ExitCode::Repository,
            Self::Index { .. } => ExitCode::Index,
            Self::Parser { .. } => ExitCode::Parser,
            Self::Git { .. } => ExitCode::Git,
            Self::Internal { .. } => ExitCode::Internal,
        }
    }
}
