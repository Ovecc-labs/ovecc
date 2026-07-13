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

    /// A query/impact/context target that resolved to nothing. Carries the
    /// closest indexed candidates so a caller can retry with a real target
    /// instead of falling back to a broad text search. `message` is the human
    /// prose; the CLI turns `input`/`candidates` into a machine-readable JSON
    /// envelope under `--format json`. Shares the usage exit code.
    #[error("{message}")]
    UnresolvedTarget {
        message: String,
        input: String,
        candidates: Vec<(String, String)>,
    },

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
            Self::UnresolvedTarget { .. } => ExitCode::Usage,
            Self::Repository { .. } => ExitCode::Repository,
            Self::Index { .. } => ExitCode::Index,
            Self::Parser { .. } => ExitCode::Parser,
            Self::Git { .. } => ExitCode::Git,
            Self::Internal { .. } => ExitCode::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_have_stable_numeric_values() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::FindingsPresent.code(), 1);
        assert_eq!(ExitCode::Usage.code(), 2);
        assert_eq!(ExitCode::Repository.code(), 3);
        assert_eq!(ExitCode::Index.code(), 4);
        assert_eq!(ExitCode::Parser.code(), 5);
        assert_eq!(ExitCode::Git.code(), 6);
        assert_eq!(ExitCode::Internal.code(), 7);
    }

    #[test]
    fn every_error_variant_maps_to_its_exit_code() {
        assert_eq!(
            OveccError::Usage {
                message: "x".into()
            }
            .exit_code(),
            ExitCode::Usage
        );
        assert_eq!(
            OveccError::UnresolvedTarget {
                message: "x".into(),
                input: "x".into(),
                candidates: vec![]
            }
            .exit_code(),
            ExitCode::Usage
        );
        assert_eq!(
            OveccError::Repository {
                message: "x".into()
            }
            .exit_code(),
            ExitCode::Repository
        );
        assert_eq!(
            OveccError::Index {
                message: "x".into(),
                source: None
            }
            .exit_code(),
            ExitCode::Index
        );
        assert_eq!(
            OveccError::Parser {
                path: "a.ts".into(),
                message: "x".into()
            }
            .exit_code(),
            ExitCode::Parser
        );
        assert_eq!(
            OveccError::Git {
                message: "x".into(),
                source: None
            }
            .exit_code(),
            ExitCode::Git
        );
        assert_eq!(
            OveccError::Internal {
                message: "x".into()
            }
            .exit_code(),
            ExitCode::Internal
        );
    }
}
