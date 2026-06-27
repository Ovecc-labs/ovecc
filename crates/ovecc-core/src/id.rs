//! Stable entity identifiers.
//!
//! Every entity gets an ID that survives re-indexing when possible, in the
//! form `{prefix}:{hash_of_parts}` where the parts follow the documented
//! strategy, e.g. `file:{repository_id}:{normalized_path}` or
//! `symbol:{repository_id}:{language}:{qualified_name}:{span_hash}`.
//!
//! Stable IDs are required for incremental updates, architecture diffs,
//! drift tracking, finding persistence, and explain commands.

use serde::{Deserialize, Serialize};

macro_rules! stable_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(
            Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            /// Builds the identifier by hashing the ordered parts.
            /// The form is `{prefix}:{hash(parts)}`, matching the string-based
            /// `util::stable_id` so typed and legacy IDs stay interchangeable.
            pub fn from_parts(parts: &[&str]) -> Self {
                Self(crate::util::stable_id($prefix, parts))
            }

            /// Wraps an already-built identifier string.
            pub fn from_raw(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

stable_id!(
    /// `repo:{hash(normalized_root_path)}`
    RepositoryId, "repo"
);
stable_id!(
    /// `file:{repository_id}:{normalized_path}`
    FileId, "file"
);
stable_id!(
    /// `module:{repository_id}:{module_name}`
    ModuleId, "module"
);
stable_id!(
    /// `symbol:{repository_id}:{file_path}:{language}:{qualified_name}:{declaration_span_hash}`
    SymbolId, "symbol"
);
stable_id!(
    /// `dependency:{repository_id}:{source_id}:{target_id}:{kind}:{evidence}`
    DependencyId, "dependency"
);
stable_id!(
    /// `call:{repository_id}:{caller_id}:{callee_or_name}:{evidence}`
    CallId, "call"
);
stable_id!(
    /// `api:{repository_id}:{method}:{path_or_name}`
    ApiId, "api"
);
stable_id!(
    /// `table:{repository_id}:{schema_name}:{object_name}` (tables, views, columns, ...)
    SchemaObjectId, "table"
);
stable_id!(
    /// `migration:{repository_id}:{path}`
    MigrationId, "migration"
);
stable_id!(
    /// `ownership:{repository_id}:{owner_name}:{target_id}`
    OwnershipId, "ownership"
);
stable_id!(
    /// `commit:{repository_id}:{sha}`
    CommitId, "commit"
);
stable_id!(
    /// `change:{repository_id}:{commit_sha}:{file_path}`
    FileChangeId, "change"
);
stable_id!(
    /// `snapshot:{repository_id}:{timestamp}:{commit_sha}`
    SnapshotId, "snapshot"
);
stable_id!(
    /// `metric:{snapshot_id}:{metric_name}:{scope}:{target_id}`
    MetricId, "metric"
);
stable_id!(
    /// `finding:{repository_id}:{kind}:{target_id}:{evidence_hash}`
    FindingId, "finding"
);
stable_id!(
    /// `complexity:{repository_id}:{file_id}:{qualified_name}:{line}`
    ComplexityId, "complexity"
);
stable_id!(
    /// `export:{repository_id}:{file_id}:{name}:{line}`
    ExportId, "export"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_ids_are_deterministic_and_prefixed() {
        let a = FileId::from_parts(&["repo", "src/a.ts"]);
        assert_eq!(a, FileId::from_parts(&["repo", "src/a.ts"]));
        assert!(a.as_str().starts_with("file:"));
        assert_eq!(FileId::PREFIX, "file");
    }

    #[test]
    fn different_id_types_never_collide_for_same_parts() {
        // The prefix is part of the identity, so a file and a module built from
        // identical parts get distinct ids.
        assert_ne!(
            FileId::from_parts(&["repo", "x"]).0,
            ModuleId::from_parts(&["repo", "x"]).0
        );
    }

    #[test]
    fn from_raw_round_trips() {
        let id = SymbolId::from_raw("symbol:abc123");
        assert_eq!(id.as_str(), "symbol:abc123");
    }

    #[test]
    fn distinct_parts_produce_distinct_ids() {
        assert_ne!(
            CommitId::from_parts(&["repo", "sha1"]),
            CommitId::from_parts(&["repo", "sha2"])
        );
    }
}
