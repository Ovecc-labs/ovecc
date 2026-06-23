//! Architecture graph model.
//!
//! The graph is persisted as typed node/edge rows in DuckDB and reconstructed
//! in memory (petgraph, in `ovecc-graph`) for traversal. Core only defines
//! the storage-facing representation.

use crate::id::RepositoryId;
use serde::{Deserialize, Serialize};

/// Graph node kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Repository,
    File,
    Module,
    Namespace,
    Symbol,
    Function,
    Class,
    Trait,
    Interface,
    Type,
    Api,
    Route,
    RpcMethod,
    Event,
    Table,
    View,
    Column,
    Migration,
    Owner,
    Commit,
    Snapshot,
}

/// Graph edge kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Contains,
    Declares,
    Imports,
    DependsOn,
    Calls,
    Implements,
    Extends,
    Reads,
    Writes,
    Exposes,
    Handles,
    Publishes,
    Subscribes,
    Owns,
    ChangedBy,
    IntroducedBy,
    ModifiedBy,
    Violates,
    SimilarTo,
}

impl EdgeKind {
    /// Edge kinds traversed by default during blast-radius analysis. Mirrors
    /// `ovecc_graph::blast::IMPACT_EDGE_KINDS` in typed form.
    pub fn default_impact_kinds() -> &'static [EdgeKind] {
        &[
            EdgeKind::DependsOn,
            EdgeKind::Calls,
            EdgeKind::Reads,
            EdgeKind::Writes,
            EdgeKind::Exposes,
            EdgeKind::Handles,
        ]
    }
}

/// Persisted graph node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub repository_id: RepositoryId,
    pub kind: NodeKind,
    pub label: String,
    pub properties: serde_json::Value,
}

/// Persisted graph edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub repository_id: RepositoryId,
    pub source_id: String,
    pub target_id: String,
    pub kind: EdgeKind,
    pub weight: Option<f64>,
    pub evidence: Option<serde_json::Value>,
}

/// Independent graph views: only the needed layers are loaded in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphLayer {
    File,
    Symbol,
    Module,
    Api,
    Schema,
    Ownership,
    Temporal,
}

/// A loadable slice of the persisted graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphSlice {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}
