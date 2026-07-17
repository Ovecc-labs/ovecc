//! Structured query language and target syntax.
//! Not a chatbot: a small, deterministic, parseable grammar.

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Parsed query grammar:
///
/// ```text
/// query          = path_query | deps_query | reverse_deps_query | relation_query | named_query
/// path_query     = "paths" target
/// deps_query     = "deps" target
/// rdeps_query    = "rdeps" target
/// relation_query = target "->" target
/// named_query    = "hotspots" | "violations" | "cycles"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Query {
    Paths(TargetSelector),
    Deps(TargetSelector),
    ReverseDeps(TargetSelector),
    Relation {
        source: TargetSelector,
        target: TargetSelector,
    },
    Module(String),
    Hotspots,
    Violations,
    Cycles,
}

impl Query {
    /// Parses the textual form, e.g. `"deps Billing"` or `"billing -> user"`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(crate::error::OveccError::Usage {
                message: "empty query".to_string(),
            });
        }

        // Named queries (no argument).
        match trimmed {
            "hotspots" => return Ok(Query::Hotspots),
            "violations" => return Ok(Query::Violations),
            "cycles" => return Ok(Query::Cycles),
            _ => {}
        }

        // Relation query: `<source> -> <target>`.
        if let Some((source, target)) = trimmed.split_once("->") {
            return Ok(Query::Relation {
                source: TargetSelector::parse(source.trim()),
                target: TargetSelector::parse(target.trim()),
            });
        }

        // Verb queries: `<verb> <target>`.
        if let Some((verb, rest)) = trimmed.split_once(char::is_whitespace) {
            let target = rest.trim();
            if target.is_empty() {
                return Err(crate::error::OveccError::Usage {
                    message: format!("query '{verb}' needs a target"),
                });
            }
            return match verb {
                "paths" => Ok(Query::Paths(TargetSelector::parse(target))),
                "deps" => Ok(Query::Deps(TargetSelector::parse(target))),
                "rdeps" => Ok(Query::ReverseDeps(TargetSelector::parse(target))),
                "module" => Ok(Query::Module(target.to_string())),
                other => Err(crate::error::OveccError::Usage {
                    message: format!(
                        "unknown query verb '{other}' (expected paths/deps/rdeps/module/hotspots/violations/cycles or 'a -> b')"
                    ),
                }),
            };
        }

        Err(crate::error::OveccError::Usage {
            message: format!("could not parse query '{trimmed}'"),
        })
    }
}

/// Target syntax shared by `impact`, `query`, `explain`, and
/// `export context`, e.g. `Billing`, `table:customers`,
/// `api:GET:/customers/{id}`, `violation-42`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TargetSelector {
    Module(String),
    Symbol(String),
    QualifiedSymbol(String),
    Api {
        method: Option<String>,
        path: String,
    },
    Table(String),
    File(String),
    Finding(String),
    /// Unprefixed input — resolved by matching across kinds, with
    /// disambiguation when several entities match.
    Free(String),
}

impl TargetSelector {
    /// Parses prefixed (`table:customers`) or free-form (`Billing`) targets.
    /// Quoted strings are unwrapped.
    pub fn parse(input: &str) -> Self {
        // Prefixes that wrap the rest of the string verbatim.
        type Prefix = (&'static str, fn(String) -> TargetSelector);
        const PREFIXED: &[Prefix] = &[
            ("table:", TargetSelector::Table),
            ("file:", TargetSelector::File),
            ("symbol:", TargetSelector::Symbol),
            ("finding:", TargetSelector::Finding),
        ];
        let trimmed = unquote(input.trim());
        if let Some(rest) = trimmed.strip_prefix("api:") {
            return Self::parse_api(rest);
        }
        for (prefix, make) in PREFIXED {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                return make(rest.to_string());
            }
        }
        if trimmed.contains('.') {
            // A dotted name is a qualified symbol (`Class.method`).
            Self::QualifiedSymbol(trimmed.to_string())
        } else {
            Self::Free(trimmed.to_string())
        }
    }

    /// `api:GET:/path` (method + path), else `api:/path` or `api:name` (path only).
    fn parse_api(rest: &str) -> Self {
        match rest.split_once(':') {
            Some((method, path))
                if !method.is_empty() && method.chars().all(|c| c.is_ascii_alphabetic()) =>
            {
                Self::Api {
                    method: Some(method.to_string()),
                    path: path.to_string(),
                }
            }
            _ => Self::Api {
                method: None,
                path: rest.to_string(),
            },
        }
    }

    /// The raw string a resolver matches against (the part after any prefix).
    pub fn needle(&self) -> &str {
        match self {
            Self::Module(s)
            | Self::Symbol(s)
            | Self::QualifiedSymbol(s)
            | Self::Table(s)
            | Self::File(s)
            | Self::Finding(s)
            | Self::Free(s) => s,
            Self::Api { path, .. } => path,
        }
    }
}

/// Strips a single pair of matching surrounding quotes.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if value.len() >= 2 {
        let first = bytes[0];
        let last = bytes[value.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verb_relation_and_named_queries() {
        assert_eq!(
            Query::parse("deps Billing").unwrap(),
            Query::Deps(TargetSelector::Free("Billing".to_string()))
        );
        assert_eq!(
            Query::parse("rdeps table:customers").unwrap(),
            Query::ReverseDeps(TargetSelector::Table("customers".to_string()))
        );
        assert_eq!(Query::parse("hotspots").unwrap(), Query::Hotspots);
        assert_eq!(Query::parse("cycles").unwrap(), Query::Cycles);
        match Query::parse("billing -> user").unwrap() {
            Query::Relation { source, target } => {
                assert_eq!(source, TargetSelector::Free("billing".to_string()));
                assert_eq!(target, TargetSelector::Free("user".to_string()));
            }
            other => panic!("expected relation, got {other:?}"),
        }
        assert!(Query::parse("bogus Thing").is_err());
        assert!(Query::parse("").is_err());
    }

    #[test]
    fn parses_target_prefixes() {
        assert_eq!(
            TargetSelector::parse("api:GET:/users/{id}"),
            TargetSelector::Api {
                method: Some("GET".to_string()),
                path: "/users/{id}".to_string()
            }
        );
        assert_eq!(
            TargetSelector::parse("api:/users/:id"),
            TargetSelector::Api {
                method: None,
                path: "/users/:id".to_string()
            }
        );
        assert_eq!(
            TargetSelector::parse("\"My Module\""),
            TargetSelector::Free("My Module".to_string())
        );
        assert_eq!(
            TargetSelector::parse("Billing.createInvoice"),
            TargetSelector::QualifiedSymbol("Billing.createInvoice".to_string())
        );
    }
}
