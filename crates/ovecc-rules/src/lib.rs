//! Architectural rule evaluation and violation classification.
//!
//! This is the deterministic findings pipeline that every rule family flows
//! through — explicit boundary/layer rules, built-in generic rules
//! (circular dependencies), and, later, the security detectors (AST
//! patterns, dependency audit, tainted flows). Each rule turns explicit facts
//! into a [`FindingRecord`] carrying its evidence, so a finding
//! is always traceable back to a source location.
//!
//! Rules that need data not yet materialized — layer rules and direct
//! database-access rules need module-layer detection and the
//! `reads`/`writes` schema edges — are intentionally deferred and noted.

pub mod deadcode;
pub mod smells;

use chrono::Utc;
use ovecc_core::config::RulesConfig;
use ovecc_core::facts::{
    EntityRef, Evidence, FindingKind, FindingRecord, SecurityPatternFact, SecurityPatternKind,
    Severity,
};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_core::legacy::DependencyRecord;

/// Read-only inputs a rule evaluation needs.
pub struct RuleInput<'a> {
    pub repository_id: &'a str,
    pub snapshot_id: Option<&'a str>,
    pub modules: &'a [String],
    pub dependencies: &'a [DependencyRecord],
    pub config: &'a RulesConfig,
    /// Security patterns detected by the parser, paired with their file path
    /// Empty when security analysis is not run.
    pub security_patterns: &'a [(String, SecurityPatternFact)],
}

/// Evaluates every enabled rule family and returns the findings, sorted by ID
/// for deterministic output.
pub fn evaluate(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    findings.extend(boundary_rules(input));
    findings.extend(banned_import_rules(input));
    findings.extend(circular_dependency_rule(input));
    findings.extend(security_rules(input));
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings
}

/// Declarative banned-import rule pack: one finding per `[[rules.banned_imports]]`
/// rule that matches at least one resolved import specifier, with every
/// offending import as file:line evidence. Operates on the neutral dependency
/// facts, so it governs every language's imports.
fn banned_import_rules(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    for rule in &input.config.banned_imports {
        let offending: Vec<&DependencyRecord> = input
            .dependencies
            .iter()
            .filter(|dependency| specifier_matches(&dependency.specifier, &rule.pattern))
            .collect();
        if offending.is_empty() {
            continue;
        }
        let evidence = offending
            .iter()
            .take(20)
            .map(|dependency| Evidence {
                file_path: dependency.source_file_path.clone(),
                line: Some(dependency.evidence_line as u32),
                symbol: None,
                detail: Some(dependency.specifier.clone()),
            })
            .collect();
        findings.push(FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "banned-import",
                &rule.name,
                &rule.pattern,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::ForbiddenImport,
            severity: rule.severity,
            rule_name: Some(format!("banned-import/{}", rule.name)),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: offending
                    .first()
                    .map(|dependency| dependency.source_module.clone())
                    .unwrap_or_default(),
            }),
            title: format!("Banned import: {}", rule.pattern),
            description: rule.message.clone().unwrap_or_else(|| {
                format!(
                    "Importing '{}' is banned by rule '{}' ({} occurrence(s)).",
                    rule.pattern,
                    rule.name,
                    offending.len()
                )
            }),
            evidence,
            created_at: Utc::now(),
        });
    }
    findings
}

/// Minimal specifier glob: exact, `prefix*`, `*suffix`, or `*infix*`.
fn specifier_matches(specifier: &str, pattern: &str) -> bool {
    match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
        (Some(_), Some(_)) => specifier.contains(pattern.trim_matches('*')),
        (None, Some(prefix)) => specifier.starts_with(prefix),
        (Some(suffix), None) => specifier.ends_with(suffix),
        (None, None) => specifier == pattern,
    }
}

/// Classifies parser-detected security patterns into findings. The
/// detection is deterministic (provider patterns, entropy, AST checks); this
/// layer only assigns kind, severity, and evidence.
fn security_rules(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    input
        .security_patterns
        .iter()
        .map(|(path, pattern)| {
            let (kind, severity, title) = match pattern.kind {
                SecurityPatternKind::HardcodedSecret => (
                    FindingKind::HardcodedSecret,
                    Severity::Critical,
                    "Hardcoded secret",
                ),
                SecurityPatternKind::DynamicEval => (
                    FindingKind::InsecurePattern,
                    Severity::High,
                    "Dynamic code execution",
                ),
                SecurityPatternKind::CommandExec => (
                    FindingKind::InsecurePattern,
                    Severity::High,
                    "OS command execution",
                ),
                SecurityPatternKind::WeakHash => (
                    FindingKind::WeakCrypto,
                    Severity::Medium,
                    "Weak hash algorithm",
                ),
                SecurityPatternKind::PermissiveCors => (
                    FindingKind::PermissiveCors,
                    Severity::Medium,
                    "Permissive CORS configuration",
                ),
            };
            let detail = pattern.detail.clone().unwrap_or_default();
            FindingRecord {
                id: FindingId::from_parts(&[
                    input.repository_id,
                    "security",
                    path,
                    &pattern.line.to_string(),
                    security_slug(pattern.kind),
                ]),
                repository_id: RepositoryId::from_raw(input.repository_id),
                snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
                kind,
                severity,
                rule_name: Some(format!("security/{}", security_slug(pattern.kind))),
                target: Some(EntityRef {
                    kind: NodeKind::File,
                    id: path.clone(),
                }),
                title: if detail.is_empty() {
                    title.to_string()
                } else {
                    format!("{title}: {detail}")
                },
                description: format!("{title} detected in {path}:{}.", pattern.line),
                evidence: vec![Evidence {
                    file_path: path.clone(),
                    line: Some(pattern.line),
                    // The enclosing symbol also anchors the finding's content
                    // identity, so a pattern that merely moves (an edit above
                    // it) is not re-reported as new by `review`.
                    symbol: pattern.caller_qualified_name.clone(),
                    detail: pattern.detail.clone(),
                }],
                created_at: Utc::now(),
            }
        })
        .collect()
}

fn security_slug(kind: SecurityPatternKind) -> &'static str {
    match kind {
        SecurityPatternKind::HardcodedSecret => "secret",
        SecurityPatternKind::DynamicEval => "eval",
        SecurityPatternKind::CommandExec => "command-exec",
        SecurityPatternKind::WeakHash => "weak-hash",
        SecurityPatternKind::PermissiveCors => "cors",
    }
}

/// Explicit boundary rules: each `allowed = false` rule that matches a
/// real module→module dependency becomes one finding, with every offending
/// import as evidence.
fn boundary_rules(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    for rule in &input.config.boundaries {
        if rule.allowed {
            continue;
        }
        let offending: Vec<&DependencyRecord> = input
            .dependencies
            .iter()
            .filter(|dependency| {
                !dependency.is_external
                    && dependency.source_module.eq_ignore_ascii_case(&rule.source)
                    && dependency.target_module.eq_ignore_ascii_case(&rule.target)
            })
            .collect();
        if offending.is_empty() {
            continue;
        }

        let evidence = offending
            .iter()
            .take(10)
            .map(|dependency| Evidence {
                file_path: dependency.source_file_path.clone(),
                line: Some(dependency.evidence_line as u32),
                symbol: None,
                detail: Some(dependency.specifier.clone()),
            })
            .collect();

        findings.push(FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "boundary",
                &rule.name,
                &rule.source,
                &rule.target,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::CrossDomainDependency,
            severity: rule.severity,
            rule_name: Some(rule.name.clone()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: rule.source.clone(),
            }),
            title: format!("{} -> {}", rule.source, rule.target),
            description: format!(
                "Forbidden dependency '{}' -> '{}' ({} occurrence(s)). Rule: {}.",
                rule.source,
                rule.target,
                offending.len(),
                rule.name
            ),
            evidence,
            created_at: Utc::now(),
        });
    }
    findings
}

/// One high-severity finding per *elementary* cycle (the actual loop
/// `A -> B -> C -> A`, not just the strongly-connected component), each carrying
/// file:line evidence for every hop so the loop is traceable to source.
fn circular_dependency_rule(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    // The witness edges come from the same connected file-level walk `review`
    // reports (`elementary_cycles_with_witness`), so every surface — findings,
    // violations, review — cites the identical evidence for a given cycle.
    ovecc_graph::cycles::elementary_cycles_with_witness(input.modules, input.dependencies)
        .into_iter()
        .map(|cycle| {
            let members = cycle.modules;
            // Render the loop closing back to its first module: A -> B -> A.
            let mut closed = members.clone();
            if let Some(first) = members.first() {
                closed.push(first.clone());
            }
            let label = closed.join(" -> ");
            let evidence = cycle
                .edges
                .iter()
                .map(|edge| Evidence {
                    file_path: edge.from_file.clone(),
                    line: Some(edge.line as u32),
                    symbol: None,
                    detail: Some(format!(
                        "{} -> {}: {}",
                        edge.from_module, edge.to_module, edge.specifier
                    )),
                })
                .collect();
            FindingRecord {
                id: FindingId::from_parts(&[input.repository_id, "cycle", &members.join(",")]),
                repository_id: RepositoryId::from_raw(input.repository_id),
                snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
                kind: FindingKind::CircularDependency,
                severity: Severity::High,
                rule_name: Some("circular-dependency".to_string()),
                target: Some(EntityRef {
                    kind: NodeKind::Module,
                    id: members.first().cloned().unwrap_or_default(),
                }),
                title: format!("Circular dependency: {label}"),
                description: format!(
                    "{} modules form a dependency cycle: {label}. Break the loop by \
                     inverting or extracting one of its edges.",
                    members.len()
                ),
                evidence,
                created_at: Utc::now(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::config::{BannedImportRule, BoundaryRuleConfig};

    fn dependency(source: &str, target: &str, path: &str, line: usize) -> DependencyRecord {
        DependencyRecord {
            id: format!("dep:{source}:{target}:{line}"),
            repository_id: "repo:test".to_string(),
            source_file_id: "f".to_string(),
            target_file_id: None,
            source_file_path: path.to_string(),
            target_file_path: None,
            source_module_id: format!("m:{source}"),
            target_module_id: format!("m:{target}"),
            source_module: source.to_string(),
            target_module: target.to_string(),
            specifier: format!("../{target}/x"),
            dependency_kind: "static_import".to_string(),
            is_external: false,
            evidence_line: line,
        }
    }

    fn config_with_boundary(allowed: bool) -> RulesConfig {
        RulesConfig {
            boundaries: vec![BoundaryRuleConfig {
                name: "Billing must not depend on User".to_string(),
                source: "billing".to_string(),
                target: "user".to_string(),
                allowed,
                severity: Severity::High,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn forbidden_boundary_produces_one_finding_with_evidence() {
        let deps = vec![
            dependency("billing", "user", "src/billing/a.ts", 3),
            dependency("billing", "user", "src/billing/b.ts", 7),
            dependency("checkout", "user", "src/checkout/c.ts", 1),
        ];
        let config = config_with_boundary(false);
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: Some("snap"),
            modules: &[
                "billing".to_string(),
                "user".to_string(),
                "checkout".to_string(),
            ],
            dependencies: &deps,
            config: &config,
            security_patterns: &[],
        };

        let findings = evaluate(&input);
        let boundary: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::CrossDomainDependency)
            .collect();
        assert_eq!(boundary.len(), 1, "one finding per forbidden edge");
        assert_eq!(boundary[0].severity, Severity::High);
        assert_eq!(boundary[0].evidence.len(), 2, "both billing->user imports");
    }

    #[test]
    fn allowed_boundary_produces_no_finding() {
        let deps = vec![dependency("billing", "user", "src/billing/a.ts", 3)];
        let config = config_with_boundary(true);
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: None,
            modules: &["billing".to_string(), "user".to_string()],
            dependencies: &deps,
            config: &config,
            security_patterns: &[],
        };
        assert!(evaluate(&input).is_empty());
    }

    #[test]
    fn classifies_security_patterns() {
        let patterns = vec![
            (
                "src/config.ts".to_string(),
                SecurityPatternFact {
                    kind: SecurityPatternKind::HardcodedSecret,
                    line: 4,
                    detail: Some("AWS access key".to_string()),
                    caller_qualified_name: None,
                    in_test_code: false,
                },
            ),
            (
                "src/hash.ts".to_string(),
                SecurityPatternFact {
                    kind: SecurityPatternKind::WeakHash,
                    line: 9,
                    detail: Some("MD5".to_string()),
                    caller_qualified_name: None,
                    in_test_code: false,
                },
            ),
        ];
        let config = RulesConfig::default();
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: None,
            modules: &[],
            dependencies: &[],
            config: &config,
            security_patterns: &patterns,
        };
        let findings = evaluate(&input);
        let secret = findings
            .iter()
            .find(|f| f.kind == FindingKind::HardcodedSecret)
            .unwrap();
        assert_eq!(secret.severity, Severity::Critical);
        assert_eq!(secret.evidence[0].line, Some(4));
        assert!(secret.title.contains("AWS access key"));

        let weak = findings
            .iter()
            .find(|f| f.kind == FindingKind::WeakCrypto)
            .unwrap();
        assert_eq!(weak.severity, Severity::Medium);
    }

    #[test]
    fn detects_circular_dependency() {
        let deps = vec![
            dependency("a", "b", "src/a/x.ts", 1),
            dependency("b", "a", "src/b/y.ts", 1),
        ];
        let config = RulesConfig::default();
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: None,
            modules: &["a".to_string(), "b".to_string()],
            dependencies: &deps,
            config: &config,
            security_patterns: &[],
        };
        let findings = evaluate(&input);
        let cycles: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::CircularDependency)
            .collect();
        assert_eq!(cycles.len(), 1);
        assert!(cycles[0].title.contains("a") && cycles[0].title.contains("b"));
    }

    #[test]
    fn specifier_glob_matches_each_form() {
        assert!(specifier_matches("lodash", "lodash")); // exact
        assert!(!specifier_matches("lodash/fp", "lodash"));
        assert!(specifier_matches("@internal/db", "@internal/*")); // prefix
        assert!(specifier_matches("../user/legacy", "*legacy")); // suffix
        assert!(specifier_matches("../legacy/x", "*legacy*")); // infix
        assert!(!specifier_matches("../user/x", "*legacy*"));
    }

    #[test]
    fn banned_import_rule_pack_flags_matching_specifiers() {
        // The `dependency` helper sets specifier to `../{target}/x`.
        let deps = vec![
            dependency("billing", "user", "src/billing/a.ts", 3),
            dependency("billing", "user", "src/billing/b.ts", 7),
            dependency("billing", "tasks", "src/billing/c.ts", 1),
        ];
        let config = RulesConfig {
            banned_imports: vec![BannedImportRule {
                name: "no-user-internals".to_string(),
                pattern: "*user*".to_string(),
                message: Some("import via the public api instead".to_string()),
                severity: Severity::Medium,
            }],
            ..Default::default()
        };
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: None,
            modules: &[],
            dependencies: &deps,
            config: &config,
            security_patterns: &[],
        };
        let findings = evaluate(&input);
        let banned: Vec<_> = findings
            .iter()
            .filter(|f| f.kind == FindingKind::ForbiddenImport)
            .collect();
        assert_eq!(banned.len(), 1, "one finding for the rule");
        assert_eq!(banned[0].severity, Severity::Medium);
        assert_eq!(banned[0].evidence.len(), 2, "both ../user imports");
        assert_eq!(banned[0].evidence[0].line, Some(3));
        assert!(banned[0].description.contains("public api"));
    }
}
