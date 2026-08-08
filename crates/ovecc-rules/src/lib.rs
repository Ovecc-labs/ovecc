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

mod contract;
pub mod deadcode;
pub mod smells;

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use ovecc_core::architecture::ArchitectureContract;
use ovecc_core::config::RulesConfig;
use ovecc_core::coverage::FileCoverage;
use ovecc_core::facts::{
    CapabilityFact, CoChangedPair, EntityRef, Evidence, FindingKind, FindingRecord,
    FunctionMetricsRow, SecurityPatternFact, SecurityPatternKind, Severity,
};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_core::lang::SourceLanguage;
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
    /// The intended architecture, when `.ovecc/architecture.toml` exists.
    pub architecture: Option<ContractInput<'a>>,
}

/// The architecture contract and its resolution against this snapshot's
/// files. Assembled by the caller (the indexer today) so the contract check
/// itself never touches the database and can later judge unsaved edges.
#[derive(Clone, Copy)]
pub struct ContractInput<'a> {
    pub contract: &'a ArchitectureContract,
    /// File path -> owning component, from
    /// [`ovecc_core::architecture::assign_components`].
    pub component_of: &'a BTreeMap<String, String>,
    /// Every indexed file path, for the unassigned policy.
    pub files: &'a [String],
    /// Accepted violations ([`ovecc_core::architecture::baseline_entry`]
    /// keys), subtracted in `new-violations` mode. Empty when no baseline
    /// store exists.
    pub baseline: &'a BTreeSet<String>,
    /// File path -> qualified slice (`features/auth`) for `slices = true`
    /// components, from [`ovecc_core::architecture::assign_slices`].
    pub slice_of: &'a BTreeMap<String, String>,
    /// `(file path, capability use)` pairs for the `deny_capabilities`
    /// check — fresh parse facts at index time, `capability_uses` rows at
    /// check time.
    pub capability_uses: &'a [(String, CapabilityFact)],
    /// Per-function metrics for the per-component budget check.
    pub functions: &'a [FunctionMetricsRow],
    /// File pairs the history keeps changing together, for the behavioral
    /// coupling check. Empty when no git history was ingested.
    pub co_changes: &'a [CoChangedPair],
    /// Per-file line coverage for the `min_coverage` check. Empty when no
    /// tracefile was indexed, which means "unknown", not "nothing covered".
    pub coverage: &'a [FileCoverage],
}

/// Evaluates every enabled rule family and returns the findings, sorted by ID
/// for deterministic output.
pub fn evaluate(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    let mut findings = Vec::new();
    findings.extend(boundary_rules(input));
    findings.extend(banned_import_rules(input));
    findings.extend(circular_dependency_rule(input));
    findings.extend(unresolved_import_rule(input));
    findings.extend(security_rules(input));
    findings.extend(contract::contract_rules(input));
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings
}

/// The contract check alone, over an arbitrary edge set. This is how
/// `ovecc architecture diff`/`check` judge a freshly edited contract against
/// the stored graph without re-indexing: same verdicts as `evaluate`, none of
/// the other rule families.
pub fn contract_findings(
    repository_id: &str,
    dependencies: &[DependencyRecord],
    architecture: ContractInput<'_>,
) -> Vec<FindingRecord> {
    let config = RulesConfig::default();
    let input = RuleInput {
        repository_id,
        snapshot_id: None,
        modules: &[],
        dependencies,
        config: &config,
        security_patterns: &[],
        architecture: Some(architecture),
    };
    let mut findings = contract::contract_rules(&input);
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings
}

/// Every current violation as a baseline entry, grouped by source component
/// and ignoring the existing baseline: the full present debt. `check
/// --freeze` writes this to the store; the ratchet intersects the store with
/// it so corrected entries disappear.
pub fn contract_entries(
    dependencies: &[DependencyRecord],
    architecture: ContractInput<'_>,
) -> BTreeMap<String, BTreeSet<String>> {
    let config = RulesConfig::default();
    let input = RuleInput {
        repository_id: "",
        snapshot_id: None,
        modules: &[],
        dependencies,
        config: &config,
        security_patterns: &[],
        architecture: Some(architecture),
    };
    contract::violation_entries(&input)
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
pub(crate) fn specifier_matches(specifier: &str, pattern: &str) -> bool {
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
                SecurityPatternKind::CommandExec => {
                    // A shell-invoking exec (`child_process.exec`/`execSync`)
                    // runs its command through `/bin/sh -c`, so a tainted
                    // argument is shell injection. The rest of the family
                    // (`spawn`, `execFile`) and Rust's `Command::new` exec the
                    // program directly with no shell, so a literal or even a
                    // tainted argument is not shell injection; the sink is worth
                    // a look but not high severity on its own.
                    let shell =
                        matches!(pattern.detail.as_deref(), Some("exec") | Some("execSync"));
                    let severity = if shell {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    (
                        FindingKind::InsecurePattern,
                        severity,
                        "OS command execution",
                    )
                }
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

fn unresolved_import_rule(input: &RuleInput<'_>) -> Vec<FindingRecord> {
    let mut by_site: BTreeMap<(&str, &str), &DependencyRecord> = BTreeMap::new();
    for dependency in input.dependencies {
        if !dependency.is_unresolved()
            || !judged_source(&dependency.source_file_path)
            || !judged_specifier(&dependency.specifier)
        {
            continue;
        }
        by_site
            .entry((
                dependency.source_file_path.as_str(),
                dependency.specifier.as_str(),
            ))
            .and_modify(|first| {
                if dependency.evidence_line < first.evidence_line {
                    *first = dependency;
                }
            })
            .or_insert(dependency);
    }
    by_site
        .into_values()
        .map(|dependency| FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "unresolved-import",
                &dependency.source_file_path,
                &dependency.specifier,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::UnresolvedImport,
            severity: Severity::Medium,
            rule_name: Some("unresolved-import".to_string()),
            target: Some(EntityRef {
                kind: NodeKind::File,
                id: dependency.source_file_path.clone(),
            }),
            title: format!("Unresolved import: {}", dependency.specifier),
            description: format!(
                "'{}' resolves to no file in the repository. The target was renamed or \
                 deleted and this import was not followed; it breaks the build, or the \
                 code path is already dead.",
                dependency.specifier
            ),
            evidence: vec![Evidence {
                file_path: dependency.source_file_path.clone(),
                line: Some(dependency.evidence_line as u32),
                symbol: None,
                detail: Some(dependency.specifier.clone()),
            }],
            created_at: Utc::now(),
        })
        .collect()
}

fn judged_specifier(specifier: &str) -> bool {
    let path = specifier.split('?').next().unwrap_or(specifier);
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => {
            SourceLanguage::from_extension(extension).is_some()
        }
        _ => true,
    }
}

fn judged_source(path: &str) -> bool {
    path.rsplit_once('.')
        .and_then(|(_, extension)| SourceLanguage::from_extension(extension))
        .is_some_and(SourceLanguage::is_js_family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::config::{BannedImportRule, BoundaryRuleConfig};
    use ovecc_core::legacy::{unindexed_module_name, unresolved_module_name};

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
            architecture: None,
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
    fn only_broken_relative_specifiers_are_flagged_as_unresolved() {
        let unresolved = |specifier: &str, line: usize| {
            let mut dependency = dependency("broken", "x", "src/broken.ts", line);
            dependency.specifier = specifier.to_string();
            dependency.target_module = unresolved_module_name(specifier);
            dependency.target_module_id = dependency.target_module.clone();
            dependency.is_external = true;
            dependency
        };
        let mut asset_but_real = unresolved("./theme.css", 9);
        asset_but_real.target_module = unindexed_module_name("./theme.css");

        let deps = vec![
            unresolved("./missing", 6),
            unresolved("../nowhere/deleted.ts", 7),
            asset_but_real,
            unresolved("./icon.svg?url", 11),
            dependency("broken", "helpers", "src/broken.ts", 12),
        ];
        let config = RulesConfig::default();
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: Some("snap"),
            modules: &["broken".to_string()],
            dependencies: &deps,
            config: &config,
            security_patterns: &[],
            architecture: None,
        };

        let findings = evaluate(&input);
        let flagged: Vec<String> = findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::UnresolvedImport)
            .flat_map(|finding| finding.evidence.iter())
            .filter_map(|evidence| evidence.detail.clone())
            .collect();
        assert_eq!(flagged.len(), 2, "{flagged:?}");
        assert!(flagged.contains(&"./missing".to_string()), "{flagged:?}");
        assert!(
            flagged.contains(&"../nowhere/deleted.ts".to_string()),
            "{flagged:?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.severity == Severity::Medium
                    || finding.kind != FindingKind::UnresolvedImport)
        );
    }

    #[test]
    fn asset_and_loader_specifiers_are_not_ovecc_to_judge() {
        assert!(judged_specifier("./missing"));
        assert!(judged_specifier("../nowhere/deleted.ts"));
        assert!(judged_specifier("./widget/index"));
        assert!(!judged_specifier("./theme.css"));
        assert!(!judged_specifier("./icon.svg?url"));
        assert!(!judged_specifier("./data.json"));
        assert!(!judged_specifier("./logo.png?raw"));
    }

    #[test]
    fn only_js_family_sources_are_judged_for_unresolved_imports() {
        assert!(judged_source("src/broken.ts"));
        assert!(judged_source("src/app.tsx"));
        assert!(judged_source("src/legacy.js"));
        // `from . import x` is legal with no file to find in a namespace
        // package, and the suffix resolvers also return nothing when a
        // candidate is merely ambiguous.
        assert!(!judged_source("src/service.py"));
        assert!(!judged_source("src/main.rs"));
        assert!(!judged_source("src/session.cpp"));
        assert!(!judged_source("Makefile"));
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
            architecture: None,
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
            architecture: None,
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
    fn command_exec_severity_follows_shell_invocation() {
        let exec_fact = |detail: &str| SecurityPatternFact {
            kind: SecurityPatternKind::CommandExec,
            line: 1,
            detail: Some(detail.to_string()),
            caller_qualified_name: None,
            in_test_code: false,
        };
        let patterns = vec![
            ("a.ts".to_string(), exec_fact("exec")),
            ("b.ts".to_string(), exec_fact("spawn")),
            ("c.rs".to_string(), exec_fact("Command::new")),
        ];
        let config = RulesConfig::default();
        let input = RuleInput {
            repository_id: "repo:test",
            snapshot_id: None,
            modules: &[],
            dependencies: &[],
            config: &config,
            security_patterns: &patterns,
            architecture: None,
        };
        let by_path = |path: &str| {
            evaluate(&input)
                .into_iter()
                .find(|f| f.evidence[0].file_path == path)
                .unwrap()
                .severity
        };
        // `exec` goes through a shell; `spawn` and Rust's `Command::new` do not.
        assert_eq!(by_path("a.ts"), Severity::High);
        assert_eq!(by_path("b.ts"), Severity::Medium);
        assert_eq!(by_path("c.rs"), Severity::Medium);
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
            architecture: None,
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
            architecture: None,
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
