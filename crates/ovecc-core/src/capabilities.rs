// SPDX-License-Identifier: MIT
//! Self-describing capability catalog — the single source of truth for the
//! `ovecc capabilities` command and for the per-command `meta` blocks (the
//! pattern is adapted from fallow's `mcp_manifest` / `Meta`; see
//! THIRD-PARTY-NOTICES.md).
//!
//! This is **language-neutral**: it describes commands, metrics, rules,
//! severities, exit codes, and output formats in terms of Ovecc's neutral fact
//! model, never a specific language. Adding a language must not change anything
//! here.

use crate::report::{MetaMetric, MetaRule};
use serde::Serialize;
use std::collections::BTreeMap;

/// One CLI command, described for machine consumers.
#[derive(Debug, Clone, Serialize)]
pub struct CommandSpec {
    pub name: &'static str,
    pub summary: &'static str,
    /// Notable parameters and flags an agent should know about.
    pub key_params: &'static [&'static str],
    /// One-line description of the JSON `data` payload the command emits.
    pub output: &'static str,
    /// True when the command only reads the database (no index/write).
    pub read_only: bool,
}

/// Every command Ovecc exposes. Ordered for a natural audit flow.
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "index",
        summary: "Build or update the local architecture database from a repository.",
        key_params: &["path", "--no-git", "--exclude <glob>", "--include <glob>"],
        output: "Index report: files/modules/dependencies/symbols/apis/tables counts and parse failures.",
        read_only: false,
    },
    CommandSpec {
        name: "capabilities",
        summary: "List every command, metric, rule, severity, exit code, and format Ovecc supports.",
        key_params: &["--format json"],
        output: "This capability manifest.",
        read_only: true,
    },
    CommandSpec {
        name: "summary",
        summary: "Show current architecture health at a glance.",
        key_params: &[],
        output: "Files/modules/dependencies, circular-dependency count, coupling density, hotspots, risk.",
        read_only: true,
    },
    CommandSpec {
        name: "impact",
        summary: "Analyze the blast radius of a module, symbol, api: or table: target.",
        key_params: &["target", "--direction downstream|upstream|both", "--max-depth"],
        output: "Impacted modules/apis/tables/symbols, representative paths, and a calibrated risk score.",
        read_only: true,
    },
    CommandSpec {
        name: "query",
        summary: "Run a structured architecture query over the persisted graph.",
        key_params: &["deps X", "rdeps X", "paths X", "cycles", "hotspots", "a -> b"],
        output: "Query-shaped result: label lists, cycle/dependency paths, or a relation answer.",
        read_only: true,
    },
    CommandSpec {
        name: "violations",
        summary: "Report architecture and security violations recorded at index time.",
        key_params: &["--severity", "--fail-on medium|high|any", "--baseline", "--write-baseline"],
        output: "Findings with kind, severity, rule, and file:line evidence.",
        read_only: true,
    },
    CommandSpec {
        name: "security",
        summary: "Surface security findings: hardcoded secrets, insecure patterns, weak crypto, and tainted source->sink flows.",
        key_params: &["--severity", "--fail-on medium|high|any"],
        output: "Security findings grouped by category with explicit 'scanned N, found M' counts.",
        read_only: true,
    },
    CommandSpec {
        name: "audit",
        summary: "Audit declared dependencies against the offline OSV database for known vulnerabilities.",
        key_params: &["--fail-on medium|high|any"],
        output: "Vulnerable-dependency findings with package, version, advisory id, and counts scanned.",
        read_only: true,
    },
    CommandSpec {
        name: "hotspots",
        summary: "Rank technical-debt hotspots (churn x coupling x ownership x violations).",
        key_params: &["--limit"],
        output: "Ranked modules with the explainable components of each score; churn/ownership labeled n/a without git.",
        read_only: true,
    },
    CommandSpec {
        name: "dupes",
        summary: "Detect duplicated code (clone families) over a normalized token stream.",
        key_params: &["--min-tokens", "--min-lines", "--include-intra-file"],
        output: "Clone families, each duplicated region as path:start-end, plus scan totals.",
        read_only: true,
    },
    CommandSpec {
        name: "health",
        summary: "Report code-health hotspots: functions over the cyclomatic/cognitive complexity thresholds (oxc TS/JS).",
        key_params: &[],
        output: "High-complexity functions with file:line and their cyclomatic/cognitive scores.",
        read_only: true,
    },
    CommandSpec {
        name: "deadcode",
        summary: "Report likely dead code: unused exports and unreachable files (oxc exports + entry-point reachability).",
        key_params: &["--fail-on medium|high|any"],
        output: "Unused-export and unused-file findings with file:line, plus counts.",
        read_only: true,
    },
    CommandSpec {
        name: "conventions",
        summary: "Learn dominant repository conventions and detect deviations.",
        key_params: &[],
        output: "Learned conventions with confidence, plus deviations.",
        read_only: true,
    },
    CommandSpec {
        name: "diff",
        summary: "Compare two stored architecture snapshots.",
        key_params: &["base", "head", "--fail-on medium|high|any"],
        output: "Added/removed modules and dependencies, and the diff risk.",
        read_only: true,
    },
    CommandSpec {
        name: "drift",
        summary: "Track architecture drift over time between snapshots.",
        key_params: &["--since <ref>"],
        output: "Per-metric base->head deltas and a trend classification.",
        read_only: true,
    },
    CommandSpec {
        name: "gate",
        summary: "CI gate: fail when a change introduces new cycles, violations, or risk above a threshold.",
        key_params: &["--base", "--head", "--fail-on medium|high|any"],
        output: "Gate verdict with the signals (new cycles/violations) that crossed the threshold.",
        read_only: true,
    },
    CommandSpec {
        name: "report",
        summary: "Produce a one-shot architecture report stitching summary, cycles, violations, security, and hotspots.",
        key_params: &["--format markdown|json"],
        output: "A composed report payload (markdown for humans, structured JSON for agents).",
        read_only: true,
    },
    CommandSpec {
        name: "export context",
        summary: "Export a compact deterministic context slice for an element (for external tools/AI).",
        key_params: &["target"],
        output: "Dependencies, dependents, call paths, apis, schemas, and findings for the target.",
        read_only: true,
    },
    CommandSpec {
        name: "explain",
        summary: "Explain an element offline from its deterministic context slice (no network, no LLM required).",
        key_params: &["target"],
        output: "A prose explanation plus the underlying context slice.",
        read_only: true,
    },
];

/// One stable exit code.
#[derive(Debug, Clone, Serialize)]
pub struct ExitCodeSpec {
    pub code: u8,
    pub name: &'static str,
    pub meaning: &'static str,
}

/// The stable exit-code contract (mirrors `error::ExitCode`).
pub const EXIT_CODES: &[ExitCodeSpec] = &[
    ExitCodeSpec { code: 0, name: "success", meaning: "Command succeeded; no gating threshold crossed." },
    ExitCodeSpec { code: 1, name: "findings_present", meaning: "A --fail-on threshold was crossed (findings/cycles/risk)." },
    ExitCodeSpec { code: 2, name: "usage", meaning: "CLI usage error (bad arguments)." },
    ExitCodeSpec { code: 3, name: "repository", meaning: "Repository or configuration error." },
    ExitCodeSpec { code: 4, name: "index", meaning: "Index or database error (e.g. database missing)." },
    ExitCodeSpec { code: 5, name: "parser", meaning: "Parser error." },
    ExitCodeSpec { code: 6, name: "git", meaning: "Git error." },
    ExitCodeSpec { code: 7, name: "internal", meaning: "Unexpected internal error." },
];

/// Output formats every analysis command supports.
pub const FORMATS: &[&str] = &["text", "json", "ndjson", "markdown", "sarif", "codeclimate"];

/// Severity vocabulary shared by rules, findings, and risk mapping.
pub const SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];

/// The full capability manifest emitted by `ovecc capabilities`.
#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    pub commands: &'static [CommandSpec],
    pub formats: &'static [&'static str],
    pub severities: &'static [&'static str],
    pub exit_codes: &'static [ExitCodeSpec],
    pub metrics: BTreeMap<String, MetaMetric>,
    pub rules: BTreeMap<String, MetaRule>,
}

/// Assembles the full capability manifest.
pub fn capabilities() -> Capabilities {
    Capabilities {
        commands: COMMANDS,
        formats: FORMATS,
        severities: SEVERITIES,
        exit_codes: EXIT_CODES,
        metrics: metric_definitions(),
        rules: rule_definitions(),
    }
}

fn metric(description: &str, range: &str, interpretation: &str) -> MetaMetric {
    MetaMetric {
        description: description.to_string(),
        range: Some(range.to_string()),
        interpretation: Some(interpretation.to_string()),
    }
}

/// Definitions of the metrics Ovecc computes and surfaces.
pub fn metric_definitions() -> BTreeMap<String, MetaMetric> {
    BTreeMap::from([
        ("modules".to_string(), metric("Number of inferred or declared modules.", "[0, inf)", "structural size")),
        ("files".to_string(), metric("Number of indexed source files.", "[0, inf)", "structural size")),
        ("dependencies".to_string(), metric("Number of resolved import dependencies.", "[0, inf)", "structural size")),
        ("external_dependencies".to_string(), metric("Dependencies resolving outside the repository.", "[0, inf)", "informational")),
        ("circular_dependencies".to_string(), metric("Number of strongly-connected (cyclic) module components.", "[0, inf)", "lower is better")),
        ("coupling_density".to_string(), metric("Realized module edges over all possible directed edges.", "[0, 1]", "lower is looser coupling")),
        ("symbols".to_string(), metric("Extracted top-level symbols (functions, classes, ...).", "[0, inf)", "structural size")),
        ("calls".to_string(), metric("Resolved call-graph edges.", "[0, inf)", "informational")),
        ("apis".to_string(), metric("Exposed routes, RPC methods, and handlers.", "[0, inf)", "informational")),
        ("tables".to_string(), metric("Database schema objects referenced by code.", "[0, inf)", "informational")),
        ("boundary_violations".to_string(), metric("Findings crossing a declared architecture boundary.", "[0, inf)", "lower is better")),
        ("security_findings".to_string(), metric("Security findings: secrets, insecure patterns, weak crypto, vulnerable deps, tainted flows.", "[0, inf)", "lower is better")),
        ("commits_ingested".to_string(), metric("Git commits ingested this run; 0 means no git history.", "[0, inf)", "0 disables churn/ownership signals")),
        ("functions".to_string(), metric("Functions/methods analyzed for complexity (oxc TS/JS).", "[0, inf)", "informational")),
        ("max_cyclomatic".to_string(), metric("Highest per-function McCabe cyclomatic complexity.", "[1, inf)", "lower is better")),
        ("max_cognitive".to_string(), metric("Highest per-function SonarSource cognitive complexity.", "[0, inf)", "lower is better")),
    ])
}

fn rule(description: &str, severity: &str) -> MetaRule {
    MetaRule {
        description: description.to_string(),
        severity: Some(severity.to_string()),
    }
}

/// Definitions of the built-in finding rules. User-declared boundary rules carry
/// their own configured names and severities.
pub fn rule_definitions() -> BTreeMap<String, MetaRule> {
    BTreeMap::from([
        ("circular-dependency".to_string(), rule("An elementary dependency cycle A -> ... -> A among modules.", "high")),
        ("banned-import".to_string(), rule("An import matches a banned specifier pattern declared in [[rules.banned_imports]].", "configurable")),
        ("complexity".to_string(), rule("A function exceeds the cyclomatic/cognitive complexity thresholds (oxc TS/JS).", "medium/high")),
        ("unused-export".to_string(), rule("An export is reachable but imported by no reachable module (candidate dead code).", "low")),
        ("unused-file".to_string(), rule("A file is reachable from no entry point and imported by nothing.", "low")),
        ("security/secret".to_string(), rule("A hardcoded credential (provider-pattern or high-entropy).", "critical")),
        ("security/eval".to_string(), rule("Dynamic code execution (eval / new Function).", "high")),
        ("security/command-exec".to_string(), rule("OS command execution (exec / spawn).", "high")),
        ("security/weak-hash".to_string(), rule("Obsolete hashing algorithm (MD5 / SHA-1).", "medium")),
        ("security/cors".to_string(), rule("Permissive CORS configuration (origin: \"*\").", "medium")),
        ("taint/writes".to_string(), rule("User-controlled input may reach a database write (injection candidate).", "high")),
        ("taint/reads".to_string(), rule("User-controlled input may reach a database read.", "medium")),
        ("taint/eval".to_string(), rule("User-controlled input may reach dynamic code execution.", "critical")),
        ("taint/command".to_string(), rule("User-controlled input may reach OS command execution.", "critical")),
        ("audit/osv".to_string(), rule("A declared dependency matches a known OSV advisory.", "high")),
    ])
}
