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
        name: "init",
        summary: "Set up ovecc in a repository: write a commented .ovecc/config.toml, git-ignore the local state, and print the first commands to run.",
        key_params: &["--force"],
        output: "The files written and the suggested next commands.",
        read_only: false,
    },
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
        key_params: &[
            "target",
            "--direction downstream|upstream|both",
            "--max-depth",
        ],
        output: "Impacted modules/apis/tables/symbols, representative paths, and a calibrated risk score.",
        read_only: true,
    },
    CommandSpec {
        name: "query",
        summary: "Run a structured architecture query over the persisted graph.",
        key_params: &[
            "deps X", "rdeps X", "paths X", "cycles", "hotspots", "a -> b",
        ],
        output: "Query-shaped result: label lists, cycle/dependency paths, or a relation answer.",
        read_only: true,
    },
    CommandSpec {
        name: "grep",
        summary: "Search the repository from the index: symbol definitions first, then text matches from an ignore-aware scan, deduplicated and capped.",
        key_params: &["pattern", "path", "--limit"],
        output: "Matching definitions with file:line spans, then path:line: text matches with totals.",
        read_only: true,
    },
    CommandSpec {
        name: "read",
        summary: "Read one element instead of a whole file: a symbol's source by name, a file:start-end slice, a file:line anchor, or a file's symbol outline.",
        key_params: &["target", "--limit"],
        output: "A line-numbered source slice with a file:line header, or a symbol outline.",
        read_only: true,
    },
    CommandSpec {
        name: "violations",
        summary: "Report architecture and security violations recorded at index time.",
        key_params: &[
            "--severity",
            "--fail-on medium|high|any",
            "--baseline",
            "--write-baseline",
            "--changed-since <ref>",
        ],
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
        summary: "Audit declared dependencies against the offline OSV database for known vulnerabilities. `--fetch` first downloads the advisories for the discovered packages (the only networked operation, opt-in).",
        key_params: &["--fail-on medium|high|any", "--fetch (network, opt-in)"],
        output: "Vulnerable-dependency findings with package, version, advisory id, and counts scanned.",
        read_only: true,
    },
    CommandSpec {
        name: "hotspots",
        summary: "Rank technical-debt hotspots (churn x coupling x ownership x violations).",
        key_params: &["--limit"],
        output: "Ranked modules with the explainable components of each score, plus the bug-fix commits each carries (count, age-weighted mass, last one) beside it; churn/ownership labeled n/a without git.",
        read_only: true,
    },
    CommandSpec {
        name: "coupling",
        summary: "List the file pairs the history keeps changing together (evolutionary coupling).",
        key_params: &["--min-confidence", "--limit"],
        output: "File pairs with commits-together, Jaccard, lift, both directed confidences, and witness commit shas; empty without git history.",
        read_only: true,
    },
    CommandSpec {
        name: "selfcheck",
        summary: "Measure each rule's findings against the repository's own fix history.",
        key_params: &[],
        output: "Per rule: files flagged, fix mass they carry, fixes per KB, and the lift over the repository's base rate; empty without git history.",
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
        key_params: &["--fail-on medium|high|any", "--changed-since <ref>"],
        output: "Unused-export and unused-file findings with file:line, plus counts.",
        read_only: true,
    },
    CommandSpec {
        name: "fix",
        summary: "Apply the mechanical fixes for auto-fixable findings: delete unused files, drop the export keyword on unused exports, remove unused manifest dependencies. Dry-run by default; every edit re-verifies the file against the index and skips stale entries.",
        key_params: &["--apply", "--rule <rule>"],
        output: "Per-action plan/result: fix kind, file:line, change preview or skip reason, and applied/skipped counts.",
        read_only: false,
    },
    CommandSpec {
        name: "diagnose",
        summary: "Diagnose architectural smells (cycles, hub-like/crossing, unstable & god components, dense structure, hotspots) at component (directory) granularity.",
        key_params: &["--target", "--severity", "--fail-on medium|high|any"],
        output: "Ranked findings: detector, target component, file:line/metric evidence, the principle broken, severity, deterministic confidence, and language-aware remediation.",
        read_only: true,
    },
    CommandSpec {
        name: "advise",
        summary: "Advise on one file, module, or component: the findings touching it and the established fix for each. The agent surface — call before editing.",
        key_params: &["target"],
        output: "The diagnose findings scoped to the target, each with its remediation.",
        read_only: true,
    },
    CommandSpec {
        name: "metrics",
        summary: "Per-component architecture metrics: fan-in/out, coupling, Martin instability, aggregate complexity, churn, and repository coupling density.",
        key_params: &["--target"],
        output: "Component metrics rows plus the repository coupling density.",
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
        name: "history",
        summary: "Trend one snapshot metric across every index run: values, deltas, and a sparkline. Without a metric, lists everything trendable.",
        key_params: &["metric", "--limit <n>"],
        output: "Per-snapshot points (when, commit, value, delta), first->last change, sparkline.",
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
        name: "review",
        summary: "Review what a change introduced: the NAMED new defects between two snapshots (the actionable companion to gate, which reports only counts).",
        key_params: &["base", "head", "--fail-on medium|high|any"],
        output: "New findings (with file:line), new dependency cycles WITH their import witness edges, change-scoped duplications, a verdict, and a rationale.",
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
        name: "export graph",
        summary: "Export the dependency graph (module + file levels) as JSON, or as a self-contained offline HTML viewer via --html.",
        key_params: &["--html"],
        output: "Sorted nodes and edges per level; with --html, the path of the written viewer file.",
        read_only: true,
    },
    CommandSpec {
        name: "explain",
        summary: "Explain an element offline from its deterministic context slice (no network, no LLM required).",
        key_params: &["target"],
        output: "A prose explanation plus the underlying context slice.",
        read_only: true,
    },
    CommandSpec {
        name: "architecture init",
        summary: "Draft .ovecc/architecture.toml from the observed graph: every depends_on entry mirrors an existing import, so the contract starts with zero violations. With --template, write a built-in reference architecture instead (needs no index); the diff then reports the migration gap.",
        key_params: &["--force", "--template <name>"],
        output: "The contract file written, with component and declared-dependency counts.",
        read_only: false,
    },
    CommandSpec {
        name: "architecture templates",
        summary: "List the built-in architecture templates: reference architectures distilled from each ecosystem's published canon, shipped in the binary.",
        key_params: &[],
        output: "Template names with summary, target stacks, and canonical source.",
        read_only: true,
    },
    CommandSpec {
        name: "architecture suggest",
        summary: "Recognize which built-in template the indexed repository most resembles: a deterministic fit score (coverage x conformance) per template, the detected root, and the divergent edges. Recognition against a curated basket of archetypes, not architecture recovery.",
        key_params: &[],
        output: "Ranked template fits (score, root, coverage, conformance) and the best match above the recognition threshold.",
        read_only: true,
    },
    CommandSpec {
        name: "architecture show",
        summary: "The contract resolved for given paths: owning components, what each may import (and through which interface files), what it must not. Answers the pre-edit question from the contract alone — no index required.",
        key_params: &["paths"],
        output: "Components with may_import (target interfaces included), interface, and external_deny.",
        read_only: true,
    },
    CommandSpec {
        name: "architecture diff",
        summary: "Reflexion report between the contract and the stored graph: convergences, divergences, interface bypasses, and absences with file:line evidence. Re-reads the contract on every run.",
        key_params: &["--format json|markdown"],
        output: "Declared edges with observed occurrence counts, plus the contract findings.",
        read_only: true,
    },
    CommandSpec {
        name: "architecture check",
        summary: "The architecture diff as a CI gate: exit 1 when a contract finding crosses the threshold. --freeze accepts the current violations into the baseline store (.ovecc/architecture/baseline/, one file per component); in new-violations mode baselined entries stop gating and the ratchet drops corrected ones.",
        key_params: &["--fail-on medium|high|any", "--freeze"],
        output: "The same report as architecture diff; the verdict is the exit code.",
        read_only: false,
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
    ExitCodeSpec {
        code: 0,
        name: "success",
        meaning: "Command succeeded; no gating threshold crossed.",
    },
    ExitCodeSpec {
        code: 1,
        name: "findings_present",
        meaning: "A --fail-on threshold was crossed (findings/cycles/risk).",
    },
    ExitCodeSpec {
        code: 2,
        name: "usage",
        meaning: "CLI usage error (bad arguments).",
    },
    ExitCodeSpec {
        code: 3,
        name: "repository",
        meaning: "Repository or configuration error.",
    },
    ExitCodeSpec {
        code: 4,
        name: "index",
        meaning: "Index or database error (e.g. database missing).",
    },
    ExitCodeSpec {
        code: 5,
        name: "parser",
        meaning: "Parser error.",
    },
    ExitCodeSpec {
        code: 6,
        name: "git",
        meaning: "Git error.",
    },
    ExitCodeSpec {
        code: 7,
        name: "internal",
        meaning: "Unexpected internal error.",
    },
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
        (
            "modules".to_string(),
            metric(
                "Number of inferred or declared modules.",
                "[0, inf)",
                "structural size",
            ),
        ),
        (
            "files".to_string(),
            metric(
                "Number of indexed source files.",
                "[0, inf)",
                "structural size",
            ),
        ),
        (
            "parse_failures".to_string(),
            metric(
                "Files found but not indexed; every other metric covers the rest.",
                "[0, inf)",
                "lower is better",
            ),
        ),
        (
            "dependencies".to_string(),
            metric(
                "Number of resolved import dependencies.",
                "[0, inf)",
                "structural size",
            ),
        ),
        (
            "external_dependencies".to_string(),
            metric(
                "Dependencies resolving outside the repository.",
                "[0, inf)",
                "informational",
            ),
        ),
        (
            "circular_dependencies".to_string(),
            metric(
                "Strongly-connected (cyclic) module components, over runtime imports \
                 only — `import type` is erased before load and never witnesses a \
                 cycle. One component can hold several elementary loops, so this sits \
                 at or below the loop count `query cycles` lists.",
                "[0, inf)",
                "lower is better",
            ),
        ),
        (
            "coupling_density".to_string(),
            metric(
                "Realized module edges over all possible directed edges.",
                "[0, 1]",
                "lower is looser coupling",
            ),
        ),
        (
            "symbols".to_string(),
            metric(
                "Extracted top-level symbols (functions, classes, ...).",
                "[0, inf)",
                "structural size",
            ),
        ),
        (
            "calls".to_string(),
            metric("Resolved call-graph edges.", "[0, inf)", "informational"),
        ),
        (
            "apis".to_string(),
            metric(
                "Exposed routes, RPC methods, and handlers.",
                "[0, inf)",
                "informational",
            ),
        ),
        (
            "tables".to_string(),
            metric(
                "Database schema objects referenced by code.",
                "[0, inf)",
                "informational",
            ),
        ),
        (
            "boundary_violations".to_string(),
            metric(
                "Findings crossing a declared architecture boundary.",
                "[0, inf)",
                "lower is better",
            ),
        ),
        (
            "security_findings".to_string(),
            metric(
                "Code security findings: secrets, insecure patterns, weak crypto, tainted flows. Dependency advisories are tracked separately.",
                "[0, inf)",
                "lower is better",
            ),
        ),
        (
            "dependency_advisories".to_string(),
            metric(
                "Known vulnerabilities (OSV) in dependencies; depends on when advisories were last fetched.",
                "[0, inf)",
                "lower is better",
            ),
        ),
        (
            "commits_ingested".to_string(),
            metric(
                "Git commits ingested this run; 0 means no git history.",
                "[0, inf)",
                "0 disables churn/ownership signals",
            ),
        ),
        (
            "functions".to_string(),
            metric(
                "Functions/methods analyzed for complexity (oxc TS/JS).",
                "[0, inf)",
                "informational",
            ),
        ),
        (
            "max_cyclomatic".to_string(),
            metric(
                "Highest per-function McCabe cyclomatic complexity.",
                "[1, inf)",
                "lower is better",
            ),
        ),
        (
            "max_cognitive".to_string(),
            metric(
                "Highest per-function SonarSource cognitive complexity.",
                "[0, inf)",
                "lower is better",
            ),
        ),
        (
            "code_smells".to_string(),
            metric(
                "Structural code-smell findings: feature envy, large classes, data clumps.",
                "[0, inf)",
                "lower is better",
            ),
        ),
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
        (
            "circular-dependency".to_string(),
            rule(
                "An elementary dependency cycle A -> ... -> A among modules.",
                "high",
            ),
        ),
        (
            "banned-import".to_string(),
            rule(
                "An import matches a banned specifier pattern declared in [[rules.banned_imports]].",
                "configurable",
            ),
        ),
        (
            "unresolved-import".to_string(),
            rule(
                "An import names a path inside the repository that resolves to no \
                 file. Asset and loader-query specifiers are excluded: a bundler \
                 rule, not ovecc, resolves those.",
                "medium",
            ),
        ),
        (
            "architecture/divergence".to_string(),
            rule(
                "A component imports another that its .ovecc/architecture.toml \
                 depends_on does not declare.",
                "high",
            ),
        ),
        (
            "architecture/interface-bypass".to_string(),
            rule(
                "A component imports another component's internals instead of its \
                 declared interface file(s).",
                "high",
            ),
        ),
        (
            "architecture/slice-isolation".to_string(),
            rule(
                "Two slices of a `slices = true` component import each other \
                 (the @x public-API exception aside).",
                "high",
            ),
        ),
        (
            "architecture/capability".to_string(),
            rule(
                "A component uses an ambient capability (network, filesystem, \
                 storage, dom, process, time, random) its contract denies.",
                "medium",
            ),
        ),
        (
            "architecture/complexity-budget".to_string(),
            rule(
                "A function exceeds the component's per-function \
                 cyclomatic/cognitive budget (an architectural fitness function).",
                "medium",
            ),
        ),
        (
            "architecture/coverage-floor".to_string(),
            rule(
                "A component's line coverage is under the `min_coverage` it \
                 declares. Silent when no tracefile was indexed.",
                "medium",
            ),
        ),
        (
            "architecture/deprecated-use".to_string(),
            rule(
                "A dependency the contract marks deprecated is still imported.",
                "medium",
            ),
        ),
        (
            "architecture/external-deny".to_string(),
            rule(
                "A component imports an external package its contract denies.",
                "medium",
            ),
        ),
        (
            "architecture/absence".to_string(),
            rule(
                "A declared depends_on edge no import implements (contract hygiene, \
                 never gates).",
                "low",
            ),
        ),
        (
            "architecture/behavioral-coupling".to_string(),
            rule(
                "Two components the contract declares independent, and no import \
                 connects, that the history keeps changing in the same commits. \
                 Advisory: the evidence is the commits, the call is the reader's. \
                 Raise or silence it with `coupling` in the contract.",
                "low",
            ),
        ),
        (
            "architecture/unassigned".to_string(),
            rule(
                "Indexed files match no component's paths, per the contract's \
                 unassigned policy.",
                "low/high",
            ),
        ),
        (
            "complexity".to_string(),
            rule(
                "A function exceeds the cyclomatic/cognitive complexity thresholds (oxc TS/JS).",
                "medium/high",
            ),
        ),
        (
            "unused-export".to_string(),
            rule(
                "An export is reachable but imported by no reachable module (candidate dead code).",
                "low",
            ),
        ),
        (
            "unused-file".to_string(),
            rule(
                "A file is reachable from no entry point and imported by nothing.",
                "low",
            ),
        ),
        (
            "unused-type".to_string(),
            rule(
                "A type-only export (interface/type alias) never imported by a reachable module.",
                "low",
            ),
        ),
        (
            "unused-dependency".to_string(),
            rule(
                "A manifest dependency never imported by an indexed file (opt-in: [index] detect_unused_deps).",
                "low",
            ),
        ),
        (
            "unlisted-dependency".to_string(),
            rule(
                "An imported package missing from every package.json — a phantom dependency.",
                "medium",
            ),
        ),
        (
            "stale-suppression".to_string(),
            rule(
                "An ovecc-ignore comment that suppresses no finding; it will silently swallow the next real finding on its line.",
                "low",
            ),
        ),
        (
            "unused-dev-dependency".to_string(),
            rule(
                "A devDependency never imported, invoked by a script, or config-loaded (opt-in: [index] detect_unused_deps).",
                "low",
            ),
        ),
        (
            "unused-optional-dependency".to_string(),
            rule(
                "An optionalDependency never imported or invoked by a script (opt-in: [index] detect_unused_deps).",
                "low",
            ),
        ),
        (
            "long-function".to_string(),
            rule(
                "A function whose source-line count exceeds the unit-size thresholds (75 low / 150 medium).",
                "low/medium",
            ),
        ),
        (
            "long-parameter-list".to_string(),
            rule(
                "A function with too many parameters (7 low / 10 medium).",
                "low/medium",
            ),
        ),
        (
            "feature-envy".to_string(),
            rule(
                "A function whose resolved calls predominantly target one other module \
                 (>= 5 calls, >= 3x its own-module calls, >= half of all its resolved calls).",
                "low/medium",
            ),
        ),
        (
            "large-class".to_string(),
            rule(
                "A class/struct/enum with too many methods in one file (20 low / 30 medium).",
                "low/medium",
            ),
        ),
        (
            "data-clumps".to_string(),
            rule(
                "The same group of >= 3 parameter names recurs across >= 3 functions; \
                 the group wants to be a parameter object.",
                "low/medium",
            ),
        ),
        (
            "security/secret".to_string(),
            rule(
                "A hardcoded credential (provider-pattern or high-entropy).",
                "critical",
            ),
        ),
        (
            "security/eval".to_string(),
            rule("Dynamic code execution (eval / new Function).", "high"),
        ),
        (
            "security/command-exec".to_string(),
            rule("OS command execution (exec / spawn).", "high"),
        ),
        (
            "security/weak-hash".to_string(),
            rule("Obsolete hashing algorithm (MD5 / SHA-1).", "medium"),
        ),
        (
            "security/cors".to_string(),
            rule("Permissive CORS configuration (origin: \"*\").", "medium"),
        ),
        (
            "taint/writes".to_string(),
            rule(
                "User-controlled input may reach a database write (injection candidate).",
                "high",
            ),
        ),
        (
            "taint/reads".to_string(),
            rule("User-controlled input may reach a database read.", "medium"),
        ),
        (
            "taint/eval".to_string(),
            rule(
                "User-controlled input may reach dynamic code execution.",
                "critical",
            ),
        ),
        (
            "taint/command".to_string(),
            rule(
                "User-controlled input may reach OS command execution.",
                "critical",
            ),
        ),
        (
            "audit/osv".to_string(),
            rule(
                "A declared dependency matches a known OSV advisory.",
                "high",
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExitCode;
    use std::collections::HashSet;

    #[test]
    fn command_names_are_unique_and_nonempty() {
        assert!(!COMMANDS.is_empty());
        let mut seen = HashSet::new();
        for c in COMMANDS {
            assert!(seen.insert(c.name), "duplicate command name: {}", c.name);
        }
    }

    #[test]
    fn exit_code_table_mirrors_the_error_enum_contract() {
        // EXIT_CODES (the machine contract) and error::ExitCode (the runtime
        // enum) are two sources of truth for one contract; lock them together
        // so they cannot silently drift apart.
        assert_eq!(EXIT_CODES.len(), 8);
        let pairs = [
            (ExitCode::Success, "success"),
            (ExitCode::FindingsPresent, "findings_present"),
            (ExitCode::Usage, "usage"),
            (ExitCode::Repository, "repository"),
            (ExitCode::Index, "index"),
            (ExitCode::Parser, "parser"),
            (ExitCode::Git, "git"),
            (ExitCode::Internal, "internal"),
        ];
        for (code, name) in pairs {
            let spec = EXIT_CODES
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("missing exit code {name}"));
            assert_eq!(spec.code, code.code(), "code mismatch for {name}");
        }
    }

    #[test]
    fn severity_vocabulary_matches_the_typed_enum() {
        assert_eq!(SEVERITIES, &["low", "medium", "high", "critical"]);
        // Each label must round-trip through the typed Severity enum.
        for s in SEVERITIES {
            let parsed: crate::facts::Severity = serde_json::from_str(&format!("\"{s}\"")).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), format!("\"{s}\""));
        }
    }

    #[test]
    fn manifest_carries_metrics_rules_and_formats() {
        let caps = capabilities();
        assert!(!caps.metrics.is_empty());
        assert!(!caps.rules.is_empty());
        assert!(caps.formats.contains(&"json"));
        assert!(caps.severities.contains(&"critical"));
    }
}
