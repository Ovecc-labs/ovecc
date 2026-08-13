use crate::commands::{
    Comparison,
    architecture::{
        run_architecture_check, run_architecture_diff, run_architecture_init,
        run_architecture_show, run_architecture_suggest, run_architecture_templates,
    },
    capabilities::render_capabilities,
    components::{load_components_report, render_components},
    conventions::{load_conventions_report, render_conventions},
    coupling::{load_coupling, render_coupling},
    diagnose::{
        diagnose_config_for, diagnose_exit, load_advise, load_metrics_report, render_advise,
        render_diagnose, render_metrics, run_diagnose,
    },
    diff::{
        build_gate_report, diff_crosses_threshold, render_diff_report, render_drift_report,
        render_gate,
    },
    dupes::{load_dupes_report, render_dupes},
    findings::{
        DEFAULT_FINDING_LIMIT, build_security_report, filter_changed_since, findings_exit,
        load_audit_report, load_baseline, load_deadcode_report, load_health_report, render_audit,
        render_deadcode, render_fix, render_health, render_security, render_violations,
    },
    history::{render_history, render_history_index},
    index::{render_index_report, render_index_timings, run_init},
    load_config, open_store,
    query::{build_context_slice, load_impact, render_blast, render_explanation, run_query},
    resolve_ref,
    review::{build_review_report, render_full_report, render_review},
    selfcheck::{load_selfcheck, render_selfcheck},
    summary::{load_hotspots, load_summary, render_hotspots, render_summary_report},
};
use crate::render::{SUPPRESS_META, emit_json, meta_for, report_run_stats};
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use ovecc_ai::DeterministicExplainer;
use ovecc_core::config::{ConfigOverrides, OutputFormat, OveccConfig, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::facts::{FindingRecord, Severity};
use ovecc_core::legacy::ImpactDirection;
use ovecc_core::query::Query;
use ovecc_core::traits::ExplanationProvider;
use ovecc_indexer::index_repository;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

#[derive(Debug, Parser)]
#[command(name = "ovecc", version)]
#[command(about = "Deterministic architecture intelligence for repositories")]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    repo: Option<PathBuf>,

    /// Output format (defaults to the configured `output.default_format`).
    #[arg(long, global = true, value_enum)]
    format: Option<FormatArg>,

    /// Print wall-clock and peak-memory stats to stderr after the command.
    /// For `index`, also shows the per-phase breakdown.
    #[arg(long, global = true)]
    stats: bool,

    /// Omit the self-describing `meta` block (metric/rule definitions) from JSON
    /// output. The `capabilities` command still carries the full contract; agents
    /// read it once, so repeating it on every result is redundant. The MCP server
    /// sets this automatically to keep tool results small.
    #[arg(long, global = true)]
    no_meta: bool,

    #[command(subcommand)]
    command: Command,
}

/// CLI-facing mirror of `ovecc_core::config::OutputFormat` (core stays
/// clap-free; same for the other arg enums below).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FormatArg {
    Text,
    Json,
    Ndjson,
    Markdown,
    Sarif,
    Codeclimate,
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Text => OutputFormat::Text,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Ndjson => OutputFormat::Ndjson,
            FormatArg::Markdown => OutputFormat::Markdown,
            FormatArg::Sarif => OutputFormat::Sarif,
            FormatArg::Codeclimate => OutputFormat::Codeclimate,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DirectionArg {
    Downstream,
    Upstream,
    Both,
}

impl From<DirectionArg> for ImpactDirection {
    fn from(value: DirectionArg) -> Self {
        match value {
            DirectionArg::Downstream => ImpactDirection::Downstream,
            DirectionArg::Upstream => ImpactDirection::Upstream,
            DirectionArg::Both => ImpactDirection::Both,
        }
    }
}

/// CI failure threshold for `ovecc diff`.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FailOn {
    /// Fail when the diff risk is Medium or higher.
    Medium,
    /// Fail when the diff risk is High or higher.
    High,
    /// Fail on any architectural change.
    Any,
}

/// Which agent hook to run. Wired into `.claude/settings.json` by
/// `ovecc init --agent`; not meant to be called by hand.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AgentHookKind {
    /// PreToolUse: block a broad text search while the graph can answer it.
    Enforce,
    /// PostToolUse no-op kept for settings wired by earlier versions.
    Mark,
    /// SessionStart: point the agent at the graph.
    Session,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Set up ovecc in a repository: write a commented .ovecc/config.toml,
    /// git-ignore the local state, and print the first commands to run.
    Init {
        /// Overwrite an existing .ovecc/config.toml.
        #[arg(long)]
        force: bool,
        /// Also wire this repo's coding agent (Claude Code hooks) to query the
        /// graph before text search. Writes .claude/settings.json; reversible.
        #[arg(long)]
        agent: bool,
        /// With --agent, remove the wiring instead of adding it.
        #[arg(long, requires = "agent")]
        remove: bool,
    },
    /// Runs one agent hook from a stdin event. Wired by `init --agent`; not
    /// meant to be called by hand.
    #[command(hide = true)]
    AgentHook {
        #[arg(value_enum)]
        kind: AgentHookKind,
    },
    /// Build or update the local architecture database.
    Index {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        /// Skip Git facts for this run.
        #[arg(long)]
        no_git: bool,
        /// Extra glob(s) to exclude, on top of the built-in defaults
        /// (node_modules, .venv, dist, target, ...). Repeatable.
        #[arg(long, value_name = "GLOB")]
        exclude: Vec<String>,
        /// Restrict indexing to these glob(s). Repeatable.
        #[arg(long, value_name = "GLOB")]
        include: Vec<String>,
        /// LCOV tracefile to read line coverage from, relative to the
        /// repository root. Without it, the conventional locations
        /// (`coverage/lcov.info`, `lcov.info`, `coverage.lcov`) are tried and
        /// finding none is not an error.
        #[arg(long, value_name = "PATH")]
        coverage: Option<String>,
    },
    /// List every command, metric, rule, severity, exit code, and format Ovecc
    /// supports — the machine-readable contract for AI agents.
    Capabilities,
    /// Show current architecture health.
    Summary,
    /// Analyze blast radius for a module.
    Impact {
        target: String,
        #[arg(long, value_enum, default_value_t = DirectionArg::Downstream)]
        direction: DirectionArg,
        #[arg(long, default_value_t = 6)]
        max_depth: usize,
    },
    /// Compare two stored architecture snapshots.
    Diff {
        #[arg(default_value = "previous")]
        base: String,
        #[arg(default_value = "latest")]
        head: String,
        /// Exit with code 1 when the diff crosses this threshold.
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
    },
    /// Track architecture drift over time.
    Drift {
        /// Compare against this Git ref or snapshot instead of the previous
        /// snapshot, e.g. `--since main` or `--since v1.0.0`.
        #[arg(long)]
        since: Option<String>,
    },
    /// Report architecture violations.
    Violations {
        /// Only show findings at or above this severity.
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        /// Exit with code 1 when a finding crosses this threshold (CI check).
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Hide findings recorded in `.ovecc/baseline.json` (only new ones).
        #[arg(long)]
        baseline: bool,
        /// Write the current findings to `.ovecc/baseline.json` and exit,
        /// accepting them as the baseline.
        #[arg(long)]
        write_baseline: bool,
        /// Only show findings touching files changed since this Git ref
        /// (progressive adoption: gate the diff, not the backlog).
        #[arg(long, value_name = "REF")]
        changed_since: Option<String>,
        /// Findings to print. 0 prints all of them. Counts, `--fail-on`, and
        /// the SARIF/Code Climate exports always cover the whole set.
        #[arg(long, default_value_t = DEFAULT_FINDING_LIMIT)]
        limit: usize,
        /// Skip this many findings before printing (pages `--limit`).
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Rank technical-debt hotspots.
    Hotspots {
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Learn repository conventions and detect deviations.
    Conventions,
    /// Search the repository from the index: symbol definitions first, then
    /// text matches from an ignore-aware scan, deduplicated and capped. Covers
    /// everything a plain grep covers, in a fraction of the output.
    Grep {
        /// Regex to search for. All-lowercase searches case-insensitively
        /// (smart case); any uppercase makes it exact.
        pattern: String,
        /// Optional paths (files or directories) to scope the text scan.
        #[arg(value_name = "PATH")]
        paths: Vec<String>,
        /// Results to print, applied to the definitions and to the matches
        /// alike. Defaults to 20 definitions and 50 matches; 0 prints all of
        /// them. Totals always cover the whole set.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Read one element instead of a whole file: a symbol's source by name, a
    /// `file:start-end` range, a `file:line` anchor (expands to the enclosing
    /// symbol), or a file's symbol outline.
    Read {
        /// Symbol name, `file:line`, `file:start-end`, or a bare file path.
        target: String,
        /// Maximum lines to print before truncating (0 = no cap).
        #[arg(long, default_value_t = crate::commands::search::DEFAULT_READ_LINES)]
        limit: usize,
    },
    /// Run a structured architecture query.
    Query {
        /// e.g. `"deps Billing"`, `"rdeps table:customers"`, `"billing -> user"`,
        /// `"paths X"`, `"hotspots"`, `"cycles"`.
        query: String,
        /// Hops to traverse. `deps`/`rdeps` are direct (1) by default; `paths`
        /// and `a -> b` follow the graph to depth 3. Use `impact` for a full
        /// blast radius.
        #[arg(long)]
        depth: Option<usize>,
    },
    /// Export deterministic architecture slices.
    Export {
        #[command(subcommand)]
        what: ExportCommand,
    },
    /// Explain an element from its deterministic context slice.
    /// Offline by default — no network or LLM required.
    Explain {
        /// Target to explain, e.g. `Billing`, `table:customers`, `api:GET:/x`.
        target: String,
    },
    /// Surface security findings: hardcoded secrets, insecure patterns, weak
    /// crypto, and tainted source→sink flows, with explicit scanned counts.
    Security {
        /// Only show findings at or above this severity.
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        /// Exit with code 1 when a finding crosses this threshold (CI check).
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
    },
    /// Audit declared dependencies against the offline OSV database.
    Audit {
        /// Exit with code 1 when a finding crosses this threshold (CI check).
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Download the OSV advisories for the discovered packages into
        /// `.ovecc/osv/` first — the ONLY ovecc operation that touches the
        /// network, and only with this flag.
        #[arg(long)]
        fetch: bool,
    },
    /// Produce a one-shot architecture report (summary + cycles + violations +
    /// security + hotspots). Markdown by default; `--format json` for agents.
    Report {
        /// Findings to list, highest severity first. 0 lists all of them; the
        /// counts always cover the whole set.
        #[arg(long, default_value_t = DEFAULT_FINDING_LIMIT)]
        limit: usize,
    },
    /// CI gate: fail when a change introduces new cycles or violations versus a
    /// base snapshot. Models a PR check over Ovecc's `diff`.
    Gate {
        #[arg(default_value = "previous")]
        base: String,
        #[arg(default_value = "latest")]
        head: String,
        /// Fail threshold: `any` new change, or new findings at `medium`/`high`.
        #[arg(long, value_enum, default_value_t = FailOn::Any)]
        fail_on: FailOn,
    },
    /// List the file pairs the history keeps changing together, whether or not
    /// anything in the code connects them.
    Coupling {
        /// Drop pairs where neither file reaches this share of changes to the
        /// other (0.0 keeps every stored pair).
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
        /// Pairs to print, strongest first. 0 prints all of them.
        #[arg(long, default_value_t = DEFAULT_FINDING_LIMIT)]
        limit: usize,
    },
    /// Measure ovecc's own rules against this repository's fix history: does
    /// the code a rule flags get corrected more than the rest?
    Selfcheck,
    /// Detect duplicated code (clone families) over a normalized token stream.
    Dupes {
        /// Minimum shared run, in tokens, to report as a clone. The default
        /// matches PMD CPD's 100; pass 50 for an aggressive scan.
        #[arg(long, default_value_t = 100)]
        min_tokens: usize,
        /// Minimum line span for a clone region.
        #[arg(long, default_value_t = 10)]
        min_lines: usize,
        /// Only report clones spanning at least two files. By default,
        /// same-file duplication is reported too — copy-paste within one
        /// file is still duplication.
        #[arg(long)]
        cross_file_only: bool,
        /// Clone families to print, longest run first. 0 prints all of them;
        /// the counts always cover the whole set.
        #[arg(long, default_value_t = DEFAULT_FINDING_LIMIT)]
        limit: usize,
    },
    /// Report code-health hotspots: functions over the complexity thresholds
    /// (cyclomatic / cognitive), computed by the oxc TS/JS extractor.
    Health,
    /// Report likely dead code: unused exports and unreachable files (from the
    /// oxc-extracted exports + entry-point reachability).
    Deadcode {
        /// Exit with code 1 when a finding crosses this threshold (CI check).
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Only show findings touching files changed since this Git ref
        /// (progressive adoption: gate the diff, not the backlog).
        #[arg(long, value_name = "REF")]
        changed_since: Option<String>,
    },
    /// Apply the mechanical fixes for auto-fixable findings: delete unused
    /// files, drop the `export` keyword on unused exports, remove unused
    /// manifest dependencies. Dry-run by default (prints exactly what would
    /// change); every edit re-verifies the file against the index first.
    Fix {
        /// Write the changes (default is a dry-run preview).
        #[arg(long)]
        apply: bool,
        /// Only fix findings from this rule (e.g. unused-export, unused-file).
        #[arg(long)]
        rule: Option<String>,
        /// Also delete the files nothing reaches. Off by default: a file run by
        /// a command or named in a string is live with no import to prove it.
        #[arg(long)]
        delete_files: bool,
    },
    /// Review what a change introduced: the NAMED new defects between a base and
    /// a head snapshot — new findings (security / dead code / complexity), new
    /// dependency cycles WITH their file-level witness edges, and the
    /// duplications the change added — in one deterministic call. The
    /// change-scoped companion to `gate`, which reports only counts.
    Review {
        #[arg(default_value = "previous")]
        base: String,
        #[arg(default_value = "latest")]
        head: String,
        /// Exit with code 1 when the change crosses this threshold (CI check).
        #[arg(long, value_enum, default_value_t = FailOn::Any)]
        fail_on: FailOn,
    },
    /// Diagnose architectural smells (cycles, hubs, unstable/god components,
    /// dense structure, hotspots), each with evidence, the principle it breaks,
    /// and an established remediation. Deterministic; no patterns are invented.
    Diagnose {
        /// Scope to findings touching this file or module (substring match).
        #[arg(long)]
        target: Option<String>,
        /// Only show findings at or above this severity.
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        /// Group the human (text/markdown) report by family, severity, or component.
        #[arg(long, value_enum)]
        group_by: Option<GroupByArg>,
        /// Exit with code 1 when a finding crosses this threshold (CI check).
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
    },
    /// Advise on one file, module, or symbol: the findings touching it and the
    /// established fix for each. The agent-facing surface — call before editing.
    Advise {
        /// The file, module, or symbol to advise on.
        target: String,
    },
    /// Report per-module architecture metrics: fan-in/out, coupling, Martin
    /// instability, aggregate complexity, and churn, plus repo coupling density.
    Metrics {
        /// Scope to a single file or module (substring match).
        #[arg(long)]
        target: Option<String>,
    },
    /// Recover subsystems from the dependency graph with ACDC's dominance-based
    /// clustering, as a second view beside the directory-derived modules, and
    /// name every module the two views disagree about.
    Components {
        /// Scope to subsystems mentioning this file, module, or name.
        #[arg(long)]
        target: Option<String>,
        /// Largest file count a dominator subsystem may claim.
        #[arg(long, default_value_t = 20)]
        max_size: usize,
        /// In-degree above which a file counts as a support library.
        #[arg(long, default_value_t = 20)]
        support_in_degree: usize,
    },
    /// Trend one snapshot metric over time: per-index values with deltas and a
    /// sparkline ("is the codebase getting worse?"). Without a metric, lists
    /// everything trendable. The data is already persisted at every `ovecc
    /// index`; this renders it.
    History {
        /// Metric to trend (e.g. coupling_density, high_complexity_functions).
        metric: Option<String>,
        /// Keep only the most recent N snapshots.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Architecture contracts: draft `.ovecc/architecture.toml` from the
    /// observed graph, diff the intended architecture against the actual one,
    /// and gate CI on the verdicts.
    Architecture {
        #[command(subcommand)]
        what: ArchitectureCommand,
    },
    /// Run an MCP (Model Context Protocol) server over stdio, exposing Ovecc's
    /// commands as tools for coding agents. Reads/writes JSON-RPC on stdin/stdout.
    Mcp,
}

#[derive(Debug, Subcommand)]
pub enum ArchitectureCommand {
    /// Draft `.ovecc/architecture.toml` from the observed graph. Every
    /// depends_on entry mirrors an import that exists today, so the contract
    /// starts with zero violations; governance is deleting what you regret.
    /// With --template, write a built-in reference architecture instead: the
    /// contract becomes the target and the diff is the migration plan.
    Init {
        /// Overwrite an existing .ovecc/architecture.toml.
        #[arg(long)]
        force: bool,
        /// Start from a named template (see `architecture templates`) instead
        /// of the observed graph. Needs no index.
        #[arg(long, value_name = "NAME")]
        template: Option<String>,
    },
    /// List the built-in architecture templates: reference architectures
    /// distilled from each ecosystem's published canon, shipped in the binary.
    Templates,
    /// Recognize which built-in template the indexed repository most
    /// resembles: a deterministic fit score (coverage x conformance) per
    /// template, the detected root, and the divergences. Needs an index.
    Suggest,
    /// Reflexion report between the contract and the stored graph:
    /// convergences, divergences, interface bypasses, and absences, each with
    /// file:line evidence. Re-reads the contract on every run — editing it
    /// never requires re-indexing.
    Diff,
    /// The contract itself, resolved: which components own the given paths,
    /// what each may import (and through which interface files), what it must
    /// not. Answers "I'm editing this file, what am I allowed to import?"
    /// from the contract alone — no index required.
    Show {
        /// Paths to look up. Without any, the whole contract is shown.
        #[arg(value_name = "PATH")]
        paths: Vec<String>,
    },
    /// The same report as an exit code for CI: exit 1 when a finding crosses
    /// the threshold. In new-violations mode, baselined entries are accepted
    /// debt and the ratchet drops the corrected ones from the store.
    Check {
        /// Fail threshold over the contract findings.
        #[arg(long, value_enum, default_value_t = FailOn::High)]
        fail_on: FailOn,
        /// Accept every current violation into the baseline store
        /// (`.ovecc/architecture/baseline/`), one file per component. The
        /// progressive-adoption entry point: freeze once, gate new
        /// violations from then on.
        #[arg(long)]
        freeze: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    /// Export a compact context slice for an element (for external tools/AI).
    /// Never sends data over the network — just prints the slice.
    Context { target: String },
    /// Export the dependency graph — module and file levels, nodes and edges —
    /// as JSON, or as a self-contained interactive HTML viewer (the renderer
    /// ships inside the binary: no CDN, no runtime dependency, opens offline).
    Graph {
        /// Write the interactive HTML viewer to this path instead of printing
        /// JSON. Without a value, writes `ovecc-graph.html`.
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "ovecc-graph.html")]
        html: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

/// Partition strategy for `diagnose` findings in human reports. (`owner` is
/// intentionally absent until CODEOWNERS ingestion lands.)
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GroupByArg {
    /// Detector family (structural, stability, size, evolutionary).
    Family,
    /// Severity level.
    Severity,
    /// Component (target directory).
    Component,
}

pub fn run() -> Result<u8> {
    let cli = Cli::parse();
    let format_override = cli.format;
    match run_command(cli) {
        Ok(code) => Ok(code),
        Err(err) => {
            print_cli_error(&err, format_override);
            Err(err)
        }
    }
}

/// Renders a command failure to stderr. Under `--format json`/`ndjson` an
/// unresolved target becomes a machine-readable envelope carrying the
/// candidates, so a caller can retry without parsing prose; every other error
/// stays the one-line human message `main` used to print.
fn print_cli_error(err: &anyhow::Error, format: Option<FormatArg>) {
    let structured = matches!(format, Some(FormatArg::Json) | Some(FormatArg::Ndjson));
    if structured
        && let Some(OveccError::UnresolvedTarget {
            input, candidates, ..
        }) = err.downcast_ref::<OveccError>()
    {
        eprintln!("{}", unresolved_target_envelope(input, candidates));
        return;
    }
    eprintln!("ovecc: {err:#}");
}

/// The JSON error envelope for an unresolved target: the named candidates plus a
/// concrete next call, so the agent retries a real target instead of grepping.
fn unresolved_target_envelope(input: &str, candidates: &[(String, String)]) -> String {
    let listed: Vec<serde_json::Value> = candidates
        .iter()
        .map(|(target, kind)| serde_json::json!({"target": target, "kind": kind}))
        .collect();
    let next_call = match candidates.first() {
        Some((target, _)) => format!(
            "retry with a candidate target, e.g. '{target}', or run `ovecc index` if the code changed"
        ),
        None => {
            "run `ovecc index`, then retry with an indexed module name or file path".to_string()
        }
    };
    serde_json::json!({
        "schema_version": 1,
        "error": {
            "kind": "unresolved_target",
            "message": format!("no architecture element matches '{input}'"),
            "input": input,
            "candidates": listed,
            "next_call": next_call,
        }
    })
    .to_string()
}

/// The repo/format resolution the search primitives share; folding it keeps
/// the two dispatch arms from cloning the setup preamble a third time.
fn search_setup(
    repo: Option<PathBuf>,
    format: Option<FormatArg>,
) -> Result<(ProjectPaths, OutputFormat)> {
    let paths = ProjectPaths::resolve(repo.unwrap_or_else(|| PathBuf::from(".")))?;
    let config = load_config(&paths, format)?;
    Ok((paths, config.output.default_format))
}

/// Executes the parsed command. Split from [`run`] so the single error boundary
/// there can render failures format-aware before they reach `main`.
fn run_command(cli: Cli) -> Result<u8> {
    let format_override = cli.format;
    let stats = cli.stats;
    if cli.no_meta {
        SUPPRESS_META.store(true, Ordering::Relaxed);
    }
    let started = std::time::Instant::now();

    let outcome = match cli.command {
        Command::Init {
            force,
            agent,
            remove,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            if agent {
                crate::commands::agent::wire(&paths, remove)
            } else {
                run_init(&paths, force)
            }
        }
        Command::AgentHook { kind } => crate::commands::agent::run_hook(kind),
        Command::Index {
            path,
            no_git,
            exclude,
            include,
            coverage,
        } => {
            let root = path.or(cli.repo).unwrap_or_else(|| PathBuf::from("."));
            let paths = ProjectPaths::resolve(root)?;
            let overrides = ConfigOverrides {
                format: format_override.map(Into::into),
                include: (!include.is_empty()).then_some(include),
                exclude: (!exclude.is_empty()).then_some(exclude),
                coverage,
                ..Default::default()
            };
            let config = OveccConfig::load(&paths.root, &overrides)?;
            let ignore_wired = crate::commands::index::wire_gitignore_for_index(&paths)?;
            let report = index_repository(&paths, &config, no_git)?;
            render_index_report(&report, config.output.default_format)?;
            if config.output.default_format == OutputFormat::Text
                && let Some(message) = ignore_wired
            {
                println!("{message}");
            }
            if stats {
                render_index_timings(&report.timings);
            }
            Ok(0)
        }
        Command::Capabilities => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            render_capabilities(config.output.default_format)?;
            Ok(0)
        }
        Command::Summary => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_summary(&paths)?;
            render_summary_report(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Impact {
            target,
            direction,
            max_depth,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let (result, redirected_from) =
                load_impact(&paths, &target, direction.into(), max_depth)?;
            render_blast(
                &result,
                redirected_from.as_deref(),
                config.output.default_format,
            )?;
            Ok(0)
        }
        Command::Diff {
            base,
            head,
            fail_on,
        } => {
            let compared = Comparison::resolve(cli.repo, format_override, &base, &head)?;
            let report = compared.store.diff(
                compared.paths.repository_id().as_str(),
                &compared.base,
                &compared.head,
            )?;
            render_diff_report(&report, compared.format())?;
            Ok(if diff_crosses_threshold(&report, fail_on) {
                1
            } else {
                0
            })
        }
        Command::Drift { since } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let base = since
                .map(|reference| resolve_ref(&paths.root, &reference))
                .unwrap_or_else(|| "previous".to_string());
            let report = store.drift(paths.repository_id().as_str(), &base, "latest")?;
            render_drift_report(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Violations {
            severity,
            fail_on,
            baseline,
            write_baseline,
            changed_since,
            limit,
            offset,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let mut findings =
                store.findings(&paths.repository_id().0, severity.map(Into::into))?;
            let baseline_path = paths.ovecc_dir.join("baseline.json");

            if write_baseline {
                let ids: Vec<&str> = findings.iter().map(|finding| finding.id.as_str()).collect();
                std::fs::write(&baseline_path, serde_json::to_string_pretty(&ids)?)?;
                println!(
                    "Wrote baseline with {} findings to {}",
                    ids.len(),
                    baseline_path.display()
                );
                return Ok(0);
            }
            if baseline {
                let accepted = load_baseline(&baseline_path);
                findings.retain(|finding| !accepted.contains(finding.id.as_str()));
            }
            if let Some(reference) = &changed_since {
                filter_changed_since(&mut findings, &paths.root, reference)?;
            }

            render_violations(&findings, config.output.default_format, limit, offset)?;
            Ok(findings_exit(&findings, fail_on))
        }
        Command::History { metric, limit } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let repository_id = paths.repository_id().0;
            match metric {
                None => {
                    let names = store.metric_names(&repository_id)?;
                    render_history_index(&names, config.output.default_format)?;
                }
                Some(name) => {
                    let points = store.metric_history(&repository_id, &name, limit)?;
                    if points.is_empty() {
                        return Err(OveccError::Usage {
                            message: format!(
                                "no history for metric '{name}' — run `ovecc history` to list \
                                 the trendable metrics"
                            ),
                        }
                        .into());
                    }
                    render_history(&name, &points, config.output.default_format)?;
                }
            }
            Ok(0)
        }
        Command::Hotspots { limit } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_hotspots(&paths, limit)?;
            render_hotspots(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Conventions => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_conventions_report(&paths)?;
            render_conventions(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Query { query, depth } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let parsed = Query::parse(&query)?;
            run_query(&paths, &parsed, config.output.default_format, depth)
        }
        Command::Grep {
            pattern,
            paths: scope,
            limit,
        } => {
            let (paths, format) = search_setup(cli.repo, format_override)?;
            crate::commands::search::run_grep(&paths, &pattern, &scope, limit, format)
        }
        Command::Read { target, limit } => {
            let (paths, format) = search_setup(cli.repo, format_override)?;
            crate::commands::search::run_read(&paths, &target, limit, format)
        }
        Command::Export {
            what: ExportCommand::Context { target },
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let store = open_store(&paths)?;
            let slice = build_context_slice(&paths, &store, &target)?;
            emit_json("export context", &slice, meta_for("export context"))?;
            Ok(0)
        }
        Command::Export {
            what: ExportCommand::Graph { html },
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let store = open_store(&paths)?;
            let repository_id = paths.repository_id().0;
            let files = store.current_files(&repository_id)?;
            let deps = store.current_dependencies(&repository_id)?;
            let repository = paths
                .root
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "repository".to_string());
            let export = crate::export_graph::build(repository, &files, &deps);
            match html {
                None => emit_json("export graph", &export, meta_for("export graph"))?,
                Some(path) => {
                    let page = crate::export_graph::render_html(&export)?;
                    std::fs::write(&path, &page).map_err(|error| {
                        ovecc_core::error::OveccError::Repository {
                            message: format!("failed to write {}: {error}", path.display()),
                        }
                    })?;
                    let summary = serde_json::json!({
                        "html": path.to_string_lossy(),
                        "bytes": page.len(),
                        "modules": export.modules.nodes.len(),
                        "files": export.files.nodes.len(),
                        "file_edges": export.files.edges.len(),
                    });
                    emit_json("export graph", &summary, meta_for("export graph"))?;
                }
            }
            Ok(0)
        }
        Command::Explain { target } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let slice = build_context_slice(&paths, &store, &target)?;
            let explanation = DeterministicExplainer.explain(&slice)?;
            render_explanation(&slice, &explanation, config.output.default_format)?;
            Ok(0)
        }
        Command::Security { severity, fail_on } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let findings = store.findings(&paths.repository_id().0, None)?;
            let report = build_security_report(&findings, severity.map(Into::into));
            render_security(&report, config.output.default_format)?;
            Ok(findings_exit(&report.findings, fail_on))
        }
        Command::Audit { fail_on, fetch } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_audit_report(&paths, fetch)?;
            render_audit(&report, config.output.default_format)?;
            Ok(findings_exit(&report.findings, fail_on))
        }
        Command::Report { limit } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            render_full_report(&paths, config.output.default_format, limit)?;
            Ok(0)
        }
        Command::Gate {
            base,
            head,
            fail_on,
        } => {
            let compared = Comparison::resolve(cli.repo, format_override, &base, &head)?;
            let report = build_gate_report(
                &compared.paths,
                &compared.store,
                &compared.base,
                &compared.head,
                fail_on,
            )?;
            let failed = report.verdict == "fail";
            render_gate(&report, compared.format())?;
            Ok(u8::from(failed))
        }
        Command::Coupling {
            min_confidence,
            limit,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_coupling(&paths, min_confidence)?;
            render_coupling(&report, config.output.default_format, limit)?;
            Ok(0)
        }
        Command::Selfcheck => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_selfcheck(&paths)?;
            render_selfcheck(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Dupes {
            min_tokens,
            min_lines,
            cross_file_only,
            limit,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report =
                load_dupes_report(&paths, &config, min_tokens, min_lines, cross_file_only)?;
            render_dupes(&report, config.output.default_format, limit)?;
            Ok(0)
        }
        Command::Health => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_health_report(&paths)?;
            render_health(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Deadcode {
            fail_on,
            changed_since,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let report = load_deadcode_report(&paths, changed_since.as_deref())?;
            render_deadcode(&report, config.output.default_format)?;
            Ok(findings_exit(&report.findings, fail_on))
        }
        Command::Fix {
            apply,
            rule,
            delete_files,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let findings: Vec<FindingRecord> = store
                .findings(&paths.repository_id().0, None)?
                .into_iter()
                .filter(|finding| finding.kind.fix_spec().auto_fixable)
                .filter(|finding| {
                    rule.as_deref()
                        .is_none_or(|wanted| finding.rule_name.as_deref() == Some(wanted))
                })
                .collect();
            let report = crate::fix::run(&paths.root, &findings, apply, delete_files);
            render_fix(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Review {
            base,
            head,
            fail_on,
        } => {
            let compared = Comparison::resolve(cli.repo, format_override, &base, &head)?;
            let report = build_review_report(
                &compared.paths,
                &compared.config,
                &compared.store,
                &compared.base,
                &compared.head,
                fail_on,
            )?;
            let failed = report.verdict == "fail";
            render_review(&report, compared.format())?;
            Ok(u8::from(failed))
        }
        Command::Diagnose {
            target,
            severity,
            group_by,
            fail_on,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let diagnose_config = diagnose_config_for(&paths, &config);
            let report = run_diagnose(
                &paths,
                target.as_deref(),
                severity.map(Into::into),
                &diagnose_config,
            )?;
            render_diagnose(&report, config.output.default_format, group_by)?;
            Ok(diagnose_exit(&report, fail_on))
        }
        Command::Advise { target } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let diagnose_config = diagnose_config_for(&paths, &config);
            let (findings, smells) = load_advise(&paths, &diagnose_config, &target)?;
            render_advise(&target, &findings, &smells, config.output.default_format)?;
            Ok(0)
        }
        Command::Metrics { target } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let diagnose_config = diagnose_config_for(&paths, &config);
            let report = load_metrics_report(&paths, &diagnose_config, target.as_deref())?;
            render_metrics(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Components {
            target,
            max_size,
            support_in_degree,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let acdc = ovecc_graph::acdc::AcdcConfig {
                max_subsystem_size: max_size,
                support_in_degree,
            };
            let diagnose_config = diagnose_config_for(&paths, &config);
            let report =
                load_components_report(&paths, &acdc, &diagnose_config, target.as_deref())?;
            render_components(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Architecture { what } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            match what {
                ArchitectureCommand::Init { force, template } => {
                    run_architecture_init(&paths, force, template.as_deref())
                }
                ArchitectureCommand::Templates => {
                    let config = load_config(&paths, format_override)?;
                    run_architecture_templates(config.output.default_format)
                }
                ArchitectureCommand::Suggest => {
                    let config = load_config(&paths, format_override)?;
                    run_architecture_suggest(&paths, config.output.default_format)
                }
                ArchitectureCommand::Diff => {
                    let config = load_config(&paths, format_override)?;
                    run_architecture_diff(&paths, config.output.default_format)
                }
                ArchitectureCommand::Show { paths: query } => {
                    let config = load_config(&paths, format_override)?;
                    run_architecture_show(&paths, config.output.default_format, &query)
                }
                ArchitectureCommand::Check { fail_on, freeze } => {
                    let config = load_config(&paths, format_override)?;
                    run_architecture_check(&paths, config.output.default_format, fail_on, freeze)
                }
            }
        }
        Command::Mcp => {
            let default_repo = cli
                .repo
                .as_deref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".".to_string());
            crate::mcp::serve(&default_repo)
        }
    };

    if stats {
        report_run_stats(started.elapsed());
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_names_candidates_and_a_concrete_next_call() {
        let candidates = vec![
            ("table:customers".to_string(), "table".to_string()),
            ("billing".to_string(), "module".to_string()),
        ];
        let envelope: serde_json::Value =
            serde_json::from_str(&unresolved_target_envelope("custommers", &candidates)).unwrap();
        assert_eq!(envelope["error"]["kind"], "unresolved_target");
        assert_eq!(envelope["error"]["input"], "custommers");
        assert_eq!(
            envelope["error"]["candidates"][0]["target"],
            "table:customers"
        );
        assert_eq!(envelope["error"]["candidates"][0]["kind"], "table");
        // The next call points at the top candidate, not a bare prose hint.
        assert!(
            envelope["error"]["next_call"]
                .as_str()
                .unwrap()
                .contains("table:customers")
        );
    }

    #[test]
    fn envelope_without_candidates_falls_back_to_indexing() {
        let envelope: serde_json::Value =
            serde_json::from_str(&unresolved_target_envelope("zzzz", &[])).unwrap();
        assert_eq!(envelope["error"]["candidates"].as_array().unwrap().len(), 0);
        assert!(
            envelope["error"]["next_call"]
                .as_str()
                .unwrap()
                .contains("ovecc index")
        );
    }
}
