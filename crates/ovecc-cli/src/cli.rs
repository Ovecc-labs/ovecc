use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use ovecc_ai::DeterministicExplainer;
use ovecc_core::capabilities;
use ovecc_core::config::{ConfigOverrides, OutputFormat, OveccConfig, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::facts::{FindingKind, FindingRecord, Severity};
use ovecc_core::legacy::{
    ConventionsReport, DependencyEdge, DiffReport, DriftReport, HotspotsReport, ImpactDirection,
    IndexReport, RiskLevel, SummaryReport,
};
use ovecc_core::query::{Query, TargetSelector};
use ovecc_core::report::{ChangedFiles, ContextSlice, Envelope, Meta, ToolInfo};
use ovecc_core::traits::ExplanationProvider;
use ovecc_db::ArchitectureStore;
use ovecc_graph as graph;
use ovecc_graph::blast::{self, BlastEdge, BlastNode, BlastResult};
use ovecc_indexer::index_repository;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the global `--no-meta` flag. When true, [`meta_for`] returns an empty
/// `Meta`, so the self-describing metric/rule dictionaries are omitted from every
/// command's JSON. The MCP server sets this on every tool call: the agent reads
/// the dictionaries once via `capabilities`, so repeating them on every result
/// only inflates tokens (roughly halving MCP tool-result size in practice).
static SUPPRESS_META: AtomicBool = AtomicBool::new(false);

/// Prints `data` wrapped in the stable, self-describing JSON envelope
/// (schema_version + tool + command + meta). The `data` payload is
/// byte-identical across runs for identical inputs.
fn emit_json<T: serde::Serialize + ?Sized>(command: &str, data: &T, meta: Meta) -> Result<()> {
    let envelope = Envelope::new(command, data, meta);
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

/// Prints the NDJSON envelope header line carrying the schema_version, tool, and
/// command, so an NDJSON stream is self-describing without buffering.
fn emit_ndjson_meta(command: &str, meta: &Meta) -> Result<()> {
    let header = serde_json::json!({
        "type": "meta",
        "schema_version": ovecc_core::report::SCHEMA_VERSION,
        "tool": ToolInfo::default(),
        "command": command,
        "meta": meta,
    });
    println!("{}", serde_json::to_string(&header)?);
    Ok(())
}

/// Builds the `meta` block for a command from the capability catalog: the
/// metric and/or rule dictionaries relevant to it, so an agent can interpret the
/// payload without the docs site. Static and therefore deterministic.
fn meta_for(command: &str) -> Meta {
    if SUPPRESS_META.load(Ordering::Relaxed) {
        return Meta::default();
    }
    let mut meta = Meta::default();
    if matches!(
        command,
        "summary" | "report" | "drift" | "diff" | "hotspots" | "index" | "health" | "review"
    ) {
        meta.metrics = capabilities::metric_definitions();
    }
    if matches!(
        command,
        "violations"
            | "security"
            | "audit"
            | "gate"
            | "report"
            | "summary"
            | "health"
            | "deadcode"
            | "review"
    ) {
        meta.rules = capabilities::rule_definitions();
    }
    meta
}

#[derive(Debug, Parser)]
#[command(name = "ovecc")]
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
/// clap-free).
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

/// CLI-facing mirror of `legacy::ImpactDirection`.
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

#[derive(Debug, Subcommand)]
pub enum Command {
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
    },
    /// Rank technical-debt hotspots.
    Hotspots {
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Learn repository conventions and detect deviations.
    Conventions,
    /// Run a structured architecture query.
    Query {
        /// e.g. `"deps Billing"`, `"rdeps table:customers"`, `"billing -> user"`,
        /// `"paths X"`, `"hotspots"`, `"cycles"`.
        query: String,
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
    },
    /// Produce a one-shot architecture report (summary + cycles + violations +
    /// security + hotspots). Markdown by default; `--format json` for agents.
    Report,
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
    /// Detect duplicated code (clone families) over a normalized token stream.
    Dupes {
        /// Minimum shared run, in tokens, to report as a clone.
        #[arg(long, default_value_t = 50)]
        min_tokens: usize,
        /// Minimum line span for a clone region.
        #[arg(long, default_value_t = 5)]
        min_lines: usize,
        /// Also report clones confined to a single file (off by default).
        #[arg(long)]
        include_intra_file: bool,
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
    /// Run an MCP (Model Context Protocol) server over stdio, exposing Ovecc's
    /// commands as tools for coding agents. Reads/writes JSON-RPC on stdin/stdout.
    Mcp,
}

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    /// Export a compact context slice for an element (for external tools/AI).
    /// Never sends data over the network — just prints the slice.
    Context { target: String },
}

/// CLI-facing mirror of `ovecc_core::facts::Severity`.
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

/// How to partition `diagnose` findings in the human (text/markdown) output.
/// (`owner` is intentionally absent until CODEOWNERS ingestion lands.)
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum GroupByArg {
    /// Detector family: structural / stability / size / evolutionary.
    Family,
    /// Severity bucket.
    Severity,
    /// The finding's component (target directory).
    Component,
}

pub fn run() -> Result<u8> {
    let cli = Cli::parse();
    let format_override = cli.format;
    let stats = cli.stats;
    if cli.no_meta {
        SUPPRESS_META.store(true, Ordering::Relaxed);
    }
    let started = std::time::Instant::now();

    let outcome = match cli.command {
        Command::Index {
            path,
            no_git,
            exclude,
            include,
        } => {
            let root = path.or(cli.repo).unwrap_or_else(|| PathBuf::from("."));
            let paths = ProjectPaths::resolve(root)?;
            let overrides = ConfigOverrides {
                format: format_override.map(Into::into),
                include: (!include.is_empty()).then_some(include),
                exclude: (!exclude.is_empty()).then_some(exclude),
                ..Default::default()
            };
            let config = OveccConfig::load(&paths.root, &overrides)?;
            let report = index_repository(&paths, &config, no_git)?;
            render_index_report(&report, config.output.default_format)?;
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
            let result = load_impact(&paths, &target, direction.into(), max_depth)?;
            render_blast(&target, result.as_ref(), config.output.default_format)?;
            Ok(0)
        }
        Command::Diff {
            base,
            head,
            fail_on,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let base = resolve_ref(&paths.root, &base);
            let head = resolve_ref(&paths.root, &head);
            let report = store.diff(paths.repository_id().as_str(), &base, &head)?;
            render_diff_report(&report, config.output.default_format)?;
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

            render_violations(&findings, config.output.default_format)?;
            Ok(findings_exit(&findings, fail_on))
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
            let store = open_store(&paths)?;
            let repository_id = paths.repository_id().0;
            let file_dependencies: Vec<(String, String)> = store
                .current_dependencies(&repository_id)?
                .into_iter()
                .filter(|dependency| !dependency.is_external)
                .filter_map(|dependency| {
                    dependency
                        .target_file_path
                        .map(|target| (dependency.source_file_path, target))
                })
                .collect();
            let db_files = store.db_accessing_files(&repository_id)?;
            let report = ovecc_graph::conventions::learn_conventions(&file_dependencies, &db_files);
            render_conventions(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Query { query } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let parsed = Query::parse(&query)?;
            run_query(&paths, &parsed, config.output.default_format)
        }
        Command::Export {
            what: ExportCommand::Context { target },
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let store = open_store(&paths)?;
            let slice = build_context_slice(&paths, &store, &target)?;
            println!("{}", serde_json::to_string_pretty(&slice)?);
            Ok(0)
        }
        Command::Explain { target } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let slice = build_context_slice(&paths, &store, &target)?;
            // Deterministic, offline explanation: the slice is the only
            // input, assembled locally and sent nowhere.
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
        Command::Audit { fail_on } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let packages = ovecc_audit::discover_packages(&paths.root);
            let osv = ovecc_audit::load_osv_dir(&paths.ovecc_dir.join("osv"));
            let findings = ovecc_audit::audit(&paths.repository_id().0, None, &packages, &osv);
            let report = AuditReport {
                packages_scanned: packages.len(),
                advisories_loaded: osv.len(),
                vulnerabilities: findings.len(),
                findings,
            };
            render_audit(&report, config.output.default_format)?;
            Ok(findings_exit(&report.findings, fail_on))
        }
        Command::Report => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            render_full_report(&paths, config.output.default_format)?;
            Ok(0)
        }
        Command::Gate {
            base,
            head,
            fail_on,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let base = resolve_ref(&paths.root, &base);
            let head = resolve_ref(&paths.root, &head);
            let report =
                build_gate_report(&store, &paths.repository_id().0, &base, &head, fail_on)?;
            let failed = report.verdict == "fail";
            render_gate(&report, config.output.default_format)?;
            Ok(u8::from(failed))
        }
        Command::Dupes {
            min_tokens,
            min_lines,
            include_intra_file,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let files = ovecc_indexer::collect_file_tokens(&paths, &config)?;
            let families =
                ovecc_graph::dupes::detect(&files, min_tokens, min_lines, !include_intra_file);
            let duplicated_lines: u32 = families.iter().map(|family| family.line_span).sum();
            let report = DupesReport {
                files_scanned: files.len(),
                min_tokens,
                min_lines,
                clone_families: families.len(),
                duplicated_lines,
                families,
            };
            render_dupes(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Health => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let mut findings: Vec<FindingRecord> = store
                .findings(&paths.repository_id().0, None)?
                .into_iter()
                .filter(|finding| finding.kind == FindingKind::HighComplexity)
                .collect();
            findings.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(|| a.title.cmp(&b.title))
            });
            let report = HealthReport {
                high_complexity_functions: findings.len(),
                findings,
            };
            render_health(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Deadcode { fail_on } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let findings: Vec<FindingRecord> = store
                .findings(&paths.repository_id().0, None)?
                .into_iter()
                .filter(|finding| {
                    matches!(
                        finding.kind,
                        FindingKind::UnusedExport
                            | FindingKind::UnusedFile
                            | FindingKind::UnusedDependency
                    )
                })
                .collect();
            let report = DeadcodeReport {
                unused_exports: findings
                    .iter()
                    .filter(|f| f.kind == FindingKind::UnusedExport)
                    .count(),
                unused_files: findings
                    .iter()
                    .filter(|f| f.kind == FindingKind::UnusedFile)
                    .count(),
                unused_dependencies: findings
                    .iter()
                    .filter(|f| f.kind == FindingKind::UnusedDependency)
                    .count(),
                findings,
            };
            render_deadcode(&report, config.output.default_format)?;
            Ok(findings_exit(&report.findings, fail_on))
        }
        Command::Review {
            base,
            head,
            fail_on,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let store = open_store(&paths)?;
            let base = resolve_ref(&paths.root, &base);
            let head = resolve_ref(&paths.root, &head);
            let report = build_review_report(&paths, &config, &store, &base, &head, fail_on)?;
            let failed = report.verdict == "fail";
            render_review(&report, config.output.default_format)?;
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
            let report = run_diagnose(
                &paths,
                target.as_deref(),
                severity.map(Into::into),
                &config.diagnose,
            )?;
            render_diagnose(&report, config.output.default_format, group_by)?;
            Ok(diagnose_exit(&report, fail_on))
        }
        Command::Advise { target } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            // Advise is diagnose focused on a single target.
            let report = run_diagnose(&paths, Some(&target), None, &config.diagnose)?;
            render_diagnose(&report, config.output.default_format, None)?;
            Ok(0)
        }
        Command::Metrics { target } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let config = load_config(&paths, format_override)?;
            let (files, file_deps, churn, complexity, abstractness, _co_change) =
                load_diagnose_inputs(&paths)?;
            let mut report = ovecc_graph::diagnose::metrics(
                &files,
                &file_deps,
                &churn,
                &complexity,
                &abstractness,
                &config.diagnose,
            );
            if let Some(t) = &target {
                let needle = t.to_ascii_lowercase();
                report
                    .components
                    .retain(|m| m.component.to_ascii_lowercase().contains(&needle));
            }
            render_metrics(&report, config.output.default_format)?;
            Ok(0)
        }
        Command::Mcp => crate::mcp::serve(),
    };

    if stats {
        report_run_stats(started.elapsed());
    }
    outcome
}

/// Prints overall wall-clock and peak heap to stderr. Diagnostics go to
/// stderr so they never pollute the machine-readable report on stdout.
fn report_run_stats(elapsed: std::time::Duration) {
    eprintln!(
        "stats: {} ms wall, {:.1} MB peak heap",
        elapsed.as_millis(),
        crate::PEAK_ALLOC.peak_usage_as_mb()
    );
}

/// Prints the per-phase indexing breakdown to stderr.
fn render_index_timings(timings: &ovecc_core::report::IndexTimings) {
    eprintln!("index phases (ms):");
    eprintln!("  discovery {:>7}", timings.discovery_ms);
    eprintln!("  parse     {:>7}", timings.parse_ms);
    eprintln!("  resolve   {:>7}", timings.resolve_ms);
    eprintln!("  analyze   {:>7}", timings.analyze_ms);
    eprintln!("  persist   {:>7}", timings.persist_ms);
    eprintln!("  total     {:>7}", timings.total_ms);
}

/// Renders an explanation: prose for text/markdown, a structured envelope
/// (slice + explanation) for json/ndjson.
fn render_explanation(slice: &ContextSlice, explanation: &str, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            let envelope = serde_json::json!({
                "target": slice.target,
                "explanation": explanation,
                "context": slice,
            });
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        }
        _ => print!("{explanation}"),
    }
    Ok(())
}

/// Maps a parsed [`TargetSelector`] back to a string the blast resolver
/// understands (re-attaching the `table:`/`api:` prefix it strips on parse).
fn selector_to_blast(selector: &TargetSelector) -> String {
    match selector {
        TargetSelector::Table(name) => format!("table:{name}"),
        TargetSelector::Api { path, .. } => format!("api:{path}"),
        other => other.needle().to_string(),
    }
}

/// Executes a structured query against the persisted graph.
fn run_query(paths: &ProjectPaths, query: &Query, format: OutputFormat) -> Result<u8> {
    // Named queries reuse the dedicated reports.
    match query {
        Query::Hotspots => {
            let report = load_hotspots(paths, 10)?;
            render_hotspots(&report, format)?;
            return Ok(0);
        }
        Query::Violations => {
            let store = open_store(paths)?;
            let findings = store.findings(&paths.repository_id().0, None)?;
            render_violations(&findings, format)?;
            return Ok(0);
        }
        Query::Cycles => {
            let store = open_store(paths)?;
            let repository_id = paths.repository_id().0;
            let modules = store.current_modules(&repository_id)?;
            let dependencies = store.current_dependencies(&repository_id)?;
            // Actual elementary loops (A -> B -> C -> A), shortest-first, each
            // with the file:line import edges that witness every hop — the same
            // walk `review` and the circular-dependency finding report.
            let cycles =
                ovecc_graph::cycles::elementary_cycles_with_witness(&modules, &dependencies);
            match format {
                OutputFormat::Json | OutputFormat::Ndjson => {
                    let data = serde_json::json!({ "query": "cycles", "cycles": cycles });
                    emit_json("query", &data, meta_for("query"))?;
                }
                _ => {
                    println!("Cycles: {}", cycles.len());
                    for cycle in &cycles {
                        let mut closed = cycle.modules.clone();
                        if let Some(first) = cycle.modules.first().cloned() {
                            closed.push(first);
                        }
                        println!("  {}", closed.join(" -> "));
                        for edge in &cycle.edges {
                            println!(
                                "    {}:{} -> {} ({})",
                                edge.from_file,
                                edge.line,
                                edge.to_file.as_deref().unwrap_or(&edge.to_module),
                                edge.specifier
                            );
                        }
                    }
                }
            }
            return Ok(0);
        }
        _ => {}
    }

    // Graph queries traverse the persisted graph.
    let store = open_store(paths)?;
    let (nodes, edges) = load_graph(&store, &paths.repository_id().0)?;
    const DEPTH: usize = blast::DEFAULT_MAX_DEPTH;

    let run = |selector: &TargetSelector, direction: ImpactDirection| {
        blast::resolve_target(&selector_to_blast(selector), &nodes)
            .and_then(|node| blast::blast_radius(&nodes, &edges, &node.id, direction, DEPTH))
    };

    match query {
        Query::Deps(target) => print_query_labels(
            "Dependencies",
            run(target, ImpactDirection::Upstream),
            format,
        ),
        Query::ReverseDeps(target) => print_query_labels(
            "Dependents",
            run(target, ImpactDirection::Downstream),
            format,
        ),
        Query::Module(name) => {
            let selector = TargetSelector::Free(name.clone());
            print_query_labels(
                "Dependencies",
                run(&selector, ImpactDirection::Upstream),
                format,
            )
        }
        Query::Paths(target) => {
            let result = run(target, ImpactDirection::Both);
            print_query_paths(
                "Paths",
                &result.map(|r| r.paths).unwrap_or_default(),
                format,
            )
        }
        Query::Relation { source, target } => {
            let result = run(source, ImpactDirection::Upstream);
            let needle = target.needle().to_ascii_lowercase();
            let reached = result
                .as_ref()
                .map(|r| {
                    r.impacted_labels
                        .iter()
                        .any(|label| label.to_ascii_lowercase().contains(&needle))
                })
                .unwrap_or(false);
            let path = result
                .as_ref()
                .and_then(|r| {
                    r.paths.iter().find(|p| {
                        p.last()
                            .is_some_and(|l| l.to_ascii_lowercase().contains(&needle))
                    })
                })
                .cloned();
            match format {
                OutputFormat::Json | OutputFormat::Ndjson => {
                    let data = serde_json::json!({
                        "query": "relation",
                        "source": source.needle(),
                        "target": target.needle(),
                        "depends_on": reached,
                        "path": path,
                    });
                    emit_json("query", &data, meta_for("query"))?;
                }
                _ => {
                    println!(
                        "{} depends on {}: {}",
                        source.needle(),
                        target.needle(),
                        if reached { "yes" } else { "no" }
                    );
                    if let Some(path) = path {
                        println!("  {}", path.join(" -> "));
                    }
                }
            }
            Ok(0)
        }
        // Named queries handled above.
        Query::Hotspots | Query::Violations | Query::Cycles => unreachable!(),
    }
}

fn print_query_labels(
    label: &str,
    result: Option<BlastResult>,
    format: OutputFormat,
) -> Result<u8> {
    let labels = result.map(|r| r.impacted_labels).unwrap_or_default();
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            // Same self-describing envelope as every other command.
            let data = serde_json::json!({
                "query": label.to_ascii_lowercase(),
                "items": labels,
            });
            emit_json("query", &data, meta_for("query"))?;
        }
        _ => {
            println!("{label}: {}", labels.len());
            for item in &labels {
                println!("  {item}");
            }
        }
    }
    Ok(0)
}

fn print_query_paths(label: &str, paths: &[Vec<String>], format: OutputFormat) -> Result<u8> {
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            // Same self-describing envelope as every other command.
            let data = serde_json::json!({
                "query": label.to_ascii_lowercase(),
                "paths": paths,
            });
            emit_json("query", &data, meta_for("query"))?;
        }
        _ => {
            println!("{label}: {}", paths.len());
            for path in paths {
                println!("  {}", path.join(" -> "));
            }
        }
    }
    Ok(0)
}

/// Builds the deterministic context slice for a target: its
/// dependencies, dependents, call/dependency paths, and findings. The slice
/// is assembled locally and sent nowhere.
fn build_context_slice(
    paths: &ProjectPaths,
    store: &ArchitectureStore,
    target: &str,
) -> Result<ContextSlice> {
    let repository_id = paths.repository_id().0;
    let (nodes, edges) = load_graph(store, &repository_id)?;
    let resolved = blast::resolve_target(target, &nodes);
    let (label, target_id) = match &resolved {
        Some(node) => (node.label.clone(), Some(node.id.clone())),
        None => (target.to_string(), None),
    };

    let radius = |direction| {
        target_id.as_ref().and_then(|id| {
            blast::blast_radius(&nodes, &edges, id, direction, blast::DEFAULT_MAX_DEPTH)
        })
    };
    let dependencies = radius(ImpactDirection::Upstream)
        .map(|r| r.impacted_labels)
        .unwrap_or_default();
    let both = radius(ImpactDirection::Both);
    let reverse_dependencies = radius(ImpactDirection::Downstream)
        .map(|r| r.impacted_labels)
        .unwrap_or_default();
    let call_paths = both.map(|r| r.paths).unwrap_or_default();

    // Findings whose target matches (by id or label).
    let needle = label.to_ascii_lowercase();
    let findings = store
        .findings(&repository_id, None)?
        .into_iter()
        .filter(|finding| {
            finding.target.as_ref().is_some_and(|t| {
                Some(&t.id) == target_id.as_ref() || t.id.to_ascii_lowercase().contains(&needle)
            })
        })
        .collect();

    Ok(ContextSlice {
        target: label,
        dependencies,
        reverse_dependencies,
        call_paths,
        findings,
        // apis/schemas/ownership/drift are not yet assembled here;
        // export and explain consume the same canonical slice as it grows.
        ..ContextSlice::default()
    })
}

fn render_conventions(report: &ConventionsReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("conventions", report, meta_for("conventions"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("conventions", &meta_for("conventions"))?;
            for convention in &report.conventions {
                println!("{}", ndjson_line("convention", convention)?);
            }
            for deviation in &report.deviations {
                println!("{}", ndjson_line("deviation", deviation)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Conventions");
            println!();
            for convention in &report.conventions {
                println!(
                    "- **{}** (confidence {:.2}, {}/{})",
                    convention.description,
                    convention.confidence,
                    convention.matching,
                    convention.total
                );
            }
            if !report.deviations.is_empty() {
                println!();
                println!("## Deviations");
                println!();
                for deviation in &report.deviations {
                    println!(
                        "- [{}] {} — {}",
                        deviation.severity, deviation.description, deviation.reason
                    );
                    if let Some(evidence) = &deviation.evidence {
                        println!("  - Evidence: `{evidence}`");
                    }
                }
            }
        }
        OutputFormat::Text => {
            println!("Detected conventions:");
            for convention in &report.conventions {
                println!();
                println!("  {}", convention.description);
                println!(
                    "    Confidence: {:.2} ({}/{})",
                    convention.confidence, convention.matching, convention.total
                );
            }
            if report.conventions.is_empty() {
                println!("  (none with sufficient evidence)");
            }
            if !report.deviations.is_empty() {
                println!();
                println!("Deviations:");
                for deviation in &report.deviations {
                    println!();
                    println!("  [{}] {}", deviation.severity, deviation.description);
                    println!("    Reason: {}", deviation.reason);
                    if let Some(evidence) = &deviation.evidence {
                        println!("    Evidence: {evidence}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Assembles the per-module inputs (churn, ownership fragmentation, violations)
/// and computes the hotspot scores.
fn load_hotspots(paths: &ProjectPaths, limit: usize) -> Result<HotspotsReport> {
    use std::collections::HashMap;
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;

    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let churn: HashMap<String, f64> = store.module_churn(&repository_id)?.into_iter().collect();

    // Ownership fragmentation per module: share of its files with low majority
    // ownership (< 50%).
    let file_modules: HashMap<String, String> =
        store.file_modules(&repository_id)?.into_iter().collect();
    let ownership_rows = store.ownership_metrics(&repository_id)?;
    // No ingested commits => no git history, so churn and ownership are
    // unavailable ("n/a"), not genuinely zero. `module_churn` can't be the
    // signal: it LEFT JOINs file_changes and returns a 0 row per module even
    // with no history.
    let has_git_history = store.count_rows("commits", &repository_id)? > 0;
    let mut fragmented: HashMap<String, (usize, usize)> = HashMap::new();
    for ownership in &ownership_rows {
        if let Some(module) = file_modules.get(&ownership.file_path) {
            let entry = fragmented.entry(module.clone()).or_insert((0, 0));
            entry.1 += 1;
            if ownership.ownership < 0.5 {
                entry.0 += 1;
            }
        }
    }
    let fragmentation: HashMap<String, f64> = fragmented
        .iter()
        .map(|(module, (low, total))| {
            (
                module.clone(),
                if *total > 0 {
                    *low as f64 / *total as f64
                } else {
                    0.0
                },
            )
        })
        .collect();

    // Violations per module: findings whose target is the module.
    let mut violations: HashMap<String, usize> = HashMap::new();
    for finding in store.findings(&repository_id, None)? {
        if let Some(target) = &finding.target {
            *violations.entry(target.id.clone()).or_default() += 1;
        }
    }

    // Per-module cognitive complexity (oxc), aggregated from the v4 table.
    let complexity: HashMap<String, f64> = store
        .module_complexity(&repository_id)?
        .into_iter()
        .collect();

    Ok(HotspotsReport {
        hotspots: graph::compute_hotspots(
            &modules,
            &dependencies,
            &churn,
            &fragmentation,
            &violations,
            &complexity,
            limit,
        ),
        has_git_history,
    })
}

fn render_hotspots(report: &HotspotsReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("hotspots", report, meta_for("hotspots"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("hotspots", &meta_for("hotspots"))?;
            for hotspot in &report.hotspots {
                println!("{}", ndjson_line("hotspot", hotspot)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Hotspots");
            println!();
            if !report.has_git_history {
                println!("> Churn and owner-fragmentation are **n/a** — no git history indexed.");
                println!();
            }
            println!(
                "| # | Module | Score | Churn | Coupling | Fan-in | Fan-out | Owner frag. | Violations |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for (rank, hotspot) in report.hotspots.iter().enumerate() {
                let churn = if report.has_git_history {
                    format!("{:.0}", hotspot.churn)
                } else {
                    "n/a".to_string()
                };
                let owner = if report.has_git_history {
                    format!("{:.0}%", hotspot.ownership_fragmentation * 100.0)
                } else {
                    "n/a".to_string()
                };
                println!(
                    "| {} | {} | {:.0} | {} | {} | {} | {} | {} | {} |",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    churn,
                    hotspot.coupling,
                    hotspot.fan_in,
                    hotspot.fan_out,
                    owner,
                    hotspot.violations
                );
            }
        }
        OutputFormat::Text => {
            println!("Hotspots:");
            if !report.has_git_history {
                println!("  (churn and ownership: n/a — no git history indexed)");
            }
            for (rank, hotspot) in report.hotspots.iter().enumerate() {
                println!();
                println!("{}. {}", rank + 1, hotspot.module);
                println!("   Score: {:.0}", hotspot.score);
                if report.has_git_history {
                    println!("   Churn: {:.0}", hotspot.churn);
                    println!(
                        "   Ownership fragmentation: {:.0}%",
                        hotspot.ownership_fragmentation * 100.0
                    );
                } else {
                    println!("   Churn: n/a (no git history)");
                    println!("   Ownership fragmentation: n/a (no git history)");
                }
                println!(
                    "   Coupling: {} (fan-in {}, fan-out {})",
                    hotspot.coupling, hotspot.fan_in, hotspot.fan_out
                );
                println!("   Complexity: {:.0} (cognitive)", hotspot.complexity);
                println!("   Violations: {}", hotspot.violations);
            }
            if report.hotspots.is_empty() {
                println!("  (none)");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc diagnose / advise / metrics
// ---------------------------------------------------------------------------

/// Assembles the per-module graph inputs the diagnosis engine consumes: module
/// names, the dependency records, churn, and aggregate complexity. Mirrors the
/// inputs `load_hotspots` gathers, minus the hotspot-only fragmentation.
type DiagnoseInputs = (
    Vec<String>,
    Vec<ovecc_graph::diagnose::FileDep>,
    std::collections::HashMap<String, f64>,
    std::collections::HashMap<String, f64>,
    std::collections::HashMap<String, (f64, f64)>,
    Vec<(String, String, f64)>,
);

fn load_diagnose_inputs(paths: &ProjectPaths) -> Result<DiagnoseInputs> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    // Every indexed file (so components with no edges still count toward size).
    let files: Vec<String> = store
        .file_modules(&repository_id)?
        .into_iter()
        .map(|(path, _module)| path)
        .collect();
    // Internal file -> file edges (the component graph is aggregated from
    // these), each carrying its import evidence so detectors can cite the
    // concrete `file:line` witness of a cycle hop.
    let file_deps: Vec<ovecc_graph::diagnose::FileDep> = store
        .current_dependencies(&repository_id)?
        .into_iter()
        .filter(|dependency| !dependency.is_external)
        .filter_map(|dependency| {
            dependency
                .target_file_path
                .map(|target| ovecc_graph::diagnose::FileDep {
                    source: dependency.source_file_path,
                    target,
                    specifier: dependency.specifier,
                    line: dependency.evidence_line,
                })
        })
        .collect();
    let churn: std::collections::HashMap<String, f64> =
        store.file_churn(&repository_id)?.into_iter().collect();
    let complexity: std::collections::HashMap<String, f64> =
        store.file_complexity(&repository_id)?.into_iter().collect();
    // Per-file (abstract_types, total_types) for Abstractness / Zone of Pain.
    let abstractness: std::collections::HashMap<String, (f64, f64)> = store
        .file_abstractness(&repository_id)?
        .into_iter()
        .map(|(path, abs, tot)| (path, (abs, tot)))
        .collect();
    // Evolutionary signal (empty without git history).
    let co_change = store.co_change_pairs(&repository_id)?;
    Ok((files, file_deps, churn, complexity, abstractness, co_change))
}

/// Runs the diagnosis engine, then applies the optional severity and target
/// filters and rebuilds the ranked report.
fn run_diagnose(
    paths: &ProjectPaths,
    target: Option<&str>,
    min_severity: Option<Severity>,
    cfg: &ovecc_graph::diagnose::DiagnoseConfig,
) -> Result<ovecc_graph::diagnose::DiagnoseReport> {
    let (files, file_deps, churn, complexity, abstractness, co_change) =
        load_diagnose_inputs(paths)?;
    let report = ovecc_graph::diagnose::diagnose(
        &files,
        &file_deps,
        &churn,
        &complexity,
        &abstractness,
        &co_change,
        cfg,
    );
    let components = report.components;
    let mut findings = report.findings;
    if let Some(min) = min_severity {
        findings.retain(|finding| finding.severity >= min);
    }
    if let Some(needle) = target.map(|t| t.to_ascii_lowercase()) {
        findings.retain(|finding| finding.target.to_ascii_lowercase().contains(&needle));
    }
    Ok(ovecc_graph::diagnose::DiagnoseReport::new(
        components, findings,
    ))
}

/// CI exit code for `diagnose`: 1 when a finding crosses the threshold, else 0.
fn diagnose_exit(report: &ovecc_graph::diagnose::DiagnoseReport, fail_on: Option<FailOn>) -> u8 {
    let Some(fail_on) = fail_on else {
        return 0;
    };
    let triggered = match fail_on {
        FailOn::Any => !report.findings.is_empty(),
        FailOn::Medium => report
            .findings
            .iter()
            .any(|f| f.severity >= Severity::Medium),
        FailOn::High => report.findings.iter().any(|f| f.severity >= Severity::High),
    };
    u8::from(triggered)
}

/// Formats a number with no trailing `.0` for whole values.
fn fmt_num(value: f64) -> String {
    if value.fract().abs() < 1e-9 {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    }
}

/// Renders one piece of diagnosis evidence as `file:line — metric=value (>= t)`.
fn fmt_diag_evidence(e: &ovecc_graph::diagnose::DiagEvidence) -> String {
    let mut text = String::new();
    if let Some(file) = &e.file {
        text.push_str(file);
        if let Some(line) = e.line {
            text.push_str(&format!(":{line}"));
        }
        text.push_str(" — ");
    }
    text.push_str(&format!("{}={}", e.metric, fmt_num(e.value)));
    if let Some(threshold) = e.threshold
        && threshold > 0.0
    {
        text.push_str(&format!(" (>= {})", fmt_num(threshold)));
    }
    if let Some(detail) = &e.detail {
        text.push_str(&format!(" ({detail})"));
    }
    text
}

/// Serializes a diagnosis and enriches it with its machine-actionable `fix`
/// descriptor (derived deterministically from the detector) — the field an agent
/// branches on after reading the finding.
fn diagnosis_value(finding: &ovecc_graph::diagnose::Diagnosis) -> serde_json::Value {
    let mut value = serde_json::to_value(finding).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &mut value {
        let fix = ovecc_graph::diagnose::fix_spec(&finding.detector);
        map.insert(
            "fix".to_string(),
            serde_json::to_value(fix).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

/// Partitions findings for the human report, preserving the overall severity
/// ranking (groups appear in order of their most-severe finding). `None` yields a
/// single unlabelled group = the flat ranked list.
fn group_diagnoses(
    findings: &[ovecc_graph::diagnose::Diagnosis],
    group_by: Option<GroupByArg>,
) -> Vec<(String, Vec<&ovecc_graph::diagnose::Diagnosis>)> {
    let mut groups: Vec<(String, Vec<&ovecc_graph::diagnose::Diagnosis>)> = Vec::new();
    for finding in findings {
        let label = match group_by {
            None => String::new(),
            Some(GroupByArg::Family) => finding.family.clone(),
            Some(GroupByArg::Severity) => format!("{:?}", finding.severity),
            Some(GroupByArg::Component) => diagnose_location(finding).0,
        };
        match groups.iter_mut().find(|(existing, _)| *existing == label) {
            Some((_, bucket)) => bucket.push(finding),
            None => groups.push((label, vec![finding])),
        }
    }
    groups
}

fn render_diagnose(
    report: &ovecc_graph::diagnose::DiagnoseReport,
    format: OutputFormat,
    group_by: Option<GroupByArg>,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let findings: Vec<serde_json::Value> =
                report.findings.iter().map(diagnosis_value).collect();
            let data = serde_json::json!({
                "components": report.components,
                "findings": findings,
                "total": report.total,
                "critical": report.critical,
                "high": report.high,
                "medium": report.medium,
                "low": report.low,
            });
            emit_json("diagnose", &data, meta_for("diagnose"))?
        }
        OutputFormat::Sarif => emit_diagnose_sarif(&report.findings)?,
        OutputFormat::Codeclimate => emit_diagnose_codeclimate(&report.findings)?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("diagnose", &meta_for("diagnose"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("diagnosis", &diagnosis_value(finding))?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Diagnosis ({} finding(s))", report.total);
            println!();
            println!(
                "Critical: {} · High: {} · Medium: {} · Low: {}",
                report.critical, report.high, report.medium, report.low
            );
            for (label, bucket) in group_diagnoses(&report.findings, group_by) {
                if !label.is_empty() {
                    println!();
                    println!("# {} ({})", label, bucket.len());
                }
                for finding in bucket {
                    println!();
                    println!(
                        "## [{:?}] {} — `{}`",
                        finding.severity, finding.title, finding.target
                    );
                    println!("- Principle: {}", finding.principle);
                    println!("- Confidence: {:.2}", finding.confidence);
                    for evidence in &finding.evidence {
                        println!("- Evidence: `{}`", fmt_diag_evidence(evidence));
                    }
                    println!(
                        "- Fix: {} ({})",
                        finding.remediation.summary, finding.remediation.refactoring
                    );
                    let fix = ovecc_graph::diagnose::fix_spec(&finding.detector);
                    println!(
                        "- Action: `{}` (auto-fixable: {})",
                        fix.kind,
                        if fix.auto_fixable { "yes" } else { "no" }
                    );
                    if let Some(note) = &finding.remediation.when_not_to_act {
                        println!("- When not to act: {note}");
                    }
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Diagnosis: {} finding(s) — critical {}, high {}, medium {}, low {}",
                report.total, report.critical, report.high, report.medium, report.low
            );
            for (label, bucket) in group_diagnoses(&report.findings, group_by) {
                if !label.is_empty() {
                    println!();
                    println!("== {} ({}) ==", label, bucket.len());
                }
                for finding in bucket {
                    println!();
                    println!(
                        "[{:?}] {} — {} {}  (confidence {:.2})",
                        finding.severity,
                        finding.title,
                        finding.target_kind,
                        finding.target,
                        finding.confidence
                    );
                    println!("  Principle: {}", finding.principle);
                    let evidence: Vec<String> =
                        finding.evidence.iter().map(fmt_diag_evidence).collect();
                    println!("  Evidence: {}", evidence.join(", "));
                    println!(
                        "  Fix: {} [{}]",
                        finding.remediation.summary, finding.remediation.refactoring
                    );
                    let fix = ovecc_graph::diagnose::fix_spec(&finding.detector);
                    println!(
                        "  Action: {} (auto-fixable: {})",
                        fix.kind,
                        if fix.auto_fixable { "yes" } else { "no" }
                    );
                    if let Some(note) = &finding.remediation.when_not_to_act {
                        println!("  When not to act: {note}");
                    }
                }
            }
            if report.total == 0 {
                println!("  (no findings)");
            }
        }
    }
    Ok(())
}

/// A best-effort file/path location for a diagnosis: the first evidence with a
/// concrete file, else a path extracted from the target (the first component of
/// a `a <-> b` pair/group; `.` for the whole-repository target).
fn diagnose_location(finding: &ovecc_graph::diagnose::Diagnosis) -> (String, u32) {
    if let Some(e) = finding.evidence.iter().find(|e| e.file.is_some()) {
        return (e.file.clone().unwrap(), e.line.unwrap_or(1).max(1));
    }
    if finding.target == "<repository>" {
        return (".".to_string(), 1);
    }
    let path = finding
        .target
        .split(" <-> ")
        .next()
        .unwrap_or(&finding.target)
        .split(" … ")
        .next()
        .unwrap_or(&finding.target)
        .trim()
        .to_string();
    (path, 1)
}

/// A stable fingerprint (FNV-1a over `detector|target`) so GitLab can diff a
/// diagnosis across pipelines even though diagnoses have no persisted id.
fn diagnose_fingerprint(finding: &ovecc_graph::diagnose::Diagnosis) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in format!("{}|{}", finding.detector, finding.target).bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Serializes diagnoses as SARIF 2.1.0 (one rule per detector), so
/// `ovecc diagnose --format sarif` flows into GitHub code scanning.
fn emit_diagnose_sarif(findings: &[ovecc_graph::diagnose::Diagnosis]) -> Result<()> {
    use std::collections::BTreeMap;
    let mut rules: BTreeMap<String, (String, String)> = BTreeMap::new();
    for f in findings {
        rules
            .entry(f.detector.clone())
            .or_insert_with(|| (f.title.clone(), f.principle.clone()));
    }
    let rule_list: Vec<serde_json::Value> = rules
        .iter()
        .map(|(id, (title, principle))| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": title },
                "fullDescription": { "text": principle },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let (path, line) = diagnose_location(f);
            let message = format!(
                "{} — {}. Fix: {} [{}]",
                f.title, f.principle, f.remediation.summary, f.remediation.refactoring
            );
            serde_json::json!({
                "ruleId": f.detector,
                "level": level,
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": path },
                        "region": { "startLine": line },
                    }
                }],
                "properties": {
                    "family": f.family,
                    "confidence": f.confidence,
                    "target": f.target,
                    "fix": {
                        "kind": ovecc_graph::diagnose::fix_spec(&f.detector).kind,
                        "auto_fixable": ovecc_graph::diagnose::fix_spec(&f.detector).auto_fixable,
                    },
                },
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "ovecc",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/gitvonBS/ovecc",
                "rules": rule_list,
            }},
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

/// Serializes diagnoses as Code Climate / GitLab Code Quality JSON.
fn emit_diagnose_codeclimate(findings: &[ovecc_graph::diagnose::Diagnosis]) -> Result<()> {
    let issues: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let severity = match f.severity {
                Severity::Critical => "blocker",
                Severity::High => "critical",
                Severity::Medium => "major",
                Severity::Low => "minor",
            };
            let (path, line) = diagnose_location(f);
            serde_json::json!({
                "type": "issue",
                "check_name": f.detector,
                "description": format!("{} ({})", f.title, f.target),
                "fingerprint": diagnose_fingerprint(f),
                "severity": severity,
                "location": { "path": path, "lines": { "begin": line } },
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&issues)?);
    Ok(())
}

fn render_metrics(
    report: &ovecc_graph::diagnose::MetricsReport,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("metrics", report, meta_for("metrics"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("metrics", &meta_for("metrics"))?;
            for component in &report.components {
                println!("{}", ndjson_line("component_metric", component)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Metrics");
            println!();
            println!("Coupling density: {:.2}%", report.coupling_density * 100.0);
            println!();
            println!(
                "| Component | Files | Fan-in | Fan-out | Coupling | Instability | Abstractness | Distance | Complexity | Churn |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for m in &report.components {
                println!(
                    "| {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.0} | {:.0} |",
                    m.component,
                    m.files,
                    m.fan_in,
                    m.fan_out,
                    m.coupling,
                    m.instability,
                    m.abstractness,
                    m.distance,
                    m.complexity,
                    m.churn
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "Metrics: {} component(s), coupling density {:.2}%",
                report.components.len(),
                report.coupling_density * 100.0
            );
            for m in &report.components {
                println!();
                println!("{}", m.component);
                println!(
                    "  files {}, fan-in {}, fan-out {}, coupling {}, instability {:.2}",
                    m.files, m.fan_in, m.fan_out, m.coupling, m.instability
                );
                println!(
                    "  abstractness {:.2}, distance {:.2}, complexity {:.0}, churn {:.0}",
                    m.abstractness, m.distance, m.complexity, m.churn
                );
            }
        }
    }
    Ok(())
}

/// Loads the accepted finding IDs from a baseline file (JSON array). A missing
/// or invalid file is treated as an empty baseline.
fn load_baseline(path: &std::path::Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<Vec<String>>(&content).ok())
        .map(|ids| ids.into_iter().collect())
        .unwrap_or_default()
}

/// CI exit code for finding-bearing commands (`violations`, `security`,
/// `audit`): 1 when a finding crosses the threshold, else 0.
fn findings_exit(findings: &[FindingRecord], fail_on: Option<FailOn>) -> u8 {
    let Some(fail_on) = fail_on else {
        return 0;
    };
    let triggered = match fail_on {
        FailOn::Any => !findings.is_empty(),
        FailOn::Medium => findings.iter().any(|f| f.severity >= Severity::Medium),
        FailOn::High => findings.iter().any(|f| f.severity >= Severity::High),
    };
    u8::from(triggered)
}

/// Injects each finding's machine-actionable `fix` (derived from its kind) into a
/// serialized findings payload — whether a bare array of findings or a report
/// object carrying a `findings` array. Pure output enrichment: nothing is
/// persisted, so the DB schema is untouched.
fn enrich_findings_with_fix(value: &mut serde_json::Value) {
    fn enrich_array(arr: &mut [serde_json::Value]) {
        for item in arr {
            let kind = item.get("kind").and_then(|k| k.as_str()).and_then(|s| {
                serde_json::from_value::<ovecc_core::facts::FindingKind>(serde_json::Value::String(
                    s.to_string(),
                ))
                .ok()
            });
            if let (Some(kind), serde_json::Value::Object(map)) = (kind, item) {
                map.insert(
                    "fix".to_string(),
                    serde_json::to_value(kind.fix_spec()).unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    match value {
        serde_json::Value::Array(arr) => enrich_array(arr),
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(arr)) = map.get_mut("findings") {
                enrich_array(arr);
            }
        }
        _ => {}
    }
}

/// Serializes `data`, enriches its findings with `fix` descriptors, and emits the
/// standard envelope.
fn emit_json_with_fix(command: &str, data: impl serde::Serialize) -> Result<()> {
    let mut value = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
    enrich_findings_with_fix(&mut value);
    emit_json(command, &value, meta_for(command))
}

fn render_violations(findings: &[FindingRecord], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => emit_json_with_fix("violations", findings)?,
        OutputFormat::Ndjson => {
            emit_ndjson_meta("violations", &meta_for("violations"))?;
            for finding in findings {
                println!("{}", ndjson_line("violation", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Violations ({})", findings.len());
            for finding in findings {
                println!();
                println!("## [{:?}] {}", finding.severity, finding.title);
                if let Some(rule) = &finding.rule_name {
                    println!("- Rule: `{rule}`");
                }
                println!("- Type: {:?}", finding.kind);
                println!("- {}", finding.description);
                for evidence in &finding.evidence {
                    println!("- Evidence: `{}`", format_evidence(evidence));
                }
            }
        }
        OutputFormat::Text => {
            println!("Violations: {}", findings.len());
            for finding in findings {
                println!();
                println!("[{:?}] {}", finding.severity, finding.title);
                if let Some(rule) = &finding.rule_name {
                    println!("  Rule: {rule}");
                }
                println!("  Type: {:?}", finding.kind);
                for evidence in &finding.evidence {
                    println!("  Evidence: {}", format_evidence(evidence));
                }
            }
        }
        OutputFormat::Sarif => emit_sarif(findings)?,
        OutputFormat::Codeclimate => emit_codeclimate(findings)?,
    }
    Ok(())
}

/// Serializes findings as SARIF 2.1.0 so `ovecc violations`/`security` output
/// flows into GitHub code scanning and CI security dashboards.
fn emit_sarif(findings: &[FindingRecord]) -> Result<()> {
    use std::collections::BTreeMap;

    // One SARIF rule per distinct rule name, with its description.
    let mut rules: BTreeMap<String, String> = BTreeMap::new();
    for finding in findings {
        let rule_id = finding
            .rule_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", finding.kind));
        rules
            .entry(rule_id)
            .or_insert_with(|| finding.title.clone());
    }
    let rule_list: Vec<serde_json::Value> = rules
        .iter()
        .map(|(id, desc)| serde_json::json!({ "id": id, "shortDescription": { "text": desc } }))
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let rule_id = finding
                .rule_name
                .clone()
                .unwrap_or_else(|| format!("{:?}", finding.kind));
            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let locations: Vec<serde_json::Value> = finding
                .evidence
                .iter()
                .map(|evidence| {
                    let mut region = serde_json::Map::new();
                    if let Some(line) = evidence.line {
                        region.insert("startLine".to_string(), serde_json::json!(line.max(1)));
                    }
                    serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": { "uri": evidence.file_path },
                            "region": region,
                        }
                    })
                })
                .collect();
            serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": finding.description },
                "locations": locations,
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ovecc",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/gitvonBS/ovecc",
                    "rules": rule_list,
                }
            },
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

/// Serializes findings as Code Climate / GitLab Code Quality JSON, so
/// `ovecc violations` flows into GitLab merge-request quality reports.
fn emit_codeclimate(findings: &[FindingRecord]) -> Result<()> {
    let issues: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let check_name = finding
                .rule_name
                .clone()
                .unwrap_or_else(|| format!("{:?}", finding.kind));
            let severity = match finding.severity {
                Severity::Critical => "blocker",
                Severity::High => "critical",
                Severity::Medium => "major",
                Severity::Low => "minor",
            };
            let evidence = finding.evidence.first();
            let path = evidence
                .map(|e| e.file_path.clone())
                .unwrap_or_else(|| "<unknown>".to_string());
            let line = evidence.and_then(|e| e.line).unwrap_or(1).max(1);
            serde_json::json!({
                "type": "issue",
                "check_name": check_name,
                "description": finding.title,
                // Stable across runs (derived from the finding's identity), as
                // GitLab expects to diff fingerprints between pipelines.
                "fingerprint": finding.id.as_str(),
                "severity": severity,
                "location": { "path": path, "lines": { "begin": line } },
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&issues)?);
    Ok(())
}

fn format_evidence(evidence: &ovecc_core::facts::Evidence) -> String {
    let mut text = evidence.file_path.clone();
    if let Some(line) = evidence.line {
        text.push_str(&format!(":{line}"));
    }
    if let Some(detail) = &evidence.detail {
        text.push_str(&format!(" ({detail})"));
    }
    text
}

// ---------------------------------------------------------------------------
// ovecc capabilities
// ---------------------------------------------------------------------------

/// Renders the capability manifest: JSON for agents (the primary consumer), a
/// readable catalog for humans. Needs no database — it is pure contract.
fn render_capabilities(format: OutputFormat) -> Result<()> {
    let caps = capabilities::capabilities();
    match format {
        OutputFormat::Json
        | OutputFormat::Ndjson
        | OutputFormat::Sarif
        | OutputFormat::Codeclimate => emit_json("capabilities", &caps, Meta::default())?,
        OutputFormat::Markdown => {
            println!("# Ovecc capabilities");
            println!();
            println!("Schema version: `{}`", ovecc_core::report::SCHEMA_VERSION);
            println!();
            println!("## Commands");
            println!();
            for command in caps.commands {
                let ro = if command.read_only {
                    " _(read-only)_"
                } else {
                    ""
                };
                println!("- **{}** — {}{ro}", command.name, command.summary);
            }
            println!();
            println!("## Exit codes");
            println!();
            for code in caps.exit_codes {
                println!("- `{}` {} — {}", code.code, code.name, code.meaning);
            }
        }
        OutputFormat::Text => {
            println!("ovecc — deterministic architecture intelligence");
            println!("schema_version: {}", ovecc_core::report::SCHEMA_VERSION);
            println!("formats: {}", caps.formats.join(", "));
            println!("severities: {}", caps.severities.join(", "));
            println!();
            println!("Commands:");
            for command in caps.commands {
                println!("  {:<16} {}", command.name, command.summary);
            }
            println!();
            println!("Exit codes:");
            for code in caps.exit_codes {
                println!("  {} {:<16} {}", code.code, code.name, code.meaning);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc security
// ---------------------------------------------------------------------------

/// The finding kinds the `security` command surfaces (dependency vulnerabilities
/// are surfaced by `audit` instead).
fn is_security_kind(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::HardcodedSecret
            | FindingKind::InsecurePattern
            | FindingKind::WeakCrypto
            | FindingKind::PermissiveCors
            | FindingKind::TaintedFlow
    )
}

/// Security findings grouped by category, with explicit per-category counts so a
/// "0 findings" result is stated rather than silent.
#[derive(serde::Serialize)]
struct SecurityReport {
    secrets: usize,
    insecure_patterns: usize,
    weak_crypto: usize,
    permissive_cors: usize,
    tainted_flows: usize,
    total: usize,
    findings: Vec<FindingRecord>,
}

/// Filters all findings to the security kinds (optionally by minimum severity)
/// and tallies per category.
fn build_security_report(all: &[FindingRecord], min_severity: Option<Severity>) -> SecurityReport {
    let findings: Vec<FindingRecord> = all
        .iter()
        .filter(|finding| is_security_kind(finding.kind))
        .filter(|finding| min_severity.is_none_or(|min| finding.severity >= min))
        .cloned()
        .collect();
    let count = |kind: FindingKind| findings.iter().filter(|f| f.kind == kind).count();
    SecurityReport {
        secrets: count(FindingKind::HardcodedSecret),
        insecure_patterns: count(FindingKind::InsecurePattern),
        weak_crypto: count(FindingKind::WeakCrypto),
        permissive_cors: count(FindingKind::PermissiveCors),
        tainted_flows: count(FindingKind::TaintedFlow),
        total: findings.len(),
        findings,
    }
}

fn render_security(report: &SecurityReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json_with_fix("security", report)?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("security", &meta_for("security"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("security_finding", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Security ({} finding(s))", report.total);
            println!();
            println!("- Hardcoded secrets: {}", report.secrets);
            println!(
                "- Insecure patterns (eval/exec): {}",
                report.insecure_patterns
            );
            println!("- Weak crypto: {}", report.weak_crypto);
            println!("- Permissive CORS: {}", report.permissive_cors);
            println!("- Tainted flows: {}", report.tainted_flows);
            for finding in &report.findings {
                println!();
                println!("## [{:?}] {}", finding.severity, finding.title);
                println!("- {}", finding.description);
                for evidence in &finding.evidence {
                    println!("- Evidence: `{}`", format_evidence(evidence));
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Security findings: {} (scanned the indexed repository)",
                report.total
            );
            println!(
                "  secrets {}, insecure {}, weak-crypto {}, cors {}, tainted-flows {}",
                report.secrets,
                report.insecure_patterns,
                report.weak_crypto,
                report.permissive_cors,
                report.tainted_flows
            );
            for finding in &report.findings {
                println!();
                println!("[{:?}] {}", finding.severity, finding.title);
                for evidence in &finding.evidence {
                    println!("  Evidence: {}", format_evidence(evidence));
                }
            }
            if report.total == 0 {
                println!("  (no security findings)");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc audit (OSV dependency vulnerabilities)
// ---------------------------------------------------------------------------

/// OSV audit result with explicit scanned counts (packages, advisories) so a
/// clean result is stated, not silent.
#[derive(serde::Serialize)]
struct AuditReport {
    packages_scanned: usize,
    advisories_loaded: usize,
    vulnerabilities: usize,
    findings: Vec<FindingRecord>,
}

fn render_audit(report: &AuditReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("audit", report, meta_for("audit"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("audit", &meta_for("audit"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("vulnerability", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Dependency audit (OSV)");
            println!();
            println!("- Packages scanned: {}", report.packages_scanned);
            println!("- Advisories loaded: {}", report.advisories_loaded);
            println!("- Vulnerabilities: {}", report.vulnerabilities);
            for finding in &report.findings {
                println!();
                println!("## [{:?}] {}", finding.severity, finding.title);
                println!("- {}", finding.description);
            }
        }
        OutputFormat::Text => {
            println!(
                "Dependency audit (OSV): scanned {} package(s) against {} advisor(ies)",
                report.packages_scanned, report.advisories_loaded
            );
            println!("Vulnerabilities: {}", report.vulnerabilities);
            for finding in &report.findings {
                println!();
                println!("[{:?}] {}", finding.severity, finding.title);
            }
            if report.advisories_loaded == 0 {
                println!("  (no OSV database in .ovecc/osv/ — sync advisories to enable matching)");
            } else if report.vulnerabilities == 0 {
                println!("  (no known vulnerabilities)");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc gate (CI gate over diff/drift)
// ---------------------------------------------------------------------------

/// CI gate verdict and the signals (new cycles/structure/risk) behind it.
#[derive(serde::Serialize)]
struct GateReport {
    base: String,
    head: String,
    /// `"pass"` or `"fail"`.
    verdict: String,
    new_cycles: i64,
    new_modules: usize,
    new_dependencies: usize,
    risk: String,
    signals: Vec<String>,
}

/// Computes the gate verdict from the diff (added modules/deps + risk) and the
/// drift (cycle delta) between base and head. New cycles always fail; new
/// structure and diff risk fail per `fail_on`.
fn build_gate_report(
    store: &ArchitectureStore,
    repository_id: &str,
    base: &str,
    head: &str,
    fail_on: FailOn,
) -> Result<GateReport> {
    let diff = store.diff(repository_id, base, head)?;
    let drift = store.drift(repository_id, base, head)?;
    let new_cycles = i64::from(drift.circular_dependency_delta.max(0) as i32);
    let new_modules = diff.added_modules.len();
    let new_dependencies = diff.added_dependencies.len();

    let mut signals = Vec::new();
    if new_cycles > 0 {
        signals.push(format!("{new_cycles} new circular-dependency component(s)"));
    }
    let risk_fail = diff_crosses_threshold(&diff, fail_on);
    if risk_fail {
        signals.push(format!(
            "diff risk {} crosses --fail-on {:?}",
            diff.risk_score.as_str(),
            fail_on
        ));
    }
    if matches!(fail_on, FailOn::Any) {
        if new_modules > 0 {
            signals.push(format!("{new_modules} new module(s)"));
        }
        if new_dependencies > 0 {
            signals.push(format!("{new_dependencies} new dependency edge(s)"));
        }
    }
    // Quality regressions: any increase in a security/dead-code/complexity
    // metric fails the gate regardless of --fail-on, because a PR that adds a
    // vulnerability, dead code, or complexity is the case this gate exists for.
    const REGRESSION_METRICS: &[(&str, &str)] = &[
        ("security_findings", "security finding"),
        ("unused_exports", "unused export"),
        ("unused_files", "unused file"),
        ("high_complexity_functions", "high-complexity function"),
        ("boundary_violations", "boundary violation"),
    ];
    let mut quality_regressed = false;
    for delta in &drift.metric_deltas {
        for (metric, label) in REGRESSION_METRICS {
            if delta.metric == *metric && delta.head > delta.base {
                let added = (delta.head - delta.base) as i64;
                signals.push(format!("{added} new {label}(s)"));
                quality_regressed = true;
            }
        }
    }
    let failed = new_cycles > 0
        || risk_fail
        || quality_regressed
        || (matches!(fail_on, FailOn::Any) && (new_modules > 0 || new_dependencies > 0));

    Ok(GateReport {
        base: diff.base.id,
        head: diff.head.id,
        verdict: if failed { "fail" } else { "pass" }.to_string(),
        new_cycles,
        new_modules,
        new_dependencies,
        risk: diff.risk_score.as_str().to_string(),
        signals,
    })
}

fn render_gate(report: &GateReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json
        | OutputFormat::Ndjson
        | OutputFormat::Sarif
        | OutputFormat::Codeclimate => emit_json("gate", report, meta_for("gate"))?,
        OutputFormat::Markdown => {
            println!("# CI gate: {}", report.verdict.to_uppercase());
            println!();
            println!("- Base: `{}`", report.base);
            println!("- Head: `{}`", report.head);
            println!("- New cycles: {}", report.new_cycles);
            println!("- Risk: {}", report.risk);
            if report.signals.is_empty() {
                println!("- No gating signals.");
            } else {
                println!();
                println!("## Signals");
                println!();
                for signal in &report.signals {
                    println!("- {signal}");
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Gate: {} ({} -> {})",
                report.verdict, report.base, report.head
            );
            println!(
                "New cycles: {}, new modules: {}, new deps: {}, risk: {}",
                report.new_cycles, report.new_modules, report.new_dependencies, report.risk
            );
            for signal in &report.signals {
                println!("  - {signal}");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc review (change-scoped, named new defects)
// ---------------------------------------------------------------------------

/// The named defects a change introduced between two snapshots: the actionable,
/// change-scoped report that `gate` (counts only) cannot give.
#[derive(serde::Serialize)]
struct ReviewReport {
    base: String,
    head: String,
    /// `"pass"` or `"fail"` against `--fail-on`.
    verdict: String,
    /// Calibrated risk band: Low/Medium/High/Critical.
    risk: String,
    /// Human-readable reasons behind the verdict — the explanation `gate` lacks.
    rationale: Vec<String>,
    summary: ReviewSummary,
    /// Each new finding is a full, named record with file:line evidence.
    new_findings: Vec<FindingRecord>,
    /// New dependency cycles, each carrying the file-level witness edges that
    /// form it (so a consumer never has to guess — and mis-guess — the edges).
    new_cycles: Vec<graph::cycles::CycleWitness>,
    /// Clone families the change introduced (scoped to touched files), so new
    /// duplication is not buried under pre-existing repo-wide clones.
    new_duplications: Vec<graph::dupes::CloneFamily>,
    changed_files: ChangedFiles,
}

#[derive(serde::Serialize)]
struct ReviewSummary {
    files_added: usize,
    files_modified: usize,
    new_findings: usize,
    new_security: usize,
    new_dead_code: usize,
    new_complexity: usize,
    new_cycles: usize,
    new_duplications: usize,
    /// Findings present in base but gone in head — credit for fixes.
    resolved_findings: usize,
}

/// Assembles the change review from the snapshot-diff primitives in `ovecc-db`
/// (named finding diff, changed files) and the graph analyses (cycle witnesses,
/// change-scoped duplication). Head cycle/duplication evidence is drawn from the
/// current index, so this is most precise when `head` is `latest` (the gate
/// workflow: index base, apply change, index, review).
fn build_review_report(
    paths: &ProjectPaths,
    config: &OveccConfig,
    store: &ArchitectureStore,
    base: &str,
    head: &str,
    fail_on: FailOn,
) -> Result<ReviewReport> {
    let repository_id = paths.repository_id().0;

    let base_snapshot = store
        .resolve_snapshot(&repository_id, base)?
        .ok_or_else(|| OveccError::Index {
            message: format!(
                "could not resolve base snapshot '{base}'; index the repository at \
                 least twice (a baseline, then again after the change) so there is a \
                 base to compare against"
            ),
            source: None,
        })?;
    let head_snapshot = store
        .resolve_snapshot(&repository_id, head)?
        .ok_or_else(|| OveccError::Index {
            message: format!("could not resolve head snapshot '{head}'; run 'ovecc index' first"),
            source: None,
        })?;

    // 1. Named new/resolved findings (security, dead code, complexity, ...).
    //    Cycles are surfaced richly (with witness edges) in `new_cycles` below,
    //    so the plain CircularDependency findings are dropped here to avoid
    //    double-reporting the same cycle.
    let finding_diff = store.finding_diff(&repository_id, &base_snapshot.id, &head_snapshot.id)?;
    let new_findings: Vec<FindingRecord> = finding_diff
        .new
        .into_iter()
        .filter(|finding| finding.kind != FindingKind::CircularDependency)
        .collect();

    // 2. The files the change touched (for scoping duplication).
    let changed_files =
        store.changed_files(&repository_id, &base_snapshot.id, &head_snapshot.id)?;

    // 3. New dependency cycles WITH witness edges. Head cycles come from the
    //    current graph (file-level, so witnesses carry file:line); a cycle is
    //    new when its module set is not already a cycle in the base snapshot.
    let head_modules = store.current_modules(&repository_id)?;
    let head_dependencies = store.current_dependencies(&repository_id)?;
    let base_cycles: std::collections::HashSet<Vec<String>> = graph::cycles::module_cycles(
        &store.snapshot_module_names(&base_snapshot.id)?,
        &store.snapshot_module_edges(&base_snapshot.id)?,
    )
    .into_iter()
    .collect();
    let new_cycles: Vec<graph::cycles::CycleWitness> =
        graph::cycles::elementary_cycles_with_witness(&head_modules, &head_dependencies)
            .into_iter()
            .filter(|cycle| !base_cycles.contains(&cycle.modules))
            .collect();

    // 4. Duplications the change introduced: clone families with at least one
    //    region in a touched file, so pre-existing clones elsewhere do not drown
    //    out what THIS change added. (Scanning is still repo-wide — that is how a
    //    new block is matched against an existing utility — only the output is
    //    scoped.)
    let touched: std::collections::HashSet<&str> =
        changed_files.touched().map(String::as_str).collect();
    let new_duplications: Vec<graph::dupes::CloneFamily> = if touched.is_empty() {
        Vec::new()
    } else {
        ovecc_indexer::collect_file_tokens(paths, config)
            .map(|files| graph::dupes::detect(&files, 50, 5, true))
            .unwrap_or_default()
            .into_iter()
            .filter(|family| {
                family
                    .instances
                    .iter()
                    .any(|instance| touched.contains(instance.path.as_str()))
            })
            .collect()
    };

    // Category counts over the new findings.
    let count_kinds = |kinds: &[FindingKind]| {
        new_findings
            .iter()
            .filter(|finding| kinds.contains(&finding.kind))
            .count()
    };
    let new_security = count_kinds(&[
        FindingKind::HardcodedSecret,
        FindingKind::InsecurePattern,
        FindingKind::WeakCrypto,
        FindingKind::PermissiveCors,
        FindingKind::VulnerableDependency,
        FindingKind::TaintedFlow,
    ]);
    let new_dead_code = count_kinds(&[
        FindingKind::UnusedExport,
        FindingKind::UnusedFile,
        FindingKind::UnusedDependency,
    ]);
    let new_complexity = count_kinds(&[FindingKind::HighComplexity]);
    let max_new_severity = new_findings.iter().map(|finding| finding.severity).max();

    let failed = review_crosses_threshold(
        fail_on,
        &new_findings,
        &new_cycles,
        &new_duplications,
        max_new_severity,
    );
    let risk = review_risk(max_new_severity, &new_cycles, &new_duplications);
    let rationale = review_rationale(
        &new_cycles,
        new_security,
        new_complexity,
        new_dead_code,
        &new_duplications,
    );

    Ok(ReviewReport {
        base: base_snapshot.id,
        head: head_snapshot.id,
        verdict: if failed { "fail" } else { "pass" }.to_string(),
        risk: risk.as_str().to_string(),
        rationale,
        summary: ReviewSummary {
            files_added: changed_files.added.len(),
            files_modified: changed_files.modified.len(),
            new_findings: new_findings.len(),
            new_security,
            new_dead_code,
            new_complexity,
            new_cycles: new_cycles.len(),
            new_duplications: new_duplications.len(),
            resolved_findings: finding_diff.resolved.len(),
        },
        new_findings,
        new_cycles,
        new_duplications,
        changed_files,
    })
}

/// Whether the change fails the gate at `fail_on`. A new cycle always fails (it
/// is an architectural regression); findings fail by severity; duplication only
/// counts under `any`.
fn review_crosses_threshold(
    fail_on: FailOn,
    new_findings: &[FindingRecord],
    new_cycles: &[graph::cycles::CycleWitness],
    new_duplications: &[graph::dupes::CloneFamily],
    max_new_severity: Option<Severity>,
) -> bool {
    match fail_on {
        FailOn::Any => {
            !new_findings.is_empty() || !new_cycles.is_empty() || !new_duplications.is_empty()
        }
        FailOn::Medium => !new_cycles.is_empty() || max_new_severity >= Some(Severity::Medium),
        FailOn::High => !new_cycles.is_empty() || max_new_severity >= Some(Severity::High),
    }
}

fn review_risk(
    max_new_severity: Option<Severity>,
    new_cycles: &[graph::cycles::CycleWitness],
    new_duplications: &[graph::dupes::CloneFamily],
) -> RiskLevel {
    if max_new_severity == Some(Severity::Critical) {
        RiskLevel::Critical
    } else if !new_cycles.is_empty() || max_new_severity == Some(Severity::High) {
        RiskLevel::High
    } else if max_new_severity == Some(Severity::Medium) || !new_duplications.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn review_rationale(
    new_cycles: &[graph::cycles::CycleWitness],
    new_security: usize,
    new_complexity: usize,
    new_dead_code: usize,
    new_duplications: &[graph::dupes::CloneFamily],
) -> Vec<String> {
    let mut rationale = Vec::new();
    if !new_cycles.is_empty() {
        let names: Vec<String> = new_cycles
            .iter()
            .map(|cycle| format_cycle_path(&cycle.modules, " ↔ ", " → "))
            .collect();
        rationale.push(format!(
            "{} new dependency cycle(s): {}",
            new_cycles.len(),
            names.join("; ")
        ));
    }
    if new_security > 0 {
        rationale.push(format!("{new_security} new security finding(s)"));
    }
    if new_complexity > 0 {
        rationale.push(format!("{new_complexity} new high-complexity function(s)"));
    }
    if new_dead_code > 0 {
        rationale.push(format!("{new_dead_code} new dead-code finding(s)"));
    }
    if !new_duplications.is_empty() {
        rationale.push(format!("{} new duplication(s)", new_duplications.len()));
    }
    if rationale.is_empty() {
        rationale.push("no new defects introduced by this change".to_string());
    }
    rationale
}

/// Renders a cycle's module path for display. A 2-node loop is genuinely
/// bidirectional (`a ↔ b`); a longer loop is *directed*, so it reads as the
/// actual path back to the start (`a → b → c → a`) rather than a misleading
/// `a ↔ b ↔ c` (which would imply `a` and `c` depend on each other directly).
fn format_cycle_path(modules: &[String], bidi: &str, arrow: &str) -> String {
    match modules.first() {
        Some(first) if modules.len() >= 3 => {
            let mut path = modules.join(arrow);
            path.push_str(arrow);
            path.push_str(first);
            path
        }
        _ => modules.join(bidi),
    }
}

fn render_review(report: &ReviewReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("review", report, meta_for("review"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("review", &meta_for("review"))?;
            println!("{}", ndjson_line("review_summary", &report.summary)?);
            for finding in &report.new_findings {
                println!("{}", ndjson_line("new_finding", finding)?);
            }
            for cycle in &report.new_cycles {
                println!("{}", ndjson_line("new_cycle", cycle)?);
            }
            for family in &report.new_duplications {
                println!("{}", ndjson_line("new_duplication", family)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Change review: {}", report.verdict.to_uppercase());
            println!();
            println!("- Base: `{}`", report.base);
            println!("- Head: `{}`", report.head);
            println!("- Risk: **{}**", report.risk);
            println!(
                "- Files: +{} added, ~{} modified",
                report.summary.files_added, report.summary.files_modified
            );
            for reason in &report.rationale {
                println!("- {reason}");
            }

            println!();
            println!("## New dependency cycles ({})", report.new_cycles.len());
            if report.new_cycles.is_empty() {
                println!("_None._");
            }
            for cycle in &report.new_cycles {
                println!();
                println!("### {}", format_cycle_path(&cycle.modules, " ↔ ", " → "));
                for edge in &cycle.edges {
                    let target = edge.to_file.as_deref().unwrap_or(edge.to_module.as_str());
                    println!(
                        "- `{}:{}` imports `{}` → `{}`",
                        edge.from_file, edge.line, edge.specifier, target
                    );
                }
            }

            println!();
            println!("## New findings ({})", report.new_findings.len());
            if report.new_findings.is_empty() {
                println!("_None._");
            }
            for finding in &report.new_findings {
                let rule = finding.rule_name.as_deref().unwrap_or("-");
                let fix = finding.kind.fix_spec();
                let auto = if fix.auto_fixable {
                    ", auto-fixable"
                } else {
                    ""
                };
                println!(
                    "- **[{:?}] {:?}**{} — {} _(rule `{}`)_ · action: `{}`{}",
                    finding.severity,
                    finding.kind,
                    first_evidence(finding),
                    finding.title,
                    rule,
                    fix.kind,
                    auto
                );
            }

            println!();
            println!("## New duplications ({})", report.new_duplications.len());
            if report.new_duplications.is_empty() {
                println!("_None._");
            }
            for (rank, family) in report.new_duplications.iter().enumerate() {
                println!();
                println!(
                    "### Clone {} ({} tokens, {} lines, {} copies)",
                    rank + 1,
                    family.token_length,
                    family.line_span,
                    family.instances.len()
                );
                for instance in &family.instances {
                    println!(
                        "- `{}:{}-{}`",
                        instance.path, instance.start_line, instance.end_line
                    );
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Review: {} (risk {}) {} -> {}",
                report.verdict, report.risk, report.base, report.head
            );
            for reason in &report.rationale {
                println!("  - {reason}");
            }
            if !report.new_cycles.is_empty() {
                println!("New cycles:");
                for cycle in &report.new_cycles {
                    println!("  {}", format_cycle_path(&cycle.modules, " <-> ", " -> "));
                    for edge in &cycle.edges {
                        println!(
                            "    {}:{} imports {} -> {}",
                            edge.from_file,
                            edge.line,
                            edge.specifier,
                            edge.to_file.as_deref().unwrap_or(edge.to_module.as_str())
                        );
                    }
                }
            }
            if !report.new_findings.is_empty() {
                println!("New findings:");
                for finding in &report.new_findings {
                    println!(
                        "  [{:?}] {:?}{} {}",
                        finding.severity,
                        finding.kind,
                        first_evidence(finding),
                        finding.title
                    );
                }
            }
            if !report.new_duplications.is_empty() {
                println!("New duplications:");
                for family in &report.new_duplications {
                    println!(
                        "  {} tokens / {} lines / {} copies",
                        family.token_length,
                        family.line_span,
                        family.instances.len()
                    );
                    for instance in &family.instances {
                        println!(
                            "    {}:{}-{}",
                            instance.path, instance.start_line, instance.end_line
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc report (one-shot composite)
// ---------------------------------------------------------------------------

/// First evidence location of a finding, formatted as ` (path:line)`, or empty.
fn first_evidence(finding: &FindingRecord) -> String {
    finding
        .evidence
        .first()
        .map(|evidence| format!(" ({})", format_evidence(evidence)))
        .unwrap_or_default()
}

/// Renders a one-shot report stitching health, cycles, all findings, a security
/// breakdown, and hotspots — so the report no longer has to be hand-assembled
/// from six commands. Markdown for humans; structured JSON for agents.
fn render_full_report(paths: &ProjectPaths, format: OutputFormat) -> Result<()> {
    let repository_id = paths.repository_id().0;
    // `load_summary` and `load_hotspots` each open and release their own store,
    // so gather them before opening one here: DuckDB permits only one
    // connection per file per process.
    let summary = load_summary(paths)?;
    let hotspots = load_hotspots(paths, 10)?;

    let store = open_store(paths)?;
    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let cycles: Vec<Vec<String>> = ovecc_graph::cycles::elementary_cycles(&modules, &dependencies)
        .into_iter()
        .map(|mut members| {
            if let Some(first) = members.first().cloned() {
                members.push(first);
            }
            members
        })
        .collect();
    let mut findings = store.findings(&repository_id, None)?;
    drop(store);
    // Highest severity first, then stable by title, for deterministic output.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
    });
    let security = build_security_report(&findings, None);

    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            let data = serde_json::json!({
                "summary": summary,
                "cycles": cycles,
                "findings": findings,
                "security": security,
                "hotspots": hotspots,
            });
            emit_json("report", &data, meta_for("report"))?;
        }
        _ => {
            println!("# Architecture report: {}", summary.repository_root);
            println!();
            println!("## Health");
            println!();
            println!(
                "- Files: {} · Modules: {} · Dependencies: {} ({} external)",
                summary.files, summary.modules, summary.dependencies, summary.external_dependencies
            );
            println!(
                "- Circular dependencies: {} · Coupling density: {:.2}% · Risk: **{}**",
                summary.circular_dependencies,
                summary.coupling_density * 100.0,
                summary.risk_score.as_str()
            );
            println!();
            println!("## Circular dependencies ({})", cycles.len());
            println!();
            if cycles.is_empty() {
                println!("_None._");
            }
            for cycle in &cycles {
                println!("- `{}`", cycle.join(" -> "));
            }
            println!();
            println!("## Findings ({})", findings.len());
            println!();
            if findings.is_empty() {
                println!("_None._");
            }
            for finding in &findings {
                println!(
                    "- [{:?}] {}{}",
                    finding.severity,
                    finding.title,
                    first_evidence(finding)
                );
            }
            println!();
            println!("## Security");
            println!();
            println!(
                "- Secrets {}, insecure {}, weak-crypto {}, CORS {}, tainted-flows {} (total {})",
                security.secrets,
                security.insecure_patterns,
                security.weak_crypto,
                security.permissive_cors,
                security.tainted_flows,
                security.total
            );
            println!();
            println!("## Hotspots");
            println!();
            if hotspots.hotspots.is_empty() {
                println!("_None._");
            }
            for (rank, hotspot) in hotspots.hotspots.iter().enumerate() {
                println!(
                    "{}. {} (score {:.0}, fan-in {}, fan-out {})",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    hotspot.fan_in,
                    hotspot.fan_out
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc dupes (clone detection)
// ---------------------------------------------------------------------------

/// Duplication report: scan parameters and the clone families found.
#[derive(serde::Serialize)]
struct DupesReport {
    files_scanned: usize,
    min_tokens: usize,
    min_lines: usize,
    clone_families: usize,
    duplicated_lines: u32,
    families: Vec<ovecc_graph::dupes::CloneFamily>,
}

fn render_dupes(report: &DupesReport, format: OutputFormat) -> Result<()> {
    let plural = |n: usize| if n == 1 { "y" } else { "ies" };
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("dupes", report, meta_for("dupes"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("dupes", &meta_for("dupes"))?;
            for family in &report.families {
                println!("{}", ndjson_line("clone_family", family)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Duplication ({} clone famil{})",
                report.clone_families,
                plural(report.clone_families)
            );
            println!();
            println!("- Files scanned: {}", report.files_scanned);
            println!(
                "- Thresholds: >= {} tokens, >= {} lines",
                report.min_tokens, report.min_lines
            );
            for (rank, family) in report.families.iter().enumerate() {
                println!();
                println!(
                    "## Clone {} ({} tokens, {} lines, {} copies)",
                    rank + 1,
                    family.token_length,
                    family.line_span,
                    family.instances.len()
                );
                for instance in &family.instances {
                    println!(
                        "- `{}:{}-{}`",
                        instance.path, instance.start_line, instance.end_line
                    );
                }
            }
        }
        OutputFormat::Text => {
            println!(
                "Duplication: {} clone famil{} (scanned {} files, >= {} tokens / {} lines)",
                report.clone_families,
                plural(report.clone_families),
                report.files_scanned,
                report.min_tokens,
                report.min_lines
            );
            for (rank, family) in report.families.iter().enumerate() {
                println!();
                println!(
                    "{}. {} tokens / {} lines, {} copies:",
                    rank + 1,
                    family.token_length,
                    family.line_span,
                    family.instances.len()
                );
                for instance in &family.instances {
                    println!(
                        "   {}:{}-{}",
                        instance.path, instance.start_line, instance.end_line
                    );
                }
            }
            if report.families.is_empty() {
                println!("  (no duplication above the threshold)");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc health (complexity hotspots)
// ---------------------------------------------------------------------------

/// Code-health report: functions over the complexity thresholds.
#[derive(serde::Serialize)]
struct HealthReport {
    high_complexity_functions: usize,
    findings: Vec<FindingRecord>,
}

fn render_health(report: &HealthReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("health", report, meta_for("health"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("health", &meta_for("health"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("complexity", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Health: {} high-complexity function(s)",
                report.high_complexity_functions
            );
            println!();
            if report.findings.is_empty() {
                println!("_No functions over the complexity thresholds._");
            }
            for finding in &report.findings {
                println!(
                    "- [{:?}] {}{}",
                    finding.severity,
                    finding.title,
                    first_evidence(finding)
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "Code health: {} high-complexity function(s)",
                report.high_complexity_functions
            );
            for finding in &report.findings {
                println!();
                println!("[{:?}] {}", finding.severity, finding.title);
                for evidence in &finding.evidence {
                    println!("  {}", format_evidence(evidence));
                }
            }
            if report.findings.is_empty() {
                println!("  (no functions over the complexity thresholds)");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ovecc deadcode (unused exports / files)
// ---------------------------------------------------------------------------

/// Dead-code report: unused exports and unreachable files.
#[derive(serde::Serialize)]
struct DeadcodeReport {
    unused_exports: usize,
    unused_files: usize,
    unused_dependencies: usize,
    findings: Vec<FindingRecord>,
}

fn render_deadcode(report: &DeadcodeReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json_with_fix("deadcode", report)?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("deadcode", &meta_for("deadcode"))?;
            for finding in &report.findings {
                println!("{}", ndjson_line("dead_code", finding)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Dead code ({} unused export(s), {} unused file(s), {} unused dependency(ies))",
                report.unused_exports, report.unused_files, report.unused_dependencies
            );
            println!();
            if report.findings.is_empty() {
                println!("_No dead code detected (or no entry points)._");
            }
            for finding in &report.findings {
                println!(
                    "- [{:?}] {}{}",
                    finding.severity,
                    finding.title,
                    first_evidence(finding)
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "Dead code: {} unused export(s), {} unused file(s), {} unused dependency(ies)",
                report.unused_exports, report.unused_files, report.unused_dependencies
            );
            for finding in &report.findings {
                println!();
                println!("[{:?}] {}", finding.severity, finding.title);
                for evidence in &finding.evidence {
                    println!("  {}", format_evidence(evidence));
                }
            }
            if report.findings.is_empty() {
                println!("  (none — or no entry points detected)");
            }
        }
    }
    Ok(())
}

/// Resolves a CLI ref argument for `diff`/`drift`. Snapshot keywords
/// (`latest`/`previous`/`base`) and `snapshot:` IDs pass through unchanged;
/// anything else is resolved as a Git ref to its commit SHA, which
/// is then matched against the snapshot commits.
fn resolve_ref(root: &std::path::Path, reference: &str) -> String {
    if matches!(reference, "latest" | "previous" | "base") || reference.starts_with("snapshot:") {
        return reference.to_string();
    }
    ovecc_git::resolve_ref(root, reference).unwrap_or_else(|| reference.to_string())
}

fn load_config(paths: &ProjectPaths, format: Option<FormatArg>) -> Result<OveccConfig> {
    let overrides = ConfigOverrides {
        format: format.map(Into::into),
        ..Default::default()
    };
    Ok(OveccConfig::load(&paths.root, &overrides)?)
}

fn open_store(paths: &ProjectPaths) -> Result<ArchitectureStore> {
    if !paths.db_path.exists() {
        return Err(OveccError::Index {
            message: format!(
                "architecture database does not exist at {}; run 'ovecc index' first",
                paths.db_path.display()
            ),
            source: None,
        }
        .into());
    }
    let mut store = ArchitectureStore::open(&paths.db_path)?;
    store.initialize_schema()?;
    Ok(store)
}

fn diff_crosses_threshold(report: &DiffReport, fail_on: FailOn) -> bool {
    fn rank(level: RiskLevel) -> u8 {
        match level {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 1,
            RiskLevel::High => 2,
            RiskLevel::Critical => 3,
        }
    }
    match fail_on {
        FailOn::Any => {
            !(report.added_modules.is_empty()
                && report.removed_modules.is_empty()
                && report.added_dependencies.is_empty()
                && report.removed_dependencies.is_empty())
        }
        FailOn::Medium => rank(report.risk_score) >= 1,
        FailOn::High => rank(report.risk_score) >= 2,
    }
}

fn load_summary(paths: &ProjectPaths) -> Result<SummaryReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let files = store.current_file_count(&repository_id)?;
    let snapshot_id = store
        .latest_snapshot(&repository_id)?
        .map(|snapshot| snapshot.id);
    let repository_root = store
        .repository_root(&repository_id)?
        .unwrap_or_else(|| paths.root_display());
    let boundary_violations = store
        .findings(&repository_id, None)?
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::CrossDomainDependency
                    | FindingKind::ForbiddenImport
                    | FindingKind::LayerViolation
            )
        })
        .count();

    Ok(graph::summarize(
        repository_root,
        snapshot_id,
        files,
        modules,
        &dependencies,
        boundary_violations,
    ))
}

/// Blast-radius impact over the persisted architecture graph. Loads the
/// graph view, resolves the target (module, symbol, `api:`, or `table:`),
/// and traverses it. Returns `None` when nothing matches the target.
/// Loads the persisted graph view (nodes + edges) for in-memory traversal.
fn load_graph(
    store: &ArchitectureStore,
    repository_id: &str,
) -> Result<(Vec<BlastNode>, Vec<BlastEdge>)> {
    let nodes = store
        .graph_nodes(repository_id)?
        .into_iter()
        .map(|(id, kind, label)| BlastNode { id, kind, label })
        .collect();
    let edges = store
        .graph_edges(repository_id)?
        .into_iter()
        .map(|(source, target, kind)| BlastEdge {
            source,
            target,
            kind,
        })
        .collect();
    Ok((nodes, edges))
}

fn load_impact(
    paths: &ProjectPaths,
    target: &str,
    direction: ImpactDirection,
    max_depth: usize,
) -> Result<Option<BlastResult>> {
    let store = open_store(paths)?;
    let (nodes, edges) = load_graph(&store, &paths.repository_id().0)?;
    let Some(node) = blast::resolve_target(target, &nodes) else {
        return Ok(None);
    };
    // A file target carries no architectural edges of its own — dependency edges
    // are module-level — so a raw file node yields an empty (and falsely
    // reassuring "Low risk") blast radius. Redirect it to the module that
    // `contains` it, so `impact src/foo/bar.ts` answers for module `foo`.
    let node = if node.kind == "file" {
        edges
            .iter()
            .find(|edge| edge.kind == "contains" && edge.target == node.id)
            .and_then(|edge| nodes.iter().find(|candidate| candidate.id == edge.source))
            .unwrap_or(node)
    } else {
        node
    };
    Ok(blast::blast_radius(
        &nodes, &edges, &node.id, direction, max_depth,
    ))
}

/// One NDJSON line: the serialized payload with an injected `"type"` tag.
fn ndjson_line<T: serde::Serialize>(kind: &str, payload: &T) -> Result<String> {
    let mut value = serde_json::to_value(payload)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "type".to_string(),
            serde_json::Value::String(kind.to_string()),
        );
    }
    Ok(serde_json::to_string(&value)?)
}

/// Serializes the payload, dropping the given top-level list fields (they are
/// emitted as separate NDJSON lines instead).
fn ndjson_header<T: serde::Serialize>(kind: &str, payload: &T, drop: &[&str]) -> Result<String> {
    let mut value = serde_json::to_value(payload)?;
    if let serde_json::Value::Object(map) = &mut value {
        for field in drop {
            map.remove(*field);
        }
        map.insert(
            "type".to_string(),
            serde_json::Value::String(kind.to_string()),
        );
    }
    Ok(serde_json::to_string(&value)?)
}

fn render_index_report(report: &IndexReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("index", report, meta_for("index"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("index", &meta_for("index"))?;
            println!("{}", ndjson_line("index", report)?);
        }
        OutputFormat::Markdown => {
            println!("# Ovecc index");
            println!();
            println!("- Repository: `{}`", report.repository_root);
            println!("- Snapshot: `{}`", report.snapshot_id);
            println!("- Files scanned: {}", report.files_scanned);
            println!("- Files indexed: {}", report.files_indexed);
            println!("- Files parsed: {}", report.files_parsed);
            println!("- Files from cache: {}", report.files_from_cache);
            println!("- Modules: {}", report.modules);
            println!("- Dependencies: {}", report.dependencies);
            println!("- External dependencies: {}", report.external_dependencies);
            println!("- Symbols: {}", report.symbols);
            println!("- Calls: {}", report.calls);
            println!("- APIs: {}", report.apis);
            println!("- Tables: {}", report.tables);
            println!("- Commits ingested: {}", report.commits_ingested);
            if !report.parse_failures.is_empty() {
                println!();
                println!("## Parse failures");
                println!();
                for failure in &report.parse_failures {
                    println!("- `{}`: {}", failure.path, failure.message);
                }
            }
        }
        OutputFormat::Text => {
            println!("Indexed repository: {}", report.repository_root);
            println!("Database: {}", report.database_path);
            println!("Snapshot: {}", report.snapshot_id);
            println!("Files scanned: {}", report.files_scanned);
            println!("Files indexed: {}", report.files_indexed);
            println!("Files parsed: {}", report.files_parsed);
            println!("Files from cache: {}", report.files_from_cache);
            println!("Modules: {}", report.modules);
            println!("Dependencies: {}", report.dependencies);
            println!("External dependencies: {}", report.external_dependencies);
            println!("Symbols: {}", report.symbols);
            println!("Calls: {}", report.calls);
            println!("APIs: {}", report.apis);
            println!("Tables: {}", report.tables);
            println!("Commits ingested: {}", report.commits_ingested);
            if !report.parse_failures.is_empty() {
                println!();
                println!("Parse failures: {}", report.parse_failures.len());
                for failure in &report.parse_failures {
                    println!("  {}: {}", failure.path, failure.message);
                }
            }
        }
    }
    Ok(())
}

fn render_summary_report(report: &SummaryReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("summary", report, meta_for("summary"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("summary", &meta_for("summary"))?;
            println!("{}", ndjson_header("summary", report, &["hotspots"])?);
            for hotspot in &report.hotspots {
                println!("{}", ndjson_line("hotspot", hotspot)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Architecture summary");
            println!();
            println!("- Repository: `{}`", report.repository_root);
            if let Some(snapshot_id) = &report.snapshot_id {
                println!("- Snapshot: `{snapshot_id}`");
            }
            println!("- Files: {}", report.files);
            println!("- Modules: {}", report.modules);
            println!("- Dependencies: {}", report.dependencies);
            println!("- External dependencies: {}", report.external_dependencies);
            println!("- Circular dependencies: {}", report.circular_dependencies);
            println!("- Boundary violations: {}", report.boundary_violations);
            println!(
                "- Coupling density: {:.2}%",
                report.coupling_density * 100.0
            );
            println!("- Risk score: **{}**", report.risk_score.as_str());
            if !report.hotspots.is_empty() {
                println!();
                println!("## Hotspots");
                println!();
                println!("| Module | Score | Fan-in | Fan-out | Instability |");
                println!("| --- | --- | --- | --- | --- |");
                for hotspot in &report.hotspots {
                    println!(
                        "| {} | {} | {} | {} | {:.2} |",
                        hotspot.module,
                        hotspot.score,
                        hotspot.fan_in,
                        hotspot.fan_out,
                        hotspot.instability
                    );
                }
            }
        }
        OutputFormat::Text => {
            println!("Repository: {}", report.repository_root);
            if let Some(snapshot_id) = &report.snapshot_id {
                println!("Snapshot: {snapshot_id}");
            }
            println!("Files: {}", report.files);
            println!("Modules: {}", report.modules);
            println!("Dependencies: {}", report.dependencies);
            println!("External dependencies: {}", report.external_dependencies);
            println!("Circular deps: {}", report.circular_dependencies);
            println!("Boundary violations: {}", report.boundary_violations);
            println!("Coupling density: {:.2}%", report.coupling_density * 100.0);
            println!("Risk score: {}", report.risk_score.as_str());

            if !report.hotspots.is_empty() {
                println!();
                println!("Hotspots:");
                for hotspot in &report.hotspots {
                    println!(
                        "  {} (score {}, fan-in {}, fan-out {}, instability {:.2})",
                        hotspot.module,
                        hotspot.score,
                        hotspot.fan_in,
                        hotspot.fan_out,
                        hotspot.instability
                    );
                }
            }
        }
    }
    Ok(())
}

fn render_blast(target: &str, result: Option<&BlastResult>, format: OutputFormat) -> Result<()> {
    let Some(result) = result else {
        match format {
            OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => emit_json(
                "impact",
                &serde_json::json!({"target": target, "matched": false}),
                meta_for("impact"),
            )?,
            OutputFormat::Ndjson => {
                emit_ndjson_meta("impact", &meta_for("impact"))?;
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"type": "impact", "target": target, "matched": false})
                    )?
                );
            }
            OutputFormat::Markdown => {
                println!("# Impact: {target}");
                println!();
                println!("No matching architecture element.");
            }
            OutputFormat::Text => {
                println!("Impact: {target}");
                println!("No matching architecture element.");
            }
        }
        return Ok(());
    };

    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("impact", result, meta_for("impact"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("impact", &meta_for("impact"))?;
            println!(
                "{}",
                ndjson_header("impact", result, &["impacted_labels", "paths"])?
            );
            for path in &result.paths {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({"type": "path", "nodes": path}))?
                );
            }
        }
        OutputFormat::Markdown => {
            println!("# Impact: {}", result.target_label);
            println!();
            println!("- Affected modules: {}", result.impacted_modules);
            println!("- Affected APIs: {}", result.impacted_apis);
            println!("- Affected tables: {}", result.impacted_tables);
            println!("- Affected symbols: {}", result.impacted_symbols);
            println!("- Affected files: {}", result.impacted_files);
            println!(
                "- Risk: **{}** ({})",
                result.risk.as_str(),
                result.risk_value
            );
            if !result.paths.is_empty() {
                println!();
                println!("## Top paths");
                println!();
                for path in &result.paths {
                    println!("- `{}`", path.join(" -> "));
                }
            }
        }
        OutputFormat::Text => {
            println!("Impact: {}", result.target_label);
            println!("Affected modules: {}", result.impacted_modules);
            println!("Affected APIs: {}", result.impacted_apis);
            println!("Affected tables: {}", result.impacted_tables);
            println!("Affected symbols: {}", result.impacted_symbols);
            println!("Affected files: {}", result.impacted_files);
            println!("Risk: {} ({})", result.risk.as_str(), result.risk_value);
            if !result.paths.is_empty() {
                println!();
                println!("Top paths:");
                for path in &result.paths {
                    println!("  {}", path.join(" -> "));
                }
            }
        }
    }
    Ok(())
}

fn render_diff_report(report: &DiffReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("diff", report, meta_for("diff"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("diff", &meta_for("diff"))?;
            println!(
                "{}",
                ndjson_header(
                    "diff",
                    report,
                    &[
                        "added_modules",
                        "removed_modules",
                        "added_dependencies",
                        "removed_dependencies",
                    ],
                )?
            );
            for module in &report.added_modules {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"type": "added_module", "name": module})
                    )?
                );
            }
            for module in &report.removed_modules {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"type": "removed_module", "name": module})
                    )?
                );
            }
            for dependency in &report.added_dependencies {
                println!("{}", ndjson_line("added_dependency", dependency)?);
            }
            for dependency in &report.removed_dependencies {
                println!("{}", ndjson_line("removed_dependency", dependency)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# Architecture diff: `{}` -> `{}`",
                report.base.id, report.head.id
            );
            println!();
            println!("- Added modules: {}", report.added_modules.len());
            println!("- Removed modules: {}", report.removed_modules.len());
            println!("- Added dependencies: {}", report.added_dependencies.len());
            println!(
                "- Removed dependencies: {}",
                report.removed_dependencies.len()
            );
            println!("- Risk: **{}**", report.risk_score.as_str());
            print_markdown_modules("New modules", &report.added_modules);
            print_markdown_modules("Removed modules", &report.removed_modules);
            print_markdown_dependencies("New dependencies", &report.added_dependencies);
            print_markdown_dependencies("Removed dependencies", &report.removed_dependencies);
        }
        OutputFormat::Text => {
            println!(
                "Architecture diff: {} -> {}",
                report.base.id, report.head.id
            );
            println!("Added modules: {}", report.added_modules.len());
            println!("Removed modules: {}", report.removed_modules.len());
            println!("Added dependencies: {}", report.added_dependencies.len());
            println!(
                "Removed dependencies: {}",
                report.removed_dependencies.len()
            );
            println!("Risk: {}", report.risk_score.as_str());

            print_modules("New modules", &report.added_modules);
            print_modules("Removed modules", &report.removed_modules);
            print_dependencies("New dependencies", &report.added_dependencies);
            print_dependencies("Removed dependencies", &report.removed_dependencies);
        }
    }
    Ok(())
}

fn render_drift_report(report: &DriftReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("drift", report, meta_for("drift"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("drift", &meta_for("drift"))?;
            println!("{}", ndjson_line("drift", report)?);
        }
        OutputFormat::Markdown => {
            println!("# Drift: `{}` -> `{}`", report.base.id, report.head.id);
            println!();
            println!("- Coupling: {:+.2}%", report.coupling_delta_percent);
            println!("- Trend: **{}**", report.trend.as_str());
            println!();
            println!("| Metric | Base | Head | Δ |");
            println!("| --- | --- | --- | --- |");
            for delta in &report.metric_deltas {
                println!(
                    "| {} | {} | {} | {:+} |",
                    delta.metric,
                    format_metric(delta.base),
                    format_metric(delta.head),
                    format_metric(delta.head - delta.base)
                );
            }
        }
        OutputFormat::Text => {
            println!("Drift: {} -> {}", report.base.id, report.head.id);
            println!("Coupling: {:+.2}%", report.coupling_delta_percent);
            println!("Trend: {}", report.trend.as_str());
            for delta in &report.metric_deltas {
                let change = delta.head - delta.base;
                if change != 0.0 {
                    println!(
                        "  {}: {} -> {} ({:+})",
                        delta.metric,
                        format_metric(delta.base),
                        format_metric(delta.head),
                        format_metric(change)
                    );
                }
            }
        }
    }
    Ok(())
}

/// Formats a drift metric: integers without a decimal point, others with two.
fn format_metric(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value:.2}")
    }
}

fn print_modules(label: &str, modules: &[String]) {
    if modules.is_empty() {
        return;
    }
    println!();
    println!("{label}:");
    for module in modules {
        println!("  {module}");
    }
}

fn print_dependencies(label: &str, dependencies: &[DependencyEdge]) {
    if dependencies.is_empty() {
        return;
    }
    println!();
    println!("{label}:");
    for dependency in dependencies {
        println!(
            "  {} -> {} ({})",
            dependency.source_module, dependency.target_module, dependency.specifier
        );
    }
}

fn print_markdown_modules(label: &str, modules: &[String]) {
    if modules.is_empty() {
        return;
    }
    println!();
    println!("## {label}");
    println!();
    for module in modules {
        println!("- {module}");
    }
}

fn print_markdown_dependencies(label: &str, dependencies: &[DependencyEdge]) {
    if dependencies.is_empty() {
        return;
    }
    println!();
    println!("## {label}");
    println!();
    for dependency in dependencies {
        println!(
            "- `{} -> {}` ({})",
            dependency.source_module, dependency.target_module, dependency.specifier
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cycle(a: &str, b: &str) -> graph::cycles::CycleWitness {
        graph::cycles::CycleWitness {
            modules: vec![a.to_string(), b.to_string()],
            edges: Vec::new(),
        }
    }

    fn clone_family() -> graph::dupes::CloneFamily {
        graph::dupes::CloneFamily {
            token_length: 60,
            line_span: 8,
            instances: Vec::new(),
        }
    }

    #[test]
    fn no_meta_flag_suppresses_the_meta_block() {
        // Default: a command that carries metric/rule dictionaries has meta.
        SUPPRESS_META.store(false, Ordering::Relaxed);
        assert!(!meta_for("summary").is_empty());
        // Suppressed: every command's meta collapses to empty (so the envelope
        // omits it), while `capabilities` output is unaffected (it never uses
        // meta_for — the contract lives in its `data`).
        SUPPRESS_META.store(true, Ordering::Relaxed);
        assert!(meta_for("summary").is_empty());
        assert!(meta_for("review").is_empty());
        SUPPRESS_META.store(false, Ordering::Relaxed);
    }

    #[test]
    fn review_verdict_respects_fail_on_threshold() {
        // Nothing new → pass at any threshold.
        assert!(!review_crosses_threshold(FailOn::Any, &[], &[], &[], None));
        // A new cycle is an architectural regression: it fails at every level.
        assert!(review_crosses_threshold(
            FailOn::Any,
            &[],
            &[cycle("a", "b")],
            &[],
            None
        ));
        assert!(review_crosses_threshold(
            FailOn::High,
            &[],
            &[cycle("a", "b")],
            &[],
            None
        ));
        // Under `any`, a lone new duplication fails; under medium/high it does not.
        assert!(review_crosses_threshold(
            FailOn::Any,
            &[],
            &[],
            &[clone_family()],
            None
        ));
        assert!(!review_crosses_threshold(
            FailOn::Medium,
            &[],
            &[],
            &[clone_family()],
            None
        ));
        // Findings gate by severity.
        assert!(!review_crosses_threshold(
            FailOn::High,
            &[],
            &[],
            &[],
            Some(Severity::Medium)
        ));
        assert!(review_crosses_threshold(
            FailOn::High,
            &[],
            &[],
            &[],
            Some(Severity::High)
        ));
        assert!(review_crosses_threshold(
            FailOn::Medium,
            &[],
            &[],
            &[],
            Some(Severity::Medium)
        ));
    }

    #[test]
    fn review_risk_band_reflects_worst_signal() {
        assert_eq!(review_risk(None, &[], &[]).as_str(), "Low");
        assert_eq!(
            review_risk(Some(Severity::Medium), &[], &[]).as_str(),
            "Medium"
        );
        // A new duplication alone lifts risk to Medium.
        assert_eq!(review_risk(None, &[], &[clone_family()]).as_str(), "Medium");
        // A new cycle (or a High finding) is High.
        assert_eq!(review_risk(None, &[cycle("a", "b")], &[]).as_str(), "High");
        assert_eq!(review_risk(Some(Severity::High), &[], &[]).as_str(), "High");
        // A Critical finding dominates everything.
        assert_eq!(
            review_risk(Some(Severity::Critical), &[cycle("a", "b")], &[]).as_str(),
            "Critical"
        );
    }

    #[test]
    fn review_rationale_is_empty_message_when_clean() {
        let rationale = review_rationale(&[], 0, 0, 0, &[]);
        assert_eq!(rationale.len(), 1);
        assert!(rationale[0].contains("no new defects"));
        // Populated signals are each spelled out for the verdict explanation.
        let rationale = review_rationale(&[cycle("alpha", "beta")], 2, 1, 3, &[clone_family()]);
        assert!(rationale.iter().any(|r| r.contains("alpha ↔ beta")));
        assert!(rationale.iter().any(|r| r.contains("2 new security")));
        assert!(
            rationale
                .iter()
                .any(|r| r.contains("1 new high-complexity"))
        );
        assert!(rationale.iter().any(|r| r.contains("3 new dead-code")));
        assert!(rationale.iter().any(|r| r.contains("1 new duplication")));
    }
}
