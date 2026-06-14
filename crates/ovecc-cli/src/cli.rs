use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use ovecc_ai::DeterministicExplainer;
use ovecc_core::config::{ConfigOverrides, OutputFormat, OveccConfig, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::facts::{FindingKind, FindingRecord, Severity};
use ovecc_core::legacy::{
    ConventionsReport, DependencyEdge, DiffReport, DriftReport, HotspotsReport, ImpactDirection,
    IndexReport, RiskLevel, SummaryReport,
};
use ovecc_core::query::{Query, TargetSelector};
use ovecc_core::report::ContextSlice;
use ovecc_core::traits::ExplanationProvider;
use ovecc_db::ArchitectureStore;
use ovecc_graph as graph;
use ovecc_graph::blast::{self, BlastEdge, BlastNode, BlastResult};
use ovecc_indexer::index_repository;
use std::path::PathBuf;

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
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Text => OutputFormat::Text,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Ndjson => OutputFormat::Ndjson,
            FormatArg::Markdown => OutputFormat::Markdown,
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
    },
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

pub fn run() -> Result<u8> {
    let cli = Cli::parse();
    let format_override = cli.format;
    let stats = cli.stats;
    let started = std::time::Instant::now();

    let outcome = match cli.command {
        Command::Index { path, no_git } => {
            let root = path.or(cli.repo).unwrap_or_else(|| PathBuf::from("."));
            let paths = ProjectPaths::resolve(root)?;
            let config = load_config(&paths, format_override)?;
            let report = index_repository(&paths, &config, no_git)?;
            render_index_report(&report, config.output.default_format)?;
            if stats {
                render_index_timings(&report.timings);
            }
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
            Ok(violations_exit(&findings, fail_on))
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
            let cycles = ovecc_graph::strongly_connected_modules(&modules, &dependencies);
            print_query_paths("Cycles", &cycles, format)?;
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
                OutputFormat::Json | OutputFormat::Ndjson => println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "source": source.needle(),
                        "target": target.needle(),
                        "depends_on": reached,
                        "path": path,
                    }))?
                ),
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
            println!("{}", serde_json::to_string(&labels)?)
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
            println!("{}", serde_json::to_string(paths)?)
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
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Ndjson => {
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
    let mut fragmented: HashMap<String, (usize, usize)> = HashMap::new();
    for ownership in store.ownership_metrics(&repository_id)? {
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

    Ok(HotspotsReport {
        hotspots: graph::compute_hotspots(
            &modules,
            &dependencies,
            &churn,
            &fragmentation,
            &violations,
            limit,
        ),
    })
}

fn render_hotspots(report: &HotspotsReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Ndjson => {
            for hotspot in &report.hotspots {
                println!("{}", ndjson_line("hotspot", hotspot)?);
            }
        }
        OutputFormat::Markdown => {
            println!("# Hotspots");
            println!();
            println!(
                "| # | Module | Score | Churn | Coupling | Fan-in | Fan-out | Owner frag. | Violations |"
            );
            println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
            for (rank, hotspot) in report.hotspots.iter().enumerate() {
                println!(
                    "| {} | {} | {:.0} | {:.0} | {} | {} | {} | {:.0}% | {} |",
                    rank + 1,
                    hotspot.module,
                    hotspot.score,
                    hotspot.churn,
                    hotspot.coupling,
                    hotspot.fan_in,
                    hotspot.fan_out,
                    hotspot.ownership_fragmentation * 100.0,
                    hotspot.violations
                );
            }
        }
        OutputFormat::Text => {
            println!("Hotspots:");
            for (rank, hotspot) in report.hotspots.iter().enumerate() {
                println!();
                println!("{}. {}", rank + 1, hotspot.module);
                println!("   Score: {:.0}", hotspot.score);
                println!("   Churn: {:.0}", hotspot.churn);
                println!(
                    "   Coupling: {} (fan-in {}, fan-out {})",
                    hotspot.coupling, hotspot.fan_in, hotspot.fan_out
                );
                println!(
                    "   Ownership fragmentation: {:.0}%",
                    hotspot.ownership_fragmentation * 100.0
                );
                println!("   Violations: {}", hotspot.violations);
            }
            if report.hotspots.is_empty() {
                println!("  (none)");
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

/// CI exit code for `violations`: 1 when a finding crosses the threshold.
fn violations_exit(findings: &[FindingRecord], fail_on: Option<FailOn>) -> u8 {
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

fn render_violations(findings: &[FindingRecord], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(findings)?),
        OutputFormat::Ndjson => {
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
    }
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
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Ndjson => println!("{}", ndjson_line("index", report)?),
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
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Ndjson => {
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
            OutputFormat::Json | OutputFormat::Ndjson => println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"target": target, "matched": false}))?
            ),
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
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(result)?),
        OutputFormat::Ndjson => {
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
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Ndjson => {
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
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Ndjson => println!("{}", ndjson_line("drift", report)?),
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
