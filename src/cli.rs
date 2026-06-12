use crate::config::ProjectPaths;
use crate::graph;
use crate::indexer::index_repository;
use crate::model::{
    DiffReport, DriftReport, ImpactDirection, ImpactReport, IndexReport, RiskLevel, SummaryReport,
};
use crate::storage::ArchitectureStore;
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ovecc")]
#[command(about = "Deterministic architecture intelligence for repositories")]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    repo: Option<PathBuf>,

    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Build or update the local architecture database.
    Index {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Show current architecture health.
    Summary,
    /// Analyze blast radius for a module.
    Impact {
        target: String,
        #[arg(long, value_enum, default_value_t = ImpactDirection::Downstream)]
        direction: ImpactDirection,
        #[arg(long, default_value_t = 6)]
        max_depth: usize,
    },
    /// Compare two stored architecture snapshots.
    Diff {
        #[arg(default_value = "previous")]
        base: String,
        #[arg(default_value = "latest")]
        head: String,
    },
    /// Compare the previous and latest architecture snapshots.
    Drift,
}

pub fn run() -> Result<u8> {
    let cli = Cli::parse();

    match cli.command {
        Command::Index { path } => {
            let root = path.or(cli.repo).unwrap_or_else(|| PathBuf::from("."));
            let paths = ProjectPaths::resolve(root)?;
            let report = index_repository(&paths)?;
            render_index_report(&report, cli.format)?;
            Ok(0)
        }
        Command::Summary => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let report = load_summary(&paths)?;
            render_summary_report(&report, cli.format)?;
            Ok(0)
        }
        Command::Impact {
            target,
            direction,
            max_depth,
        } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let report = load_impact(&paths, &target, direction, max_depth)?;
            render_impact_report(&report, cli.format)?;
            Ok(0)
        }
        Command::Diff { base, head } => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let mut store = open_store(&paths)?;
            let report = store.diff(&paths.repository_id(), &base, &head)?;
            render_diff_report(&report, cli.format)?;
            Ok(
                if matches!(report.risk_score, RiskLevel::High | RiskLevel::Critical) {
                    1
                } else {
                    0
                },
            )
        }
        Command::Drift => {
            let paths = ProjectPaths::resolve(cli.repo.unwrap_or_else(|| PathBuf::from(".")))?;
            let mut store = open_store(&paths)?;
            let report = store.drift(&paths.repository_id())?;
            render_drift_report(&report, cli.format)?;
            Ok(0)
        }
    }
}

fn open_store(paths: &ProjectPaths) -> Result<ArchitectureStore> {
    if !paths.db_path.exists() {
        return Err(anyhow!(
            "architecture database does not exist at {}; run 'ovecc index' first",
            paths.db_path.display()
        ));
    }
    let store = ArchitectureStore::open(&paths.db_path)?;
    store.initialize_schema()?;
    Ok(store)
}

fn load_summary(paths: &ProjectPaths) -> Result<SummaryReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id();
    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    let files = store.current_file_count(&repository_id)?;
    let snapshot_id = store
        .latest_snapshot(&repository_id)?
        .map(|snapshot| snapshot.id);
    let repository_root = store
        .repository_root(&repository_id)?
        .unwrap_or_else(|| paths.root_display());

    Ok(graph::summarize(
        repository_root,
        snapshot_id,
        files,
        modules,
        &dependencies,
    ))
}

fn load_impact(
    paths: &ProjectPaths,
    target: &str,
    direction: ImpactDirection,
    max_depth: usize,
) -> Result<ImpactReport> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id();
    let modules = store.current_modules(&repository_id)?;
    let dependencies = store.current_dependencies(&repository_id)?;
    Ok(graph::impact(
        target,
        direction,
        max_depth,
        &modules,
        &dependencies,
    ))
}

fn render_index_report(report: &IndexReport, format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("Indexed repository: {}", report.repository_root);
    println!("Database: {}", report.database_path);
    println!("Snapshot: {}", report.snapshot_id);
    println!("Files scanned: {}", report.files_scanned);
    println!("Files indexed: {}", report.files_indexed);
    println!("Modules: {}", report.modules);
    println!("Dependencies: {}", report.dependencies);
    println!("External dependencies: {}", report.external_dependencies);
    Ok(())
}

fn render_summary_report(report: &SummaryReport, format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("Repository: {}", report.repository_root);
    if let Some(snapshot_id) = &report.snapshot_id {
        println!("Snapshot: {snapshot_id}");
    }
    println!("Files: {}", report.files);
    println!("Modules: {}", report.modules);
    println!("Dependencies: {}", report.dependencies);
    println!("External dependencies: {}", report.external_dependencies);
    println!("Circular deps: {}", report.circular_dependencies);
    println!("Coupling density: {:.2}%", report.coupling_density * 100.0);
    println!("Risk score: {}", report.risk_score.as_str());

    if !report.hotspots.is_empty() {
        println!();
        println!("Hotspots:");
        for hotspot in &report.hotspots {
            println!(
                "  {} (score {}, fan-in {}, fan-out {})",
                hotspot.module, hotspot.score, hotspot.fan_in, hotspot.fan_out
            );
        }
    }
    Ok(())
}

fn render_impact_report(report: &ImpactReport, format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("Impact: {}", report.target);
    match &report.matched_module {
        Some(module) => println!("Matched module: {module}"),
        None => {
            println!("Matched module: none");
            println!("Risk: Low");
            return Ok(());
        }
    }
    println!("Direction: {:?}", report.direction);
    println!("Affected modules: {}", report.affected_modules.len());
    println!("Dependency paths: {}", report.dependency_paths.len());
    println!("Risk: {}", report.risk_score.as_str());

    if !report.affected_modules.is_empty() {
        println!();
        println!("Modules:");
        for module in &report.affected_modules {
            println!("  {module}");
        }
    }

    if !report.dependency_paths.is_empty() {
        println!();
        println!("Top paths:");
        for path in &report.dependency_paths {
            println!("  {}", path.join(" -> "));
        }
    }
    Ok(())
}

fn render_diff_report(report: &DiffReport, format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

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
    Ok(())
}

fn render_drift_report(report: &DriftReport, format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("Drift: {} -> {}", report.base.id, report.head.id);
    println!("Modules: {:+}", report.module_delta);
    println!("Dependencies: {:+}", report.dependency_delta);
    println!(
        "Circular dependencies: {:+}",
        report.circular_dependency_delta
    );
    println!("Coupling: {:+.2}%", report.coupling_delta_percent);
    println!("Trend: {}", report.trend.as_str());
    Ok(())
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

fn print_dependencies(label: &str, dependencies: &[crate::model::DependencyEdge]) {
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
