//! `ovecc init` and the `ovecc index` report rendering.

use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_line};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::legacy::IndexReport;
use std::path::Path;

pub(crate) fn render_index_timings(timings: &ovecc_core::report::IndexTimings) {
    eprintln!("index phases (ms):");
    eprintln!("  discovery {:>7}", timings.discovery_ms);
    eprintln!("  parse     {:>7}", timings.parse_ms);
    eprintln!("  resolve   {:>7}", timings.resolve_ms);
    eprintln!("  analyze   {:>7}", timings.analyze_ms);
    eprintln!("  persist   {:>7}", timings.persist_ms);
    eprintln!("  total     {:>7}", timings.total_ms);
}

const INIT_CONFIG_TEMPLATE: &str = r#"# ovecc configuration - every key is optional; commented values are the defaults.
# Machine-readable reference: `ovecc capabilities`.

[output]
# text | json | ndjson | markdown (sarif / codeclimate via --format)
# default_format = "text"

[index]
# Extra paths to skip, on top of the built-ins (node_modules, target, dist, .venv, ...).
# exclude = ["vendored"]
# Flag manifest dependencies that no indexed file imports (off by default:
# config-only usages cause false positives).
# detect_unused_deps = true

[architecture]
# How many directory levels below the repository root name a module. 1 makes
# `backend/services/pay.js` part of `backend`; 2 makes it `backend/services`.
# Too shallow and every file lands in a handful of modules that never import
# each other, so cycles, boundary violations and coupling density all read 0 for
# want of edges. `ovecc summary` says so when it detects that shape.
# module_depth = 1

# --- governance: declarative architecture rules, enforced at index time ---
# [[rules.boundaries]]
# name = "billing must not depend on user"
# source = "billing"
# target = "user"
# allowed = false
# severity = "high"

# [[rules.banned_imports]]
# name = "no-deprecated-lodash"
# pattern = "lodash"
# message = "use es-toolkit instead"
# severity = "medium"

# --- architecture diagnosis thresholds (see `ovecc diagnose` in docs/COMMANDS.md) ---
# [diagnose]
# min_confidence = 0.5
"#;

/// The template, with `module_depth` uncommented at the detected value when the
/// repository's layout needs one other than the default.
fn config_template(module_depth: Option<usize>) -> String {
    match module_depth {
        None => INIT_CONFIG_TEMPLATE.to_string(),
        Some(depth) => {
            INIT_CONFIG_TEMPLATE.replace("# module_depth = 1", &format!("module_depth = {depth}"))
        }
    }
}

pub(crate) fn run_init(paths: &ProjectPaths, force: bool) -> Result<u8> {
    let config_path = paths.ovecc_dir.join("config.toml");
    if config_path.exists() && !force {
        println!(
            "Already initialized: {} exists (pass --force to overwrite it).",
            config_path.display()
        );
    } else {
        std::fs::create_dir_all(&paths.ovecc_dir)?;
        let depth = ovecc_indexer::suggest_module_depth(&paths.root);
        std::fs::write(&config_path, config_template(depth))?;
        println!("Wrote {}", config_path.display());
        if let Some(depth) = depth {
            println!(
                "Set module_depth = {depth}: the code sits under several top-level \
                 directories, and the default of 1 would make each of them a single \
                 module with no dependencies between them."
            );
        }
    }

    match wire_gitignore(&paths.root)? {
        GitignoreOutcome::AlreadyCovered => println!(".gitignore already covers .ovecc/"),
        other => {
            if let Some(message) = other.change() {
                println!("{message}");
            }
        }
    }

    println!();
    println!("Next steps:");
    println!("  ovecc index .        build the architecture model (fully local)");
    println!("  ovecc summary        one-screen health");
    println!("  ovecc diagnose       named architecture smells, each with a fix");
    println!("  ovecc mcp            expose every command to your coding agent");
    println!("  ovecc init --agent   make the agent query the graph before grepping");
    Ok(0)
}

/// The ignore block for `.ovecc/`: the machine state stays local, but the
/// architecture contract and its baseline are shared team state, so the
/// pattern is `.ovecc/*` with re-inclusions rather than a blanket `.ovecc/`
/// (git cannot re-include below an excluded directory).
const OVECC_IGNORE_BLOCK: &str = "# ovecc local state (database + parse cache); the architecture contract\n\
     # and its baseline are shared and stay tracked\n\
     .ovecc/*\n\
     !.ovecc/architecture.toml\n\
     !.ovecc/architecture/\n";

/// What [`wire_gitignore`] did, so `init` can confirm a no-op while `index`
/// stays quiet about one.
pub(crate) enum GitignoreOutcome {
    NotAGitRepository,
    AlreadyCovered,
    Upgraded,
    Added,
}

impl GitignoreOutcome {
    /// The line to print, or `None` when nothing changed.
    fn change(&self) -> Option<&'static str> {
        match self {
            Self::NotAGitRepository | Self::AlreadyCovered => None,
            Self::Upgraded => Some(
                "Upgraded the .ovecc/ ignore to keep .ovecc/architecture.toml and its \
                 baseline trackable",
            ),
            Self::Added => {
                Some("Added .ovecc/* to .gitignore (contract and baseline stay trackable)")
            }
        }
    }
}

/// Git-ignores the local `.ovecc/` state while keeping the architecture
/// contract trackable. An ovecc-written blanket `.ovecc/` line from an
/// earlier version is upgraded in place; a granular block is left alone.
pub(crate) fn wire_gitignore(root: &Path) -> Result<GitignoreOutcome> {
    if !root.join(".git").exists() {
        return Ok(GitignoreOutcome::NotAGitRepository);
    }
    let gitignore = root.join(".gitignore");
    let current = std::fs::read_to_string(&gitignore).unwrap_or_default();
    if current.lines().any(|line| line.trim() == ".ovecc/*") {
        return Ok(GitignoreOutcome::AlreadyCovered);
    }
    let blanket = |line: &str| matches!(line.trim(), ".ovecc" | ".ovecc/" | "/.ovecc" | "/.ovecc/");
    if current.lines().any(blanket) {
        let updated: Vec<&str> = current
            .lines()
            .map(|line| {
                if blanket(line) {
                    ".ovecc/*\n!.ovecc/architecture.toml\n!.ovecc/architecture/"
                } else {
                    line
                }
            })
            .collect();
        std::fs::write(&gitignore, updated.join("\n") + "\n")?;
        return Ok(GitignoreOutcome::Upgraded);
    }
    let mut updated = current;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(OVECC_IGNORE_BLOCK);
    std::fs::write(&gitignore, updated)?;
    Ok(GitignoreOutcome::Added)
}

/// `ovecc index` on a repository that was never `init`ed used to leave a
/// multi-megabyte `.ovecc/` untracked in someone else's `git status`, with
/// nothing to stop it being committed. Indexing writes the ignore rule itself
/// when it is the one creating the directory.
pub(crate) fn wire_gitignore_for_index(paths: &ProjectPaths) -> Result<Option<&'static str>> {
    if paths.ovecc_dir.exists() {
        return Ok(None);
    }
    Ok(wire_gitignore(&paths.root)?.change())
}

/// Warns when the default module depth collapses this layout, for the user who
/// went straight to `ovecc index` and so has no config file to read the option
/// off. Silent once a config exists: the value is then a choice, not a default.
pub(crate) fn module_depth_hint(paths: &ProjectPaths, configured_depth: usize) -> Option<String> {
    if configured_depth != 1 || paths.ovecc_dir.join("config.toml").exists() {
        return None;
    }
    let depth = ovecc_indexer::suggest_module_depth(&paths.root)?;
    Some(format!(
        "The code sits under several top-level directories, so at the default depth each \
         of them is one module and no module imports another: cycles, boundary violations \
         and coupling density will read 0. Run `ovecc init` to write a config with \
         module_depth = {depth}, or set it by hand under [architecture]."
    ))
}

/// The notices an index run collects before it starts, printed under the report
/// it belongs to. Only the text renderer takes them: the machine formats would
/// need a field for something a human reads once and acts on.
pub(crate) fn render_index_hints(
    format: OutputFormat,
    ignore_wired: Option<&str>,
    depth_hint: Option<String>,
) {
    if format != OutputFormat::Text {
        return;
    }
    for message in [ignore_wired, depth_hint.as_deref()].into_iter().flatten() {
        println!("{message}");
    }
}

/// What the coverage step did, or `None` when no tracefile was configured and
/// none of the conventional paths exist — the common case, and not worth a line.
fn coverage_line(report: &IndexReport) -> Option<String> {
    let coverage = report.coverage.as_ref()?;
    Some(match &coverage.error {
        Some(error) => format!("Coverage: {} unusable ({error})", coverage.path),
        None => format!(
            "Coverage: {} file(s) from {}",
            coverage.files, coverage.path
        ),
    })
}

/// Says so when the repository has no history to read. `Commits ingested: 0` on
/// its own reads as a fact about the repository; it is really a fact about what
/// ran. Churn is then 0 for every module, and a reader can reasonably conclude
/// the codebase has no hotspots when that analysis never happened. `hotspots`
/// and `coupling` already report their own "n/a"; this is the line that says it
/// at the source.
fn no_history_line(commits_ingested: usize) -> Option<String> {
    (commits_ingested == 0).then(|| {
        "No git history found — churn, hotspots ranking, coupling, ownership and selfcheck \
         are unavailable, not zero"
            .to_string()
    })
}

/// The syntax-error paths, plus a tail line when the count exceeds what the
/// report carries. A bare count is not actionable: the answer to "which file?"
/// has to be in the same output.
fn parse_error_file_lines(report: &IndexReport) -> Vec<String> {
    let mut lines: Vec<String> = report.parse_error_files.clone();
    let remaining = report
        .files_with_parse_errors
        .saturating_sub(report.parse_error_files.len());
    if remaining > 0 {
        lines.push(format!("... and {remaining} more"));
    }
    lines
}

/// The counters shared by the text and markdown renderings, in print order.
fn counters(report: &IndexReport) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("Files scanned", report.files_scanned.to_string()),
        ("Files indexed", report.files_indexed.to_string()),
        ("Files parsed", report.files_parsed.to_string()),
        ("Files from cache", report.files_from_cache.to_string()),
        ("Modules", report.modules.to_string()),
        ("Dependencies", report.dependencies.to_string()),
        (
            "External dependencies",
            report.external_dependencies.to_string(),
        ),
        ("Symbols", report.symbols.to_string()),
        ("Calls", report.calls.to_string()),
        ("APIs", report.apis.to_string()),
        ("Tables", report.tables.to_string()),
        ("Commits ingested", report.commits_ingested.to_string()),
    ];
    if report.tracked_files_scanned > 0 {
        rows.push((
            "Tracked non-source files scanned for secrets",
            report.tracked_files_scanned.to_string(),
        ));
    }
    rows
}

/// The counter block both renderers print. They differ only in how a line
/// opens, so markdown passes its bullet and text passes nothing.
fn render_counters(report: &IndexReport, bullet: &str) {
    for (label, value) in counters(report) {
        println!("{bullet}{label}: {value}");
    }
    if let Some(line) = coverage_line(report) {
        println!("{bullet}{line}");
    }
    if let Some(line) = no_history_line(report.commits_ingested) {
        println!("{bullet}{line}");
    }
    if report.files_with_parse_errors > 0 {
        println!(
            "{bullet}Files with syntax errors: {} (facts may be partial)",
            report.files_with_parse_errors
        );
        for line in parse_error_file_lines(report) {
            println!("  {bullet}{line}");
        }
    }
}

fn render_markdown(report: &IndexReport) {
    println!("# Ovecc index");
    println!();
    println!("- Repository: `{}`", report.repository_root);
    println!("- Snapshot: `{}`", report.snapshot_id);
    render_counters(report, "- ");
    if !report.parse_failures.is_empty() {
        println!();
        println!("## Parse failures");
        println!();
        for failure in &report.parse_failures {
            println!("- `{}`: {}", failure.path, failure.message);
        }
    }
}

fn render_text(report: &IndexReport) {
    // A clean run from cache changed nothing worth fifteen lines: one
    // line says "stop re-indexing" to a human and an agent alike.
    if report.files_parsed == 0 && report.parse_failures.is_empty() {
        println!(
            "Index up to date: {} files ({} from cache), snapshot {}.",
            report.files_indexed, report.files_from_cache, report.snapshot_id
        );
        // Coverage is read on every run, unchanged tree or not, so a
        // tracefile that broke since last time has to say so here too.
        if let Some(line) = coverage_line(report) {
            println!("{line}");
        }
        return;
    }
    println!("Indexed repository: {}", report.repository_root);
    println!("Database: {}", report.database_path);
    println!("Snapshot: {}", report.snapshot_id);
    render_counters(report, "");
    if !report.parse_failures.is_empty() {
        println!();
        println!("Parse failures: {}", report.parse_failures.len());
        for failure in &report.parse_failures {
            println!("  {}: {}", failure.path, failure.message);
        }
    }
}

pub(crate) fn render_index_report(report: &IndexReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("index", report, meta_for("index"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("index", &meta_for("index"))?;
            println!("{}", ndjson_line("index", report)?);
        }
        OutputFormat::Markdown => render_markdown(report),
        OutputFormat::Text => render_text(report),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_template_references_only_existing_docs() {
        assert!(!INIT_CONFIG_TEMPLATE.contains("DIAGNOSE.md"));
        assert!(INIT_CONFIG_TEMPLATE.contains("docs/COMMANDS.md"));
    }

    #[test]
    fn an_index_without_history_says_which_analyses_did_not_run() {
        // Every churn-based metric reads 0 without history, which is
        // indistinguishable from a codebase that genuinely has no hotspots.
        // Absence is ternary: say "unavailable", never imply "none".
        let line = no_history_line(0).expect("0 commits must be explained");
        for feature in ["churn", "hotspots", "coupling", "ownership", "selfcheck"] {
            assert!(line.contains(feature), "{feature} missing from: {line}");
        }
        assert!(line.contains("not zero"), "{line}");

        assert!(no_history_line(1).is_none());
    }
}
