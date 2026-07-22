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

pub(crate) fn run_init(paths: &ProjectPaths, force: bool) -> Result<u8> {
    let config_path = paths.ovecc_dir.join("config.toml");
    if config_path.exists() && !force {
        println!(
            "Already initialized: {} exists (pass --force to overwrite it).",
            config_path.display()
        );
    } else {
        std::fs::create_dir_all(&paths.ovecc_dir)?;
        std::fs::write(&config_path, INIT_CONFIG_TEMPLATE)?;
        println!("Wrote {}", config_path.display());
    }

    wire_gitignore(&paths.root)?;

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

/// Git-ignores the local `.ovecc/` state while keeping the architecture
/// contract trackable. An ovecc-written blanket `.ovecc/` line from an
/// earlier version is upgraded in place; a granular block is left alone.
pub(crate) fn wire_gitignore(root: &Path) -> Result<u8> {
    if !root.join(".git").exists() {
        return Ok(0);
    }
    let gitignore = root.join(".gitignore");
    let current = std::fs::read_to_string(&gitignore).unwrap_or_default();
    if current.lines().any(|line| line.trim() == ".ovecc/*") {
        println!(".gitignore already covers .ovecc/");
        return Ok(0);
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
        println!(
            "Upgraded the .ovecc/ ignore to keep .ovecc/architecture.toml and its \
             baseline trackable"
        );
        return Ok(0);
    }
    let mut updated = current;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(OVECC_IGNORE_BLOCK);
    std::fs::write(&gitignore, updated)?;
    println!("Added .ovecc/* to .gitignore (contract and baseline stay trackable)");
    Ok(0)
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
            if report.files_with_parse_errors > 0 {
                println!(
                    "- Files with syntax errors: {} (facts may be partial)",
                    report.files_with_parse_errors
                );
            }
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
            // A clean run from cache changed nothing worth fifteen lines: one
            // line says "stop re-indexing" to a human and an agent alike.
            if report.files_parsed == 0 && report.parse_failures.is_empty() {
                println!(
                    "Index up to date: {} files ({} from cache), snapshot {}.",
                    report.files_indexed, report.files_from_cache, report.snapshot_id
                );
                return Ok(());
            }
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
            if report.files_with_parse_errors > 0 {
                println!(
                    "Files with syntax errors: {} (facts may be partial)",
                    report.files_with_parse_errors
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_template_references_only_existing_docs() {
        assert!(!INIT_CONFIG_TEMPLATE.contains("DIAGNOSE.md"));
        assert!(INIT_CONFIG_TEMPLATE.contains("docs/COMMANDS.md"));
    }
}
