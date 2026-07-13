use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

const USAGE: &str = "\
Usage: cargo xtask <command> [options]

Commands:
  check                     apply fixes, then lint, test, and report suppressions
  fix                       apply clippy fixes and format the workspace
  lint                      check formatting and deny clippy warnings
  test [cargo-test args]    run the workspace test suite
  ci                        lint, audit dependencies, test, report suppressions
  precommit                 lint when staged changes touch Rust or manifests
  prepush                   lint and test before a push leaves the machine
  audit [--strict]          scan dependencies with cargo-audit when installed
  coverage [--min <pct>]    enforce a line-coverage floor with cargo-llvm-cov
  suppressions              count allow and expect lint suppressions
  dogfood [--fail-on <t>]   index this repository with ovecc and review it
  hooks [--force]           install the git pre-commit and pre-push hooks
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let options = &args[1..];
    let results = match command {
        "check" => run_check(),
        "fix" => run_fix(),
        "lint" => run_lint(),
        "test" => run_test(options),
        "ci" => run_ci(),
        "precommit" => run_precommit(),
        "prepush" => run_prepush(),
        "audit" => run_audit(has_flag(options, "strict")),
        "coverage" => run_coverage(&option_value(options, "min").unwrap_or_else(|| "0".into())),
        "suppressions" => vec![report_suppressions()],
        "dogfood" => {
            run_dogfood(&option_value(options, "fail-on").unwrap_or_else(|| "high".into()))
        }
        "hooks" => install_hooks(has_flag(options, "force")),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command: {other}");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    summarize(command, &results)
}

struct StepResult {
    label: String,
    ok: bool,
}

fn passed(label: &str) -> StepResult {
    StepResult {
        label: label.to_string(),
        ok: true,
    }
}

fn failed(label: &str, reason: &str) -> StepResult {
    println!("[{label}] {reason}");
    StepResult {
        label: label.to_string(),
        ok: false,
    }
}

fn skipped(label: &str, reason: &str) -> StepResult {
    println!("[{label}] skipped: {reason}");
    passed(label)
}

fn summarize(command: &str, results: &[StepResult]) -> ExitCode {
    let failures: Vec<&str> = results
        .iter()
        .filter(|step| !step.ok)
        .map(|step| step.label.as_str())
        .collect();
    println!();
    if failures.is_empty() {
        println!("xtask {command}: {} step(s) passed", results.len());
        ExitCode::SUCCESS
    } else {
        println!("xtask {command}: failed at {}", failures.join(", "));
        ExitCode::FAILURE
    }
}

fn run_step(label: &str, program: &str, args: &[&str]) -> StepResult {
    let started = Instant::now();
    println!("[{label}] {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(workspace_root())
        .status();
    let elapsed = started.elapsed().as_secs_f32();
    match status {
        Ok(code) if code.success() => {
            println!("[{label}] ok ({elapsed:.1}s)");
            passed(label)
        }
        Ok(code) => failed(label, &format!("exited with {code} ({elapsed:.1}s)")),
        Err(error) => failed(label, &format!("could not start {program}: {error}")),
    }
}

fn cargo_step(label: &str, args: &[&str]) -> StepResult {
    run_step(label, "cargo", args)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/xtask sits two levels under the workspace root")
        .to_path_buf()
}

fn run_fix() -> Vec<StepResult> {
    vec![
        cargo_step(
            "clippy-fix",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--fix",
                "--allow-dirty",
                "--allow-staged",
            ],
        ),
        cargo_step("format", &["fmt", "--all"]),
    ]
}

fn run_lint() -> Vec<StepResult> {
    vec![
        cargo_step("format-check", &["fmt", "--all", "--check"]),
        cargo_step(
            "clippy",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ]
}

fn run_test(extra: &[String]) -> Vec<StepResult> {
    let mut args = vec!["test".to_string(), "--workspace".to_string()];
    args.extend_from_slice(extra);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    vec![cargo_step("test", &borrowed)]
}

fn run_check() -> Vec<StepResult> {
    let mut results = run_fix();
    results.extend(run_lint());
    results.extend(run_test(&[]));
    results.push(report_suppressions());
    results
}

fn run_ci() -> Vec<StepResult> {
    let mut results = run_lint();
    results.extend(run_audit(true));
    results.extend(run_test(&[]));
    results.push(report_suppressions());
    results
}

fn run_prepush() -> Vec<StepResult> {
    let mut results = run_lint();
    results.extend(run_test(&[]));
    results
}

fn run_precommit() -> Vec<StepResult> {
    if staged_files().iter().any(|path| affects_rust_build(path)) {
        run_lint()
    } else {
        vec![skipped("precommit", "no staged Rust or manifest changes")]
    }
}

fn staged_files() -> Vec<String> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=d"])
        .current_dir(workspace_root())
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn affects_rust_build(path: &str) -> bool {
    path.ends_with(".rs")
        || path.ends_with("Cargo.toml")
        || path == "Cargo.lock"
        || path == ".cargo/config.toml"
}

fn run_audit(strict: bool) -> Vec<StepResult> {
    if cargo_subcommand_available("audit") {
        vec![cargo_step("audit", &["audit"])]
    } else if strict {
        vec![failed(
            "audit",
            "cargo-audit is required here: cargo install cargo-audit",
        )]
    } else {
        vec![skipped(
            "audit",
            "cargo-audit is not installed (cargo install cargo-audit)",
        )]
    }
}

fn run_coverage(min: &str) -> Vec<StepResult> {
    if cfg!(all(target_os = "windows", target_env = "gnu")) {
        return vec![skipped(
            "coverage",
            "the windows-gnu toolchain ships no profiler runtime; run coverage on linux, macos, or windows-msvc",
        )];
    }
    if !cargo_subcommand_available("llvm-cov") {
        return vec![skipped(
            "coverage",
            "cargo-llvm-cov is not installed (cargo install cargo-llvm-cov)",
        )];
    }
    vec![cargo_step(
        "coverage",
        &[
            "llvm-cov",
            "--workspace",
            "--summary-only",
            "--fail-under-lines",
            min,
        ],
    )]
}

fn cargo_subcommand_available(name: &str) -> bool {
    Command::new("cargo")
        .args([name, "--version"])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn report_suppressions() -> StepResult {
    let counts = suppression_counts(&workspace_root().join("crates"));
    let total: usize = counts.values().sum();
    println!("[suppressions] {total} in crates/**/*.rs");
    for (name, count) in &counts {
        println!("  {count:>4}  {name}");
    }
    passed("suppressions")
}

fn suppression_counts(root: &Path) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|name| name != "target") {
                    pending.push(path);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                count_file_suppressions(&path, &mut counts);
            }
        }
    }
    counts
}

fn count_file_suppressions(path: &Path, counts: &mut BTreeMap<String, usize>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        for lint in suppressed_lints(line) {
            *counts.entry(lint).or_insert(0) += 1;
        }
    }
}

fn suppressed_lints(line: &str) -> Vec<String> {
    let mut lints = Vec::new();
    for keyword in ["allow", "expect"] {
        for opener in [format!("#[{keyword}("), format!("#![{keyword}(")] {
            for segment in line.split(opener.as_str()).skip(1) {
                let inner = segment.split(')').next().unwrap_or(segment);
                lints.extend(
                    inner
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                );
            }
        }
    }
    lints
}

fn run_dogfood(fail_on: &str) -> Vec<StepResult> {
    let mut results = vec![cargo_step(
        "build",
        &["build", "--release", "--bin", "ovecc"],
    )];
    if results.last().is_some_and(|step| !step.ok) {
        return results;
    }
    let first_index = !workspace_root().join(".ovecc").join("graph.db").exists();
    let binary = release_binary().to_string_lossy().into_owned();
    results.push(run_step("index", &binary, &["index", "."]));
    if results.last().is_some_and(|step| !step.ok) {
        return results;
    }
    results.push(run_step("summary", &binary, &["summary"]));
    if first_index {
        results.push(skipped(
            "review",
            "baseline snapshot established; rerun dogfood after your next change",
        ));
    } else {
        results.push(run_step(
            "review",
            &binary,
            &["review", "--fail-on", fail_on],
        ));
    }
    results
}

fn release_binary() -> PathBuf {
    let name = if cfg!(windows) { "ovecc.exe" } else { "ovecc" };
    workspace_root().join("target").join("release").join(name)
}

fn install_hooks(force: bool) -> Vec<StepResult> {
    [("pre-commit", "precommit"), ("pre-push", "prepush")]
        .into_iter()
        .map(|(hook, task)| install_hook(hook, task, force))
        .collect()
}

fn install_hook(hook: &str, task: &str, force: bool) -> StepResult {
    let label = format!("hook:{hook}");
    let Some(path) = hook_path(hook) else {
        return failed(&label, "git did not report a hooks directory");
    };
    if path.exists() && !force && !is_owned_hook(&path) {
        return failed(
            &label,
            &format!(
                "{} exists and was not installed by xtask; rerun with --force to replace it",
                path.display()
            ),
        );
    }
    let script = format!("#!/bin/sh\nexec cargo xtask {task}\n");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::write(&path, script) {
        Ok(()) => {
            mark_executable(&path);
            println!("[{label}] installed {}", path.display());
            passed(&label)
        }
        Err(error) => failed(
            &label,
            &format!("could not write {}: {error}", path.display()),
        ),
    }
}

fn is_owned_hook(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.contains("cargo xtask"))
}

fn hook_path(hook: &str) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", &format!("hooks/{hook}")])
        .current_dir(workspace_root())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if printed.is_empty() {
        return None;
    }
    let path = PathBuf::from(printed);
    Some(if path.is_absolute() {
        path
    } else {
        workspace_root().join(path)
    })
}

#[cfg(unix)]
fn mark_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        let _ = fs::set_permissions(path, permissions);
    }
}

#[cfg(not(unix))]
fn mark_executable(_path: &Path) {}

fn has_flag(options: &[String], name: &str) -> bool {
    options.iter().any(|option| option == &format!("--{name}"))
}

fn option_value(options: &[String], name: &str) -> Option<String> {
    let key = format!("--{name}");
    let prefix = format!("--{name}=");
    let mut iter = options.iter();
    while let Some(option) = iter.next() {
        if let Some(value) = option.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
        if option == &key {
            return iter.next().cloned();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(keyword: &str, body: &str) -> String {
        format!("#[{keyword}({body})]")
    }

    #[test]
    fn parses_multiple_lints_in_one_attribute() {
        let line = attribute("allow", "dead_code, unused_imports");
        assert_eq!(suppressed_lints(&line), vec!["dead_code", "unused_imports"]);
    }

    #[test]
    fn parses_inner_expect_attributes() {
        let line = attribute("expect", "clippy::todo").replacen("#[", "#![", 1);
        assert_eq!(suppressed_lints(&line), vec!["clippy::todo"]);
    }

    #[test]
    fn counts_two_attributes_on_one_line() {
        let line = format!(
            "{} {}",
            attribute("allow", "unused"),
            attribute("allow", "unused")
        );
        assert_eq!(suppressed_lints(&line), vec!["unused", "unused"]);
    }

    #[test]
    fn ignores_lines_without_suppressions() {
        assert!(suppressed_lints("fn main() {}").is_empty());
        assert!(suppressed_lints("let allowance = 3;").is_empty());
    }

    #[test]
    fn staged_path_filter_matches_build_inputs() {
        assert!(affects_rust_build("crates/ovecc-core/src/lib.rs"));
        assert!(affects_rust_build("crates/xtask/Cargo.toml"));
        assert!(affects_rust_build("Cargo.lock"));
        assert!(affects_rust_build(".cargo/config.toml"));
        assert!(!affects_rust_build("docs/COMMANDS.md"));
        assert!(!affects_rust_build("tests/fixtures/smelly/src/main.ts"));
    }

    #[test]
    fn option_parsing_reads_both_forms() {
        let options = vec!["--min=80".to_string(), "--strict".to_string()];
        assert_eq!(option_value(&options, "min").as_deref(), Some("80"));
        assert!(has_flag(&options, "strict"));
        let spaced = vec!["--fail-on".to_string(), "medium".to_string()];
        assert_eq!(option_value(&spaced, "fail-on").as_deref(), Some("medium"));
        assert!(option_value(&spaced, "min").is_none());
        assert!(!has_flag(&spaced, "strict"));
    }
}
