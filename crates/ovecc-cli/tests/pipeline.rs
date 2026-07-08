//! End-to-end pipeline tests: index a committed fixture
//! through the real crates and assert deterministic, persisted facts. These
//! exercise the full chain — walk, parse, resolve, persist — for both the
//! TypeScript family and the Python/Go/Rust/C++ generic adapters, and pin the
//! incremental parse-cache behaviour.

use ovecc_core::config::{OveccConfig, ProjectPaths};
use ovecc_db::ArchitectureStore;
use ovecc_indexer::index_repository;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Copies a committed fixture into a fresh temp dir so the `.ovecc` database
/// and parse cache never touch the source tree.
fn staged_fixture(name: &str) -> tempfile::TempDir {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join(name);
    let temp = tempfile::tempdir().expect("temp dir");
    copy_dir(&source, temp.path());
    temp
}

/// Opens the persisted store, retrying briefly. `index_repository` writes the
/// DuckDB file in this same process and, on Windows, the file handle can lag a
/// few milliseconds behind the writer being dropped; the real CLI never hits
/// this (each command is a fresh process).
fn open_store(db_path: &Path) -> ArchitectureStore {
    for attempt in 0..20 {
        match ArchitectureStore::open(db_path) {
            Ok(store) => return store,
            Err(_) if attempt < 19 => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => panic!("failed to reopen store: {error:#}"),
        }
    }
    unreachable!()
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create dir");
    for entry in fs::read_dir(source).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn ovecc(repo: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ovecc"))
        .args(["--repo", repo])
        .args(args)
        .output()
        .expect("run ovecc")
}

fn index_repo(repo: &str) {
    let indexed = ovecc(repo, &["index"]);
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
}

fn plant_banned_import_rule(root: &Path) {
    let dir = root.join(".ovecc");
    fs::create_dir_all(&dir).expect("create .ovecc");
    fs::write(
        dir.join("config.toml"),
        "[[rules.banned_imports]]\n\
         name = \"no-cross-module-user-imports\"\n\
         pattern = \"../user/*\"\n\
         severity = \"medium\"\n",
    )
    .expect("write config");
}

#[test]
fn typescript_service_indexes_and_resolves_internally() {
    let staged = staged_fixture("small-service");
    let paths = ProjectPaths::resolve(staged.path()).unwrap();
    let config = OveccConfig::default();

    let report = index_repository(&paths, &config, true).unwrap();
    assert_eq!(report.files_indexed, 5, "{report:?}");
    assert!(report.parse_failures.is_empty(), "{report:?}");
    assert!(report.symbols >= 5, "expected symbols, got {report:?}");
    // The relative imports resolve to files; only `express` stays external.
    assert!(report.external_dependencies >= 1, "{report:?}");
    assert!(
        report.dependencies > report.external_dependencies,
        "internal deps must resolve: {report:?}"
    );

    let repository_id = paths.repository_id().0;
    let store = open_store(&paths.db_path);
    let dependencies = store.current_dependencies(&repository_id).unwrap();
    let internal = dependencies.iter().filter(|d| !d.is_external).count();
    assert!(internal >= 5, "expected >=5 internal deps, got {internal}");
    assert!(
        dependencies
            .iter()
            .any(|d| !d.is_external && d.target_module == "user"),
        "billing/user should resolve to an internal dependency"
    );
    // Release the single-writer connection before re-indexing (DuckDB allows
    // one connection per file per process).
    drop(store);

    // Determinism + parse cache: an unchanged re-run reads everything from
    // cache and yields identical counts.
    let again = index_repository(&paths, &config, true).unwrap();
    assert_eq!(again.files_from_cache, 5, "{again:?}");
    assert_eq!(again.files_parsed, 0, "{again:?}");
    assert_eq!(again.symbols, report.symbols);
    assert_eq!(again.dependencies, report.dependencies);
}

#[test]
fn polyglot_repository_indexes_every_language() {
    let staged = staged_fixture("polyglot");
    let paths = ProjectPaths::resolve(staged.path()).unwrap();
    let config = OveccConfig::default();

    let report = index_repository(&paths, &config, true).unwrap();
    assert_eq!(report.files_indexed, 8, "{report:?}");
    assert!(report.parse_failures.is_empty(), "{report:?}");
    // Python + Go + Rust + C++ all contribute symbols and calls.
    assert!(
        report.symbols >= 10,
        "expected polyglot symbols, got {report:?}"
    );
    assert!(report.calls >= 4, "expected polyglot calls, got {report:?}");

    let repository_id = paths.repository_id().0;
    let store = open_store(&paths.db_path);
    let dependencies = store.current_dependencies(&repository_id).unwrap();

    let internal: Vec<_> = dependencies.iter().filter(|d| !d.is_external).collect();
    assert!(
        internal.len() >= 4,
        "every language's intra-repo import should resolve, got {}: {:?}",
        internal.len(),
        internal
            .iter()
            .map(|d| format!("{} -> {}", d.source_module, d.target_module))
            .collect::<Vec<_>>()
    );
    // Python/Rust both depend on `user`; Go `svc` depends on the `store` package.
    assert!(
        dependencies
            .iter()
            .any(|d| !d.is_external && d.target_module == "user"),
        "python/rust -> user must resolve"
    );
    assert!(
        dependencies
            .iter()
            .any(|d| !d.is_external && d.target_module == "store"),
        "go svc -> store must resolve"
    );

    // Stdlib/external imports (`os`, `std::*`, `fmt`, `<string>`) stay external.
    assert!(report.external_dependencies >= 4, "{report:?}");

    // Phase instrumentation is populated: the total bounds every phase.
    let t = &report.timings;
    assert!(
        t.total_ms >= t.parse_ms,
        "timings should be measured: {t:?}"
    );
    assert!(
        t.total_ms >= t.persist_ms,
        "timings should be measured: {t:?}"
    );
}

/// The capability manifest is self-describing and lists every command — the
/// contract an AI agent reads first. Needs no database.
#[test]
fn capabilities_manifest_lists_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_ovecc"))
        .args(["capabilities", "--format", "json"])
        .output()
        .expect("run ovecc capabilities");
    assert!(output.status.success(), "capabilities failed");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("\"schema_version\": 1"), "{stdout}");
    assert!(stdout.contains("\"command\": \"capabilities\""), "{stdout}");
    for command in [
        "index",
        "summary",
        "impact",
        "security",
        "audit",
        "gate",
        "report",
        "violations",
    ] {
        assert!(
            stdout.contains(&format!("\"name\": \"{command}\"")),
            "capabilities should list `{command}`"
        );
    }
}

/// Determinism invariant: for an unchanged database, structured output is
/// byte-for-byte identical across runs. Every step is a fresh process, so the
/// DuckDB writer is fully released before the readers run.
#[test]
fn summary_json_is_byte_identical_across_runs() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    let bin = env!("CARGO_BIN_EXE_ovecc");

    let indexed = Command::new(bin)
        .args(["--repo", &repo, "index"])
        .output()
        .expect("run ovecc index");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    let index_stdout = String::from_utf8_lossy(&indexed.stdout);
    assert!(
        !index_stdout.contains(r"\\?\"),
        "index output must not leak the Windows verbatim prefix: {index_stdout}"
    );

    let run_summary = || {
        Command::new(bin)
            .args(["--repo", &repo, "summary", "--format", "json"])
            .output()
            .expect("run ovecc summary")
    };
    let first = run_summary();
    // Re-index (a fresh snapshot with a new id and wall-clock time) and read
    // again: the payload must depend only on the analyzed content, not on the
    // volatile snapshot identity — the stronger cross-index determinism that
    // lets large-scale runs diff outputs without normalizing.
    let reindexed = Command::new(bin)
        .args(["--repo", &repo, "index"])
        .output()
        .expect("re-run ovecc index");
    assert!(
        reindexed.status.success(),
        "re-index failed: {}",
        String::from_utf8_lossy(&reindexed.stderr)
    );
    let second = run_summary();
    assert!(
        first.status.success(),
        "summary failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    // The envelope carries the contract; the payload is deterministic.
    let stdout = String::from_utf8(first.stdout.clone()).expect("utf8");
    assert!(stdout.contains("\"schema_version\": 1"), "{stdout}");
    assert!(stdout.contains("\"command\": \"summary\""), "{stdout}");
    assert_eq!(
        first.stdout, second.stdout,
        "summary JSON must be byte-identical across runs"
    );
    // Paths in the payload are POSIX-normalized with no Windows verbatim prefix.
    assert!(
        !stdout.contains("//?/"),
        "normalized output must not leak the Windows \\\\?\\ prefix: {stdout}"
    );
}

/// The one-shot `report` composes several sub-reports, each of which opens the
/// store; it must keep only one DuckDB connection open at a time and emit the
/// full composite payload.
#[test]
fn report_command_produces_composite_payload() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    let bin = env!("CARGO_BIN_EXE_ovecc");

    let indexed = Command::new(bin)
        .args(["--repo", &repo, "index"])
        .output()
        .expect("run ovecc index");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let out = Command::new(bin)
        .args(["--repo", &repo, "report", "--format", "json"])
        .output()
        .expect("run ovecc report");
    assert!(
        out.status.success(),
        "report failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(stdout.contains("\"command\": \"report\""), "{stdout}");
    for key in [
        "\"summary\"",
        "\"cycles\"",
        "\"security\"",
        "\"hotspots\"",
        "\"findings\"",
    ] {
        assert!(stdout.contains(key), "report json should contain {key}");
    }
}

/// `advise` lists the persisted findings that touch a target and *also* runs the
/// component diagnose, which re-opens the same database. DuckDB allows one
/// handle per file per process, so the command must drop the first before the
/// second — a regression here crashes instead of reporting. Its own process,
/// against a freshly indexed fixture.
#[test]
fn impact_distinguishes_unknown_target_from_no_impact() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    let bin = env!("CARGO_BIN_EXE_ovecc");

    let indexed = Command::new(bin)
        .args(["--repo", &repo, "index"])
        .output()
        .expect("run ovecc index");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let hit = Command::new(bin)
        .args(["--repo", &repo, "impact", "billing"])
        .output()
        .expect("run ovecc impact");
    assert!(
        hit.status.success(),
        "impact on a real module failed: {}",
        String::from_utf8_lossy(&hit.stderr)
    );

    let miss = Command::new(bin)
        .args(["--repo", &repo, "impact", "definitely-not-a-target"])
        .output()
        .expect("run ovecc impact");
    assert_eq!(
        miss.status.code(),
        Some(2),
        "unknown target must exit 2, stderr: {}",
        String::from_utf8_lossy(&miss.stderr)
    );
    let stderr = String::from_utf8_lossy(&miss.stderr);
    assert!(
        stderr.contains("no architecture element matches 'definitely-not-a-target'"),
        "error should name the unmatched target: {stderr}"
    );
}

#[test]
fn exit_codes_follow_the_documented_contract() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();

    let unindexed = ovecc(&repo, &["summary"]);
    assert_eq!(
        unindexed.status.code(),
        Some(4),
        "missing index must exit 4 (index error), stderr: {}",
        String::from_utf8_lossy(&unindexed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unindexed.stderr).contains("run 'ovecc index' first"),
        "missing-index error must say how to recover"
    );

    let usage = ovecc(&repo, &["impact"]);
    assert_eq!(
        usage.status.code(),
        Some(2),
        "a missing required argument must exit 2 (usage), stderr: {}",
        String::from_utf8_lossy(&usage.stderr)
    );

    plant_banned_import_rule(staged.path());
    index_repo(&repo);

    let report_only = ovecc(&repo, &["violations"]);
    assert_eq!(
        report_only.status.code(),
        Some(0),
        "violations without --fail-on only reports, stderr: {}",
        String::from_utf8_lossy(&report_only.stderr)
    );
    let stdout = String::from_utf8_lossy(&report_only.stdout);
    assert!(
        stdout.contains("Banned import"),
        "the planted rule must produce a finding: {stdout}"
    );

    let gated = ovecc(&repo, &["violations", "--fail-on", "any"]);
    assert_eq!(
        gated.status.code(),
        Some(1),
        "findings crossing --fail-on must exit 1, stderr: {}",
        String::from_utf8_lossy(&gated.stderr)
    );
}

#[test]
fn api_targets_resolve_in_every_documented_form() {
    let staged = staged_fixture("web-api");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    index_repo(&repo);

    for target in ["api:GET:/users/:id", "api:/users/:id", "GET /users/:id"] {
        let out = ovecc(&repo, &["impact", target]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "impact must resolve `{target}`, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let explained = ovecc(&repo, &["explain", "api:POST:/charge"]);
    assert_eq!(
        explained.status.code(),
        Some(0),
        "explain must resolve the colon form, stderr: {}",
        String::from_utf8_lossy(&explained.stderr)
    );
}

#[test]
fn history_trends_metrics_across_snapshots() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    index_repo(&repo);
    index_repo(&repo);

    let listed = ovecc(&repo, &["history"]);
    assert_eq!(listed.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("coupling_density"),
        "bare history must list trendable metrics"
    );

    let trended = ovecc(&repo, &["history", "coupling_density"]);
    assert_eq!(
        trended.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&trended.stderr)
    );
    let stdout = String::from_utf8(trended.stdout).expect("utf8");
    let header = stdout.lines().next().unwrap_or_default();
    assert!(
        header.contains("over 2 snapshot(s)"),
        "both snapshots must appear: {header}"
    );
    assert!(
        longest_decimal_run(header) <= 3,
        "values must render human-friendly, not raw floats: {header}"
    );

    let unknown = ovecc(&repo, &["history", "nope"]);
    assert_eq!(
        unknown.status.code(),
        Some(2),
        "an unknown metric is a usage error"
    );
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("no history for metric 'nope'"),
        "error must name the unknown metric"
    );
}

fn longest_decimal_run(line: &str) -> usize {
    let bytes = line.as_bytes();
    let mut longest = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'.' {
            let run = bytes[i + 1..]
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .count();
            longest = longest.max(run);
        }
    }
    longest
}

#[test]
fn diff_reports_added_dependencies_between_snapshots() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    index_repo(&repo);

    let notify_dir = staged.path().join("src").join("notify");
    fs::create_dir_all(&notify_dir).expect("create notify module");
    fs::write(
        notify_dir.join("index.ts"),
        "import { getUser } from \"../user/service\";\n\n\
         export function notifyUser(id: string): string {\n\
           return `notified-${getUser(id).id}`;\n\
         }\n",
    )
    .expect("write notify module");
    index_repo(&repo);

    let diffed = ovecc(&repo, &["diff", "--format", "json"]);
    assert_eq!(
        diffed.status.code(),
        Some(0),
        "one added dependency stays under the default high threshold, stderr: {}",
        String::from_utf8_lossy(&diffed.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&diffed.stdout).expect("diff json");
    let data = &payload["data"];
    assert!(
        data["added_modules"]
            .as_array()
            .is_some_and(|modules| modules.iter().any(|m| m == "notify")),
        "the new module must appear in added_modules: {data}"
    );
    let added = data["added_dependencies"]
        .as_array()
        .expect("added_dependencies array");
    assert!(
        added
            .iter()
            .any(|e| e["source_module"] == "notify" && e["target_module"] == "user"),
        "the new notify -> user dependency must surface: {added:?}"
    );
    assert!(
        added
            .iter()
            .all(|e| e["is_external"] == true || e["source_module"] != e["target_module"]),
        "diff must not surface module self-edges: {added:?}"
    );
}

#[test]
fn init_scaffolds_config_and_preserves_user_edits() {
    let temp = tempfile::tempdir().expect("temp dir");
    fs::create_dir(temp.path().join(".git")).expect("fake git dir");
    fs::create_dir_all(temp.path().join("src")).expect("src dir");
    fs::write(
        temp.path().join("src").join("app.ts"),
        "export const app = 1;\n",
    )
    .expect("write source");
    let repo = temp.path().to_str().expect("utf8 path").to_string();

    let first = ovecc(&repo, &["init"]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let config_path = temp.path().join(".ovecc").join("config.toml");
    assert!(config_path.exists(), "init must write the starter config");
    let gitignore_path = temp.path().join(".gitignore");
    let gitignore = fs::read_to_string(&gitignore_path).expect("gitignore");
    assert_eq!(
        gitignore.matches(".ovecc/").count(),
        1,
        "init must ignore .ovecc/ exactly once: {gitignore}"
    );

    let mut config = fs::read_to_string(&config_path).expect("config");
    config.push_str("\n# user marker\n");
    fs::write(&config_path, &config).expect("edit config");

    let second = ovecc(&repo, &["init"]);
    assert_eq!(second.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("Already initialized"),
        "re-init must refuse to overwrite without --force"
    );
    assert!(
        fs::read_to_string(&config_path)
            .expect("config")
            .contains("# user marker"),
        "re-init must not clobber an edited config"
    );
    let gitignore = fs::read_to_string(&gitignore_path).expect("gitignore");
    assert_eq!(
        gitignore.matches(".ovecc/").count(),
        1,
        "re-init must not duplicate the ignore entry: {gitignore}"
    );

    let indexed = ovecc(&repo, &["index", "--no-git"]);
    assert!(
        indexed.status.success(),
        "the written starter config must load as valid configuration: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
}

#[test]
fn ci_output_formats_parse_as_valid_json() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    plant_banned_import_rule(staged.path());
    index_repo(&repo);

    let sarif_out = ovecc(&repo, &["violations", "--format", "sarif"]);
    assert_eq!(
        sarif_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&sarif_out.stderr)
    );
    let sarif: serde_json::Value = serde_json::from_slice(&sarif_out.stdout).expect("sarif json");
    assert_eq!(sarif["version"], "2.1.0", "{sarif}");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("sarif results array");
    assert!(
        results
            .iter()
            .any(|r| r["ruleId"] == "banned-import/no-cross-module-user-imports"),
        "the planted finding must appear as a SARIF result: {results:?}"
    );

    let cc_out = ovecc(&repo, &["violations", "--format", "codeclimate"]);
    assert_eq!(
        cc_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&cc_out.stderr)
    );
    let issues: serde_json::Value =
        serde_json::from_slice(&cc_out.stdout).expect("codeclimate json");
    let issues = issues.as_array().expect("codeclimate issue array");
    assert!(
        issues
            .iter()
            .any(|i| i["type"] == "issue" && i["severity"] == "major"),
        "the planted medium finding must map to a major issue: {issues:?}"
    );
}

#[test]
fn advise_reports_without_opening_the_database_twice() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    let bin = env!("CARGO_BIN_EXE_ovecc");

    let indexed = Command::new(bin)
        .args(["--repo", &repo, "index"])
        .output()
        .expect("run ovecc index");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let advised = Command::new(bin)
        .args(["--repo", &repo, "advise", "src/billing/service.ts"])
        .output()
        .expect("run ovecc advise");
    assert!(
        advised.status.success(),
        "advise crashed or errored: {}",
        String::from_utf8_lossy(&advised.stderr)
    );
    let stdout = String::from_utf8(advised.stdout).expect("utf8");
    assert!(
        stdout.contains("Advise for"),
        "advise should render its report, got: {stdout}"
    );
}
