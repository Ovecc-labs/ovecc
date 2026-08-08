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
        // Never stage a .ovecc left by running ovecc on the fixture in place:
        // tests that assert on the unindexed state would see a database.
        if entry.file_name() == ".ovecc" {
            continue;
        }
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

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An empty repository with an identity set, so committing works whatever the
/// machine's git config says.
fn git_repo() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("temp dir");
    git(temp.path(), &["init", "-q"]);
    git(temp.path(), &["config", "user.email", "dev@example.com"]);
    git(temp.path(), &["config", "user.name", "Dev"]);
    temp
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

/// The list a reader sees is cut; the gate is not. If `--limit` reached
/// `--fail-on`, a CI check would go green on a truncated page.
#[test]
fn limiting_the_printed_findings_does_not_soften_the_gate() {
    let staged = staged_fixture("smelly");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    index_repo(&repo);

    let full = ovecc(&repo, &["violations", "--format", "json", "--limit", "0"]);
    let envelope: serde_json::Value =
        serde_json::from_slice(&full.stdout).expect("violations json");
    let total = envelope["data"]["total"].as_u64().expect("total") as usize;
    assert!(
        total > 1,
        "fixture needs several findings to page, got {total}"
    );
    assert_eq!(
        envelope["data"]["findings"]
            .as_array()
            .expect("findings")
            .len(),
        total,
        "--limit 0 prints the whole set"
    );

    let one = ovecc(&repo, &["violations", "--format", "json", "--limit", "1"]);
    let envelope: serde_json::Value = serde_json::from_slice(&one.stdout).expect("violations json");
    assert_eq!(envelope["data"]["shown"], 1);
    assert_eq!(
        envelope["data"]["total"].as_u64().expect("total") as usize,
        total,
        "the count still describes the whole set"
    );
    assert!(
        envelope["data"]["note"].is_string(),
        "a cut list must say how to see the rest"
    );

    let gated = ovecc(&repo, &["violations", "--limit", "1", "--fail-on", "any"]);
    assert_eq!(
        gated.status.code(),
        Some(1),
        "a one-row page must still fail the gate, stderr: {}",
        String::from_utf8_lossy(&gated.stderr)
    );

    // SARIF feeds CI ingestion, where a partial file is a wrong file.
    let sarif = ovecc(&repo, &["violations", "--format", "sarif", "--limit", "1"]);
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).expect("sarif json");
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results")
            .len(),
        total,
        "sarif ignores --limit"
    );
}

#[test]
fn rdeps_returns_direct_callers_and_depth_opts_into_reach() {
    let staged = staged_fixture("small-service");
    let repo = staged.path().to_string_lossy().to_string();
    index_repo(&repo);

    // checkout -> handleCreateInvoice -> createInvoice.
    let labels = |args: &[&str]| -> Vec<String> {
        let out = ovecc(&repo, args);
        assert!(
            out.status.success(),
            "query failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("query emits json");
        json["data"]["items"]
            .as_array()
            .expect("items array")
            .iter()
            .filter_map(|item| item["label"].as_str().map(str::to_string))
            .collect()
    };

    // `rdeps` answers "who calls X", so only the immediate caller belongs here.
    // It used to run at the blast-radius depth and drag the whole reverse
    // reachable set in with it.
    let direct = labels(&["query", "rdeps createInvoice", "--format", "json"]);
    assert!(
        direct.iter().any(|l| l == "handleCreateInvoice"),
        "direct caller missing: {direct:?}"
    );
    assert!(
        !direct.iter().any(|l| l == "checkout"),
        "transitive caller leaked into rdeps: {direct:?}"
    );

    let reached = labels(&[
        "query",
        "rdeps createInvoice",
        "--depth",
        "3",
        "--format",
        "json",
    ]);
    assert!(
        reached.iter().any(|l| l == "checkout"),
        "--depth must opt back into transitive reach: {reached:?}"
    );
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
        gitignore.matches(".ovecc/*").count(),
        1,
        "init must ignore the .ovecc state exactly once: {gitignore}"
    );
    assert!(
        gitignore.contains("!.ovecc/architecture.toml"),
        "the architecture contract must stay trackable: {gitignore}"
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
        gitignore.matches(".ovecc/*").count(),
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
fn architecture_init_template_needs_no_index() {
    let temp = tempfile::tempdir().expect("temp dir");
    fs::create_dir(temp.path().join(".git")).expect("fake git dir");
    let repo = temp.path().to_str().expect("utf8 path").to_string();

    let listed = ovecc(&repo, &["architecture", "templates"]);
    assert_eq!(listed.status.code(), Some(0));
    let listing = String::from_utf8_lossy(&listed.stdout);
    for name in [
        "fsd",
        "bulletproof-react",
        "nx-workspace",
        "clean-architecture",
    ] {
        assert!(
            listing.contains(name),
            "the template listing must name {name}"
        );
    }

    let unknown = ovecc(&repo, &["architecture", "init", "--template", "nope"]);
    assert_eq!(
        unknown.status.code(),
        Some(2),
        "an unknown template is a usage error"
    );
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("available: fsd"),
        "the error must list the known templates"
    );

    // The contract-first workflow: template, then show — before any index.
    let init = ovecc(&repo, &["architecture", "init", "--template", "fsd"]);
    assert_eq!(
        init.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let contract = fs::read_to_string(temp.path().join(".ovecc").join("architecture.toml"))
        .expect("contract written");
    assert!(contract.contains("role = \"fsd/shared\""));
    let gitignore = fs::read_to_string(temp.path().join(".gitignore")).expect("gitignore");
    assert!(
        gitignore.contains("!.ovecc/architecture.toml"),
        "the templated contract must stay trackable: {gitignore}"
    );

    let shown = ovecc(&repo, &["architecture", "show", "src/features/auth/ui.tsx"]);
    assert_eq!(shown.status.code(), Some(0));
    let shown_out = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown_out.contains("features"),
        "show must resolve the owning layer from the contract alone: {shown_out}"
    );

    let again = ovecc(&repo, &["architecture", "init", "--template", "fsd"]);
    assert_eq!(
        again.status.code(),
        Some(2),
        "re-init must refuse to overwrite without --force"
    );
}

#[test]
fn architecture_suggest_recognizes_a_feature_sliced_repo() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();
    fs::write(root.join("package.json"), "{ \"name\": \"fsd-demo\" }").expect("manifest");
    // A minimal FSD lattice: app -> features -> shared, nothing upward.
    let write = |rel: &str, body: &str| {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        fs::write(path, body).expect("write source");
    };
    write("src/shared/api.ts", "export const api = 1;\n");
    write(
        "src/features/auth.ts",
        "import { api } from \"../shared/api\";\nexport const auth = api;\n",
    );
    write(
        "src/app/main.ts",
        "import { auth } from \"../features/auth\";\n\
         import { api } from \"../shared/api\";\nexport const main = auth + api;\n",
    );

    let indexed = ovecc(&repo, &["index", "--no-git"]);
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let suggested = ovecc(&repo, &["architecture", "suggest", "--format", "json"]);
    assert_eq!(suggested.status.code(), Some(0));
    let envelope: serde_json::Value =
        serde_json::from_slice(&suggested.stdout).expect("suggest json");
    let data = &envelope["data"];
    assert_eq!(
        data["best"],
        "fsd",
        "the lattice is Feature-Sliced: {}",
        String::from_utf8_lossy(&suggested.stdout)
    );
    let fsd = data["suggestions"]
        .as_array()
        .expect("suggestions array")
        .iter()
        .find(|suggestion| suggestion["template"] == "fsd")
        .expect("fsd is ranked");
    assert_eq!(fsd["root"], "src/", "the detected root is src/");
    assert_eq!(fsd["conformance"], 1.0, "every edge is allowed");
    assert_eq!(fsd["divergent_edges"], 0);
}

fn write_source(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().expect("has a parent")).expect("mkdir");
    fs::write(path, body).expect("write source");
}

fn json_output(repo: &str, args: &[&str]) -> serde_json::Value {
    let out = ovecc(repo, args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json envelope")
}

#[test]
fn a_type_only_cycle_is_no_cycle_on_any_surface() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();

    write_source(
        root,
        "src/p/x.ts",
        "export interface PShape { id: string }\nexport const p = 1;\n",
    );
    write_source(
        root,
        "src/q/x.ts",
        "import { p } from \"../p/x\";\nexport const q = p + 1;\n",
    );
    let indexed = ovecc(&repo, &["index", "--no-git"]);
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    let baseline = json_output(&repo, &["summary", "--format", "json"]);
    assert_eq!(baseline["data"]["circular_dependencies"], 0, "{baseline}");

    write_source(
        root,
        "src/p/x.ts",
        "import type { QShape } from \"../q/x\";\n\
         export interface PShape { id: string }\n\
         export const p: number = 1;\n\
         export type Echo = QShape;\n",
    );
    write_source(
        root,
        "src/q/x.ts",
        "import { p } from \"../p/x\";\n\
         export interface QShape { total: number }\n\
         export const q = p + 1;\n",
    );
    let reindexed = ovecc(&repo, &["index", "--no-git"]);
    assert!(
        reindexed.status.success(),
        "re-index failed: {}",
        String::from_utf8_lossy(&reindexed.stderr)
    );

    let summary = json_output(&repo, &["summary", "--format", "json"]);
    assert_eq!(
        summary["data"]["circular_dependencies"], 0,
        "the persisted metric must not see a type-only loop: {summary}"
    );
    let cycles = json_output(&repo, &["query", "cycles", "--format", "json"]);
    assert_eq!(
        cycles["data"]["cycles"].as_array().map(Vec::len),
        Some(0),
        "{cycles}"
    );
    let violations = json_output(&repo, &["violations", "--format", "json"]);
    assert!(
        violations["data"]["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .all(|finding| finding["rule_name"] != "circular-dependency"),
        "{violations}"
    );

    let gate = ovecc(&repo, &["gate", "--format", "json"]);
    let verdict: serde_json::Value = serde_json::from_slice(&gate.stdout).expect("gate json");
    assert_eq!(
        verdict["data"]["new_cycles"], 0,
        "a type-only edge is not a new cycle: {verdict}"
    );
}

/// A repository holding one of each sentence an allow-list cannot write:
/// `api` reaches into `db`, which only `repository` may touch; into `legacy`,
/// which nothing may touch; into `telemetry`, which it is forbidden outright; and
/// one `api` file never reaches the `auth` every one of them must.
fn dcl_repo(root: &Path) {
    write_source(
        root,
        "src/auth/guard.ts",
        "export const guard = () => true;\n",
    );
    write_source(
        root,
        "src/db/pool.ts",
        "export const pool = { query: 1 };\n",
    );
    write_source(
        root,
        "src/legacy/store.ts",
        "export const legacyStore = { get: 1 };\n",
    );
    write_source(
        root,
        "src/telemetry/sdk.ts",
        "export const sdk = { call: 1 };\n",
    );
    write_source(
        root,
        "src/repository/users.ts",
        "import { pool } from \"../db/pool\";\nexport const users = pool;\n",
    );
    write_source(
        root,
        "src/api/orders.ts",
        "import { guard } from \"../auth/guard\";\n\
         import { users } from \"../repository/users\";\n\
         import { pool } from \"../db/pool\";\n\
         import { sdk } from \"../telemetry/sdk\";\n\
         export const orders = [guard, users, pool, sdk];\n",
    );
    write_source(
        root,
        "src/api/prices.ts",
        "import { users } from \"../repository/users\";\n\
         import { legacyStore } from \"../legacy/store\";\n\
         export const prices = [users, legacyStore];\n",
    );
}

fn write_contract(root: &Path, body: &str) {
    let dir = root.join(".ovecc");
    fs::create_dir_all(&dir).expect("create .ovecc");
    fs::write(dir.join("architecture.toml"), body).expect("write contract");
}

const DCL_CONTRACT: &str = r#"
schema = 1
mode = "strict"
unassigned = "ignore"

[[component]]
name = "api"
paths = ["src/api/**"]
depends_on = ["repository"]
must_depend_on = ["auth"]
cannot_depend_on = ["telemetry"]

[[component]]
name = "repository"
paths = ["src/repository/**"]
depends_on = ["db"]

[[component]]
name = "auth"
paths = ["src/auth/**"]

[[component]]
name = "telemetry"
paths = ["src/telemetry/**"]

[[component]]
name = "db"
paths = ["src/db/**"]
consumed_by = ["repository"]

[[component]]
name = "legacy"
paths = ["src/legacy/**"]
consumed_by = []
"#;

/// Every finding of a rule, as `(title, first evidence path)`. Sorted, because
/// the report orders by finding id — a hash — and these assertions are about
/// content, not about an order `summary_json_is_byte_identical_across_runs`
/// already pins.
fn findings_of<'a>(report: &'a serde_json::Value, rule: &str) -> Vec<(&'a str, &'a str)> {
    let mut found: Vec<(&str, &str)> = report["data"]["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter(|finding| finding["rule_name"] == rule)
        .map(|finding| {
            (
                finding["title"].as_str().expect("title"),
                finding["evidence"][0]["file_path"].as_str().unwrap_or(""),
            )
        })
        .collect();
    found.sort_unstable();
    found
}

#[test]
fn the_three_dcl_forms_gate_a_build_and_freeze_into_the_baseline() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();
    dcl_repo(root);
    write_contract(root, DCL_CONTRACT);
    index_repo(&repo);

    let report = json_output(&repo, &["architecture", "diff", "--format", "json"]);

    let restricted = findings_of(&report, "architecture/restricted-access");
    assert_eq!(
        restricted,
        vec![
            ("api imports db, which is closed to it", "src/api/orders.ts"),
            (
                "api imports legacy, which is closed to it",
                "src/api/prices.ts"
            ),
        ],
        "a component reached only through repository, and one reached by nobody"
    );
    assert_eq!(
        findings_of(&report, "architecture/forbidden-dependency"),
        vec![(
            "api -> telemetry is forbidden by the contract",
            "src/api/orders.ts"
        )],
        "{report}"
    );
    assert_eq!(
        findings_of(&report, "architecture/required-dependency"),
        vec![(
            "1 file(s) of api never reach the required auth",
            "src/api/prices.ts"
        )],
        "orders.ts imports auth and is silent; prices.ts does not"
    );

    assert!(
        findings_of(&report, "architecture/divergence").is_empty(),
        "a prohibited import is reported once, as prohibited, not also as undeclared: {report}"
    );
    assert!(
        findings_of(&report, "architecture/absence").is_empty(),
        "must_depend_on is not a depends_on entry that can go stale: {report}"
    );

    let checked = ovecc(&repo, &["architecture", "check"]);
    assert_eq!(
        checked.status.code(),
        Some(1),
        "the contract must fail the build: {}",
        String::from_utf8_lossy(&checked.stdout)
    );

    // Freezing accepts today's debt; `new-violations` is the mode that hides
    // it, so the ratchet can shrink it from there.
    ovecc(&repo, &["architecture", "check", "--freeze"]);
    fs::write(
        root.join(".ovecc").join("architecture.toml"),
        DCL_CONTRACT.replace("mode = \"strict\"", "mode = \"new-violations\""),
    )
    .expect("relax the mode");
    let ratcheted = json_output(&repo, &["architecture", "diff", "--format", "json"]);
    for rule in [
        "architecture/restricted-access",
        "architecture/forbidden-dependency",
        "architecture/required-dependency",
    ] {
        assert!(
            findings_of(&ratcheted, rule).is_empty(),
            "{rule} was frozen and must stop being reported: {ratcheted}"
        );
    }
    assert_eq!(
        ovecc(&repo, &["architecture", "check"]).status.code(),
        Some(0),
        "with the debt accepted the build passes again"
    );
}

/// `cannot_depend_on` is not `depends_on` by omission: it names the
/// prohibition, and the verdict says so instead of reporting an undeclared
/// edge.
#[test]
fn a_forbidden_import_is_reported_as_forbidden_not_undeclared() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();
    dcl_repo(root);
    write_contract(
        root,
        r#"
schema = 1
mode = "strict"
unassigned = "ignore"

[[component]]
name = "api"
paths = ["src/api/**"]
depends_on = ["repository", "auth"]
cannot_depend_on = ["legacy"]

[[component]]
name = "repository"
paths = ["src/repository/**"]
depends_on = ["db"]

[[component]]
name = "auth"
paths = ["src/auth/**"]

[[component]]
name = "db"
paths = ["src/db/**"]

[[component]]
name = "legacy"
paths = ["src/legacy/**"]
"#,
    );
    index_repo(&repo);

    let report = json_output(&repo, &["architecture", "diff", "--format", "json"]);
    assert_eq!(
        findings_of(&report, "architecture/forbidden-dependency"),
        vec![(
            "api -> legacy is forbidden by the contract",
            "src/api/prices.ts"
        )],
        "{report}"
    );
    assert_eq!(
        findings_of(&report, "architecture/divergence"),
        vec![("api -> db is not in the contract", "src/api/orders.ts")],
        "an ordinary undeclared edge still reads as a divergence: {report}"
    );
}

/// A contract that both forbids and allows the same edge has no right answer,
/// so it is refused at parse time rather than resolved by precedence.
#[test]
fn a_self_contradictory_contract_is_refused_before_it_judges_anything() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();
    dcl_repo(root);
    index_repo(&repo);

    for (contract, expected) in [
        (
            r#"
schema = 1
[[component]]
name = "api"
paths = ["src/api/**"]
depends_on = ["db"]
cannot_depend_on = ["db"]
[[component]]
name = "db"
paths = ["src/db/**"]
"#,
            "cannot_depend_on",
        ),
        (
            r#"
schema = 1
[[component]]
name = "api"
paths = ["src/api/**"]
depends_on = ["db"]
[[component]]
name = "repository"
paths = ["src/repository/**"]
[[component]]
name = "db"
paths = ["src/db/**"]
consumed_by = ["repository"]
"#,
            "consumed_by",
        ),
    ] {
        write_contract(root, contract);
        let out = ovecc(&repo, &["architecture", "diff"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(out.status.code(), Some(0), "{stderr}");
        assert!(
            stderr.contains(expected),
            "the error must name the field: {stderr}"
        );
    }
}

/// The pre-edit question an agent asks: the new forms have to be visible in
/// `architecture show`, or a coding agent cannot honour them.
#[test]
fn architecture_show_states_what_a_component_must_and_must_not_import() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();
    dcl_repo(root);
    write_contract(root, DCL_CONTRACT);

    let shown = json_output(&repo, &["architecture", "show", "--format", "json"]);
    let components = shown["data"]["components"]
        .as_array()
        .expect("component array");
    let api = components
        .iter()
        .find(|component| component["name"] == "api")
        .expect("api");
    assert_eq!(api["must_import"], serde_json::json!(["auth"]));
    assert_eq!(api["must_not_import"], serde_json::json!(["telemetry"]));
    let legacy = components
        .iter()
        .find(|component| component["name"] == "legacy")
        .expect("legacy");
    assert_eq!(
        legacy["importable_by"],
        serde_json::json!([]),
        "closed to everyone must be a value, not a missing field: {legacy}"
    );
    assert!(
        components
            .iter()
            .find(|component| component["name"] == "auth")
            .expect("auth")["importable_by"]
            .is_null(),
        "an unrestricted component says nothing"
    );

    let text = ovecc(&repo, &["architecture", "show"]);
    let rendered = String::from_utf8_lossy(&text.stdout);
    assert!(
        rendered.contains("must import: auth (every file)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("must not import: telemetry"),
        "{rendered}"
    );
    assert!(
        rendered.contains("importable by: nothing (no component may import it)"),
        "{rendered}"
    );
}

#[test]
fn unresolved_relative_imports_are_flagged_and_never_counted_as_packages() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path();
    let repo = root.to_str().expect("utf8 path").to_string();

    fs::write(
        root.join("package.json"),
        "{ \"name\": \"broken-demo\", \"dependencies\": { \"lodash\": \"^4.17.21\" } }",
    )
    .expect("manifest");
    write_source(root, "src/helpers.ts", "export const help = 1;\n");
    write_source(root, "src/theme.css", ".a { color: red }\n");
    write_source(
        root,
        "src/ambient.d.ts",
        "export declare const ambient: number;\n",
    );
    write_source(
        root,
        "src/broken.ts",
        "import { gone } from \"./missing\";\n\
         import { alsoGone } from \"../nowhere/deleted.ts\";\n\
         import styles from \"./theme.css\";\n\
         import iconUrl from \"./icon.svg?url\";\n\
         import { ambient } from \"./ambient\";\n\
         import { help } from \"./helpers\";\n\
         import { chunk } from \"lodash\";\n\
         export const all = [gone, alsoGone, styles, iconUrl, ambient, help, chunk];\n",
    );

    let indexed = ovecc(&repo, &["index", "--no-git"]);
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let violations = json_output(&repo, &["violations", "--format", "json"]);
    let unresolved: Vec<String> = violations["data"]["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter(|finding| finding["rule_name"] == "unresolved-import")
        .map(|finding| finding["evidence"][0]["detail"].to_string())
        .collect();
    assert_eq!(
        unresolved.len(),
        2,
        "exactly the two dangling specifiers: {unresolved:?} in {violations}"
    );
    assert!(unresolved.iter().any(|d| d.contains("./missing")));
    assert!(
        unresolved
            .iter()
            .any(|d| d.contains("../nowhere/deleted.ts"))
    );
    for suppressed in ["theme.css", "icon.svg", "./ambient", "./helpers", "lodash"] {
        assert!(
            !unresolved.iter().any(|d| d.contains(suppressed)),
            "{suppressed} must not be flagged: {unresolved:?}"
        );
    }

    let summary = json_output(&repo, &["summary", "--format", "json"]);
    assert_eq!(
        summary["data"]["external_dependencies"], 1,
        "lodash is the only real external package: {summary}"
    );

    let graph = json_output(&repo, &["export", "graph", "--format", "json"]);
    for level in ["modules", "files"] {
        let nodes = graph["data"][level]["nodes"]
            .as_array()
            .expect("node array");
        let externals: Vec<&str> = nodes
            .iter()
            .filter(|node| node["kind"] == "external")
            .map(|node| node["label"].as_str().expect("label"))
            .collect();
        assert_eq!(
            externals,
            ["external:lodash"],
            "{level} nodes: {externals:?}"
        );
    }
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
fn code_smell_rules_flag_envy_large_class_and_clumps() {
    let staged = staged_fixture("smelly");
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    index_repo(&repo);

    let out = ovecc(&repo, &["violations", "--format", "json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).expect("violations json");
    let findings = envelope["data"]["findings"]
        .as_array()
        .expect("findings array");
    let by_rule = |rule: &str| -> Vec<&serde_json::Value> {
        findings.iter().filter(|f| f["rule_name"] == rule).collect()
    };

    let envy = by_rule("feature-envy");
    assert_eq!(envy.len(), 1, "{envy:#?}");
    assert!(
        envy[0]["title"]
            .as_str()
            .unwrap()
            .contains("settleUserInvoices -> billing"),
        "{}",
        envy[0]["title"]
    );
    assert_eq!(envy[0]["target"]["kind"], "module", "{}", envy[0]["target"]);

    let large = by_rule("large-class");
    assert_eq!(large.len(), 1, "{large:#?}");
    assert!(
        large[0]["title"]
            .as_str()
            .unwrap()
            .contains("Transport (21 methods)"),
        "{}",
        large[0]["title"]
    );

    let clumps = by_rule("data-clumps");
    assert_eq!(clumps.len(), 1, "{clumps:#?}");
    assert!(
        clumps[0]["title"]
            .as_str()
            .unwrap()
            .contains("(host, port, timeout)"),
        "{}",
        clumps[0]["title"]
    );
    assert_eq!(
        clumps[0]["evidence"].as_array().map(Vec::len),
        Some(3),
        "one evidence entry per participating function"
    );

    let envious = "\nexport function summarizeUserLedger(userId: string): string {\n  \
                   const ledger = openLedger(userId);\n  postEntry(ledger);\n  \
                   auditTrail(ledger);\n  reconcile(ledger);\n  balance(ledger);\n  \
                   closeLedger(ledger);\n  return ledger;\n}\n";
    let profile = staged.path().join("src").join("user").join("profile.ts");
    let mut source = fs::read_to_string(&profile).expect("read profile.ts");
    source.push_str(envious);
    fs::write(&profile, source).expect("grow profile.ts");
    index_repo(&repo);

    let review = ovecc(&repo, &["review", "--format", "json"]);
    let envelope: serde_json::Value = serde_json::from_slice(&review.stdout).expect("review json");
    assert_eq!(
        envelope["data"]["summary"]["new_smells"], 1,
        "review must scope the smell to the change: {}",
        envelope["data"]["summary"]
    );
    let new_findings = envelope["data"]["new_findings"]
        .as_array()
        .expect("new findings");
    assert!(
        new_findings.iter().any(|f| f["rule_name"] == "feature-envy"
            && f["title"].as_str().unwrap().contains("summarizeUserLedger")),
        "the newly added envious function must be the named new finding: {new_findings:#?}"
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

/// A finding's identity is keyed on its file path, so moving a file renames
/// every finding in it and the snapshot diff reports pre-existing defects as
/// new — the gate then fails a refactor that introduced nothing. With both
/// snapshots on commits, review consults the rename-aware git diff and only
/// charges a lexical finding to the change if its lines were actually touched.
#[test]
fn review_does_not_charge_findings_a_file_move_renamed() {
    let temp = git_repo();
    let root = temp.path();
    fs::create_dir_all(root.join("src")).expect("mkdir");
    // A committed provider token is a Critical finding, enough to trip
    // --fail-on high if review were to charge it to the wrong change.
    fs::write(
        root.join("src").join("config.ts"),
        "export const region = \"eu-west-3\";\n\
         export const awsKey = \"AKIAAAAABBBBCCCCDDDD\";\n\
         export function endpoint(name: string): string {\n  return name + region;\n}\n",
    )
    .expect("write config.ts");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    let repo = root.to_str().expect("utf8 path").to_string();
    index_repo(&repo);

    let baseline = ovecc(&repo, &["violations", "--format", "json"]);
    let envelope: serde_json::Value =
        serde_json::from_slice(&baseline.stdout).expect("violations json");
    assert_eq!(
        envelope["data"]["by_severity"]["critical"], 1,
        "the fixture must start with exactly the planted secret: {}",
        envelope["data"]
    );

    // A pure move: the secret's finding identity changes with the path, but
    // no line of the change touched it.
    git(root, &["mv", "src/config.ts", "src/settings.ts"]);
    git(root, &["commit", "-q", "-m", "move"]);
    index_repo(&repo);

    let review = ovecc(&repo, &["review", "--fail-on", "high", "--format", "json"]);
    let envelope: serde_json::Value = serde_json::from_slice(&review.stdout).expect("review json");
    let summary = &envelope["data"]["summary"];
    assert!(
        review.status.success(),
        "a pure file move must pass the gate: {summary}"
    );
    assert_eq!(
        summary["new_security"], 0,
        "the moved secret predates the change: {summary}"
    );
    assert!(
        summary["shifted_findings"].as_u64().unwrap_or(0) >= 1,
        "the uncharged finding should be counted, not silently dropped: {summary}"
    );

    // A genuinely new secret in that same file must still fail the gate.
    let mut source = fs::read_to_string(root.join("src").join("settings.ts")).expect("read");
    source.push_str("export const backupKey = \"AKIAEEEEFFFFGGGGHHHH\";\n");
    fs::write(root.join("src").join("settings.ts"), source).expect("grow settings.ts");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "add another"]);
    index_repo(&repo);

    let review = ovecc(&repo, &["review", "--fail-on", "high", "--format", "json"]);
    let envelope: serde_json::Value = serde_json::from_slice(&review.stdout).expect("review json");
    assert!(
        !review.status.success(),
        "a new hardcoded secret must still fail: {}",
        envelope["data"]["summary"]
    );
    let new_findings = envelope["data"]["new_findings"]
        .as_array()
        .expect("new findings");
    assert!(
        new_findings
            .iter()
            .any(|finding| finding["kind"] == "hardcoded_secret"),
        "the added secret must be the named finding: {new_findings:#?}"
    );

    // Severity is part of a finding's identity, so a function pushed across a
    // band is a new fact: growing `endpoint` from medium to high complexity
    // must fail the gate even though the finding's kind, file, and symbol all
    // already existed.
    let complex_fn = |name: &str, branches: usize| -> String {
        let body: String = (1..=branches)
            .map(|i| format!("  if (n > {i}) {{ x += {i}; }}\n"))
            .collect();
        format!(
            "export function {name}(n: number): number {{\n  let x = 0;\n{body}  return x;\n}}\n"
        )
    };
    let secrets = "export const awsKey = \"AKIAAAAABBBBCCCCDDDD\";\n\
                   export const backupKey = \"AKIAEEEEFFFFGGGGHHHH\";\n";
    fs::write(
        root.join("src").join("settings.ts"),
        format!("{secrets}{}", complex_fn("endpoint", 12)),
    )
    .expect("medium endpoint");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "medium"]);
    index_repo(&repo);

    fs::write(
        root.join("src").join("settings.ts"),
        format!("{secrets}{}", complex_fn("endpoint", 30)),
    )
    .expect("high endpoint");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "escalate"]);
    index_repo(&repo);

    let review = ovecc(&repo, &["review", "--fail-on", "high", "--format", "json"]);
    let envelope: serde_json::Value = serde_json::from_slice(&review.stdout).expect("review json");
    let summary = &envelope["data"]["summary"];
    assert!(
        !review.status.success(),
        "an escalation to high must fail the gate: {summary}"
    );
    assert!(
        summary["resolved_findings"].as_u64().unwrap_or(0) >= 1,
        "the medium band it left behind reads as resolved: {summary}"
    );
}

#[test]
fn review_scopes_new_duplications_to_touched_lines() {
    // ~160 normalized tokens over 16 lines: identical copies form a clone
    // family above the 100-token / 10-line defaults (names normalize away).
    fn clone_copy(name: &str) -> String {
        let body = r#"  let total = 0;
  const items = [a, b, a + b, a - b];
  const flags = { low: a < b, high: a > b, same: a === b };
  for (const item of items) {
    if (item > a) { total += item * 2; } else { total -= item; }
    while (total > b) { total = total - b; }
  }
  if (flags.low && !flags.same) { total += 5; }
  switch (total % 3) {
    case 0: total += a; break;
    case 1: total -= b; break;
    default: total *= 2; break;
  }
  return total < 0 ? -total : total;
}
"#;
        format!("function {name}(a: number, b: number): number {{\n{body}")
    }

    let temp = git_repo();
    let root = temp.path();
    fs::create_dir_all(root.join("src")).expect("mkdir");
    let copies = format!("{}{}", clone_copy("alpha"), clone_copy("beta"));
    fs::write(root.join("src").join("util.ts"), &copies).expect("write util.ts");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    let repo = root.to_str().expect("utf8 path").to_string();
    index_repo(&repo);
    let review = |repo: &str| -> (bool, serde_json::Value) {
        let output = ovecc(repo, &["review", "--fail-on", "any", "--format", "json"]);
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("review json");
        (output.status.success(), envelope["data"]["summary"].clone())
    };

    let dupes = ovecc(&repo, &["dupes", "--format", "json"]);
    let envelope: serde_json::Value = serde_json::from_slice(&dupes.stdout).expect("dupes json");
    assert!(
        envelope["data"]["clone_families"].as_u64().unwrap_or(0) >= 1,
        "the planted pair must be a family at the defaults: {}",
        envelope["data"]
    );

    // An edit below both instances touches the file but no clone line: the
    // pre-existing family is not this change's doing. (A `function` here would
    // share a declaration prefix with the clone tail and stretch the second
    // instance's token run onto the appended line.)
    let mut source = copies.clone();
    source.push_str("const pad = 9;\n");
    fs::write(root.join("src").join("util.ts"), &source).expect("append pad");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "pad"]);
    index_repo(&repo);

    let (passed, summary) = review(&repo);
    assert_eq!(
        summary["new_duplications"], 0,
        "a family the change never touched is not new: {summary}"
    );
    assert!(
        passed,
        "an unrelated edit must pass --fail-on any: {summary}"
    );

    // A comment inside a clone shifts its line span without changing a token
    // of it, so the family is still the code it was before the change.
    source = source.replacen(
        "  let total = 0;\n",
        "  let total = 0;\n  // running total\n",
        1,
    );
    fs::write(root.join("src").join("util.ts"), &source).expect("insert comment");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "comment"]);
    index_repo(&repo);

    let (passed, summary) = review(&repo);
    assert_eq!(
        summary["new_duplications"], 0,
        "a comment inside a pre-existing clone does not make it new: {summary}"
    );
    assert!(
        passed,
        "a comment-only edit must pass --fail-on any: {summary}"
    );

    // Pasting a third copy is what introducing duplication looks like.
    source.push_str(&clone_copy("gamma"));
    fs::write(root.join("src").join("util.ts"), &source).expect("append gamma");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "copy again"]);
    index_repo(&repo);

    let (passed, summary) = review(&repo);
    assert!(
        summary["new_duplications"].as_u64().unwrap_or(0) >= 1,
        "the pasted copy must be charged to the change: {summary}"
    );
    assert!(
        !passed,
        "new duplication must fail --fail-on any: {summary}"
    );
}

/// Evolutionary coupling is the signal no import declares: two files that keep
/// being edited together, with nothing in the code tying them.
#[test]
fn coupling_reports_files_that_keep_changing_together() {
    let temp = git_repo();
    let root = temp.path();
    fs::create_dir_all(root.join("src")).expect("mkdir");

    // The registry and its schema are edited in lockstep, four times over. Each
    // round also carries a commit over two throwaway files: with no other
    // multi-file work to compare against, the pair would be the whole window
    // and its lift would fall back to 1.
    for round in 0..4 {
        for name in ["registry.ts", "schema.ts"] {
            fs::write(
                root.join("src").join(name),
                format!("export const entries{round} = {round};\n"),
            )
            .expect("write paired file");
        }
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", &format!("pair {round}")]);

        for side in ["a", "b"] {
            fs::write(
                root.join("src").join(format!("other{round}{side}.ts")),
                format!("export const other{round}{side} = {round};\n"),
            )
            .expect("write background file");
        }
        git(root, &["add", "."]);
        git(
            root,
            &["commit", "-q", "-m", &format!("background {round}")],
        );
    }

    let repo = root.to_str().expect("utf8 path").to_string();
    index_repo(&repo);

    let coupling = ovecc(&repo, &["coupling", "--format", "json"]);
    let envelope: serde_json::Value =
        serde_json::from_slice(&coupling.stdout).expect("coupling json");
    let pairs = envelope["data"]["pairs"]
        .as_array()
        .expect("pairs array")
        .clone();
    assert_eq!(pairs.len(), 1, "one pair, and only one: {pairs:?}");
    let pair = &pairs[0];
    assert_eq!(pair["left"], "src/registry.ts");
    assert_eq!(pair["right"], "src/schema.ts");
    assert_eq!(pair["support"], 4);
    assert!(
        pair["lift"].as_f64().expect("lift") > 1.0,
        "the pair meets more often than chance: {pair}"
    );
    assert_eq!(
        pair["commits"].as_array().expect("witnesses").len(),
        4,
        "each meeting is witnessed by its commit: {pair}"
    );
}
