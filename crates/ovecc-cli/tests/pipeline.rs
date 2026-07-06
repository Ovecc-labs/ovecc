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
