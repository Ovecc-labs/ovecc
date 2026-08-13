use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Deserialize)]
struct CaseSpec {
    #[serde(default = "default_command")]
    command: String,
    #[serde(default)]
    config: Option<String>,
    #[serde(default)]
    require: Vec<FindingSpec>,
    #[serde(default)]
    deny: Vec<FindingSpec>,
}

#[derive(Deserialize)]
struct FindingSpec {
    rule: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    title: Option<String>,
}

fn default_command() -> String {
    "violations".to_string()
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("accuracy")
}

fn corpus_cases() -> Vec<PathBuf> {
    let mut cases: Vec<PathBuf> = fs::read_dir(corpus_root())
        .expect("read the accuracy corpus directory")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    cases.sort();
    cases
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

fn case_findings(case: &Path, spec: &CaseSpec) -> (tempfile::TempDir, Vec<serde_json::Value>) {
    let staged = tempfile::tempdir().expect("temp dir");
    copy_dir(&case.join("repo"), staged.path());
    if let Some(config) = &spec.config {
        let dir = staged.path().join(".ovecc");
        fs::create_dir_all(&dir).expect("create .ovecc");
        fs::write(dir.join("config.toml"), config).expect("write case config");
    }
    let repo = staged.path().to_str().expect("utf8 path").to_string();
    let indexed = ovecc(&repo, &["index"]);
    assert!(
        indexed.status.success(),
        "index failed for {} ({}): {}",
        case.display(),
        indexed.status,
        String::from_utf8_lossy(&indexed.stderr)
    );
    let out = ovecc(&repo, &[spec.command.as_str(), "--format", "json"]);
    assert!(
        out.status.success(),
        "{} failed for {} ({}): {}",
        spec.command,
        case.display(),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("command envelope json");
    (staged, extract_findings(&envelope["data"]))
}

fn extract_findings(data: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(findings) = data.as_array() {
        return findings.clone();
    }
    for key in ["findings", "new_findings"] {
        if let Some(findings) = data[key].as_array() {
            return findings.clone();
        }
    }
    Vec::new()
}

fn finding_paths(finding: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(evidence) = finding["evidence"].as_array() {
        paths.extend(
            evidence
                .iter()
                .filter_map(|entry| entry["file_path"].as_str())
                .map(str::to_string),
        );
    }
    if let Some(target) = finding["target"]["id"].as_str() {
        paths.push(target.to_string());
    }
    paths
}

fn matches(finding: &serde_json::Value, spec: &FindingSpec) -> bool {
    if finding["rule_name"].as_str() != Some(spec.rule.as_str()) {
        return false;
    }
    if let Some(path) = &spec.path
        && !finding_paths(finding).iter().any(|found| found == path)
    {
        return false;
    }
    if let Some(title) = &spec.title
        && !finding["title"]
            .as_str()
            .is_some_and(|t| t.contains(title.as_str()))
    {
        return false;
    }
    true
}

fn describe(spec: &FindingSpec) -> String {
    let mut description = spec.rule.clone();
    if let Some(path) = &spec.path {
        description.push_str(&format!(" @ {path}"));
    }
    if let Some(title) = &spec.title {
        description.push_str(&format!(" titled '{title}'"));
    }
    description
}

#[test]
fn accuracy_corpus_detects_required_and_stays_silent_on_probes() {
    let cases = corpus_cases();
    assert!(!cases.is_empty(), "the accuracy corpus must contain cases");

    let mut required = 0usize;
    let mut probes = 0usize;
    let mut misses: Vec<String> = Vec::new();
    let mut false_positives: Vec<String> = Vec::new();

    for case in &cases {
        let name = case
            .file_name()
            .expect("case name")
            .to_string_lossy()
            .to_string();
        let manifest = fs::read_to_string(case.join("expected.toml")).expect("read expected.toml");
        let spec: CaseSpec = toml::from_str(&manifest).expect("parse expected.toml");
        assert!(
            !spec.require.is_empty() || !spec.deny.is_empty(),
            "{name}: a case must require or deny at least one finding"
        );
        let (_staged, findings) = case_findings(case, &spec);
        for expectation in &spec.require {
            required += 1;
            if !findings.iter().any(|finding| matches(finding, expectation)) {
                misses.push(format!("{name}: missed {}", describe(expectation)));
            }
        }
        for probe in &spec.deny {
            probes += 1;
            if let Some(finding) = findings.iter().find(|finding| matches(finding, probe)) {
                false_positives.push(format!(
                    "{name}: probe {} fired as '{}'",
                    describe(probe),
                    finding["title"].as_str().unwrap_or("?")
                ));
            }
        }
    }

    let detected = required - misses.len();
    let silent = probes - false_positives.len();
    println!("[accuracy] cases: {}", cases.len());
    println!("[accuracy] required findings detected: {detected}/{required}");
    println!("[accuracy] true-negative probes silent: {silent}/{probes}");
    assert!(
        misses.is_empty() && false_positives.is_empty(),
        "accuracy corpus failed\nmisses:\n  {}\nfalse positives:\n  {}",
        misses.join("\n  "),
        false_positives.join("\n  ")
    );
}
