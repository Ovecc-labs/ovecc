//! `ovecc init --agent`: point a repository's coding agent at the graph before
//! it falls back to text search, plus the hidden `agent-hook` command the
//! wiring calls. The wiring is written for Claude Code's hook system
//! (`.claude/settings.json`); the MCP server stays the agent-agnostic surface.
//!
//! The policy is redirect, not toll booth: a repo-wide text search is turned
//! into an `ovecc grep` (same coverage, capped output), while a search scoped
//! to an existing path or file always passes. The earlier design unlocked all
//! search for five minutes after one ovecc call, and measured agent sessions
//! showed what that buys: the ovecc call stacked on top of the unchanged
//! grep+read routine instead of replacing it. The block still fails open when
//! the graph is absent, so the agent is never trapped. Everything runs through
//! the ovecc binary itself; no interpreter or script is written to the repo.

use crate::cli::AgentHookKind;
use anyhow::{Context, Result};
use ovecc_core::config::ProjectPaths;
use serde_json::{Value, json};
use std::io::Read;
use std::path::Path;

const ENFORCE_BODY: &str = "\
Repo-wide text search is blocked here: the index answers it in fewer tokens.
  ovecc grep <pattern> [path]   search: definitions first, then matches
  ovecc read <name|file:lines>  one symbol's source, or a file's outline
  ovecc query \"rdeps <name>\"    direct callers (\"deps <name>\" for callees)
  ovecc impact <name>           blast radius of changing <name>
";

/// The pass-through line must match what the hook actually allows, or the
/// agent burns a turn retrying a scope that will be blocked again.
fn enforce_message(strict: bool) -> String {
    let valve = if strict {
        "A search against one existing file passes through unchanged."
    } else {
        "A search scoped to an existing path or file passes through unchanged."
    };
    format!("{ENFORCE_BODY}{valve}\nSet OVECC_AGENT_HOOKS=off to disable.\n")
}

/// The hook commands `init --agent` writes into settings, matched to the events
/// they fire on. Kept in one place so wiring and unwiring stay in sync.
const HOOK_WIRING: &[(&str, &str, &str)] = &[
    ("PreToolUse", "Grep|Bash", "ovecc agent-hook enforce"),
    ("SessionStart", "", "ovecc agent-hook session"),
];

pub(crate) fn run_hook(kind: AgentHookKind) -> Result<u8> {
    match kind {
        AgentHookKind::Enforce => Ok(enforce()),
        AgentHookKind::Mark => Ok(mark()),
        AgentHookKind::Session => Ok(session()),
    }
}

fn hooks_disabled() -> bool {
    std::env::var("OVECC_AGENT_HOOKS")
        .map(|v| v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
}

/// Strict mode narrows the valve: only a search against one existing FILE
/// passes; directory scopes are served by the index too. Opt-in per session
/// (`OVECC_AGENT_HOOKS=strict`) while the A/B decides whether it becomes the
/// default.
fn strict_mode() -> bool {
    std::env::var("OVECC_AGENT_HOOKS")
        .map(|v| v.eq_ignore_ascii_case("strict"))
        .unwrap_or(false)
}

fn project_root() -> std::path::PathBuf {
    std::env::var_os("CLAUDE_PROJECT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn read_event() -> Value {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        return Value::Null;
    }
    serde_json::from_str(&buf).unwrap_or(Value::Null)
}

/// PreToolUse: block a repo-wide text search while the index can answer it.
/// Exit 2 returns the message to the agent as the tool error; exit 0 lets the
/// call through. Fails open whenever the graph cannot answer.
fn enforce() -> u8 {
    if hooks_disabled() {
        return 0;
    }
    let root = project_root();
    if !graph_ready(&root) {
        return 0;
    }
    let event = read_event();
    let tool = event.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let input = event.get("tool_input").cloned().unwrap_or(Value::Null);
    let strict = strict_mode();
    if is_broad_search(&root, tool, &input, strict) {
        eprint!("{}", enforce_message(strict));
        return 2;
    }
    0
}

/// PostToolUse survivor of the grace-window design: it used to time-stamp an
/// unlock marker. Settings wired by earlier versions still invoke it, so the
/// verb stays as an accepted no-op instead of failing their sessions.
fn mark() -> u8 {
    0
}

/// SessionStart: a one-line pointer so the session reaches for the index
/// before rediscovering the repo with grep, and does not waste a call
/// re-indexing a database that is already there.
fn session() -> u8 {
    if hooks_disabled() || !graph_ready(&project_root()) {
        return 0;
    }
    println!(
        "Architecture index ready (do not re-run `ovecc index` unless files changed). \
         Search: ovecc grep <pattern> [path]. One symbol's source: ovecc read <name>. \
         Callers: ovecc query \"rdeps <name>\". Blast radius: ovecc impact <name>."
    );
    0
}

fn graph_ready(root: &Path) -> bool {
    root.join(".ovecc").join("graph.db").exists()
}

/// Whether the tool call is a repo-wide text search the index should serve
/// instead. A search with a real path scope passes: reading one file's matches
/// is exactly the kind of call `ovecc grep` does not need to intercept. In
/// strict mode only a single-file scope passes. An `ovecc` invocation on the
/// Bash line is never blocked.
fn is_broad_search(root: &Path, tool: &str, input: &Value, strict: bool) -> bool {
    if tool == "Grep" {
        let path = input.get("path").and_then(Value::as_str).unwrap_or("");
        return !is_scope_path(root, path, strict);
    }
    if tool != "Bash" {
        return false;
    }
    let command = input.get("command").and_then(Value::as_str).unwrap_or("");
    if command.contains("ovecc") {
        return false;
    }
    let mut any_search = false;
    let mut scoped = false;
    for segment in command.split(['|', ';', '&']) {
        let tokens = shell_tokens(segment);
        match searcher_position(&tokens) {
            Some(position) => {
                any_search = true;
                // The first non-flag token after the searcher is the pattern;
                // any later one naming a real path scopes the search.
                let mut rest = tokens[position + 1..]
                    .iter()
                    .filter(|t| *t != "--" && !t.starts_with('-'));
                let _pattern = rest.next();
                if rest.any(|t| is_scope_path(root, t, strict)) {
                    scoped = true;
                }
            }
            // A non-search segment naming a real file scopes the pipeline:
            // `cat notes.txt | grep foo` searches one file, not the repo.
            None => {
                if tokens.iter().any(|t| is_scope_path(root, t, strict)) {
                    scoped = true;
                }
            }
        }
    }
    any_search && !scoped
}

/// A token that names an existing file — or, outside strict mode, an existing
/// directory other than the repository root itself. The root (and `.`) is what
/// a repo-wide search passes, so it never counts as a scope.
fn is_scope_path(root: &Path, token: &str, strict: bool) -> bool {
    if token.is_empty() || matches!(token, "." | "./" | ".\\" | "/") {
        return false;
    }
    let candidate = Path::new(token);
    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    if strict {
        return absolute.is_file();
    }
    if !absolute.exists() {
        return false;
    }
    match (absolute.canonicalize(), root.canonicalize()) {
        (Ok(a), Ok(r)) => a != r,
        _ => true,
    }
}

/// Whitespace-splitting that honours single and double quotes (stripped from
/// the token) and treats backslashes literally — they are Windows path
/// separators here, not escapes.
fn shell_tokens(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in segment.chars() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => current.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (None, _) => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Index of the search verb in the token list. Only the command position
/// counts — the segment's first token, or right after a wrapper like `git`
/// or `xargs` — so `pip install grep` is not read as a search.
fn searcher_position(tokens: &[String]) -> Option<usize> {
    const SEARCHERS: &[&str] = &[
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ack",
        "ag",
        "findstr",
        "select-string",
        "sls",
    ];
    const WRAPPERS: &[&str] = &["git", "xargs", "sudo", "command", "exec"];
    tokens.iter().enumerate().position(|(index, token)| {
        let bare = token.rsplit(['/', '\\']).next().unwrap_or(token);
        if !SEARCHERS.contains(&bare) {
            return false;
        }
        index == 0 || WRAPPERS.contains(&tokens[index - 1].as_str())
    })
}

pub(crate) fn wire(paths: &ProjectPaths, remove: bool) -> Result<u8> {
    let claude_dir = paths.root.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    let existing: Value = match std::fs::read_to_string(&settings_path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON", settings_path.display()))?,
        Err(_) => json!({}),
    };

    let updated = if remove {
        remove_agent_hooks(existing)
    } else {
        merge_agent_hooks(existing)
    };

    if remove && !settings_path.exists() {
        println!("No agent wiring to remove.");
        return Ok(0);
    }

    std::fs::create_dir_all(&claude_dir)?;
    let mut serialized = serde_json::to_string_pretty(&updated)?;
    serialized.push('\n');
    std::fs::write(&settings_path, serialized)?;

    if remove {
        println!("Removed ovecc hooks from {}", settings_path.display());
    } else {
        println!(
            "Wired the coding agent to the graph in {}",
            settings_path.display()
        );
        println!();
        println!("Before it text-searches, the agent now queries the graph; the block");
        println!("fails open when ovecc cannot answer. Disable per-session with");
        println!("OVECC_AGENT_HOOKS=off, or undo with `ovecc init --agent --remove`.");
        println!("Commit .claude/settings.json to share this with the team.");
    }
    Ok(0)
}

/// Adds ovecc's hook entries to the settings, leaving any of the user's own
/// hooks untouched and never duplicating our own on a re-run.
fn merge_agent_hooks(mut settings: Value) -> Value {
    let hooks = settings
        .as_object_mut()
        .expect("settings root is an object")
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks = hooks.as_object_mut().expect("hooks is an object");
    for (event, matcher, command) in HOOK_WIRING {
        let entries = hooks
            .entry(event.to_string())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("event holds an array");
        if entries.iter().any(|e| entry_command_is(e, command)) {
            continue;
        }
        let mut entry = json!({ "hooks": [{ "type": "command", "command": command }] });
        if !matcher.is_empty() {
            entry
                .as_object_mut()
                .unwrap()
                .insert("matcher".to_string(), json!(matcher));
        }
        entries.push(entry);
    }
    settings
}

fn remove_agent_hooks(mut settings: Value) -> Value {
    if let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) {
        for entries in hooks.values_mut() {
            if let Some(list) = entries.as_array_mut() {
                list.retain(|entry| !entry_targets_ovecc(entry));
            }
        }
        hooks.retain(|_, entries| entries.as_array().map(|l| !l.is_empty()).unwrap_or(true));
    }
    settings
}

fn entry_command_is(entry: &Value, command: &str) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .map(|inner| {
            inner
                .iter()
                .any(|h| h.get("command").and_then(Value::as_str) == Some(command))
        })
        .unwrap_or(false)
}

fn entry_targets_ovecc(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .map(|inner| {
            inner.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .map(|c| c.starts_with("ovecc agent-hook"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little repo: `src/` and `notes.txt` exist, nothing else does.
    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        dir
    }

    fn bash(command: &str) -> Value {
        json!({ "command": command })
    }

    #[test]
    fn repo_wide_searches_are_broad() {
        let repo = repo();
        let root = repo.path();
        assert!(is_broad_search(root, "Grep", &json!({}), false));
        assert!(is_broad_search(root, "Grep", &json!({"path": "."}), false));
        assert!(is_broad_search(root, "Bash", &bash("grep -r foo ."), false));
        assert!(is_broad_search(root, "Bash", &bash("git grep foo"), false));
        assert!(is_broad_search(root, "Bash", &bash("rg foo"), false));
        assert!(is_broad_search(
            root,
            "Bash",
            &bash("/usr/bin/grep foo"),
            false
        ));
        // The path scope must actually exist to count.
        assert!(is_broad_search(
            root,
            "Bash",
            &bash("rg foo missing/"),
            false
        ));
    }

    #[test]
    fn scoped_searches_pass() {
        let repo = repo();
        let root = repo.path();
        assert!(!is_broad_search(
            root,
            "Grep",
            &json!({"path": "src"}),
            false
        ));
        assert!(!is_broad_search(root, "Bash", &bash("rg foo src"), false));
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("grep foo notes.txt"),
            false
        ));
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("rg foo \"src\""),
            false
        ));
        // A pipe fed from a named file is a one-file search, not a repo scan.
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("cat notes.txt | grep foo"),
            false
        ));
    }

    #[test]
    fn strict_mode_only_passes_single_files() {
        let repo = repo();
        let root = repo.path();
        // Directory scopes are broad under strict; a named file still passes.
        assert!(is_broad_search(root, "Grep", &json!({"path": "src"}), true));
        assert!(is_broad_search(root, "Bash", &bash("rg foo src"), true));
        assert!(!is_broad_search(
            root,
            "Grep",
            &json!({"path": "notes.txt"}),
            true
        ));
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("grep foo notes.txt"),
            true
        ));
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("ovecc grep foo"),
            true
        ));
        // The message names what actually passes in each mode.
        assert!(enforce_message(true).contains("one existing file"));
        assert!(enforce_message(false).contains("path or file"));
    }

    #[test]
    fn ovecc_and_ordinary_commands_are_not_broad() {
        let repo = repo();
        let root = repo.path();
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("ovecc query \"rdeps foo\""),
            false
        ));
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("ovecc grep foo"),
            false
        ));
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("echo foo | ovecc query deps"),
            false
        ));
        assert!(!is_broad_search(root, "Bash", &bash("cargo build"), false));
        assert!(!is_broad_search(root, "Read", &json!({}), false));
        assert!(!is_broad_search(root, "Bash", &bash("ls -la"), false));
        // A searcher mentioned off the command position is not a search.
        assert!(!is_broad_search(
            root,
            "Bash",
            &bash("pip install grep"),
            false
        ));
    }

    #[test]
    fn shell_tokens_honour_quotes() {
        assert_eq!(
            shell_tokens("rg 'foo bar' \"my dir\""),
            vec!["rg", "foo bar", "my dir"]
        );
        assert_eq!(
            shell_tokens("grep -r x src\\sub"),
            vec!["grep", "-r", "x", "src\\sub"]
        );
    }

    #[test]
    fn wiring_is_idempotent_and_preserves_user_hooks() {
        let user = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [{ "type": "command", "command": "my-linter" }] }
                ]
            }
        });
        let once = merge_agent_hooks(user.clone());
        let twice = merge_agent_hooks(once.clone());
        assert_eq!(once, twice, "re-running must not duplicate hooks");

        let pre = once["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(
            pre.iter()
                .any(|e| entry_command_is(e, "ovecc agent-hook enforce")),
            "ovecc hook added"
        );
        assert!(
            pre.iter().any(|e| e["hooks"][0]["command"] == "my-linter"),
            "user hook preserved"
        );
    }

    #[test]
    fn remove_takes_out_only_ovecc_hooks() {
        let wired = merge_agent_hooks(json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [{ "type": "command", "command": "my-linter" }] }
                ]
            }
        }));
        let cleaned = remove_agent_hooks(wired);
        let pre = cleaned["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "only the user's hook remains");
        assert_eq!(pre[0]["hooks"][0]["command"], "my-linter");
        // SessionStart held only our hook, so it is dropped entirely.
        assert!(cleaned["hooks"].get("SessionStart").is_none());
    }
}
