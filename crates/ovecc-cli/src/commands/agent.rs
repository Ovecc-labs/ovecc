//! `ovecc init --agent`: point a repository's coding agent at the graph before
//! it falls back to text search, plus the hidden `agent-hook` command the
//! wiring calls. The wiring is written for Claude Code's hook system
//! (`.claude/settings.json`); the MCP server stays the agent-agnostic surface.
//!
//! The policy is graph-first, grep-fallback: a broad text search is blocked
//! while the graph can answer it, but the block fails open the moment ovecc
//! cannot help (no index, or a query already ran) so the agent is never
//! trapped. Everything runs through the ovecc binary itself; no interpreter or
//! script is written to the repo.

use crate::cli::AgentHookKind;
use anyhow::{Context, Result};
use ovecc_core::config::ProjectPaths;
use serde_json::{Value, json};
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

/// Grace after any ovecc call during which text search is allowed, so the agent
/// can read string literals, comments, and log lines it legitimately needs.
const GRACE_SECONDS: u64 = 300;

const MARKER: &str = "agent-graph-query";

const ENFORCE_MESSAGE: &str = "\
Broad text search is blocked here: the architecture graph already answers it.
Query the graph instead:
  ovecc query \"rdeps <name>\"   what depends on <name> (callers)
  ovecc query \"deps <name>\"    what <name> depends on (callees)
  ovecc impact <name>          blast radius of changing <name>
  ovecc context <name>         deps, dependents, findings for one element
Unknown names return did-you-mean suggestions. After one ovecc call, text
search unlocks for 5 minutes. Set OVECC_AGENT_HOOKS=off to disable.
";

/// The hook commands `init --agent` writes into settings, matched to the events
/// they fire on. Kept in one place so wiring and unwiring stay in sync.
const HOOK_WIRING: &[(&str, &str, &str)] = &[
    ("PreToolUse", "Grep|Bash", "ovecc agent-hook enforce"),
    ("PostToolUse", "Bash|mcp__ovecc.*", "ovecc agent-hook mark"),
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

/// PreToolUse: block a broad text search while the graph can answer it. Exit 2
/// returns the message to the agent as the tool error; exit 0 lets the call
/// through. Fails open whenever the graph cannot answer.
fn enforce() -> u8 {
    if hooks_disabled() {
        return 0;
    }
    let root = project_root();
    if !graph_ready(&root) || recently_queried(&root) {
        return 0;
    }
    let event = read_event();
    let tool = event.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let command = event
        .get("tool_input")
        .and_then(|i| i.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if is_broad_search(tool, command) {
        eprint!("{ENFORCE_MESSAGE}");
        return 2;
    }
    0
}

/// PostToolUse: after any ovecc call, touch the marker so text search unlocks
/// for the grace window.
fn mark() -> u8 {
    let event = read_event();
    let tool = event.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let command = event
        .get("tool_input")
        .and_then(|i| i.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if is_ovecc_call(tool, command) {
        let dir = project_root().join(".ovecc");
        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = std::fs::write(dir.join(MARKER), b"");
        }
    }
    0
}

/// SessionStart: a one-line pointer so the session reaches for the graph before
/// rediscovering the repo with grep.
fn session() -> u8 {
    if hooks_disabled() || !graph_ready(&project_root()) {
        return 0;
    }
    println!(
        "The architecture graph is indexed. Query it before any text search: \
         ovecc query \"rdeps <name>\" | \"deps <name>\" | impact <name> | context <name>."
    );
    0
}

fn graph_ready(root: &Path) -> bool {
    root.join(".ovecc").join("graph.db").exists()
}

fn recently_queried(root: &Path) -> bool {
    let marker = root.join(".ovecc").join(MARKER);
    let Ok(modified) = std::fs::metadata(&marker).and_then(|m| m.modified()) else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age.as_secs() < GRACE_SECONDS
}

fn is_ovecc_call(tool: &str, command: &str) -> bool {
    tool.starts_with("mcp__ovecc") || (tool == "Bash" && command.contains("ovecc"))
}

/// Whether the tool call is a broad text search the graph should answer first.
/// An `ovecc` invocation on the Bash line is never a broad search.
fn is_broad_search(tool: &str, command: &str) -> bool {
    if tool == "Grep" {
        return true;
    }
    if tool != "Bash" || command.contains("ovecc") {
        return false;
    }
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
    command.split(['|', ';', '&']).any(|segment| {
        let segment = segment.trim();
        if segment.starts_with("git grep") {
            return true;
        }
        let first = segment.split_whitespace().next().unwrap_or("");
        let bare = first.rsplit(['/', '\\']).next().unwrap_or(first);
        SEARCHERS.contains(&bare)
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

    #[test]
    fn grep_and_search_binaries_are_broad() {
        assert!(is_broad_search("Grep", ""));
        assert!(is_broad_search("Bash", "grep -r foo ."));
        assert!(is_broad_search("Bash", "git grep foo"));
        assert!(is_broad_search("Bash", "rg foo"));
        assert!(is_broad_search("Bash", "cat x.txt | grep foo"));
        assert!(is_broad_search("Bash", "/usr/bin/grep foo"));
    }

    #[test]
    fn ovecc_and_ordinary_commands_are_not_broad() {
        assert!(!is_broad_search("Bash", "ovecc query \"rdeps foo\""));
        // A pipe into ovecc must not be read as a search.
        assert!(!is_broad_search("Bash", "echo foo | ovecc query deps"));
        assert!(!is_broad_search("Bash", "cargo build"));
        assert!(!is_broad_search("Read", ""));
        assert!(!is_broad_search("Bash", "ls -la"));
    }

    #[test]
    fn marks_only_ovecc_calls() {
        assert!(is_ovecc_call("mcp__ovecc__ovecc_query", ""));
        assert!(is_ovecc_call("Bash", "ovecc impact foo"));
        assert!(!is_ovecc_call("Bash", "grep foo"));
        assert!(!is_ovecc_call("Grep", ""));
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
