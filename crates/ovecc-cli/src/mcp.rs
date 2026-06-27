//! Minimal Model Context Protocol (MCP) server over stdio.
//!
//! Exposes Ovecc to coding agents as a set of read-only tools (plus `index`)
//! that map one-to-one onto the CLI. Each tool re-invokes this same binary with
//! `--format json` and returns the machine-readable envelope, so the server is a
//! thin, deterministic wrapper over the contract `capabilities` already
//! describes — no new analysis lives here.
//!
//! Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout, hand-rolled to
//! keep the offline, dependency-light, synchronous design of the rest of Ovecc
//! (no async runtime, no SDK). Diagnostics go to stderr so they never corrupt
//! the protocol stream.

use anyhow::Result;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;

/// MCP protocol revision we implement. We echo the client's requested version
/// when present (forward-compatible), falling back to this.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// Runs the stdio server loop until stdin closes. Always exits 0: a transport
/// read error ends the session cleanly rather than failing the process.
pub fn serve() -> Result<u8> {
    let exe = std::env::current_exe()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            continue; // ignore unparseable frames rather than crash the stream
        };
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params");
        let response = handle(method, params, &exe);

        // Notifications (no `id`) never get a reply.
        let Some(id) = id else { continue };
        let message = match response {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, msg)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
            }
        };
        write_message(&mut stdout, &message)?;
    }
    Ok(0)
}

fn write_message(out: &mut impl Write, message: &Value) -> Result<()> {
    serde_json::to_writer(&mut *out, message)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Dispatches one JSON-RPC method. `Ok` carries the `result` object; `Err`
/// carries a `(code, message)` JSON-RPC error. Tool *execution* failures are
/// reported in-band as a result with `isError: true`, per MCP convention.
fn handle(method: &str, params: Option<&Value>, exe: &Path) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => {
            let version = params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL_VERSION);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ovecc", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Deterministic, offline architecture intelligence. \
                    Call ovecc_capabilities first for the full contract (commands, \
                    metrics, rules, exit codes). Run ovecc_index once before querying \
                    a repository. Every tool accepts an optional `repo` path."
            }))
        }
        "tools/list" => Ok(json!({"tools": tool_specs()})),
        "tools/call" => {
            let params = params.ok_or((-32602, "missing params".to_string()))?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or((-32602, "missing tool name".to_string()))?;
            let empty = json!({});
            let arguments = params.get("arguments").unwrap_or(&empty);
            Ok(call_tool(name, arguments, exe))
        }
        "ping" => Ok(json!({})),
        _ => Err((-32601, format!("method not found: {method}"))),
    }
}

/// Runs the CLI subcommand behind a tool and wraps stdout as the tool result.
/// Unknown tools and bad arguments come back as `isError` results so the agent
/// can recover without a protocol-level failure.
fn call_tool(name: &str, arguments: &Value, exe: &Path) -> Value {
    let Some(sub_argv) = build_argv(name, arguments) else {
        return error_result(format!("unknown tool or missing required argument: {name}"));
    };
    let repo = arguments
        .get("repo")
        .and_then(Value::as_str)
        .unwrap_or(".")
        .to_string();

    let mut argv = vec![
        "--repo".to_string(),
        repo,
        "--format".to_string(),
        "json".to_string(),
    ];
    argv.extend(sub_argv);

    match std::process::Command::new(exe).args(&argv).output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            // Exit 0 = ok; 1 = a `--fail-on` threshold (a signal, not an error).
            // 2+ are real failures (usage, repo/config, db, parser, internal).
            if code >= 2 {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error_result(format!("ovecc exited with code {code}: {}", stderr.trim()))
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                json!({"content": [{"type": "text", "text": stdout}], "isError": false})
            }
        }
        Err(err) => error_result(format!("failed to run ovecc: {err}")),
    }
}

fn error_result(message: String) -> Value {
    json!({"content": [{"type": "text", "text": message}], "isError": true})
}

/// Builds the CLI sub-argv for a tool, or `None` if the tool is unknown or a
/// required argument is absent. The global `--repo`/`--format` flags are added
/// by the caller.
fn build_argv(name: &str, args: &Value) -> Option<Vec<String>> {
    let s = |key: &str| args.get(key).and_then(Value::as_str);
    let n = |key: &str| args.get(key).and_then(Value::as_u64);
    let flag = |key: &str| args.get(key).and_then(Value::as_bool).unwrap_or(false);
    let mut argv = Vec::new();
    match name {
        "ovecc_index" => {
            argv.push("index".into());
            if let Some(path) = s("path") {
                argv.push(path.into());
            }
        }
        "ovecc_capabilities" => argv.push("capabilities".into()),
        "ovecc_summary" => argv.push("summary".into()),
        "ovecc_report" => argv.push("report".into()),
        "ovecc_health" => argv.push("health".into()),
        "ovecc_deadcode" => argv.push("deadcode".into()),
        "ovecc_audit" => argv.push("audit".into()),
        "ovecc_conventions" => argv.push("conventions".into()),
        "ovecc_impact" => {
            argv.push("impact".into());
            argv.push(s("target")?.into());
            if let Some(direction) = s("direction") {
                argv.push("--direction".into());
                argv.push(direction.into());
            }
            if let Some(depth) = n("max_depth") {
                argv.push("--max-depth".into());
                argv.push(depth.to_string());
            }
        }
        "ovecc_violations" => {
            argv.push("violations".into());
            if let Some(severity) = s("severity") {
                argv.push("--severity".into());
                argv.push(severity.into());
            }
            if flag("baseline") {
                argv.push("--baseline".into());
            }
        }
        "ovecc_security" => {
            argv.push("security".into());
            if let Some(severity) = s("severity") {
                argv.push("--severity".into());
                argv.push(severity.into());
            }
        }
        "ovecc_hotspots" => {
            argv.push("hotspots".into());
            if let Some(limit) = n("limit") {
                argv.push("--limit".into());
                argv.push(limit.to_string());
            }
        }
        "ovecc_dupes" => {
            argv.push("dupes".into());
            if let Some(min_tokens) = n("min_tokens") {
                argv.push("--min-tokens".into());
                argv.push(min_tokens.to_string());
            }
        }
        "ovecc_query" => {
            argv.push("query".into());
            argv.push(s("query")?.into());
        }
        "ovecc_explain" => {
            argv.push("explain".into());
            argv.push(s("target")?.into());
        }
        "ovecc_context" => {
            argv.push("export".into());
            argv.push("context".into());
            argv.push(s("target")?.into());
        }
        "ovecc_drift" => {
            argv.push("drift".into());
            if let Some(since) = s("since") {
                argv.push("--since".into());
                argv.push(since.into());
            }
        }
        _ => return None,
    }
    Some(argv)
}

/// The `tools/list` payload. Every tool takes an optional `repo`; the schemas
/// mirror the CLI arguments so an agent can drive an end-to-end audit.
fn tool_specs() -> Value {
    let repo = json!({"type": "string", "description": "Repository root path (defaults to the server's working directory)."});
    let severity = json!({"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Only findings at or above this severity."});
    let obj = |props: Value, required: Value| json!({"type": "object", "properties": props, "required": required});

    json!([
        {"name": "ovecc_capabilities", "description": "The machine-readable contract: every command, metric, rule, severity, exit code, and output format. Call this first.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_index", "description": "Build or update the local architecture database for a repository. Run once before querying.", "inputSchema": obj(json!({"repo": repo, "path": {"type": "string", "description": "Repository path to index (alternative to repo)."}}), json!([]))},
        {"name": "ovecc_summary", "description": "Repository-level architecture health: coupling, density, cycles, risk score.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_report", "description": "One-shot architecture report: summary + cycles + violations + security + hotspots.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_impact", "description": "Blast radius of changing a target (module, table:NAME, api:METHOD:/path): the impacted nodes and the paths that reach them.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to analyze, e.g. Billing, table:customers, api:GET:/x."}, "direction": {"type": "string", "enum": ["downstream", "upstream", "both"], "description": "Traversal direction (default downstream)."}, "max_depth": {"type": "integer", "description": "Maximum traversal depth (default 6)."}}), json!(["target"]))},
        {"name": "ovecc_query", "description": "Structured architecture query. Verbs: deps X, rdeps X, paths X, module X, 'a -> b', hotspots, violations, cycles.", "inputSchema": obj(json!({"repo": repo, "query": {"type": "string", "description": "Query expression, e.g. 'cycles' or 'deps Billing'."}}), json!(["query"]))},
        {"name": "ovecc_violations", "description": "Architecture and rule findings (boundaries, banned imports, cycles), with optional severity filter and baseline.", "inputSchema": obj(json!({"repo": repo, "severity": severity, "baseline": {"type": "boolean", "description": "Hide findings recorded in the baseline (show only new ones)."}}), json!([]))},
        {"name": "ovecc_security", "description": "Security findings: hardcoded secrets, insecure patterns, weak crypto, tainted source->sink flows.", "inputSchema": obj(json!({"repo": repo, "severity": severity}), json!([]))},
        {"name": "ovecc_audit", "description": "Offline OSV audit of declared dependencies against the local vulnerability database.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_health", "description": "Functions over the cyclomatic/cognitive complexity thresholds (oxc TS/JS extractor).", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_deadcode", "description": "Likely dead code: unused exports and unreachable files, from exports + entry-point reachability.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_dupes", "description": "Duplicated code (clone families) over a normalized token stream.", "inputSchema": obj(json!({"repo": repo, "min_tokens": {"type": "integer", "description": "Minimum shared token run to report (default 50)."}}), json!([]))},
        {"name": "ovecc_hotspots", "description": "Technical-debt hotspot ranking: churn x coupling x ownership.", "inputSchema": obj(json!({"repo": repo, "limit": {"type": "integer", "description": "Number of hotspots to return (default 10)."}}), json!([]))},
        {"name": "ovecc_conventions", "description": "Learned repository conventions and their deviations.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_drift", "description": "Architecture drift over time versus a previous snapshot or Git ref.", "inputSchema": obj(json!({"repo": repo, "since": {"type": "string", "description": "Git ref or snapshot to compare against, e.g. main or v1.0.0."}}), json!([]))},
        {"name": "ovecc_explain", "description": "Offline, deterministic architectural explanation of a target from its context slice.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to explain, e.g. Billing."}}), json!(["target"]))},
        {"name": "ovecc_context", "description": "Deterministic ContextSlice for a target as JSON, for feeding other tools or agents.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to slice, e.g. Billing."}}), json!(["target"]))}
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_argv_for_simple_and_parameterized_tools() {
        assert_eq!(build_argv("ovecc_summary", &json!({})).unwrap(), vec!["summary"]);
        assert_eq!(
            build_argv("ovecc_impact", &json!({"target": "Billing", "direction": "both", "max_depth": 3})).unwrap(),
            vec!["impact", "Billing", "--direction", "both", "--max-depth", "3"]
        );
        assert_eq!(
            build_argv("ovecc_query", &json!({"query": "cycles"})).unwrap(),
            vec!["query", "cycles"]
        );
        assert_eq!(
            build_argv("ovecc_context", &json!({"target": "Billing"})).unwrap(),
            vec!["export", "context", "Billing"]
        );
        assert_eq!(
            build_argv("ovecc_security", &json!({"severity": "high"})).unwrap(),
            vec!["security", "--severity", "high"]
        );
    }

    #[test]
    fn missing_required_argument_or_unknown_tool_yields_none() {
        assert!(build_argv("ovecc_impact", &json!({})).is_none());
        assert!(build_argv("ovecc_query", &json!({})).is_none());
        assert!(build_argv("ovecc_nope", &json!({})).is_none());
    }

    #[test]
    fn initialize_echoes_protocol_version_and_lists_tools() {
        let exe = std::path::PathBuf::from("ovecc");
        let init = handle("initialize", Some(&json!({"protocolVersion": "2025-03-26"})), &exe).unwrap();
        assert_eq!(init["protocolVersion"], "2025-03-26");
        assert_eq!(init["serverInfo"]["name"], "ovecc");

        let listed = handle("tools/list", None, &exe).unwrap();
        let tools = listed["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "ovecc_capabilities"));
        assert!(tools.len() >= 15);
    }

    #[test]
    fn unknown_method_is_a_jsonrpc_error() {
        let exe = std::path::PathBuf::from("ovecc");
        assert!(handle("frobnicate", None, &exe).is_err());
    }
}
