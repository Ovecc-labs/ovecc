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
///
/// When `OVECC_MCP_LOG` is set, each call is traced to stderr (never stdout, so
/// the JSON-RPC stream stays clean) — drives a live "backend" panel in demos.
fn call_tool(name: &str, arguments: &Value, exe: &Path) -> Value {
    let log = std::env::var_os("OVECC_MCP_LOG").is_some();
    let started = std::time::Instant::now();
    if log {
        let args = serde_json::to_string(arguments).unwrap_or_default();
        eprintln!("[ovecc-mcp] → {name} {}", truncate(&args, 80));
    }
    let result = run_tool(name, arguments, exe);
    if log {
        let is_err = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let bytes = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .map_or(0, str::len);
        eprintln!(
            "[ovecc-mcp] ← {name} {} {bytes}B {}ms",
            if is_err { "ERR" } else { "ok" },
            started.elapsed().as_millis()
        );
    }
    result
}

/// Char-boundary-safe truncation for the stderr trace.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    }
}

fn run_tool(name: &str, arguments: &Value, exe: &Path) -> Value {
    let Some(sub_argv) = build_argv(name, arguments) else {
        return error_result(format!("unknown tool or missing required argument: {name}"));
    };
    let repo = arguments
        .get("repo")
        .and_then(Value::as_str)
        .unwrap_or(".")
        .to_string();

    // `--no-meta`: the agent reads the metric/rule dictionaries once via
    // ovecc_capabilities, so repeating them on every tool result only inflates
    // tokens. `capabilities` itself carries the full contract in `data`,
    // unaffected by this flag.
    let mut argv = vec![
        "--repo".to_string(),
        repo,
        "--format".to_string(),
        "json".to_string(),
        "--no-meta".to_string(),
    ];
    argv.extend(sub_argv);

    // The MCP server IS a subprocess launcher by design: each tool call re-runs
    // this same binary (`exe` = std::env::current_exe), never a caller-supplied
    // program, and argv is built above from the tool schema — nothing to inject.
    // ovecc-ignore-next-line
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
        "ovecc_init" => {
            argv.push("init".into());
            if flag("force") {
                argv.push("--force".into());
            }
        }
        "ovecc_history" => {
            argv.push("history".into());
            if let Some(metric) = s("metric") {
                argv.push(metric.into());
            }
            if let Some(limit) = n("limit") {
                argv.push("--limit".into());
                argv.push(limit.to_string());
            }
        }
        "ovecc_capabilities" => argv.push("capabilities".into()),
        "ovecc_summary" => argv.push("summary".into()),
        "ovecc_report" => argv.push("report".into()),
        "ovecc_health" => argv.push("health".into()),
        "ovecc_deadcode" => {
            argv.push("deadcode".into());
            if let Some(reference) = s("changed_since") {
                argv.push("--changed-since".into());
                argv.push(reference.into());
            }
        }
        "ovecc_fix" => {
            argv.push("fix".into());
            if flag("apply") {
                argv.push("--apply".into());
            }
            if let Some(rule) = s("rule") {
                argv.push("--rule".into());
                argv.push(rule.into());
            }
        }
        "ovecc_audit" => {
            argv.push("audit".into());
            if flag("fetch") {
                argv.push("--fetch".into());
            }
        }
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
            if let Some(reference) = s("changed_since") {
                argv.push("--changed-since".into());
                argv.push(reference.into());
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
        "ovecc_export_graph" => {
            argv.push("export".into());
            argv.push("graph".into());
            if let Some(path) = s("html") {
                argv.push("--html".into());
                argv.push(path.into());
            }
        }
        "ovecc_drift" => {
            argv.push("drift".into());
            if let Some(since) = s("since") {
                argv.push("--since".into());
                argv.push(since.into());
            }
        }
        "ovecc_gate" => {
            argv.push("gate".into());
            push_base_head(&mut argv, s("base"), s("head"));
            if let Some(fail_on) = s("fail_on") {
                argv.push("--fail-on".into());
                argv.push(fail_on.into());
            }
        }
        "ovecc_diff" => {
            argv.push("diff".into());
            push_base_head(&mut argv, s("base"), s("head"));
            if let Some(fail_on) = s("fail_on") {
                argv.push("--fail-on".into());
                argv.push(fail_on.into());
            }
        }
        "ovecc_review" => {
            argv.push("review".into());
            push_base_head(&mut argv, s("base"), s("head"));
            if let Some(fail_on) = s("fail_on") {
                argv.push("--fail-on".into());
                argv.push(fail_on.into());
            }
        }
        "ovecc_diagnose" => {
            argv.push("diagnose".into());
            if let Some(target) = s("target") {
                argv.push("--target".into());
                argv.push(target.into());
            }
            if let Some(severity) = s("severity") {
                argv.push("--severity".into());
                argv.push(severity.into());
            }
        }
        "ovecc_advise" => {
            argv.push("advise".into());
            argv.push(s("target")?.into());
        }
        "ovecc_metrics" => {
            argv.push("metrics".into());
            if let Some(target) = s("target") {
                argv.push("--target".into());
                argv.push(target.into());
            }
        }
        _ => return None,
    }
    Some(argv)
}

/// Appends the positional `base`/`head` ref arguments shared by `gate` and
/// `diff`. Because they are positional, passing `head` requires also passing
/// `base`, so we backfill the CLI default (`previous`) when only `head` is set.
fn push_base_head(argv: &mut Vec<String>, base: Option<&str>, head: Option<&str>) {
    match (base, head) {
        (_, Some(head)) => {
            argv.push(base.unwrap_or("previous").to_string());
            argv.push(head.to_string());
        }
        (Some(base), None) => argv.push(base.to_string()),
        (None, None) => {}
    }
}

/// The `tools/list` payload. Every tool takes an optional `repo`; the schemas
/// mirror the CLI arguments so an agent can drive an end-to-end audit.
fn tool_specs() -> Value {
    let repo = json!({"type": "string", "description": "Repository root path (defaults to the server's working directory)."});
    let severity = json!({"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Only findings at or above this severity."});
    let base = json!({"type": "string", "description": "Base snapshot or Git ref to compare from (default 'previous')."});
    let head = json!({"type": "string", "description": "Head snapshot or Git ref to compare to (default 'latest')."});
    let fail_on = json!({"type": "string", "enum": ["any", "medium", "high"], "description": "Threshold for the fail verdict: any change, or new findings at medium/high."});
    let obj = |props: Value, required: Value| json!({"type": "object", "properties": props, "required": required});

    json!([
        {"name": "ovecc_capabilities", "description": "The machine-readable contract: every command, metric, rule, severity, exit code, and output format. Call this first.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_index", "description": "Build or update the local architecture database for a repository. Run once before querying.", "inputSchema": obj(json!({"repo": repo, "path": {"type": "string", "description": "Repository path to index (alternative to repo)."}}), json!([]))},
        {"name": "ovecc_summary", "description": "Repository-level architecture health: coupling, density, cycles, risk score.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_report", "description": "One-shot architecture report: summary + cycles + violations + security + hotspots.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_impact", "description": "Blast radius of changing a target (module, table:NAME, api:METHOD:/path): the impacted nodes and the paths that reach them.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to analyze, e.g. Billing, table:customers, api:GET:/x."}, "direction": {"type": "string", "enum": ["downstream", "upstream", "both"], "description": "Traversal direction (default downstream)."}, "max_depth": {"type": "integer", "description": "Maximum traversal depth (default 6)."}}), json!(["target"]))},
        {"name": "ovecc_query", "description": "Structured architecture query. Verbs: deps X, rdeps X, paths X, module X, 'a -> b', hotspots, violations, cycles.", "inputSchema": obj(json!({"repo": repo, "query": {"type": "string", "description": "Query expression, e.g. 'cycles' or 'deps Billing'."}}), json!(["query"]))},
        {"name": "ovecc_violations", "description": "Architecture and rule findings (boundaries, banned imports, cycles), with optional severity filter and baseline.", "inputSchema": obj(json!({"repo": repo, "severity": severity, "baseline": {"type": "boolean", "description": "Hide findings recorded in the baseline (show only new ones)."}, "changed_since": {"type": "string", "description": "Only findings touching files changed since this Git ref (progressive adoption)."}}), json!([]))},
        {"name": "ovecc_security", "description": "Security findings: hardcoded secrets, insecure patterns, weak crypto, tainted source->sink flows.", "inputSchema": obj(json!({"repo": repo, "severity": severity}), json!([]))},
        {"name": "ovecc_audit", "description": "OSV audit of declared dependencies against the local vulnerability database (offline). Set fetch=true to first download the advisories for the discovered packages — the only ovecc operation that touches the network.", "inputSchema": obj(json!({"repo": repo, "fetch": {"type": "boolean", "description": "Download OSV advisories into .ovecc/osv/ before auditing (network, opt-in)."}}), json!([]))},
        {"name": "ovecc_health", "description": "Functions over the cyclomatic/cognitive complexity thresholds (oxc TS/JS extractor).", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_deadcode", "description": "Likely dead code: unused exports and unreachable files, from exports + entry-point reachability.", "inputSchema": obj(json!({"repo": repo, "changed_since": {"type": "string", "description": "Only findings touching files changed since this Git ref (progressive adoption)."}}), json!([]))},
        {"name": "ovecc_fix", "description": "Apply the mechanical fixes for auto-fixable findings: delete unused files, drop the export keyword on unused exports, remove unused manifest dependencies. Dry-run unless apply=true; every edit re-verifies the file against the index first and skips stale entries with a reason. After apply=true, call ovecc_index to refresh the model.", "inputSchema": obj(json!({"repo": repo, "apply": {"type": "boolean", "description": "Write the changes (default false = dry-run preview)."}, "rule": {"type": "string", "description": "Only fix findings from this rule, e.g. unused-export, unused-file."}}), json!([]))},
        {"name": "ovecc_dupes", "description": "Duplicated code (clone families) over a normalized token stream.", "inputSchema": obj(json!({"repo": repo, "min_tokens": {"type": "integer", "description": "Minimum shared token run to report (default 50)."}}), json!([]))},
        {"name": "ovecc_hotspots", "description": "Technical-debt hotspot ranking: churn x coupling x ownership.", "inputSchema": obj(json!({"repo": repo, "limit": {"type": "integer", "description": "Number of hotspots to return (default 10)."}}), json!([]))},
        {"name": "ovecc_conventions", "description": "Learned repository conventions and their deviations.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_drift", "description": "Architecture drift over time versus a previous snapshot or Git ref.", "inputSchema": obj(json!({"repo": repo, "since": {"type": "string", "description": "Git ref or snapshot to compare against, e.g. main or v1.0.0."}}), json!([]))},
        {"name": "ovecc_history", "description": "Trend one snapshot metric across every index run (values, deltas, sparkline). Without a metric, lists everything trendable.", "inputSchema": obj(json!({"repo": repo, "metric": {"type": "string", "description": "Metric to trend, e.g. coupling_density, high_complexity_functions."}, "limit": {"type": "integer", "description": "Most recent N snapshots to keep (default 20)."}}), json!([]))},
        {"name": "ovecc_init", "description": "Set up ovecc in a repository: write a commented .ovecc/config.toml, git-ignore the local state, and return the suggested first commands.", "inputSchema": obj(json!({"repo": repo, "force": {"type": "boolean", "description": "Overwrite an existing config."}}), json!([]))},
        {"name": "ovecc_review", "description": "Change review (lead with this for PR review): the NAMED new defects a change introduced between base and head — new findings (security/dead-code/complexity) with file:line, new dependency cycles WITH their concrete import witness edges, and the duplications the change added (scoped to touched files). One deterministic call; the actionable companion to ovecc_gate, which reports only counts.", "inputSchema": obj(json!({"repo": repo, "base": base, "head": head, "fail_on": fail_on}), json!([]))},
        {"name": "ovecc_gate", "description": "CI gate: fail when a change introduces new cycles, violations, or quality regressions (security/dead-code/complexity) versus a base snapshot or Git ref. Returns a pass/fail verdict and the signals behind it. For the named defects behind the verdict, use ovecc_review.", "inputSchema": obj(json!({"repo": repo, "base": base, "head": head, "fail_on": fail_on}), json!([]))},
        {"name": "ovecc_diff", "description": "Compare two stored architecture snapshots (or Git refs): added/removed modules and dependency edges, plus the overall diff risk score.", "inputSchema": obj(json!({"repo": repo, "base": base, "head": head, "fail_on": fail_on}), json!([]))},
        {"name": "ovecc_explain", "description": "Offline, deterministic architectural explanation of a target from its context slice.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to explain, e.g. Billing."}}), json!(["target"]))},
        {"name": "ovecc_context", "description": "Deterministic ContextSlice for a target as JSON, for feeding other tools or agents.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to slice, e.g. Billing."}}), json!(["target"]))},
        {"name": "ovecc_export_graph", "description": "The dependency graph as data: module- and file-level nodes and edges, sorted and deterministic. Pass html to instead write a self-contained offline HTML viewer for the human in the loop.", "inputSchema": obj(json!({"repo": repo, "html": {"type": "string", "description": "Optional path: write the interactive HTML viewer there instead of returning JSON."}}), json!([]))},
        {"name": "ovecc_diagnose", "description": "Deterministic architectural diagnosis: cycles, hub-like (crossing), unstable and god components, dense structure, and hotspots — each with evidence, the design principle it breaks, and an established remediation. Components are directories; no design patterns are invented.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Scope to findings touching this file or component (substring)."}, "severity": severity}), json!([]))},
        {"name": "ovecc_advise", "description": "Advise on one file, module, or component: the findings touching it and the established fix for each. Call before editing that area.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "File, module, or component to advise on."}}), json!(["target"]))},
        {"name": "ovecc_metrics", "description": "Per-component architecture metrics: fan-in/out, coupling, Martin instability, aggregate complexity, churn, and repository coupling density.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Scope to a single component (substring)."}}), json!([]))}
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_argv_for_simple_and_parameterized_tools() {
        assert_eq!(
            build_argv("ovecc_summary", &json!({})).unwrap(),
            vec!["summary"]
        );
        assert_eq!(
            build_argv(
                "ovecc_impact",
                &json!({"target": "Billing", "direction": "both", "max_depth": 3})
            )
            .unwrap(),
            vec![
                "impact",
                "Billing",
                "--direction",
                "both",
                "--max-depth",
                "3"
            ]
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
            build_argv("ovecc_export_graph", &json!({})).unwrap(),
            vec!["export", "graph"]
        );
        assert_eq!(
            build_argv("ovecc_export_graph", &json!({"html": "graph.html"})).unwrap(),
            vec!["export", "graph", "--html", "graph.html"]
        );
        assert_eq!(
            build_argv("ovecc_security", &json!({"severity": "high"})).unwrap(),
            vec!["security", "--severity", "high"]
        );
        assert_eq!(
            build_argv(
                "ovecc_gate",
                &json!({"base": "main", "head": "HEAD", "fail_on": "medium"})
            )
            .unwrap(),
            vec!["gate", "main", "HEAD", "--fail-on", "medium"]
        );
        // base/head are positional: a `head` with no `base` backfills the default.
        assert_eq!(
            build_argv("ovecc_diff", &json!({"head": "HEAD"})).unwrap(),
            vec!["diff", "previous", "HEAD"]
        );
        assert_eq!(build_argv("ovecc_gate", &json!({})).unwrap(), vec!["gate"]);
        assert_eq!(
            build_argv("ovecc_review", &json!({"base": "main", "fail_on": "any"})).unwrap(),
            vec!["review", "main", "--fail-on", "any"]
        );
        assert_eq!(
            build_argv("ovecc_review", &json!({})).unwrap(),
            vec!["review"]
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
        let init = handle(
            "initialize",
            Some(&json!({"protocolVersion": "2025-03-26"})),
            &exe,
        )
        .unwrap();
        assert_eq!(init["protocolVersion"], "2025-03-26");
        assert_eq!(init["serverInfo"]["name"], "ovecc");

        let listed = handle("tools/list", None, &exe).unwrap();
        let tools = listed["tools"].as_array().unwrap();
        let has = |name: &str| tools.iter().any(|t| t["name"] == name);
        assert!(has("ovecc_capabilities"));
        assert!(has("ovecc_gate"));
        assert!(has("ovecc_diff"));
        assert!(has("ovecc_review"));
        assert!(tools.len() >= 18);
    }

    #[test]
    fn unknown_method_is_a_jsonrpc_error() {
        let exe = std::path::PathBuf::from("ovecc");
        assert!(handle("frobnicate", None, &exe).is_err());
    }
}
