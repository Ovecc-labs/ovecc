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

/// Which slice of the tool registry `tools/list` advertises. `tools/call` still
/// dispatches every tool regardless — the profile only controls discovery, so a
/// scripted CI caller naming `ovecc_gate` keeps working under either.
///
/// `Agent` is the default: a small, ordered set for interactive coding agents.
/// A bloated list and weak positional ordering both suppress adoption (a full
/// ~25-tool surface is the "too many tools" failure mode, and list order biases
/// the pick when descriptions are close — arXiv 2505.18135). `Full` exposes
/// everything for humans and CI automation.
#[derive(Clone, Copy)]
enum Profile {
    Agent,
    Full,
}

fn active_profile() -> Profile {
    match std::env::var("OVECC_MCP_PROFILE").ok().as_deref() {
        Some("full") => Profile::Full,
        _ => Profile::Agent,
    }
}

/// The agent profile, ordered by how readily a coding agent should reach for
/// each tool. The navigation tools lead because that is where an ambiguous
/// "search the code" impulse gets resolved, and the first listed tool wins ties
/// under positional bias; setup (`capabilities`, `index`) trails since the
/// SessionStart digest and the `initialize` instructions already point at it.
const AGENT_PROFILE: &[&str] = &[
    "ovecc_query",
    "ovecc_impact",
    "ovecc_context",
    "ovecc_advise",
    "ovecc_review",
    "ovecc_summary",
    "ovecc_capabilities",
    "ovecc_index",
];

/// Opt-in LSP-vocabulary aliases (`find_references`, `get_call_hierarchy`,
/// `workspace_symbol`) over the existing commands. The hypothesis (arXiv
/// 2505.18135: renaming a tool shifts its use >10x) is that a name the model
/// already knows from language servers attracts the call a proprietary name
/// misses. Additive and off by default so the baseline agent profile stays
/// clean; the Phase 4 A/B flips this on to measure which name gets called.
fn lsp_aliases_enabled() -> bool {
    matches!(
        std::env::var("OVECC_MCP_LSP_ALIASES").ok().as_deref(),
        Some("on" | "1" | "true")
    )
}

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
                    Reach for these tools before Grep or Read to trace code \
                    relationships and understand an element from the index instead of \
                    scanning files. Call ovecc_capabilities once for the full contract \
                    and run ovecc_index before querying a repository, then use \
                    ovecc_query, ovecc_impact, and ovecc_context. Every tool accepts an \
                    optional `repo` path. This is the agent profile; set \
                    OVECC_MCP_PROFILE=full for the complete command surface."
            }))
        }
        "tools/list" => Ok(json!({
            "tools": listed_tools(active_profile(), lsp_aliases_enabled())
        })),
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
                let trimmed = stderr.trim();
                // A structured error envelope (emitted under `--format json`) is
                // already the machine-readable payload the agent should parse;
                // forward it verbatim instead of prefixing prose over it.
                if trimmed.starts_with('{') && serde_json::from_str::<Value>(trimmed).is_ok() {
                    error_result(trimmed.to_string())
                } else {
                    error_result(format!("ovecc exited with code {code}: {trimmed}"))
                }
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
/// by the caller. The tools are grouped so each builder stays small; names are
/// disjoint, so the first group that recognizes `name` produces the argv.
fn build_argv(name: &str, args: &Value) -> Option<Vec<String>> {
    argv_setup(name, args)
        .or_else(|| argv_findings(name, args))
        .or_else(|| argv_navigation(name, args))
        .or_else(|| argv_change(name, args))
        .or_else(|| argv_lsp_alias(name, args))
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn arg_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(Value::as_u64)
}

fn arg_flag(args: &Value, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Appends `--<flag> <value>` when the string arg is present.
fn push_opt(argv: &mut Vec<String>, args: &Value, key: &str, flag: &str) {
    if let Some(value) = arg_str(args, key) {
        argv.push(flag.into());
        argv.push(value.into());
    }
}

/// Appends `--<flag> <value>` when the numeric arg is present.
fn push_opt_u64(argv: &mut Vec<String>, args: &Value, key: &str, flag: &str) {
    if let Some(value) = arg_u64(args, key) {
        argv.push(flag.into());
        argv.push(value.to_string());
    }
}

/// index, init, history, and the no-argument status reports.
fn argv_setup(name: &str, args: &Value) -> Option<Vec<String>> {
    let mut argv = Vec::new();
    match name {
        "ovecc_index" => {
            argv.push("index".into());
            if let Some(path) = arg_str(args, "path") {
                argv.push(path.into());
            }
        }
        "ovecc_init" => {
            argv.push("init".into());
            if arg_flag(args, "force") {
                argv.push("--force".into());
            }
        }
        "ovecc_history" => {
            argv.push("history".into());
            if let Some(metric) = arg_str(args, "metric") {
                argv.push(metric.into());
            }
            push_opt_u64(&mut argv, args, "limit", "--limit");
        }
        "ovecc_capabilities" => argv.push("capabilities".into()),
        "ovecc_summary" => argv.push("summary".into()),
        "ovecc_report" => argv.push("report".into()),
        "ovecc_health" => argv.push("health".into()),
        "ovecc_conventions" => argv.push("conventions".into()),
        _ => return None,
    }
    Some(argv)
}

/// The finding-bearing commands: their severity/baseline/changed-since filters.
fn argv_findings(name: &str, args: &Value) -> Option<Vec<String>> {
    let mut argv = Vec::new();
    match name {
        "ovecc_deadcode" => {
            argv.push("deadcode".into());
            push_opt(&mut argv, args, "changed_since", "--changed-since");
        }
        "ovecc_fix" => {
            argv.push("fix".into());
            if arg_flag(args, "apply") {
                argv.push("--apply".into());
            }
            push_opt(&mut argv, args, "rule", "--rule");
        }
        "ovecc_audit" => {
            argv.push("audit".into());
            if arg_flag(args, "fetch") {
                argv.push("--fetch".into());
            }
        }
        "ovecc_violations" => {
            argv.push("violations".into());
            push_opt(&mut argv, args, "severity", "--severity");
            if arg_flag(args, "baseline") {
                argv.push("--baseline".into());
            }
            push_opt(&mut argv, args, "changed_since", "--changed-since");
        }
        "ovecc_security" => {
            argv.push("security".into());
            push_opt(&mut argv, args, "severity", "--severity");
        }
        "ovecc_hotspots" => {
            argv.push("hotspots".into());
            push_opt_u64(&mut argv, args, "limit", "--limit");
        }
        "ovecc_dupes" => {
            argv.push("dupes".into());
            push_opt_u64(&mut argv, args, "min_tokens", "--min-tokens");
        }
        "ovecc_metrics" => {
            argv.push("metrics".into());
            push_opt(&mut argv, args, "target", "--target");
        }
        _ => return None,
    }
    Some(argv)
}

/// The element-scoped navigation commands; each needs a target/query.
fn argv_navigation(name: &str, args: &Value) -> Option<Vec<String>> {
    let mut argv = Vec::new();
    match name {
        "ovecc_impact" => {
            argv.push("impact".into());
            argv.push(arg_str(args, "target")?.into());
            push_opt(&mut argv, args, "direction", "--direction");
            push_opt_u64(&mut argv, args, "max_depth", "--max-depth");
        }
        "ovecc_query" => {
            argv.push("query".into());
            argv.push(arg_str(args, "query")?.into());
            push_opt_u64(&mut argv, args, "depth", "--depth");
        }
        "ovecc_explain" => {
            argv.push("explain".into());
            argv.push(arg_str(args, "target")?.into());
        }
        "ovecc_context" => {
            argv.push("export".into());
            argv.push("context".into());
            argv.push(arg_str(args, "target")?.into());
        }
        "ovecc_export_graph" => {
            argv.push("export".into());
            argv.push("graph".into());
            push_opt(&mut argv, args, "html", "--html");
        }
        _ => return None,
    }
    Some(argv)
}

/// The change-comparison commands (drift/gate/diff/review) and diagnose/advise.
fn argv_change(name: &str, args: &Value) -> Option<Vec<String>> {
    let base_head_fail = |verb: &str| {
        let mut argv = vec![verb.to_string()];
        push_base_head(&mut argv, arg_str(args, "base"), arg_str(args, "head"));
        push_opt(&mut argv, args, "fail_on", "--fail-on");
        argv
    };
    let mut argv = Vec::new();
    match name {
        "ovecc_drift" => {
            argv.push("drift".into());
            push_opt(&mut argv, args, "since", "--since");
        }
        "ovecc_gate" => return Some(base_head_fail("gate")),
        "ovecc_diff" => return Some(base_head_fail("diff")),
        "ovecc_review" => return Some(base_head_fail("review")),
        "ovecc_diagnose" => {
            argv.push("diagnose".into());
            push_opt(&mut argv, args, "target", "--target");
            push_opt(&mut argv, args, "severity", "--severity");
        }
        "ovecc_advise" => {
            argv.push("advise".into());
            argv.push(arg_str(args, "target")?.into());
        }
        _ => return None,
    }
    Some(argv)
}

/// LSP-vocabulary aliases (opt-in, see `lsp_aliases_enabled`). Each is a thin
/// renaming of an existing verb, not new analysis.
fn argv_lsp_alias(name: &str, args: &Value) -> Option<Vec<String>> {
    let mut argv = Vec::new();
    match name {
        "find_references" => {
            argv.push("query".into());
            argv.push(format!("rdeps {}", arg_str(args, "symbol")?));
        }
        "get_call_hierarchy" => {
            argv.push("impact".into());
            argv.push(arg_str(args, "symbol")?.into());
            push_opt(&mut argv, args, "direction", "--direction");
        }
        "workspace_symbol" => {
            argv.push("explain".into());
            argv.push(arg_str(args, "query")?.into());
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
        {"name": "ovecc_capabilities", "description": "The machine-readable contract: every command, metric, rule, severity, exit code, and output format. Call this once up front for the full vocabulary. Example: {}.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_index", "description": "Build or refresh the local architecture database. Run once before the other tools and again after edits. Example: {}.", "inputSchema": obj(json!({"repo": repo, "path": {"type": "string", "description": "Repository path to index (alternative to repo)."}}), json!([]))},
        {"name": "ovecc_summary", "description": "Orient in a repo before ls/Read sweeps: architecture health at a glance (coupling, density, cycles, risk score). Example: {}.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_report", "description": "One-shot architecture report: summary + cycles + violations + security + hotspots.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_impact", "description": "Blast radius of changing a target: every element the change reaches (each with a file:line anchor) and the paths that carry it. Use before editing instead of grepping for usages. Targets: module, table:NAME, api:METHOD:/path. Example: {\"target\": \"Billing\", \"direction\": \"downstream\"}.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to analyze, e.g. Billing, table:customers, api:GET:/x."}, "direction": {"type": "string", "enum": ["downstream", "upstream", "both"], "description": "Traversal direction (default downstream)."}, "max_depth": {"type": "integer", "description": "Maximum traversal depth (default 6)."}}), json!(["target"]))},
        {"name": "ovecc_query", "description": "Trace code relationships from the index instead of grepping: callers, callees, import paths, cycles, each returned with a file:line anchor for a scoped read. Use before Grep or Bash grep when the question is 'who calls X', 'what does X import', or 'is there a cycle'. Verbs: rdeps X (direct callers), deps X (direct callees), paths X, 'a -> b', cycles, hotspots, violations. For the transitive blast radius of a change, use ovecc_impact instead. Example: {\"query\": \"rdeps Billing\"}.", "inputSchema": obj(json!({"repo": repo, "query": {"type": "string", "description": "Query expression, e.g. 'cycles' or 'rdeps Billing'."}, "depth": {"type": "integer", "description": "Hops to traverse. Omit for the default: 1 for rdeps/deps, 3 for paths and 'a -> b'."}}), json!(["query"]))},
        {"name": "ovecc_violations", "description": "Architecture and rule findings (boundaries, banned imports, cycles), with optional severity filter and baseline.", "inputSchema": obj(json!({"repo": repo, "severity": severity, "baseline": {"type": "boolean", "description": "Hide findings recorded in the baseline (show only new ones)."}, "changed_since": {"type": "string", "description": "Only findings touching files changed since this Git ref (progressive adoption)."}}), json!([]))},
        {"name": "ovecc_security", "description": "Security findings: hardcoded secrets, insecure patterns, weak crypto, tainted source->sink flows.", "inputSchema": obj(json!({"repo": repo, "severity": severity}), json!([]))},
        {"name": "ovecc_audit", "description": "OSV audit of declared dependencies against the local vulnerability database (offline). Set fetch=true to first download the advisories for the discovered packages — the only ovecc operation that touches the network.", "inputSchema": obj(json!({"repo": repo, "fetch": {"type": "boolean", "description": "Download OSV advisories into .ovecc/osv/ before auditing (network, opt-in)."}}), json!([]))},
        {"name": "ovecc_health", "description": "Functions over the cyclomatic/cognitive complexity thresholds (oxc TS/JS extractor).", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_deadcode", "description": "Likely dead code: unused exports and unreachable files, from exports + entry-point reachability.", "inputSchema": obj(json!({"repo": repo, "changed_since": {"type": "string", "description": "Only findings touching files changed since this Git ref (progressive adoption)."}}), json!([]))},
        {"name": "ovecc_fix", "description": "Apply the mechanical fixes for auto-fixable findings: delete unused files, drop the export keyword on unused exports, remove unused manifest dependencies. Dry-run unless apply=true; every edit re-verifies the file against the index first and skips stale entries with a reason. After apply=true, call ovecc_index to refresh the model.", "inputSchema": obj(json!({"repo": repo, "apply": {"type": "boolean", "description": "Write the changes (default false = dry-run preview)."}, "rule": {"type": "string", "description": "Only fix findings from this rule, e.g. unused-export, unused-file."}}), json!([]))},
        {"name": "ovecc_dupes", "description": "Duplicated code (clone families) over a normalized token stream.", "inputSchema": obj(json!({"repo": repo, "min_tokens": {"type": "integer", "description": "Minimum shared token run to report (default 100, PMD CPD's)."}}), json!([]))},
        {"name": "ovecc_hotspots", "description": "Technical-debt hotspot ranking: churn x coupling x ownership.", "inputSchema": obj(json!({"repo": repo, "limit": {"type": "integer", "description": "Number of hotspots to return (default 10)."}}), json!([]))},
        {"name": "ovecc_conventions", "description": "Learned repository conventions and their deviations.", "inputSchema": obj(json!({"repo": repo}), json!([]))},
        {"name": "ovecc_drift", "description": "Architecture drift over time versus a previous snapshot or Git ref.", "inputSchema": obj(json!({"repo": repo, "since": {"type": "string", "description": "Git ref or snapshot to compare against, e.g. main or v1.0.0."}}), json!([]))},
        {"name": "ovecc_history", "description": "Trend one snapshot metric across every index run (values, deltas, sparkline). Without a metric, lists everything trendable.", "inputSchema": obj(json!({"repo": repo, "metric": {"type": "string", "description": "Metric to trend, e.g. coupling_density, high_complexity_functions."}, "limit": {"type": "integer", "description": "Most recent N snapshots to keep (default 20)."}}), json!([]))},
        {"name": "ovecc_init", "description": "Set up ovecc in a repository: write a commented .ovecc/config.toml, git-ignore the local state, and return the suggested first commands.", "inputSchema": obj(json!({"repo": repo, "force": {"type": "boolean", "description": "Overwrite an existing config."}}), json!([]))},
        {"name": "ovecc_review", "description": "Lead with this to review a change instead of reading the diff by hand: the named new defects between base and head. Reports new security/dead-code/complexity findings with file:line, new dependency cycles with their concrete import witness edges, and the duplications the change added (scoped to touched files). The actionable companion to ovecc_gate, which reports only counts. Example: {\"base\": \"main\", \"head\": \"HEAD\"}.", "inputSchema": obj(json!({"repo": repo, "base": base, "head": head, "fail_on": fail_on}), json!([]))},
        {"name": "ovecc_gate", "description": "CI gate: fail when a change introduces new cycles, violations, or quality regressions (security/dead-code/complexity) versus a base snapshot or Git ref. Returns a pass/fail verdict and the signals behind it. For the named defects behind the verdict, use ovecc_review.", "inputSchema": obj(json!({"repo": repo, "base": base, "head": head, "fail_on": fail_on}), json!([]))},
        {"name": "ovecc_diff", "description": "Compare two stored architecture snapshots (or Git refs): added/removed modules and dependency edges, plus the overall diff risk score.", "inputSchema": obj(json!({"repo": repo, "base": base, "head": head, "fail_on": fail_on}), json!([]))},
        {"name": "ovecc_explain", "description": "Offline, deterministic architectural explanation of a target from its context slice.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to explain, e.g. Billing."}}), json!(["target"]))},
        {"name": "ovecc_context", "description": "Deterministic ContextSlice for a target as JSON: its neighbors, findings, and file:line anchors. Use instead of reading whole files to understand an element. Example: {\"target\": \"Billing\"}.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Element to slice, e.g. Billing."}}), json!(["target"]))},
        {"name": "ovecc_export_graph", "description": "The dependency graph as data: module- and file-level nodes and edges, sorted and deterministic. Pass html to instead write a self-contained offline HTML viewer for the human in the loop.", "inputSchema": obj(json!({"repo": repo, "html": {"type": "string", "description": "Optional path: write the interactive HTML viewer there instead of returning JSON."}}), json!([]))},
        {"name": "ovecc_diagnose", "description": "Deterministic architectural diagnosis: cycles, hub-like (crossing), unstable and god components, dense structure, and hotspots — each with evidence, the design principle it breaks, and an established remediation. Components are directories; no design patterns are invented.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Scope to findings touching this file or component (substring)."}, "severity": severity}), json!([]))},
        {"name": "ovecc_advise", "description": "Findings touching one file, module, or component and the established fix for each. Call before editing that area so a change doesn't reintroduce a known problem. Example: {\"target\": \"src/billing\"}.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "File, module, or component to advise on."}}), json!(["target"]))},
        {"name": "ovecc_metrics", "description": "Per-component architecture metrics: fan-in/out, coupling, Martin instability, aggregate complexity, churn, and repository coupling density.", "inputSchema": obj(json!({"repo": repo, "target": {"type": "string", "description": "Scope to a single component (substring)."}}), json!([]))}
    ])
}

/// The tools `tools/list` advertises for a profile, in order. `Full` returns
/// the whole registry; `Agent` returns the ordered [`AGENT_PROFILE`] subset,
/// prefixed with the LSP aliases when they are enabled so the familiar names
/// sit first (positional bias). Kept pure (profile passed in) so tests need no
/// environment coupling.
fn listed_tools(profile: Profile, lsp_aliases: bool) -> Vec<Value> {
    let specs = tool_specs();
    let all = specs.as_array().expect("tool_specs is a JSON array");
    match profile {
        Profile::Full => all.clone(),
        Profile::Agent => {
            let mut out = Vec::with_capacity(AGENT_PROFILE.len() + 3);
            if lsp_aliases {
                out.extend(lsp_alias_specs());
            }
            for name in AGENT_PROFILE {
                let spec = all
                    .iter()
                    .find(|t| t["name"] == *name)
                    .unwrap_or_else(|| panic!("agent profile names a missing tool: {name}"));
                out.push(spec.clone());
            }
            out
        }
    }
}

/// Tool specs for the opt-in LSP aliases. Their schemas mirror the LSP requests
/// an agent knows, and `build_argv` routes each onto an existing command.
fn lsp_alias_specs() -> Vec<Value> {
    let repo = json!({"type": "string", "description": "Repository root path (defaults to the server's working directory)."});
    let direction = json!({"type": "string", "enum": ["downstream", "upstream", "both"], "description": "Traversal direction (default downstream)."});
    let obj = |props: Value, required: Value| json!({"type": "object", "properties": props, "required": required});
    vec![
        json!({"name": "find_references", "description": "Find all references to a symbol across the repository (its callers and dependents), each with a file:line anchor, served from the architecture index rather than a text scan. Example: {\"symbol\": \"Billing\"}.", "inputSchema": obj(json!({"repo": repo, "symbol": {"type": "string", "description": "Symbol or element to find references to."}}), json!(["symbol"]))}),
        json!({"name": "get_call_hierarchy", "description": "Incoming/outgoing call and dependency hierarchy for a symbol: everything reachable from it and the paths that get there. Example: {\"symbol\": \"Billing\", \"direction\": \"downstream\"}.", "inputSchema": obj(json!({"repo": repo, "symbol": {"type": "string", "description": "Symbol or element to walk the hierarchy from."}, "direction": direction}), json!(["symbol"]))}),
        json!({"name": "workspace_symbol", "description": "Look up an architecture element by name and return what it is and where it sits, with file:line anchors. Example: {\"query\": \"Billing\"}.", "inputSchema": obj(json!({"repo": repo, "query": {"type": "string", "description": "Symbol or element name to resolve."}}), json!(["query"]))}),
    ]
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
    fn lsp_aliases_route_onto_existing_commands() {
        assert_eq!(
            build_argv("find_references", &json!({"symbol": "Billing"})).unwrap(),
            vec!["query", "rdeps Billing"]
        );
        assert_eq!(
            build_argv(
                "get_call_hierarchy",
                &json!({"symbol": "Billing", "direction": "upstream"})
            )
            .unwrap(),
            vec!["impact", "Billing", "--direction", "upstream"]
        );
        assert_eq!(
            build_argv("workspace_symbol", &json!({"query": "Billing"})).unwrap(),
            vec!["explain", "Billing"]
        );
        // The aliases are off by default, so they must not shadow a required arg.
        assert!(build_argv("find_references", &json!({})).is_none());
    }

    #[test]
    fn agent_profile_is_lean_ordered_and_hides_ci_tools() {
        let tools = listed_tools(Profile::Agent, false);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, AGENT_PROFILE);
        // Navigation leads (positional bias); CI-only tools are not advertised
        // here even though `build_argv` still dispatches them.
        assert_eq!(names.first(), Some(&"ovecc_query"));
        assert!(!names.contains(&"ovecc_gate"));
        assert!(!names.contains(&"ovecc_diff"));
    }

    #[test]
    fn full_profile_lists_the_whole_registry() {
        let full = listed_tools(Profile::Full, false);
        let registry = tool_specs();
        assert_eq!(full.len(), registry.as_array().unwrap().len());
        assert!(full.iter().any(|t| t["name"] == "ovecc_gate"));
        assert!(full.iter().any(|t| t["name"] == "ovecc_diff"));
    }

    #[test]
    fn lsp_aliases_prepend_only_when_enabled() {
        let off = listed_tools(Profile::Agent, false);
        assert_eq!(off.len(), AGENT_PROFILE.len());

        let on = listed_tools(Profile::Agent, true);
        assert_eq!(on.len(), AGENT_PROFILE.len() + 3);
        let lead: Vec<&str> = on
            .iter()
            .take(3)
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            lead,
            ["find_references", "get_call_hierarchy", "workspace_symbol"]
        );
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

        // The default (no OVECC_MCP_PROFILE) is the agent profile.
        let listed = handle("tools/list", None, &exe).unwrap();
        let tools = listed["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "ovecc_query"));
        assert!(!tools.is_empty());
    }

    #[test]
    fn unknown_method_is_a_jsonrpc_error() {
        let exe = std::path::PathBuf::from("ovecc");
        assert!(handle("frobnicate", None, &exe).is_err());
    }
}
