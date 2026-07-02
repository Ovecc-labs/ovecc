# Using the Ovecc MCP Server End-to-End

Ovecc ships a built-in **Model Context Protocol (MCP)** server that exposes its
analysis as tools a coding agent (Claude Code, Claude Desktop, Cursor, …) can call.
This guide takes you from a built binary to an agent running a full architecture
audit over MCP.

> **TL;DR:** build `ovecc.exe`, `index` your repo once, register `ovecc mcp` with your
> MCP client, then let the agent call `ovecc_capabilities` → `ovecc_index` → the
> analysis tools.

---

## How it works (read this first)

The server is **not** a separate long-running service with its own logic. It is a
thin wrapper that re-invokes the same `ovecc` binary for each tool call
(`crates/ovecc-cli/src/mcp.rs`):

- **Transport:** newline-delimited **JSON-RPC 2.0 over stdin/stdout**. No HTTP, no
  port, no daemon. The client launches `ovecc mcp` as a child process and exits it by
  closing stdin.
- **Tools = the CLI:** a `tools/call` runs `ovecc --repo <path> --format json <subcommand>`
  and returns its stdout. No new analysis lives in the server — every tool maps 1:1
  onto a CLI command described by `ovecc capabilities`.
- **Stateless between calls:** because each call is a fresh subprocess, the server
  keeps nothing in memory. All state lives on disk in the repo's `.ovecc/` database,
  written by `index`. **This is why you must index before querying.**
- **Deterministic:** identical inputs produce byte-identical tool output (wall-clock
  is confined to `meta.timing`).

---

## Prerequisites

- A built `target/release/ovecc.exe` — see [SETUP.md](./SETUP.md).
- An MCP client (Claude Code, Claude Desktop, Cursor, or any MCP-capable agent).
- The target repository you want analyzed (TS/JS is the MVP focus).

---

## 1. Build the binary

```sh
cargo build --release
./target/release/ovecc.exe --help     # smoke test
```

The binary is self-contained; note its absolute path — the MCP client needs it.

## 2. Index the repository once

The server's analysis tools read the `.ovecc/` database. Build it first:

```sh
./target/release/ovecc.exe --repo "C:\path\to\your-repo" index
```

This creates `C:\path\to\your-repo\.ovecc\`. You (or the agent, via `ovecc_index`)
re-run this after changes. For the regression tools (`gate`/`diff`/`drift`) you need
**at least two snapshots**, so index again after each change you want to compare.

## 3. Register the server with your MCP client

Each tool accepts an optional `repo` argument; when omitted it defaults to the
server's working directory. Point the client at the binary with `mcp` as the argument.

### Claude Code (CLI)

```sh
claude mcp add ovecc -- "C:\Users\Boch\Desktop\inscrition ENSIIE\ovecc\app\target\release\ovecc.exe" mcp
```

Then `claude mcp list` should show `ovecc`, and the tools appear as `ovecc_*`.

### Claude Desktop / generic JSON config

In `claude_desktop_config.json` (or a project `.mcp.json`):

```json
{
  "mcpServers": {
    "ovecc": {
      "command": "C:\\Users\\Boch\\Desktop\\inscrition ENSIIE\\ovecc\\app\\target\\release\\ovecc.exe",
      "args": ["mcp"]
    }
  }
}
```

> Tip: set the client's working directory to the repo you analyze most often, or have
> the agent pass an explicit `repo` to every tool. Paths with spaces must be escaped
> (`\\` in JSON).

### Cursor / other clients

Any client that launches a stdio MCP server works: command = the `ovecc.exe` path,
args = `["mcp"]`.

## 4. Verify it works (manual smoke test)

You can drive the server by hand without an agent — pipe JSON-RPC frames into it.

**bash / Git Bash:**

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ./target/release/ovecc.exe mcp
```

**PowerShell:**

```powershell
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
'{"jsonrpc":"2.0","id":2,"method":"tools/list"}' |
  & ".\target\release\ovecc.exe" mcp
```

You should get an `initialize` result (serverInfo `ovecc`) followed by a `tools/list`
result enumerating **20 tools**. To exercise a real analysis tool against an indexed
repo:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ovecc_summary","arguments":{"repo":"C:/path/to/your-repo"}}}' \
  | ./target/release/ovecc.exe mcp
```

The result's `content[0].text` is the JSON envelope (`schema_version`, `command`,
`meta`, `data`). The protocol-level `initialize` handshake is sent by the client
automatically — you only send it by hand in this manual test.

---

## Tool catalog

All 20 tools (every one takes an optional `repo`; `*` marks required arguments):

| Tool | Maps to | Key arguments |
| --- | --- | --- |
| `ovecc_capabilities` | `capabilities` | — (call first: the full contract) |
| `ovecc_index` | `index` | `path` |
| `ovecc_summary` | `summary` | — |
| `ovecc_report` | `report` | — |
| `ovecc_impact` | `impact` | `target*`, `direction`, `max_depth` |
| `ovecc_query` | `query` | `query*` (e.g. `cycles`, `deps Billing`) |
| `ovecc_violations` | `violations` | `severity`, `baseline` |
| `ovecc_security` | `security` | `severity` |
| `ovecc_audit` | `audit` | — |
| `ovecc_health` | `health` | — |
| `ovecc_deadcode` | `deadcode` | — |
| `ovecc_dupes` | `dupes` | `min_tokens` |
| `ovecc_hotspots` | `hotspots` | `limit` |
| `ovecc_conventions` | `conventions` | — |
| `ovecc_drift` | `drift` | `since` (git ref / snapshot) |
| `ovecc_review` | `review` | `base`, `head`, `fail_on` (lead with this for PR review) |
| `ovecc_gate` | `gate` | `base`, `head`, `fail_on` |
| `ovecc_diff` | `diff` | `base`, `head`, `fail_on` |
| `ovecc_explain` | `explain` | `target*` |
| `ovecc_context` | `export context` | `target*` |

---

## Typical agent workflows

**Audit a repository (flag issues now):**

1. `ovecc_capabilities` — learn the commands, metrics, rules, exit codes.
2. `ovecc_index` — build `.ovecc/` (once).
3. `ovecc_summary` / `ovecc_report` — overall health.
4. `ovecc_violations`, `ovecc_security`, `ovecc_audit`, `ovecc_deadcode`,
   `ovecc_health` — specific findings.
5. `ovecc_impact` / `ovecc_query` — reason about blast radius and dependencies.

**Detect what a change introduced (the MVP regression loop):**

1. `ovecc_index` on the base ref → produces a snapshot.
2. Make the change, `ovecc_index` again → second snapshot.
3. `ovecc_review` (`base`/`head`/`fail_on`) → the **named** new defects in one call:
   new findings with `file:line`, new dependency cycles **with their concrete import
   witness edges**, and the duplications the change added. This is what you report.
4. `ovecc_gate` for a bare pass/fail verdict; `ovecc_diff` for raw added/removed
   structure if you need the module/dependency deltas behind the review.

---

## Error & exit-code semantics

The server follows the MCP convention of reporting tool failures *in-band*:

- Underlying CLI exit **0** (clean) or **1** (a `--fail-on` / gate threshold was
  crossed — a signal, not a crash) → normal result, `isError: false`. So a *failing*
  gate still returns its verdict payload for the agent to read.
- Exit **≥ 2** (usage, repo/config, DB, parser, internal) → `isError: true` with the
  stderr message.
- Unknown tool or a missing required argument → `isError: true` (the agent can
  recover without a protocol-level failure).
- Unparseable JSON-RPC frames are ignored; unknown methods return a JSON-RPC error.

---

## Troubleshooting

- **"could not resolve base snapshot 'previous'"** (from `ovecc_gate`/`ovecc_diff`/
  `ovecc_drift`): the repo has fewer than two snapshots. Run `ovecc_index` again so a
  base exists, or pass an explicit `base`/`since` git ref.
- **Empty or stale results:** the repo was never indexed, or was changed since the
  last index. Re-run `ovecc_index`.
- **Tool returns `isError` with no detail:** check the CLI directly —
  `ovecc --repo <path> --format json <subcommand>` — to see the real error; the server
  just forwards it.
- **Client shows no tools:** confirm the `command` path is correct and absolute, and
  that `ovecc.exe mcp` runs from a terminal (it will block waiting on stdin — that's
  expected). Diagnostics go to **stderr**, so they never corrupt the protocol stream.
- **Agent skips indexing:** the server's `initialize` instructions tell it to call
  `ovecc_capabilities` first and `ovecc_index` once; if your client ignores
  `instructions`, prompt the agent to do so explicitly.
