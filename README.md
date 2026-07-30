<div align="center">

  <img src="docs/img/ovecc_white_logo.png" alt="Ovecc" width="180" />

  <p>
    <b>CLI-first architecture intelligence: understand your codebase, then hold it to the rules you set.</b>
  </p>

  <p>
    Ovecc reads your repo once and builds a deterministic, offline model of it,
    then answers the hard questions: what breaks if I change this, where are the
    cycles, what's coupled, dead, or insecure. And it lets you write your
    architecture down as a contract, so the build fails when the code drifts.<br/>
    It runs locally, stays fully deterministic, and never puts an LLM in the loop.
  </p>

  <p>
    <a href="https://github.com/Ovecc-labs/ovecc/actions/workflows/ci.yml"><img src="https://github.com/Ovecc-labs/ovecc/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square" alt="License" /></a>
    <a href="../../releases/latest"><img src="https://img.shields.io/badge/Release-latest-00d2b4?style=flat-square" alt="Latest release" /></a>
    <img src="https://img.shields.io/badge/Built%20with-Rust-dea584?style=flat-square&logo=rust" alt="Rust" />
  </p>

</div>

---

## What is Ovecc

Ovecc reads your repository once and builds a deterministic, persistent model of
it: every file, import, symbol, and call. From that single index it answers the
questions you actually ask about a codebase:

- What breaks if I change this? (`impact`)
- Where are the dependency cycles and the tight coupling? (`query`, `summary`)
- What is duplicated, dead, or over-complex? (`dupes`, `deadcode`, `health`)
- What is insecure, and which dependencies have known CVEs? (`security`, `audit`)
- Where is the churn, and who owns this code? (`hotspots`)

It runs on your machine, gives byte-identical answers every run, and never
treats an LLM as the source of truth: it's an architecture database with
deterministic commands, usable from the CLI, in CI, or by a coding agent over
MCP.

<img src="docs/img/graph-hero.png" alt="React's dependency graph in ovecc's offline viewer" width="100%" />
<p align="center"><i>React's dependency graph, rendered by <code>ovecc export graph --html</code> into a single file you can open directly, no server or CDN needed.</i></p>

Measured performance and answer accuracy on real repositories are in
[docs/benchmark/BENCHMARKS.md](docs/benchmark/BENCHMARKS.md).

## Write your architecture down, and hold the code to it

Most tools stop at reading the code. Ovecc goes one step further: you write
down which parts of your codebase are allowed to depend on which, in one small
file, and every build checks the real code against it.

Here's one for a small app:

```toml
# .ovecc/architecture.toml
[[component]]
name = "api"
paths = ["src/api/**"]
depends_on = ["core"]              # the api may use core, nothing else

[[component]]
name = "features"
paths = ["src/features/**"]
depends_on = ["core"]
slices = true                      # and features may not import each other

[[component]]
name = "core"
paths = ["src/core/**"]
deny_capabilities = ["network"]    # pure domain: no fetch, no I/O
max_cyclomatic = 8                 # keep core functions simple
```

Run the check and every breach comes back with a file and a line:

```console
$ ovecc architecture check

Divergences (1):
  [High] api -> features is not in the contract
    src/api/routes.ts:2 (../features/billing/service)

Slice isolation breaches (1):
  [High] features/billing -> features/users breaks slice isolation
    src/features/billing/service.ts:1 (../users/repo)

Denied capabilities used (1):
  [Medium] core uses denied capability 'network'
    src/core/pricing.ts:3 (fetch)

Complexity budgets exceeded (1):
  [Medium] core: 1 function over the cyclomatic budget
    src/core/pricing.ts:8 (cyclomatic 11 > 8)
```

Four kinds of decay caught in one run: a layer reaching where it shouldn't, a
feature tangling into its neighbor, a network call inside code you promised was
pure, and a function creeping past the budget you set. Put `ovecc architecture
check` in CI and the pull request fails on the drift, instead of a reviewer
noticing three months later, or nobody noticing at all.

**Don't have one yet?** `ovecc architecture suggest` recognizes the architecture
you already follow (Feature-Sliced, bulletproof-react, Clean/Hexagonal, an Nx
workspace) and writes the file bound to your real folders. Or `ovecc
architecture init` drafts it from your actual import graph, so day one starts
green and you tighten from there. The details are in [the contract reference
below](#the-architecture-contract-in-depth).

## Install

Grab a prebuilt binary from the [latest release](../../releases/latest) (Linux and
Windows x86_64), drop it on your `PATH`, and run `ovecc index .`. There is nothing
else to install: DuckDB is bundled, there is no runtime, and it works fully
offline. A rolling [dev build](../../releases/tag/latest) ships on every push to
`main`.

### Build from source

Builds with stable Rust (on Windows use the `windows-gnu` toolchain; DuckDB is
compiled from source on the first build). The step-by-step Windows setup is in
[docs/dev/SETUP.md](docs/dev/SETUP.md).

```sh
cargo build --release
cargo test --workspace
```

The binary is `ovecc` (`crates/ovecc-cli`).

## Quick start

```sh
ovecc index .                 # parse, resolve, and persist the model into .ovecc/
ovecc summary                 # coupling, density, cycles, risk score
ovecc violations              # architecture + security findings, with file:line
ovecc diagnose                # named architectural smells, evidence + curated remediation
ovecc security                # secrets, insecure patterns, weak crypto, tainted flows
ovecc audit                   # offline OSV dependency vulnerabilities
ovecc impact Billing          # blast radius of a change
ovecc hotspots                # churn x coupling x ownership debt ranking
ovecc dupes                   # duplicated code (clone families), with file:line
ovecc health                  # functions over the complexity thresholds (oxc)
ovecc deadcode                # unused exports + unreachable files (oxc + reachability)
ovecc fix                     # apply the mechanical fixes for those findings (dry-run by default)
ovecc query "cycles"          # real elementary dependency cycles (A -> B -> A)
ovecc report                  # one-shot architecture report (markdown or json)
ovecc gate                    # CI gate: fail a PR on new cycles / violations
ovecc review                  # the named new defects a change introduced (file:line + cycle witnesses)
ovecc architecture init       # draft .ovecc/architecture.toml from the graph, or a --template
ovecc architecture check      # gate the code against the contract, with file:line
ovecc architecture suggest    # recognize which architecture the repo already follows
ovecc export graph --html     # interactive dependency-graph viewer, one self-contained offline file
ovecc capabilities            # machine-readable contract: commands, metrics, rules, exit codes
ovecc mcp                     # MCP server over stdio: expose every command as an agent tool
```

Every command renders as `text`, `json`, `ndjson`, or `markdown` via `--format`
(plus `sarif` for GitHub code scanning and `codeclimate` for GitLab Code Quality)
and returns stable exit codes for CI. The full per-command reference, with real
output, is in [docs/COMMANDS.md](docs/COMMANDS.md). For pull requests, the repo
ships a drop-in [GitHub Action](action.yml) that indexes base and head, comments
the `review` findings on the PR, and gates on severity.

## The architecture contract in depth

`.ovecc/architecture.toml` is your intended architecture as code. Each component
claims files by path glob; `depends_on` is the allow-list of what it may import.
`ovecc architecture init` writes the first draft from the graph you already have,
so every entry mirrors a real import and day one has zero violations. Prefer a
known shape? `init --template fsd` (or `bulletproof-react`, `nx-workspace`,
`clean-architecture`) drops in a reference architecture, and the diff against your
code becomes your migration plan.

From then on, each run compares code to contract and names what it finds:

- a **divergence** is an import the contract does not allow,
- a **bypass** is an import that skips a component's declared public interface,
- an **absence** is a dependency you declared but never actually use.

Three more checks read past the import graph (JS/TS):

- `slices = true` isolates a component's sub-folders from each other, the rule
  behind Feature-Sliced Design and bulletproof-react, with FSD's `@x` public-API
  escape hatch honored.
- `deny_capabilities` forbids a component the ambient powers that break purity:
  `network`, `filesystem`, `storage`, `dom`, `process`, `time`, `random`. A
  `Date.now()` in a pure domain comes back with its file and line.
- `max_cyclomatic` / `max_cognitive` put a per-function complexity budget in the
  contract, so "keep the core simple" becomes a rule the build can check.

Interfaces are virtual: you list a component's public entry files and ovecc
enforces them on the real imports, so you get encapsulation without barrel files
or an extra re-export layer.

Adoption is meant to be gradual. `check --freeze` records today's violations in a
per-component baseline (one line each, so branches merge cleanly), gates only new
ones from then on, and drops entries as you fix them so the count never climbs.
Agents can read the contract before editing, through `ovecc architecture show
<path>` or the `ovecc_architecture` MCP tool.

### Rules

Simpler, language-neutral policy lives in `.ovecc/config.toml`, is enforced at
index time, and shows up in `violations` (and the `gate` CI check):

```toml
# Forbid a module-to-module dependency.
[[rules.boundaries]]
name = "billing must not depend on user"
source = "billing"
target = "user"
allowed = false
severity = "high"

# Ban imports by specifier pattern (exact, prefix*, *suffix, or *infix*).
[[rules.banned_imports]]
name = "no-deprecated-lodash"
pattern = "lodash"
message = "use es-toolkit instead"
severity = "medium"
```

Silence a single finding inline with `// ovecc-ignore` (or
`// ovecc-ignore-next-line`, and `# ovecc-ignore` in Python) on the offending
line; it is dropped at index time.

## For CI and coding agents

Every command is built to run in a pipeline: pick a format with `--format`, rely
on stable exit codes (`0` clean, `1` a `--fail-on` threshold crossed, `2` and up
a real error), and emit `sarif` or `codeclimate` for GitHub and GitLab. The
drop-in [GitHub Action](action.yml) wires `review` into pull requests.

The same analysis is available to coding agents over the Model Context Protocol.
`ovecc mcp` runs an MCP server over stdio that exposes each command as a tool
(`ovecc_summary`, `ovecc_impact`, `ovecc_architecture`, ...), so an agent can ask
"is this export used?", "what is the blast radius of `BillingService`?", or "does
this PR break the architecture contract?" and get the same deterministic answer.
Register it with any MCP client:

```json
{ "mcpServers": { "ovecc": { "command": "ovecc", "args": ["mcp"] } } }
```

Start with `ovecc capabilities --format json`: it returns every command, the
metrics and rules they emit (each with a definition), the severity vocabulary,
and the exit-code contract, enough to drive an audit without reading these docs.
Every command's JSON is a stable, self-describing envelope, normalized to
repo-relative POSIX paths and byte-identical across runs. The full walkthrough is
in [docs/dev/MCP.md](docs/dev/MCP.md).

## Languages

The JavaScript and TypeScript family is parsed with tree-sitter and enriched by
the pure-Rust **oxc** stack: real `tsconfig` path and `exports` resolution
(`oxc_resolver`), plus per-function complexity and exports
(`oxc_parser`/`oxc_semantic`). One tree-sitter adapter covers Python, Go, Rust,
and C++. They all feed the same language-agnostic model, so resolution, the call
graph, taint, and the rules work across every supported language. Adding a
language is a new extractor behind the parser boundary, not a core change.

## Workspace layout

Ten library crates and one binary, each documented in its own `README.md` (plus
`xtask`, the std-only task runner behind `cargo xtask`):

| Crate | Responsibility |
| --- | --- |
| [`ovecc-core`](crates/ovecc-core) | Data model, typed ids, config, error type, trait contracts |
| [`ovecc-parser`](crates/ovecc-parser) | Tree-sitter adapters and security pattern detection |
| [`ovecc-indexer`](crates/ovecc-indexer) | Indexing pipeline: discover, parse, resolve, analyze, persist |
| [`ovecc-db`](crates/ovecc-db) | DuckDB persistence, migrations, differential sync |
| [`ovecc-git`](crates/ovecc-git) | Native Git history, churn, ownership (via gix) |
| [`ovecc-graph`](crates/ovecc-graph) | Blast radius, hotspots, cycles, conventions |
| [`ovecc-rules`](crates/ovecc-rules) | Rule evaluation and security classification |
| [`ovecc-dataflow`](crates/ovecc-dataflow) | Source-to-sink taint reachability |
| [`ovecc-audit`](crates/ovecc-audit) | Offline OSV dependency audit |
| [`ovecc-ai`](crates/ovecc-ai) | Optional deterministic, offline explanation |
| [`ovecc-cli`](crates/ovecc-cli) | Command-line interface |

## Design guarantees

- **Deterministic before generative.** Every finding traces back to explicit
  facts; the same input produces the same output.
- **Local and private.** Indexing, analysis, and explanation run on the machine;
  nothing leaves it.
- **Incremental.** Re-indexing an unchanged repository re-parses nothing and
  writes only a new snapshot.

## License

Apache-2.0; see [LICENSE](LICENSE). Portions are adapted from
[fallow](https://github.com/fallow-rs/fallow) (MIT); third-party attributions are
in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
