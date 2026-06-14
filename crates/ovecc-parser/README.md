# ovecc-parser

## Purpose

`ovecc-parser` turns source files into `FileFacts` using Tree-sitter. It is the
only crate that touches a syntax tree; the tree never crosses the crate
boundary. A parse failure is per-file and never aborts an index run — the adapter
returns a `ParseFailure` and the indexer records it and continues.

## Adapters

The crate implements `LanguageAdapter` (defined in `ovecc-core`) twice:

- `TypeScriptAdapter` — a bespoke walker for the whole JS/TS family (js, jsx, ts,
  tsx). One recursive pass extracts every fact kind so the tree is traversed
  once: symbols, imports (static / re-export / require / dynamic / type-only),
  calls attributed to their enclosing callable, Express/Fastify/Koa routes, and
  SQL embedded in string and template literals.
- `GenericAdapter` — a specification-driven walker for Python, Go, Rust, and C++.
  Instead of four hand-written walkers, one recursive visitor is parametrized by
  language: each language only differs in which node kinds declare callables,
  types, calls, and imports, how a declared name is read (a `name` field for most,
  a nested *declarator* for C++), and how a call's callee/receiver and an import's
  specifier are spelled. Qualified names are normalized to a single `.` separator
  across languages, which is what the dispatch resolver expects.

Both adapters also emit security patterns and inline suppressions (see below), so
adding a language is adding a branch in `GenericAdapter`, not touching resolution,
taint, the graph, or the rules.

## Security detection (`security` module)

Deterministic and dependency-free (no regex crate):

- **Provider-pattern secrets** follow the gitleaks rule set — exact prefix,
  charset, and length scanners for AWS, GitHub, Slack, Stripe, Google, and PEM
  private keys. Near-zero false positives, scanned over every string literal.
- **High-entropy secrets** follow the detect-secrets heuristic — a value bound to
  a secret-shaped name that clears a charset-aware Shannon-entropy threshold.
- **Dangerous calls** become taint sinks: `eval`/`exec`, `os.system`/`subprocess`,
  `exec.Command`, `Command::new`, `system`/`popen`, attributed to the enclosing
  symbol so the dataflow engine can reach them.
- **Weak hashes** (MD5, SHA-1) per language.

Inline `// ovecc-ignore` (and `# ovecc-ignore` in Python) comments are recorded
as suppressed lines, so a finding landing on one is dropped downstream.

## Output

The single output is `FileFacts` (symbols, imports, calls, apis, schema_refs,
security_patterns, suppressed_lines, local_types). The indexer resolves these into
typed records; the parser assigns no identities and does no cross-file work.
