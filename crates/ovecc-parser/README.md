# ovecc-parser

Turns source files into `FileFacts` with Tree-sitter. This is the only crate
that touches a syntax tree, and the tree never crosses the crate boundary. A
parse failure is per-file and never aborts an index run: the adapter returns
a `ParseFailure`, and the indexer records it and continues.

Two adapters implement `LanguageAdapter`:

- `TypeScriptAdapter`, a bespoke walker for the whole JS/TS family (js, jsx,
  ts, tsx). One recursive pass extracts every fact kind, so the tree is
  traversed once: symbols, imports (static, re-export, require, dynamic,
  type-only), calls attributed to their enclosing callable,
  Express/Fastify/Koa routes, and SQL embedded in string and template
  literals. oxc supplies the JS/TS exports and per-function complexity.
- `GenericAdapter`, a specification-driven walker for Python, Go, Rust, and
  C++. One recursive visitor is parametrized by language: each language only
  differs in which node kinds declare callables, types, calls, and imports,
  how a declared name is read (a `name` field for most, a nested declarator
  chain for C++), and how a call's callee and an import's specifier are
  spelled. Qualified names normalize to a single `.` separator, which is
  what the dispatch resolver expects.

Both adapters also emit security patterns and inline suppressions, so adding
a language means adding a branch in `GenericAdapter`, not touching
resolution, taint, the graph, or the rules.

Security detection (`security`) is deterministic and dependency-free (no
regex crate). Provider-pattern secrets follow the gitleaks rule set: exact
prefix, charset, and length scanners for AWS, GitHub, Slack, Stripe, Google,
and PEM private keys, scanned over every string literal. High-entropy
secrets follow the detect-secrets heuristic: a value bound to a
secret-shaped name that clears a charset-aware Shannon-entropy threshold.
Dangerous calls (`eval`/`exec`, `os.system`/`subprocess`, `exec.Command`,
`Command::new`, `system`/`popen`) become taint sinks attributed to their
enclosing symbol, and weak hashes (MD5, SHA-1) are flagged per language.
Inline `// ovecc-ignore` comments (`# ovecc-ignore` in Python) are recorded
as suppressed lines, so a finding landing on one is dropped downstream.

The single output is `FileFacts` (symbols, imports, calls, apis, schema
refs, security patterns, suppressed lines, local types). The parser assigns
no identities and does no cross-file work.
