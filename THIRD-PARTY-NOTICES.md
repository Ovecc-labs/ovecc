# Third-Party Notices

Ovecc is built on open-source software. This file records the licenses and
attributions for code adapted into Ovecc and for its notable dependencies.

---

## fallow

Portions of Ovecc are adapted from **fallow**
(<https://github.com/fallow-rs/fallow>), a deterministic TypeScript/JavaScript
codebase-intelligence engine, used under the MIT License.

Adapted or ported (verbatim or lightly-modified) into Ovecc:

| Ovecc location | What was adapted from fallow |
| --- | --- |
| `crates/ovecc-graph/src/cycles.rs` | Elementary circular-dependency enumeration: iterative Tarjan SCC + iterative-deepening DFS, canonicalization, and bounding (`crates/graph/src/graph/cycles.rs`). Re-implemented on Ovecc's `String` module model with the standard library (no `fixedbitset`/`rustc_hash`). |
| `crates/ovecc-core/src/report.rs` | The versioned output envelope and `Meta` block (integer `schema_version` + bump policy, `MetaMetric`/`MetaRule`), adapted from `crates/types/src/envelope.rs` to Ovecc's command vocabulary. |
| `crates/ovecc-core/src/capabilities.rs` | The self-describing capability-manifest pattern (single source of truth for the `capabilities` command and per-command `meta`), modeled on `crates/types/src/mcp_manifest.rs` and the `Meta` shapes. |
| `crates/ovecc-graph/src/dupes.rs` | Clone-family detection: normalized k-gram fingerprint grouping + region merging, adapted from fallow's `core/src/duplicates/` engine (SA-IS/LCP detector, the rolling-fingerprint alternative, and the family/instance/stat shapes). |
| `crates/ovecc-parser/src/tokenize.rs` | The duplication tokenizer/normalizer (identifier and literal bucketing), re-implemented on tree-sitter from fallow's `core/src/duplicates/tokenize` + `normalize`. |
| `crates/ovecc-indexer/src/imports.rs` | The oxc_resolver-backed JS/TS module resolution (resolver options: extensions, `extension_alias`, condition names, tsconfig auto-discovery; the tsconfig-error retry; the resolve→repo-relative mapping), adapted from fallow's `crates/graph/src/resolve/specifier.rs`. |
| `crates/ovecc-parser/src/oxc_extractor.rs` | The oxc-based TS/JS semantic extractor: file exports (with re-export provenance) and per-function McCabe cyclomatic + SonarSource cognitive complexity, ported from fallow's `crates/extract/src/{parse.rs, complexity.rs, visitor/visit_impl.rs, visitor/declarations.rs}` and `crates/types/src/extract.rs`. |
| `crates/ovecc-rules/src/deadcode.rs` | Dead-code analysis (unused exports/files): entry-point reachability BFS, per-export reference sets, and the unused-export/unused-file predicates, ported from fallow's `crates/graph/src/graph/{reachability.rs, re_exports}` and `crates/core/src/analyze/{unused_exports.rs, unused_files.rs}`. |

Each adapted file carries an `SPDX-License-Identifier: MIT` tag and a provenance
comment pointing here. Pure-idea re-implementations that share no substantial
code are attributed here out of caution.

### fallow license

```
MIT License

Copyright (c) 2026 Bart Waardenburg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Rust crate dependencies

Ovecc links a number of Rust crates (see `Cargo.toml` and `Cargo.lock`), each
under its own license (predominantly MIT or Apache-2.0). Notable ones:

- **DuckDB** (`duckdb`, bundled): MIT License.
- **oxc** (`oxc_resolver`, and the `oxc_parser`/`oxc_ast`/`oxc_semantic`/`oxc_span`
  stack where used for the TS/JS extractor): MIT License. Pure-Rust, offline.
- **tree-sitter** and the grammar crates: MIT License.
- **petgraph**, **serde**, **clap**, **chrono**, **rayon**, **gix**, **ignore**,
  **globset**, **toml**, **anyhow**, **thiserror**, **sha2**, **semver**:
  MIT or Apache-2.0.

For the authoritative, complete list of dependency licenses, run:

```sh
cargo install cargo-about   # or cargo-license
cargo about generate about.hbs   # or: cargo license
```

No dependency on the analysis/audit path performs network I/O; vulnerability data
(OSV) is vendored into `.ovecc/osv/` out of band and read locally.
