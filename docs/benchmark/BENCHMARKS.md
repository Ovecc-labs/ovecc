# Ovecc Benchmarks

This document records measured performance and detection behaviour of Ovecc on
real open-source repositories across all five supported languages. The numbers
exist to validate performance goals and to show how the analysis scales
from a few files to several thousand.

## Method

- **Binary**: release build (`cargo build --release`), the `ovecc` CLI.
- **Command**: `ovecc index <repo> --no-git --stats`. Git ingestion is excluded so
  the timing reflects the analysis pipeline itself (discovery, parse, resolve,
  analyze, persist) rather than history walking.
- **Timing**: the `total` line from `--stats` (end-to-end wall-clock of the run),
  one cold run per repository (empty parse cache, no prior `.ovecc`).
- **Memory**: peak heap as reported by the tracking allocator. This counts the
  Rust heap; DuckDB's native allocations are not included.
- **Findings**: the count from `ovecc violations`; the risk score from
  `ovecc summary`.
- The checkouts themselves are not committed (see `.gitignore`); only these
  results are.

Absolute times depend on the machine and are meant to be read relatively: the
pipeline is linear in repository size, and parsing is a small fraction of the
total.

## Large repositories

These are the stress cases: industrial codebases with tens of thousands of
symbols and call edges.

| Repository | Lang | Files | Modules | Deps | Symbols | Call edges | APIs / Tables | Findings | Risk | Time | Peak heap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| django/django | Python | 2 967 | 6 | 11 999 | 45 282 | 189 469 | 171 / 1 | 43 | High | 28.5 s | 198.5 MB |
| gohugoio/hugo | Go | 929 | 38 | 6 370 | 13 463 | 57 541 | 2 / 0 | 22 | High | 13.1 s | 56.8 MB |
| tokio-rs/tokio | Rust | 784 | 10 | 4 300 | 9 004 | 40 499 | 0 / 0 | 20 | High | 9.3 s | 48.1 MB |
| vuejs/core | JS/TS | 524 | 16 | 1 926 | 12 723 | 55 179 | 0 / 7 | 7 | High | 5.5 s | 49.2 MB |
| abseil/abseil-cpp | C++ | 875 | 4 | 7 967 | 20 448 | 96 523 | 0 / 0 | 1 | Low | 17.2 s | 90.8 MB |

The largest case, Django, builds a graph of ~45k symbols and ~189k call edges in
under thirty seconds. C++ is the slowest per file because the grammar's nested
declarators make extraction heavier; Abseil's 875 headers and sources produce
the second-largest symbol count.

## Security findings on the large repositories

The findings are deterministic pattern and source-to-sink detections, surfaced
for review rather than asserted as exploitable. In mature libraries most land in
build scripts, developer tooling, and tests.

| Repository | Findings | Breakdown |
| --- | --- | --- |
| django/django | 43 | 25 command execution, 10 dynamic eval/exec, 7 weak hash (MD5/SHA-1), 1 circular dependency |
| gohugoio/hugo | 22 | 11 command execution, 9 weak hash, 1 hardcoded secret (critical), 1 other |
| tokio-rs/tokio | 20 | 19 command execution, 1 circular dependency |
| vuejs/core | 7 | 6 dynamic `new Function`, 1 circular dependency |
| abseil/abseil-cpp | 1 | 1 command execution |

A note on interpretation: the command-execution and eval findings in these
projects are concentrated in management commands, autoreload utilities, code
generators, and test suites, not in remotely reachable request paths. The Vue
`new Function` findings sit in the runtime template compiler, where they are only
a concern if untrusted input reaches client-side compilation. Ovecc reports the
flow; judging exploitability is the reviewer's call. The single Hugo secret is a
high-entropy value in a documentation asset, the kind of true positive a
pre-commit scan is meant to catch.

## Observations

- **Linear and predictable.** Time and memory track repository size; there is no
  super-linear blow-up on the largest graphs.
- **Parsing is cheap; persistence dominated, then was fixed.** Earlier profiling
  showed the DuckDB write phase taking ~80% of a run; moving the high-volume code
  facts to the columnar appender cut indexing time several-fold, which these
  release numbers reflect.
- **Incremental runs are near-instant.** A re-index with an unchanged tree
  re-parses nothing (content-addressed parse cache) and writes only a new
  snapshot.
- **Cross-language reach.** The same pipeline produces symbols, call graphs,
  dependency graphs, APIs, taint flows, and security findings for Python, Go,
  Rust, C++, and JavaScript/TypeScript.
