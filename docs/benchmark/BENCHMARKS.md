# Ovecc Benchmarks

This document records measured performance, detection behaviour, and answer
accuracy of Ovecc on real open-source repositories across all five supported
languages. The numbers exist to validate performance goals, to show how the
analysis scales from a few files to several thousand, and to show how often
the dependency answers are right.

All numbers below were measured on 16 July 2026 with a release build. Earlier
revisions of this document carried a much smaller findings count (43 on
Django); the ruleset has since grown from security patterns and cycles to
complexity, dead code, dependency hygiene, clones, and design smells, and the
call graph now records callables referenced in value position (passed as
arguments, stored in registries, used as decorators), which alone grew
Django's call edges by roughly 60%.

## Method

- **Binary**: release build (`cargo build --release`), the `ovecc` CLI.
- **Command**: `ovecc index <repo> --no-git --stats`. Git ingestion is excluded so
  the timing reflects the analysis pipeline itself (discovery, parse, resolve,
  analyze, persist) rather than history walking.
- **Timing**: the stats line (end-to-end wall-clock of the run), one cold run
  per repository (no prior `.ovecc`, empty parse cache) on an otherwise idle
  machine. The "from cache" hits Django reports on a cold run are its several
  hundred identical `__init__.py` files: the parse cache is content-addressed,
  so duplicate content parses once even within a single run.
- **Memory**: peak heap as reported by the tracking allocator. This counts the
  Rust heap; DuckDB's native allocations are not included.
- **Findings**: the count from `ovecc violations`, split by severity. The
  totals span the whole ruleset; the security subset is broken out separately.
- The checkouts themselves are not committed (see `.gitignore`); only these
  results are. Checkouts measured: django `5f30fd2358`, hugo `89b8c32`,
  tokio `f61fcca`, vuejs/core `fa2885d`, abseil-cpp `9d6a530`.

Absolute times depend on the machine and are meant to be read relatively: the
pipeline is linear in repository size, and parsing is a small fraction of the
total.

## Large repositories

These are the stress cases: industrial codebases with tens of thousands of
symbols and call edges.

| Repository | Lang | Files | Modules | Deps | Symbols | Call edges | APIs / Tables | Findings (high / med / low) | Risk | Time | Peak heap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| django/django | Python | 2 868 | 6 | 11 113 | 42 980 | 303 442 | 170 / 0 | 1 825 (149 / 698 / 978) | High | 20.3 s | 317.3 MB |
| gohugoio/hugo | Go | 913 | 38 | 6 384 | 11 758 | 57 927 | 2 / 0 | 1 510 (225 / 517 / 768) | High | 7.2 s | 58.6 MB |
| tokio-rs/tokio | Rust | 790 | 10 | 8 147 | 9 110 | 41 216 | 0 / 0 | 395 (30 / 60 / 305) | High | 4.5 s | 51.5 MB |
| vuejs/core | JS/TS | 526 | 16 | 2 120 | 12 944 | 113 817 | 0 / 7 | 1 160 (142 / 419 / 599) | High | 6.0 s | 85.5 MB |
| abseil/abseil-cpp | C++ | 878 | 4 | 8 003 | 20 557 | 97 435 | 0 / 0 | 1 673 (80 / 417 / 1 176) | Low | 8.9 s | 94.5 MB |

The largest case, Django, builds a graph of ~43k symbols and ~303k call edges
in about twenty seconds. Most findings by volume are code-quality rules
(complexity, long functions, unused files, data clumps); severity is what
separates a hygiene backlog from a risk signal, which is why the split is
published rather than the bare total.

## Security findings on the large repositories

The findings are deterministic pattern and source-to-sink detections, surfaced
for review rather than asserted as exploitable. In mature libraries most land in
build scripts, developer tooling, and tests; findings inside test files are
kept but reported at low severity.

| Repository | Command exec | Dynamic eval | Weak hash | Secrets | Dependency cycles |
| --- | --- | --- | --- | --- | --- |
| django/django | 13 | 8 | 7 | 0 | 1 |
| gohugoio/hugo | 12 | 0 | 11 | 1 (critical) | 20 |
| tokio-rs/tokio | 19 | 0 | 0 | 0 | 15 |
| vuejs/core | 0 | 7 | 0 | 0 | 20 |
| abseil/abseil-cpp | 0 | 0 | 0 | 0 | 0 |

A note on interpretation: the command-execution and eval findings in these
projects are concentrated in management commands, autoreload utilities, code
generators, and test suites, not in remotely reachable request paths. The Vue
eval findings sit in the runtime template compiler, where they are only a
concern if untrusted input reaches client-side compilation. Ovecc reports the
flow; judging exploitability is the reviewer's call. The single Hugo secret is a
high-entropy value in a documentation asset, the kind of true positive a
pre-commit scan is meant to catch.

## Answer accuracy against language servers

Performance says nothing about whether the answers are right. This section
scores the question an agent actually asks, "which files reference function
F", against an independent language server as ground truth, with plain
`grep -rwl F` as the baseline an agent would otherwise use.

Method:

- **Ground truth**: jedi 0.20.0 project-scope `get_references` for Python (the
  engine behind Python language servers); the TypeScript compiler via ts-morph
  28.0.0 `findReferencesAsNodes` for TypeScript (the engine behind VS Code).
- **Sample**: uniquely-named functions, drawn with a fixed seed. Unique names
  are deliberate: they remove grep's name-collision false positives, so the
  baseline is tested at its best.
- **Scoring**: file-level sets, `ovecc query "rdeps F"` (direct callers)
  versus the truth set. Test files are removed from every set, truth included.
  The definition occurrence itself is dropped from the truth. A query ovecc
  fails to resolve counts as an empty answer, not a skipped row.
- **Checkouts**: remeda `465991f`, sqlglot `5d3ee4cac`, dask `5b115c436`,
  django `5f30fd2358`, yt-dlp `2037a6414`.

| Repository | Lang | n | ovecc P | ovecc R | ovecc exact-set | grep P | grep R | grep exact-set | ovecc empty |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| remeda | TS | 80 | 0.84 | 0.94 | **80%** | 0.62 | 1.00 | 46% | 6% |
| sqlglot | Python | 73 | 0.75 | 0.79 | **64%** | 0.73 | 1.00 | 40% | 14% |
| dask | Python | 32 | 0.75 | 0.75 | **62%** | 0.73 | 1.00 | 53% | 19% |
| django | Python | 74 | 0.66 | 0.71 | **61%** | 0.70 | 0.82 | 46% | 22% |
| yt-dlp | Python | 78 | 0.64 | 0.70 | **50%** | 0.66 | 0.85 | 47% | 12% |

How to read this: the truth set is by construction a subset of the files that
contain the identifier as a word, so grep's recall is close to 1.0 no matter
what and inflates any recall-weighted score. The honest comparison is
exact-set match, the share of symbols where a method returns exactly the
reference set with nothing to sift. Ovecc leads it on all five repositories,
from 50% against 47% on yt-dlp's dynamic dispatch up to 80% against 46% on
TypeScript, where value-position references (callbacks, registries, pipe
combinators) are invisible to a call-only graph and are now recorded.

Where ovecc still loses ground: Python recall sits at 0.70 to 0.79, the cost
of dynamic dispatch and inheritance that no static graph resolves for free,
and it answers empty on 6 to 22% of symbols where the reference sits in
constructs the extractors do not yet model.

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
- **Value references doubled the graph's reach.** Recording callables used as
  values (arguments, registry entries, decorators) raised Django's call edges
  from ~189k to ~303k and vuejs/core's from ~55k to ~114k, and is what closed
  the gap on registry-heavy code: TypeScript coverage in the accuracy table
  went from answering 24% of symbols to 94% with this change.
- **Cross-language reach.** The same pipeline produces symbols, call graphs,
  dependency graphs, APIs, taint flows, and security findings for Python, Go,
  Rust, C++, and JavaScript/TypeScript.
