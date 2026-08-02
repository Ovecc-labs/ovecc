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
| django/django | Python | 2 868 | 6 | 11 113 | 42 980 | 303 442 | 170 / 0 | 1 825 (133 / 714 / 978) | High | 20.3 s | 317.3 MB |
| gohugoio/hugo | Go | 913 | 38 | 6 384 | 11 758 | 57 927 | 2 / 0 | 1 510 (206 / 536 / 768) | High | 7.2 s | 58.6 MB |
| tokio-rs/tokio | Rust | 790 | 10 | 8 147 | 9 110 | 41 216 | 0 / 0 | 395 (24 / 66 / 305) | High | 4.5 s | 51.5 MB |
| vuejs/core | JS/TS | 526 | 16 | 2 120 | 12 944 | 113 817 | 0 / 7 | 1 160 (132 / 429 / 599) | High | 6.0 s | 85.5 MB |
| abseil/abseil-cpp | C++ | 878 | 4 | 8 003 | 20 557 | 97 435 | 0 / 0 | 1 673 (71 / 426 / 1 176) | Low | 8.9 s | 94.5 MB |

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
| sqlglot | Python | 73 | 0.75 | 0.79 | **64%** | 0.73 | 1.00 | 41% | 14% |
| dask | Python | 32 | 0.75 | 0.75 | **62%** | 0.73 | 1.00 | 53% | 19% |
| django | Python | 74 | 0.66 | 0.71 | **61%** | 0.68 | 0.95 | 46% | 22% |
| yt-dlp | Python | 78 | 0.64 | 0.70 | **50%** | 0.66 | 0.85 | 46% | 12% |

How to read this: the truth set is by construction a subset of the files that
contain the identifier as a word, so grep's recall is close to 1.0 no matter
what and inflates any recall-weighted score. The honest comparison is
exact-set match, the share of symbols where a method returns exactly the
reference set with nothing to sift. Ovecc leads it on all five repositories,
from 50% against 46% on yt-dlp's dynamic dispatch up to 80% against 46% on
TypeScript, where value-position references (callbacks, registries, pipe
combinators) are invisible to a call-only graph and are now recorded.

Where ovecc still loses ground: Python recall sits at 0.70 to 0.79, the cost
of dynamic dispatch and inheritance that no static graph resolves for free,
and it answers empty on 6 to 22% of symbols where the reference sits in
constructs the extractors do not yet model.

## What one question costs an agent

Accuracy says nothing about what the answer costs to obtain. This section
prices the same question, "which files reference F", on both paths: one
`ovecc query "rdeps F"` against the index, versus `rg -w` and then opening the
files it matched, which is what an agent does with a hit list it cannot trust.

Method:

- **Sample**: the same construction as the accuracy table, uniquely-named
  functions drawn with a fixed seed, 40 per repository. Unique names again
  favour the baseline by removing its collision noise.
- **Baseline**: ripgrep 15.1.0, scoped to the language's extension. Both
  commands run once to warm the cache before the timed run.
- **Bytes**: what the tool writes to stdout, and for the baseline also the size
  of every file it matched. Roughly four bytes to the token.
- **Checkouts**: django `5f30fd2358`, remeda `465991f`.

| Repository | Files | ovecc median | rg median | ovecc bytes | rg hit lines | rg + reading the files |
| --- | --- | --- | --- | --- | --- | --- |
| django | 2 868 | 517 ms | 315 ms | 8 805 | 68 070 (7.7×) | 4 355 185 (**495×**) |
| remeda | 391 | 138 ms | 91 ms | 9 784 | 77 724 (7.9×) | 954 320 (**98×**) |

Ovecc is not the faster command. It is about 1.6× slower per call than
ripgrep, because it opens and queries a database where ripgrep streams bytes
past a matcher, and `ovecc_capabilities` returning in 32 ms over a warm MCP
session shows that cost is the query, not process startup.

What it removes is reading. Against ripgrep's hit list alone the answer is
7.7 to 7.9× smaller, which is the floor: it credits the baseline with resolving
the reference set from `file:line` pairs, which it cannot do, since the truth
set is a subset of the lines containing the identifier and nothing in the
output says which. Against the path an agent actually takes, opening the
matched files to decide, it is 98 to 495× smaller. Half a second of query
against a 33 kB median read is the trade, and it only pays off because the
tokens are what the model is slow at, not the tool call.

These are single-question costs, and a whole task compounds them in ways the
table does not model. One end-to-end run that does compound them, on zod with
Claude Sonnet 4.6, asking whether importing `scripts/check-semver.js` from
`packages/zod/src/index.ts` closes an architectural cycle:

| Path | Tokens | Cost | Wall clock |
| --- | --- | --- | --- |
| agent + ovecc over MCP | 58 906 | $0.22 | 64 s |
| agent reading files | 528 865 | $1.63 | 96 s |

Read that as one observation, not a benchmark: a single run, one model, one
question, and agent runs are not deterministic. It is recorded because it is
the only measurement here of what the token difference is worth once inference
is in the loop, and because the ratios land where the table predicts, roughly
an order of magnitude on tokens and much less than that on time.

## Self-check: do the findings track the corrections?

A benchmark that only measures speed and coverage never asks whether the
findings are worth acting on. `ovecc selfcheck` asks: for each rule, does the
code it flags get corrected more often than the rest of the repository?

Rates are age-weighted fix mass per kilobyte of source (a fix loses half its
weight every 180 days). A rule's lift is its rate over the repository's base
rate, so 1.00 means "flags code exactly as fix-prone as the average line", and
2.00 means twice as fix-prone. Bytes rather than lines because bytes are what
the index stores; the lift is a ratio, so the unit cancels.

Measured on ovecc's own repository, 145 commits from 12 June to 1 August 2026,
109 indexed files, 1661 KB, base rate 0.04 fixes/KB.

| Rule | Files flagged | KB flagged | Fix mass | Lift |
| --- | --- | --- | --- | --- |
| `architecture/behavioral-coupling` | 7 | 165.8 | 11.70 | 1.63 |
| `security/command-exec` | 5 | 166.2 | 11.02 | 1.53 |
| `security/secret` | 5 | 290.7 | 14.51 | 1.15 |
| `long-parameter-list` | 9 | 346.0 | 14.51 | 0.97 |
| `data-clumps` | 16 | 498.0 | 20.02 | 0.93 |
| `complexity` | 43 | 1161.6 | 43.92 | 0.87 |
| `long-function` | 37 | 1132.5 | 41.29 | 0.84 |
| `unlisted-dependency` | 4 | 35.2 | 1.00 | 0.66 |
| `large-class` | 3 | 180.1 | 4.46 | 0.57 |
| `feature-envy` | 7 | 249.9 | 3.79 | 0.35 |
| `security/weak-hash` | 1 | 0.1 | 0.00 | 0.00 |

Read plainly: two rules clear the base rate by a margin worth naming, one sits
on it, and the rest are below. Behavioural coupling ranking first is the result
we would have predicted and is therefore the one to trust least on a single
repository. `security/weak-hash` flags one 99-byte test fixture; any rule with a
flagged surface that small is noise, not a measurement.

What this number does not show:

- **One repository, and the most conflicted one.** Everything above is ovecc
  measured on ovecc. The five benchmark repositories are indexed with
  `--no-git`, so they have no fix history and cannot appear here.
- **Association, not proof.** Findings are computed on today's code while the
  corrections happened in the past.
- **It penalises the rules that worked.** A file flagged, fixed, and cleaned up
  no longer carries the finding, so the rules that got acted on lose exactly the
  evidence that would have vindicated them.
- **Fixes that landed outside the index are excluded**, 10% of the mass here:
  deleted files, documentation, unsupported languages. Folding them in would
  raise the base rate and depress every lift; leaving them silent would be worse.

There is no published bar to clear here. The protocol is ours, and so is the
obligation to ship the figure when it is unflattering.

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
