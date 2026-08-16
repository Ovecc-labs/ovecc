# Contributing to Ovecc

Thanks for your interest! Ovecc is early-stage and moving fast, so the process
is deliberately light.

## Building

Stable Rust. On Linux/macOS a plain build works out of the box; on Windows use
the GNU toolchain; the full walkthrough is in
[docs/dev/SETUP.md](docs/dev/SETUP.md). The first build compiles bundled DuckDB
from source and takes a while; later builds are incremental.

```sh
cargo build --release
cargo test --workspace
```

## Development workflow

The `cargo xtask` runner (crates/xtask, std-only) is the single entry point
for every quality gate; CI runs the same commands, so green locally means
green in CI. One-time setup:

```sh
cargo xtask hooks     # install the git pre-commit (lint) and pre-push (lint+test) hooks
```

Day to day:

```sh
cargo xtask check     # after edits: clippy --fix, rustfmt, lint, tests, suppression report
cargo xtask lint      # what the pre-commit hook runs: fmt --check + clippy -D warnings
cargo xtask ci        # the full CI gate: lint, cargo-audit (strict), tests, suppressions
cargo xtask dogfood   # build ovecc, index this repo, review the latest change
cargo xtask coverage --min 0   # cargo-llvm-cov line coverage (ratchet the floor up over time)
```

`cargo xtask --help` lists the rest. The accuracy corpus under
`tests/fixtures/accuracy/` gates detector precision and recall: every case
stages a small repository, and the suite fails if a required finding goes
missing or a `deny` probe fires. When you add or tune a detector, add a case
(`repo/` files plus `expected.toml` with `require`/`deny` entries) in the
same change.

## Before opening a PR

CI blocks on these, so run them locally first:

```sh
cargo xtask ci
```

We also dogfood: run `cargo xtask dogfood` (or `ovecc index . && ovecc review`)
on your branch and make sure your change doesn't introduce new findings on
ovecc itself — CI enforces this with the `self-review` job.

## Licensing and the DCO

Ovecc is MPL-2.0, and contributions come in under the same license
(inbound = outbound): by opening a pull request you agree that your change is
licensed under MPL-2.0. We use the
[Developer Certificate of Origin](https://developercertificate.org/) rather than
a CLA, so sign off each commit to certify that you wrote the change or have the
right to submit it under this license:

```sh
git commit -s   # appends a Signed-off-by line
```

## What makes a good change

- **Determinism is the product.** Identical inputs must produce byte-identical
  output. No wall-clock, no randomness, no map iteration order leaking into
  results (use `BTreeMap`/sorting at boundaries).
- **Offline by default.** Only `audit --fetch` may touch the network, ever.
- **The JSON envelope is a contract.** Additive changes only; never rename or
  remove fields without discussion.
- New analysis belongs behind the existing crate boundaries (see the workspace
  table in the [README](README.md)); the CLI crate stays thin.

## Bugs and ideas

Open a GitHub issue. For false positives/negatives in the analysis, an
`ovecc --format json` excerpt of the finding plus a minimal repro file is the
fastest path to a fix.
