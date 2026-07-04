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

## Before opening a PR

CI blocks on all three, so run them locally first:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

We also dogfood: run `ovecc index . && ovecc review` on your branch and make
sure your change doesn't introduce new findings on ovecc itself.

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
