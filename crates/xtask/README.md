# xtask

The workspace's development task runner, invoked as `cargo xtask <command>`
(the alias lives in `.cargo/config.toml`). It exists so the git hooks, a
contributor's terminal, and CI all execute the same gate definitions from one
place: a check that passes locally cannot fail differently in CI.

The crate is a single std-only binary with zero dependencies, so it compiles
in seconds and never adds to the product's dependency tree; `publish = false`
keeps it out of any release. `lint`, `test`, `audit`, and `coverage` wrap the
underlying cargo tools; `check` is the after-every-edit loop (apply clippy
fixes, format, lint, test, report suppressions); `ci` is the exact pipeline
the CI lint job runs. `suppressions` counts `allow`/`expect` attributes across
the crates so silenced lints stay visible instead of accumulating quietly.

`hooks` installs the git `pre-commit` (lint, only when staged changes touch
Rust or manifests) and `pre-push` (lint + test) hooks, resolving the hook
directory through `git rev-parse --git-path` so linked worktrees behave, and
refusing to overwrite a hook it did not write unless `--force` is passed.

`dogfood` closes the loop ovecc sells: it builds the release binary, indexes
this repository with it, prints the summary, and runs `ovecc review` so a
change that introduces new high-severity findings on ovecc itself fails —
the same gate CI enforces in the `self-review` job.

Gates that need an external cargo tool (`cargo-audit`, `cargo-llvm-cov`)
detect its absence and skip with an install hint rather than failing, except
under `ci`, where the audit is strict. Coverage starts at `--min 0` — a
floor to ratchet upward, not a day-one wall.
