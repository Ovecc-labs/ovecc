# ovecc

Ovecc reads your repository once and builds a deterministic, persistent model of
it: every file, import, symbol, and call. From that single index it answers what
breaks if you change something, where the dependency cycles are, what is
duplicated or dead, and which architectural rule a pull request just broke.

It runs on your machine, gives byte-identical answers every run, and never puts
an LLM in the loop.

```sh
npx ovecc index .
npx ovecc summary
npx ovecc architecture check
```

Or add it to a project:

```sh
npm install --save-dev ovecc
```

This package is a thin launcher. The binary itself ships in a platform package
(`@ovecc/cli-darwin-arm64`, `@ovecc/cli-linux-x64`, `@ovecc/cli-linux-arm64`,
`@ovecc/cli-win32-x64`) that npm picks by `os` and `cpu`, so only one is
downloaded and there is no install script to run.

Full documentation, the architecture contract format, and the CI gate are in the
[repository](https://github.com/Ovecc-labs/ovecc). MPL-2.0.
