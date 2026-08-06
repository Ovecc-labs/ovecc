#!/usr/bin/env node
// npm installs exactly one of the platform packages, the one whose os/cpu
// fields match the machine. This finds it and hands the process over to the
// real binary. CommonJS on purpose: no build step, runs on any Node >= 18.

const { spawnSync } = require('node:child_process')

const PACKAGES = {
  'darwin arm64': '@ovecc/cli-darwin-arm64',
  'linux x64': '@ovecc/cli-linux-x64',
  'win32 x64': '@ovecc/cli-win32-x64',
}

const target = `${process.platform} ${process.arch}`
const pkg = PACKAGES[target]
if (!pkg) {
  console.error(`ovecc: no prebuilt binary for ${target}.`)
  console.error('Build from source: https://github.com/Ovecc-labs/ovecc#build-from-source')
  process.exit(1)
}

let binary
try {
  // Exact-file resolution, so the extensionless binary resolves; the platform
  // packages declare no "exports" field, which would block this subpath.
  binary = require.resolve(`${pkg}/bin/ovecc${process.platform === 'win32' ? '.exe' : ''}`)
} catch {
  console.error(`ovecc: ${pkg} is not installed.`)
  console.error('Optional dependencies are how the binary ships; reinstall without --no-optional or --omit=optional.')
  process.exit(1)
}

const run = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' })
if (run.error) {
  console.error(`ovecc: ${run.error.message}`)
  process.exit(1)
}
// Killed by a signal: report it the way a shell would, so CI sees a failure.
process.exit(run.status === null ? 1 : run.status)
