# ovecc-audit

Offline dependency auditing: inventories the third-party packages a
repository declares and matches them against a local copy of the OSV
vulnerability database, with no network access. The audit trades the coverage
of a live feed for determinism and privacy; it is reproducible and sends
nothing out.

`discover_packages` parses lockfiles (currently `package-lock.json`) into a
package list: ecosystem, name, version, manifest path, direct or transitive. It
reports a lockfile that exists but cannot be read separately from one that is
absent, so a scan of nothing is never mistaken for a clean bill of health.
`load_osv_dir` reads OSV entries from `.ovecc/osv/`, each carrying affected
version ranges as SEMVER events (introduced/fixed). `audit` evaluates every
package against those ranges with the `semver` crate and emits one
`VulnerableDependency` finding per affected package.

The indexer runs both steps during the analyze phase and merges the results
with the rule and taint findings. Without a local OSV database the audit is
simply empty; the package inventory is still recorded.
