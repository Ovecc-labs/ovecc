# ovecc-audit

## Purpose

`ovecc-audit` is the offline dependency auditor. It inventories the third-party
packages a repository declares and matches them against a local copy of the OSV
vulnerability database, with no network access. Like the rest of Ovecc, it
trades coverage of a live feed for determinism and privacy: the audit is
reproducible and sends nothing out.

## How it works

- **Inventory** — `discover_packages` parses lockfiles (starting with
  `package-lock.json`) into a package list (ecosystem, name, version, manifest
  path, direct/transitive). The indexer persists this into the `packages` table.
- **Advisory database** — `load_osv_dir` reads OSV entries from `.ovecc/osv/`.
  Each entry follows the OSV schema: affected packages with version ranges
  expressed as SEMVER events (introduced / fixed).
- **Matching** — `audit` checks each package against the affected ranges using
  the `semver` crate (`version_in_semver_range`) and emits a
  `VulnerableDependency` finding per affected package.

## Place in the pipeline

The indexer calls `discover_packages` and `audit` during the analyze phase and
merges the findings with the rule and taint findings before persisting. With no
local OSV database present the audit is simply empty; the package inventory is
still recorded.
