//! `ovecc version`: what this binary is, in every format.
//!
//! `--version` prints one line for a human. This is the same fact shaped for a
//! caller that has to act on it: the release, and the `schema_version` that says
//! whether the JSON envelope it is about to parse is the one it was written
//! against. Neither number is derived from a repository, so the command needs no
//! index and no `.ovecc/` — it answers from the binary alone.

use crate::render::{ndjson_line, render_report};
use anyhow::Result;
use ovecc_core::config::OutputFormat;
use ovecc_core::report::SCHEMA_VERSION;
use serde::Serialize;

/// The binary's own identity. Not a snapshot of anything — both fields are
/// compiled in, so the answer is identical on every run of a given build.
#[derive(Debug, Serialize)]
pub(crate) struct VersionReport {
    /// The release, matching `--version` and the published crate.
    pub(crate) version: &'static str,
    /// The JSON envelope contract. Bumps only on a breaking change, so a client
    /// that pins this can trust the field names it reads.
    pub(crate) schema_version: u32,
}

pub(crate) fn build_version_report() -> VersionReport {
    VersionReport {
        version: env!("CARGO_PKG_VERSION"),
        schema_version: SCHEMA_VERSION,
    }
}

pub(crate) fn render_version(report: &VersionReport, format: OutputFormat) -> Result<()> {
    render_report(
        "version",
        report,
        format,
        || {
            println!("{}", ndjson_line("version", report)?);
            Ok(())
        },
        || {
            println!("# ovecc {}", report.version);
            println!();
            println!("- Schema version: `{}`", report.schema_version);
        },
        || {
            // First line matches `ovecc --version` exactly, so a script that
            // already greps for it keeps working when it moves to this command.
            println!("ovecc {}", report.version);
            println!("schema_version: {}", report.schema_version);
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_carries_the_compiled_in_release_and_contract() {
        let report = build_version_report();
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        // A version string that is not a version is the one failure mode worth
        // pinning: it reaches every consumer that parses the output.
        assert!(
            report.version.split('.').count() >= 3
                && report
                    .version
                    .split('.')
                    .all(|part| !part.is_empty() && part.chars().next().unwrap().is_ascii_digit()),
            "unexpected version shape: {}",
            report.version
        );
    }
}
