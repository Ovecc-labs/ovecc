//! `ovecc capabilities`: the machine-readable contract.

use crate::render::emit_json;
use anyhow::Result;
use ovecc_core::capabilities;
use ovecc_core::config::OutputFormat;
use ovecc_core::report::Meta;

/// Renders the capability manifest. Works without a database — the contract
/// is static.
pub(crate) fn render_capabilities(format: OutputFormat) -> Result<()> {
    let caps = capabilities::capabilities();
    match format {
        OutputFormat::Json
        | OutputFormat::Ndjson
        | OutputFormat::Sarif
        | OutputFormat::Codeclimate => emit_json("capabilities", &caps, Meta::default())?,
        OutputFormat::Markdown => {
            println!("# Ovecc capabilities");
            println!();
            println!("Schema version: `{}`", ovecc_core::report::SCHEMA_VERSION);
            println!();
            println!("## Commands");
            println!();
            for command in caps.commands {
                let ro = if command.read_only {
                    " _(read-only)_"
                } else {
                    ""
                };
                println!("- **{}** — {}{ro}", command.name, command.summary);
            }
            println!();
            println!("## Exit codes");
            println!();
            for code in caps.exit_codes {
                println!("- `{}` {} — {}", code.code, code.name, code.meaning);
            }
        }
        OutputFormat::Text => {
            println!("ovecc — deterministic architecture intelligence");
            println!("schema_version: {}", ovecc_core::report::SCHEMA_VERSION);
            println!("formats: {}", caps.formats.join(", "));
            println!("severities: {}", caps.severities.join(", "));
            println!();
            println!("Commands:");
            for command in caps.commands {
                println!("  {:<16} {}", command.name, command.summary);
            }
            println!();
            println!("Exit codes:");
            for code in caps.exit_codes {
                println!("  {} {:<16} {}", code.code, code.name, code.meaning);
            }
        }
    }
    Ok(())
}
