mod cli;
mod mcp;

use ovecc_core::error::OveccError;
use peak_alloc::PeakAlloc;
use std::process::ExitCode;

/// Tracks peak heap usage for `--stats`. The tracking is a single atomic
/// update per allocation — negligible for an I/O- and parse-bound tool.
#[global_allocator]
pub(crate) static PEAK_ALLOC: PeakAlloc = PeakAlloc;

fn main() -> ExitCode {
    match cli::run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ovecc: {error:#}");
            // Stable exit codes; unknown errors fall back to 7.
            let code = error
                .downcast_ref::<OveccError>()
                .map(|inner| inner.exit_code().code())
                .unwrap_or(7);
            ExitCode::from(code)
        }
    }
}
