mod cli;
mod commands;
mod export_graph;
mod fix;
mod mcp;
mod render;

use ovecc_core::error::OveccError;
use peak_alloc::PeakAlloc;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tracks peak heap usage for `--stats`. The tracking is a single atomic
/// update per allocation — negligible for an I/O- and parse-bound tool.
#[global_allocator]
pub(crate) static PEAK_ALLOC: PeakAlloc = PeakAlloc;

/// Set by the panic hook when a panic was caused by stdout going away
/// (`ovecc ... | head`, a pager quitting). That is the *reader's* choice,
/// not an ovecc failure, so it must not look like a crash.
static BROKEN_PIPE: AtomicBool = AtomicBool::new(false);

/// True for the panic `print!`/`println!` raise when stdout can no longer be
/// written — on Windows `os error 109/232`, on Unix `EPIPE`. The stable
/// "failed printing to stdout" prefix comes from std itself.
fn is_stdout_pipe_panic(payload: &dyn std::any::Any) -> bool {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied());
    message.is_some_and(|m| m.starts_with("failed printing to stdout"))
}

fn main() -> ExitCode {
    // Downstream readers may close the pipe at any time (`| head`, a pager
    // quit). std's print macros panic on that; intercept it globally so every
    // command exits quietly instead of dumping a panic trace.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if is_stdout_pipe_panic(info.payload()) {
            BROKEN_PIPE.store(true, Ordering::SeqCst);
        } else {
            default_hook(info);
        }
    }));

    let outcome = std::panic::catch_unwind(cli::run);

    match outcome {
        Ok(Ok(code)) => ExitCode::from(code),
        Ok(Err(error)) => {
            // `cli::run` has already rendered the error (format-aware); here we
            // only map it to its stable exit code. Unknown errors fall back to 7.
            let code = error
                .downcast_ref::<OveccError>()
                .map(|inner| inner.exit_code().code())
                .unwrap_or(7);
            ExitCode::from(code)
        }
        Err(_) if BROKEN_PIPE.load(Ordering::SeqCst) => {
            // Output was truncated by the reader on purpose; success.
            ExitCode::SUCCESS
        }
        // A real panic: the default hook has already printed the message and
        // backtrace; map it to the documented "internal error" exit code.
        Err(_) => ExitCode::from(7),
    }
}
