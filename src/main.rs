mod cli;
mod config;
mod graph;
mod indexer;
mod model;
mod parser;
mod storage;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ovecc: {error:#}");
            ExitCode::from(7)
        }
    }
}
