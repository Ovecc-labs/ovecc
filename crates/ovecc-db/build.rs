fn main() {
    // DuckDB's LocalFileSystem calls the Windows Restart Manager API
    // (RmStartSession, RmGetList, ...) to report which process holds a file
    // lock. libduckdb-sys only emits the import library on MSVC targets, so
    // on *-windows-gnu we must link rstrtmgr ourselves (mingw-w64 ships
    // librstrtmgr.a).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "gnu" {
        println!("cargo:rustc-link-lib=rstrtmgr");
    }
}
