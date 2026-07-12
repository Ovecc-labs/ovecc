# Setup Guide: Building Ovecc from Source on Windows

Ovecc bundles **DuckDB** and compiles it from source on the first build, so you need a
working C++ toolchain in addition to Rust. The workspace officially targets the
**Windows GNU (MinGW-w64)** toolchain: `.cargo/config.toml` is preconfigured for it
(big-object assembly for DuckDB's unity sources, static linking of the MinGW runtime,
and the Windows Restart Manager import library). Follow the steps below for a clean
from-scratch build.

> **Result:** a self-contained `target/release/ovecc.exe` (~95 MB) that runs on any
> Windows machine; no MSYS2 on PATH required at runtime.

---

## Prerequisites

- Windows 10/11 (x64)
- [rustup](https://rustup.rs/) with Rust **1.96+**
- ~3 GB free disk (toolchains + DuckDB build artifacts)

---

## 1. Rust (GNU toolchain)

```sh
rustup update
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

Verify the active host:

```sh
rustc -vV        # expect: host: x86_64-pc-windows-gnu
```

> To switch back to MSVC later: `rustup default stable-x86_64-pc-windows-msvc`.

## 2. MinGW-w64 (C/C++ compiler) via MSYS2

Install MSYS2:

- **winget:** `winget install --id MSYS2.MSYS2 -e`
- **or** the installer from <https://www.msys2.org/> (installs to `C:\msys64`).

Then install the compiler. Open **"MSYS2 MINGW64"** from the Start Menu and run:

```sh
pacman -Syu        # update; if it asks to close the terminal, reopen it and re-run
pacman -S --needed mingw-w64-x86_64-gcc
```

This provides `gcc`, `g++`, the assembler (`as`, with `-mbig-obj`), the MinGW runtime,
and the Windows import libraries, including `librstrtmgr.a`, which DuckDB needs. The
full `mingw-w64-x86_64-toolchain` group also works but is larger.

> **Mirror timeouts?** If a download stalls (`error: ... Operation too slow ...`), just
> re-run the `pacman -S` command; it resumes from the package cache.

## 3. Add MinGW to PATH

Add `C:\msys64\mingw64\bin` to your PATH **before** any older MinGW (e.g. a legacy
`C:\MinGW`), so the correct compiler wins:

- **GUI:** System Properties → Environment Variables → edit `Path` → add
  `C:\msys64\mingw64\bin` and move it to the top.
- **PowerShell (user PATH):**
  ```powershell
  [Environment]::SetEnvironmentVariable('Path',
    'C:\msys64\mingw64\bin;' + [Environment]::GetEnvironmentVariable('Path','User'), 'User')
  ```

**Restart your terminal**, then verify you get a recent MSYS2 build (e.g. 16.x), not an
old MinGW.org 6.x:

```sh
gcc --version
```

## 4. Build & test

```sh
cargo build --release
cargo test --workspace
```

- The **first build takes ~15–20 min**: DuckDB's C++ amalgamation compiles from source.
  Subsequent builds are incremental and fast.
- Smoke-test the binary:
  ```sh
  ./target/release/ovecc.exe --help
  ```

The binary is `ovecc` (from `crates/ovecc-cli`).

> **Next:** to expose Ovecc to a coding agent over MCP, see [MCP.md](./MCP.md).

---

## Notes & troubleshooting

- **`ring` build script fails ("Compiler family detection failed") from a Git-Bash/MSYS
  shell?** The `ring` crate (pulled in by the HTTPS client behind `audit --fetch`) probes
  the C compiler in a way that breaks under some MSYS/Git-Bash environments even when
  `gcc` itself works there. Build from **PowerShell or cmd** instead: the same
  `cargo build --release` succeeds. Also note that piping cargo output (e.g.
  `cargo build 2>&1 | tail`) can mask the real exit code in some shells; check
  `$LASTEXITCODE` (PowerShell) explicitly.
- **Link error `ld: cannot find -lssp` / `-lwinpthread` / `-lrstrtmgr`?** An older MinGW on
  your PATH (typically a legacy `C:\MinGW` from MinGW.org) is shadowing the MSYS2 toolchain.
  The libraries *are* installed; confirm with
  `x86_64-w64-mingw32-gcc -print-file-name=librstrtmgr.a`, which should print a path under
  `C:\msys64\mingw64\lib`. Fix: ensure `C:\msys64\mingw64\bin` is first on PATH **and remove
  the old MinGW entry**, then open a fresh terminal. (This commonly surfaces on `cargo test`,
  since that links extra test executables that a plain `cargo build` does not.)
- **Don't edit the `C(XX)FLAGS` in `.cargo/config.toml`** unless necessary: changing them
  invalidates the `libduckdb-sys` cache and forces a full ~10-min C++ rebuild.
- The GNU-specific settings in `.cargo/config.toml` (scoped to `x86_64-pc-windows-gnu`)
  handle DuckDB's oversized objects (`-Wa,-mbig-obj`) and statically link
  `libstdc++`/`libgcc`/`winpthread` plus the Restart Manager (`-lrstrtmgr`). They do not
  affect other targets.
- The resulting `ovecc.exe` is statically linked, so it runs on machines without MSYS2.

## Alternative: MSVC (not the supported path)

The workspace is wired for GNU. To build with MSVC you must:

1. Widen the Restart Manager link in `crates/ovecc-db/build.rs` from
   `target_env == "gnu"` to `target_os == "windows"` (`libduckdb-sys` does not emit the
   import library for MSVC).
2. Use the **VS 2022 (MSVC 14.41)** toolset, **not** VS 2026 / 14.51, which removed
   `stdext::checked_array_iterator`, a symbol DuckDB's bundled `fmt` still uses. Build
   from the *"x64 Native Tools Command Prompt for VS 2022"*.
