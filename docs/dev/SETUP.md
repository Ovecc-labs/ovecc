# Setup Guide: Compiling Ovecc on Windows

Ovecc bundles and compiles DuckDB from source (using `duckdb-sys` with the `bundled` feature) on the first build. Because DuckDB is a C++ library, compilation on Windows requires a working C++ compiler toolchain. 

Ovecc officially targets the **Windows GNU toolchain**. Follow the steps below to set up your environment before compiling.

---

## Prerequisites

### 1. Install Rust
If you haven't already, install Rust via [rustup](https://rustup.rs/).
Ensure you have Rust version **1.96** or higher:
```sh
rustup update
```

### 2. Configure the GNU Toolchain
Set your default Rust toolchain to target `x86_64-pc-windows-gnu`:
```sh
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

### 3. Install MinGW-w64 via MSYS2
To compile the C++ source code of DuckDB, you need a C++ compiler (`gcc`/`g++`) and library archiving tools:

1. Download and run the installer from the **[MSYS2 Website](https://www.msys2.org/)**.
2. Open the **MSYS2 UCRT64** or **MSYS2 MinGW 64-bit** terminal from your Start Menu.
3. Update the package database and core system packages by running:
   ```sh
   pacman -Syu
   ```
   *(If prompted, close the terminal and reopen it to complete the update).*
4. Install the compiler toolchain and development build tools:
   ```sh
   pacman -S mingw-w64-x86_64-toolchain base-devel
   ```

### 4. Update Windows Environment PATH
You must add the folder containing the newly installed GCC compiler to your Windows environment `PATH` so Cargo can find it:

1. Press `Win + R`, type `sysdm.cpl`, and press **Enter**.
2. Go to the **Advanced** tab and click **Environment Variables...**.
3. Under **User variables** (or **System variables**), select `Path` and click **Edit...**.
4. Click **New** and add the absolute path to the MSYS2 Mingw64 bin directory:
   * **Default path**: `C:\msys64\mingw64\bin`
5. Click **OK** to save and close all dialogs.
6. **Restart your terminal/IDE** to reload the updated path variables.

---

## Verification and Compilation

Once the PATH is updated, open a fresh terminal (PowerShell or Command Prompt) and run:

1. **Verify Compiler Access**:
   ```sh
   g++ --version
   ```
   *(This should output details about the GCC/MinGW installation).*

2. **Compile the Workspace**:
   ```sh
   cargo build --release
   ```

3. **Run the Workspace Tests**:
   ```sh
   cargo test --workspace
   ```
