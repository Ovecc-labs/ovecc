//! Path normalization and stable hashing helpers shared by all crates.
//!
//! These implement the deterministic ID strategy: identical inputs
//! must always produce identical identifiers across runs and platforms.

use crate::error::{OveccError, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn simplify_verbatim(path: &Path) -> Option<PathBuf> {
    const MAX_LEGACY_PATH: usize = 260;
    let raw = path.to_string_lossy();
    let rest = raw.strip_prefix(r"\\?\")?;
    if rest.starts_with(r"UNC\") || rest.len() >= MAX_LEGACY_PATH {
        return None;
    }
    Some(PathBuf::from(rest))
}

/// Normalizes a path to forward slashes for stable, platform-independent IDs.
///
/// Strips the Windows verbatim/UNC prefixes that `std::fs::canonicalize`
/// emits (`\\?\C:\...`, `\\?\UNC\server\share\...`) so they never leak into
/// IDs or reports as `//?/C:/...`.
pub fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        // `\\?\UNC\server\share` denotes the network path `\\server\share`.
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    };
    stripped.replace('\\', "/")
}

/// Repository-relative '/'-normalized path, or an error if outside the root.
pub fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| OveccError::Repository {
            message: format!("{} is outside {}", path.display(), root.display()),
        })?;
    Ok(normalize_path(relative))
}

/// True for paths under a conventional test directory or with a test-file
/// naming pattern (`.test.`, `.spec.`, `_test.go`, `test_*.py`, …).
pub fn is_test_path(path: &str) -> bool {
    // `testdata/` is the Go convention and the Go toolchain itself skips it;
    // `__fixtures__/` is the JS sibling of `__tests__/` and `__mocks__/`.
    const TEST_DIRS: [&str; 9] = [
        "__tests__/",
        "__mocks__/",
        "__fixtures__/",
        "test-d/",
        "type-tests/",
        "type-test/",
        "tests/",
        "test/",
        "testdata/",
    ];
    if TEST_DIRS
        .iter()
        .any(|dir| path.starts_with(dir) || path.contains(&format!("/{dir}")))
    {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    name.contains(".test.")
        || name.contains(".spec.")
        || name.ends_with(".test-d.ts")
        || name.ends_with("_test.go")
        || name.ends_with("_test.py")
        || name.ends_with("_test.rs")
        || name.starts_with("test_")
}

/// Builds a stable identifier `{prefix}:{hash}` from ordered parts.
/// Parts are NUL-separated before hashing so `["ab","c"]` != `["a","bc"]`.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{prefix}:{}", hex_prefix(hasher.finalize().as_slice(), 24))
}

/// Full-length content hash used for incremental change detection.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_prefix(hasher.finalize().as_slice(), 64)
}

/// Short hex digest of a string, e.g. for repository IDs.
pub fn short_hash(input: &str, chars: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex_prefix(hasher.finalize().as_slice(), chars)
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    bytes
        .iter()
        .flat_map(|byte| [hex_char(byte >> 4), hex_char(byte & 0x0f)])
        .take(chars)
        .collect()
}

/// Maps a 4-bit nibble to its lowercase hex digit. Masks to the low nibble so
/// the function is total (callers already pass `byte >> 4` / `byte & 0x0f`).
fn hex_char(nibble: u8) -> char {
    b"0123456789abcdef"[(nibble & 0x0f) as usize] as char
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn simplify_verbatim_keeps_only_safe_drive_paths() {
        assert_eq!(
            simplify_verbatim(Path::new(r"\\?\C:\Users\dev\app")),
            Some(PathBuf::from(r"C:\Users\dev\app"))
        );
        assert_eq!(
            simplify_verbatim(Path::new(r"\\?\UNC\server\share")),
            None,
            "network paths need the verbatim form"
        );
        assert_eq!(
            simplify_verbatim(Path::new(r"C:\already\plain")),
            None,
            "non-verbatim paths pass through unchanged"
        );
        let deep = format!(r"\\?\C:\{}", "a\\".repeat(140));
        assert_eq!(
            simplify_verbatim(Path::new(&deep)),
            None,
            "paths past the legacy limit keep the verbatim form"
        );
    }

    #[test]
    fn normalize_strips_windows_verbatim_and_unc_prefixes() {
        // `\\?\C:\...` must never leak into ids/reports as `//?/C:/...`.
        assert_eq!(
            normalize_path(Path::new(r"\\?\C:\Users\dev\app")),
            "C:/Users/dev/app"
        );
        // `\\?\UNC\server\share` denotes the network path `\\server\share`.
        assert_eq!(
            normalize_path(Path::new(r"\\?\UNC\server\share\file.ts")),
            "//server/share/file.ts"
        );
        // A plain path just gets forward slashes.
        assert_eq!(
            normalize_path(Path::new(r"src\billing\service.ts")),
            "src/billing/service.ts"
        );
    }

    #[test]
    fn relative_path_is_root_relative_or_errors_outside() {
        let root = Path::new("/repo");
        assert_eq!(
            relative_path(root, Path::new("/repo/src/a.ts")).unwrap(),
            "src/a.ts"
        );
        assert!(relative_path(root, Path::new("/elsewhere/a.ts")).is_err());
    }

    #[test]
    fn stable_id_is_deterministic_prefixed_and_collision_resistant() {
        let a = stable_id("file", &["repo", "src/a.ts"]);
        assert_eq!(a, stable_id("file", &["repo", "src/a.ts"]));
        assert!(a.starts_with("file:"));
        // NUL-separation: ["ab","c"] must not collide with ["a","bc"].
        assert_ne!(stable_id("x", &["ab", "c"]), stable_id("x", &["a", "bc"]));
    }

    #[test]
    fn hashes_have_expected_widths_and_vary_with_input() {
        assert_eq!(hash_bytes(b"hello").len(), 64);
        assert_ne!(hash_bytes(b"hello"), hash_bytes(b"world"));
        assert_eq!(short_hash("repo-root", 12).len(), 12);
        assert!(hash_bytes(b"x").chars().all(|c| c.is_ascii_hexdigit()));
    }
}
