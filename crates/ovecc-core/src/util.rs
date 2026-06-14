//! Path normalization and stable hashing helpers shared by all crates.
//!
//! These implement the deterministic ID strategy: identical inputs
//! must always produce identical identifiers across runs and platforms.

use crate::error::{OveccError, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Normalizes a path to forward slashes for stable, platform-independent IDs.
pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
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

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => unreachable!(),
    }
}
