use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProjectPaths {
    pub root: PathBuf,
    pub ovecc_dir: PathBuf,
    pub db_path: PathBuf,
    pub snapshots_dir: PathBuf,
    pub metrics_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl ProjectPaths {
    pub fn resolve(root: impl AsRef<Path>) -> Result<Self> {
        let root = std::fs::canonicalize(root.as_ref()).with_context(|| {
            format!(
                "failed to resolve repository root {}",
                root.as_ref().display()
            )
        })?;
        let ovecc_dir = root.join(".ovecc");
        Ok(Self {
            root,
            db_path: ovecc_dir.join("graph.db"),
            snapshots_dir: ovecc_dir.join("snapshots"),
            metrics_dir: ovecc_dir.join("metrics"),
            exports_dir: ovecc_dir.join("exports"),
            cache_dir: ovecc_dir.join("cache"),
            ovecc_dir,
        })
    }

    pub fn ensure_runtime_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.ovecc_dir)?;
        std::fs::create_dir_all(&self.snapshots_dir)?;
        std::fs::create_dir_all(&self.metrics_dir)?;
        std::fs::create_dir_all(&self.exports_dir)?;
        std::fs::create_dir_all(self.cache_dir.join("parse"))?;
        std::fs::create_dir_all(self.cache_dir.join("git"))?;
        Ok(())
    }

    pub fn repository_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(normalize_path(&self.root).as_bytes());
        format!("repo:{}", hex_prefix(hasher.finalize().as_slice(), 16))
    }

    pub fn root_display(&self) -> String {
        normalize_path(&self.root)
    }
}

pub fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
    Ok(normalize_path(relative))
}

pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{prefix}:{}", hex_prefix(hasher.finalize().as_slice(), 24))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_prefix(hasher.finalize().as_slice(), 64)
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
