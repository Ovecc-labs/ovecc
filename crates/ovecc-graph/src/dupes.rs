// SPDX-License-Identifier: MIT
//! Code-duplication (clone-family) detection.
//!
//! Parser-agnostic clone detection over a normalized token stream, in the spirit
//! of fallow's `core/src/duplicates/` engine: each file is reduced to a sequence
//! of token hashes (identifiers and literals normalized away upstream), and
//! repeated `k`-token windows are grouped into **clone families** — sets of
//! regions across the codebase that share the same token sequence.
//!
//! fallow uses a linear-time SA-IS suffix array + LCP scan; this port uses the
//! exact-fingerprint `k`-gram grouping fallow also ships as its rolling
//! detector, which is collision-free (128-bit window fingerprints) and keeps the
//! engine dependency-free and easy to verify. The family/region/stat shapes
//! mirror fallow's. See THIRD-PARTY-NOTICES.md.

use std::collections::{BTreeSet, HashMap, HashSet};

/// One file's normalized token stream: `token_hashes[i]` is the i-th token's
/// normalized hash, on 1-based source line `token_lines[i]`.
#[derive(Debug, Clone)]
pub struct FileTokens {
    pub path: String,
    pub token_hashes: Vec<u64>,
    pub token_lines: Vec<u32>,
}

/// One occurrence of a duplicated region.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CloneInstance {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub token_count: usize,
}

/// A group of duplicated regions sharing the same token sequence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CloneFamily {
    /// Length, in tokens, of the shared sequence.
    pub token_length: usize,
    /// Number of duplicated lines (max region line-span), for ranking.
    pub line_span: u32,
    pub instances: Vec<CloneInstance>,
}

/// Detects clone families across `files`.
///
/// - `min_tokens`: window size; the minimum shared token run to consider.
/// - `min_lines`: a region must span at least this many lines to be reported.
/// - `cross_file_only`: when true, families confined to one file are dropped.
///
/// Output is deterministic: families are sorted by token length (desc), then
/// line span (desc), then first instance path/line; instances within a family
/// are sorted by path then line.
pub fn detect(
    files: &[FileTokens],
    min_tokens: usize,
    min_lines: usize,
    cross_file_only: bool,
) -> Vec<CloneFamily> {
    let k = min_tokens;
    if k == 0 {
        return Vec::new();
    }

    // Per-file sequence of k-window fingerprints: `fps[file][i]` covers tokens
    // `i..i+k`.
    let fps: Vec<Vec<u128>> = files
        .iter()
        .map(|file| {
            let count = file.token_hashes.len();
            if count < k {
                Vec::new()
            } else {
                (0..=count - k)
                    .map(|i| window_fingerprint(&file.token_hashes[i..i + k]))
                    .collect()
            }
        })
        .collect();

    // Index every window start by its fingerprint.
    let mut index: HashMap<u128, Vec<(usize, usize)>> = HashMap::new();
    for (file_index, file_fps) in fps.iter().enumerate() {
        for (start, &fingerprint) in file_fps.iter().enumerate() {
            index
                .entry(fingerprint)
                .or_default()
                .push((file_index, start));
        }
    }

    // Distinct-file reach of each fingerprint, so the most widely-shared clone
    // families are formed FIRST. Without this, a long run shared by two
    // near-identical *copies* can consume their overlapping windows before the
    // shorter run that ALSO covers the canonical original is ever considered —
    // silently dropping the original from the family. That made membership depend
    // on file scan order (a canonical util sorted after its copies vanished from
    // the report). Ranking seeds by reach makes the output order-independent.
    let mut fingerprint_reach: HashMap<u128, usize> = HashMap::with_capacity(index.len());
    for (fingerprint, occurrences) in &index {
        let distinct = occurrences
            .iter()
            .map(|(file, _)| *file)
            .collect::<BTreeSet<_>>()
            .len();
        fingerprint_reach.insert(*fingerprint, distinct);
    }

    let mut seeds: Vec<(usize, usize)> = Vec::new();
    for (file_index, file_fps) in fps.iter().enumerate() {
        for start in 0..file_fps.len() {
            seeds.push((file_index, start));
        }
    }
    seeds.sort_by(|&(file_a, start_a), &(file_b, start_b)| {
        let reach_a = fingerprint_reach
            .get(&fps[file_a][start_a])
            .copied()
            .unwrap_or(0);
        let reach_b = fingerprint_reach
            .get(&fps[file_b][start_b])
            .copied()
            .unwrap_or(0);
        reach_b
            .cmp(&reach_a)
            .then_with(|| file_a.cmp(&file_b))
            .then_with(|| start_a.cmp(&start_b))
    });

    // Window starts already absorbed into an emitted clone, so the overlapping
    // windows of one maximal clone are not re-reported as many families.
    let mut consumed: Vec<HashSet<usize>> = files.iter().map(|_| HashSet::new()).collect();
    let mut families: Vec<CloneFamily> = Vec::new();

    // Ranked scan: widest-reaching fingerprints first, then (file, start).
    for (file_index, start) in seeds {
        if consumed[file_index].contains(&start) {
            continue;
        }
        let fingerprint = fps[file_index][start];
        let Some(group) = index.get(&fingerprint) else {
            continue;
        };
        // Live instances that begin with this exact window.
        let members: Vec<(usize, usize)> = group
            .iter()
            .copied()
            .filter(|(file, pos)| !consumed[*file].contains(pos))
            .collect();
        if members.len() < 2 {
            continue;
        }
        let distinct = members
            .iter()
            .map(|(file, _)| *file)
            .collect::<BTreeSet<_>>();
        if cross_file_only && distinct.len() < 2 {
            continue;
        }

        // Extend in lock-step while every member's next window agrees — this
        // grows the shared run to its maximal common length.
        let mut windows = 1usize;
        loop {
            let Some(expected) = fps[members[0].0].get(members[0].1 + windows).copied() else {
                break;
            };
            let all_match = members
                .iter()
                .all(|(file, pos)| fps[*file].get(pos + windows).copied() == Some(expected));
            if all_match {
                windows += 1;
            } else {
                break;
            }
        }
        let token_count = windows - 1 + k;

        // Mark every covered window start consumed, then build instances.
        let mut instances: Vec<CloneInstance> = Vec::new();
        for (file, pos) in &members {
            for offset in 0..windows {
                consumed[*file].insert(pos + offset);
            }
            let lines = &files[*file].token_lines;
            let start_line = lines[*pos];
            let end_line = lines[(pos + token_count - 1).min(lines.len() - 1)];
            if end_line.saturating_sub(start_line) + 1 < min_lines as u32 {
                continue;
            }
            instances.push(CloneInstance {
                path: files[*file].path.clone(),
                start_line,
                end_line,
                token_count,
            });
        }

        let distinct_files = instances
            .iter()
            .map(|instance| instance.path.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        if instances.len() < 2 || (cross_file_only && distinct_files < 2) {
            continue;
        }
        let line_span = instances
            .iter()
            .map(|instance| instance.end_line.saturating_sub(instance.start_line) + 1)
            .max()
            .unwrap_or(0);
        instances.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.start_line.cmp(&b.start_line))
        });
        families.push(CloneFamily {
            token_length: token_count,
            line_span,
            instances,
        });
    }

    families.sort_by(|a, b| {
        b.token_length
            .cmp(&a.token_length)
            .then_with(|| b.line_span.cmp(&a.line_span))
            .then_with(|| {
                let a0 = a.instances.first();
                let b0 = b.instances.first();
                a0.map(|i| (&i.path, i.start_line))
                    .cmp(&b0.map(|i| (&i.path, i.start_line)))
            })
    });
    families
}

/// Collision-free 128-bit fingerprint of a token window (two independent FNV-1a
/// hashes), so distinct sequences never share a family.
fn window_fingerprint(window: &[u64]) -> u128 {
    let mut hi: u64 = 0xcbf2_9ce4_8422_2325;
    let mut lo: u64 = 0x9e37_79b9_7f4a_7c15;
    for &token in window {
        hi = (hi ^ token).wrapping_mul(0x0000_0100_0000_01b3);
        lo = (lo ^ token.rotate_left(23)).wrapping_mul(0xff51_afd7_ed55_8ccd);
    }
    ((hi as u128) << 64) | lo as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, tokens: &[(u64, u32)]) -> FileTokens {
        FileTokens {
            path: path.to_string(),
            token_hashes: tokens.iter().map(|(h, _)| *h).collect(),
            token_lines: tokens.iter().map(|(_, l)| *l).collect(),
        }
    }

    /// A token run repeated across two files is one cross-file family.
    #[test]
    fn finds_cross_file_clone() {
        let run: Vec<(u64, u32)> = (0..10).map(|i| (i as u64 + 1, i as u32 + 1)).collect();
        let a = file("a.ts", &run);
        let b = file("b.ts", &run);
        let families = detect(&[a, b], 5, 1, true);
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].instances.len(), 2);
        assert!(families[0].instances.iter().any(|i| i.path == "a.ts"));
        assert!(families[0].instances.iter().any(|i| i.path == "b.ts"));
    }

    #[test]
    fn unique_code_has_no_clones() {
        let a = file("a.ts", &[(1, 1), (2, 1), (3, 2), (4, 2)]);
        let b = file("b.ts", &[(9, 1), (8, 1), (7, 2), (6, 2)]);
        assert!(detect(&[a, b], 3, 1, true).is_empty());
    }

    #[test]
    fn cross_file_only_drops_intra_file_repeats() {
        // The same 5-token run twice in one file.
        let mut tokens: Vec<(u64, u32)> = (0..5).map(|i| (i as u64 + 1, i as u32 + 1)).collect();
        tokens.extend((0..5).map(|i| (i as u64 + 1, i as u32 + 10)));
        let a = file("a.ts", &tokens);
        assert!(detect(&[a.clone()], 5, 1, true).is_empty());
        // ... but it IS a family when intra-file clones are allowed.
        assert_eq!(detect(&[a], 5, 1, false).len(), 1);
    }

    #[test]
    fn respects_min_lines() {
        // A 6-token clone all on one line cannot meet a 3-line minimum.
        let run: Vec<(u64, u32)> = (0..6).map(|i| (i as u64 + 1, 1)).collect();
        let a = file("a.ts", &run);
        let b = file("b.ts", &run);
        assert!(detect(&[a, b], 4, 3, true).is_empty());
    }

    #[test]
    fn deterministic_across_runs() {
        let run: Vec<(u64, u32)> = (0..12).map(|i| (i as u64 + 1, i as u32 + 1)).collect();
        let files = vec![file("a.ts", &run), file("b.ts", &run)];
        assert_eq!(detect(&files, 5, 1, true), detect(&files, 5, 1, true));
    }
}
