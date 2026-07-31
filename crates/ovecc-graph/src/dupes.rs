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

    let fps = window_fingerprints(files, k);
    let index = index_windows(&fps);
    let seeds = rank_seeds(&fps, &index);

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
        if members.len() < 2 || (cross_file_only && !spans_two_files(&members)) {
            continue;
        }

        let windows = maximal_run(&members, &fps);
        let token_count = windows - 1 + k;
        let instances = build_instances(&members, windows, k, files, min_lines, &mut consumed);

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

/// Per-file sequence of k-window fingerprints: `fps[file][i]` covers tokens
/// `i..i+k`. Files shorter than `k` contribute no windows.
fn window_fingerprints(files: &[FileTokens], k: usize) -> Vec<Vec<u128>> {
    files
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
        .collect()
}

/// Every window start indexed by its fingerprint.
fn index_windows(fps: &[Vec<u128>]) -> HashMap<u128, Vec<(usize, usize)>> {
    let mut index: HashMap<u128, Vec<(usize, usize)>> = HashMap::new();
    for (file_index, file_fps) in fps.iter().enumerate() {
        for (start, &fingerprint) in file_fps.iter().enumerate() {
            index
                .entry(fingerprint)
                .or_default()
                .push((file_index, start));
        }
    }
    index
}

/// Window starts ordered by how many distinct files share their fingerprint
/// (desc), then (file, start). Forming the most widely-shared families FIRST is
/// what makes the output order-independent: without it, a long run shared by two
/// near-identical copies can consume their overlapping windows before the
/// shorter run that ALSO covers the canonical original is considered, silently
/// dropping the original from the family (its membership then depended on file
/// scan order, so a canonical util sorted after its copies vanished).
fn rank_seeds(
    fps: &[Vec<u128>],
    index: &HashMap<u128, Vec<(usize, usize)>>,
) -> Vec<(usize, usize)> {
    let mut reach: HashMap<u128, usize> = HashMap::with_capacity(index.len());
    for (fingerprint, occurrences) in index {
        let distinct = occurrences
            .iter()
            .map(|(file, _)| *file)
            .collect::<BTreeSet<_>>()
            .len();
        reach.insert(*fingerprint, distinct);
    }
    let mut seeds: Vec<(usize, usize)> = Vec::new();
    for (file_index, file_fps) in fps.iter().enumerate() {
        for start in 0..file_fps.len() {
            seeds.push((file_index, start));
        }
    }
    let reach_of =
        |&(file, start): &(usize, usize)| reach.get(&fps[file][start]).copied().unwrap_or(0);
    seeds.sort_by(|a, b| {
        reach_of(b)
            .cmp(&reach_of(a))
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });
    seeds
}

/// True when the members touch at least two distinct files.
fn spans_two_files(members: &[(usize, usize)]) -> bool {
    members
        .iter()
        .map(|(file, _)| *file)
        .collect::<BTreeSet<_>>()
        .len()
        >= 2
}

/// Grows the shared run in lock-step to its maximal common length, returning the
/// number of windows (>= 1) every member agrees on.
fn maximal_run(members: &[(usize, usize)], fps: &[Vec<u128>]) -> usize {
    let mut windows = 1usize;
    while let Some(expected) = fps[members[0].0].get(members[0].1 + windows).copied() {
        let all_match = members
            .iter()
            .all(|(file, pos)| fps[*file].get(pos + windows).copied() == Some(expected));
        if all_match {
            windows += 1;
        } else {
            break;
        }
    }
    windows
}

/// Marks every covered window start consumed and builds the clone instances,
/// dropping any that span fewer than `min_lines` and any that overlap one
/// already kept. Sorted by path then line.
fn build_instances(
    members: &[(usize, usize)],
    windows: usize,
    k: usize,
    files: &[FileTokens],
    min_lines: usize,
    consumed: &mut [HashSet<usize>],
) -> Vec<CloneInstance> {
    let token_count = windows - 1 + k;
    let mut instances: Vec<CloneInstance> = Vec::new();
    for (file, pos) in members {
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
    instances.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.start_line.cmp(&b.start_line))
    });
    // A periodic run (a block of near-identical lines, once identifiers are
    // normalized) gives consecutive window starts the same fingerprint, so one
    // region would be reported as several copies of itself. Duplication means
    // disjoint regions: keep the first of any overlapping run, and let the
    // caller's two-instance minimum drop what collapses to a single region.
    instances.dedup_by(|later, kept| later.path == kept.path && later.start_line <= kept.end_line);
    instances
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
        assert!(detect(std::slice::from_ref(&a), 5, 1, true).is_empty());
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

    /// A block of near-identical lines (`row.get(0)?, row.get(1)?, ...` once
    /// identifiers normalize away) gives consecutive window starts the same
    /// fingerprint. One region is not several copies of itself.
    #[test]
    fn instances_of_a_family_do_not_overlap() {
        let run: Vec<(u64, u32)> = (0..40)
            .map(|i| (1 + i as u64 % 2, i as u32 / 2 + 1))
            .collect();
        let families = detect(&[file("a.ts", &run)], 8, 1, false);
        assert!(!families.is_empty(), "the repeated pair is still a family");
        for family in &families {
            for pair in family.instances.windows(2) {
                assert!(
                    pair[0].path != pair[1].path || pair[0].end_line < pair[1].start_line,
                    "overlapping instances: {:?} and {:?}",
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    #[test]
    fn deterministic_across_runs() {
        let run: Vec<(u64, u32)> = (0..12).map(|i| (i as u64 + 1, i as u32 + 1)).collect();
        let files = vec![file("a.ts", &run), file("b.ts", &run)];
        assert_eq!(detect(&files, 5, 1, true), detect(&files, 5, 1, true));
    }
}
