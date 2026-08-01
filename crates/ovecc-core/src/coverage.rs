//! LCOV tracefile parsing.
//!
//! Only the records that carry line and function totals are read: `SF`, `DA`,
//! `LF`, `LH`, `FN`, `FNDA`, `FNF`, `FNH`, terminated by `end_of_record`.
//! Anything else — branch data, checksums, test names — is skipped, so a
//! tracefile from a tool that emits more than `geninfo(1)` describes still
//! parses. Written here rather than taken as a dependency: the grammar is a
//! dozen prefixes, and a crate for that is a supply-chain entry for nothing.

use crate::util::normalize_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// One source file's coverage, as a tracefile reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCoverage {
    /// Repository-relative, forward slashes.
    pub path: String,
    pub lines_found: usize,
    pub lines_hit: usize,
    pub functions_found: usize,
    pub functions_hit: usize,
}

impl FileCoverage {
    /// Share of executable lines executed at least once, in `[0, 1]`. A file
    /// with no executable line is fully covered: there was nothing to miss.
    pub fn line_rate(&self) -> f64 {
        if self.lines_found == 0 {
            return 1.0;
        }
        self.lines_hit as f64 / self.lines_found as f64
    }
}

/// What one `SF ... end_of_record` section accumulates before it is collapsed.
#[derive(Default)]
struct Section {
    /// Hits per line, merged with `max` so a tracefile concatenating several
    /// runs of the same suite reports the line as covered if any run reached it.
    lines: BTreeMap<u32, u64>,
    functions: BTreeMap<String, u64>,
    /// `LF`/`LH`/`FNF`/`FNH` totals, used only when the detailed records are
    /// absent: some tools emit the summary alone.
    declared_lines: Option<(usize, usize)>,
    declared_functions: Option<(usize, usize)>,
}

impl Section {
    fn merge(&mut self, other: Section) {
        for (line, hits) in other.lines {
            let entry = self.lines.entry(line).or_default();
            *entry = (*entry).max(hits);
        }
        for (name, hits) in other.functions {
            let entry = self.functions.entry(name).or_default();
            *entry = (*entry).max(hits);
        }
        self.declared_lines = self.declared_lines.or(other.declared_lines);
        self.declared_functions = self.declared_functions.or(other.declared_functions);
    }

    fn totals(&self) -> (usize, usize, usize, usize) {
        let (lines_found, lines_hit) = match self.declared_lines {
            Some(declared) if self.lines.is_empty() => declared,
            _ => (
                self.lines.len(),
                self.lines.values().filter(|hits| **hits > 0).count(),
            ),
        };
        let (functions_found, functions_hit) = match self.declared_functions {
            Some(declared) if self.functions.is_empty() => declared,
            _ => (
                self.functions.len(),
                self.functions.values().filter(|hits| **hits > 0).count(),
            ),
        };
        (lines_found, lines_hit, functions_found, functions_hit)
    }
}

/// Repository-relative form of a tracefile's `SF` path, or `None` when it names
/// a file outside the repository. Tracefiles carry absolute paths as often as
/// relative ones, and Windows tools mix separators within one file.
fn relative_to_root(raw: &str, root: &Path) -> Option<String> {
    let normalized = normalize_path(Path::new(raw.trim()));
    let root = normalize_path(root);
    let relative = match normalized.strip_prefix(&root) {
        Some(rest) => rest.trim_start_matches('/'),
        // A rooted path that does not start at the root belongs to another
        // checkout and cannot be matched to an indexed file. `has_root` rather
        // than `is_absolute`: on Windows a leading `/` is rooted but not
        // absolute, and a tracefile written on CI carries exactly that form.
        None if Path::new(&normalized).has_root() => return None,
        None => normalized.as_str(),
    };
    let relative = relative.trim_start_matches("./");
    (!relative.is_empty()).then(|| relative.to_string())
}

/// Parses an LCOV tracefile into one entry per source file, sorted by path.
///
/// Sections for the same file are merged rather than the last one winning: a
/// tracefile assembled from several suites lists a shared file once per suite.
pub fn parse_lcov(content: &str, root: &Path) -> Vec<FileCoverage> {
    let mut files: BTreeMap<String, Section> = BTreeMap::new();
    let mut current: Option<(String, Section)> = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "end_of_record" {
            if let Some((path, section)) = current.take() {
                files.entry(path).or_default().merge(section);
            }
            continue;
        }
        let Some((tag, value)) = line.split_once(':') else {
            continue;
        };
        if tag == "SF" {
            // A missing `end_of_record` before the next `SF` is malformed but
            // recoverable: close the open section rather than drop it.
            if let Some((path, section)) = current.take() {
                files.entry(path).or_default().merge(section);
            }
            current = relative_to_root(value, root).map(|path| (path, Section::default()));
            continue;
        }
        let Some((_, section)) = current.as_mut() else {
            continue;
        };
        match tag {
            // `DA:<line>,<hits>` with an optional checksum third field.
            "DA" => {
                let mut fields = value.split(',');
                if let (Some(Ok(line)), Some(Ok(hits))) = (
                    fields.next().map(str::parse::<u32>),
                    fields.next().map(parse_hits),
                ) {
                    let entry = section.lines.entry(line).or_default();
                    *entry = (*entry).max(hits);
                }
            }
            // `FN:<line>,<name>`: declares the function, hit count comes later.
            "FN" => {
                if let Some((_, name)) = value.split_once(',') {
                    section.functions.entry(name.to_string()).or_default();
                }
            }
            "FNDA" => {
                if let Some((Ok(hits), name)) = value
                    .split_once(',')
                    .map(|(hits, name)| (parse_hits(hits), name))
                {
                    let entry = section.functions.entry(name.to_string()).or_default();
                    *entry = (*entry).max(hits);
                }
            }
            "LF" | "LH" | "FNF" | "FNH" => {
                let Ok(count) = value.trim().parse::<usize>() else {
                    continue;
                };
                let slot = match tag {
                    "LF" | "LH" => &mut section.declared_lines,
                    _ => &mut section.declared_functions,
                };
                let (found, hit) = slot.unwrap_or((0, 0));
                *slot = Some(match tag {
                    "LF" | "FNF" => (count, hit),
                    _ => (found, count),
                });
            }
            _ => {}
        }
    }
    if let Some((path, section)) = current.take() {
        files.entry(path).or_default().merge(section);
    }

    files
        .into_iter()
        .map(|(path, section)| {
            let (lines_found, lines_hit, functions_found, functions_hit) = section.totals();
            FileCoverage {
                path,
                lines_found,
                lines_hit,
                functions_found,
                functions_hit,
            }
        })
        .collect()
}

/// Hit counts are integers, but some tools emit them as `1.0`. Take the integer
/// part rather than dropping the line.
fn parse_hits(raw: &str) -> Result<u64, std::num::ParseIntError> {
    let raw = raw.trim();
    raw.split_once('.').map_or(raw, |(whole, _)| whole).parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = if cfg!(windows) { r"C:\repo" } else { "/repo" };

    #[test]
    fn counts_lines_and_functions_from_the_detailed_records() {
        let tracefile = "\
SF:src/a.ts
FN:3,render
FNDA:2,render
FN:9,unused
FNDA:0,unused
DA:3,2
DA:4,2
DA:9,0
LF:3
LH:2
end_of_record
";
        let files = parse_lcov(tracefile, Path::new(ROOT));

        assert_eq!(files.len(), 1);
        let a = &files[0];
        assert_eq!(a.path, "src/a.ts");
        assert_eq!((a.lines_found, a.lines_hit), (3, 2));
        assert_eq!((a.functions_found, a.functions_hit), (2, 1));
        assert!((a.line_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn a_summary_only_tracefile_still_reports_totals() {
        // Some tools emit LF/LH without the per-line DA records.
        let files = parse_lcov("SF:src/b.ts\nLF:10\nLH:7\nend_of_record\n", Path::new(ROOT));

        assert_eq!((files[0].lines_found, files[0].lines_hit), (10, 7));
    }

    #[test]
    fn sections_for_one_file_merge_on_the_best_run() {
        let tracefile = "\
SF:src/a.ts
DA:1,0
DA:2,1
end_of_record
SF:src/a.ts
DA:1,3
DA:2,0
end_of_record
";
        let files = parse_lcov(tracefile, Path::new(ROOT));

        assert_eq!(files.len(), 1, "one entry per file, not per section");
        assert_eq!((files[0].lines_found, files[0].lines_hit), (2, 2));
    }

    #[test]
    fn absolute_paths_land_under_the_repository_root() {
        let inside = format!("SF:{ROOT}/src/a.ts\nDA:1,1\nend_of_record\n");
        assert_eq!(parse_lcov(&inside, Path::new(ROOT))[0].path, "src/a.ts");

        // Another checkout's tracefile cannot be matched to an indexed file.
        let outside = "SF:/elsewhere/src/a.ts\nDA:1,1\nend_of_record\n";
        assert!(parse_lcov(outside, Path::new(ROOT)).is_empty());
    }

    #[test]
    fn unknown_records_and_a_missing_terminator_do_not_lose_the_file() {
        let tracefile = "\
TN:suite one
SF:./src/a.ts
BRDA:4,0,0,1
DA:4,1
";
        let files = parse_lcov(tracefile, Path::new(ROOT));

        assert_eq!(files[0].path, "src/a.ts");
        assert_eq!(files[0].lines_hit, 1);
    }

    #[test]
    fn a_file_with_nothing_executable_is_not_a_coverage_hole() {
        let files = parse_lcov(
            "SF:src/types.ts\nLF:0\nLH:0\nend_of_record\n",
            Path::new(ROOT),
        );

        assert_eq!(files[0].line_rate(), 1.0);
    }
}
