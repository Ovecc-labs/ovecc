//! What a change touches, measured against the indexed repository.
//!
//! Six measurements and no score. Each one is a count or a ratio over facts the
//! index already holds, so a reader can check any of them by hand; folding them
//! into a single number is a separate decision, and inventing the weights here
//! would produce something that looks calibrated without ever having been.
//!
//! Nothing is compared to a threshold either. "Touches a hotspot" reuses the
//! ranking `hotspots` already publishes, and the fix mass is reported as the
//! share of the repository's own total, so a quiet repository and a busy one
//! are each read against themselves.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChangeShape {
    pub files: usize,
    /// Head-side lines the change touches. A pure deletion touches none.
    pub lines: u32,
    /// Contract components the change reaches, 0 when no contract is declared.
    pub components: usize,
    /// How evenly the touched lines spread over the touched files: the Shannon
    /// entropy of the per-file share, divided by `ln(files)` so that a two-file
    /// change and a twenty-file one compare. 0 when one file carries
    /// everything, 1 when every file carries the same share.
    ///
    /// `None` under two files, where the division has no denominator, and for a
    /// change that touches no head line at all.
    pub spread: Option<f64>,
    /// Touched modules the hotspot ranking lists, in the order it ranked them.
    pub hotspots: Vec<String>,
    /// Age-weighted fix mass carried by the touched files, and its share of the
    /// repository's total. Landing where the corrections landed is not by
    /// itself a defect, but it is not the same change as one landing on code
    /// nobody has had to fix.
    pub fix_mass: f64,
    pub fix_mass_share: f64,
    /// Mean days since the touched files were last changed. `None` when the
    /// history knows none of them: a new file has no age, and reporting 0 would
    /// make the newest possible change out of a change to nothing.
    pub mean_age_days: Option<f64>,
}

/// Measures `ranges` (the head-side line spans of a change, as
/// `ovecc_git::changed_line_ranges` returns them) against the indexed facts.
///
/// `component_of` and `module_of` map a file to what owns it, `hotspots` is the
/// module ranking as published, `fix_mass` is the whole repository's per-file
/// mass, and `age_days` the per-file age. Every one of them may be empty: the
/// corresponding measurement then reports nothing rather than zero.
pub fn change_shape(
    ranges: &BTreeMap<String, Vec<(u32, u32)>>,
    component_of: &BTreeMap<String, String>,
    module_of: &BTreeMap<String, String>,
    hotspots: &[String],
    fix_mass: &[(String, f64)],
    age_days: &BTreeMap<String, f64>,
) -> ChangeShape {
    let per_file: Vec<u32> = ranges.values().map(|spans| touched_lines(spans)).collect();
    let lines: u32 = per_file.iter().sum();

    let components: BTreeSet<&str> = ranges
        .keys()
        .filter_map(|path| component_of.get(path))
        .map(String::as_str)
        .collect();
    let modules: BTreeSet<&str> = ranges
        .keys()
        .filter_map(|path| module_of.get(path))
        .map(String::as_str)
        .collect();

    let touched_mass: f64 = fix_mass
        .iter()
        .filter(|(path, _)| ranges.contains_key(path))
        .map(|(_, mass)| mass)
        .fold(0.0, |total, mass| total + mass);
    let total_mass: f64 = fix_mass
        .iter()
        .map(|(_, mass)| mass)
        .fold(0.0, |total, mass| total + mass);

    let ages: Vec<f64> = ranges
        .keys()
        .filter_map(|path| age_days.get(path))
        .copied()
        .collect();

    ChangeShape {
        files: ranges.len(),
        lines,
        components: components.len(),
        spread: spread(&per_file, lines),
        hotspots: hotspots
            .iter()
            .filter(|module| modules.contains(module.as_str()))
            .cloned()
            .collect(),
        fix_mass: touched_mass,
        fix_mass_share: if total_mass > 0.0 {
            touched_mass / total_mass
        } else {
            0.0
        },
        mean_age_days: (!ages.is_empty())
            .then(|| ages.iter().fold(0.0, |total, age| total + age) / ages.len() as f64),
    }
}

/// Head-side lines an inclusive 1-based span list covers. Spans come from a
/// diff, so they never overlap and the sum needs no deduplication.
fn touched_lines(spans: &[(u32, u32)]) -> u32 {
    spans
        .iter()
        .map(|(start, end)| end.saturating_sub(*start) + 1)
        .sum()
}

fn spread(per_file: &[u32], lines: u32) -> Option<f64> {
    if per_file.len() < 2 || lines == 0 {
        return None;
    }
    let entropy = per_file
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let share = *count as f64 / lines as f64;
            -share * share.ln()
        })
        .fold(0.0, |total, term| total + term);
    Some(entropy / (per_file.len() as f64).ln())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(entries: &[(&str, &[(u32, u32)])]) -> BTreeMap<String, Vec<(u32, u32)>> {
        entries
            .iter()
            .map(|(path, spans)| (path.to_string(), spans.to_vec()))
            .collect()
    }

    fn owners(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, owner)| (path.to_string(), owner.to_string()))
            .collect()
    }

    #[test]
    fn a_change_is_measured_against_what_the_index_knows() {
        let shape = change_shape(
            &ranges(&[
                ("src/api/routes.ts", &[(1, 10), (40, 49)]),
                ("src/core/logic.ts", &[(5, 5)]),
                ("src/new.ts", &[(1, 3)]),
            ]),
            &owners(&[("src/api/routes.ts", "api"), ("src/core/logic.ts", "core")]),
            &owners(&[
                ("src/api/routes.ts", "api"),
                ("src/core/logic.ts", "core"),
                ("src/new.ts", "core"),
            ]),
            &["core".to_string(), "api".to_string()],
            &[
                ("src/api/routes.ts".to_string(), 3.0),
                ("src/untouched.ts".to_string(), 1.0),
            ],
            &[("src/api/routes.ts".to_string(), 10.0)]
                .into_iter()
                .collect(),
        );

        assert_eq!(shape.files, 3);
        assert_eq!(shape.lines, 24, "20 + 1 + 3, spans inclusive");
        assert_eq!(shape.components, 2, "the unassigned file owns nothing");
        assert_eq!(
            shape.hotspots,
            ["core", "api"],
            "reported in the ranking's order, not the change's"
        );
        assert!((shape.fix_mass - 3.0).abs() < 1e-9);
        assert!((shape.fix_mass_share - 0.75).abs() < 1e-9);
        assert_eq!(shape.mean_age_days, Some(10.0), "over the files it knows");
    }

    #[test]
    fn spread_separates_one_deep_edit_from_a_wide_sweep() {
        let concentrated = change_shape(
            &ranges(&[("a.ts", &[(1, 100)]), ("b.ts", &[(1, 1)])]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            &[],
            &BTreeMap::new(),
        );
        let even = change_shape(
            &ranges(&[("a.ts", &[(1, 10)]), ("b.ts", &[(1, 10)])]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            &[],
            &BTreeMap::new(),
        );

        assert_eq!(even.spread, Some(1.0), "an even split is maximal spread");
        assert!(
            concentrated.spread.unwrap() < 0.2,
            "one file carrying almost everything: {:?}",
            concentrated.spread
        );
    }

    #[test]
    fn a_single_file_change_has_no_spread_to_report() {
        let shape = change_shape(
            &ranges(&[("a.ts", &[(1, 10)])]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert_eq!(shape.spread, None, "ln(1) is 0 and would divide by zero");
    }

    #[test]
    fn an_index_that_knows_nothing_reports_nothing_rather_than_zero() {
        let shape = change_shape(
            &ranges(&[("a.ts", &[(1, 4)]), ("b.ts", &[(1, 4)])]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            &[],
            &BTreeMap::new(),
        );

        assert_eq!(shape.files, 2);
        assert_eq!(shape.components, 0);
        assert!(shape.hotspots.is_empty());
        assert_eq!(
            shape.fix_mass_share, 0.0,
            "no mass anywhere to take a share of"
        );
        assert_eq!(shape.mean_age_days, None);
    }
}
