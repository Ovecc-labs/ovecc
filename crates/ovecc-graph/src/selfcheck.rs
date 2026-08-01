//! Checks ovecc's own findings against the repository's fix history.
//!
//! For each rule: does the code it flags get corrected more often than the rest
//! of the repository? The answer is a lift over the repository's own base rate,
//! so a repository that is quiet everywhere and one that is on fire everywhere
//! are both judged against themselves.
//!
//! Rates are per kilobyte of source, not per file. Large files collect more
//! findings *and* more corrections, so a per-file rate would credit every rule
//! that happens to fire on large files. Bytes rather than lines because bytes
//! are what the index stores; the lift is a ratio, so the unit cancels.

use ovecc_core::facts::FindingRecord;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One rule measured against the history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSelfCheck {
    pub rule: String,
    pub files_flagged: usize,
    pub bytes_flagged: u64,
    /// Age-weighted fix mass carried by the flagged files.
    pub fix_mass: f64,
    /// `fix_mass` per KB of flagged source.
    pub rate: f64,
    /// `rate` over the repository's base rate. Above 1, the rule points at code
    /// the maintainers keep coming back to fix.
    pub lift: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckReport {
    /// Half-life the fix mass was weighted with, in days.
    pub half_life_days: f64,
    pub files_evaluated: usize,
    pub bytes_evaluated: u64,
    /// Fix mass carried by indexed files: the numerator of [`Self::base_rate`].
    pub fix_mass: f64,
    /// Fix mass that landed on paths the index does not hold — deleted files,
    /// documentation, anything outside the indexed languages. Excluded from
    /// every rate above, and reported because excluding it silently is how a
    /// self-check flatters itself: the files a team deletes are often the ones
    /// it fixed the most.
    pub fix_mass_off_index: f64,
    /// Fix mass per KB across every indexed file. What a rule has to beat.
    pub base_rate: f64,
    /// One entry per rule that flagged at least one indexed file, strongest
    /// lift first.
    pub rules: Vec<RuleSelfCheck>,
}

/// Mass per kilobyte, or 0 for an empty group.
fn rate(mass: f64, bytes: u64) -> f64 {
    if bytes == 0 {
        return 0.0;
    }
    mass / (bytes as f64 / 1024.0)
}

/// Measures every rule in `findings` against the fix history in `fix_mass`.
///
/// `files` and `fix_mass` are both `(path, value)` under the paths the index
/// holds; a fix on a path outside `files` is counted in
/// [`SelfCheckReport::fix_mass_off_index`] and nowhere else.
pub fn self_check(
    files: &[(String, u64)],
    fix_mass: &[(String, f64)],
    findings: &[FindingRecord],
    half_life_days: f64,
) -> SelfCheckReport {
    let sizes: BTreeMap<&str, u64> = files
        .iter()
        .map(|(path, bytes)| (path.as_str(), *bytes))
        .collect();
    let bytes_evaluated = sizes.values().sum();

    let mut mass_by_file: BTreeMap<&str, f64> = BTreeMap::new();
    let mut mass_indexed = 0.0;
    let mut mass_off_index = 0.0;
    for (path, mass) in fix_mass {
        match sizes.get_key_value(path.as_str()) {
            Some((indexed, _)) => {
                mass_indexed += mass;
                *mass_by_file.entry(indexed).or_default() += mass;
            }
            None => mass_off_index += mass,
        }
    }
    let base_rate = rate(mass_indexed, bytes_evaluated);

    let mut flagged: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for finding in findings {
        // Kind-only findings still name a rule for SARIF; use the same fallback
        // so a rule never splits across two labels.
        let rule = finding
            .rule_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", finding.kind));
        for evidence in &finding.evidence {
            if let Some((path, _)) = sizes.get_key_value(evidence.file_path.as_str()) {
                flagged.entry(rule.clone()).or_default().insert(path);
            }
        }
    }

    let mut rules: Vec<RuleSelfCheck> = flagged
        .into_iter()
        .map(|(rule, paths)| {
            let bytes_flagged = paths.iter().filter_map(|path| sizes.get(path)).sum();
            // Folded from +0.0 rather than summed: `f64::sum` starts from -0.0,
            // so a rule whose files carry no correction would report "-0.00".
            let mass = paths
                .iter()
                .filter_map(|path| mass_by_file.get(path))
                .fold(0.0, |total, mass| total + mass);
            let flagged_rate = rate(mass, bytes_flagged);
            RuleSelfCheck {
                rule,
                files_flagged: paths.len(),
                bytes_flagged,
                fix_mass: mass,
                rate: flagged_rate,
                lift: if base_rate > 0.0 {
                    flagged_rate / base_rate
                } else {
                    0.0
                },
            }
        })
        .collect();
    rules.sort_by(|a, b| {
        b.lift
            .partial_cmp(&a.lift)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.rule.cmp(&b.rule))
    });

    SelfCheckReport {
        half_life_days,
        files_evaluated: sizes.len(),
        bytes_evaluated,
        fix_mass: mass_indexed,
        fix_mass_off_index: mass_off_index,
        base_rate,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::facts::{Evidence, FindingKind, Severity};
    use ovecc_core::id::{FindingId, RepositoryId};

    fn finding(rule: &str, file: &str) -> FindingRecord {
        FindingRecord {
            id: FindingId::from_raw("finding:1"),
            repository_id: RepositoryId::from_raw("repo:1"),
            snapshot_id: None,
            kind: FindingKind::HighComplexity,
            severity: Severity::Medium,
            rule_name: Some(rule.to_string()),
            target: None,
            title: "t".to_string(),
            description: "d".to_string(),
            evidence: vec![Evidence {
                file_path: file.to_string(),
                line: Some(1),
                symbol: None,
                detail: None,
            }],
            created_at: Default::default(),
        }
    }

    fn files() -> Vec<(String, u64)> {
        vec![
            ("hot.ts".to_string(), 1024),
            ("calm.ts".to_string(), 1024),
            ("quiet.ts".to_string(), 2048),
        ]
    }

    #[test]
    fn a_rule_on_the_repeatedly_fixed_file_lifts_above_the_base() {
        // 4 KB of source carrying 4.0 of fix mass: a base rate of 1.0/KB.
        let fixes = vec![("hot.ts".to_string(), 4.0)];
        let report = self_check(&files(), &fixes, &[finding("complexity", "hot.ts")], 180.0);

        assert_eq!(report.files_evaluated, 3);
        assert_eq!(report.bytes_evaluated, 4096);
        assert!((report.base_rate - 1.0).abs() < 1e-9, "{report:?}");

        let complexity = &report.rules[0];
        assert_eq!(complexity.files_flagged, 1);
        // All 4.0 on the flagged 1 KB: 4 times the repository's own rate.
        assert!((complexity.lift - 4.0).abs() < 1e-9, "{complexity:?}");
    }

    #[test]
    fn a_rule_on_untouched_code_lifts_below_one() {
        let fixes = vec![("hot.ts".to_string(), 4.0)];
        let report = self_check(&files(), &fixes, &[finding("dead-code", "quiet.ts")], 180.0);

        assert_eq!(report.rules[0].fix_mass, 0.0);
        assert_eq!(report.rules[0].lift, 0.0);
        // -0.0 compares equal to 0.0 but serializes as "-0.0" and prints as
        // "-0.00", which reads as a broken number rather than an empty one.
        assert!(report.rules[0].fix_mass.is_sign_positive());
        assert!(report.rules[0].rate.is_sign_positive());
    }

    #[test]
    fn fixes_on_paths_the_index_lost_stay_out_of_the_rates() {
        let fixes = vec![
            ("hot.ts".to_string(), 4.0),
            ("deleted.ts".to_string(), 9.0),
            ("README.md".to_string(), 3.0),
        ];
        let report = self_check(&files(), &fixes, &[finding("complexity", "hot.ts")], 180.0);

        assert_eq!(report.fix_mass, 4.0);
        assert_eq!(report.fix_mass_off_index, 12.0);
        // The base rate would drop to 0.25 if the 12.0 were spread over the
        // indexed bytes, and the lift would quadruple on nothing but absence.
        assert!((report.base_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn rules_rank_by_lift_then_name() {
        let fixes = vec![("hot.ts".to_string(), 4.0), ("calm.ts".to_string(), 1.0)];
        let findings = vec![
            finding("zzz-weak", "calm.ts"),
            finding("complexity", "hot.ts"),
            finding("aaa-weak", "calm.ts"),
        ];
        let report = self_check(&files(), &fixes, &findings, 180.0);

        let order: Vec<&str> = report.rules.iter().map(|r| r.rule.as_str()).collect();
        assert_eq!(order, ["complexity", "aaa-weak", "zzz-weak"]);
    }
}
