//! Convention intelligence.
//!
//! Learns how the repository already behaves and flags contradictions. This
//! is deterministic and evidence-based: a convention is only reported when
//! enough examples agree (confidence ≥ 0.70), and a deviation is the minority
//! that goes against a confident convention — a warning between 0.70 and 0.85,
//! a violation above 0.85.
//!
//! Two convention families are learned from facts already in the graph:
//! - **Dependency direction** between architectural roles inferred from file
//!   names (`controller -> service -> repository`).
//! - **Database access**: which role performs direct DB access.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use ovecc_core::legacy::{Convention, ConventionsReport, Deviation};

/// Don't report a convention below this confidence.
const REPORT_THRESHOLD: f64 = 0.70;
/// At or above this confidence, a deviation is a violation, not a warning.
const VIOLATION_THRESHOLD: f64 = 0.85;
/// Minimum supporting examples before a convention is trustworthy.
const MIN_EXAMPLES: usize = 3;

/// Architectural roles, ordered high→low layer, recognized in a file path.
const ROLES: &[&str] = &[
    "controller",
    "resolver",
    "route",
    "handler",
    "middleware",
    "service",
    "usecase",
    "repository",
    "dao",
    "model",
    "entity",
];

/// Infers a file's architectural role from its path (first keyword wins).
pub fn role_of(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    ROLES.iter().copied().find(|role| lower.contains(role))
}

/// Learns conventions from role-tagged dependencies and DB-accessing files.
pub fn learn_conventions(
    file_dependencies: &[(String, String)],
    db_accessing_files: &[String],
) -> ConventionsReport {
    let mut conventions = Vec::new();
    let mut deviations = Vec::new();

    learn_dependency_direction(file_dependencies, &mut conventions, &mut deviations);
    learn_database_access(db_accessing_files, &mut conventions, &mut deviations);

    conventions.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.description.cmp(&b.description))
    });
    deviations.sort_by(|a, b| {
        a.description
            .cmp(&b.description)
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    ConventionsReport {
        conventions,
        deviations,
    }
}

fn learn_dependency_direction(
    file_dependencies: &[(String, String)],
    conventions: &mut Vec<Convention>,
    deviations: &mut Vec<Deviation>,
) {
    let mut counts: HashMap<(&str, &str), usize> = HashMap::new();
    let mut examples: HashMap<(&str, &str), Vec<(String, String)>> = HashMap::new();
    for (source, target) in file_dependencies {
        let (Some(role_s), Some(role_t)) = (role_of(source), role_of(target)) else {
            continue;
        };
        if role_s == role_t {
            continue;
        }
        *counts.entry((role_s, role_t)).or_default() += 1;
        examples
            .entry((role_s, role_t))
            .or_default()
            .push((source.clone(), target.clone()));
    }

    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for &(a, b) in counts.keys() {
        let unordered = if a <= b { (a, b) } else { (b, a) };
        if !seen.insert(unordered) {
            continue;
        }
        let n_forward = *counts.get(&(unordered.0, unordered.1)).unwrap_or(&0);
        let n_backward = *counts.get(&(unordered.1, unordered.0)).unwrap_or(&0);
        let total = n_forward + n_backward;
        if total < MIN_EXAMPLES {
            continue;
        }
        let (dominant, dom_n, minority, minor_n) = if n_forward >= n_backward {
            (
                (unordered.0, unordered.1),
                n_forward,
                (unordered.1, unordered.0),
                n_backward,
            )
        } else {
            (
                (unordered.1, unordered.0),
                n_backward,
                (unordered.0, unordered.1),
                n_forward,
            )
        };
        let confidence = dom_n as f64 / total as f64;
        if confidence < REPORT_THRESHOLD {
            continue;
        }
        conventions.push(Convention {
            kind: "dependency_direction".to_string(),
            description: format!("{} -> {}", dominant.0, dominant.1),
            confidence,
            matching: dom_n,
            total,
        });
        if minor_n > 0 {
            let severity = severity_for(confidence);
            for (source, target) in examples.get(&minority).into_iter().flatten() {
                deviations.push(Deviation {
                    description: format!("{} -> {}", minority.0, minority.1),
                    reason: format!(
                        "against the convention '{} -> {}' (confidence {:.2})",
                        dominant.0, dominant.1, confidence
                    ),
                    severity: severity.to_string(),
                    evidence: Some(format!("{source} -> {target}")),
                });
            }
        }
    }
}

fn learn_database_access(
    db_accessing_files: &[String],
    conventions: &mut Vec<Convention>,
    deviations: &mut Vec<Deviation>,
) {
    let mut role_counts: HashMap<&str, usize> = HashMap::new();
    let mut unroled = 0usize;
    for path in db_accessing_files {
        match role_of(path) {
            Some(role) => *role_counts.entry(role).or_default() += 1,
            None => unroled += 1,
        }
    }
    let total: usize = role_counts.values().sum::<usize>() + unroled;
    if total < MIN_EXAMPLES {
        return;
    }
    let Some((&dominant_role, &dom_n)) = role_counts.iter().max_by_key(|(_, n)| **n) else {
        return;
    };
    let confidence = dom_n as f64 / total as f64;
    if confidence < REPORT_THRESHOLD {
        return;
    }
    conventions.push(Convention {
        kind: "database_access".to_string(),
        description: format!("{dominant_role} performs database access"),
        confidence,
        matching: dom_n,
        total,
    });
    let severity = severity_for(confidence);
    for path in db_accessing_files {
        if let Some(role) = role_of(path)
            && role != dominant_role
        {
            deviations.push(Deviation {
                    description: format!("{role} performs direct database access"),
                    reason: format!(
                        "convention: '{dominant_role} performs database access' (confidence {confidence:.2})"
                    ),
                    severity: severity.to_string(),
                    evidence: Some(path.clone()),
                });
        }
    }
}

fn severity_for(confidence: f64) -> &'static str {
    if confidence > VIOLATION_THRESHOLD {
        "violation"
    } else {
        "warning"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(source: &str, target: &str) -> (String, String) {
        (source.to_string(), target.to_string())
    }

    #[test]
    fn learns_layering_and_flags_reverse_dependency() {
        // controllers → services dominate; one service → controller deviates.
        let deps = vec![
            dep("src/aController.ts", "src/aService.ts"),
            dep("src/bController.ts", "src/bService.ts"),
            dep("src/cController.ts", "src/cService.ts"),
            dep("src/dController.ts", "src/dService.ts"),
            dep("src/badService.ts", "src/badController.ts"),
        ];
        let report = learn_conventions(&deps, &[]);

        let layering = report
            .conventions
            .iter()
            .find(|c| c.kind == "dependency_direction")
            .unwrap();
        assert_eq!(layering.description, "controller -> service");
        assert_eq!(layering.matching, 4);
        assert_eq!(layering.total, 5);
        assert!((layering.confidence - 0.8).abs() < 1e-9);

        // 0.80 confidence → warning (not violation, < 0.85).
        let deviation = report
            .deviations
            .iter()
            .find(|d| d.severity == "warning")
            .unwrap();
        assert_eq!(deviation.description, "service -> controller");
    }

    #[test]
    fn learns_db_access_convention_and_flags_controller_access() {
        let db_files = vec![
            "src/userRepository.ts".to_string(),
            "src/orderRepository.ts".to_string(),
            "src/itemRepository.ts".to_string(),
            "src/legacyController.ts".to_string(),
        ];
        let report = learn_conventions(&[], &db_files);
        let convention = report
            .conventions
            .iter()
            .find(|c| c.kind == "database_access")
            .unwrap();
        assert_eq!(
            convention.description,
            "repository performs database access"
        );
        let deviation = report
            .deviations
            .iter()
            .find(|d| d.description.contains("controller"))
            .unwrap();
        assert!(deviation.evidence.as_deref() == Some("src/legacyController.ts"));
    }

    #[test]
    fn weak_evidence_yields_no_convention() {
        // Only two examples → below MIN_EXAMPLES.
        let deps = vec![
            dep("src/aController.ts", "src/aService.ts"),
            dep("src/bController.ts", "src/bService.ts"),
        ];
        assert!(learn_conventions(&deps, &[]).conventions.is_empty());
    }
}
