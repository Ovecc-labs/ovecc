//! Optional explanation layer.
//!
//! Ovecc's analysis is deterministic; an LLM is not required and does not
//! run as part of the scan. This crate turns a [`ContextSlice`] — the data
//! slice representing a component's localized architecture context — into
//! a readable narrative.
//!
//! The default [`DeterministicExplainer`] works offline: it reads only the slice
//! and does not perform network requests, ensuring reproducible results. An LLM-backed
//! provider can be added via the [`ExplanationProvider`] trait; if disabled or
//! unavailable, the deterministic provider acts as the fallback so explaining components
//! remains operational.
//!
//! Every statement is grounded in facts from the slice to ensure explanations
//! remain traceable and accurate to the parsed source code.

use ovecc_core::error::Result;
use ovecc_core::facts::{FindingRecord, Severity};
use ovecc_core::report::ContextSlice;
use ovecc_core::traits::ExplanationProvider;
use std::fmt::Write as _;

/// Deterministic, offline [`ExplanationProvider`]. The default explanation
/// backend and the fallback whenever an optional LLM provider is unavailable.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicExplainer;

impl ExplanationProvider for DeterministicExplainer {
    fn name(&self) -> &str {
        "deterministic"
    }

    fn explain(&self, context: &ContextSlice) -> Result<String> {
        Ok(render(context))
    }
}

/// Renders the full Markdown explanation for a slice.
fn render(slice: &ContextSlice) -> String {
    let target = if slice.target.is_empty() {
        "(unknown target)"
    } else {
        slice.target.as_str()
    };
    let fan_in = slice.reverse_dependencies.len();
    let fan_out = slice.dependencies.len();

    let mut out = String::new();
    let _ = writeln!(out, "# {target}");
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", coupling_summary(target, fan_in, fan_out, slice));
    let _ = writeln!(out);

    section_list(
        &mut out,
        &format!("Dependencies ({fan_out})"),
        &slice.dependencies,
        &format!("`{target}` has no outgoing dependencies in scope."),
    );
    section_list(
        &mut out,
        &format!("Dependents ({fan_in})"),
        &slice.reverse_dependencies,
        &format!("Nothing depends on `{target}` (an entry point or leaf)."),
    );

    change_impact(&mut out, target, slice);

    if !slice.apis.is_empty() {
        let _ = writeln!(out, "## Exposed APIs ({})", slice.apis.len());
        for api in &slice.apis {
            let method = api.method.as_deref().unwrap_or("");
            let path = api
                .path
                .as_deref()
                .or(api.name.as_deref())
                .unwrap_or("(unnamed)");
            let _ = writeln!(out, "- {method} {path}");
        }
        let _ = writeln!(out);
    }
    if !slice.schemas.is_empty() {
        let _ = writeln!(out, "## Data objects ({})", slice.schemas.len());
        for object in &slice.schemas {
            let _ = writeln!(out, "- {} `{}`", kind_label(&object.kind), object.name);
        }
        let _ = writeln!(out);
    }
    if !slice.ownership.is_empty() {
        let _ = writeln!(out, "## Ownership");
        for owner in &slice.ownership {
            let _ = writeln!(out, "- {}", owner.owner);
        }
        let _ = writeln!(out);
    }
    if !slice.drift.is_empty() {
        let _ = writeln!(out, "## Recent drift");
        for delta in &slice.drift {
            let pct = delta
                .delta_percent
                .map(|p| format!(" ({p:+.1}%)"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "- {}: {} -> {}{pct}",
                delta.metric, delta.base, delta.head
            );
        }
        let _ = writeln!(out);
    }

    findings_section(&mut out, target, &slice.findings);
    out
}

/// One-paragraph characterization of the component's coupling, grounded in its
/// fan-in/fan-out and call-path count.
fn coupling_summary(target: &str, fan_in: usize, fan_out: usize, slice: &ContextSlice) -> String {
    let role = match (fan_in, fan_out) {
        (0, 0) => format!(
            "`{target}` is isolated: nothing depends on it and it has no dependencies in scope."
        ),
        (0, _) => format!(
            "`{target}` is an entry point: it depends on {fan_out} component(s) but nothing depends on it, \
             so changes here stay local."
        ),
        (_, 0) => format!(
            "`{target}` is foundational: {fan_in} component(s) depend on it and it has no dependencies of its own, \
             so changes here ripple outward."
        ),
        (_, _) => format!(
            "`{target}` is an intermediary: it depends on {fan_out} component(s) and is used by {fan_in}."
        ),
    };
    let paths = slice.call_paths.len();
    let path_note = if paths > 0 {
        format!(" It lies on {paths} traced call path(s).")
    } else {
        String::new()
    };
    let risk_note = match severity_high_water(&slice.findings) {
        Some(sev) => format!(
            " {} finding(s) affect it, the most severe being {}.",
            slice.findings.len(),
            severity_label(sev)
        ),
        None => String::new(),
    };
    format!("{role}{path_note}{risk_note}")
}

/// "Change impact" paragraph: how far a modification can reach (blast radius),
/// illustrated by a few concrete paths.
fn change_impact(out: &mut String, target: &str, slice: &ContextSlice) {
    let reach = slice.reverse_dependencies.len();
    let _ = writeln!(out, "## Change impact");
    if reach == 0 {
        let _ = writeln!(
            out,
            "Modifying `{target}` has no known downstream impact: no component depends on it."
        );
    } else {
        let _ = writeln!(
            out,
            "Modifying `{target}` can affect up to {reach} component(s) downstream."
        );
        // Show representative internal paths, skipping external dependency nodes
        // (which have opaque IDs less useful in a narrative). Capped for readability.
        for path in slice
            .call_paths
            .iter()
            .filter(|path| path.iter().all(|node| !node.starts_with("external:")))
            .take(5)
        {
            let _ = writeln!(out, "- {}", path.join(" -> "));
        }
    }
    let _ = writeln!(out);
}

/// Findings section, ordered most-severe first.
fn findings_section(out: &mut String, target: &str, findings: &[FindingRecord]) {
    let _ = writeln!(out, "## Findings ({})", findings.len());
    if findings.is_empty() {
        let _ = writeln!(out, "No findings recorded for `{target}`.");
        return;
    }
    let mut ordered: Vec<&FindingRecord> = findings.iter().collect();
    // Severity descending, then a stable tie-break on title.
    ordered.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
    });
    for finding in ordered {
        let _ = writeln!(
            out,
            "- [{}] {}: {}",
            severity_label(finding.severity),
            finding.title,
            finding.description
        );
    }
}

/// Writes a `## Heading` followed by a bullet list, or a fallback line when the
/// list is empty.
fn section_list(out: &mut String, heading: &str, items: &[String], empty: &str) {
    let _ = writeln!(out, "## {heading}");
    if items.is_empty() {
        let _ = writeln!(out, "{empty}");
    } else {
        for item in items {
            let _ = writeln!(out, "- {item}");
        }
    }
    let _ = writeln!(out);
}

/// The highest severity present in a set of findings, if any.
fn severity_high_water(findings: &[FindingRecord]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn kind_label(kind: &ovecc_core::facts::SchemaObjectKind) -> &'static str {
    use ovecc_core::facts::SchemaObjectKind as K;
    match kind {
        K::Table => "table",
        K::View => "view",
        K::Column => "column",
        K::Index => "index",
        K::ForeignKey => "foreign key",
        K::Enum => "enum",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::facts::{EntityRef, Evidence, FindingKind};
    use ovecc_core::graph::NodeKind;
    use ovecc_core::id::FindingId;

    fn finding(title: &str, severity: Severity) -> FindingRecord {
        FindingRecord {
            id: FindingId::from_raw("finding:1"),
            repository_id: ovecc_core::id::RepositoryId::from_raw("r"),
            snapshot_id: None,
            kind: FindingKind::TaintedFlow,
            severity,
            rule_name: None,
            target: Some(EntityRef {
                kind: NodeKind::Symbol,
                id: "Billing".to_string(),
            }),
            title: title.to_string(),
            description: "untrusted input reaches a sink".to_string(),
            evidence: vec![Evidence {
                file_path: "src/billing.ts".to_string(),
                line: Some(10),
                symbol: None,
                detail: None,
            }],
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn explains_an_intermediary_with_findings() {
        let slice = ContextSlice {
            target: "Billing".to_string(),
            dependencies: vec!["User".to_string(), "Db".to_string()],
            reverse_dependencies: vec!["Api".to_string()],
            call_paths: vec![vec![
                "Api".to_string(),
                "Billing".to_string(),
                "Db".to_string(),
            ]],
            findings: vec![
                finding("SQL injection", Severity::Critical),
                finding("weak hash", Severity::Low),
            ],
            ..ContextSlice::default()
        };

        let text = DeterministicExplainer.explain(&slice).unwrap();

        assert!(text.contains("# Billing"));
        assert!(text.contains("intermediary"), "{text}");
        // Fan-in / fan-out are reported.
        assert!(text.contains("Dependencies (2)"), "{text}");
        assert!(text.contains("Dependents (1)"), "{text}");
        // Change impact lists the traced path.
        assert!(text.contains("Api -> Billing -> Db"), "{text}");
        // Findings are ordered critical-first.
        let critical = text.find("critical").unwrap();
        let low = text.find("[low]").unwrap();
        assert!(critical < low, "critical finding must come first:\n{text}");
    }

    #[test]
    fn explains_isolated_target_without_findings() {
        let slice = ContextSlice {
            target: "Orphan".to_string(),
            ..ContextSlice::default()
        };
        let text = DeterministicExplainer.explain(&slice).unwrap();
        assert!(text.contains("isolated"), "{text}");
        assert!(text.contains("No findings recorded"), "{text}");
    }

    #[test]
    fn explanation_is_deterministic() {
        let slice = ContextSlice {
            target: "Billing".to_string(),
            dependencies: vec!["User".to_string()],
            ..ContextSlice::default()
        };
        let a = DeterministicExplainer.explain(&slice).unwrap();
        let b = DeterministicExplainer.explain(&slice).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn explains_entry_point_role() {
        // Depends on others but nothing depends on it → entry point.
        let slice = ContextSlice {
            target: "Cli".to_string(),
            dependencies: vec!["Parser".to_string()],
            ..ContextSlice::default()
        };
        let text = DeterministicExplainer.explain(&slice).unwrap();
        assert!(text.contains("entry point"), "{text}");
        assert!(text.contains("stay local"), "{text}");
    }

    #[test]
    fn explains_foundational_role() {
        // Others depend on it but it has no dependencies → foundational.
        let slice = ContextSlice {
            target: "Core".to_string(),
            reverse_dependencies: vec!["A".to_string(), "B".to_string()],
            ..ContextSlice::default()
        };
        let text = DeterministicExplainer.explain(&slice).unwrap();
        assert!(text.contains("foundational"), "{text}");
        assert!(text.contains("ripple outward"), "{text}");
    }

    #[test]
    fn change_impact_omits_external_call_paths() {
        let slice = ContextSlice {
            target: "Svc".to_string(),
            reverse_dependencies: vec!["X".to_string()],
            call_paths: vec![
                vec!["X".to_string(), "Svc".to_string()],
                vec!["external:lodash".to_string(), "Svc".to_string()],
            ],
            ..ContextSlice::default()
        };
        let text = DeterministicExplainer.explain(&slice).unwrap();
        // The internal path is shown; the path through an external node is filtered.
        assert!(text.contains("X -> Svc"), "{text}");
        assert!(!text.contains("external:lodash"), "{text}");
    }
}
