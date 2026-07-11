//! Output plumbing shared by every command: the self-describing JSON
//! envelope, NDJSON framing, fix-descriptor enrichment, and the SARIF /
//! Code Climate serializations CI systems ingest.

use anyhow::Result;
use ovecc_core::capabilities;
use ovecc_core::facts::{FindingRecord, Severity};
use ovecc_core::report::{Envelope, Meta, ToolInfo};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the global `--no-meta` flag. When true, [`meta_for`] returns an empty
/// `Meta`, so the self-describing metric/rule dictionaries are omitted from every
/// command's JSON. The MCP server sets this on every tool call: the agent reads
/// the dictionaries once via `capabilities`, so repeating them on every result
/// only inflates tokens (roughly halving MCP tool-result size in practice).
pub(crate) static SUPPRESS_META: AtomicBool = AtomicBool::new(false);

/// Prints `data` wrapped in the self-describing JSON envelope
/// (schema_version + tool + command + meta).
pub(crate) fn emit_json<T: serde::Serialize + ?Sized>(
    command: &str,
    data: &T,
    meta: Meta,
) -> Result<()> {
    let envelope = Envelope::new(command, data, meta);
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

/// Prints the NDJSON header line, so a stream is self-describing without
/// buffering.
pub(crate) fn emit_ndjson_meta(command: &str, meta: &Meta) -> Result<()> {
    let header = serde_json::json!({
        "type": "meta",
        "schema_version": ovecc_core::report::SCHEMA_VERSION,
        "tool": ToolInfo::default(),
        "command": command,
        "meta": meta,
    });
    println!("{}", serde_json::to_string(&header)?);
    Ok(())
}

/// The metric and/or rule dictionaries relevant to a command, so an agent can
/// interpret the payload without the docs site.
pub(crate) fn meta_for(command: &str) -> Meta {
    if SUPPRESS_META.load(Ordering::Relaxed) {
        return Meta::default();
    }
    let mut meta = Meta::default();
    if matches!(
        command,
        "summary" | "report" | "drift" | "diff" | "hotspots" | "index" | "health" | "review"
    ) {
        meta.metrics = capabilities::metric_definitions();
    }
    if matches!(
        command,
        "violations"
            | "security"
            | "audit"
            | "gate"
            | "report"
            | "summary"
            | "health"
            | "deadcode"
            | "review"
    ) {
        meta.rules = capabilities::rule_definitions();
    }
    meta
}

/// Prints wall-clock and peak heap to stderr, keeping stdout machine-readable.
pub(crate) fn report_run_stats(elapsed: std::time::Duration) {
    eprintln!(
        "stats: {} ms wall, {:.1} MB peak heap",
        elapsed.as_millis(),
        crate::PEAK_ALLOC.peak_usage_as_mb()
    );
}

/// Injects each finding's machine-actionable `fix` (derived from its kind) into a
/// serialized findings payload — whether a bare array of findings or a report
/// object carrying a `findings` array.
pub(crate) fn enrich_findings_with_fix(value: &mut serde_json::Value) {
    fn enrich_array(arr: &mut [serde_json::Value]) {
        for item in arr {
            let kind = item.get("kind").and_then(|k| k.as_str()).and_then(|s| {
                serde_json::from_value::<ovecc_core::facts::FindingKind>(serde_json::Value::String(
                    s.to_string(),
                ))
                .ok()
            });
            if let (Some(kind), serde_json::Value::Object(map)) = (kind, item) {
                map.insert(
                    "fix".to_string(),
                    serde_json::to_value(kind.fix_spec()).unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    match value {
        serde_json::Value::Array(arr) => enrich_array(arr),
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(arr)) = map.get_mut("findings") {
                enrich_array(arr);
            }
        }
        _ => {}
    }
}

pub(crate) fn emit_json_with_fix(command: &str, data: impl serde::Serialize) -> Result<()> {
    let mut value = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
    enrich_findings_with_fix(&mut value);
    emit_json(command, &value, meta_for(command))
}

/// SARIF 2.1.0, so findings flow into GitHub code scanning.
pub(crate) fn emit_sarif(findings: &[FindingRecord]) -> Result<()> {
    use std::collections::BTreeMap;

    // One SARIF rule per distinct rule name, with its description.
    let mut rules: BTreeMap<String, String> = BTreeMap::new();
    for finding in findings {
        let rule_id = finding
            .rule_name
            .clone()
            .unwrap_or_else(|| format!("{:?}", finding.kind));
        rules
            .entry(rule_id)
            .or_insert_with(|| finding.title.clone());
    }
    let rule_list: Vec<serde_json::Value> = rules
        .iter()
        .map(|(id, desc)| serde_json::json!({ "id": id, "shortDescription": { "text": desc } }))
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let rule_id = finding
                .rule_name
                .clone()
                .unwrap_or_else(|| format!("{:?}", finding.kind));
            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let locations: Vec<serde_json::Value> = finding
                .evidence
                .iter()
                .map(|evidence| {
                    let mut region = serde_json::Map::new();
                    if let Some(line) = evidence.line {
                        region.insert("startLine".to_string(), serde_json::json!(line.max(1)));
                    }
                    serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": { "uri": evidence.file_path },
                            "region": region,
                        }
                    })
                })
                .collect();
            serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": finding.description },
                "locations": locations,
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ovecc",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Ovecc-labs/ovecc",
                    "rules": rule_list,
                }
            },
            "results": results,
        }],
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

/// Code Climate JSON, so findings flow into GitLab merge-request quality
/// reports.
pub(crate) fn emit_codeclimate(findings: &[FindingRecord]) -> Result<()> {
    let issues: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let check_name = finding
                .rule_name
                .clone()
                .unwrap_or_else(|| format!("{:?}", finding.kind));
            let severity = match finding.severity {
                Severity::Critical => "blocker",
                Severity::High => "critical",
                Severity::Medium => "major",
                Severity::Low => "minor",
            };
            let evidence = finding.evidence.first();
            let path = evidence
                .map(|e| e.file_path.clone())
                .unwrap_or_else(|| "<unknown>".to_string());
            let line = evidence.and_then(|e| e.line).unwrap_or(1).max(1);
            serde_json::json!({
                "type": "issue",
                "check_name": check_name,
                "description": finding.title,
                // GitLab diffs fingerprints between pipelines, so this must be
                // stable across runs.
                "fingerprint": finding.id.as_str(),
                "severity": severity,
                "location": { "path": path, "lines": { "begin": line } },
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&issues)?);
    Ok(())
}

pub(crate) fn format_evidence(evidence: &ovecc_core::facts::Evidence) -> String {
    let mut text = evidence.file_path.clone();
    if let Some(line) = evidence.line {
        text.push_str(&format!(":{line}"));
    }
    if let Some(detail) = &evidence.detail {
        text.push_str(&format!(" ({detail})"));
    }
    text
}

/// First evidence location of a finding, formatted as ` (path:line)`, or empty.
pub(crate) fn first_evidence(finding: &FindingRecord) -> String {
    finding
        .evidence
        .first()
        .map(|evidence| format!(" ({})", format_evidence(evidence)))
        .unwrap_or_default()
}

/// One NDJSON line: the serialized payload with an injected `"type"` tag.
pub(crate) fn ndjson_line<T: serde::Serialize>(kind: &str, payload: &T) -> Result<String> {
    let mut value = serde_json::to_value(payload)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "type".to_string(),
            serde_json::Value::String(kind.to_string()),
        );
    }
    Ok(serde_json::to_string(&value)?)
}

/// Serializes the payload, dropping the given top-level list fields (they are
/// emitted as separate NDJSON lines instead).
pub(crate) fn ndjson_header<T: serde::Serialize>(
    kind: &str,
    payload: &T,
    drop: &[&str],
) -> Result<String> {
    let mut value = serde_json::to_value(payload)?;
    if let serde_json::Value::Object(map) = &mut value {
        for field in drop {
            map.remove(*field);
        }
        map.insert(
            "type".to_string(),
            serde_json::Value::String(kind.to_string()),
        );
    }
    Ok(serde_json::to_string(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_meta_flag_suppresses_the_meta_block() {
        // Default: a command that carries metric/rule dictionaries has meta.
        SUPPRESS_META.store(false, Ordering::Relaxed);
        assert!(!meta_for("summary").is_empty());
        // Suppressed: every command's meta collapses to empty (so the envelope
        // omits it), while `capabilities` output is unaffected (it never uses
        // meta_for — the contract lives in its `data`).
        SUPPRESS_META.store(true, Ordering::Relaxed);
        assert!(meta_for("summary").is_empty());
        assert!(meta_for("review").is_empty());
        SUPPRESS_META.store(false, Ordering::Relaxed);
    }
}
