//! `ovecc history`: metric trends across snapshots, with sparklines.

use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_line};
use anyhow::Result;
use ovecc_core::config::OutputFormat;

#[derive(Debug, serde::Serialize)]
struct HistoryPoint {
    snapshot_id: String,
    commit_sha: Option<String>,
    created_at: String,
    value: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta: Option<f64>,
}

#[derive(Debug, serde::Serialize)]
struct HistoryReport {
    metric: String,
    snapshots: usize,
    first: f64,
    last: f64,
    change: f64,
    sparkline: String,
    points: Vec<HistoryPoint>,
}

/// Eight-level Unicode sparkline; a flat series renders mid-level bars so "no
/// movement" still reads as a line, not an artifact.
fn sparkline(values: &[f64]) -> String {
    const LEVELS: [char; 8] = [
        '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if !min.is_finite() || !max.is_finite() || (max - min).abs() < f64::EPSILON {
        return LEVELS[3].to_string().repeat(values.len());
    }
    values
        .iter()
        .map(|v| {
            let t = (v - min) / (max - min);
            LEVELS[((t * 7.0).round() as usize).min(7)]
        })
        .collect()
}

/// Whole numbers stay whole, ratios round to three decimals, and values that
/// would round to zero keep their raw form. JSON output stays raw.
fn format_metric_value(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.fract() == 0.0 {
        return format!("{value:.0}");
    }
    let rounded = format!("{value:.3}");
    if rounded.trim_start_matches(['-', '0', '.']).is_empty() {
        return format!("{value}");
    }
    rounded
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn format_metric_delta(delta: f64) -> String {
    let sign = if delta < 0.0 { "-" } else { "+" };
    format!("{sign}{}", format_metric_value(delta.abs()))
}

fn build_history_report(
    metric: &str,
    points: &[(String, Option<String>, String, f64)],
) -> HistoryReport {
    let values: Vec<f64> = points.iter().map(|(_, _, _, v)| *v).collect();
    let history_points: Vec<HistoryPoint> = points
        .iter()
        .enumerate()
        .map(|(i, (id, sha, at, value))| HistoryPoint {
            snapshot_id: id.clone(),
            commit_sha: sha.clone(),
            created_at: at.clone(),
            value: *value,
            delta: (i > 0).then(|| value - values[i - 1]),
        })
        .collect();
    let first = *values.first().unwrap_or(&0.0);
    let last = *values.last().unwrap_or(&0.0);
    HistoryReport {
        metric: metric.to_string(),
        snapshots: points.len(),
        first,
        last,
        change: last - first,
        sparkline: sparkline(&values),
        points: history_points,
    }
}

pub(crate) fn render_history(
    metric: &str,
    points: &[(String, Option<String>, String, f64)],
    format: OutputFormat,
) -> Result<()> {
    let report = build_history_report(metric, points);
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("history", &report, meta_for("history"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("history", &meta_for("history"))?;
            for point in &report.points {
                println!("{}", ndjson_line("history", point)?);
            }
        }
        OutputFormat::Markdown => {
            println!(
                "# History: `{}` over {} snapshot(s) — {} -> {} ({})",
                report.metric,
                report.snapshots,
                format_metric_value(report.first),
                format_metric_value(report.last),
                format_metric_delta(report.change)
            );
            println!();
            println!("`{}`", report.sparkline);
            println!();
            println!("| When | Commit | Value | Delta |");
            println!("| --- | --- | ---: | ---: |");
            for point in &report.points {
                println!(
                    "| {} | {} | {} | {} |",
                    point.created_at,
                    point
                        .commit_sha
                        .as_deref()
                        .map(|s| &s[..s.len().min(7)])
                        .unwrap_or("-"),
                    format_metric_value(point.value),
                    point.delta.map(format_metric_delta).unwrap_or_default()
                );
            }
        }
        OutputFormat::Text => {
            println!(
                "History: {} over {} snapshot(s)   {} -> {} ({})",
                report.metric,
                report.snapshots,
                format_metric_value(report.first),
                format_metric_value(report.last),
                format_metric_delta(report.change)
            );
            println!("  {}", report.sparkline);
            for point in &report.points {
                println!(
                    "  {}  {:>7}  {:>10}  {}",
                    point.created_at,
                    point
                        .commit_sha
                        .as_deref()
                        .map(|s| &s[..s.len().min(7)])
                        .unwrap_or("-"),
                    format_metric_value(point.value),
                    point.delta.map(format_metric_delta).unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn render_history_index(names: &[String], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json
        | OutputFormat::Ndjson
        | OutputFormat::Sarif
        | OutputFormat::Codeclimate => emit_json(
            "history",
            &serde_json::json!({ "metrics": names }),
            meta_for("history"),
        )?,
        _ => {
            println!("Trendable metrics ({}):", names.len());
            for name in names {
                println!("  {name}");
            }
            if names.is_empty() {
                println!("  (none yet — run `ovecc index` first)");
            } else {
                println!();
                println!("Run `ovecc history <metric>` to trend one.");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_values_render_for_humans() {
        assert_eq!(format_metric_value(11.0), "11");
        assert_eq!(format_metric_value(0.18181818181818182), "0.182");
        assert_eq!(format_metric_value(0.5), "0.5");
        assert_eq!(format_metric_value(-2.25), "-2.25");
        assert_eq!(format_metric_value(0.0001), "0.0001");
        assert_eq!(format_metric_value(0.0), "0");
        assert_eq!(format_metric_delta(3.0), "+3");
        assert_eq!(format_metric_delta(-0.045454545454545456), "-0.045");
        assert_eq!(format_metric_delta(0.0), "+0");
    }
}
