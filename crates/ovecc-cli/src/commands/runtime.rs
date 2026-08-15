//! `ovecc runtime`: import a trace export as runtime evidence, and report what
//! it joined to.
//!
//! The import path never opens a socket. Bytes arrive from a file or from
//! stdin, which is what makes every backend supported on day one:
//! `curl ... | ovecc runtime import -`.

use super::open_store;
use crate::cli::RuntimeCommand;
use crate::render::{
    emit_ndjson_meta, first_evidence, meta_for, ndjson_header, ndjson_line, render_report,
    severity_tag,
};
use anyhow::{Context, Result};
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::facts::FindingRecord;
use ovecc_core::runtime::{
    EdgeFact, PathAttribution, PointFact, RouteJoinCounts, RuntimeSnapshot, SamplingSummary,
    UnattributedShape, WitnessMode,
};
use ovecc_db::ArchitectureStore;
use ovecc_runtime::attribute::{IndexView, IndexedRoute};
use ovecc_runtime::import::{ImportOptions, import};
use serde::Serialize;
use std::io::Read;
use std::path::Path;

const STDIN_SOURCE: &str = "-";
const NANOS_PER_MILLI: f64 = 1_000_000.0;

#[derive(Serialize)]
pub(crate) struct ImportReport {
    /// `stored` when the evidence replaced what was there, `unchanged` when the
    /// same bytes were already imported. Re-import is a no-op, not a duplicate.
    outcome: &'static str,
    provider: String,
    format: String,
    source_digest: String,
    witnesses: WitnessMode,
    window: Option<WindowView>,
    observations: u64,
    attributed: u64,
    attribution_rate: Option<f64>,
    by_path: Vec<PathAttribution>,
    route_joins: RouteJoinCounts,
    sampling: SamplingSummary,
    points: usize,
    edges: usize,
    unattributed_observations: u64,
    index: IndexCoverage,
}

#[derive(Serialize)]
struct WindowView {
    start: String,
    end: String,
    duration_seconds: u64,
}

/// What the index offered the join. A zero here explains a zero attribution
/// rate without the reader having to guess whether the export or the index was
/// at fault.
#[derive(Serialize)]
struct IndexCoverage {
    routes: usize,
    tables: usize,
    files: usize,
}

#[derive(Serialize)]
pub(crate) struct RuntimeReport {
    /// False when no import has run. An empty report then means "nobody
    /// looked", never "nothing ran".
    has_evidence: bool,
    snapshot: Option<SnapshotView>,
    points: Vec<PointFact>,
    edges: Vec<EdgeFact>,
    unattributed: Vec<UnattributedShape>,
    divergences: Vec<FindingRecord>,
}

#[derive(Serialize)]
struct SnapshotView {
    provider: String,
    format: String,
    source_digest: String,
    witnesses: WitnessMode,
    query: Option<String>,
    window: Option<WindowView>,
    observations: u64,
    attributed: u64,
    attribution_rate: Option<f64>,
    by_path: Vec<PathAttribution>,
    route_joins: RouteJoinCounts,
    sampling: SamplingSummary,
}

pub(crate) fn run(
    paths: &ProjectPaths,
    format: OutputFormat,
    what: Option<RuntimeCommand>,
    unattributed: bool,
    limit: usize,
) -> Result<u8> {
    match what {
        Some(RuntimeCommand::Import {
            source,
            input_format,
            provider,
            witnesses,
        }) => run_import(
            paths,
            format,
            &source,
            input_format.as_deref(),
            provider.as_deref(),
            witnesses,
        ),
        None => run_report(paths, format, unattributed, limit),
    }
}

fn run_import(
    paths: &ProjectPaths,
    format: OutputFormat,
    source: &str,
    telemetry_format: Option<&str>,
    provider: Option<&str>,
    witnesses: bool,
) -> Result<u8> {
    let mut store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let bytes = read_source(&paths.root, source)?;
    let view = index_view(&store, &repository_id)?;
    let snapshot = import(
        &bytes,
        &view,
        &ImportOptions {
            repository_id: &repository_id,
            provider: provider.unwrap_or(default_provider(source)),
            format: telemetry_format,
            query: None,
            keep_trace_ids: witnesses,
        },
    )?;

    let stored = store.runtime_snapshot_id(&repository_id)?;
    let outcome = if stored.as_deref() == Some(snapshot.id.as_str()) {
        "unchanged"
    } else {
        store.replace_runtime_snapshot(&repository_id, &snapshot)?;
        "stored"
    };
    render_import(&build_import_report(&snapshot, outcome, &view), format)?;
    Ok(0)
}

fn run_report(
    paths: &ProjectPaths,
    format: OutputFormat,
    unattributed: bool,
    limit: usize,
) -> Result<u8> {
    // Scoped: DuckDB admits one writer per file per process, and the contract
    // verdicts below open the store again to read the graph they judge.
    let snapshot = {
        let store = open_store(paths)?;
        store.runtime_snapshot(&paths.repository_id().0)?
    };
    let divergences = match &snapshot {
        Some(_) => crate::commands::architecture::runtime_divergences(paths)?,
        None => Vec::new(),
    };
    let report = build_report(snapshot, divergences, unattributed, limit);
    render_runtime(&report, format, unattributed)?;
    Ok(0)
}

fn default_provider(source: &str) -> &'static str {
    if source == STDIN_SOURCE {
        "stdin"
    } else {
        "file"
    }
}

fn read_source(root: &Path, source: &str) -> Result<Vec<u8>> {
    if source == STDIN_SOURCE {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("failed to read the telemetry export from stdin")?;
        return Ok(bytes);
    }
    let candidate = Path::new(source);
    let path = if candidate.is_absolute() || candidate.exists() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))
}

fn index_view(store: &ArchitectureStore, repository_id: &str) -> Result<IndexView> {
    let routes = store
        .indexed_routes(repository_id)?
        .into_iter()
        .map(|row| IndexedRoute {
            method: row.method,
            path: row.path,
            file: row.file_path,
            symbol: row.symbol,
            line: row.line,
        })
        .collect();
    Ok(IndexView::new(
        routes,
        store.indexed_table_names(repository_id)?,
        store.indexed_file_paths(repository_id)?,
    ))
}

fn window_view(snapshot: &RuntimeSnapshot) -> Option<WindowView> {
    snapshot.window.map(|window| WindowView {
        start: window.start_rfc3339(),
        end: window.end_rfc3339(),
        duration_seconds: window.duration_seconds(),
    })
}

fn build_import_report(
    snapshot: &RuntimeSnapshot,
    outcome: &'static str,
    view: &IndexView,
) -> ImportReport {
    ImportReport {
        outcome,
        provider: snapshot.provider.clone(),
        format: snapshot.format.clone(),
        source_digest: snapshot.source_digest.clone(),
        witnesses: snapshot.witnesses,
        window: window_view(snapshot),
        observations: snapshot.observations,
        attributed: snapshot.attributed,
        attribution_rate: snapshot.attribution_rate(),
        by_path: snapshot.by_path.clone(),
        route_joins: snapshot.route_joins,
        sampling: snapshot.sampling,
        points: snapshot.points.len(),
        edges: snapshot.edges.len(),
        unattributed_observations: snapshot
            .unattributed
            .iter()
            .map(|shape| shape.observations)
            .sum(),
        index: IndexCoverage {
            routes: view.route_count(),
            tables: view.table_count(),
            files: view.file_count(),
        },
    }
}

fn build_report(
    snapshot: Option<RuntimeSnapshot>,
    divergences: Vec<FindingRecord>,
    unattributed: bool,
    limit: usize,
) -> RuntimeReport {
    let Some(snapshot) = snapshot else {
        return RuntimeReport {
            has_evidence: false,
            snapshot: None,
            points: Vec::new(),
            edges: Vec::new(),
            unattributed: Vec::new(),
            divergences: Vec::new(),
        };
    };
    let mut points = snapshot.points.clone();
    points.sort_by(|left, right| {
        right
            .calls
            .cmp(&left.calls)
            .then_with(|| left.anchor.cmp(&right.anchor))
    });
    let mut edges = snapshot.edges.clone();
    edges.sort_by(|left, right| {
        right
            .calls
            .cmp(&left.calls)
            .then_with(|| (&left.from, &left.to).cmp(&(&right.from, &right.to)))
    });
    RuntimeReport {
        has_evidence: true,
        snapshot: Some(SnapshotView {
            provider: snapshot.provider.clone(),
            format: snapshot.format.clone(),
            source_digest: snapshot.source_digest.clone(),
            witnesses: snapshot.witnesses,
            query: snapshot.query.clone(),
            window: window_view(&snapshot),
            observations: snapshot.observations,
            attributed: snapshot.attributed,
            attribution_rate: snapshot.attribution_rate(),
            by_path: snapshot.by_path.clone(),
            route_joins: snapshot.route_joins,
            sampling: snapshot.sampling,
        }),
        points: capped(points, limit),
        edges: capped(edges, limit),
        unattributed: if unattributed {
            capped(snapshot.unattributed, limit)
        } else {
            Vec::new()
        },
        divergences,
    }
}

fn capped<T>(mut rows: Vec<T>, limit: usize) -> Vec<T> {
    if limit > 0 {
        rows.truncate(limit);
    }
    rows
}

fn percent(rate: Option<f64>) -> String {
    rate.map_or_else(|| "n/a".to_string(), |rate| format!("{:.1}%", rate * 100.0))
}

fn millis(nanos: u64) -> String {
    format!("{:.1}ms", nanos as f64 / NANOS_PER_MILLI)
}

fn render_import(report: &ImportReport, format: OutputFormat) -> Result<()> {
    render_report(
        "runtime import",
        report,
        format,
        || {
            emit_ndjson_meta("runtime import", &meta_for("runtime import"))?;
            println!("{}", ndjson_line("runtime_import", report)?);
            Ok(())
        },
        || {
            println!("# Runtime import ({})", report.outcome);
            println!();
            println!("| Measure | Value |");
            println!("| --- | --- |");
            println!("| Format | {} via {} |", report.format, report.provider);
            println!("| Observations | {} |", report.observations);
            println!(
                "| Attributed | {} ({}) |",
                report.attributed,
                percent(report.attribution_rate)
            );
            println!("| Point facts | {} |", report.points);
            println!("| Edge facts | {} |", report.edges);
            println!("| Digest | `{}` |", report.source_digest);
        },
        || print_import_text(report),
    )
}

fn print_import_text(report: &ImportReport) {
    println!(
        "Runtime import: {} ({} via {})",
        report.outcome, report.format, report.provider
    );
    if let Some(window) = &report.window {
        println!(
            "  window        {} .. {} ({}s)",
            window.start, window.end, window.duration_seconds
        );
    }
    println!("  observations  {}", report.observations);
    println!(
        "  attributed    {} ({})",
        report.attributed,
        percent(report.attribution_rate)
    );
    for count in &report.by_path {
        println!("     {:<14} {}", count.path.as_str(), count.observations);
    }
    print_route_joins(&report.route_joins);
    print_sampling(&report.sampling);
    println!(
        "  facts         {} anchors, {} edges",
        report.points, report.edges
    );
    if report.unattributed_observations > 0 {
        println!(
            "  unattributed  {} observation(s) — run `ovecc runtime --unattributed` for the shapes",
            report.unattributed_observations
        );
    }
    println!(
        "  index offered {} route(s), {} table(s), {} file(s)",
        report.index.routes, report.index.tables, report.index.files
    );
    println!("  witnesses     {} trace ids", report.witnesses.as_str());
    println!("  digest        {}", report.source_digest);
}

fn print_route_joins(joins: &RouteJoinCounts) {
    if joins.exact == 0 && joins.mount_suffix == 0 {
        return;
    }
    println!(
        "  route joins   {} exact, {} through a router mount prefix",
        joins.exact, joins.mount_suffix
    );
}

fn print_sampling(sampling: &SamplingSummary) {
    let modal = sampling
        .modal_adjusted_count
        .map_or_else(|| "unknown".to_string(), |count| format!("1 in {count}"));
    println!(
        "  sampling      {} span(s) carried a rate (modal {modal}), {} did not",
        sampling.known, sampling.unknown
    );
    if sampling.is_mixed() {
        println!(
            "                {} distinct rates: totals are extrapolated per observation, not \
             with one multiplier",
            sampling.distinct_rates
        );
    }
}

fn render_runtime(report: &RuntimeReport, format: OutputFormat, unattributed: bool) -> Result<()> {
    render_report(
        "runtime",
        report,
        format,
        || {
            emit_ndjson_meta("runtime", &meta_for("runtime"))?;
            println!(
                "{}",
                ndjson_header(
                    "runtime",
                    report,
                    &["points", "edges", "unattributed", "divergences"]
                )?
            );
            for point in &report.points {
                println!("{}", ndjson_line("runtime_point", point)?);
            }
            for edge in &report.edges {
                println!("{}", ndjson_line("runtime_edge", edge)?);
            }
            for shape in &report.unattributed {
                println!("{}", ndjson_line("runtime_unattributed", shape)?);
            }
            for finding in &report.divergences {
                println!("{}", ndjson_line("finding", finding)?);
            }
            Ok(())
        },
        || print_runtime_markdown(report),
        || print_runtime_text(report, unattributed),
    )
}

fn print_runtime_markdown(report: &RuntimeReport) {
    println!("# Runtime evidence");
    println!();
    let Some(snapshot) = &report.snapshot else {
        println!("> No runtime evidence imported. Run `ovecc runtime import <export>`.");
        return;
    };
    println!(
        "{} observation(s), {} attributed ({}).",
        snapshot.observations,
        snapshot.attributed,
        percent(snapshot.attribution_rate)
    );
    println!();
    println!("| From | To | Kind | Calls | Errors |");
    println!("| --- | --- | --- | --- | --- |");
    for edge in &report.edges {
        println!(
            "| `{}` | `{}` | {} | {} | {} |",
            edge.from.label(),
            edge.to.label(),
            edge.kind.as_str(),
            edge.calls,
            edge.errors
        );
    }
}

fn print_runtime_text(report: &RuntimeReport, unattributed: bool) {
    let Some(snapshot) = &report.snapshot else {
        println!("Runtime evidence: none imported");
        println!("  (nobody looked — this is not evidence that nothing ran)");
        println!("  import one with: ovecc runtime import <export.json>");
        return;
    };
    println!(
        "Runtime evidence ({} via {})",
        snapshot.format, snapshot.provider
    );
    if let Some(window) = &snapshot.window {
        println!(
            "  window        {} .. {} ({}s)",
            window.start, window.end, window.duration_seconds
        );
    }
    println!(
        "  attributed    {} of {} observation(s) ({})",
        snapshot.attributed,
        snapshot.observations,
        percent(snapshot.attribution_rate)
    );
    for count in &snapshot.by_path {
        println!("     {:<14} {}", count.path.as_str(), count.observations);
    }
    print_route_joins(&snapshot.route_joins);
    print_sampling(&snapshot.sampling);

    print_anchors(&report.points);
    print_edges(&report.edges);
    print_divergences(&report.divergences);
    if unattributed {
        print_unattributed(&report.unattributed);
    } else if !report.points.is_empty() || !report.edges.is_empty() {
        println!();
        println!("  (run `ovecc runtime --unattributed` for the spans that did not join)");
    }
}

fn print_anchors(points: &[PointFact]) {
    if points.is_empty() {
        return;
    }
    println!();
    println!("Busiest anchors:");
    for point in points {
        let location = match point.anchor.line {
            Some(line) => format!("{}:{line}", point.anchor.file),
            None => point.anchor.file.clone(),
        };
        let symbol = point.anchor.symbol.as_deref().unwrap_or("");
        let latency = point.latency.map_or_else(String::new, |latency| {
            format!("  p95 {}", millis(latency.p95_ns))
        });
        println!(
            "  {location} {symbol}  {} call(s), {} error(s){latency}  [{}]",
            point.calls,
            point.errors,
            point.path.as_str()
        );
    }
}

fn print_edges(edges: &[EdgeFact]) {
    if edges.is_empty() {
        return;
    }
    println!();
    println!("Observed calls:");
    for edge in edges {
        let estimate = edge
            .estimated_calls
            .filter(|estimated| *estimated > edge.calls)
            .map_or_else(String::new, |estimated| format!(" (~{estimated} sampled)"));
        println!(
            "  {} -> {}  {} {} call(s){estimate}, {} error(s)",
            edge.from.label(),
            edge.to.label(),
            edge.calls,
            edge.kind.as_str(),
            edge.errors
        );
    }
}

fn print_divergences(divergences: &[FindingRecord]) {
    if divergences.is_empty() {
        return;
    }
    println!();
    println!("Contract verdicts over this evidence:");
    for finding in divergences {
        anstream::println!(
            "  {} {}{}",
            severity_tag(finding.severity),
            finding.title,
            first_evidence(finding)
        );
    }
}

fn print_unattributed(shapes: &[UnattributedShape]) {
    println!();
    println!("Observations attribution could not place:");
    if shapes.is_empty() {
        println!("  (none)");
        return;
    }
    for shape in shapes {
        println!(
            "  {} observation(s)  {}",
            shape.observations,
            shape.reason.as_str()
        );
        println!("     {}", shape.reason.explanation());
        if let Some(service) = &shape.service {
            println!("     service {service}");
        }
        if let Some(route) = &shape.route {
            println!("     route {route}");
        }
        if !shape.attribute_keys.is_empty() {
            println!("     attributes {}", shape.attribute_keys.join(", "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::runtime::{
        Anchor, AttributionPath, EdgeKind, Endpoint, Percentiles, UnattributedReason,
    };

    fn snapshot() -> RuntimeSnapshot {
        RuntimeSnapshot {
            id: "runtime-snapshot:x".to_string(),
            source_digest: "digest".to_string(),
            witnesses: WitnessMode::Hashed,
            provider: "file".to_string(),
            format: "otlp-json".to_string(),
            query: None,
            window: None,
            observations: 10,
            attributed: 7,
            by_path: vec![
                PathAttribution {
                    path: AttributionPath::Route,
                    observations: 2,
                },
                PathAttribution {
                    path: AttributionPath::Schema,
                    observations: 3,
                },
                PathAttribution {
                    path: AttributionPath::CodeAttribute,
                    observations: 2,
                },
            ],
            route_joins: RouteJoinCounts {
                exact: 5,
                mount_suffix: 2,
            },
            sampling: SamplingSummary::default(),
            points: vec![
                PointFact {
                    anchor: Anchor {
                        file: "src/a.ts".to_string(),
                        symbol: None,
                        line: Some(1),
                    },
                    path: AttributionPath::Route,
                    calls: 2,
                    errors: 0,
                    estimated_calls: None,
                    latency: Some(Percentiles {
                        p50_ns: 1_000_000,
                        p95_ns: 2_000_000,
                        p99_ns: 3_000_000,
                    }),
                },
                PointFact {
                    anchor: Anchor {
                        file: "src/b.ts".to_string(),
                        symbol: None,
                        line: Some(2),
                    },
                    path: AttributionPath::CodeAttribute,
                    calls: 5,
                    errors: 1,
                    estimated_calls: None,
                    latency: None,
                },
            ],
            edges: vec![EdgeFact {
                from: Endpoint::file("src/a.ts".to_string()),
                to: Endpoint::table("orders".to_string()),
                kind: EdgeKind::Db,
                path: AttributionPath::Schema,
                calls: 3,
                errors: 0,
                estimated_calls: None,
                witnesses: Vec::new(),
            }],
            unattributed: vec![UnattributedShape {
                reason: UnattributedReason::NoJoinKey,
                service: None,
                route: None,
                attribute_keys: Vec::new(),
                observations: 3,
            }],
        }
    }

    #[test]
    fn no_import_reports_absence_rather_than_an_empty_result() {
        let report = build_report(None, Vec::new(), true, 10);

        assert!(!report.has_evidence);
        assert!(report.snapshot.is_none());
        assert!(report.points.is_empty());
    }

    #[test]
    fn the_report_ranks_anchors_by_calls_and_breaks_ties_on_the_anchor() {
        let report = build_report(Some(snapshot()), Vec::new(), false, 0);

        assert_eq!(report.points[0].anchor.file, "src/b.ts");
        assert_eq!(report.points[1].anchor.file, "src/a.ts");
    }

    #[test]
    fn the_unattributed_shapes_are_withheld_until_they_are_asked_for() {
        let quiet = build_report(Some(snapshot()), Vec::new(), false, 0);
        assert!(quiet.unattributed.is_empty());

        let asked = build_report(Some(snapshot()), Vec::new(), true, 0);
        assert_eq!(asked.unattributed.len(), 1);
    }

    #[test]
    fn a_limit_cuts_the_rows_printed_and_zero_prints_all_of_them() {
        assert_eq!(
            build_report(Some(snapshot()), Vec::new(), true, 1)
                .points
                .len(),
            1
        );
        assert_eq!(
            build_report(Some(snapshot()), Vec::new(), true, 0)
                .points
                .len(),
            2
        );
    }

    #[test]
    fn the_per_path_breakdown_sums_to_the_attributed_count() {
        let snapshot = snapshot();
        let total: u64 = snapshot
            .by_path
            .iter()
            .map(|entry| entry.observations)
            .sum();

        assert_eq!(
            total, snapshot.attributed,
            "the schema path anchors nothing, so a breakdown derived from the point facts \
             alone would silently lose every database span"
        );
        assert_eq!(snapshot.attributed_by_path(AttributionPath::Schema), 3);
        assert_eq!(snapshot.attributed_by_path(AttributionPath::Profile), 0);
    }

    #[test]
    fn an_absent_attribution_rate_renders_as_unknown_rather_than_zero() {
        assert_eq!(percent(None), "n/a");
        assert_eq!(percent(Some(0.737)), "73.7%");
    }

    #[test]
    fn stdin_and_a_path_pick_different_default_providers() {
        assert_eq!(default_provider("-"), "stdin");
        assert_eq!(default_provider("export.json"), "file");
    }
}
