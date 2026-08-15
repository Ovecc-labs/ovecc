//! Runtime-evidence persistence and the index views the attribution chain
//! joins against.
//!
//! Every read here ends in an explicit total `ORDER BY`. DuckDB preserves
//! insertion order through a single-table scan but not through a join, a
//! `GROUP BY`, or a `UNION`, so an implicit order would let the same snapshot
//! render differently between runs. Aggregation stays on integers: the
//! percentiles were computed exactly at import time, so no floating-point
//! aggregate and no approximate quantile function is ever called.

use crate::{ArchitectureStore, collect_rows};
use anyhow::Result;
use chrono::Utc;
use duckdb::{Transaction, params};
use ovecc_core::runtime::{
    Anchor, AttributionPath, EdgeFact, EdgeKind, Endpoint, EndpointKind, PathAttribution,
    Percentiles, PointFact, RouteJoinCounts, RuntimeSnapshot, RuntimeWindow, SamplingSummary,
    UnattributedReason, UnattributedShape, WitnessMode,
};
use ovecc_core::util::stable_id;
use std::collections::BTreeMap;

const LIST_SEPARATOR: char = ',';

/// One HTTP route as the runtime attribution chain needs it: the declared
/// path plus where the handler lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow {
    pub method: Option<String>,
    pub path: String,
    pub file_path: String,
    pub symbol: Option<String>,
    pub line: Option<u32>,
}

impl ArchitectureStore {
    /// HTTP routes anchored at their handler, ordered so the view the
    /// attributors build is identical on every run.
    ///
    /// Reached through `handler_symbol_id` rather than the api row's own
    /// evidence file, which the indexer leaves null: the handler's file is
    /// also the better anchor, since that is the code the request ran. A route
    /// whose handler did not resolve carries no file and is not offered to the
    /// join — `runtime import` reports how many routes it was given, so a low
    /// attribution rate never has to be guessed at.
    pub fn indexed_routes(&self, repository_id: &str) -> Result<Vec<RouteRow>> {
        let mut statement = self.conn.prepare(
            "SELECT a.method, a.path, f.path, s.qualified_name,
                    COALESCE(s.start_line, a.evidence_line)
             FROM apis a
             JOIN symbols s ON s.id = a.handler_symbol_id AND s.repository_id = a.repository_id
             JOIN files f ON f.id = s.file_id AND f.repository_id = s.repository_id
             WHERE a.repository_id = ?
               AND a.api_kind = 'http_route'
               AND a.path IS NOT NULL
             ORDER BY f.path, a.path, a.method, s.qualified_name",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(RouteRow {
                method: row.get(0)?,
                path: row.get(1)?,
                file_path: row.get(2)?,
                symbol: row.get(3)?,
                line: row.get::<_, Option<i64>>(4)?.map(|line| line as u32),
            })
        })?;
        collect_rows(rows)
    }

    /// Names of the schema objects a database span can join to.
    pub fn indexed_table_names(&self, repository_id: &str) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT name
             FROM schema_objects
             WHERE repository_id = ? AND schema_kind IN ('table', 'view')
             ORDER BY name",
        )?;
        let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    pub fn indexed_file_paths(&self, repository_id: &str) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT path FROM files WHERE repository_id = ? ORDER BY path")?;
        let rows = statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    /// Identity of the evidence currently stored, so a re-import that would
    /// write the same rows is recognized before anything is written. Compared
    /// on the snapshot id rather than the source digest: the same bytes
    /// imported with `--witnesses` are different evidence.
    pub fn runtime_snapshot_id(&self, repository_id: &str) -> Result<Option<String>> {
        let mut statement = self.conn.prepare(
            "SELECT id FROM runtime_snapshots
             WHERE repository_id = ? ORDER BY id LIMIT 1",
        )?;
        let mut rows =
            statement.query_map(params![repository_id], |row| row.get::<_, String>(0))?;
        rows.next().transpose().map_err(Into::into)
    }

    /// Swaps in one import's evidence. Wholesale, like coverage: a runtime
    /// snapshot is one sampled window, and merging two windows would produce
    /// counts that describe no period anybody chose.
    pub fn replace_runtime_snapshot(
        &mut self,
        repository_id: &str,
        snapshot: &RuntimeSnapshot,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for table in [
            "runtime_unattributed",
            "runtime_edges",
            "runtime_points",
            "runtime_snapshots",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE repository_id = ?"),
                params![repository_id],
            )?;
        }
        insert_snapshot_row(&tx, repository_id, snapshot)?;
        append_points(&tx, repository_id, snapshot)?;
        append_edges(&tx, repository_id, snapshot)?;
        append_unattributed(&tx, repository_id, snapshot)?;
        tx.commit()?;
        Ok(())
    }

    /// The stored evidence, or `None` when no import has run. Absence is not
    /// "nothing ran": it is "nobody looked".
    pub fn runtime_snapshot(&self, repository_id: &str) -> Result<Option<RuntimeSnapshot>> {
        let Some(mut snapshot) = self.runtime_snapshot_header(repository_id)? else {
            return Ok(None);
        };
        snapshot.points = self.runtime_points(repository_id)?;
        snapshot.edges = self.runtime_edges(repository_id)?;
        snapshot.unattributed = self.runtime_unattributed(repository_id)?;
        Ok(Some(snapshot))
    }

    fn runtime_snapshot_header(&self, repository_id: &str) -> Result<Option<RuntimeSnapshot>> {
        let mut statement = self.conn.prepare(
            "SELECT id, source_digest, provider, format, query,
                    window_start_unix_nano, window_end_unix_nano,
                    observations, attributed, route_joins_exact, route_joins_mount_suffix,
                    sampling_known, sampling_unknown, sampling_distinct_rates,
                    sampling_modal_adjusted_count, witness_mode, attributed_by_path
             FROM runtime_snapshots
             WHERE repository_id = ?
             ORDER BY id
             LIMIT 1",
        )?;
        let mut rows = statement.query_map(params![repository_id], |row| {
            let start: Option<i64> = row.get(5)?;
            let end: Option<i64> = row.get(6)?;
            Ok(RuntimeSnapshot {
                id: row.get(0)?,
                source_digest: row.get(1)?,
                witnesses: WitnessMode::parse(&row.get::<_, String>(15)?)
                    .unwrap_or(WitnessMode::Hashed),
                provider: row.get(2)?,
                format: row.get(3)?,
                query: row.get(4)?,
                window: start.zip(end).map(|(start, end)| RuntimeWindow {
                    start_unix_nano: start as u64,
                    end_unix_nano: end as u64,
                }),
                observations: row.get::<_, i64>(7)? as u64,
                attributed: row.get::<_, i64>(8)? as u64,
                by_path: decode_path_attributions(&row.get::<_, String>(16)?),
                route_joins: RouteJoinCounts {
                    exact: row.get::<_, i64>(9)? as u64,
                    mount_suffix: row.get::<_, i64>(10)? as u64,
                },
                sampling: SamplingSummary {
                    known: row.get::<_, i64>(11)? as u64,
                    unknown: row.get::<_, i64>(12)? as u64,
                    distinct_rates: row.get::<_, i64>(13)? as usize,
                    modal_adjusted_count: row.get::<_, Option<i64>>(14)?.map(|count| count as u64),
                },
                points: Vec::new(),
                edges: Vec::new(),
                unattributed: Vec::new(),
            })
        })?;
        rows.next().transpose().map_err(Into::into)
    }

    pub fn runtime_points(&self, repository_id: &str) -> Result<Vec<PointFact>> {
        let mut statement = self.conn.prepare(
            "SELECT file_path, symbol, line, attribution_path, calls, errors, estimated_calls,
                    latency_p50_ns, latency_p95_ns, latency_p99_ns
             FROM runtime_points
             WHERE repository_id = ?
             ORDER BY file_path, symbol, line, attribution_path",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            let p50: Option<i64> = row.get(7)?;
            Ok(PointFact {
                anchor: Anchor {
                    file: row.get(0)?,
                    symbol: row.get(1)?,
                    line: row.get::<_, Option<i64>>(2)?.map(|line| line as u32),
                },
                path: AttributionPath::parse(&row.get::<_, String>(3)?)
                    .unwrap_or(AttributionPath::Service),
                calls: row.get::<_, i64>(4)? as u64,
                errors: row.get::<_, i64>(5)? as u64,
                estimated_calls: row.get::<_, Option<i64>>(6)?.map(|count| count as u64),
                latency: p50.map(|p50| Percentiles {
                    p50_ns: p50 as u64,
                    p95_ns: row.get::<_, i64>(8).unwrap_or(p50) as u64,
                    p99_ns: row.get::<_, i64>(9).unwrap_or(p50) as u64,
                }),
            })
        })?;
        collect_rows(rows)
    }

    pub fn runtime_edges(&self, repository_id: &str) -> Result<Vec<EdgeFact>> {
        let mut statement = self.conn.prepare(
            "SELECT from_kind, from_name, to_kind, to_name, edge_kind, attribution_path,
                    calls, errors, estimated_calls, witnesses
             FROM runtime_edges
             WHERE repository_id = ?
             ORDER BY from_kind, from_name, to_kind, to_name, edge_kind, attribution_path",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(EdgeFact {
                from: endpoint(row.get::<_, String>(0)?, row.get(1)?),
                to: endpoint(row.get::<_, String>(2)?, row.get(3)?),
                kind: EdgeKind::parse(&row.get::<_, String>(4)?).unwrap_or(EdgeKind::Internal),
                path: AttributionPath::parse(&row.get::<_, String>(5)?)
                    .unwrap_or(AttributionPath::Service),
                calls: row.get::<_, i64>(6)? as u64,
                errors: row.get::<_, i64>(7)? as u64,
                estimated_calls: row.get::<_, Option<i64>>(8)?.map(|count| count as u64),
                witnesses: split_list(&row.get::<_, String>(9)?),
            })
        })?;
        collect_rows(rows)
    }

    pub fn runtime_unattributed(&self, repository_id: &str) -> Result<Vec<UnattributedShape>> {
        let mut statement = self.conn.prepare(
            "SELECT reason, service, route, attribute_keys, observations
             FROM runtime_unattributed
             WHERE repository_id = ?
             ORDER BY observations DESC, reason, service, route, attribute_keys",
        )?;
        let rows = statement.query_map(params![repository_id], |row| {
            Ok(UnattributedShape {
                reason: UnattributedReason::parse(&row.get::<_, String>(0)?)
                    .unwrap_or(UnattributedReason::NoJoinKey),
                service: row.get(1)?,
                route: row.get(2)?,
                attribute_keys: split_list(&row.get::<_, String>(3)?),
                observations: row.get::<_, i64>(4)? as u64,
            })
        })?;
        collect_rows(rows)
    }
}

fn endpoint(kind: String, name: String) -> Endpoint {
    Endpoint {
        kind: EndpointKind::parse(&kind).unwrap_or(EndpointKind::Service),
        name,
    }
}

fn split_list(joined: &str) -> Vec<String> {
    joined
        .split(LIST_SEPARATOR)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn join_list(entries: &[String]) -> String {
    entries.join(&LIST_SEPARATOR.to_string())
}

/// `route=8110,schema=994` — one column rather than a fourth table, matching
/// how `co_changes.commit_shas` already carries a short list.
fn encode_path_attributions(entries: &[PathAttribution]) -> String {
    let pairs: Vec<String> = entries
        .iter()
        .map(|entry| format!("{}={}", entry.path.as_str(), entry.observations))
        .collect();
    join_list(&pairs)
}

fn decode_path_attributions(encoded: &str) -> Vec<PathAttribution> {
    let counts: BTreeMap<AttributionPath, u64> = encoded
        .split(LIST_SEPARATOR)
        .filter_map(|pair| pair.split_once('='))
        .filter_map(|(path, count)| Some((AttributionPath::parse(path)?, count.parse().ok()?)))
        .collect();
    AttributionPath::ORDERED
        .iter()
        .filter_map(|path| {
            counts.get(path).map(|observations| PathAttribution {
                path: *path,
                observations: *observations,
            })
        })
        .collect()
}

fn insert_snapshot_row(
    tx: &Transaction<'_>,
    repository_id: &str,
    snapshot: &RuntimeSnapshot,
) -> Result<()> {
    tx.execute(
        "INSERT INTO runtime_snapshots (
             id, repository_id, source_digest, witness_mode, provider, format, query,
             window_start_unix_nano, window_end_unix_nano, observations, attributed,
             attributed_by_path, route_joins_exact, route_joins_mount_suffix,
             sampling_known, sampling_unknown, sampling_distinct_rates,
             sampling_modal_adjusted_count, imported_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            snapshot.id,
            repository_id,
            snapshot.source_digest,
            snapshot.witnesses.as_str(),
            snapshot.provider,
            snapshot.format,
            snapshot.query,
            snapshot.window.map(|window| window.start_unix_nano as i64),
            snapshot.window.map(|window| window.end_unix_nano as i64),
            snapshot.observations as i64,
            snapshot.attributed as i64,
            encode_path_attributions(&snapshot.by_path),
            snapshot.route_joins.exact as i64,
            snapshot.route_joins.mount_suffix as i64,
            snapshot.sampling.known as i64,
            snapshot.sampling.unknown as i64,
            snapshot.sampling.distinct_rates as i64,
            snapshot
                .sampling
                .modal_adjusted_count
                .map(|count| count as i64),
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn append_points(
    tx: &Transaction<'_>,
    repository_id: &str,
    snapshot: &RuntimeSnapshot,
) -> Result<()> {
    let mut appender = tx.appender("runtime_points")?;
    for point in &snapshot.points {
        let line = point.anchor.line.map(i64::from);
        appender.append_row(params![
            stable_id(
                "runtime-point",
                &[
                    &snapshot.id,
                    &point.anchor.file,
                    point.anchor.symbol.as_deref().unwrap_or_default(),
                    &line.unwrap_or(-1).to_string(),
                    point.path.as_str(),
                ]
            ),
            repository_id,
            snapshot.id,
            point.anchor.file,
            point.anchor.symbol,
            line,
            point.path.as_str(),
            point.calls as i64,
            point.errors as i64,
            point.estimated_calls.map(|count| count as i64),
            point.latency.map(|latency| latency.p50_ns as i64),
            point.latency.map(|latency| latency.p95_ns as i64),
            point.latency.map(|latency| latency.p99_ns as i64),
        ])?;
    }
    Ok(())
}

fn append_edges(
    tx: &Transaction<'_>,
    repository_id: &str,
    snapshot: &RuntimeSnapshot,
) -> Result<()> {
    let mut appender = tx.appender("runtime_edges")?;
    for edge in &snapshot.edges {
        appender.append_row(params![
            stable_id(
                "runtime-edge",
                &[
                    &snapshot.id,
                    edge.from.kind.as_str(),
                    &edge.from.name,
                    edge.to.kind.as_str(),
                    &edge.to.name,
                    edge.kind.as_str(),
                    edge.path.as_str(),
                ]
            ),
            repository_id,
            snapshot.id,
            edge.from.kind.as_str(),
            edge.from.name,
            edge.to.kind.as_str(),
            edge.to.name,
            edge.kind.as_str(),
            edge.path.as_str(),
            edge.calls as i64,
            edge.errors as i64,
            edge.estimated_calls.map(|count| count as i64),
            join_list(&edge.witnesses),
        ])?;
    }
    Ok(())
}

fn append_unattributed(
    tx: &Transaction<'_>,
    repository_id: &str,
    snapshot: &RuntimeSnapshot,
) -> Result<()> {
    let mut appender = tx.appender("runtime_unattributed")?;
    for shape in &snapshot.unattributed {
        let keys = join_list(&shape.attribute_keys);
        appender.append_row(params![
            stable_id(
                "runtime-shape",
                &[
                    &snapshot.id,
                    shape.reason.as_str(),
                    shape.service.as_deref().unwrap_or_default(),
                    shape.route.as_deref().unwrap_or_default(),
                    &keys,
                ]
            ),
            repository_id,
            snapshot.id,
            shape.reason.as_str(),
            shape.service,
            shape.route,
            keys,
            shape.observations as i64,
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn sample_snapshot() -> RuntimeSnapshot {
        RuntimeSnapshot {
            id: RuntimeSnapshot::snapshot_id("repo:test", "digest-one", WitnessMode::Hashed),
            source_digest: "digest-one".to_string(),
            witnesses: WitnessMode::Hashed,
            provider: "file".to_string(),
            format: "otlp-json".to_string(),
            query: Some("--since 24h".to_string()),
            window: Some(RuntimeWindow {
                start_unix_nano: 1_700_000_000_000_000_000,
                end_unix_nano: 1_700_000_600_000_000_000,
            }),
            observations: 12,
            attributed: 9,
            by_path: vec![
                PathAttribution {
                    path: AttributionPath::Route,
                    observations: 8,
                },
                PathAttribution {
                    path: AttributionPath::Schema,
                    observations: 1,
                },
            ],
            route_joins: RouteJoinCounts {
                exact: 5,
                mount_suffix: 3,
            },
            sampling: SamplingSummary {
                known: 8,
                unknown: 4,
                distinct_rates: 2,
                modal_adjusted_count: Some(4),
            },
            points: vec![PointFact {
                anchor: Anchor {
                    file: "src/orders/routes.ts".to_string(),
                    symbol: Some("getOrder".to_string()),
                    line: Some(12),
                },
                path: AttributionPath::Route,
                calls: 9,
                errors: 1,
                estimated_calls: Some(36),
                latency: Some(Percentiles {
                    p50_ns: 1_000,
                    p95_ns: 9_000,
                    p99_ns: 12_000,
                }),
            }],
            edges: vec![EdgeFact {
                from: Endpoint::file("src/users/routes.ts".to_string()),
                to: Endpoint::table("orders".to_string()),
                kind: EdgeKind::Db,
                path: AttributionPath::Schema,
                calls: 40_000,
                errors: 0,
                estimated_calls: None,
                witnesses: vec!["aabbccdd".to_string(), "eeff0011".to_string()],
            }],
            unattributed: vec![UnattributedShape {
                reason: UnattributedReason::RouteNotIndexed,
                service: Some("legacy".to_string()),
                route: Some("/admin/{}".to_string()),
                attribute_keys: vec!["http.route".to_string()],
                observations: 3,
            }],
        }
    }

    #[test]
    fn a_snapshot_round_trips_through_storage_unchanged() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let snapshot = sample_snapshot();

        store
            .replace_runtime_snapshot("repo:test", &snapshot)
            .unwrap();
        let loaded = store.runtime_snapshot("repo:test").unwrap().unwrap();

        assert_eq!(loaded, snapshot);
    }

    #[test]
    fn a_second_import_replaces_the_first_rather_than_merging_two_windows() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        store
            .replace_runtime_snapshot("repo:test", &sample_snapshot())
            .unwrap();

        let mut second = sample_snapshot();
        second.source_digest = "digest-two".to_string();
        second.id = RuntimeSnapshot::snapshot_id("repo:test", "digest-two", WitnessMode::Hashed);
        second.points.clear();
        second.edges.clear();
        second.unattributed.clear();
        store
            .replace_runtime_snapshot("repo:test", &second)
            .unwrap();

        let loaded = store.runtime_snapshot("repo:test").unwrap().unwrap();
        assert_eq!(loaded.source_digest, "digest-two");
        assert!(
            loaded.points.is_empty(),
            "the first window's facts are gone"
        );
        assert_eq!(count(&store, "SELECT count(*) FROM runtime_points"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM runtime_snapshots"), 1);
    }

    #[test]
    fn no_import_reads_back_as_absence_rather_than_an_empty_window() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();

        assert_eq!(store.runtime_snapshot("repo:test").unwrap(), None);
        assert_eq!(store.runtime_snapshot_id("repo:test").unwrap(), None);
    }

    #[test]
    fn the_stored_identity_covers_the_witness_mode_not_only_the_bytes() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        let hashed = sample_snapshot();
        store
            .replace_runtime_snapshot("repo:test", &hashed)
            .unwrap();

        assert_eq!(
            store.runtime_snapshot_id("repo:test").unwrap().as_deref(),
            Some(hashed.id.as_str())
        );

        let raw = RuntimeSnapshot {
            id: RuntimeSnapshot::snapshot_id("repo:test", "digest-one", WitnessMode::Raw),
            witnesses: WitnessMode::Raw,
            ..sample_snapshot()
        };
        assert_ne!(
            raw.id, hashed.id,
            "the same bytes stored with raw trace ids must not read as unchanged"
        );
        store.replace_runtime_snapshot("repo:test", &raw).unwrap();
        assert_eq!(
            store
                .runtime_snapshot("repo:test")
                .unwrap()
                .unwrap()
                .witnesses,
            WitnessMode::Raw
        );
    }

    #[test]
    fn one_repositorys_evidence_is_untouched_when_another_imports() {
        let (_dir, mut store) = temp_store();
        store.migrate_to_latest().unwrap();
        store
            .replace_runtime_snapshot("repo:test", &sample_snapshot())
            .unwrap();

        let mut other = sample_snapshot();
        other.id = RuntimeSnapshot::snapshot_id("repo:other", "digest-one", WitnessMode::Hashed);
        store
            .replace_runtime_snapshot("repo:other", &other)
            .unwrap();

        assert!(store.runtime_snapshot("repo:test").unwrap().is_some());
        assert!(store.runtime_snapshot("repo:other").unwrap().is_some());
        assert_eq!(count(&store, "SELECT count(*) FROM runtime_points"), 2);
    }

    #[test]
    fn a_witness_list_survives_the_round_trip_through_one_text_column() {
        assert_eq!(split_list(""), Vec::<String>::new());
        assert_eq!(split_list("a,b"), ["a", "b"]);
        assert_eq!(join_list(&["a".to_string(), "b".to_string()]), "a,b");
        assert_eq!(join_list(&[]), "");
    }

    #[test]
    fn the_per_path_breakdown_survives_the_round_trip_and_keeps_the_chain_order() {
        let entries = vec![
            PathAttribution {
                path: AttributionPath::CodeAttribute,
                observations: 7,
            },
            PathAttribution {
                path: AttributionPath::Route,
                observations: 12,
            },
        ];
        let decoded = decode_path_attributions(&encode_path_attributions(&entries));

        assert_eq!(
            decoded.iter().map(|e| e.path).collect::<Vec<_>>(),
            [AttributionPath::Route, AttributionPath::CodeAttribute],
            "read back in attribution-chain order whatever order it was written in"
        );
        assert_eq!(decoded[0].observations, 12);
        assert_eq!(decode_path_attributions(""), Vec::new());
        assert_eq!(decode_path_attributions("nonsense=x,route=3").len(), 1);
    }
}
