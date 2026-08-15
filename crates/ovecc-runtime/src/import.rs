use crate::attribute::{Attribution, IndexView, attribute};
use crate::decode::{self, RawObservation};
use crate::sampling::SamplingAccumulator;
use crate::scrub;
use anyhow::Result;
use ovecc_core::runtime::{
    Anchor, AttributionPath, EdgeFact, EdgeKind, Endpoint, PathAttribution, Percentiles, PointFact,
    RouteJoinCounts, RouteMatch, RuntimeSnapshot, RuntimeWindow, SamplingSummary,
    UnattributedReason, UnattributedShape, WitnessMode,
};
use ovecc_core::util::hash_bytes;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_WITNESSES: usize = 10;
pub const MAX_UNATTRIBUTED_SHAPES: usize = 100;
const MAX_ANCESTOR_WALK: usize = 64;

const REMOTE_TARGET_KEYS: &[&str] = &[
    "peer.service",
    "rpc.service",
    "server.address",
    "net.peer.name",
];
const QUEUE_TARGET_KEY: &str = "messaging.destination.name";
const RPC_KEYS: &[&str] = &["rpc.system", "rpc.service"];
const HTTP_KEYS: &[&str] = &[
    "http.route",
    "http.request.method",
    "http.method",
    "server.address",
    "peer.service",
    "net.peer.name",
];

pub struct ImportOptions<'a> {
    pub repository_id: &'a str,
    pub provider: &'a str,
    pub format: Option<&'a str>,
    pub query: Option<String>,
    pub keep_trace_ids: bool,
}

struct Attributed<'a> {
    observation: &'a RawObservation,
    attribution: Attribution,
}

pub fn import(
    bytes: &[u8],
    index: &IndexView,
    options: &ImportOptions<'_>,
) -> Result<RuntimeSnapshot> {
    let decoder = decode::select(bytes, options.format)?;
    let observations = decoder.decode(bytes)?;
    let attributed: Vec<Attributed<'_>> = observations
        .iter()
        .map(|observation| Attributed {
            observation,
            attribution: attribute(observation, index),
        })
        .collect();
    let source_digest = hash_bytes(bytes);
    let witnesses = WitnessMode::of(options.keep_trace_ids);

    Ok(RuntimeSnapshot {
        id: RuntimeSnapshot::snapshot_id(options.repository_id, &source_digest, witnesses),
        source_digest,
        witnesses,
        provider: options.provider.to_string(),
        format: decoder.id().to_string(),
        query: options.query.clone(),
        window: window_of(&observations),
        observations: observations.len() as u64,
        attributed: attributed
            .iter()
            .filter(|entry| entry.attribution.is_attributed())
            .count() as u64,
        by_path: path_attributions(&attributed),
        route_joins: route_join_counts(&attributed),
        sampling: sampling_summary(&observations),
        points: build_points(&attributed),
        edges: build_edges(&attributed, options.keep_trace_ids),
        unattributed: build_unattributed(&attributed),
    })
}

fn window_of(observations: &[RawObservation]) -> Option<RuntimeWindow> {
    let timed: Vec<&RawObservation> = observations
        .iter()
        .filter(|observation| observation.start_unix_nano > 0)
        .collect();
    Some(RuntimeWindow {
        start_unix_nano: timed
            .iter()
            .map(|observation| observation.start_unix_nano)
            .min()?,
        end_unix_nano: timed
            .iter()
            .map(|observation| observation.end_unix_nano)
            .max()?,
    })
}

fn path_attributions(attributed: &[Attributed<'_>]) -> Vec<PathAttribution> {
    let mut counts: BTreeMap<AttributionPath, u64> = BTreeMap::new();
    for entry in attributed {
        if let Some(path) = entry.attribution.path() {
            *counts.entry(path).or_default() += 1;
        }
    }
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

fn route_join_counts(attributed: &[Attributed<'_>]) -> RouteJoinCounts {
    let mut counts = RouteJoinCounts::default();
    for entry in attributed {
        if let Attribution::Anchored(anchored) = &entry.attribution {
            match anchored.route_match {
                Some(RouteMatch::Exact) => counts.exact += 1,
                Some(RouteMatch::MountSuffix) => counts.mount_suffix += 1,
                None => {}
            }
        }
    }
    counts
}

fn sampling_summary(observations: &[RawObservation]) -> SamplingSummary {
    let mut known = 0;
    let mut unknown = 0;
    let mut frequency: BTreeMap<u64, u64> = BTreeMap::new();
    for observation in observations {
        match observation.sampling {
            Some(threshold) => {
                known += 1;
                *frequency.entry(threshold.adjusted_count()).or_default() += 1;
            }
            None => unknown += 1,
        }
    }
    SamplingSummary {
        known,
        unknown,
        distinct_rates: frequency.len(),
        modal_adjusted_count: frequency
            .iter()
            .max_by_key(|(count, seen)| (**seen, std::cmp::Reverse(**count)))
            .map(|(count, _)| *count),
    }
}

#[derive(Default)]
struct PointAccumulator {
    calls: u64,
    errors: u64,
    durations: Vec<u64>,
    sampling: SamplingAccumulator,
}

impl PointAccumulator {
    fn observe(&mut self, observation: &RawObservation) {
        self.calls += 1;
        self.errors += u64::from(observation.error);
        self.durations.push(observation.duration_ns());
        self.sampling.observe(observation.sampling);
    }

    fn into_fact(mut self, anchor: Anchor, path: AttributionPath) -> PointFact {
        self.durations.sort_unstable();
        PointFact {
            anchor,
            path,
            calls: self.calls,
            errors: self.errors,
            estimated_calls: self.sampling.estimate().value(),
            latency: Percentiles::of_sorted(&self.durations),
        }
    }
}

fn build_points(attributed: &[Attributed<'_>]) -> Vec<PointFact> {
    let mut grouped: BTreeMap<(Anchor, AttributionPath), PointAccumulator> = BTreeMap::new();
    for entry in attributed {
        if let Attribution::Anchored(anchored) = &entry.attribution {
            grouped
                .entry((anchored.anchor.clone(), anchored.path))
                .or_default()
                .observe(entry.observation);
        }
    }
    grouped
        .into_iter()
        .map(|((anchor, path), accumulator)| accumulator.into_fact(anchor, path))
        .collect()
}

#[derive(Default)]
struct EdgeAccumulator {
    calls: u64,
    errors: u64,
    witnesses: BTreeSet<String>,
    sampling: SamplingAccumulator,
}

impl EdgeAccumulator {
    fn observe(&mut self, observation: &RawObservation, keep_trace_ids: bool) {
        self.calls += 1;
        self.errors += u64::from(observation.error);
        self.sampling.observe(observation.sampling);
        if !observation.trace_id.is_empty() && self.witnesses.len() < MAX_WITNESSES {
            self.witnesses
                .insert(scrub::witness(&observation.trace_id, keep_trace_ids));
        }
    }

    fn into_fact(self, key: EdgeKey) -> EdgeFact {
        EdgeFact {
            from: key.from,
            to: key.to,
            kind: key.kind,
            path: key.path,
            calls: self.calls,
            errors: self.errors,
            estimated_calls: self.sampling.estimate().value(),
            witnesses: self.witnesses.into_iter().collect(),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    from: Endpoint,
    to: Endpoint,
    kind: EdgeKind,
    path: AttributionPath,
}

struct SpanGraph<'a> {
    attributed: &'a [Attributed<'a>],
    by_span_id: BTreeMap<&'a str, usize>,
}

impl<'a> SpanGraph<'a> {
    fn new(attributed: &'a [Attributed<'a>]) -> Self {
        let mut by_span_id = BTreeMap::new();
        for (position, entry) in attributed.iter().enumerate() {
            by_span_id
                .entry(entry.observation.span_id.as_str())
                .or_insert(position);
        }
        Self {
            attributed,
            by_span_id,
        }
    }

    fn ancestors(&self, position: usize) -> Vec<&'a Attributed<'a>> {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = self.attributed[position]
            .observation
            .parent_span_id
            .as_deref();
        while let Some(parent_id) = current {
            if chain.len() >= MAX_ANCESTOR_WALK || !seen.insert(parent_id) {
                break;
            }
            let Some(&parent) = self.by_span_id.get(parent_id) else {
                break;
            };
            chain.push(&self.attributed[parent]);
            current = self.attributed[parent]
                .observation
                .parent_span_id
                .as_deref();
        }
        chain
    }

    fn source_endpoint(&self, position: usize) -> Option<Endpoint> {
        let entry = &self.attributed[position];
        let chain = self.ancestors(position);
        if let Some(anchored) = chain.iter().find_map(|parent| parent.attribution.anchor()) {
            return Some(Endpoint::file(anchored.file.clone()));
        }
        if let Some(service) = chain.iter().find_map(|parent| {
            parent
                .observation
                .service
                .as_ref()
                .filter(|service| Some(*service) != entry.observation.service.as_ref())
        }) {
            return Some(Endpoint::service(service.clone()));
        }
        if let Some(anchored) = entry.attribution.anchor() {
            return Some(Endpoint::file(anchored.file.clone()));
        }
        entry.observation.service.clone().map(Endpoint::service)
    }
}

fn target_endpoint(entry: &Attributed<'_>) -> Option<Endpoint> {
    match &entry.attribution {
        Attribution::Table(name) => Some(Endpoint::table(name.clone())),
        Attribution::Anchored(anchored) if entry.observation.kind.is_inbound() => {
            Some(Endpoint::file(anchored.anchor.file.clone()))
        }
        _ => remote_endpoint(entry.observation),
    }
}

fn remote_endpoint(observation: &RawObservation) -> Option<Endpoint> {
    if !observation.kind.is_outbound() {
        return None;
    }
    observation
        .attribute(QUEUE_TARGET_KEY)
        .or_else(|| observation.first_attribute(REMOTE_TARGET_KEYS))
        .map(Endpoint::service)
}

fn edge_kind(entry: &Attributed<'_>, to: &Endpoint) -> EdgeKind {
    use ovecc_core::runtime::EndpointKind;
    if to.kind == EndpointKind::Table {
        return EdgeKind::Db;
    }
    let observation = entry.observation;
    if observation.attribute(QUEUE_TARGET_KEY).is_some()
        || observation.attribute("messaging.system").is_some()
    {
        return EdgeKind::Queue;
    }
    if observation.first_attribute(RPC_KEYS).is_some() {
        return EdgeKind::Rpc;
    }
    if observation.first_attribute(HTTP_KEYS).is_some() {
        return EdgeKind::Http;
    }
    EdgeKind::Internal
}

fn build_edges(attributed: &[Attributed<'_>], keep_trace_ids: bool) -> Vec<EdgeFact> {
    let graph = SpanGraph::new(attributed);
    let mut grouped: BTreeMap<EdgeKey, EdgeAccumulator> = BTreeMap::new();
    for (position, entry) in attributed.iter().enumerate() {
        let Some(to) = target_endpoint(entry) else {
            continue;
        };
        let kind = edge_kind(entry, &to);
        if kind == EdgeKind::Internal {
            continue;
        }
        let Some(from) = graph.source_endpoint(position) else {
            continue;
        };
        if from == to {
            continue;
        }
        let path = entry.attribution.path().unwrap_or(AttributionPath::Service);
        grouped
            .entry(EdgeKey {
                from,
                to,
                kind,
                path,
            })
            .or_default()
            .observe(entry.observation, keep_trace_ids);
    }
    grouped
        .into_iter()
        .map(|(key, accumulator)| accumulator.into_fact(key))
        .collect()
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ShapeKey {
    reason: UnattributedReason,
    service: Option<String>,
    route: Option<String>,
    attribute_keys: Vec<String>,
}

fn build_unattributed(attributed: &[Attributed<'_>]) -> Vec<UnattributedShape> {
    let mut grouped: BTreeMap<ShapeKey, u64> = BTreeMap::new();
    for entry in attributed {
        let Attribution::Unattributed(reason) = entry.attribution else {
            continue;
        };
        let key = ShapeKey {
            reason,
            service: entry.observation.service.clone(),
            route: entry
                .observation
                .attribute("http.route")
                .map(str::to_string),
            attribute_keys: entry.observation.attribute_keys(),
        };
        *grouped.entry(key).or_default() += 1;
    }
    let mut shapes: Vec<UnattributedShape> = grouped
        .into_iter()
        .map(|(key, observations)| UnattributedShape {
            reason: key.reason,
            service: key.service,
            route: key.route,
            attribute_keys: key.attribute_keys,
            observations,
        })
        .collect();
    shapes.sort_by(|left, right| {
        right
            .observations
            .cmp(&left.observations)
            .then_with(|| left.reason.cmp(&right.reason))
            .then_with(|| left.service.cmp(&right.service))
            .then_with(|| left.route.cmp(&right.route))
            .then_with(|| left.attribute_keys.cmp(&right.attribute_keys))
    });
    shapes.truncate(MAX_UNATTRIBUTED_SHAPES);
    shapes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::IndexedRoute;
    use ovecc_core::runtime::EndpointKind;

    fn index() -> IndexView {
        IndexView::new(
            vec![
                IndexedRoute {
                    method: Some("GET".to_string()),
                    path: "/orders/:id".to_string(),
                    file: "src/orders/routes.ts".to_string(),
                    symbol: Some("getOrder".to_string()),
                    line: Some(12),
                },
                IndexedRoute {
                    method: Some("GET".to_string()),
                    path: "/users/:id".to_string(),
                    file: "src/users/routes.ts".to_string(),
                    symbol: Some("getUser".to_string()),
                    line: Some(7),
                },
            ],
            vec!["orders".to_string()],
            vec![
                "src/orders/routes.ts".to_string(),
                "src/users/routes.ts".to_string(),
            ],
        )
    }

    fn options() -> ImportOptions<'static> {
        ImportOptions {
            repository_id: "repo:test",
            provider: "file",
            format: None,
            query: None,
            keep_trace_ids: false,
        }
    }

    fn span(
        service: &str,
        span_id: &str,
        parent: Option<&str>,
        kind: u8,
        attributes: &[(&str, &str)],
    ) -> String {
        let attributes: Vec<String> = attributes
            .iter()
            .map(|(key, value)| format!(r#"{{"key":"{key}","value":{{"stringValue":"{value}"}}}}"#))
            .collect();
        let parent = parent.map_or(String::new(), |id| format!(r#""parentSpanId":"{id}","#));
        format!(
            r#"{{"resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"{service}"}}}}]}},
               "scopeSpans":[{{"spans":[{{
                 "traceId":"4bf92f3577b34da6a3ce929d0e0e4736","spanId":"{span_id}",{parent}
                 "kind":{kind},"traceState":"ot=th:0",
                 "startTimeUnixNano":"1000","endTimeUnixNano":"3000",
                 "attributes":[{}]}}]}}]}}"#,
            attributes.join(",")
        )
    }

    fn payload(resource_spans: &[String]) -> String {
        format!(r#"{{"resourceSpans":[{}]}}"#, resource_spans.join(","))
    }

    #[test]
    fn a_cross_service_call_becomes_an_edge_between_the_two_handlers() {
        let bytes = payload(&[
            span(
                "users",
                "a1",
                None,
                2,
                &[
                    ("http.route", "/users/{id}"),
                    ("http.request.method", "GET"),
                ],
            ),
            span(
                "users",
                "b1",
                Some("a1"),
                3,
                &[("server.address", "orders")],
            ),
            span(
                "orders",
                "c1",
                Some("b1"),
                2,
                &[
                    ("http.route", "/orders/{id}"),
                    ("http.request.method", "GET"),
                ],
            ),
        ]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        let handler_edge = snapshot
            .edges
            .iter()
            .find(|edge| edge.to == Endpoint::file("src/orders/routes.ts".to_string()))
            .expect("the cross-service call should be an edge");
        assert_eq!(
            handler_edge.from,
            Endpoint::file("src/users/routes.ts".to_string())
        );
        assert_eq!(handler_edge.kind, EdgeKind::Http);
        assert_eq!(handler_edge.calls, 1);
        assert_eq!(handler_edge.witnesses.len(), 1);
    }

    #[test]
    fn a_database_span_becomes_an_edge_from_the_handler_that_issued_it() {
        let bytes = payload(&[
            span(
                "orders",
                "a1",
                None,
                2,
                &[
                    ("http.route", "/orders/{id}"),
                    ("http.request.method", "GET"),
                ],
            ),
            span(
                "orders",
                "b1",
                Some("a1"),
                3,
                &[("db.collection.name", "orders")],
            ),
        ]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        let db_edge = snapshot
            .edges
            .iter()
            .find(|edge| edge.to.kind == EndpointKind::Table)
            .expect("the database call should be an edge");
        assert_eq!(
            db_edge.from,
            Endpoint::file("src/orders/routes.ts".to_string())
        );
        assert_eq!(db_edge.to, Endpoint::table("orders".to_string()));
        assert_eq!(db_edge.kind, EdgeKind::Db);
        assert_eq!(db_edge.path, AttributionPath::Schema);
    }

    #[test]
    fn an_unparented_outbound_call_still_names_its_own_service_as_the_source() {
        let bytes = payload(&[span(
            "worker",
            "a1",
            None,
            3,
            &[
                ("server.address", "billing"),
                ("http.request.method", "POST"),
            ],
        )]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.edges[0].from, Endpoint::service("worker"));
        assert_eq!(snapshot.edges[0].to, Endpoint::service("billing"));
    }

    #[test]
    fn point_facts_carry_exact_integer_percentiles_per_anchor() {
        let bytes = payload(&[
            span(
                "orders",
                "a1",
                None,
                2,
                &[
                    ("http.route", "/orders/{id}"),
                    ("http.request.method", "GET"),
                ],
            ),
            span(
                "orders",
                "a2",
                None,
                2,
                &[
                    ("http.route", "/orders/{id}"),
                    ("http.request.method", "GET"),
                ],
            ),
        ]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.points.len(), 1);
        let point = &snapshot.points[0];
        assert_eq!(point.anchor.file, "src/orders/routes.ts");
        assert_eq!(point.anchor.symbol.as_deref(), Some("getOrder"));
        assert_eq!(point.calls, 2);
        assert_eq!(point.latency.unwrap().p50_ns, 2000);
        assert_eq!(point.estimated_calls, Some(2));
    }

    #[test]
    fn the_same_bytes_import_to_a_byte_identical_snapshot() {
        let bytes = payload(&[
            span("users", "a1", None, 2, &[("http.route", "/users/{id}")]),
            span(
                "users",
                "b1",
                Some("a1"),
                3,
                &[("db.collection.name", "orders")],
            ),
            span(
                "users",
                "c1",
                Some("a1"),
                3,
                &[("server.address", "orders")],
            ),
        ]);

        let first = import(bytes.as_bytes(), &index(), &options()).unwrap();
        let second = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        assert_eq!(first.id, second.id);
        assert_eq!(first.source_digest, second.source_digest);
    }

    #[test]
    fn the_window_spans_the_earliest_start_to_the_latest_end() {
        let bytes = payload(&[span("orders", "a1", None, 2, &[])]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        let window = snapshot.window.unwrap();
        assert_eq!(window.start_unix_nano, 1000);
        assert_eq!(window.end_unix_nano, 3000);
    }

    #[test]
    fn the_route_join_is_counted_separately_for_exact_and_mounted_matches() {
        let bytes = payload(&[
            span("orders", "a1", None, 2, &[("http.route", "/orders/{id}")]),
            span(
                "orders",
                "a2",
                None,
                2,
                &[("http.route", "/api/orders/{id}")],
            ),
            span("orders", "a3", None, 2, &[("http.route", "/nowhere")]),
        ]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.route_joins.exact, 1);
        assert_eq!(snapshot.route_joins.mount_suffix, 1);
        assert_eq!(snapshot.observations, 3);
        assert_eq!(snapshot.attributed, 2);
    }

    #[test]
    fn unattributed_spans_are_grouped_into_shapes_that_carry_no_values() {
        let bytes = payload(&[
            span("orders", "a1", None, 2, &[("http.route", "/nowhere")]),
            span("orders", "a2", None, 2, &[("http.route", "/nowhere")]),
        ]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.unattributed.len(), 1);
        let shape = &snapshot.unattributed[0];
        assert_eq!(shape.observations, 2);
        assert_eq!(shape.reason, UnattributedReason::RouteNotIndexed);
        assert_eq!(shape.attribute_keys, ["http.route"]);
        assert_eq!(shape.service.as_deref(), Some("orders"));
    }

    #[test]
    fn a_sampled_import_extrapolates_per_observation_rather_than_globally() {
        let bytes = payload(&[
            span("orders", "a1", None, 2, &[("http.route", "/orders/{id}")]),
            span("orders", "a2", None, 2, &[("http.route", "/orders/{id}")]),
        ])
        .replace(r#""traceState":"ot=th:0""#, r#""traceState":"ot=th:c""#);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.sampling.known, 2);
        assert_eq!(snapshot.sampling.unknown, 0);
        assert_eq!(snapshot.sampling.modal_adjusted_count, Some(4));
        assert_eq!(snapshot.points[0].estimated_calls, Some(8));
    }

    #[test]
    fn a_span_without_a_sampling_threshold_leaves_the_estimate_absent() {
        let bytes = payload(&[span(
            "orders",
            "a1",
            None,
            2,
            &[("http.route", "/orders/{id}")],
        )])
        .replace(r#""traceState":"ot=th:0","#, "");

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.sampling.unknown, 1);
        assert_eq!(snapshot.points[0].estimated_calls, None);
        assert_eq!(snapshot.points[0].calls, 1);
    }

    #[test]
    fn a_parent_cycle_in_a_malformed_export_terminates_the_walk() {
        let bytes = payload(&[
            span(
                "orders",
                "a1",
                Some("b1"),
                3,
                &[("server.address", "billing")],
            ),
            span(
                "orders",
                "b1",
                Some("a1"),
                3,
                &[("server.address", "billing")],
            ),
        ]);

        let snapshot = import(bytes.as_bytes(), &index(), &options()).unwrap();

        assert_eq!(snapshot.observations, 2);
    }

    #[test]
    fn raw_trace_ids_are_only_stored_when_they_were_asked_for() {
        let bytes = payload(&[span(
            "worker",
            "a1",
            None,
            3,
            &[
                ("server.address", "billing"),
                ("http.request.method", "GET"),
            ],
        )]);

        let hashed = import(bytes.as_bytes(), &index(), &options()).unwrap();
        assert_ne!(
            hashed.edges[0].witnesses[0],
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );

        let kept = import(
            bytes.as_bytes(),
            &index(),
            &ImportOptions {
                keep_trace_ids: true,
                ..options()
            },
        )
        .unwrap();
        assert_eq!(
            kept.edges[0].witnesses[0],
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
    }
}
