use crate::decode::RawObservation;
use crate::route;
use ovecc_core::runtime::{Anchor, AttributionPath, RouteMatch, UnattributedReason};
use std::collections::{BTreeMap, BTreeSet};

const ROUTE_KEYS: &[&str] = &["http.route"];
const METHOD_KEYS: &[&str] = &["http.request.method", "http.method"];
const TABLE_KEYS: &[&str] = &["db.collection.name", "db.sql.table"];
const FILE_KEYS: &[&str] = &["code.file.path", "code.filepath"];
const LINE_KEYS: &[&str] = &["code.line.number", "code.lineno"];
const FUNCTION_KEYS: &[&str] = &["code.function.name", "code.function"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRoute {
    pub method: Option<String>,
    pub path: String,
    pub file: String,
    pub symbol: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredAt {
    pub anchor: Anchor,
    pub path: AttributionPath,
    pub route_match: Option<RouteMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    Anchored(AnchoredAt),
    Table(String),
    Unattributed(UnattributedReason),
}

impl Attribution {
    pub fn is_attributed(&self) -> bool {
        !matches!(self, Attribution::Unattributed(_))
    }

    pub fn anchor(&self) -> Option<&Anchor> {
        match self {
            Attribution::Anchored(anchored) => Some(&anchored.anchor),
            _ => None,
        }
    }

    pub fn path(&self) -> Option<AttributionPath> {
        match self {
            Attribution::Anchored(anchored) => Some(anchored.path),
            Attribution::Table(_) => Some(AttributionPath::Schema),
            Attribution::Unattributed(_) => None,
        }
    }
}

enum Step {
    Resolved(Attribution),
    Failed(UnattributedReason),
    NotApplicable,
}

#[derive(Debug, Default)]
pub struct IndexView {
    routes: Vec<IndexedRoute>,
    by_path: BTreeMap<String, Vec<usize>>,
    by_last_segment: BTreeMap<String, Vec<usize>>,
    tables: BTreeMap<String, String>,
    files: BTreeSet<String>,
    files_by_name: BTreeMap<String, Vec<String>>,
}

impl IndexView {
    pub fn new(routes: Vec<IndexedRoute>, tables: Vec<String>, files: Vec<String>) -> Self {
        let routes: Vec<IndexedRoute> = routes
            .into_iter()
            .map(|indexed| IndexedRoute {
                path: route::canonical(&indexed.path),
                ..indexed
            })
            .collect();
        let mut by_path: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_last_segment: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (position, indexed) in routes.iter().enumerate() {
            by_path
                .entry(indexed.path.clone())
                .or_default()
                .push(position);
            by_last_segment
                .entry(route::last_segment(&indexed.path).to_string())
                .or_default()
                .push(position);
        }
        let mut files_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for file in &files {
            files_by_name
                .entry(file_name(file).to_string())
                .or_default()
                .push(file.clone());
        }
        Self {
            routes,
            by_path,
            by_last_segment,
            tables: tables
                .into_iter()
                .map(|name| (name.to_ascii_lowercase(), name))
                .collect(),
            files: files.into_iter().collect(),
            files_by_name,
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn indexed_route_paths(&self) -> BTreeSet<&str> {
        self.routes
            .iter()
            .map(|indexed| indexed.path.as_str())
            .collect()
    }
}

pub fn attribute(observation: &RawObservation, index: &IndexView) -> Attribution {
    let mut first_failure = None;
    for step in [
        resolve_route(observation, index),
        resolve_table(observation, index),
        resolve_code(observation, index),
    ] {
        match step {
            Step::Resolved(attribution) => return attribution,
            Step::Failed(reason) => {
                first_failure.get_or_insert(reason);
            }
            Step::NotApplicable => {}
        }
    }
    Attribution::Unattributed(first_failure.unwrap_or(UnattributedReason::NoJoinKey))
}

fn resolve_route(observation: &RawObservation, index: &IndexView) -> Step {
    let Some(raw) = observation.first_attribute(ROUTE_KEYS) else {
        return Step::NotApplicable;
    };
    let observed = route::canonical(raw);
    let method = observation.first_attribute(METHOD_KEYS);

    let exact = matching(
        index,
        index.by_path.get(&observed).map(Vec::as_slice),
        method,
        |_| true,
    );
    if let Some(indexed) = only(&exact) {
        return Step::Resolved(anchored(indexed, RouteMatch::Exact));
    }
    if exact.len() > 1 {
        return Step::Failed(UnattributedReason::RouteAmbiguous);
    }

    let suffix = most_specific(matching(
        index,
        index
            .by_last_segment
            .get(route::last_segment(&observed))
            .map(Vec::as_slice),
        method,
        |indexed| route::is_mount_suffix(&observed, &indexed.path),
    ));
    match only(&suffix) {
        Some(indexed) => Step::Resolved(anchored(indexed, RouteMatch::MountSuffix)),
        None if suffix.len() > 1 => Step::Failed(UnattributedReason::RouteAmbiguous),
        None => Step::Failed(UnattributedReason::RouteNotIndexed),
    }
}

fn matching<'a>(
    index: &'a IndexView,
    positions: Option<&[usize]>,
    method: Option<&str>,
    accept: impl Fn(&IndexedRoute) -> bool,
) -> Vec<&'a IndexedRoute> {
    positions
        .unwrap_or_default()
        .iter()
        .map(|position| &index.routes[*position])
        .filter(|indexed| route::method_matches(indexed.method.as_deref(), method))
        .filter(|indexed| accept(indexed))
        .collect()
}

fn most_specific(candidates: Vec<&IndexedRoute>) -> Vec<&IndexedRoute> {
    let Some(longest) = candidates.iter().map(|indexed| indexed.path.len()).max() else {
        return candidates;
    };
    candidates
        .into_iter()
        .filter(|indexed| indexed.path.len() == longest)
        .collect()
}

fn only<'a>(candidates: &[&'a IndexedRoute]) -> Option<&'a IndexedRoute> {
    match candidates {
        [single] => Some(single),
        _ => None,
    }
}

fn anchored(indexed: &IndexedRoute, route_match: RouteMatch) -> Attribution {
    Attribution::Anchored(AnchoredAt {
        anchor: Anchor {
            file: indexed.file.clone(),
            symbol: indexed.symbol.clone(),
            line: indexed.line,
        },
        path: AttributionPath::Route,
        route_match: Some(route_match),
    })
}

fn resolve_table(observation: &RawObservation, index: &IndexView) -> Step {
    let Some(raw) = observation.first_attribute(TABLE_KEYS) else {
        return Step::NotApplicable;
    };
    match index.tables.get(&raw.trim().to_ascii_lowercase()) {
        Some(indexed) => Step::Resolved(Attribution::Table(indexed.clone())),
        None => Step::Failed(UnattributedReason::TableNotIndexed),
    }
}

fn resolve_code(observation: &RawObservation, index: &IndexView) -> Step {
    let Some(raw) = observation.first_attribute(FILE_KEYS) else {
        return Step::NotApplicable;
    };
    let Some(file) = resolve_file(raw, index) else {
        return Step::Failed(UnattributedReason::FileNotIndexed);
    };
    Step::Resolved(Attribution::Anchored(AnchoredAt {
        anchor: Anchor {
            file,
            symbol: observation
                .first_attribute(FUNCTION_KEYS)
                .map(str::to_string),
            line: observation
                .first_attribute(LINE_KEYS)
                .and_then(|value| value.trim().parse().ok()),
        },
        path: AttributionPath::CodeAttribute,
        route_match: None,
    }))
}

fn resolve_file(raw: &str, index: &IndexView) -> Option<String> {
    let normalized = raw.trim().replace('\\', "/");
    let relative = normalized.trim_start_matches("./");
    if index.files.contains(relative) {
        return Some(relative.to_string());
    }
    let candidates = index.files_by_name.get(file_name(relative))?;
    let mut matches = candidates
        .iter()
        .filter(|indexed| relative.ends_with(&format!("/{indexed}")));
    let first = matches.next()?;
    matches.next().is_none().then(|| first.clone())
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::SpanKind;
    use crate::sampling::SamplingThreshold;

    fn observation(attributes: &[(&str, &str)]) -> RawObservation {
        RawObservation {
            trace_id: "aa".to_string(),
            span_id: "bb".to_string(),
            parent_span_id: None,
            kind: SpanKind::Server,
            service: Some("billing".to_string()),
            start_unix_nano: 0,
            end_unix_nano: 1,
            error: false,
            sampling: SamplingThreshold::from_hex("0"),
            attributes: attributes
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    fn indexed_route(method: &str, path: &str, file: &str) -> IndexedRoute {
        IndexedRoute {
            method: Some(method.to_string()),
            path: path.to_string(),
            file: file.to_string(),
            symbol: Some("handler".to_string()),
            line: Some(12),
        }
    }

    fn view() -> IndexView {
        IndexView::new(
            vec![
                indexed_route("GET", "/orders/:id", "src/orders/routes.ts"),
                indexed_route("POST", "/orders", "src/orders/routes.ts"),
                indexed_route("GET", "/health", "src/health.ts"),
            ],
            vec!["orders".to_string(), "customers".to_string()],
            vec![
                "src/orders/routes.ts".to_string(),
                "src/health.ts".to_string(),
                "src/orders/service.ts".to_string(),
            ],
        )
    }

    #[test]
    fn a_route_joins_across_the_frameworks_placeholder_syntax() {
        let observed = observation(&[
            ("http.route", "/orders/{id}"),
            ("http.request.method", "GET"),
        ]);

        let Attribution::Anchored(anchored) = attribute(&observed, &view()) else {
            panic!("the route should have joined");
        };
        assert_eq!(anchored.anchor.file, "src/orders/routes.ts");
        assert_eq!(anchored.anchor.symbol.as_deref(), Some("handler"));
        assert_eq!(anchored.path, AttributionPath::Route);
        assert_eq!(anchored.route_match, Some(RouteMatch::Exact));
    }

    #[test]
    fn a_router_mount_prefix_joins_as_a_suffix_and_says_so() {
        let observed = observation(&[
            ("http.route", "/api/v1/orders/{id}"),
            ("http.request.method", "GET"),
        ]);

        let Attribution::Anchored(anchored) = attribute(&observed, &view()) else {
            panic!("the mounted route should have joined");
        };
        assert_eq!(anchored.route_match, Some(RouteMatch::MountSuffix));
        assert_eq!(anchored.anchor.file, "src/orders/routes.ts");
    }

    #[test]
    fn a_method_the_index_disagrees_with_blocks_the_join() {
        let observed = observation(&[
            ("http.route", "/orders/{id}"),
            ("http.request.method", "DELETE"),
        ]);

        assert_eq!(
            attribute(&observed, &view()),
            Attribution::Unattributed(UnattributedReason::RouteNotIndexed)
        );
    }

    #[test]
    fn two_routes_equally_entitled_to_a_span_leave_it_unattributed() {
        let index = IndexView::new(
            vec![
                indexed_route("GET", "/orders", "src/a.ts"),
                indexed_route("GET", "/orders", "src/b.ts"),
            ],
            Vec::new(),
            vec!["src/a.ts".to_string(), "src/b.ts".to_string()],
        );
        let observed = observation(&[("http.route", "/orders"), ("http.request.method", "GET")]);

        assert_eq!(
            attribute(&observed, &index),
            Attribution::Unattributed(UnattributedReason::RouteAmbiguous)
        );
    }

    #[test]
    fn the_more_specific_route_wins_a_contested_suffix_match() {
        let index = IndexView::new(
            vec![
                indexed_route("GET", "/orders/:id", "src/orders.ts"),
                indexed_route("GET", "/:id", "src/catchall.ts"),
            ],
            Vec::new(),
            vec!["src/orders.ts".to_string(), "src/catchall.ts".to_string()],
        );
        let observed = observation(&[
            ("http.route", "/api/orders/{id}"),
            ("http.request.method", "GET"),
        ]);

        let Attribution::Anchored(anchored) = attribute(&observed, &index) else {
            panic!("the longer route should have won");
        };
        assert_eq!(anchored.anchor.file, "src/orders.ts");
    }

    #[test]
    fn a_database_span_resolves_to_the_indexed_table_name() {
        let observed = observation(&[("db.collection.name", "ORDERS")]);

        assert_eq!(
            attribute(&observed, &view()),
            Attribution::Table("orders".to_string())
        );
    }

    #[test]
    fn a_table_the_index_never_saw_is_reported_rather_than_invented() {
        let observed = observation(&[("db.sql.table", "audit_log")]);

        assert_eq!(
            attribute(&observed, &view()),
            Attribution::Unattributed(UnattributedReason::TableNotIndexed)
        );
    }

    #[test]
    fn code_attributes_join_under_both_the_stable_and_the_legacy_spellings() {
        for (file_key, line_key) in [
            ("code.file.path", "code.line.number"),
            ("code.filepath", "code.lineno"),
        ] {
            let observed = observation(&[(file_key, "src/orders/service.ts"), (line_key, "88")]);

            let Attribution::Anchored(anchored) = attribute(&observed, &view()) else {
                panic!("{file_key} should have joined");
            };
            assert_eq!(anchored.anchor.file, "src/orders/service.ts");
            assert_eq!(anchored.anchor.line, Some(88));
            assert_eq!(anchored.path, AttributionPath::CodeAttribute);
        }
    }

    #[test]
    fn an_absolute_build_path_lands_on_the_repository_relative_file() {
        let observed = observation(&[("code.file.path", "/app/build/src/orders/service.ts")]);

        assert_eq!(
            attribute(&observed, &view())
                .anchor()
                .map(|a| a.file.as_str()),
            Some("src/orders/service.ts")
        );
    }

    #[test]
    fn a_windows_separator_in_a_code_attribute_still_lands() {
        let observed = observation(&[("code.file.path", r"C:\build\src\orders\service.ts")]);

        assert!(attribute(&observed, &view()).is_attributed());
    }

    #[test]
    fn a_failed_route_join_still_falls_through_to_the_code_attributes() {
        let observed = observation(&[
            ("http.route", "/unknown"),
            ("http.request.method", "GET"),
            ("code.file.path", "src/health.ts"),
        ]);

        let Attribution::Anchored(anchored) = attribute(&observed, &view()) else {
            panic!("the code attribute should have rescued the join");
        };
        assert_eq!(anchored.path, AttributionPath::CodeAttribute);
    }

    #[test]
    fn the_reported_reason_is_the_first_join_key_that_failed() {
        let observed = observation(&[
            ("http.route", "/unknown"),
            ("code.file.path", "vendor/other.ts"),
        ]);

        assert_eq!(
            attribute(&observed, &view()),
            Attribution::Unattributed(UnattributedReason::RouteNotIndexed)
        );
    }

    #[test]
    fn a_span_with_no_join_key_says_so_rather_than_blaming_the_index() {
        assert_eq!(
            attribute(&observation(&[]), &view()),
            Attribution::Unattributed(UnattributedReason::NoJoinKey)
        );
    }
}
