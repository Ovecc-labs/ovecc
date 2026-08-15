use crate::util::stable_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionPath {
    Route,
    Schema,
    CodeAttribute,
    Profile,
    Service,
}

impl AttributionPath {
    pub const ORDERED: &'static [AttributionPath] = &[
        AttributionPath::Route,
        AttributionPath::Schema,
        AttributionPath::CodeAttribute,
        AttributionPath::Profile,
        AttributionPath::Service,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AttributionPath::Route => "route",
            AttributionPath::Schema => "schema",
            AttributionPath::CodeAttribute => "code_attribute",
            AttributionPath::Profile => "profile",
            AttributionPath::Service => "service",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ORDERED.iter().copied().find(|p| p.as_str() == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMatch {
    Exact,
    MountSuffix,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Anchor {
    pub file: String,
    pub symbol: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    Service,
    File,
    Table,
}

impl EndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Service => "service",
            EndpointKind::File => "file",
            EndpointKind::Table => "table",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "service" => Some(EndpointKind::Service),
            "file" => Some(EndpointKind::File),
            "table" => Some(EndpointKind::Table),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub kind: EndpointKind,
    pub name: String,
}

impl Endpoint {
    pub fn service(name: impl Into<String>) -> Self {
        Self {
            kind: EndpointKind::Service,
            name: name.into(),
        }
    }

    pub fn file(name: impl Into<String>) -> Self {
        Self {
            kind: EndpointKind::File,
            name: name.into(),
        }
    }

    pub fn table(name: impl Into<String>) -> Self {
        Self {
            kind: EndpointKind::Table,
            name: name.into(),
        }
    }

    pub fn label(&self) -> String {
        match self.kind {
            EndpointKind::Table => format!("table:{}", self.name),
            EndpointKind::Service => format!("service:{}", self.name),
            EndpointKind::File => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Http,
    Rpc,
    Db,
    Queue,
    Internal,
}

impl EdgeKind {
    pub const ALL: &'static [EdgeKind] = &[
        EdgeKind::Http,
        EdgeKind::Rpc,
        EdgeKind::Db,
        EdgeKind::Queue,
        EdgeKind::Internal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Http => "http",
            EdgeKind::Rpc => "rpc",
            EdgeKind::Db => "db",
            EdgeKind::Queue => "queue",
            EdgeKind::Internal => "internal",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Percentiles {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

impl Percentiles {
    pub fn of_sorted(sorted_ns: &[u64]) -> Option<Self> {
        if sorted_ns.is_empty() {
            return None;
        }
        Some(Self {
            p50_ns: nearest_rank(sorted_ns, 50),
            p95_ns: nearest_rank(sorted_ns, 95),
            p99_ns: nearest_rank(sorted_ns, 99),
        })
    }
}

pub fn nearest_rank(sorted_ns: &[u64], percentile: u64) -> u64 {
    let count = sorted_ns.len() as u64;
    let rank = percentile.saturating_mul(count).div_ceil(100).max(1);
    sorted_ns[(rank - 1).min(count - 1) as usize]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointFact {
    pub anchor: Anchor,
    pub path: AttributionPath,
    pub calls: u64,
    pub errors: u64,
    pub estimated_calls: Option<u64>,
    pub latency: Option<Percentiles>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeFact {
    pub from: Endpoint,
    pub to: Endpoint,
    pub kind: EdgeKind,
    pub path: AttributionPath,
    pub calls: u64,
    pub errors: u64,
    pub estimated_calls: Option<u64>,
    pub witnesses: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnattributedReason {
    NoJoinKey,
    RouteNotIndexed,
    RouteAmbiguous,
    TableNotIndexed,
    FileNotIndexed,
}

impl UnattributedReason {
    pub const ALL: &'static [UnattributedReason] = &[
        UnattributedReason::NoJoinKey,
        UnattributedReason::RouteNotIndexed,
        UnattributedReason::RouteAmbiguous,
        UnattributedReason::TableNotIndexed,
        UnattributedReason::FileNotIndexed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            UnattributedReason::NoJoinKey => "no_join_key",
            UnattributedReason::RouteNotIndexed => "route_not_indexed",
            UnattributedReason::RouteAmbiguous => "route_ambiguous",
            UnattributedReason::TableNotIndexed => "table_not_indexed",
            UnattributedReason::FileNotIndexed => "file_not_indexed",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.as_str() == name)
    }

    pub fn explanation(self) -> &'static str {
        match self {
            UnattributedReason::NoJoinKey => {
                "the span carries none of http.route, a database collection, or code.file.path"
            }
            UnattributedReason::RouteNotIndexed => {
                "http.route matches no route the index extracted, even allowing for a router \
                 mount prefix"
            }
            UnattributedReason::RouteAmbiguous => {
                "http.route matches several indexed routes; attributing to one of them would be \
                 a guess"
            }
            UnattributedReason::TableNotIndexed => {
                "the database collection matches no schema object the index extracted"
            }
            UnattributedReason::FileNotIndexed => {
                "code.file.path names a file this repository does not index"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattributedShape {
    pub reason: UnattributedReason,
    pub service: Option<String>,
    pub route: Option<String>,
    pub attribute_keys: Vec<String>,
    pub observations: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingSummary {
    pub known: u64,
    pub unknown: u64,
    pub distinct_rates: usize,
    pub modal_adjusted_count: Option<u64>,
}

impl SamplingSummary {
    pub fn is_mixed(&self) -> bool {
        self.distinct_rates > 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeWindow {
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
}

impl RuntimeWindow {
    pub fn duration_seconds(&self) -> u64 {
        self.end_unix_nano.saturating_sub(self.start_unix_nano) / 1_000_000_000
    }

    pub fn start_rfc3339(&self) -> String {
        format_unix_nano(self.start_unix_nano)
    }

    pub fn end_rfc3339(&self) -> String {
        format_unix_nano(self.end_unix_nano)
    }
}

/// Nanoseconds since the Unix epoch as an RFC 3339 timestamp. A value the
/// calendar cannot hold renders as the raw count rather than a wrong date.
pub fn format_unix_nano(nanos: u64) -> String {
    let seconds = (nanos / 1_000_000_000) as i64;
    let remainder = (nanos % 1_000_000_000) as u32;
    match chrono::DateTime::from_timestamp(seconds, remainder) {
        Some(moment) => moment.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => nanos.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RouteJoinCounts {
    pub exact: u64,
    pub mount_suffix: u64,
}

/// Observations one attributor placed. Counted per observation rather than per
/// fact, so the breakdown sums to `attributed`: the schema path produces edges
/// and no anchor, and deriving the split from the point facts alone would lose
/// every database span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathAttribution {
    pub path: AttributionPath,
    pub observations: u64,
}

/// How trace ids were stored. Part of the snapshot's identity: the same bytes
/// imported both ways are two different things on disk, and a reader of a
/// committed `.ovecc/` is entitled to know which one it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessMode {
    Hashed,
    Raw,
}

impl WitnessMode {
    pub fn of(keep_trace_ids: bool) -> Self {
        if keep_trace_ids {
            WitnessMode::Raw
        } else {
            WitnessMode::Hashed
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WitnessMode::Hashed => "hashed",
            WitnessMode::Raw => "raw",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "hashed" => Some(WitnessMode::Hashed),
            "raw" => Some(WitnessMode::Raw),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    pub id: String,
    pub source_digest: String,
    pub witnesses: WitnessMode,
    pub provider: String,
    pub format: String,
    pub query: Option<String>,
    pub window: Option<RuntimeWindow>,
    pub observations: u64,
    pub attributed: u64,
    pub by_path: Vec<PathAttribution>,
    pub route_joins: RouteJoinCounts,
    pub sampling: SamplingSummary,
    pub points: Vec<PointFact>,
    pub edges: Vec<EdgeFact>,
    pub unattributed: Vec<UnattributedShape>,
}

impl RuntimeSnapshot {
    /// Identity of the evidence *as stored*, which is why the witness mode is
    /// part of it: re-importing the same bytes is a no-op only when it would
    /// produce the same rows.
    pub fn snapshot_id(repository_id: &str, source_digest: &str, witnesses: WitnessMode) -> String {
        stable_id(
            "runtime-snapshot",
            &[repository_id, source_digest, witnesses.as_str()],
        )
    }

    pub fn attribution_rate(&self) -> Option<f64> {
        (self.observations > 0).then(|| self.attributed as f64 / self.observations as f64)
    }

    pub fn attributed_by_path(&self, path: AttributionPath) -> u64 {
        self.by_path
            .iter()
            .find(|entry| entry.path == path)
            .map_or(0, |entry| entry.observations)
    }

    pub fn observed_files(&self) -> std::collections::BTreeSet<&str> {
        self.points
            .iter()
            .map(|point| point.anchor.file.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Observed,
    ObservedZero,
    NotInstrumented,
    NoSnapshot,
}

impl RuntimeState {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeState::Observed => "observed",
            RuntimeState::ObservedZero => "observed_zero",
            RuntimeState::NotInstrumented => "not_instrumented",
            RuntimeState::NoSnapshot => "no_snapshot",
        }
    }

    pub fn confirms_unused(self) -> bool {
        matches!(self, RuntimeState::ObservedZero)
    }

    pub fn contradicts_unused(self) -> bool {
        matches!(self, RuntimeState::Observed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimePolicy {
    Off,
    #[default]
    Low,
    Medium,
    High,
}

impl RuntimePolicy {
    pub fn severity(self) -> Option<crate::facts::Severity> {
        use crate::facts::Severity;
        match self {
            RuntimePolicy::Off => None,
            RuntimePolicy::Low => Some(Severity::Low),
            RuntimePolicy::Medium => Some(Severity::Medium),
            RuntimePolicy::High => Some(Severity::High),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_enum_label_round_trips_through_its_parser() {
        for path in AttributionPath::ORDERED {
            assert_eq!(AttributionPath::parse(path.as_str()), Some(*path));
        }
        for kind in EdgeKind::ALL {
            assert_eq!(EdgeKind::parse(kind.as_str()), Some(*kind));
        }
        for reason in UnattributedReason::ALL {
            assert_eq!(UnattributedReason::parse(reason.as_str()), Some(*reason));
        }
        for kind in [
            EndpointKind::Service,
            EndpointKind::File,
            EndpointKind::Table,
        ] {
            assert_eq!(EndpointKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn nearest_rank_picks_a_real_observation_never_an_interpolation() {
        let values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(nearest_rank(&values, 50), 50);
        assert_eq!(nearest_rank(&values, 95), 100);
        assert_eq!(nearest_rank(&values, 99), 100);
        assert_eq!(nearest_rank(&values, 0), 10);
    }

    #[test]
    fn a_single_observation_is_every_percentile_of_itself() {
        let percentiles = Percentiles::of_sorted(&[42]).unwrap();
        assert_eq!(percentiles.p50_ns, 42);
        assert_eq!(percentiles.p95_ns, 42);
        assert_eq!(percentiles.p99_ns, 42);
        assert_eq!(Percentiles::of_sorted(&[]), None);
    }

    #[test]
    fn snapshot_id_is_content_addressed_so_reimport_is_a_no_op() {
        let id = |repo, digest, mode| RuntimeSnapshot::snapshot_id(repo, digest, mode);
        let first = id("repo:a", "digest", WitnessMode::Hashed);

        assert_eq!(first, id("repo:a", "digest", WitnessMode::Hashed));
        assert_ne!(first, id("repo:a", "other", WitnessMode::Hashed));
        assert_ne!(first, id("repo:b", "digest", WitnessMode::Hashed));
        assert_ne!(
            first,
            id("repo:a", "digest", WitnessMode::Raw),
            "the same bytes stored with raw trace ids are different evidence"
        );
    }

    #[test]
    fn the_witness_mode_round_trips_through_its_label() {
        for mode in [WitnessMode::Hashed, WitnessMode::Raw] {
            assert_eq!(WitnessMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(WitnessMode::of(true), WitnessMode::Raw);
        assert_eq!(WitnessMode::of(false), WitnessMode::Hashed);
    }

    #[test]
    fn runtime_state_separates_confirmation_from_contradiction() {
        assert!(RuntimeState::ObservedZero.confirms_unused());
        assert!(RuntimeState::Observed.contradicts_unused());
        for state in [RuntimeState::NotInstrumented, RuntimeState::NoSnapshot] {
            assert!(!state.confirms_unused(), "{state:?} claims proof it lacks");
            assert!(!state.contradicts_unused());
        }
    }

    #[test]
    fn a_window_renders_as_utc_timestamps_a_reader_can_paste_into_a_backend() {
        let window = RuntimeWindow {
            start_unix_nano: 1_700_000_000_000_000_000,
            end_unix_nano: 1_700_000_600_000_000_000,
        };
        assert_eq!(window.start_rfc3339(), "2023-11-14T22:13:20Z");
        assert_eq!(window.end_rfc3339(), "2023-11-14T22:23:20Z");
        assert_eq!(window.duration_seconds(), 600);
    }

    #[test]
    fn an_empty_snapshot_reports_no_attribution_rate_rather_than_zero() {
        let snapshot = RuntimeSnapshot {
            id: "s".to_string(),
            source_digest: "d".to_string(),
            witnesses: WitnessMode::Hashed,
            provider: "stdin".to_string(),
            format: "otlp-json".to_string(),
            query: None,
            window: None,
            observations: 0,
            attributed: 0,
            by_path: Vec::new(),
            route_joins: RouteJoinCounts::default(),
            sampling: SamplingSummary::default(),
            points: Vec::new(),
            edges: Vec::new(),
            unattributed: Vec::new(),
        };
        assert_eq!(snapshot.attribution_rate(), None);
    }
}
