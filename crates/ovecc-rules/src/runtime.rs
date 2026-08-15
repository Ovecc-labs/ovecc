//! The contract judged against production traffic.
//!
//! An observed call between two components that the contract does not allow is
//! reported the same way an undeclared import is, with one difference stated on
//! every finding: the evidence is a sampled, time-bounded export rather than the
//! source tree. That is why the family ships advisory-first — `runtime` in
//! `.ovecc/architecture.toml` raises it, exactly as `coupling` does.
//!
//! What this cannot tell you. An edge is only judged when both of its endpoints
//! resolve to a component: a file the contract claims, or a `service.name` a
//! component declares in `services`. Traffic to an unmapped service, and every
//! edge into a database table, is carried as evidence and never as a verdict.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use ovecc_core::architecture::{ArchitectureContract, baseline_entry};
use ovecc_core::facts::{EntityRef, Evidence, FindingKind, FindingRecord, Severity};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_core::runtime::{EdgeFact, Endpoint, EndpointKind};

use crate::{ContractInput, RuleInput};

pub(crate) const RULE: &str = "architecture/runtime-divergence";
pub(crate) const BASELINE_SLUG: &str = "runtime-divergence";

const MAX_EVIDENCE: usize = 10;
const MAX_WITNESSES_SHOWN: usize = 3;

/// (source component, target component) -> the observed calls between them, and
/// whether the contract forbids the pair outright rather than merely not
/// declaring it.
pub(crate) type RuntimeMap<'a> = BTreeMap<(&'a str, &'a str), RuntimeViolation<'a>>;

pub(crate) struct RuntimeViolation<'a> {
    pub(crate) edges: Vec<&'a EdgeFact>,
    pub(crate) forbidden: bool,
}

impl RuntimeViolation<'_> {
    fn calls(&self) -> u64 {
        self.edges.iter().map(|edge| edge.calls).sum()
    }

    fn estimated_calls(&self) -> Option<u64> {
        self.edges
            .iter()
            .map(|edge| edge.estimated_calls)
            .try_fold(0, |total, estimate| Some(total + estimate?))
    }
}

pub(crate) fn classify<'a>(architecture: ContractInput<'a>) -> RuntimeMap<'a> {
    let contract = architecture.contract;
    if contract.runtime.severity().is_none() {
        return RuntimeMap::default();
    }
    let services = declared_services(contract);
    let mut violations = RuntimeMap::default();
    for edge in architecture.runtime_edges {
        let (Some(source), Some(target)) = (
            component_of(&edge.from, architecture, &services),
            component_of(&edge.to, architecture, &services),
        ) else {
            continue;
        };
        if source == target || permitted(contract, source, target) {
            continue;
        }
        violations
            .entry((source, target))
            .or_insert_with(|| RuntimeViolation {
                edges: Vec::new(),
                forbidden: forbids(contract, source, target),
            })
            .edges
            .push(edge);
    }
    violations
}

fn declared_services(contract: &ArchitectureContract) -> BTreeMap<&str, &str> {
    contract
        .components
        .iter()
        .flat_map(|component| {
            component
                .services
                .iter()
                .map(|service| (service.as_str(), component.name.as_str()))
        })
        .collect()
}

fn component_of<'a>(
    endpoint: &Endpoint,
    architecture: ContractInput<'a>,
    services: &BTreeMap<&'a str, &'a str>,
) -> Option<&'a str> {
    match endpoint.kind {
        EndpointKind::File => architecture
            .component_of
            .get(&endpoint.name)
            .map(String::as_str),
        EndpointKind::Service => services.get(endpoint.name.as_str()).copied(),
        EndpointKind::Table => None,
    }
}

/// An edge the contract already sanctions. `must_depend_on` implies permission
/// on the static side, so it does here too.
fn permitted(contract: &ArchitectureContract, source: &str, target: &str) -> bool {
    contract.component(source).is_some_and(|spec| {
        spec.depends_on
            .iter()
            .any(|entry| entry.component() == target)
            || spec.must_depend_on.iter().any(|name| name == target)
    })
}

fn forbids(contract: &ArchitectureContract, source: &str, target: &str) -> bool {
    let named = contract
        .component(source)
        .is_some_and(|spec| spec.cannot_depend_on.iter().any(|name| name == target));
    let restricted = contract.component(target).is_some_and(|spec| {
        spec.consumed_by
            .as_ref()
            .is_some_and(|allowed| !allowed.iter().any(|name| name == source))
    });
    named || restricted
}

pub(crate) fn prune_baselined<'a>(
    violations: RuntimeMap<'a>,
    baseline: &BTreeSet<String>,
) -> RuntimeMap<'a> {
    violations
        .into_iter()
        .filter_map(|(pair, violation)| {
            let kept: Vec<&EdgeFact> = violation
                .edges
                .into_iter()
                .filter(|edge| !baseline.contains(&entry_for(edge)))
                .collect();
            (!kept.is_empty()).then_some((
                pair,
                RuntimeViolation {
                    edges: kept,
                    forbidden: violation.forbidden,
                },
            ))
        })
        .collect()
}

pub(crate) fn baseline_entries(violations: &RuntimeMap<'_>) -> BTreeMap<String, BTreeSet<String>> {
    let mut entries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (&(source, _), violation) in violations {
        for edge in &violation.edges {
            entries
                .entry(source.to_string())
                .or_default()
                .insert(entry_for(edge));
        }
    }
    entries
}

fn entry_for(edge: &EdgeFact) -> String {
    baseline_entry(BASELINE_SLUG, &edge.from.label(), &edge.to.label())
}

pub(crate) fn findings(
    input: &RuleInput<'_>,
    violations: &RuntimeMap<'_>,
    severity: Severity,
) -> Vec<FindingRecord> {
    violations
        .iter()
        .map(|(&(source, target), violation)| FindingRecord {
            id: FindingId::from_parts(&[
                input.repository_id,
                "architecture",
                BASELINE_SLUG,
                source,
                target,
            ]),
            repository_id: RepositoryId::from_raw(input.repository_id),
            snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
            kind: FindingKind::RuntimeDivergence,
            severity,
            rule_name: Some(RULE.to_string()),
            target: Some(EntityRef {
                kind: NodeKind::Module,
                id: source.to_string(),
            }),
            title: title(source, target, violation),
            description: description(source, target, violation),
            evidence: evidence(violation),
            created_at: Utc::now(),
        })
        .collect()
}

fn title(source: &str, target: &str, violation: &RuntimeViolation<'_>) -> String {
    format!(
        "{source} called {target} {} time(s) in production, and the contract does not allow it",
        violation.calls()
    )
}

fn description(source: &str, target: &str, violation: &RuntimeViolation<'_>) -> String {
    let prohibition = if violation.forbidden {
        format!("The contract forbids '{source}' from reaching '{target}' outright")
    } else {
        format!("'{source}' does not declare a dependency on '{target}'")
    };
    let estimate = match violation.estimated_calls() {
        Some(estimated) if estimated > violation.calls() => format!(
            " Sampling puts the true figure near {estimated}, extrapolated per observation from \
             the threshold each span carried.",
            estimated = estimated
        ),
        Some(_) => String::new(),
        None => " Some spans carried no sampling threshold, so the observed count is a floor and \
                 the true figure is unknown."
            .to_string(),
    };
    format!(
        "{prohibition}, yet the imported runtime evidence records {} call(s) between them. \
         The evidence is one sampled, time-bounded window: it proves the calls happened, not \
         how many there are in general. Either the dependency is real and belongs in \
         .ovecc/architecture.toml, or the traffic does.{estimate}",
        violation.calls()
    )
}

fn evidence(violation: &RuntimeViolation<'_>) -> Vec<Evidence> {
    violation
        .edges
        .iter()
        .take(MAX_EVIDENCE)
        .map(|edge| Evidence {
            file_path: edge.from.label(),
            line: None,
            symbol: None,
            detail: Some(detail(edge)),
        })
        .collect()
}

fn detail(edge: &EdgeFact) -> String {
    let witnesses: Vec<&str> = edge
        .witnesses
        .iter()
        .take(MAX_WITNESSES_SHOWN)
        .map(String::as_str)
        .collect();
    let traces = if witnesses.is_empty() {
        String::new()
    } else {
        format!(", traces {}", witnesses.join(", "))
    };
    format!(
        "{} {} call(s) to {}, {} error(s){traces}",
        edge.calls,
        edge.kind.as_str(),
        edge.to.label(),
        edge.errors
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::architecture::{ArchitectureContract, ComponentSpec, DependsOn};
    use ovecc_core::config::RulesConfig;
    use ovecc_core::runtime::{AttributionPath, EdgeKind};

    fn component(name: &str, paths: &[&str]) -> ComponentSpec {
        ComponentSpec {
            name: name.to_string(),
            paths: paths.iter().map(|path| path.to_string()).collect(),
            ..ComponentSpec::default()
        }
    }

    fn edge(from: Endpoint, to: Endpoint) -> EdgeFact {
        EdgeFact {
            from,
            to,
            kind: EdgeKind::Http,
            path: AttributionPath::Route,
            calls: 40_000,
            errors: 12,
            estimated_calls: Some(160_000),
            witnesses: vec!["aabb".to_string(), "ccdd".to_string()],
        }
    }

    struct Fixture {
        contract: ArchitectureContract,
        component_of: BTreeMap<String, String>,
        edges: Vec<EdgeFact>,
        baseline: BTreeSet<String>,
    }

    impl Fixture {
        fn new(components: Vec<ComponentSpec>, edges: Vec<EdgeFact>) -> Self {
            Self {
                contract: ArchitectureContract {
                    components,
                    ..ArchitectureContract::default()
                },
                component_of: [
                    ("src/web/routes.ts", "web"),
                    ("src/db/client.ts", "db"),
                    ("src/domain/order.ts", "domain"),
                ]
                .into_iter()
                .map(|(file, owner)| (file.to_string(), owner.to_string()))
                .collect(),
                edges,
                baseline: BTreeSet::new(),
            }
        }

        fn run(&self) -> Vec<FindingRecord> {
            let config = RulesConfig::default();
            let files: Vec<String> = self.component_of.keys().cloned().collect();
            let slice_of = BTreeMap::new();
            let architecture = ContractInput {
                contract: &self.contract,
                component_of: &self.component_of,
                files: &files,
                baseline: &self.baseline,
                slice_of: &slice_of,
                capability_uses: &[],
                functions: &[],
                co_changes: &[],
                coverage: &[],
                runtime_edges: &self.edges,
            };
            let input = RuleInput {
                repository_id: "repo:test",
                snapshot_id: None,
                modules: &[],
                dependencies: &[],
                config: &config,
                security_patterns: &[],
                architecture: Some(architecture),
            };
            let mut violations = classify(architecture);
            if !self.baseline.is_empty() {
                violations = prune_baselined(violations, &self.baseline);
            }
            findings(&input, &violations, Severity::Low)
        }
    }

    #[test]
    fn an_observed_call_the_contract_never_declared_is_reported() {
        let fixture = Fixture::new(
            vec![
                component("web", &["src/web/**"]),
                component("db", &["src/db/**"]),
            ],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::file("src/db/client.ts".to_string()),
            )],
        );

        let findings = fixture.run();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name.as_deref(), Some(RULE));
        assert_eq!(findings[0].kind, FindingKind::RuntimeDivergence);
        assert!(findings[0].title.contains("40000"), "{}", findings[0].title);
        assert!(
            findings[0].description.contains("160000"),
            "the sampled estimate belongs in the description: {}",
            findings[0].description
        );
        assert!(
            findings[0].evidence[0]
                .detail
                .as_ref()
                .unwrap()
                .contains("aabb")
        );
    }

    #[test]
    fn a_declared_dependency_is_a_convergence_not_a_finding() {
        let mut web = component("web", &["src/web/**"]);
        web.depends_on = vec![DependsOn::Name("db".to_string())];
        let fixture = Fixture::new(
            vec![web, component("db", &["src/db/**"])],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::file("src/db/client.ts".to_string()),
            )],
        );

        assert!(fixture.run().is_empty());
    }

    #[test]
    fn a_forbidden_pair_says_so_rather_than_reading_as_merely_undeclared() {
        let mut web = component("web", &["src/web/**"]);
        web.cannot_depend_on = vec!["db".to_string()];
        let fixture = Fixture::new(
            vec![web, component("db", &["src/db/**"])],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::file("src/db/client.ts".to_string()),
            )],
        );

        let findings = fixture.run();

        assert!(
            findings[0].description.contains("forbids"),
            "{}",
            findings[0].description
        );
    }

    #[test]
    fn a_consumed_by_list_that_excludes_the_caller_is_a_prohibition() {
        let mut db = component("db", &["src/db/**"]);
        db.consumed_by = Some(vec!["domain".to_string()]);
        let fixture = Fixture::new(
            vec![component("web", &["src/web/**"]), db],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::file("src/db/client.ts".to_string()),
            )],
        );

        let findings = fixture.run();

        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("forbids"));
    }

    #[test]
    fn a_service_name_a_component_declares_resolves_the_endpoint() {
        let mut web = component("web", &["src/web/**"]);
        web.services = vec!["web-api".to_string()];
        let fixture = Fixture::new(
            vec![web, component("db", &["src/db/**"])],
            vec![edge(
                Endpoint::service("web-api"),
                Endpoint::file("src/db/client.ts".to_string()),
            )],
        );

        assert_eq!(fixture.run().len(), 1);
    }

    #[test]
    fn traffic_to_an_unmapped_service_is_evidence_and_never_a_verdict() {
        let fixture = Fixture::new(
            vec![component("web", &["src/web/**"])],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::service("some-vendor-api"),
            )],
        );

        assert!(fixture.run().is_empty());
    }

    #[test]
    fn a_database_table_is_never_judged_as_a_component() {
        let fixture = Fixture::new(
            vec![component("web", &["src/web/**"])],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::table("orders".to_string()),
            )],
        );

        assert!(fixture.run().is_empty());
    }

    #[test]
    fn a_component_calling_itself_is_not_a_boundary_crossing() {
        let fixture = Fixture::new(
            vec![component("web", &["src/web/**"])],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::file("src/web/routes.ts".to_string()),
            )],
        );

        assert!(fixture.run().is_empty());
    }

    #[test]
    fn the_family_stays_silent_when_the_contract_turns_it_off() {
        let mut fixture = Fixture::new(
            vec![
                component("web", &["src/web/**"]),
                component("db", &["src/db/**"]),
            ],
            vec![edge(
                Endpoint::file("src/web/routes.ts".to_string()),
                Endpoint::file("src/db/client.ts".to_string()),
            )],
        );
        fixture.contract.runtime = ovecc_core::runtime::RuntimePolicy::Off;

        assert!(fixture.run().is_empty());
    }

    #[test]
    fn a_baselined_edge_stops_gating_while_a_new_one_still_does() {
        let observed = edge(
            Endpoint::file("src/web/routes.ts".to_string()),
            Endpoint::file("src/db/client.ts".to_string()),
        );
        let mut fixture = Fixture::new(
            vec![
                component("web", &["src/web/**"]),
                component("db", &["src/db/**"]),
            ],
            vec![observed.clone()],
        );
        fixture.baseline = [entry_for(&observed)].into_iter().collect();

        assert!(fixture.run().is_empty());

        fixture.edges.push(edge(
            Endpoint::file("src/web/routes.ts".to_string()),
            Endpoint::service("db-api"),
        ));
        let mut db = component("db", &["src/db/**"]);
        db.services = vec!["db-api".to_string()];
        fixture.contract.components = vec![component("web", &["src/web/**"]), db];

        assert_eq!(fixture.run().len(), 1);
    }

    #[test]
    fn freeze_entries_are_owned_by_the_calling_component() {
        let observed = edge(
            Endpoint::file("src/web/routes.ts".to_string()),
            Endpoint::file("src/db/client.ts".to_string()),
        );
        let fixture = Fixture::new(
            vec![
                component("web", &["src/web/**"]),
                component("db", &["src/db/**"]),
            ],
            vec![observed],
        );
        let files: Vec<String> = fixture.component_of.keys().cloned().collect();
        let slice_of = BTreeMap::new();
        let entries = baseline_entries(&classify(ContractInput {
            contract: &fixture.contract,
            component_of: &fixture.component_of,
            files: &files,
            baseline: &fixture.baseline,
            slice_of: &slice_of,
            capability_uses: &[],
            functions: &[],
            co_changes: &[],
            coverage: &[],
            runtime_edges: &fixture.edges,
        }));

        assert_eq!(entries.keys().collect::<Vec<_>>(), ["web"]);
        assert!(
            entries["web"]
                .iter()
                .next()
                .unwrap()
                .contains(BASELINE_SLUG)
        );
    }

    #[test]
    fn an_unknown_sampling_rate_makes_the_finding_say_the_count_is_a_floor() {
        let mut observed = edge(
            Endpoint::file("src/web/routes.ts".to_string()),
            Endpoint::file("src/db/client.ts".to_string()),
        );
        observed.estimated_calls = None;
        let fixture = Fixture::new(
            vec![
                component("web", &["src/web/**"]),
                component("db", &["src/db/**"]),
            ],
            vec![observed],
        );

        let findings = fixture.run();

        assert!(
            findings[0].description.contains("floor"),
            "{}",
            findings[0].description
        );
    }
}
