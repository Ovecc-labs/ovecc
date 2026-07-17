//! Code-smell detectors over the resolved symbol/call model: feature envy,
//! large class, and data clumps (Fowler's catalog, the subset a dependency
//! graph can witness without type information).
//!
//! Same contract as every other analyzer: deterministic output (sorted, id-safe
//! across runs), only resolved calls count as evidence, and test files are
//! exempt — test helpers legitimately reach across modules and take wide
//! parameter lists. Thresholds are deliberately conservative: a smell that
//! fires on idiomatic code trains people to ignore the rule.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::Utc;
use ovecc_core::facts::{
    CallRecord, EntityRef, Evidence, FindingKind, FindingRecord, Severity, SymbolKind, SymbolRecord,
};
use ovecc_core::graph::NodeKind;
use ovecc_core::id::{FindingId, RepositoryId, SnapshotId};
use ovecc_core::lang::SourceLanguage;
use ovecc_core::util::is_test_path;

// Envy fires when a function makes >= MIN foreign calls into one module, at
// least OWN_RATIO x its own-module calls, and that module gets half its total.
const ENVY_MIN_FOREIGN_CALLS: usize = 5;
const ENVY_OWN_RATIO: usize = 3;
const ENVY_MEDIUM_FOREIGN_CALLS: usize = 10;

const CLASS_METHODS_LOW: usize = 20;
const CLASS_METHODS_MEDIUM: usize = 30;

const CLUMP_MIN_NAMES: usize = 3;
const CLUMP_MIN_FUNCTIONS: usize = 3;
const CLUMP_MEDIUM_NAMES: usize = 4;
const CLUMP_MEDIUM_FUNCTIONS: usize = 4;
// Triple enumeration is C(n,3); cap n so a mega-signature can't blow it up.
const CLUMP_MAX_NAMES_PER_FUNCTION: usize = 12;
const MAX_EVIDENCE: usize = 20;

// Receiver conventions carry no data; they never count toward a clump.
const RECEIVER_NAMES: [&str; 3] = ["self", "cls", "this"];

// Framework signatures every codebase repeats (Express middleware, Node
// callbacks, AWS handlers). Recurring by design, not a clump.
const IDIOMATIC_GROUPS: [&[&str]; 4] = [
    &["err", "next", "req", "res"],
    &["error", "next", "req", "res"],
    &["error", "next", "request", "response"],
    &["callback", "context", "event"],
];

/// One function signature as the data-clumps detector sees it: just the
/// parameter names, with enough location to point the finding somewhere.
pub struct ClumpFunction {
    pub path: String,
    pub language: SourceLanguage,
    pub qualified_name: String,
    pub line: u32,
    pub param_names: Vec<String>,
}

pub struct SmellsInput<'a> {
    pub repository_id: &'a str,
    pub snapshot_id: Option<&'a str>,
    pub symbols: &'a [SymbolRecord],
    pub calls: &'a [CallRecord],
    pub module_names: &'a HashMap<String, String>,
    pub file_paths: &'a HashMap<String, String>,
    pub entry_points: &'a HashSet<String>,
    pub functions: &'a [ClumpFunction],
}

/// Runs every smell detector and returns the findings sorted by id, so the
/// output (and therefore the persisted snapshot) is byte-stable across runs.
pub fn analyze(input: &SmellsInput<'_>) -> Vec<FindingRecord> {
    let mut findings = feature_envy(input);
    findings.extend(large_class(input));
    findings.extend(data_clumps(input));
    findings.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    findings.dedup_by(|a, b| a.id.0 == b.id.0);
    findings
}

#[allow(clippy::too_many_arguments)]
fn finding(
    input: &SmellsInput<'_>,
    id: FindingId,
    kind: FindingKind,
    severity: Severity,
    rule_name: &str,
    target: Option<EntityRef>,
    title: String,
    description: String,
    evidence: Vec<Evidence>,
) -> FindingRecord {
    FindingRecord {
        id,
        repository_id: RepositoryId::from_raw(input.repository_id),
        snapshot_id: input.snapshot_id.map(SnapshotId::from_raw),
        kind,
        severity,
        rule_name: Some(rule_name.to_string()),
        target,
        title,
        description,
        evidence,
        created_at: Utc::now(),
    }
}

/// A function that talks to one foreign module far more than to its own is
/// probably in the wrong place. Entry points are exempt (dispatching outward
/// is their job), and only resolved calls count — unresolved names would turn
/// every dynamic-dispatch-heavy file into a false positive.
fn feature_envy(input: &SmellsInput<'_>) -> Vec<FindingRecord> {
    let symbol_by_id: HashMap<&str, &SymbolRecord> = input
        .symbols
        .iter()
        .map(|symbol| (symbol.id.0.as_str(), symbol))
        .collect();

    let mut calls_by_caller: HashMap<&str, HashMap<&str, usize>> = HashMap::new();
    for call in input.calls {
        let Some(callee_id) = &call.callee_symbol_id else {
            continue;
        };
        let Some(callee) = symbol_by_id.get(callee_id.0.as_str()) else {
            continue;
        };
        let Some(callee_module) = &callee.module_id else {
            continue;
        };
        *calls_by_caller
            .entry(call.caller_symbol_id.0.as_str())
            .or_default()
            .entry(callee_module.0.as_str())
            .or_insert(0) += 1;
    }

    let mut findings = Vec::new();
    for caller in input.symbols {
        if caller.name == "<module>"
            || !matches!(caller.kind, SymbolKind::Function | SymbolKind::Method)
        {
            continue;
        }
        let Some(own_module) = &caller.module_id else {
            continue;
        };
        let Some(path) = input.file_paths.get(caller.file_id.0.as_str()) else {
            continue;
        };
        if input.entry_points.contains(path) || is_test_path(path) {
            continue;
        }
        let Some(counts) = calls_by_caller.get(caller.id.0.as_str()) else {
            continue;
        };

        let total: usize = counts.values().sum();
        let own = counts.get(own_module.0.as_str()).copied().unwrap_or(0);
        // Deterministic winner on a count tie: highest count, then the
        // alphabetically first module name (hence the Reverse under max).
        let top_foreign = counts
            .iter()
            .filter(|(module, _)| **module != own_module.0.as_str())
            .map(|(module, count)| {
                let name = input
                    .module_names
                    .get(*module)
                    .map(String::as_str)
                    .unwrap_or(*module);
                (*count, std::cmp::Reverse(name), *module)
            })
            .max();
        let Some((foreign_calls, std::cmp::Reverse(module_name), module_id)) = top_foreign else {
            continue;
        };

        if foreign_calls < ENVY_MIN_FOREIGN_CALLS
            || foreign_calls < ENVY_OWN_RATIO * own.max(1)
            || foreign_calls * 2 < total
        {
            continue;
        }

        let severity = if own == 0 && foreign_calls >= ENVY_MEDIUM_FOREIGN_CALLS {
            Severity::Medium
        } else {
            Severity::Low
        };
        let line = caller.span.map(|span| span.start_line);
        findings.push(finding(
            input,
            FindingId::from_parts(&[
                input.repository_id,
                "feature-envy",
                path,
                &caller.qualified_name,
            ]),
            FindingKind::FeatureEnvy,
            severity,
            "feature-envy",
            Some(EntityRef {
                kind: NodeKind::Module,
                id: module_id.to_string(),
            }),
            format!(
                "Feature envy: {} -> {module_name} ({foreign_calls} of {total} calls)",
                caller.qualified_name
            ),
            format!(
                "{} at {path}:{} makes {foreign_calls} of its {total} resolved calls into \
                 module '{module_name}' but only {own} within its own module; move it (or \
                 extract the envious section) into '{module_name}'.",
                caller.qualified_name,
                line.unwrap_or(0),
            ),
            vec![Evidence {
                file_path: path.clone(),
                line,
                symbol: Some(caller.qualified_name.clone()),
                detail: Some(format!(
                    "{foreign_calls}/{total} resolved calls target '{module_name}', {own} stay home"
                )),
            }],
        ));
    }
    findings
}

/// A type with too many methods concentrates too many reasons to change.
/// Methods are attributed by `(file, owner)` from the qualified name, so
/// same-named types in different files stay separate.
fn large_class(input: &SmellsInput<'_>) -> Vec<FindingRecord> {
    let mut methods: HashMap<(&str, &str), (usize, u64)> = HashMap::new();
    for symbol in input.symbols {
        if symbol.kind != SymbolKind::Method {
            continue;
        }
        let Some((owner, _)) = symbol.qualified_name.rsplit_once('.') else {
            continue;
        };
        let lines = symbol
            .span
            .map(|span| u64::from(span.end_line.saturating_sub(span.start_line)) + 1)
            .unwrap_or(0);
        let entry = methods
            .entry((symbol.file_id.0.as_str(), owner))
            .or_insert((0, 0));
        entry.0 += 1;
        entry.1 += lines;
    }

    let mut findings = Vec::new();
    for class in input.symbols {
        if !matches!(
            class.kind,
            SymbolKind::Class | SymbolKind::Struct | SymbolKind::Enum
        ) {
            continue;
        }
        let Some(path) = input.file_paths.get(class.file_id.0.as_str()) else {
            continue;
        };
        if is_test_path(path) {
            continue;
        }
        let Some((method_count, method_lines)) = methods
            .get(&(class.file_id.0.as_str(), class.qualified_name.as_str()))
            .copied()
        else {
            continue;
        };
        if method_count < CLASS_METHODS_LOW {
            continue;
        }
        let severity = if method_count >= CLASS_METHODS_MEDIUM {
            Severity::Medium
        } else {
            Severity::Low
        };
        let line = class.span.map(|span| span.start_line);
        findings.push(finding(
            input,
            FindingId::from_parts(&[
                input.repository_id,
                "large-class",
                path,
                &class.qualified_name,
            ]),
            FindingKind::LargeClass,
            severity,
            "large-class",
            None,
            format!(
                "Large class: {} ({method_count} methods)",
                class.qualified_name
            ),
            format!(
                "{} at {path}:{} has {method_count} methods spanning {method_lines} source \
                 lines; split it along its responsibilities by extracting cohesive method \
                 groups into collaborating classes.",
                class.qualified_name,
                line.unwrap_or(0),
            ),
            vec![Evidence {
                file_path: path.clone(),
                line,
                symbol: Some(class.qualified_name.clone()),
                detail: Some(format!(
                    "{method_count} methods, {method_lines} method lines"
                )),
            }],
        ));
    }
    findings
}

// JS and TS share naming conventions, so their clumps live in one namespace;
// other languages never clump across a language boundary.
fn language_family(language: SourceLanguage) -> &'static str {
    if language.is_js_family() {
        "js"
    } else {
        language.as_str()
    }
}

struct ClumpSite<'a> {
    path: &'a str,
    qualified_name: &'a str,
    line: u32,
    names: Vec<&'a str>,
}

/// The same parameter names traveling together through several signatures are
/// an object waiting to be extracted. Detection: normalize each function's
/// parameter names, enumerate every 3-name combination, and report a group
/// when at least CLUMP_MIN_FUNCTIONS functions share it. Name-based on
/// purpose — no type information exists at this layer, and names are the
/// convention a team actually repeats.
/// The non-test functions whose deduplicated parameter names could form a
/// clump, sorted for deterministic output. Overloads and re-exports collapse to
/// one site so a repeated signature does not inflate a clump.
fn collect_clump_sites<'a>(input: &'a SmellsInput<'a>) -> Vec<(&'static str, ClumpSite<'a>)> {
    let mut sites: Vec<(&'static str, ClumpSite<'a>)> = Vec::new();
    for function in input.functions {
        if is_test_path(&function.path) {
            continue;
        }
        let mut names: Vec<&str> = function
            .param_names
            .iter()
            .map(String::as_str)
            .filter(|name| !name.starts_with('_') && !RECEIVER_NAMES.contains(name))
            .collect();
        names.sort_unstable();
        names.dedup();
        names.truncate(CLUMP_MAX_NAMES_PER_FUNCTION);
        if names.len() < CLUMP_MIN_NAMES {
            continue;
        }
        sites.push((
            language_family(function.language),
            ClumpSite {
                path: &function.path,
                qualified_name: &function.qualified_name,
                line: function.line,
                names,
            },
        ));
    }
    sites.sort_by(|a, b| {
        (a.1.path, a.1.line, a.1.qualified_name).cmp(&(b.1.path, b.1.line, b.1.qualified_name))
    });
    let mut seen: HashSet<(&str, &str, Vec<&str>)> = HashSet::new();
    sites.retain(|(family, site)| seen.insert((family, site.qualified_name, site.names.clone())));
    sites
}

/// Each name triple mapped to the site indices whose signature contains it. A
/// clump is a triple (or wider group) shared by enough functions.
fn index_triples<'a>(
    sites: &[(&'static str, ClumpSite<'a>)],
) -> BTreeMap<(&'a str, [&'a str; 3]), BTreeSet<usize>> {
    let mut triples: BTreeMap<(&str, [&str; 3]), BTreeSet<usize>> = BTreeMap::new();
    for (index, (family, site)) in sites.iter().enumerate() {
        let names = &site.names;
        for i in 0..names.len() {
            for j in (i + 1)..names.len() {
                for k in (j + 1)..names.len() {
                    triples
                        .entry((family, [names[i], names[j], names[k]]))
                        .or_default()
                        .insert(index);
                }
            }
        }
    }
    triples
}

fn data_clumps(input: &SmellsInput<'_>) -> Vec<FindingRecord> {
    let sites = collect_clump_sites(input);
    let triples = index_triples(&sites);

    // Triples shared by the same set of functions are one clump: merging them
    // rebuilds the widest recurring group (a 4-name clump would otherwise be
    // reported as four separate triples).
    let mut clumps: BTreeMap<(&str, Vec<usize>), BTreeSet<&str>> = BTreeMap::new();
    for ((family, names), members) in &triples {
        if members.len() < CLUMP_MIN_FUNCTIONS {
            continue;
        }
        clumps
            .entry((family, members.iter().copied().collect()))
            .or_default()
            .extend(names.iter().copied());
    }

    let mut findings = Vec::new();
    for ((family, members), names) in &clumps {
        if IDIOMATIC_GROUPS
            .iter()
            .any(|idiom| names.iter().all(|name| idiom.contains(name)))
        {
            continue;
        }
        let severity =
            if names.len() >= CLUMP_MEDIUM_NAMES && members.len() >= CLUMP_MEDIUM_FUNCTIONS {
                Severity::Medium
            } else {
                Severity::Low
            };
        let group: Vec<&str> = names.iter().copied().collect();
        let first = &sites[members[0]].1;
        let evidence: Vec<Evidence> = members
            .iter()
            .take(MAX_EVIDENCE)
            .map(|index| {
                let site = &sites[*index].1;
                Evidence {
                    file_path: site.path.to_string(),
                    line: Some(site.line),
                    symbol: Some(site.qualified_name.to_string()),
                    detail: Some(format!("takes ({})", group.join(", "))),
                }
            })
            .collect();
        findings.push(finding(
            input,
            FindingId::from_parts(&[input.repository_id, "data-clumps", family, &group.join(",")]),
            FindingKind::DataClumps,
            severity,
            "data-clumps",
            None,
            format!(
                "Data clump: ({}) recurs across {} functions",
                group.join(", "),
                members.len()
            ),
            format!(
                "The parameter group ({}) travels together through {} functions (first: {} \
                 at {}:{}); introduce a parameter object and pass it instead of the \
                 individual values.",
                group.join(", "),
                members.len(),
                first.qualified_name,
                first.path,
                first.line,
            ),
            evidence,
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovecc_core::facts::{CallKind, Span};
    use ovecc_core::id::{CallId, FileId, ModuleId, SymbolId};

    fn symbol(
        id: &str,
        file: &str,
        module: &str,
        kind: SymbolKind,
        qualified: &str,
    ) -> SymbolRecord {
        SymbolRecord {
            id: SymbolId::from_raw(id),
            repository_id: RepositoryId::from_raw("repo"),
            file_id: FileId::from_raw(file),
            module_id: Some(ModuleId::from_raw(module)),
            language: SourceLanguage::TypeScript,
            kind,
            name: qualified
                .rsplit('.')
                .next()
                .unwrap_or(qualified)
                .to_string(),
            qualified_name: qualified.to_string(),
            span: Some(Span {
                start_line: 10,
                end_line: 20,
            }),
            visibility: None,
            type_signature: None,
        }
    }

    fn call(index: usize, caller: &str, callee: Option<&str>) -> CallRecord {
        CallRecord {
            id: CallId::from_raw(format!("call:{index}")),
            repository_id: RepositoryId::from_raw("repo"),
            caller_symbol_id: SymbolId::from_raw(caller),
            callee_symbol_id: callee.map(SymbolId::from_raw),
            callee_name: None,
            kind: CallKind::Direct,
            evidence: None,
        }
    }

    fn calls_to(caller: &str, callee: &str, count: usize, offset: usize) -> Vec<CallRecord> {
        (0..count)
            .map(|i| call(offset + i, caller, Some(callee)))
            .collect()
    }

    struct Fixture {
        symbols: Vec<SymbolRecord>,
        calls: Vec<CallRecord>,
        module_names: HashMap<String, String>,
        file_paths: HashMap<String, String>,
        entry_points: HashSet<String>,
        functions: Vec<ClumpFunction>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                symbols: Vec::new(),
                calls: Vec::new(),
                module_names: HashMap::from([
                    ("m:a".to_string(), "alpha".to_string()),
                    ("m:b".to_string(), "beta".to_string()),
                    ("m:c".to_string(), "gamma".to_string()),
                    ("m:d".to_string(), "delta".to_string()),
                ]),
                file_paths: HashMap::from([
                    ("f:a".to_string(), "alpha/service.ts".to_string()),
                    ("f:b".to_string(), "beta/store.ts".to_string()),
                    ("f:t".to_string(), "alpha/service.test.ts".to_string()),
                    ("f:e".to_string(), "alpha/index.ts".to_string()),
                ]),
                entry_points: HashSet::from(["alpha/index.ts".to_string()]),
                functions: Vec::new(),
            }
        }

        fn analyze(&self) -> Vec<FindingRecord> {
            analyze(&SmellsInput {
                repository_id: "repo",
                snapshot_id: None,
                symbols: &self.symbols,
                calls: &self.calls,
                module_names: &self.module_names,
                file_paths: &self.file_paths,
                entry_points: &self.entry_points,
                functions: &self.functions,
            })
        }
    }

    fn envy_fixture(own_calls: usize, foreign_calls: usize) -> Fixture {
        let mut fixture = Fixture::new();
        fixture.symbols = vec![
            symbol("s:f", "f:a", "m:a", SymbolKind::Function, "syncAll"),
            symbol("s:own", "f:a", "m:a", SymbolKind::Function, "helper"),
            symbol("s:store", "f:b", "m:b", SymbolKind::Function, "persist"),
        ];
        fixture.calls = calls_to("s:f", "s:own", own_calls, 0);
        fixture
            .calls
            .extend(calls_to("s:f", "s:store", foreign_calls, 100));
        fixture
    }

    #[test]
    fn feature_envy_flags_function_dominated_by_a_foreign_module() {
        let fixture = envy_fixture(1, 6);
        let findings = fixture.analyze();
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let finding = &findings[0];
        assert_eq!(finding.kind, FindingKind::FeatureEnvy);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.title.contains("syncAll"), "{}", finding.title);
        assert!(finding.title.contains("beta"), "{}", finding.title);
        assert_eq!(
            finding.target.as_ref().map(|t| t.id.as_str()),
            Some("m:b"),
            "target must name the envied module"
        );
        assert_eq!(finding.evidence[0].file_path, "alpha/service.ts");
        assert_eq!(finding.evidence[0].line, Some(10));
    }

    #[test]
    fn feature_envy_spares_functions_loyal_to_their_module() {
        assert!(envy_fixture(6, 5).analyze().is_empty(), "ratio guard");
        assert!(envy_fixture(0, 4).analyze().is_empty(), "volume guard");
    }

    #[test]
    fn feature_envy_requires_a_dominant_target_not_just_fan_out() {
        let mut fixture = envy_fixture(0, 5);
        fixture.symbols.push(symbol(
            "s:gamma",
            "f:b",
            "m:c",
            SymbolKind::Function,
            "audit",
        ));
        fixture.symbols.push(symbol(
            "s:delta",
            "f:b",
            "m:d",
            SymbolKind::Function,
            "notify",
        ));
        fixture.calls.extend(calls_to("s:f", "s:gamma", 5, 200));
        fixture.calls.extend(calls_to("s:f", "s:delta", 5, 300));
        let findings = fixture.analyze();
        assert!(
            findings.is_empty(),
            "an orchestrator spreading 5/5/5 across three modules envies none of them: {findings:#?}"
        );
    }

    #[test]
    fn feature_envy_is_medium_when_fully_estranged() {
        let findings = envy_fixture(0, 10).analyze();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn feature_envy_skips_tests_entry_points_and_module_init() {
        for (id, file) in [("s:f", "f:t"), ("s:f", "f:e")] {
            let mut fixture = envy_fixture(0, 8);
            fixture.symbols[0] = symbol(id, file, "m:a", SymbolKind::Function, "syncAll");
            assert!(fixture.analyze().is_empty(), "{file} must be excluded");
        }
        let mut fixture = envy_fixture(0, 8);
        fixture.symbols[0] = symbol("s:f", "f:a", "m:a", SymbolKind::Function, "<module>");
        fixture.symbols[0].name = "<module>".to_string();
        assert!(fixture.analyze().is_empty(), "<module> must be excluded");
    }

    #[test]
    fn feature_envy_ignores_unresolved_calls() {
        let mut fixture = envy_fixture(0, 6);
        fixture
            .calls
            .extend((0..20).map(|i| call(300 + i, "s:f", None)));
        let findings = fixture.analyze();
        assert_eq!(
            findings.len(),
            1,
            "unresolved calls must not dilute the dominance ratio"
        );
    }

    #[test]
    fn feature_envy_breaks_count_ties_by_module_name() {
        let mut fixture = envy_fixture(0, 5);
        fixture.symbols.push(symbol(
            "s:gamma",
            "f:b",
            "m:c",
            SymbolKind::Function,
            "audit",
        ));
        fixture.calls.extend(calls_to("s:f", "s:gamma", 5, 200));
        let findings = fixture.analyze();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].title.contains("beta"),
            "tie must break to the lexicographically first module name: {}",
            findings[0].title
        );
    }

    fn class_fixture(method_count: usize) -> Fixture {
        let mut fixture = Fixture::new();
        fixture.symbols = vec![symbol("s:c", "f:a", "m:a", SymbolKind::Class, "Store")];
        for index in 0..method_count {
            fixture.symbols.push(symbol(
                &format!("s:m{index}"),
                "f:a",
                "m:a",
                SymbolKind::Method,
                &format!("Store.method{index}"),
            ));
        }
        fixture
    }

    #[test]
    fn large_class_flags_method_heavy_classes_with_tiered_severity() {
        assert!(class_fixture(19).analyze().is_empty());

        let findings = class_fixture(20).analyze();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::LargeClass);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("Store (20 methods)"));

        let findings = class_fixture(30).analyze();
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn large_class_counts_struct_and_enum_owners_too() {
        for kind in [SymbolKind::Struct, SymbolKind::Enum] {
            let mut fixture = class_fixture(20);
            fixture.symbols[0].kind = kind;
            assert_eq!(fixture.analyze().len(), 1, "{kind:?} must count");
        }
    }

    #[test]
    fn large_class_requires_the_owner_in_the_same_file() {
        let mut fixture = class_fixture(25);
        for method in &mut fixture.symbols[1..] {
            method.file_id = FileId::from_raw("f:b");
        }
        assert!(
            fixture.analyze().is_empty(),
            "methods in another file must not attach"
        );
    }

    #[test]
    fn large_class_skips_test_files() {
        let mut fixture = class_fixture(25);
        for symbol in &mut fixture.symbols {
            symbol.file_id = FileId::from_raw("f:t");
        }
        assert!(fixture.analyze().is_empty());
    }

    fn clump_function(path: &str, qualified: &str, line: u32, names: &[&str]) -> ClumpFunction {
        ClumpFunction {
            path: path.to_string(),
            language: SourceLanguage::TypeScript,
            qualified_name: qualified.to_string(),
            line,
            param_names: names.iter().map(|n| n.to_string()).collect(),
        }
    }

    #[test]
    fn data_clumps_flags_a_recurring_group_and_unions_it_maximally() {
        let mut fixture = Fixture::new();
        fixture.functions = vec![
            clump_function("a.ts", "connect", 1, &["host", "port", "timeout", "extra"]),
            clump_function("a.ts", "reconnect", 9, &["timeout", "host", "port"]),
            clump_function("b.ts", "ping", 3, &["host", "port", "timeout", "verbose"]),
        ];
        let findings = fixture.analyze();
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let finding = &findings[0];
        assert_eq!(finding.kind, FindingKind::DataClumps);
        assert_eq!(finding.severity, Severity::Low);
        assert!(
            finding.title.contains("(host, port, timeout)"),
            "names must be the maximal shared set, sorted: {}",
            finding.title
        );
        assert_eq!(finding.evidence.len(), 3);
        assert_eq!(finding.evidence[0].symbol.as_deref(), Some("connect"));
        assert_eq!(finding.evidence[2].symbol.as_deref(), Some("ping"));
    }

    #[test]
    fn data_clumps_reports_the_full_group_when_all_functions_share_it() {
        let mut fixture = Fixture::new();
        fixture.functions = (0..4)
            .map(|i| {
                clump_function(
                    "a.ts",
                    &format!("f{i}"),
                    i + 1,
                    &["x0", "y0", "width", "height"],
                )
            })
            .collect();
        let findings = fixture.analyze();
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].title.contains("(height, width, x0, y0)"));
        assert_eq!(
            findings[0].severity,
            Severity::Medium,
            ">=4 names across >=4 functions escalates"
        );
    }

    #[test]
    fn data_clumps_stays_quiet_below_thresholds() {
        let mut fixture = Fixture::new();
        fixture.functions = vec![
            clump_function("a.ts", "f", 1, &["host", "port", "timeout"]),
            clump_function("a.ts", "g", 5, &["host", "port", "timeout"]),
        ];
        assert!(
            fixture.analyze().is_empty(),
            "two functions are not a clump"
        );

        fixture.functions = vec![
            clump_function("a.ts", "f", 1, &["host", "port"]),
            clump_function("a.ts", "g", 5, &["host", "port"]),
            clump_function("a.ts", "h", 9, &["host", "port"]),
        ];
        assert!(fixture.analyze().is_empty(), "two names are not a clump");
    }

    #[test]
    fn data_clumps_filters_receivers_and_placeholder_names() {
        let mut fixture = Fixture::new();
        fixture.functions = (0..3)
            .map(|i| {
                clump_function(
                    "a.py",
                    &format!("f{i}"),
                    i + 1,
                    &["self", "_ctx", "host", "port", "timeout"],
                )
            })
            .collect();
        let findings = fixture.analyze();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].title.contains("(host, port, timeout)"),
            "self/_ctx must not join the clump: {}",
            findings[0].title
        );
    }

    #[test]
    fn data_clumps_spares_idiomatic_framework_signatures() {
        let mut fixture = Fixture::new();
        fixture.functions = (0..5)
            .map(|i| clump_function("mw.ts", &format!("mw{i}"), i + 1, &["req", "res", "next"]))
            .collect();
        assert!(fixture.analyze().is_empty(), "req/res/next is idiomatic");
    }

    #[test]
    fn data_clumps_does_not_mix_language_families() {
        let mut fixture = Fixture::new();
        fixture.functions = vec![
            clump_function("a.ts", "f", 1, &["host", "port", "timeout"]),
            clump_function("b.tsx", "g", 1, &["host", "port", "timeout"]),
            {
                let mut function = clump_function("c.rs", "h", 1, &["host", "port", "timeout"]);
                function.language = SourceLanguage::Rust;
                function
            },
        ];
        assert!(
            fixture.analyze().is_empty(),
            "ts+tsx are one family (2 sites) and rust is another (1 site)"
        );
    }

    #[test]
    fn data_clumps_dedups_declaration_and_definition_pairs() {
        let mut fixture = Fixture::new();
        fixture.functions = vec![
            clump_function("a.hpp", "connect", 1, &["host", "port", "timeout"]),
            clump_function("a.cpp", "connect", 40, &["host", "port", "timeout"]),
            clump_function("a.cpp", "retry", 80, &["host", "port", "timeout"]),
        ];
        assert!(
            fixture.analyze().is_empty(),
            "prototype+definition is one function, so only two distinct sites exist"
        );
    }

    #[test]
    fn data_clumps_skips_test_files() {
        let mut fixture = Fixture::new();
        fixture.functions = (0..3)
            .map(|i| {
                clump_function(
                    "tests/util.ts",
                    &format!("f{i}"),
                    i + 1,
                    &["host", "port", "timeout"],
                )
            })
            .collect();
        assert!(fixture.analyze().is_empty());
    }

    #[test]
    fn analyze_is_deterministic_under_input_reordering() {
        let mut fixture = envy_fixture(1, 6);
        fixture.functions = vec![
            clump_function("z.ts", "f3", 30, &["host", "port", "timeout"]),
            clump_function("a.ts", "f1", 1, &["host", "port", "timeout"]),
            clump_function("m.ts", "f2", 9, &["timeout", "port", "host"]),
        ];
        let forward = fixture.analyze();

        fixture.symbols.reverse();
        fixture.calls.reverse();
        fixture.functions.reverse();
        let reversed = fixture.analyze();

        let ids = |findings: &[FindingRecord]| -> Vec<String> {
            findings.iter().map(|f| f.id.0.clone()).collect()
        };
        assert_eq!(ids(&forward), ids(&reversed));
        assert_eq!(
            forward.iter().map(|f| &f.description).collect::<Vec<_>>(),
            reversed.iter().map(|f| &f.description).collect::<Vec<_>>()
        );
    }
}
