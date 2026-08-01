//! Reads over the persisted graph: `query`, `impact`, `explain`, and the
//! `export context` slice.

use super::findings::{DEFAULT_FINDING_LIMIT, render_violations};
use super::open_store;
use super::summary::{load_hotspots, render_hotspots};
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_header};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::legacy::ImpactDirection;
use ovecc_core::query::{Query, TargetSelector};
use ovecc_core::report::{AnchoredRef, ContextSlice};
use ovecc_db::ArchitectureStore;
use ovecc_graph::blast::{self, BlastEdge, BlastNode, BlastResult, ImpactedNode};
use std::collections::HashMap;

pub(crate) fn render_explanation(
    slice: &ContextSlice,
    explanation: &str,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json
        | OutputFormat::Ndjson
        | OutputFormat::Sarif
        | OutputFormat::Codeclimate => {
            let data = serde_json::json!({
                "target": slice.target,
                "explanation": explanation,
                "context": slice,
            });
            emit_json("explain", &data, meta_for("explain"))?;
        }
        _ => print!("{explanation}"),
    }
    Ok(())
}

/// Re-attaches the `table:`/`api:` prefix that query parsing strips, so the
/// blast resolver sees the original form.
fn selector_to_blast(selector: &TargetSelector) -> String {
    match selector {
        TargetSelector::Table(name) => format!("table:{name}"),
        TargetSelector::Api {
            method: Some(method),
            path,
        } => format!("api:{method}:{path}"),
        TargetSelector::Api { method: None, path } => format!("api:{path}"),
        other => other.needle().to_string(),
    }
}

pub(crate) fn run_query(
    paths: &ProjectPaths,
    query: &Query,
    format: OutputFormat,
    depth: Option<usize>,
) -> Result<u8> {
    match query {
        Query::Hotspots => {
            let report = load_hotspots(paths, 10)?;
            render_hotspots(&report, format)?;
            return Ok(0);
        }
        Query::Violations => {
            let store = open_store(paths)?;
            let findings = store.findings(&paths.repository_id().0, None)?;
            render_violations(&findings, format, DEFAULT_FINDING_LIMIT, 0)?;
            return Ok(0);
        }
        Query::Cycles => {
            let store = open_store(paths)?;
            let repository_id = paths.repository_id().0;
            let modules = store.current_modules(&repository_id)?;
            let dependencies = store.current_dependencies(&repository_id)?;
            // Elementary loops shortest-first, each with the file:line import
            // edges that witness every hop — the same walk `review` uses.
            let cycles =
                ovecc_graph::cycles::elementary_cycles_with_witness(&modules, &dependencies);
            match format {
                OutputFormat::Json | OutputFormat::Ndjson => {
                    let data = serde_json::json!({ "query": "cycles", "cycles": cycles });
                    emit_json("query", &data, meta_for("query"))?;
                }
                _ => {
                    println!("Cycles: {}", cycles.len());
                    for cycle in &cycles {
                        let mut closed = cycle.modules.clone();
                        if let Some(first) = cycle.modules.first().cloned() {
                            closed.push(first);
                        }
                        println!("  {}", closed.join(" -> "));
                        for edge in &cycle.edges {
                            println!(
                                "    {}:{} -> {} ({})",
                                edge.from_file,
                                edge.line,
                                edge.to_file.as_deref().unwrap_or(&edge.to_module),
                                edge.specifier
                            );
                        }
                    }
                }
            }
            return Ok(0);
        }
        _ => {}
    }

    let store = open_store(paths)?;
    let (nodes, edges) = load_graph(&store, &paths.repository_id().0)?;
    // `deps`/`rdeps` answer "who calls X", one hop: what the MCP contract
    // advertises and what `find_references` aliases to. Sharing the blast-radius
    // depth returned 175 nodes for a function with one caller, everything that
    // reached that caller. Reachability (`paths`, `a -> b`) stays transitive.
    const DIRECT: usize = 1;
    let reach_depth = depth.unwrap_or(blast::DEFAULT_MAX_DEPTH);
    let direct_depth = depth.unwrap_or(DIRECT);

    let resolve = |selector: &TargetSelector| {
        let input = selector_to_blast(selector);
        blast::resolve_target(&input, &nodes)
            .ok_or_else(|| unresolved_target(&input, &nodes, &edges))
    };
    let run = |selector: &TargetSelector,
               direction: ImpactDirection,
               max_depth: usize|
     -> Result<BlastResult> {
        let node = resolve(selector)?;
        blast::blast_radius(&nodes, &edges, &node.id, direction, max_depth).ok_or_else(|| {
            OveccError::Internal {
                message: format!(
                    "resolved target '{}' vanished from the graph view",
                    node.label
                ),
            }
            .into()
        })
    };

    match query {
        Query::Deps(target) => print_query_labels(
            "Dependencies",
            run(target, ImpactDirection::Upstream, direct_depth)?,
            format,
        ),
        Query::ReverseDeps(target) => print_query_labels(
            "Dependents",
            run(target, ImpactDirection::Downstream, direct_depth)?,
            format,
        ),
        Query::Module(name) => {
            let selector = TargetSelector::Free(name.clone());
            print_query_labels(
                "Dependencies",
                run(&selector, ImpactDirection::Upstream, direct_depth)?,
                format,
            )
        }
        Query::Paths(target) => print_query_paths(
            "Paths",
            &run(target, ImpactDirection::Both, reach_depth)?,
            format,
        ),
        Query::Relation { source, target } => {
            let result = run(source, ImpactDirection::Upstream, reach_depth)?;
            // Resolving the right-hand side too keeps `a -> b` honest: an
            // unknown `b` errors with suggestions instead of a false "no".
            let target_node = resolve(target)?;
            let reached = result
                .impacted
                .iter()
                .any(|node| node.label.eq_ignore_ascii_case(&target_node.label));
            let path = result
                .paths
                .iter()
                .find(|p| {
                    p.last()
                        .is_some_and(|l| l.eq_ignore_ascii_case(&target_node.label))
                })
                .cloned();
            match format {
                OutputFormat::Json | OutputFormat::Ndjson => {
                    let data = serde_json::json!({
                        "query": "relation",
                        "source": result.target_label,
                        "target": target_node.label,
                        "depends_on": reached,
                        "path": path,
                    });
                    emit_json("query", &data, meta_for("query"))?;
                }
                _ => {
                    println!(
                        "{} depends on {}: {}",
                        result.target_label,
                        target_node.label,
                        if reached { "yes" } else { "no" }
                    );
                    if let Some(path) = path {
                        println!("  {}", path.join(" -> "));
                    }
                }
            }
            Ok(0)
        }
        // Named queries handled above.
        Query::Hotspots | Query::Violations | Query::Cycles => unreachable!(),
    }
}

/// Usage error for a target no graph node matches. Naming the closest indexed
/// elements lets the caller — human or agent — retry with a real target
/// instead of falling back to a broad text search; the stale index is the
/// other common cause, so the message always ends on it.
fn unresolved_target(input: &str, nodes: &[BlastNode], edges: &[BlastEdge]) -> anyhow::Error {
    // Own the candidate labels up front: they drive both the human prose and the
    // JSON envelope the CLI emits under `--format json`, and the borrowed nodes
    // cannot outlive this call.
    let candidates: Vec<(String, String)> = blast::closest_targets(input, nodes, edges, 5)
        .into_iter()
        .map(|node| (blast::target_syntax(node), node.kind.clone()))
        .collect();
    let message = if candidates.is_empty() {
        format!(
            "no architecture element matches '{input}' — try an indexed module name or file \
             path, or re-run `ovecc index` if the code changed since the last index"
        )
    } else {
        let mut message =
            format!("no architecture element matches '{input}' — closest indexed elements:");
        for (target, kind) in &candidates {
            message.push_str(&format!("\n  {target} ({kind})"));
        }
        message.push_str(
            "\nretry with one of these, or re-run `ovecc index` if the code changed since the last index",
        );
        message
    };
    OveccError::UnresolvedTarget {
        message,
        input: input.to_string(),
        candidates,
    }
    .into()
}

/// Anchors listed before the output caps at [`QUERY_ITEM_CAP`]. A god node can
/// carry hundreds of dependents; the count is the answer at that point, and an
/// uncapped list once cost an agent session more than the grep it replaced.
const QUERY_ITEM_CAP: usize = 50;

// Echoing the resolved label matters because targets resolve by substring:
// `deps sinc` lands on `filter_changed_since`, and a count without the
// resolved name reads as an answer about the literal input.
fn print_query_labels(label: &str, result: BlastResult, format: OutputFormat) -> Result<u8> {
    let items = result.impacted;
    let shown = &items[..items.len().min(QUERY_ITEM_CAP)];
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            let mut data = serde_json::json!({
                "query": label.to_ascii_lowercase(),
                "target": result.target_label,
                "items": shown,
                "total": items.len(),
            });
            if shown.len() < items.len() {
                data["truncated"] = serde_json::json!(true);
            }
            emit_json("query", &data, meta_for("query"))?;
        }
        _ => {
            println!("{label} of {}: {}", result.target_label, items.len());
            for item in shown {
                println!("  {}", format_anchor(item));
            }
            if shown.len() < items.len() {
                println!(
                    "  … and {} more (narrow the question, or `ovecc grep {}` to list use sites)",
                    items.len() - shown.len(),
                    result.target_label
                );
            }
        }
    }
    Ok(0)
}

/// Truncates a JSON array field in place, recording the pre-cap length in a
/// sibling `<field>_total`. Returns whether anything was cut.
fn cap_array(data: &mut serde_json::Value, field: &str, cap: usize) -> bool {
    let Some(items) = data.get_mut(field).and_then(|v| v.as_array_mut()) else {
        return false;
    };
    let total = items.len();
    if total <= cap {
        return false;
    }
    items.truncate(cap);
    data[format!("{field}_total")] = serde_json::json!(total);
    true
}

/// `label  file:line`, or just the label when the node has no single source
/// site (modules, files). The gap keeps the anchor easy to lift into a read.
fn format_anchor(node: &ImpactedNode) -> String {
    match (&node.file, node.line) {
        (Some(file), Some(line)) => format!("{}  {file}:{line}", node.label),
        (Some(file), None) => format!("{}  {file}", node.label),
        _ => node.label.clone(),
    }
}

fn print_query_paths(label: &str, result: &BlastResult, format: OutputFormat) -> Result<u8> {
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            let data = serde_json::json!({
                "query": label.to_ascii_lowercase(),
                "target": result.target_label,
                "paths": result.paths,
            });
            emit_json("query", &data, meta_for("query"))?;
        }
        _ => {
            println!(
                "{label} for {}: {}",
                result.target_label,
                result.paths.len()
            );
            for path in &result.paths {
                println!("  {}", path.join(" -> "));
            }
        }
    }
    Ok(0)
}

/// Builds the deterministic context slice for a target: its
/// dependencies, dependents, call/dependency paths, and findings. The slice
/// is assembled locally and sent nowhere.
pub(crate) fn build_context_slice(
    paths: &ProjectPaths,
    store: &ArchitectureStore,
    target: &str,
) -> Result<ContextSlice> {
    let repository_id = paths.repository_id().0;
    let (nodes, edges) = load_graph(store, &repository_id)?;
    // An unknown target would otherwise narrate an empty slice as if the
    // element existed and were isolated — actively misleading for an agent.
    let Some(node) = blast::resolve_target(target, &nodes) else {
        return Err(unresolved_target(target, &nodes, &edges));
    };
    let (label, target_id) = (node.label.clone(), node.id.clone());

    let radius =
        |direction, depth| blast::blast_radius(&nodes, &edges, &target_id, direction, depth);
    // Depth 1: "dependencies"/"dependents" must mean the direct edges, not the
    // transitive closure — a file two imports away is not a dependency of the
    // target, and narrating it as one is actively misleading.
    let to_refs = |r: BlastResult| -> Vec<AnchoredRef> {
        r.impacted
            .into_iter()
            .map(|n| AnchoredRef {
                label: n.label,
                file: n.file,
                line: n.line,
            })
            .collect()
    };
    let dependencies = radius(ImpactDirection::Upstream, 1)
        .map(to_refs)
        .unwrap_or_default();
    let reverse_dependencies = radius(ImpactDirection::Downstream, 1)
        .map(to_refs)
        .unwrap_or_default();
    // Impact paths follow the reverse-dependency direction only. A `Both`
    // walk stitches forward and backward hops into a single path, producing
    // "impact" chains through the target's own dependencies.
    let call_paths = radius(ImpactDirection::Downstream, blast::DEFAULT_MAX_DEPTH)
        .map(|r| r.paths)
        .unwrap_or_default();

    let needle = label.to_ascii_lowercase();
    let findings = store
        .findings(&repository_id, None)?
        .into_iter()
        .filter(|finding| {
            finding
                .target
                .as_ref()
                .is_some_and(|t| t.id == target_id || t.id.to_ascii_lowercase().contains(&needle))
        })
        .collect();

    Ok(ContextSlice {
        target: label,
        dependencies,
        reverse_dependencies,
        call_paths,
        findings,
        // apis/schemas/ownership/drift are not yet assembled here;
        // export and explain consume the same canonical slice as it grows.
        ..ContextSlice::default()
    })
}

/// A module node labels itself `path/to/file.ext::<module>`. It has no row in
/// the symbol/api/schema anchor tables, so recover its file (the actionable part)
/// from the label. Returns `None` for any other nodeless label (external deps,
/// packages) so only real source modules gain a file.
fn module_file_from_label(label: &str) -> Option<String> {
    const SOURCE_EXTS: [&str; 7] = [".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs"];
    let (head, _) = label.split_once("::")?;
    SOURCE_EXTS
        .iter()
        .any(|ext| head.ends_with(ext))
        .then(|| head.to_string())
}

fn load_graph(
    store: &ArchitectureStore,
    repository_id: &str,
) -> Result<(Vec<BlastNode>, Vec<BlastEdge>)> {
    // Source anchors, joined in at load time so query/impact outputs carry
    // file:line and the agent's next step is a scoped read, not a text search.
    let mut locations: HashMap<String, (String, u32)> = HashMap::new();
    for (id, file, line) in store.node_source_locations(repository_id)? {
        locations.insert(id, (file, line.max(0) as u32));
    }
    let nodes = store
        .graph_nodes(repository_id)?
        .into_iter()
        .map(|(id, kind, label)| {
            let (file, line) = match locations.get(&id) {
                Some((path, at)) => (Some(path.clone()), Some(*at)),
                // A synthesized module node (`path/to/file.py::<module>`) has no
                // anchor row; recover its file from the label so a value-reference
                // dependent still points at an actionable file (line is unknown
                // for a whole module).
                None => (module_file_from_label(&label), None),
            };
            BlastNode {
                id,
                kind,
                label,
                file,
                line,
            }
        })
        .collect();
    let edges = store
        .graph_edges(repository_id)?
        .into_iter()
        .map(|(source, target, kind)| BlastEdge {
            source,
            target,
            kind,
        })
        .collect();
    Ok((nodes, edges))
}

pub(crate) fn load_impact(
    paths: &ProjectPaths,
    target: &str,
    direction: ImpactDirection,
    max_depth: usize,
) -> Result<(BlastResult, Option<String>)> {
    let store = open_store(paths)?;
    let (nodes, edges) = load_graph(&store, &paths.repository_id().0)?;
    let Some(node) = blast::resolve_target(target, &nodes) else {
        return Err(unresolved_target(target, &nodes, &edges));
    };
    // A file target carries no architectural edges of its own — dependency edges
    // are module-level — so a raw file node yields an empty (and falsely
    // reassuring "Low risk") blast radius. Redirect it to the module that
    // `contains` it, so `impact src/foo/bar.ts` answers for module `foo`, and
    // hand the caller the file back so the report can admit the substitution.
    let (node, redirected_from) = match node.kind.as_str() {
        "file" => edges
            .iter()
            .find(|edge| edge.kind == "contains" && edge.target == node.id)
            .and_then(|edge| nodes.iter().find(|candidate| candidate.id == edge.source))
            .map_or((node, None), |module| (module, Some(node.label.clone()))),
        _ => (node, None),
    };
    let result =
        blast::blast_radius(&nodes, &edges, &node.id, direction, max_depth).ok_or_else(|| {
            OveccError::Internal {
                message: format!("resolved target '{target}' vanished from the graph view"),
            }
        })?;
    Ok((result, redirected_from))
}

pub(crate) fn render_blast(
    result: &BlastResult,
    redirected_from: Option<&str>,
    format: OutputFormat,
) -> Result<()> {
    // The prose form for the two human-facing arms; JSON carries the file itself
    // under `redirected_from`.
    let redirect = redirected_from
        .map(|file| format!("{file} has no dependency edges of its own; answering for its module"));
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            // The per-kind counts already summarize the full radius; the node
            // and path lists cap so one hub target cannot flood a session.
            let mut data = serde_json::to_value(result)?;
            let truncated = cap_array(&mut data, "impacted", QUERY_ITEM_CAP)
                | cap_array(&mut data, "paths", 10);
            if truncated {
                data["truncated"] = serde_json::json!(true);
            }
            if let Some(file) = redirected_from {
                data["redirected_from"] = serde_json::json!(file);
            }
            emit_json("impact", &data, meta_for("impact"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("impact", &meta_for("impact"))?;
            println!(
                "{}",
                ndjson_header("impact", result, &["impacted", "paths"])?
            );
            for path in &result.paths {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({"type": "path", "nodes": path}))?
                );
            }
        }
        OutputFormat::Markdown => {
            println!("# Impact: {}", result.target_label);
            println!();
            if let Some(note) = &redirect {
                println!("> {note}");
                println!();
            }
            println!("- Affected modules: {}", result.impacted_modules);
            println!("- Affected APIs: {}", result.impacted_apis);
            println!("- Affected tables: {}", result.impacted_tables);
            println!("- Affected symbols: {}", result.impacted_symbols);
            println!("- Affected files: {}", result.impacted_files);
            println!(
                "- Risk: **{}** ({})",
                result.risk.as_str(),
                result.risk_value
            );
            if !result.paths.is_empty() {
                println!();
                println!("## Top paths");
                println!();
                for path in &result.paths {
                    println!("- `{}`", path.join(" -> "));
                }
            }
        }
        OutputFormat::Text => {
            println!("Impact: {}", result.target_label);
            if let Some(note) = &redirect {
                println!("  ({note})");
            }
            println!("Affected modules: {}", result.impacted_modules);
            println!("Affected APIs: {}", result.impacted_apis);
            println!("Affected tables: {}", result.impacted_tables);
            println!("Affected symbols: {}", result.impacted_symbols);
            println!("Affected files: {}", result.impacted_files);
            println!("Risk: {} ({})", result.risk.as_str(), result.risk_value);
            if !result.paths.is_empty() {
                println!();
                println!("Top paths:");
                for path in &result.paths {
                    println!("  {}", path.join(" -> "));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(input: &str, nodes: &[BlastNode]) -> String {
        format!("{:#}", unresolved_target(input, nodes, &[]))
    }

    #[test]
    fn unresolved_target_names_the_closest_elements() {
        let nodes: Vec<BlastNode> = [
            ("m:billing", "module", "billing"),
            ("t:customers", "table", "customers"),
        ]
        .map(|(id, kind, label)| BlastNode {
            id: id.to_string(),
            kind: kind.to_string(),
            label: label.to_string(),
            file: None,
            line: None,
        })
        .into();
        let text = message("biling", &nodes);
        assert!(text.contains("no architecture element matches 'biling'"));
        assert!(text.contains("billing (module)"), "{text}");
        assert!(text.contains("`ovecc index`"));
        // The table prefix comes back so the suggested retry resolves as typed.
        assert!(message("custommers", &nodes).contains("table:customers (table)"));
    }

    #[test]
    fn unresolved_target_without_candidates_still_points_at_the_index() {
        let text = message("zzzz", &[]);
        assert!(text.contains("no architecture element matches 'zzzz'"));
        assert!(text.contains("`ovecc index`"));
        assert!(!text.contains("closest"));
    }

    #[test]
    fn unresolved_target_carries_structured_candidates() {
        let nodes: Vec<BlastNode> = [("t:customers", "table", "customers")]
            .map(|(id, kind, label)| BlastNode {
                id: id.to_string(),
                kind: kind.to_string(),
                label: label.to_string(),
                file: None,
                line: None,
            })
            .into();
        let err = unresolved_target("custommers", &nodes, &[]);
        let inner = err
            .downcast_ref::<OveccError>()
            .expect("unresolved target is an OveccError");
        match inner {
            OveccError::UnresolvedTarget {
                input, candidates, ..
            } => {
                assert_eq!(input, "custommers");
                // The retry target keeps its resolver prefix and its kind.
                assert_eq!(
                    candidates.first(),
                    Some(&("table:customers".to_string(), "table".to_string()))
                );
            }
            other => panic!("expected UnresolvedTarget, got {other:?}"),
        }
    }
}
