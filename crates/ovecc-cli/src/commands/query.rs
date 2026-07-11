//! Reads over the persisted graph: `query`, `impact`, `explain`, and the
//! `export context` slice.

use super::findings::render_violations;
use super::open_store;
use super::summary::{load_hotspots, render_hotspots};
use crate::render::{emit_json, emit_ndjson_meta, meta_for, ndjson_header};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_core::legacy::ImpactDirection;
use ovecc_core::query::{Query, TargetSelector};
use ovecc_core::report::ContextSlice;
use ovecc_db::ArchitectureStore;
use ovecc_graph::blast::{self, BlastEdge, BlastNode, BlastResult};

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

pub(crate) fn run_query(paths: &ProjectPaths, query: &Query, format: OutputFormat) -> Result<u8> {
    match query {
        Query::Hotspots => {
            let report = load_hotspots(paths, 10)?;
            render_hotspots(&report, format)?;
            return Ok(0);
        }
        Query::Violations => {
            let store = open_store(paths)?;
            let findings = store.findings(&paths.repository_id().0, None)?;
            render_violations(&findings, format)?;
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
    const DEPTH: usize = blast::DEFAULT_MAX_DEPTH;

    let run = |selector: &TargetSelector, direction: ImpactDirection| {
        blast::resolve_target(&selector_to_blast(selector), &nodes)
            .and_then(|node| blast::blast_radius(&nodes, &edges, &node.id, direction, DEPTH))
    };

    match query {
        Query::Deps(target) => print_query_labels(
            "Dependencies",
            run(target, ImpactDirection::Upstream),
            format,
        ),
        Query::ReverseDeps(target) => print_query_labels(
            "Dependents",
            run(target, ImpactDirection::Downstream),
            format,
        ),
        Query::Module(name) => {
            let selector = TargetSelector::Free(name.clone());
            print_query_labels(
                "Dependencies",
                run(&selector, ImpactDirection::Upstream),
                format,
            )
        }
        Query::Paths(target) => {
            let result = run(target, ImpactDirection::Both);
            print_query_paths(
                "Paths",
                &result.map(|r| r.paths).unwrap_or_default(),
                format,
            )
        }
        Query::Relation { source, target } => {
            let result = run(source, ImpactDirection::Upstream);
            let needle = target.needle().to_ascii_lowercase();
            let reached = result
                .as_ref()
                .map(|r| {
                    r.impacted_labels
                        .iter()
                        .any(|label| label.to_ascii_lowercase().contains(&needle))
                })
                .unwrap_or(false);
            let path = result
                .as_ref()
                .and_then(|r| {
                    r.paths.iter().find(|p| {
                        p.last()
                            .is_some_and(|l| l.to_ascii_lowercase().contains(&needle))
                    })
                })
                .cloned();
            match format {
                OutputFormat::Json | OutputFormat::Ndjson => {
                    let data = serde_json::json!({
                        "query": "relation",
                        "source": source.needle(),
                        "target": target.needle(),
                        "depends_on": reached,
                        "path": path,
                    });
                    emit_json("query", &data, meta_for("query"))?;
                }
                _ => {
                    println!(
                        "{} depends on {}: {}",
                        source.needle(),
                        target.needle(),
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

fn print_query_labels(
    label: &str,
    result: Option<BlastResult>,
    format: OutputFormat,
) -> Result<u8> {
    let labels = result.map(|r| r.impacted_labels).unwrap_or_default();
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            let data = serde_json::json!({
                "query": label.to_ascii_lowercase(),
                "items": labels,
            });
            emit_json("query", &data, meta_for("query"))?;
        }
        _ => {
            println!("{label}: {}", labels.len());
            for item in &labels {
                println!("  {item}");
            }
        }
    }
    Ok(0)
}

fn print_query_paths(label: &str, paths: &[Vec<String>], format: OutputFormat) -> Result<u8> {
    match format {
        OutputFormat::Json | OutputFormat::Ndjson => {
            let data = serde_json::json!({
                "query": label.to_ascii_lowercase(),
                "paths": paths,
            });
            emit_json("query", &data, meta_for("query"))?;
        }
        _ => {
            println!("{label}: {}", paths.len());
            for path in paths {
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
    let resolved = blast::resolve_target(target, &nodes);
    // An unknown target would otherwise narrate an empty slice as if the
    // element existed and were isolated — actively misleading for an agent.
    if resolved.is_none() {
        return Err(OveccError::Usage {
            message: format!(
                "no architecture element matches '{target}' — try a module name, a file path, \
                 or `ovecc query \"module {target}\"` to search"
            ),
        }
        .into());
    }
    let (label, target_id) = match &resolved {
        Some(node) => (node.label.clone(), Some(node.id.clone())),
        None => (target.to_string(), None),
    };

    let radius = |direction, depth| {
        target_id
            .as_ref()
            .and_then(|id| blast::blast_radius(&nodes, &edges, id, direction, depth))
    };
    // Depth 1: "dependencies"/"dependents" must mean the direct edges, not the
    // transitive closure — a file two imports away is not a dependency of the
    // target, and narrating it as one is actively misleading.
    let dependencies = radius(ImpactDirection::Upstream, 1)
        .map(|r| r.impacted_labels)
        .unwrap_or_default();
    let reverse_dependencies = radius(ImpactDirection::Downstream, 1)
        .map(|r| r.impacted_labels)
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
            finding.target.as_ref().is_some_and(|t| {
                Some(&t.id) == target_id.as_ref() || t.id.to_ascii_lowercase().contains(&needle)
            })
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

fn load_graph(
    store: &ArchitectureStore,
    repository_id: &str,
) -> Result<(Vec<BlastNode>, Vec<BlastEdge>)> {
    let nodes = store
        .graph_nodes(repository_id)?
        .into_iter()
        .map(|(id, kind, label)| BlastNode { id, kind, label })
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
) -> Result<BlastResult> {
    let store = open_store(paths)?;
    let (nodes, edges) = load_graph(&store, &paths.repository_id().0)?;
    let Some(node) = blast::resolve_target(target, &nodes) else {
        return Err(OveccError::Usage {
            message: format!(
                "no architecture element matches '{target}' — try a module name, a file path, \
                 or `ovecc query \"module {target}\"` to search"
            ),
        }
        .into());
    };
    // A file target carries no architectural edges of its own — dependency edges
    // are module-level — so a raw file node yields an empty (and falsely
    // reassuring "Low risk") blast radius. Redirect it to the module that
    // `contains` it, so `impact src/foo/bar.ts` answers for module `foo`.
    let node = if node.kind == "file" {
        edges
            .iter()
            .find(|edge| edge.kind == "contains" && edge.target == node.id)
            .and_then(|edge| nodes.iter().find(|candidate| candidate.id == edge.source))
            .unwrap_or(node)
    } else {
        node
    };
    blast::blast_radius(&nodes, &edges, &node.id, direction, max_depth).ok_or_else(|| {
        OveccError::Internal {
            message: format!("resolved target '{target}' vanished from the graph view"),
        }
        .into()
    })
}

pub(crate) fn render_blast(result: &BlastResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::Sarif | OutputFormat::Codeclimate => {
            emit_json("impact", result, meta_for("impact"))?
        }
        OutputFormat::Ndjson => {
            emit_ndjson_meta("impact", &meta_for("impact"))?;
            println!(
                "{}",
                ndjson_header("impact", result, &["impacted_labels", "paths"])?
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
