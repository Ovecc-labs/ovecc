//! `ovecc export graph` — the dependency graph as data, or as a viewer.
//!
//! The JSON is the contract: two levels (modules, files) of nodes and edges,
//! sorted so an unchanged database renders byte-identical output. The HTML
//! variant embeds that same JSON plus a vendored vanilla-JS renderer into one
//! self-contained file — no CDN, no runtime dependency, opens offline — in
//! line with the single-binary promise.

use std::collections::{BTreeMap, BTreeSet};

use ovecc_core::legacy::DependencyRecord;
use ovecc_db::FileGraphRow;
use serde::Serialize;

const VIEWER_TEMPLATE: &str = include_str!("../assets/graph-viewer.html");

#[derive(Debug, Serialize)]
pub struct GraphExport {
    pub repository: String,
    pub modules: GraphLevel,
    pub files: GraphLevel,
}

#[derive(Debug, Serialize)]
pub struct GraphLevel {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    /// "module" | "file" | "external"
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    /// "internal" | "external"
    pub kind: String,
}

/// Assembles both levels from the persisted files and dependency records.
/// Pure and deterministic: BTree containers keep every list sorted, repeated
/// imports collapse to one edge, self-edges are dropped.
pub fn build(repository: String, files: &[FileGraphRow], deps: &[DependencyRecord]) -> GraphExport {
    let known_files: BTreeSet<&str> = files.iter().map(|file| file.path.as_str()).collect();
    let mut module_files: BTreeMap<&str, usize> = BTreeMap::new();
    for file in files {
        *module_files.entry(file.module.as_str()).or_default() += 1;
    }

    let mut externals: BTreeSet<String> = BTreeSet::new();
    let mut file_edges: BTreeSet<(String, String, &'static str)> = BTreeSet::new();
    let mut module_edges: BTreeSet<(String, String, &'static str)> = BTreeSet::new();

    for dep in deps {
        if !known_files.contains(dep.source_file_path.as_str()) {
            continue; // stale row; never emit an edge with a dangling endpoint
        }
        if dep.is_unresolved() || dep.is_unindexed() {
            continue;
        }
        if dep.is_external {
            let ext_id = format!("external:{}", dep.target_module);
            file_edges.insert((dep.source_file_path.clone(), ext_id.clone(), "external"));
            module_edges.insert((dep.source_module.clone(), ext_id, "external"));
            externals.insert(dep.target_module.clone());
        } else if let Some(target) = &dep.target_file_path {
            if !known_files.contains(target.as_str()) {
                continue;
            }
            if *target != dep.source_file_path {
                file_edges.insert((dep.source_file_path.clone(), target.clone(), "internal"));
            }
            if dep.source_module != dep.target_module {
                module_edges.insert((
                    dep.source_module.clone(),
                    dep.target_module.clone(),
                    "internal",
                ));
            }
        }
    }

    let external_nodes = externals.iter().map(|name| GraphNode {
        id: format!("external:{name}"),
        label: name.clone(),
        kind: "external".to_string(),
        language: None,
        module: None,
        size_bytes: None,
        files: None,
    });

    let file_nodes = files
        .iter()
        .map(|file| GraphNode {
            id: file.path.clone(),
            label: file.path.clone(),
            kind: "file".to_string(),
            language: Some(file.language.clone()),
            module: Some(file.module.clone()),
            size_bytes: Some(file.size_bytes),
            files: None,
        })
        .chain(external_nodes.clone())
        .collect();

    let module_nodes = module_files
        .iter()
        .map(|(name, count)| GraphNode {
            id: (*name).to_string(),
            label: (*name).to_string(),
            kind: "module".to_string(),
            language: None,
            module: None,
            size_bytes: None,
            files: Some(*count),
        })
        .chain(external_nodes)
        .collect();

    GraphExport {
        repository,
        modules: GraphLevel {
            nodes: module_nodes,
            edges: to_edges(module_edges),
        },
        files: GraphLevel {
            nodes: file_nodes,
            edges: to_edges(file_edges),
        },
    }
}

fn to_edges(set: BTreeSet<(String, String, &'static str)>) -> Vec<GraphEdge> {
    set.into_iter()
        .map(|(source, target, kind)| GraphEdge {
            source,
            target,
            kind: kind.to_string(),
        })
        .collect()
}

/// Inlines the export into the vendored viewer template. Every `<` in the
/// JSON becomes the `<` escape (still valid JSON) so a label containing
/// a closing script tag cannot terminate the data block early.
pub fn render_html(export: &GraphExport) -> anyhow::Result<String> {
    let json = serde_json::to_string(export)?;
    let safe = json.replace('<', "\\u003c");
    Ok(VIEWER_TEMPLATE
        .replace("__OVECC_TITLE__", &html_escape(&export.repository))
        .replacen("__OVECC_DATA__", &safe, 1))
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, module: &str) -> FileGraphRow {
        FileGraphRow {
            path: path.to_string(),
            language: "typescript".to_string(),
            size_bytes: 100,
            module: module.to_string(),
        }
    }

    fn dep(
        source: &str,
        source_module: &str,
        target: Option<&str>,
        target_module: &str,
        is_external: bool,
    ) -> DependencyRecord {
        DependencyRecord {
            id: String::new(),
            repository_id: String::new(),
            source_file_id: String::new(),
            target_file_id: None,
            source_file_path: source.to_string(),
            target_file_path: target.map(str::to_string),
            source_module_id: String::new(),
            target_module_id: String::new(),
            source_module: source_module.to_string(),
            target_module: target_module.to_string(),
            specifier: String::new(),
            dependency_kind: "source_import".to_string(),
            is_external,
            evidence_line: 1,
        }
    }

    #[test]
    fn builds_both_levels_with_deduped_sorted_edges() {
        let files = vec![file("src/a.ts", "alpha"), file("src/b.ts", "beta")];
        let deps = vec![
            dep("src/a.ts", "alpha", Some("src/b.ts"), "beta", false),
            // A second import of the same file collapses to one edge.
            dep("src/a.ts", "alpha", Some("src/b.ts"), "beta", false),
            dep("src/a.ts", "alpha", None, "lodash", true),
            // Intra-module file edge exists; module self-edge does not.
            dep("src/b.ts", "beta", Some("src/a.ts"), "alpha", false),
        ];
        let export = build("demo".to_string(), &files, &deps);

        let file_ids: Vec<&str> = export.files.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(file_ids, ["src/a.ts", "src/b.ts", "external:lodash"]);
        assert_eq!(export.files.edges.len(), 3);

        let module_ids: Vec<&str> = export.modules.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(module_ids, ["alpha", "beta", "external:lodash"]);
        assert_eq!(export.modules.nodes[0].files, Some(1));
        // alpha->beta, beta->alpha, alpha->external — no self-edges.
        assert_eq!(export.modules.edges.len(), 3);
        assert!(
            export
                .modules
                .edges
                .iter()
                .all(|edge| edge.source != edge.target)
        );
    }

    #[test]
    fn dangling_dependency_rows_are_skipped() {
        let files = vec![file("src/a.ts", "alpha")];
        let deps = vec![dep("gone.ts", "ghost", Some("src/a.ts"), "alpha", false)];
        let export = build("demo".to_string(), &files, &deps);
        assert!(export.files.edges.is_empty());
        assert!(export.modules.edges.is_empty());
    }

    #[test]
    fn html_embeds_escaped_data_and_title() {
        let files = vec![file("src/</script>.ts", "alpha")];
        let export = build("demo & co".to_string(), &files, &[]);
        let html = render_html(&export).unwrap();
        assert!(!html.contains("__OVECC_DATA__"));
        assert!(!html.contains("__OVECC_TITLE__"));
        // The hostile label survives as JSON but cannot close the script tag.
        assert!(!html.contains("</script>.ts"));
        assert!(html.contains("\\u003c/script>.ts"));
        assert!(html.contains("demo &amp; co"));
    }
}
