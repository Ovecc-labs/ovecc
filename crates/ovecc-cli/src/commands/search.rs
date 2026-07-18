//! `ovecc read` and `ovecc grep`: the two primitives that substitute for
//! whole-file reads and repo-wide text search in an agent loop.
//!
//! The cost problem they answer is measured, not assumed: in agent sessions,
//! file reads carry ~73% of all tool-result bytes, and graph answers stack on
//! top of grep+read instead of replacing them when ovecc cannot serve the
//! search itself. `grep` searches the index first (definitions ranked before
//! text matches, deduplicated, capped) and falls back to an ignore-aware disk
//! scan so it covers everything a plain grep covers. `read` slices exactly one
//! symbol's source from disk using the spans the index already stores, so the
//! agent never pages a 2,000-line file to see a 30-line function.

use super::open_store;
use crate::render::{emit_json, meta_for};
use anyhow::Result;
use ovecc_core::config::{OutputFormat, ProjectPaths};
use ovecc_core::error::OveccError;
use ovecc_db::SymbolDef;
use regex::RegexBuilder;
use std::path::Path;

/// Lines of source `read` prints before truncating; enough for almost any
/// single function body, small enough that a stale span cannot flood a session.
pub(crate) const DEFAULT_READ_LINES: usize = 200;

/// Matches `grep` renders before truncating. Totals always cover the full set.
pub(crate) const DEFAULT_GREP_LIMIT: usize = 50;

/// Text matches shown per file; the rest of a file collapses to a count so one
/// chatty file cannot spend the whole budget.
const PER_FILE_MATCHES: usize = 5;

/// Window printed when the target is a bare `file:line` anchor with no
/// enclosing symbol, or a file with no indexed symbols.
const FALLBACK_WINDOW: usize = 40;

const MAX_LINE_CHARS: usize = 160;
const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) fn run_read(
    paths: &ProjectPaths,
    target: &str,
    max_lines: usize,
    format: OutputFormat,
) -> Result<u8> {
    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let defs = store.symbol_defs(&repository_id)?;
    let max_lines = if max_lines == 0 {
        usize::MAX
    } else {
        max_lines
    };

    let normalized = target.replace('\\', "/");
    if let Some((file, range)) = split_file_range(&normalized, &paths.root, &defs) {
        return read_range(paths, &defs, &file, range, max_lines, format);
    }
    if let Some(file) = resolve_file(&normalized, &paths.root, &defs) {
        return read_outline(paths, &defs, &file, max_lines, format);
    }
    read_symbol(paths, &defs, target, max_lines, format)
}

/// `path:12` / `path:12-80` when the prefix names a real file. Splitting on the
/// last `:` keeps Windows-style absolute prefixes from being read as ranges.
fn split_file_range(target: &str, root: &Path, defs: &[SymbolDef]) -> Option<(String, (u32, u32))> {
    let (prefix, suffix) = target.rsplit_once(':')?;
    let range = parse_range(suffix)?;
    let file = resolve_file(prefix, root, defs)?;
    Some((file, range))
}

fn parse_range(suffix: &str) -> Option<(u32, u32)> {
    if let Some((start, end)) = suffix.split_once('-') {
        let (start, end) = (start.parse().ok()?, end.parse().ok()?);
        (start >= 1 && end >= start).then_some((start, end))
    } else {
        let line: u32 = suffix.parse().ok()?;
        (line >= 1).then_some((line, line))
    }
}

/// Resolves an input path against the disk first (so unindexed files like
/// configs still read), then as a unique suffix of an indexed path (so the
/// short form `parser.py` works when it is unambiguous).
fn resolve_file(input: &str, root: &Path, defs: &[SymbolDef]) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    if root.join(input).is_file() {
        return Some(input.trim_start_matches("./").to_string());
    }
    let suffix = format!("/{}", input.trim_start_matches('/'));
    let mut hits = defs
        .iter()
        .map(|def| def.path.as_str())
        .filter(|path| path.ends_with(&suffix))
        .collect::<Vec<_>>();
    hits.dedup();
    match hits.as_slice() {
        [only] => Some(only.to_string()),
        _ => None,
    }
}

fn read_range(
    paths: &ProjectPaths,
    defs: &[SymbolDef],
    file: &str,
    (start, end): (u32, u32),
    max_lines: usize,
    format: OutputFormat,
) -> Result<u8> {
    // A single-line anchor (the form query/impact/grep emit) means "show me
    // this element", so widen to the enclosing symbol when the index knows it.
    let (start, end, label) = if start == end {
        match enclosing_symbol(defs, file, start) {
            Some(def) => (
                def.start_line,
                def.end_line,
                format!("{} {}", def.kind, def.qualified_name),
            ),
            None => (start, start + FALLBACK_WINDOW as u32 - 1, String::new()),
        }
    } else {
        (start, end, String::new())
    };
    print_slice(paths, file, start, end, &label, max_lines, format)
}

/// The innermost indexed symbol whose span contains the line.
fn enclosing_symbol<'a>(defs: &'a [SymbolDef], file: &str, line: u32) -> Option<&'a SymbolDef> {
    defs.iter()
        .filter(|def| def.path == file && def.start_line <= line && line <= def.end_line)
        .min_by_key(|def| def.end_line - def.start_line)
}

/// A bare file target prints the file's symbol outline — spans and kinds — so
/// the agent picks one body instead of paging the whole file. Files the index
/// has no symbols for (configs, docs) fall back to a capped head.
fn read_outline(
    paths: &ProjectPaths,
    defs: &[SymbolDef],
    file: &str,
    max_lines: usize,
    format: OutputFormat,
) -> Result<u8> {
    let mut symbols: Vec<&SymbolDef> = defs.iter().filter(|def| def.path == file).collect();
    symbols.sort_by_key(|def| (def.start_line, def.end_line));
    symbols.dedup_by_key(|def| def.start_line);
    if symbols.is_empty() {
        let window = FALLBACK_WINDOW.min(max_lines) as u32;
        return print_slice(paths, file, 1, window, "", max_lines, format);
    }
    if matches!(format, OutputFormat::Json | OutputFormat::Ndjson) {
        let data = serde_json::json!({
            "target": file,
            "outline": symbols.iter().map(|def| serde_json::json!({
                "name": def.qualified_name,
                "kind": def.kind,
                "start_line": def.start_line,
                "end_line": def.end_line,
            })).collect::<Vec<_>>(),
            "next_call": format!("ovecc read {file}:<start>-<end>"),
        });
        emit_json("read", &data, meta_for("read"))?;
        return Ok(0);
    }
    println!("{file}: {} symbols", symbols.len());
    for def in &symbols {
        println!(
            "  {}-{}  {} {}",
            def.start_line, def.end_line, def.kind, def.qualified_name
        );
    }
    println!("Read one body: ovecc read {file}:<start>-<end>");
    Ok(0)
}

fn read_symbol(
    paths: &ProjectPaths,
    defs: &[SymbolDef],
    target: &str,
    max_lines: usize,
    format: OutputFormat,
) -> Result<u8> {
    let matches = resolve_symbol(defs, target);
    match matches.as_slice() {
        [] => Err(unknown_symbol(defs, target)),
        [def] => {
            let label = format!("{} {}", def.kind, def.qualified_name);
            print_slice(
                paths,
                &def.path,
                def.start_line,
                def.end_line,
                &label,
                max_lines,
                format,
            )
        }
        several => print_candidates(target, several, format),
    }
}

/// Definition sites for a symbol name, best tier first: exact, case-insensitive
/// exact, qualified-name suffix, then substring. Only the first non-empty tier
/// is returned, so `run` never drowns in every symbol containing "run".
fn resolve_symbol<'a>(defs: &'a [SymbolDef], target: &str) -> Vec<&'a SymbolDef> {
    let lower = target.to_lowercase();
    let tiers: [&dyn Fn(&SymbolDef) -> bool; 4] = [
        &|def| def.name == target,
        &|def| def.name.eq_ignore_ascii_case(target),
        &|def| qualified_suffix(&def.qualified_name, target),
        &|def| def.name.to_lowercase().contains(&lower),
    ];
    for tier in tiers {
        let mut hits: Vec<&SymbolDef> = defs.iter().filter(|def| tier(def)).collect();
        if !hits.is_empty() {
            hits.sort_by_key(|def| (def.path.clone(), def.start_line));
            hits.dedup_by_key(|def| (def.path.clone(), def.start_line));
            return hits;
        }
    }
    Vec::new()
}

/// `Parser.parse` matches qualified name `sqlglot.Parser.parse` but not
/// `reparse`: the match must sit on a `.`/`:` boundary or span the whole name.
fn qualified_suffix(qualified: &str, target: &str) -> bool {
    let Some(head) = qualified.strip_suffix(target) else {
        return false;
    };
    head.is_empty() || head.ends_with(['.', ':'])
}

fn unknown_symbol(defs: &[SymbolDef], target: &str) -> anyhow::Error {
    let lower = target.to_lowercase();
    let mut candidates: Vec<(String, String)> = defs
        .iter()
        .filter(|def| {
            let name = def.name.to_lowercase();
            name.contains(&lower) || lower.contains(&name)
        })
        .map(|def| (def.name.clone(), def.kind.clone()))
        .collect();
    candidates.sort();
    candidates.dedup();
    candidates.truncate(5);
    let mut message = format!("no indexed symbol matches '{target}'");
    if candidates.is_empty() {
        message.push_str(
            " — search for it with `ovecc grep`, or re-run `ovecc index` if the code changed",
        );
    } else {
        message.push_str(" — closest indexed symbols:");
        for (name, kind) in &candidates {
            message.push_str(&format!("\n  {name} ({kind})"));
        }
        message.push_str("\nretry with one of these, or search with `ovecc grep`");
    }
    OveccError::UnresolvedTarget {
        message,
        input: target.to_string(),
        candidates,
    }
    .into()
}

/// Several definitions share the name (dialect overrides, trait impls). Listing
/// the anchors IS the answer: the agent picks one and reads that exact span.
fn print_candidates(target: &str, defs: &[&SymbolDef], format: OutputFormat) -> Result<u8> {
    let shown = &defs[..defs.len().min(10)];
    if matches!(format, OutputFormat::Json | OutputFormat::Ndjson) {
        let data = serde_json::json!({
            "target": target,
            "definitions": shown.iter().map(|def| serde_json::json!({
                "name": def.qualified_name,
                "kind": def.kind,
                "file": def.path,
                "start_line": def.start_line,
                "end_line": def.end_line,
            })).collect::<Vec<_>>(),
            "total": defs.len(),
            "next_call": "ovecc read <file>:<start>-<end> for one of these",
        });
        emit_json("read", &data, meta_for("read"))?;
        return Ok(0);
    }
    println!("{} definitions match '{target}':", defs.len());
    for def in shown {
        println!(
            "  {}  {}:{}-{}  ({})",
            def.qualified_name, def.path, def.start_line, def.end_line, def.kind
        );
    }
    if defs.len() > shown.len() {
        println!("  … and {} more", defs.len() - shown.len());
    }
    println!("Pick one: ovecc read <file>:<start>-<end>");
    Ok(0)
}

/// Prints `[start, end]` of a file, line-numbered, with a header anchor. The
/// cap truncates with the exact continuation range so a follow-up read costs
/// one call, not a guess.
fn print_slice(
    paths: &ProjectPaths,
    file: &str,
    start: u32,
    end: u32,
    label: &str,
    max_lines: usize,
    format: OutputFormat,
) -> Result<u8> {
    let full = paths.root.join(file);
    let text = std::fs::read_to_string(&full).map_err(|err| OveccError::Usage {
        message: format!("cannot read {file}: {err}"),
    })?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() || start as usize > lines.len() {
        return Err(OveccError::Usage {
            message: format!(
                "{file} has {} lines, requested start {start} — re-run `ovecc index` if the code changed",
                lines.len()
            ),
        }
        .into());
    }
    let end = (end as usize).min(lines.len()) as u32;
    let shown_end = end.min(start + max_lines.saturating_sub(1) as u32);
    let slice: Vec<String> = (start..=shown_end)
        .map(|n| lines[n as usize - 1].trim_end().to_string())
        .collect();

    if matches!(format, OutputFormat::Json | OutputFormat::Ndjson) {
        let mut data = serde_json::json!({
            "file": file,
            "start_line": start,
            "end_line": shown_end,
            "label": label,
            "source": slice.join("\n"),
        });
        if shown_end < end {
            data["truncated"] = serde_json::json!(true);
            data["next_call"] = serde_json::json!(format!(
                "ovecc read {file}:{}-{end} for the rest",
                shown_end + 1
            ));
        }
        emit_json("read", &data, meta_for("read"))?;
        return Ok(0);
    }
    if label.is_empty() {
        println!("{file}:{start}-{shown_end}");
    } else {
        println!("{file}:{start}-{shown_end}  {label}");
    }
    for (offset, line) in slice.iter().enumerate() {
        println!("{:>5}  {line}", start as usize + offset);
    }
    if shown_end < end {
        println!(
            "… truncated at {max_lines} lines; the rest: ovecc read {file}:{}-{end}",
            shown_end + 1
        );
    }
    Ok(0)
}

pub(crate) fn run_grep(
    paths: &ProjectPaths,
    pattern: &str,
    scopes: &[String],
    limit: usize,
    format: OutputFormat,
) -> Result<u8> {
    if pattern.is_empty() {
        return Err(OveccError::Usage {
            message: "empty search pattern".to_string(),
        }
        .into());
    }
    // Smart case, ripgrep's default: an all-lowercase pattern searches
    // case-insensitively, any uppercase makes it exact.
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(!pattern.chars().any(|c| c.is_ascii_uppercase()))
        .build()
        .map_err(|err| OveccError::Usage {
            message: format!("invalid regex '{pattern}': {err}"),
        })?;
    let limit = if limit == 0 { usize::MAX } else { limit };

    let store = open_store(paths)?;
    let repository_id = paths.repository_id().0;
    let mut definitions: Vec<SymbolDef> = store
        .symbol_defs(&repository_id)?
        .into_iter()
        .filter(|def| regex.is_match(&def.name) || regex.is_match(&def.qualified_name))
        .collect();
    definitions.sort_by_key(|def| (is_test_path(&def.path), def.path.clone(), def.start_line));
    definitions.dedup_by_key(|def| (def.path.clone(), def.start_line));

    let files = scan_files(&paths.root, scopes)?;
    let matches = scan_matches(&paths.root, &files, &regex);

    render_grep(pattern, &definitions, &matches, limit, format)
}

struct GrepMatch {
    file: String,
    line: u32,
    text: String,
}

/// The candidate files for the text scan: the same ignore-aware walk the
/// indexer uses (gitignore honoured, vendored/build trees pruned), but over
/// every text file — configs and docs included — so this covers everything a
/// plain grep would. Sorted for deterministic output, tests demoted last.
fn scan_files(root: &Path, scopes: &[String]) -> Result<Vec<String>> {
    let mut roots = Vec::new();
    if scopes.is_empty() {
        roots.push(root.to_path_buf());
    }
    for scope in scopes {
        let path = root.join(scope);
        if !path.exists() {
            return Err(OveccError::Usage {
                message: format!("search path '{scope}' does not exist in the repository"),
            }
            .into());
        }
        roots.push(path);
    }

    let mut files = Vec::new();
    for base in roots {
        let mut builder = ignore::WalkBuilder::new(&base);
        builder
            .hidden(false)
            .parents(true)
            .git_ignore(true)
            .git_exclude(true);
        builder.filter_entry(|entry| {
            entry.depth() == 0
                || entry
                    .file_name()
                    .to_str()
                    .map(|name| !ovecc_indexer::is_excluded_component(name))
                    .unwrap_or(true)
        });
        for entry in builder.build().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(meta) = entry.metadata()
                && meta.len() > MAX_SCAN_BYTES
            {
                continue;
            }
            if let Ok(relative) = path.strip_prefix(root) {
                files.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    files.sort_by_key(|path| (is_test_path(path), path.clone()));
    files.dedup();
    Ok(files)
}

fn scan_matches(root: &Path, files: &[String], regex: &regex::Regex) -> Vec<GrepMatch> {
    use rayon::prelude::*;
    // Parallel per file, flattened in file order, so the output stays
    // deterministic while a large corpus scans in interactive time.
    files
        .par_iter()
        .map(|file| {
            let Ok(bytes) = std::fs::read(root.join(file)) else {
                return Vec::new();
            };
            // NUL in the head marks a binary; grep skips those too.
            if bytes[..bytes.len().min(1024)].contains(&0) {
                return Vec::new();
            }
            let text = String::from_utf8_lossy(&bytes);
            let mut found = Vec::new();
            for (index, line) in text.lines().enumerate() {
                if regex.is_match(line) {
                    found.push(GrepMatch {
                        file: file.clone(),
                        line: index as u32 + 1,
                        text: clip_line(line),
                    });
                }
            }
            found
        })
        .flatten()
        .collect()
}

fn clip_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.chars().count() <= MAX_LINE_CHARS {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(MAX_LINE_CHARS).collect();
    format!("{head}…")
}

/// A test path ranks after source in both definition and match lists: when the
/// budget truncates, the implementation survives, not its fixtures.
fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    if lower.split('/').any(|part| {
        matches!(
            part,
            "test" | "tests" | "__tests__" | "testdata" | "fixtures"
        )
    }) {
        return true;
    }
    let stem = lower.rsplit('/').next().unwrap_or(&lower);
    stem.starts_with("test_")
        || stem.contains("_test.")
        || stem.contains(".test.")
        || stem.contains(".spec.")
}

fn render_grep(
    pattern: &str,
    definitions: &[SymbolDef],
    matches: &[GrepMatch],
    limit: usize,
    format: OutputFormat,
) -> Result<u8> {
    let shown_defs = &definitions[..definitions.len().min(20)];
    let files_matched = {
        let mut files: Vec<&str> = matches.iter().map(|m| m.file.as_str()).collect();
        files.dedup();
        files.len()
    };
    let (shown, per_file_hidden) = select_matches(matches, limit);

    if matches!(format, OutputFormat::Json | OutputFormat::Ndjson) {
        let data = serde_json::json!({
            "pattern": pattern,
            "definitions": shown_defs.iter().map(|def| serde_json::json!({
                "name": def.qualified_name,
                "kind": def.kind,
                "file": def.path,
                "start_line": def.start_line,
                "end_line": def.end_line,
            })).collect::<Vec<_>>(),
            "definitions_total": definitions.len(),
            "matches": shown.iter().map(|m| serde_json::json!({
                "file": m.file, "line": m.line, "text": m.text,
            })).collect::<Vec<_>>(),
            "matches_total": matches.len(),
            "files_matched": files_matched,
            "truncated": shown.len() < matches.len(),
        });
        emit_json("grep", &data, meta_for("grep"))?;
        return Ok(0);
    }

    if !definitions.is_empty() {
        println!("Definitions: {}", definitions.len());
        for def in shown_defs {
            println!(
                "  {}  {}:{}-{}  ({})",
                def.qualified_name, def.path, def.start_line, def.end_line, def.kind
            );
        }
        if definitions.len() > shown_defs.len() {
            println!("  … and {} more", definitions.len() - shown_defs.len());
        }
    }
    println!(
        "Matches: {} in {} files{}",
        matches.len(),
        files_matched,
        if shown.len() < matches.len() {
            format!(" (showing {})", shown.len())
        } else {
            String::new()
        }
    );
    for m in &shown {
        println!("  {}:{}: {}", m.file, m.line, m.text);
    }
    // Per-file remainders only for files the agent just saw; everything else
    // collapses to one line, or a match in 1,500 files would print 1,500 of
    // them.
    let shown_files: std::collections::BTreeSet<&str> =
        shown.iter().map(|m| m.file.as_str()).collect();
    let mut unseen_matches = 0usize;
    let mut unseen_files = 0usize;
    for (file, hidden) in &per_file_hidden {
        if shown_files.contains(file) {
            println!("  {file}: +{hidden} more");
        } else {
            unseen_matches += hidden;
            unseen_files += 1;
        }
    }
    if unseen_files > 0 {
        println!("  … {unseen_matches} more matches in {unseen_files} other files");
    }
    if shown.len() < matches.len() {
        println!("Narrow with a path (ovecc grep PATTERN src/) or raise --limit.");
    }
    if let Some(def) = definitions.first() {
        println!(
            "Next: ovecc read {} | ovecc query \"rdeps {}\"",
            def.name, def.name
        );
    }
    Ok(0)
}

/// Applies the per-file and global caps: up to [`PER_FILE_MATCHES`] per file
/// until `limit` fills, and a per-file hidden count for the rest.
fn select_matches(
    matches: &[GrepMatch],
    limit: usize,
) -> (Vec<&GrepMatch>, std::collections::BTreeMap<&str, usize>) {
    let mut shown = Vec::new();
    let mut per_file_shown: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    let mut per_file_hidden: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for m in matches {
        let count = per_file_shown.entry(m.file.as_str()).or_insert(0);
        if shown.len() < limit && *count < PER_FILE_MATCHES {
            *count += 1;
            shown.push(m);
        } else {
            *per_file_hidden.entry(m.file.as_str()).or_insert(0) += 1;
        }
    }
    (shown, per_file_hidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(name: &str, qualified: &str, kind: &str, path: &str, start: u32, end: u32) -> SymbolDef {
        SymbolDef {
            name: name.to_string(),
            qualified_name: qualified.to_string(),
            kind: kind.to_string(),
            path: path.to_string(),
            start_line: start,
            end_line: end,
        }
    }

    #[test]
    fn symbol_resolution_prefers_exact_over_substring() {
        let defs = vec![
            def(
                "parse",
                "sqlglot.Parser.parse",
                "method",
                "parser.py",
                10,
                40,
            ),
            def(
                "parse_into",
                "sqlglot.Parser.parse_into",
                "method",
                "parser.py",
                50,
                80,
            ),
        ];
        let hits = resolve_symbol(&defs, "parse");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "parse");
        // Substring tier still reaches the other one under a partial input.
        assert_eq!(resolve_symbol(&defs, "parse_in")[0].name, "parse_into");
    }

    #[test]
    fn qualified_suffix_needs_a_boundary() {
        assert!(qualified_suffix("sqlglot.Parser.parse", "Parser.parse"));
        assert!(qualified_suffix("mod::run", "run"));
        assert!(!qualified_suffix("sqlglot.Parser.reparse", "parse"));
    }

    #[test]
    fn range_parsing_accepts_line_and_span_forms() {
        assert_eq!(parse_range("12"), Some((12, 12)));
        assert_eq!(parse_range("10-80"), Some((10, 80)));
        assert_eq!(parse_range("80-10"), None);
        assert_eq!(parse_range("0"), None);
        assert_eq!(parse_range("abc"), None);
    }

    #[test]
    fn enclosing_symbol_picks_the_innermost_span() {
        let defs = vec![
            def("Outer", "Outer", "class", "a.py", 1, 100),
            def("inner", "Outer.inner", "method", "a.py", 40, 60),
        ];
        assert_eq!(enclosing_symbol(&defs, "a.py", 50).unwrap().name, "inner");
        assert_eq!(enclosing_symbol(&defs, "a.py", 5).unwrap().name, "Outer");
        assert!(enclosing_symbol(&defs, "b.py", 50).is_none());
    }

    #[test]
    fn test_paths_rank_after_source() {
        assert!(is_test_path("tests/test_parser.py"));
        assert!(is_test_path("src/foo.test.ts"));
        assert!(is_test_path("src/test_utils.py"));
        assert!(!is_test_path("src/parser.py"));
        assert!(!is_test_path("src/contest.py"));
    }

    #[test]
    fn per_file_and_global_caps_apply() {
        let matches: Vec<GrepMatch> = (0..12)
            .map(|i| GrepMatch {
                file: if i < 8 { "a.py" } else { "b.py" }.to_string(),
                line: i + 1,
                text: "x".to_string(),
            })
            .collect();
        let (shown, hidden) = select_matches(&matches, 50);
        // 5 per file: a.py keeps 5 of 8, b.py all 4.
        assert_eq!(shown.len(), 9);
        assert_eq!(hidden.get("a.py"), Some(&3));
        let (capped, _) = select_matches(&matches, 3);
        assert_eq!(capped.len(), 3);
    }

    #[test]
    fn long_lines_clip_with_a_marker() {
        let long = "y".repeat(500);
        assert!(clip_line(&long).ends_with('…'));
        assert_eq!(clip_line("  short  "), "short");
    }
}
