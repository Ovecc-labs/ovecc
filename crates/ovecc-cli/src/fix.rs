//! Mechanical remediation for auto-fixable findings.
//!
//! Scope is deliberately narrow — only edits with one unambiguous outcome:
//! deleting an unreachable file, dropping an `export` keyword, removing an
//! unused manifest dependency. Anything that needs judgement stays a finding
//! (`fix_spec().auto_fixable == false`) and is never touched here.
//!
//! Dry-run is the default. Every edit re-verifies the current file content
//! against the finding's evidence before writing, so a stale index makes the
//! action skip with a reason instead of mangling a file that moved on.

use ovecc_core::facts::{FindingKind, FindingRecord};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// The outcome of one `ovecc fix` run.
#[derive(Debug, Serialize)]
pub struct FixReport {
    /// False for a dry-run: `actions` describe what *would* change.
    pub applied: bool,
    pub fixed: usize,
    pub skipped: usize,
    pub actions: Vec<FixAction>,
}

#[derive(Debug, Serialize)]
pub struct FixAction {
    /// The machine fix kind (matches `FixSpec.kind`).
    pub fix: &'static str,
    pub rule: String,
    pub file: String,
    pub line: Option<u32>,
    pub symbol: Option<String>,
    /// "planned" (dry-run) | "fixed" | "skipped".
    pub status: &'static str,
    /// Change preview (`- old` / `+ new`), or the skip reason.
    pub detail: String,
}

/// Plans (and with `apply`, performs) the mechanical fixes for `findings`.
/// Only auto-fixable kinds are considered; callers pre-filter, but the run
/// re-checks so a mixed list can never trigger a non-mechanical change.
pub fn run(root: &Path, findings: &[FindingRecord], apply: bool) -> FixReport {
    let mut actions: Vec<FixAction> = Vec::new();

    // Group line edits per file so they apply bottom-up in one write, keeping
    // every other finding's line numbers valid.
    let mut exports_by_file: BTreeMap<String, Vec<&FindingRecord>> = BTreeMap::new();
    // Manifest removals grouped per manifest for the same reason.
    let mut deps_by_manifest: BTreeMap<String, Vec<&FindingRecord>> = BTreeMap::new();
    // Stale ovecc-ignore comments, grouped per file.
    let mut stale_by_file: BTreeMap<String, Vec<&FindingRecord>> = BTreeMap::new();

    for finding in findings {
        if !finding.kind.fix_spec().auto_fixable {
            continue;
        }
        let Some(evidence) = finding.evidence.first() else {
            continue;
        };
        match finding.kind {
            FindingKind::UnusedFile => {
                actions.push(fix_unused_file(root, finding, &evidence.file_path, apply));
            }
            FindingKind::UnusedExport => {
                exports_by_file
                    .entry(evidence.file_path.clone())
                    .or_default()
                    .push(finding);
            }
            FindingKind::UnusedDependency => {
                deps_by_manifest
                    .entry(evidence.file_path.clone())
                    .or_default()
                    .push(finding);
            }
            FindingKind::UnlistedDependency => {
                actions.push(fix_unlisted_dependency(root, finding, apply));
            }
            FindingKind::StaleSuppression => {
                stale_by_file
                    .entry(evidence.file_path.clone())
                    .or_default()
                    .push(finding);
            }
            _ => {}
        }
    }

    for (file, group) in &exports_by_file {
        actions.extend(fix_unused_exports(root, file, group, apply));
    }
    for (manifest, group) in &deps_by_manifest {
        actions.extend(fix_unused_dependencies(root, manifest, group, apply));
    }
    for (file, group) in &stale_by_file {
        actions.extend(fix_stale_suppressions(root, file, group, apply));
    }

    actions.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });
    let fixed = actions.iter().filter(|a| a.status != "skipped").count();
    let skipped = actions.len() - fixed;
    FixReport {
        applied: apply,
        fixed,
        skipped,
        actions,
    }
}

fn action(
    finding: &FindingRecord,
    fix: &'static str,
    file: &str,
    status: &'static str,
    detail: String,
) -> FixAction {
    let evidence = finding.evidence.first();
    FixAction {
        fix,
        rule: finding.rule_name.clone().unwrap_or_default(),
        file: file.to_string(),
        line: evidence.and_then(|e| e.line),
        symbol: evidence.and_then(|e| e.symbol.clone()),
        status,
        detail,
    }
}

fn done(apply: bool) -> &'static str {
    if apply { "fixed" } else { "planned" }
}

// --- unused file -------------------------------------------------------------

fn fix_unused_file(root: &Path, finding: &FindingRecord, file: &str, apply: bool) -> FixAction {
    let absolute = root.join(file);
    if !absolute.is_file() {
        return action(
            finding,
            "remove_unused_file",
            file,
            "skipped",
            "file no longer exists — stale index, re-run `ovecc index`".to_string(),
        );
    }
    if apply && let Err(error) = std::fs::remove_file(&absolute) {
        return action(
            finding,
            "remove_unused_file",
            file,
            "skipped",
            format!("delete failed: {error}"),
        );
    }
    action(
        finding,
        "remove_unused_file",
        file,
        done(apply),
        "delete file (no entry point reaches it)".to_string(),
    )
}

// --- unused export -----------------------------------------------------------

fn fix_unused_exports(
    root: &Path,
    file: &str,
    group: &[&FindingRecord],
    apply: bool,
) -> Vec<FixAction> {
    let absolute = root.join(file);
    let Ok(content) = std::fs::read_to_string(&absolute) else {
        return group
            .iter()
            .map(|finding| {
                action(
                    finding,
                    "remove_unused_export",
                    file,
                    "skipped",
                    "file unreadable — stale index, re-run `ovecc index`".to_string(),
                )
            })
            .collect();
    };
    // `split_inclusive` keeps each line's own terminator (`\n` or `\r\n`), so
    // re-concatenation is byte-identical outside the edited lines.
    let mut lines: Vec<String> = content.split_inclusive('\n').map(str::to_string).collect();
    let mut actions = Vec::new();
    let mut changed = false;

    // Bottom-up so earlier line numbers stay valid after each edit.
    let mut ordered: Vec<&&FindingRecord> = group.iter().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.evidence.first().and_then(|e| e.line)));

    for finding in ordered {
        let line_no = finding
            .evidence
            .first()
            .and_then(|e| e.line)
            .unwrap_or_default() as usize;
        if line_no == 0 || line_no > lines.len() {
            actions.push(action(
                finding,
                "remove_unused_export",
                file,
                "skipped",
                "evidence line out of range — stale index, re-run `ovecc index`".to_string(),
            ));
            continue;
        }
        let original = lines[line_no - 1].clone();
        let symbol = finding.evidence.first().and_then(|e| e.symbol.as_deref());
        match fix_export_line(&original, symbol) {
            Ok(ExportEdit::Replace(fixed_line)) => {
                let preview = format!("- {}\n    + {}", original.trim_end(), fixed_line.trim_end());
                if apply {
                    lines[line_no - 1] = fixed_line;
                    changed = true;
                }
                actions.push(action(
                    finding,
                    "remove_unused_export",
                    file,
                    done(apply),
                    preview,
                ));
            }
            Ok(ExportEdit::RemoveLine) => {
                let preview = format!("- {}", original.trim_end());
                if apply {
                    lines.remove(line_no - 1);
                    changed = true;
                }
                actions.push(action(
                    finding,
                    "remove_unused_export",
                    file,
                    done(apply),
                    preview,
                ));
            }
            Err(reason) => {
                actions.push(action(
                    finding,
                    "remove_unused_export",
                    file,
                    "skipped",
                    reason,
                ));
            }
        }
    }
    if apply && changed {
        let rewritten: String = lines.concat();
        if let Err(error) = std::fs::write(&absolute, rewritten) {
            for act in &mut actions {
                if act.status == "fixed" {
                    act.status = "skipped";
                    act.detail = format!("write failed: {error}");
                }
            }
        }
    }
    actions
}

/// How one export line gets fixed: rewritten in place, or removed entirely
/// (a re-export list whose only name was the unused one).
#[derive(Debug)]
enum ExportEdit {
    Replace(String),
    RemoveLine,
}

/// The mechanical fix for an export line, or the reason it must stay manual.
/// `export <declaration>` drops the keyword; `export { … }` lists lose just
/// the named entry (the whole line when it was alone). Default exports need
/// judgement — the expression may have side effects.
fn fix_export_line(line: &str, symbol: Option<&str>) -> Result<ExportEdit, String> {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("export ") else {
        return Err(
            "line no longer starts with `export` — stale index, re-run `ovecc index`".to_string(),
        );
    };
    const DECLARATIONS: [&str; 12] = [
        "const ",
        "function ",
        "function*",
        "async function",
        "class ",
        "abstract class ",
        "interface ",
        "type ",
        "enum ",
        "declare ",
        "let ",
        "var ",
    ];
    if DECLARATIONS.iter().any(|decl| rest.starts_with(decl)) {
        return Ok(ExportEdit::Replace(line.replacen("export ", "", 1)));
    }
    if rest.starts_with("default") {
        return Err(
            "default export — remove manually (the expression may have side effects)".to_string(),
        );
    }
    if rest.starts_with('{') || rest.starts_with("type {") {
        let Some(symbol) = symbol else {
            return Err("re-export list without a named symbol — remove manually".to_string());
        };
        return fix_reexport_list(line, symbol);
    }
    if rest.starts_with('*') {
        return Err("namespace re-export (`export *`) — remove manually".to_string());
    }
    Err("unrecognized export form — remove manually".to_string())
}

/// Removes `symbol` from an `export { a, b as c } from '…'` list. The exported
/// name is what deadcode flagged, so an aliased entry matches on its alias.
/// Sole entry → the whole line goes; anything unparseable stays manual.
fn fix_reexport_list(line: &str, symbol: &str) -> Result<ExportEdit, String> {
    let open = line
        .find('{')
        .ok_or_else(|| "malformed re-export list — remove manually".to_string())?;
    let close = line[open..]
        .find('}')
        .map(|offset| open + offset)
        .ok_or_else(|| "malformed re-export list — remove manually".to_string())?;
    let entries: Vec<&str> = line[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    // An entry's *exported* name: `orig as alias` exports `alias`;
    // `type X` exports `X`.
    fn exported_name(entry: &str) -> &str {
        let entry = entry.strip_prefix("type ").unwrap_or(entry);
        match entry.rsplit_once(" as ") {
            Some((_, alias)) => alias.trim(),
            None => entry.trim(),
        }
    }
    let keep: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|entry| exported_name(entry) != symbol)
        .collect();
    if keep.len() == entries.len() {
        return Err(format!(
            "'{symbol}' not found in the re-export list — stale index, re-run `ovecc index`"
        ));
    }
    if keep.is_empty() {
        return Ok(ExportEdit::RemoveLine);
    }
    let rebuilt = format!(
        "{}{{ {} }}{}",
        &line[..open],
        keep.join(", "),
        &line[close + 1..]
    );
    Ok(ExportEdit::Replace(rebuilt))
}

// --- unused dependency ---------------------------------------------------------

fn fix_unused_dependencies(
    root: &Path,
    manifest: &str,
    group: &[&FindingRecord],
    apply: bool,
) -> Vec<FixAction> {
    let absolute = root.join(manifest);
    let Ok(mut content) = std::fs::read_to_string(&absolute) else {
        return group
            .iter()
            .map(|finding| {
                action(
                    finding,
                    "remove_unused_dependency",
                    manifest,
                    "skipped",
                    "manifest unreadable — stale index, re-run `ovecc index`".to_string(),
                )
            })
            .collect();
    };
    let mut actions = Vec::new();
    let mut changed = false;
    for finding in group {
        let Some(evidence) = finding.evidence.first() else {
            continue;
        };
        let Some(package) = evidence.symbol.as_deref() else {
            continue;
        };
        let section = evidence.detail.as_deref().unwrap_or("dependencies");
        match remove_manifest_key(&content, section, package) {
            Ok(rewritten) => {
                if apply {
                    content = rewritten;
                    changed = true;
                }
                actions.push(action(
                    finding,
                    "remove_unused_dependency",
                    manifest,
                    done(apply),
                    format!("remove \"{package}\" from {section}"),
                ));
            }
            Err(reason) => {
                actions.push(action(
                    finding,
                    "remove_unused_dependency",
                    manifest,
                    "skipped",
                    reason,
                ));
            }
        }
    }
    if apply
        && changed
        && let Err(error) = std::fs::write(&absolute, content)
    {
        for act in &mut actions {
            if act.status == "fixed" {
                act.status = "skipped";
                act.detail = format!("write failed: {error}");
            }
        }
    }
    actions
}

/// Removes `"package": …` from `section` of a package.json, preserving every
/// other byte (indentation, line endings, key order). The result is re-parsed:
/// if the surgery would leave invalid JSON, the manifest is left untouched.
fn remove_manifest_key(content: &str, section: &str, package: &str) -> Result<String, String> {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let section_needle = format!("\"{section}\"");
    let key_needle = format!("\"{package}\"");

    // Locate the section block: its header line, then the first closing brace.
    let start = lines
        .iter()
        .position(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(&section_needle)
                && trimmed[section_needle.len()..]
                    .trim_start()
                    .starts_with(':')
        })
        .ok_or_else(|| {
            format!("section \"{section}\" not found — stale index, re-run `ovecc index`")
        })?;
    let end = lines[start..]
        .iter()
        .position(|line| line.trim_start().starts_with('}'))
        .map(|offset| start + offset)
        .unwrap_or(lines.len());

    let key_index = lines[start + 1..end]
        .iter()
        .position(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(&key_needle)
                && trimmed[key_needle.len()..].trim_start().starts_with(':')
        })
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| {
            format!("\"{package}\" not found in {section} — stale index, re-run `ovecc index`")
        })?;

    let mut rewritten: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
    let removed_had_comma = rewritten[key_index].trim_end().ends_with(',');
    rewritten.remove(key_index);
    if !removed_had_comma && key_index > start + 1 {
        // Removed the section's last entry: the previous entry's trailing
        // comma would dangle. Strip it only when it *is* trailing.
        let previous = &mut rewritten[key_index - 1];
        if let Some(position) = previous.rfind(',')
            && previous[position + 1..].trim().is_empty()
        {
            previous.replace_range(position..=position, "");
        }
    }
    let result: String = rewritten.concat();
    serde_json::from_str::<serde_json::Value>(&result)
        .map_err(|_| "removal would leave invalid JSON — remove manually".to_string())?;
    Ok(result)
}

// --- unlisted (phantom) dependency ------------------------------------------

/// Declares a phantom dependency in the nearest manifest, pinned to the
/// version the lockfile already resolves — the one declaration with a single
/// unambiguous outcome. No lockfile version, no empty section surgery: skip
/// with the reason instead of guessing.
fn fix_unlisted_dependency(root: &Path, finding: &FindingRecord, apply: bool) -> FixAction {
    let Some(evidence) = finding.evidence.first() else {
        return action(
            finding,
            "declare_dependency",
            "",
            "skipped",
            "no evidence".to_string(),
        );
    };
    let Some(package) = evidence.symbol.as_deref() else {
        return action(
            finding,
            "declare_dependency",
            &evidence.file_path,
            "skipped",
            "no package name".to_string(),
        );
    };
    let Some(manifest_dir) = nearest_manifest_dir(root, &evidence.file_path) else {
        return action(
            finding,
            "declare_dependency",
            &evidence.file_path,
            "skipped",
            "no package.json found above the import site".to_string(),
        );
    };
    let manifest = if manifest_dir.is_empty() {
        "package.json".to_string()
    } else {
        format!("{manifest_dir}/package.json")
    };
    let Some(version) = lockfile_version(root, &manifest_dir, package) else {
        return action(
            finding,
            "declare_dependency",
            &manifest,
            "skipped",
            format!("no lockfile version found for '{package}' — declare it manually"),
        );
    };
    let absolute = root.join(&manifest);
    let Ok(content) = std::fs::read_to_string(&absolute) else {
        return action(
            finding,
            "declare_dependency",
            &manifest,
            "skipped",
            "manifest unreadable".to_string(),
        );
    };
    match insert_manifest_key(&content, "dependencies", package, &version) {
        Ok(rewritten) => {
            if apply && let Err(error) = std::fs::write(&absolute, rewritten) {
                return action(
                    finding,
                    "declare_dependency",
                    &manifest,
                    "skipped",
                    format!("write failed: {error}"),
                );
            }
            action(
                finding,
                "declare_dependency",
                &manifest,
                done(apply),
                format!("add \"{package}\": \"^{version}\" to dependencies"),
            )
        }
        Err(reason) => action(finding, "declare_dependency", &manifest, "skipped", reason),
    }
}

/// The closest directory at or above `from_file` holding a package.json,
/// repo-relative ("" = the root). Walks the real filesystem so workspace
/// nesting is respected.
fn nearest_manifest_dir(root: &Path, from_file: &str) -> Option<String> {
    let mut dir = match from_file.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => String::new(),
    };
    loop {
        let candidate = if dir.is_empty() {
            root.join("package.json")
        } else {
            root.join(&dir).join("package.json")
        };
        if candidate.is_file() {
            return Some(dir);
        }
        if dir.is_empty() {
            return None;
        }
        dir = match dir.rsplit_once('/') {
            Some((parent, _)) => parent.to_string(),
            None => String::new(),
        };
    }
}

/// The version the lockfile already resolves for `package`: package-lock.json
/// v2/v3 (`packages["node_modules/<pkg>"].version`) or v1
/// (`dependencies[<pkg>].version`), searched from the manifest dir up to the
/// repo root.
fn lockfile_version(root: &Path, from_dir: &str, package: &str) -> Option<String> {
    let mut dir = from_dir.to_string();
    loop {
        let lock = if dir.is_empty() {
            root.join("package-lock.json")
        } else {
            root.join(&dir).join("package-lock.json")
        };
        if let Ok(content) = std::fs::read_to_string(&lock)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&content)
        {
            let v2 = value
                .get("packages")
                .and_then(|p| p.get(format!("node_modules/{package}")))
                .and_then(|entry| entry.get("version"))
                .and_then(|v| v.as_str());
            let v1 = value
                .get("dependencies")
                .and_then(|d| d.get(package))
                .and_then(|entry| entry.get("version"))
                .and_then(|v| v.as_str());
            if let Some(version) = v2.or(v1) {
                return Some(version.to_string());
            }
        }
        if dir.is_empty() {
            return None;
        }
        dir = match dir.rsplit_once('/') {
            Some((parent, _)) => parent.to_string(),
            None => String::new(),
        };
    }
}

/// Inserts `"package": "^version"` into `section`, in sorted position, with
/// the section's own indentation. Empty or single-line sections skip (brace
/// surgery needs judgement); the result must re-parse as JSON.
fn insert_manifest_key(
    content: &str,
    section: &str,
    package: &str,
    version: &str,
) -> Result<String, String> {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let section_needle = format!("\"{section}\"");
    let start = lines
        .iter()
        .position(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with(&section_needle)
                && trimmed[section_needle.len()..]
                    .trim_start()
                    .starts_with(':')
        })
        .ok_or_else(|| format!("no \"{section}\" section — declare manually"))?;
    if lines[start].contains('}') {
        return Err(format!(
            "single-line \"{section}\" section — declare manually"
        ));
    }
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('}'))
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| format!("unterminated \"{section}\" section — declare manually"))?;
    if end == start + 1 {
        return Err(format!("empty \"{section}\" section — declare manually"));
    }

    // Sorted insertion point among the existing entry keys.
    let entry_key = |line: &str| -> Option<String> {
        let trimmed = line.trim_start();
        let rest = trimmed.strip_prefix('"')?;
        rest.split('"').next().map(str::to_string)
    };
    let mut insert_at = end; // default: after the last entry
    for (index, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        if let Some(key) = entry_key(line)
            && key.as_str() > package
        {
            insert_at = index;
            break;
        }
    }
    let indent: String = lines[start + 1]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    let terminator = if lines[start + 1].ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    let mut rewritten: Vec<String> = lines.iter().map(|line| (*line).to_string()).collect();
    if insert_at == end {
        // New last entry: the previous line needs a trailing comma.
        let previous = &mut rewritten[end - 1];
        let trimmed_end = previous.trim_end();
        if !trimmed_end.ends_with(',') {
            let terminator_start = trimmed_end.len();
            previous.insert(terminator_start, ',');
        }
        rewritten.insert(
            end,
            format!("{indent}\"{package}\": \"^{version}\"{terminator}"),
        );
    } else {
        rewritten.insert(
            insert_at,
            format!("{indent}\"{package}\": \"^{version}\",{terminator}"),
        );
    }
    let result: String = rewritten.concat();
    serde_json::from_str::<serde_json::Value>(&result)
        .map_err(|_| "insertion would leave invalid JSON — declare manually".to_string())?;
    Ok(result)
}

// --- stale ovecc-ignore suppressions -----------------------------------------

/// Removes stale `ovecc-ignore` comments. The finding's evidence line is the
/// *suppressed* line: a trailing marker sits on that same line, a `-next-line`
/// marker on the line above. Content is re-verified so a stale index skips.
fn fix_stale_suppressions(
    root: &Path,
    file: &str,
    group: &[&FindingRecord],
    apply: bool,
) -> Vec<FixAction> {
    let absolute = root.join(file);
    let Ok(content) = std::fs::read_to_string(&absolute) else {
        return group
            .iter()
            .map(|finding| {
                action(
                    finding,
                    "remove_stale_suppression",
                    file,
                    "skipped",
                    "file unreadable — stale index, re-run `ovecc index`".to_string(),
                )
            })
            .collect();
    };
    let mut lines: Vec<String> = content.split_inclusive('\n').map(str::to_string).collect();
    let mut actions = Vec::new();
    let mut changed = false;

    let mut ordered: Vec<&&FindingRecord> = group.iter().collect();
    ordered.sort_by_key(|f| std::cmp::Reverse(f.evidence.first().and_then(|e| e.line)));

    for finding in ordered {
        let line_no = finding
            .evidence
            .first()
            .and_then(|e| e.line)
            .unwrap_or_default() as usize;
        match remove_suppression_comment(&mut lines, line_no) {
            // The edit happens on the in-memory copy either way (so previews
            // and line numbers stay coherent within the group); only `apply`
            // writes it back.
            Ok(preview) => {
                changed = true;
                actions.push(action(
                    finding,
                    "remove_stale_suppression",
                    file,
                    done(apply),
                    preview,
                ));
            }
            Err(reason) => actions.push(action(
                finding,
                "remove_stale_suppression",
                file,
                "skipped",
                reason,
            )),
        }
    }
    if apply
        && changed
        && let Err(error) = std::fs::write(&absolute, lines.concat())
    {
        for act in &mut actions {
            if act.status == "fixed" {
                act.status = "skipped";
                act.detail = format!("write failed: {error}");
            }
        }
    }
    actions
}

/// Edits `lines` in place to drop the ovecc-ignore comment targeting
/// (1-based) `suppressed_line`, returning a preview of the change.
fn remove_suppression_comment(
    lines: &mut Vec<String>,
    suppressed_line: usize,
) -> Result<String, String> {
    let strip_marker = |line: &str| -> Option<String> {
        for marker in ["// ovecc-ignore", "# ovecc-ignore", "/* ovecc-ignore"] {
            if let Some(position) = line.find(marker) {
                let terminator: String = line
                    .chars()
                    .rev()
                    .take_while(|c| *c == '\n' || *c == '\r')
                    .collect();
                let kept = line[..position].trim_end();
                return Some(if kept.is_empty() {
                    String::new() // whole line was the comment
                } else {
                    format!("{kept}{}", terminator.chars().rev().collect::<String>())
                });
            }
        }
        None
    };

    // Trailing form: the marker sits on the suppressed line itself.
    if suppressed_line >= 1
        && suppressed_line <= lines.len()
        && let Some(fixed) = strip_marker(&lines[suppressed_line - 1])
    {
        let original = lines[suppressed_line - 1].trim_end().to_string();
        if fixed.is_empty() {
            lines.remove(suppressed_line - 1);
            return Ok(format!("- {original}"));
        }
        lines[suppressed_line - 1] = fixed.clone();
        return Ok(format!("- {}\n    + {}", original, fixed.trim_end()));
    }
    // `-next-line` form: the marker sits one line above the suppressed line.
    if suppressed_line >= 2
        && suppressed_line - 1 <= lines.len()
        && lines[suppressed_line - 2].contains("ovecc-ignore-next-line")
        && let Some(fixed) = strip_marker(&lines[suppressed_line - 2])
    {
        let original = lines[suppressed_line - 2].trim_end().to_string();
        if fixed.is_empty() {
            lines.remove(suppressed_line - 2);
            return Ok(format!("- {original}"));
        }
        lines[suppressed_line - 2] = fixed.clone();
        return Ok(format!("- {}\n    + {}", original, fixed.trim_end()));
    }
    Err("no ovecc-ignore comment found here — stale index, re-run `ovecc index`".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replaced(edit: Result<ExportEdit, String>) -> String {
        match edit {
            Ok(ExportEdit::Replace(line)) => line,
            other => panic!("expected Replace, got {other:?}"),
        }
    }

    #[test]
    fn strips_export_from_plain_declarations() {
        assert_eq!(
            replaced(fix_export_line("export const a = 1;\n", Some("a"))),
            "const a = 1;\n"
        );
        assert_eq!(
            replaced(fix_export_line("  export function f() {}\r\n", Some("f"))),
            "  function f() {}\r\n"
        );
        assert_eq!(
            replaced(fix_export_line("export type T = string;", Some("T"))),
            "type T = string;"
        );
        assert_eq!(
            replaced(fix_export_line("export interface I {}", Some("I"))),
            "interface I {}"
        );
    }

    #[test]
    fn refuses_non_mechanical_export_forms() {
        assert!(fix_export_line("export default foo();\n", Some("x")).is_err());
        assert!(fix_export_line("export * from './x';\n", Some("x")).is_err());
        assert!(fix_export_line("const a = 1; // moved\n", Some("a")).is_err());
    }

    #[test]
    fn edits_reexport_lists_by_exported_name() {
        // Sole entry: the whole line goes.
        assert!(matches!(
            fix_export_line("export { a } from './x';\n", Some("a")),
            Ok(ExportEdit::RemoveLine)
        ));
        // One of several: only that entry goes, aliases match on the alias.
        assert_eq!(
            replaced(fix_export_line(
                "export { a, orig as b, type C } from './x';\n",
                Some("b")
            )),
            "export { a, type C } from './x';\n"
        );
        assert_eq!(
            replaced(fix_export_line("export { a, b };\n", Some("a"))),
            "export { b };\n"
        );
        // Unknown name: stale index, not a guess.
        assert!(fix_export_line("export { a, b } from './x';\n", Some("zz")).is_err());
    }

    #[test]
    fn declares_dependency_in_sorted_position_with_comma_handling() {
        let manifest =
            "{\n  \"dependencies\": {\n    \"aaa\": \"^1\",\n    \"zzz\": \"^2\"\n  }\n}\n";
        // Middle insertion keeps JSON valid and sorted.
        let mid = insert_manifest_key(manifest, "dependencies", "mmm", "3.1.4").unwrap();
        let value: serde_json::Value = serde_json::from_str(&mid).unwrap();
        assert_eq!(value["dependencies"]["mmm"], "^3.1.4");
        // Appending after the last entry adds the missing comma above.
        let last = insert_manifest_key(manifest, "dependencies", "zzz2", "1.0.0").unwrap();
        let value: serde_json::Value = serde_json::from_str(&last).unwrap();
        assert_eq!(value["dependencies"]["zzz2"], "^1.0.0");
        // No section / single-line section: manual.
        assert!(
            insert_manifest_key("{\n  \"name\": \"t\"\n}\n", "dependencies", "x", "1").is_err()
        );
        assert!(
            insert_manifest_key("{\n  \"dependencies\": {}\n}\n", "dependencies", "x", "1")
                .is_err()
        );
    }

    #[test]
    fn removes_stale_suppression_comments() {
        // Trailing marker: the comment tail goes, the code stays.
        let mut lines: Vec<String> = "const x = 1; // ovecc-ignore\n"
            .split_inclusive('\n')
            .map(str::to_string)
            .collect();
        remove_suppression_comment(&mut lines, 1).unwrap();
        assert_eq!(lines.concat(), "const x = 1;\n");
        // Next-line marker: the pure comment line disappears.
        let mut lines: Vec<String> = "// ovecc-ignore-next-line\nconst y = 2;\n"
            .split_inclusive('\n')
            .map(str::to_string)
            .collect();
        remove_suppression_comment(&mut lines, 2).unwrap();
        assert_eq!(lines.concat(), "const y = 2;\n");
        // Nothing to remove: stale index.
        let mut lines: Vec<String> = vec!["const z = 3;\n".to_string()];
        assert!(remove_suppression_comment(&mut lines, 1).is_err());
    }

    #[test]
    fn removes_middle_and_last_manifest_entries() {
        let manifest = "{\n  \"name\": \"t\",\n  \"dependencies\": {\n    \"a\": \"^1\",\n    \"b\": \"^2\",\n    \"c\": \"^3\"\n  }\n}\n";
        // Middle entry: line removed, everything else intact.
        let without_b = remove_manifest_key(manifest, "dependencies", "b").unwrap();
        assert!(!without_b.contains("\"b\""));
        assert!(without_b.contains("\"a\": \"^1\",") && without_b.contains("\"c\": \"^3\""));
        // Last entry: the previous line's trailing comma is stripped too.
        let without_c = remove_manifest_key(manifest, "dependencies", "c").unwrap();
        assert!(!without_c.contains("\"c\""));
        assert!(without_c.contains("\"b\": \"^2\"\n"), "{without_c}");
        serde_json::from_str::<serde_json::Value>(&without_c).unwrap();
    }

    #[test]
    fn manifest_removal_is_section_scoped_and_stale_safe() {
        let manifest = "{\n  \"dependencies\": {\n    \"x\": \"^1\"\n  },\n  \"devDependencies\": {\n    \"x\": \"^1\"\n  }\n}\n";
        let fixed = remove_manifest_key(manifest, "devDependencies", "x").unwrap();
        // Only the devDependencies copy goes; the production one stays.
        let value: serde_json::Value = serde_json::from_str(&fixed).unwrap();
        assert!(value["dependencies"].get("x").is_some());
        assert!(value["devDependencies"].get("x").is_none());
        // A missing key reports stale instead of guessing.
        assert!(remove_manifest_key(manifest, "dependencies", "gone").is_err());
    }
}
