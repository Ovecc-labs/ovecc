//! What the index could not see, scoped to one target.
//!
//! An empty answer means two different things: "nothing references this" and
//! "I could not work out what references this". An agent that cannot tell them
//! apart reads the second as the first, deletes the symbol, and breaks the
//! build — and that failure costs more trust than a wrong answer, because the
//! tool gave no sign it was guessing.
//!
//! Every static call graph resolves somewhere near 70% of real edges (Helm et
//! al., *Total Recall?*, ISSTA 2024), so the winnable axis is not resolving
//! more, it is being honest about the rest. This module names the unresolved
//! imports that could bear on a specific target, so an answer about that
//! target can carry its own caveat.
//!
//! Scoped deliberately: a repository-wide count would attach a warning to
//! every answer and be ignored within a day. Only imports that could plausibly
//! have meant *this* target are reported, and the matching errs toward doubt —
//! a specifier that merely ends in the target's name counts, because claiming
//! certainty we do not have is the failure this exists to prevent.

use ovecc_core::legacy::DependencyRecord;

/// One import the resolver rejected, with the site that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Blindspot {
    pub file: String,
    pub line: u32,
    pub specifier: String,
}

/// The unresolved imports bearing on one target, split by direction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Calibration {
    /// Imports the target's own file wrote that resolve to nothing, so its
    /// dependency list is short by that many. Exact: these are its own lines.
    pub outgoing: Vec<Blindspot>,
    /// Imports elsewhere that resolve to nothing and name the target, so its
    /// dependent list may be short. Plausible, not certain — see the module
    /// note on erring toward doubt.
    pub incoming: Vec<Blindspot>,
}

/// How an answer of "nothing" should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The index found references and could resolve everything bearing on the
    /// target.
    Resolved,
    /// Nothing references it, and nothing unresolved could have.
    None,
    /// Nothing was found, but the index could not resolve imports that may
    /// have meant this target. The empty set is ignorance, not absence.
    CouldNotResolve,
}

impl Answer {
    /// The state an answer of `found` items is in, given the blind spots that
    /// bear on it.
    pub fn of(found: usize, blindspots: &[Blindspot]) -> Self {
        match (found, blindspots.is_empty()) {
            (0, false) => Answer::CouldNotResolve,
            (0, true) => Answer::None,
            _ => Answer::Resolved,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Answer::Resolved => "resolved",
            Answer::None => "none",
            Answer::CouldNotResolve => "could_not_resolve",
        }
    }
}

/// The trailing name of an import specifier, without directory, loader query,
/// or extension: `../auth/guard.ts?raw` is `guard`.
fn specifier_stem(specifier: &str) -> &str {
    let last = specifier.rsplit(['/', '\\']).next().unwrap_or(specifier);
    let last = last.split(['?', '#']).next().unwrap_or(last);
    match last.split_once('.') {
        // A leading dot is `./x` collapsed to `.`, or a dotfile: keep it whole.
        Some(("", _)) | None => last,
        Some((stem, _)) => stem,
    }
}

/// The names an import would have to end in to mean this file: its own stem,
/// plus its directory when the file is the directory's entry point, since
/// `./auth` resolves to `auth/index.ts`.
fn target_names(path: &str) -> Vec<&str> {
    let normalized = path.trim_end_matches('/');
    let stem = specifier_stem(normalized);
    let mut names = vec![stem];
    if matches!(stem, "index" | "mod" | "__init__")
        && let Some((parent, _)) = normalized.rsplit_once(['/', '\\'])
        && let Some(directory) = parent.rsplit(['/', '\\']).next()
    {
        names.push(directory);
    }
    names
}

/// The unresolved imports bearing on `target_file`. `None` for a target with
/// no file of its own (an external package, a synthesized node) leaves both
/// directions empty rather than guessing.
pub fn calibrate(dependencies: &[DependencyRecord], target_file: Option<&str>) -> Calibration {
    let Some(target_file) = target_file else {
        return Calibration::default();
    };
    let target_file = target_file.replace('\\', "/");
    let names = target_names(&target_file);
    let mut calibration = Calibration::default();
    for dependency in dependencies {
        if !dependency.is_unresolved() {
            continue;
        }
        let spot = Blindspot {
            file: dependency.source_file_path.replace('\\', "/"),
            line: dependency.evidence_line as u32,
            specifier: dependency.specifier.clone(),
        };
        if spot.file == target_file {
            calibration.outgoing.push(spot);
        } else if names.contains(&specifier_stem(&dependency.specifier)) {
            calibration.incoming.push(spot);
        }
    }
    calibration.outgoing.sort_by_key(|spot| spot.line);
    calibration
        .incoming
        .sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    calibration
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unresolved(file: &str, line: usize, specifier: &str) -> DependencyRecord {
        DependencyRecord {
            id: format!("dep:{file}:{line}"),
            repository_id: "repo:test".to_string(),
            source_file_id: "f".to_string(),
            target_file_id: None,
            source_file_path: file.to_string(),
            target_file_path: None,
            source_module_id: "m".to_string(),
            target_module_id: "m".to_string(),
            source_module: "src".to_string(),
            target_module: ovecc_core::legacy::unresolved_module_name(specifier),
            specifier: specifier.to_string(),
            dependency_kind: "unresolved".to_string(),
            is_external: true,
            evidence_line: line,
        }
    }

    fn resolved(file: &str, line: usize, specifier: &str) -> DependencyRecord {
        DependencyRecord {
            target_file_path: Some("src/other.ts".to_string()),
            target_module: "other".to_string(),
            dependency_kind: "static_import".to_string(),
            is_external: false,
            ..unresolved(file, line, specifier)
        }
    }

    #[test]
    fn a_stem_survives_directories_extensions_and_loader_queries() {
        assert_eq!(specifier_stem("../auth/guard.ts?raw"), "guard");
        assert_eq!(specifier_stem("./missing"), "missing");
        assert_eq!(specifier_stem("src/api/orders.tsx"), "orders");
        assert_eq!(specifier_stem("guard"), "guard");
        assert_eq!(specifier_stem("."), ".", "a bare dot keeps its shape");
    }

    #[test]
    fn an_entry_point_answers_to_its_directory_too() {
        assert_eq!(target_names("src/auth/index.ts"), vec!["index", "auth"]);
        assert_eq!(target_names("src/auth/guard.ts"), vec!["guard"]);
    }

    #[test]
    fn the_targets_own_broken_imports_are_its_outgoing_blind_spots() {
        let dependencies = vec![
            unresolved("src/api/orders.ts", 2, "./missing"),
            resolved("src/api/orders.ts", 3, "../core/validate"),
            unresolved("src/web/shell.ts", 9, "./gone"),
        ];
        let calibration = calibrate(&dependencies, Some("src/api/orders.ts"));
        assert_eq!(
            calibration.outgoing,
            vec![Blindspot {
                file: "src/api/orders.ts".to_string(),
                line: 2,
                specifier: "./missing".to_string(),
            }],
            "only this file's own unresolved imports, and only the unresolved ones"
        );
        assert!(
            calibration.incoming.is_empty(),
            "'./gone' names nothing about orders"
        );
    }

    #[test]
    fn an_unresolved_import_naming_the_target_is_an_incoming_blind_spot() {
        let dependencies = vec![
            unresolved("src/api/legacy.ts", 4, "./guard"),
            unresolved("src/web/shell.ts", 9, "../auth/guard.ts"),
            unresolved("src/web/shell.ts", 10, "./unrelated"),
        ];
        let calibration = calibrate(&dependencies, Some("src/auth/guard.ts"));
        assert_eq!(
            calibration
                .incoming
                .iter()
                .map(|spot| (spot.file.as_str(), spot.line))
                .collect::<Vec<_>>(),
            vec![("src/api/legacy.ts", 4), ("src/web/shell.ts", 9)],
            "both name 'guard'; the third names something else"
        );
    }

    #[test]
    fn a_directory_import_bears_on_the_entry_point_it_would_resolve_to() {
        let dependencies = vec![unresolved("src/api/orders.ts", 1, "../auth")];
        assert_eq!(
            calibrate(&dependencies, Some("src/auth/index.ts"))
                .incoming
                .len(),
            1,
            "'../auth' would have resolved to auth/index.ts"
        );
        assert!(
            calibrate(&dependencies, Some("src/auth/guard.ts"))
                .incoming
                .is_empty(),
            "but not to a named file inside it"
        );
    }

    #[test]
    fn a_target_with_no_file_of_its_own_claims_no_blind_spots() {
        let dependencies = vec![unresolved("src/api/orders.ts", 1, "./missing")];
        assert_eq!(calibrate(&dependencies, None), Calibration::default());
    }

    #[test]
    fn the_answer_separates_an_empty_set_from_an_unseen_one() {
        let spot = Blindspot {
            file: "src/api/legacy.ts".to_string(),
            line: 4,
            specifier: "./guard".to_string(),
        };
        let one = std::slice::from_ref(&spot);
        assert_eq!(Answer::of(0, &[]), Answer::None);
        assert_eq!(Answer::of(0, one), Answer::CouldNotResolve);
        assert_eq!(Answer::of(3, one), Answer::Resolved);
        assert_eq!(Answer::of(3, &[]), Answer::Resolved);
    }
}
