//! The intended architecture: `.ovecc/architecture.toml` parsed, validated,
//! and resolved to a per-file component assignment.
//!
//! The contract declares components (matched to files by path globs), an
//! allow-list of legal dependencies between them (`depends_on` — anything
//! undeclared is a violation), optional public interface files, and external
//! packages a component must not import. `ovecc-rules` diffs the contract
//! against the observed dependency edges and reports each one as a
//! convergence, a divergence, or an absence.
//!
//! Rules reference components only by name; paths live solely in each
//! component's `paths`. That split is what makes a contract portable: strip
//! the `paths` and what remains is a shareable template.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use globset::GlobBuilder;
use serde::Deserialize;

use crate::error::{OveccError, Result};
use crate::facts::CapabilityKind;

/// Contract schema version this build reads. Bumped on breaking changes so
/// yesterday's contract fails loudly instead of being misread.
pub const CONTRACT_SCHEMA: u32 = 1;

/// The parsed `.ovecc/architecture.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureContract {
    pub schema: u32,
    /// How violations are enforced. `warn` reports everything at low
    /// severity; `new-violations` and `strict` differ only once the baseline
    /// store exists (until then both report every violation at full
    /// severity).
    #[serde(default)]
    pub mode: EnforcementMode,
    /// What to do with files no component claims.
    #[serde(default)]
    pub unassigned: UnassignedPolicy,
    #[serde(default, rename = "component")]
    pub components: Vec<ComponentSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementMode {
    Off,
    Warn,
    #[default]
    NewViolations,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnassignedPolicy {
    Ignore,
    #[default]
    Warn,
    Forbid,
}

/// One declared component.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSpec {
    pub name: String,
    /// Abstract identity for shareable templates ("http-entry", "domain").
    /// Free-form; no check reads it.
    #[serde(default)]
    pub role: Option<String>,
    /// Path globs claiming files, repo-relative with forward slashes.
    /// `*` stays within one path segment, `**` crosses segments.
    pub paths: Vec<String>,
    /// The only components this one may depend on. Absent entries are
    /// divergences; declared-but-unobserved entries are absences.
    #[serde(default)]
    pub depends_on: Vec<DependsOn>,
    /// Public entry files. When non-empty, other components may import only
    /// these — enforced on the observed edges, no physical barrel required.
    #[serde(default)]
    pub interface: Vec<String>,
    /// External specifier patterns this component must not import. Same
    /// matching as `[[rules.banned_imports]]`: exact, `prefix*`, `*suffix`,
    /// `*infix*`.
    #[serde(default)]
    pub external_deny: Vec<String>,
    /// Isolate the component's slices: each direct subdirectory under the
    /// component's glob prefix is a slice, and slices must not import each
    /// other (import-linter's "independence" contract; FSD's slice
    /// isolation). The `@x` public-API exception applies — see
    /// [`x_notation_allows`]. Files directly under the prefix are neutral.
    #[serde(default)]
    pub slices: bool,
    /// Ambient capabilities this component must not use. Enforced against
    /// the curated API basket in [`CapabilityKind`]: a `deny_capabilities =
    /// ["network", "time"]` domain component may neither `fetch` nor read
    /// the clock.
    #[serde(default)]
    pub deny_capabilities: Vec<CapabilityKind>,
    /// Per-function budgets, checked against every function the component
    /// owns — fitness functions in the contract (Ford/Parsons/Kua). A
    /// function over a budget is an `architecture/complexity-budget` verdict.
    #[serde(default)]
    pub max_cyclomatic: Option<u32>,
    #[serde(default)]
    pub max_cognitive: Option<u32>,
}

/// A `depends_on` entry: a bare component name, or a table when the
/// dependency is tolerated but on its way out.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DependsOn {
    Name(String),
    Detailed {
        component: String,
        #[serde(default)]
        deprecated: bool,
    },
}

impl DependsOn {
    pub fn component(&self) -> &str {
        match self {
            DependsOn::Name(name) => name,
            DependsOn::Detailed { component, .. } => component,
        }
    }

    pub fn deprecated(&self) -> bool {
        match self {
            DependsOn::Name(_) => false,
            DependsOn::Detailed { deprecated, .. } => *deprecated,
        }
    }
}

impl ArchitectureContract {
    /// Loads `.ovecc/architecture.toml` if present. Absence is not an error:
    /// the contract is opt-in.
    pub fn load(root: &Path) -> Result<Option<Self>> {
        let path = root.join(".ovecc").join("architecture.toml");
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|error| OveccError::Repository {
            message: format!("failed to read {}: {error}", path.display()),
        })?;
        Self::parse(&text)
            .map(Some)
            .map_err(|error| OveccError::Repository {
                message: format!("invalid contract {}: {error}", path.display()),
            })
    }

    /// Parses and validates a contract from TOML text, for callers that hold
    /// the source directly (the built-in templates, an editor buffer) rather
    /// than a file on disk.
    pub fn parse(text: &str) -> Result<Self> {
        let contract: Self = toml::from_str(text).map_err(|error| OveccError::Repository {
            message: format!("invalid contract: {error}"),
        })?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn component(&self, name: &str) -> Option<&ComponentSpec> {
        self.components.iter().find(|c| c.name == name)
    }

    /// Structural validation, independent of any file on disk. Every error
    /// names the offending component so the fix is one glance away.
    pub fn validate(&self) -> Result<()> {
        if self.schema != CONTRACT_SCHEMA {
            return Err(contract_error(format!(
                "schema {} is not supported (this build reads schema {CONTRACT_SCHEMA})",
                self.schema
            )));
        }
        if self.components.is_empty() {
            return Err(contract_error(
                "no [[component]] declared; a contract without components checks nothing"
                    .to_string(),
            ));
        }
        let names = self.validated_names()?;
        for component in &self.components {
            component.validate_paths()?;
            component.validate_dependencies(&names)?;
            component.validate_budgets()?;
        }
        Ok(())
    }

    /// Component names, once each name is checked non-empty and unique.
    fn validated_names(&self) -> Result<BTreeSet<&str>> {
        let mut names = BTreeSet::new();
        for component in &self.components {
            if component.name.trim().is_empty() {
                return Err(contract_error("a component has an empty name".to_string()));
            }
            if !names.insert(component.name.as_str()) {
                return Err(contract_error(format!(
                    "component '{}' is declared twice",
                    component.name
                )));
            }
        }
        Ok(names)
    }
}

/// Where the accepted-violation baseline lives: one file per component under
/// `.ovecc/architecture/baseline/`, one sorted entry per line, so concurrent
/// branches merge line by line instead of contending on a central file.
pub fn baseline_dir(root: &Path) -> PathBuf {
    root.join(".ovecc").join("architecture").join("baseline")
}

/// One baseline entry: `rule<TAB>source file<TAB>specifier`. No line number
/// (the entry survives edits around the import) and no target path (the
/// specifier already carries it). A file rename resurrects the violation on
/// purpose: moving a file is the moment to pay its debt.
pub fn baseline_entry(rule: &str, source_file: &str, specifier: &str) -> String {
    format!("{rule}\t{}\t{specifier}", source_file.replace('\\', "/"))
}

/// Every baselined entry, merged across the per-component files. A missing
/// store is an empty baseline, not an error.
pub fn load_baseline(root: &Path) -> Result<BTreeSet<String>> {
    let dir = baseline_dir(root);
    let mut entries = BTreeSet::new();
    let Ok(listing) = std::fs::read_dir(&dir) else {
        return Ok(entries);
    };
    for file in listing {
        let path = file
            .map_err(|error| baseline_error(&dir, &error.to_string()))?
            .path();
        if path.extension().is_none_or(|ext| ext != "txt") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| baseline_error(&path, &error.to_string()))?;
        for line in text.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                entries.insert(line.to_string());
            }
        }
    }
    Ok(entries)
}

/// Rewrites the store to exactly `entries` (component name -> its entries):
/// one sorted file per component, stale files removed. Written whole by
/// `check --freeze` and shrunk by the ratchet — never grown implicitly.
pub fn save_baseline(root: &Path, entries: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    let dir = baseline_dir(root);
    // Group by file name first: two component names may sanitize identically.
    let mut files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (component, lines) in entries {
        if !lines.is_empty() {
            files
                .entry(baseline_file_name(component))
                .or_default()
                .extend(lines.iter().cloned());
        }
    }
    if files.is_empty() {
        if dir.is_dir() {
            std::fs::remove_dir_all(&dir)
                .map_err(|error| baseline_error(&dir, &error.to_string()))?;
            if let Some(parent) = dir.parent() {
                // Only succeeds when nothing else lives under architecture/.
                let _ = std::fs::remove_dir(parent);
            }
        }
        return Ok(());
    }
    std::fs::create_dir_all(&dir).map_err(|error| baseline_error(&dir, &error.to_string()))?;
    if let Ok(listing) = std::fs::read_dir(&dir) {
        for file in listing.flatten() {
            let name = file.file_name().to_string_lossy().to_string();
            if name.ends_with(".txt") && !files.contains_key(&name) {
                std::fs::remove_file(file.path())
                    .map_err(|error| baseline_error(&file.path(), &error.to_string()))?;
            }
        }
    }
    for (name, lines) in &files {
        let path = dir.join(name);
        let mut text = lines.iter().cloned().collect::<Vec<_>>().join("\n");
        text.push('\n');
        std::fs::write(&path, text).map_err(|error| baseline_error(&path, &error.to_string()))?;
    }
    Ok(())
}

/// A component name as a baseline file name. Path separators would create
/// directories, so they become dashes.
pub fn baseline_file_name(component: &str) -> String {
    let safe: String = component
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':') {
                '-'
            } else {
                c
            }
        })
        .collect();
    format!("{safe}.txt")
}

fn baseline_error(path: &Path, error: &str) -> OveccError {
    OveccError::Repository {
        message: format!("architecture baseline {}: {error}", path.display()),
    }
}

impl ComponentSpec {
    fn validate_paths(&self) -> Result<()> {
        if self.paths.is_empty() {
            return Err(contract_error(format!(
                "component '{}' claims no paths",
                self.name
            )));
        }
        for pattern in &self.paths {
            compile_glob(pattern).map_err(|error| {
                contract_error(format!(
                    "component '{}': invalid glob '{pattern}': {error}",
                    self.name
                ))
            })?;
        }
        Ok(())
    }

    fn validate_dependencies(&self, names: &BTreeSet<&str>) -> Result<()> {
        for dependency in &self.depends_on {
            let target = dependency.component();
            if target == self.name {
                return Err(contract_error(format!(
                    "component '{}' declares itself in depends_on; a component \
                     always depends on itself",
                    self.name
                )));
            }
            if !names.contains(target) {
                return Err(contract_error(format!(
                    "component '{}' depends on unknown component '{target}'",
                    self.name
                )));
            }
        }
        Ok(())
    }

    fn validate_budgets(&self) -> Result<()> {
        // Cyclomatic complexity is never below 1, so a budget of 0 would
        // flag every function the component owns.
        if self.max_cyclomatic == Some(0) {
            return Err(contract_error(format!(
                "component '{}': max_cyclomatic must be at least 1",
                self.name
            )));
        }
        Ok(())
    }
}

fn contract_error(message: String) -> OveccError {
    OveccError::Repository {
        message: format!(".ovecc/architecture.toml: {message}"),
    }
}

fn compile_glob(pattern: &str) -> std::result::Result<globset::GlobMatcher, globset::Error> {
    // literal_separator keeps `*` inside one path segment; `**` crosses,
    // matching what the patterns mean everywhere else (gitignore, tsconfig).
    Ok(GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()?
        .compile_matcher())
}

/// How many path characters a pattern fixes before its first wildcard. The
/// component whose matching pattern fixes the most wins a contested file,
/// like the most specific rule wins in gitignore.
fn literal_prefix_len(pattern: &str) -> usize {
    pattern.find(['*', '?', '[', '{']).unwrap_or(pattern.len())
}

/// Resolves every file to at most one component. A file two components claim
/// with equally specific patterns is a contract error, not a silent
/// first-declared-wins: the ambiguity would make every verdict downstream
/// arbitrary.
pub fn assign_components(
    contract: &ArchitectureContract,
    files: &[String],
) -> Result<BTreeMap<String, String>> {
    struct Candidate<'a> {
        component: &'a str,
        matcher: globset::GlobMatcher,
        specificity: (usize, usize),
        pattern: &'a str,
    }
    let mut candidates = Vec::new();
    for component in &contract.components {
        for pattern in &component.paths {
            // Validated in `validate`; a failure here means the contract was
            // not loaded through `load`.
            let matcher = compile_glob(pattern)
                .map_err(|error| contract_error(format!("invalid glob '{pattern}': {error}")))?;
            candidates.push(Candidate {
                component: &component.name,
                matcher,
                specificity: (literal_prefix_len(pattern), pattern.len()),
                pattern,
            });
        }
    }

    let mut assignment = BTreeMap::new();
    for file in files {
        let path = file.replace('\\', "/");
        let mut best: Option<&Candidate<'_>> = None;
        let mut contested: Option<&Candidate<'_>> = None;
        for candidate in &candidates {
            if !candidate.matcher.is_match(&path) {
                continue;
            }
            match best {
                None => best = Some(candidate),
                Some(current) if candidate.specificity > current.specificity => {
                    best = Some(candidate);
                    contested = None;
                }
                Some(current)
                    if candidate.specificity == current.specificity
                        && candidate.component != current.component =>
                {
                    contested = Some(candidate);
                }
                Some(_) => {}
            }
        }
        if let (Some(best), Some(contested)) = (best, contested) {
            return Err(contract_error(format!(
                "'{path}' is claimed by component '{}' (glob '{}') and component \
                 '{}' (glob '{}') with equal specificity; narrow one of the globs",
                best.component, best.pattern, contested.component, contested.pattern
            )));
        }
        if let Some(best) = best {
            assignment.insert(file.clone(), best.component.to_string());
        }
    }
    Ok(assignment)
}

/// The literal directory prefixes of a component's globs: `src/features/**`
/// fixes `src/features/`, a mid-segment wildcard (`src/feat*/**`) fixes only
/// `src/`. An empty prefix means the slices are the repository's top-level
/// directories.
fn slice_prefixes(spec: &ComponentSpec) -> Vec<String> {
    spec.paths
        .iter()
        .map(|pattern| {
            let literal = &pattern[..literal_prefix_len(pattern)];
            match literal.rfind('/') {
                Some(position) => literal[..=position].to_string(),
                None => String::new(),
            }
        })
        .collect()
}

/// Resolves the files of every `slices = true` component to their slice: the
/// first path segment after the component's glob prefix, qualified as
/// `component/slice`. A file directly under the prefix belongs to no slice —
/// the component root is neutral ground, so an `index.ts` re-exporting the
/// slices never breaches isolation itself.
pub fn assign_slices(
    contract: &ArchitectureContract,
    component_of: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let sliced: BTreeMap<&str, Vec<String>> = contract
        .components
        .iter()
        .filter(|component| component.slices)
        .map(|component| (component.name.as_str(), slice_prefixes(component)))
        .collect();
    if sliced.is_empty() {
        return BTreeMap::new();
    }
    let mut assignment = BTreeMap::new();
    for (file, component) in component_of {
        let Some(prefixes) = sliced.get(component.as_str()) else {
            continue;
        };
        let path = file.replace('\\', "/");
        // Longest matching prefix wins, mirroring component assignment.
        let Some(prefix) = prefixes
            .iter()
            .filter(|prefix| path.starts_with(prefix.as_str()))
            .max_by_key(|prefix| prefix.len())
        else {
            continue;
        };
        if let Some((slice, _)) = path[prefix.len()..].split_once('/')
            && !slice.is_empty()
        {
            assignment.insert(file.clone(), format!("{component}/{slice}"));
        }
    }
    assignment
}

/// FSD's cross-import exception: slice B may expose a public API *for* slice
/// A at `B/@x/A` (the "A crossed with B" notation). The import is legal when
/// the target path holds an `@x` segment immediately followed by the
/// importing slice's name, as a directory or a file stem.
pub fn x_notation_allows(source_slice: &str, target_path: &str) -> bool {
    let source = source_slice.rsplit('/').next().unwrap_or(source_slice);
    let path = target_path.replace('\\', "/");
    let mut segments = path.split('/').peekable();
    while let Some(segment) = segments.next() {
        if segment == "@x"
            && let Some(next) = segments.peek()
        {
            let stem = next.split_once('.').map_or(*next, |(stem, _)| stem);
            if stem == source {
                return true;
            }
        }
    }
    false
}

// ---- Architecture recognition ----
//
// `ovecc architecture suggest`: given a repository's files and internal import
// edges, score how well it matches each built-in template and, when it fits,
// bind the template to the repository's real root. This is recognition against
// a curated basket of archetypes, not architecture recovery from scratch:
// recovering an unknown structure is unsolved, classifying a repo against a
// handful of known targets is not. The score is coverage x conformance, both
// in [0, 1], so it reads as a single fraction.

/// How one template fits one repository, at the best root the detector found.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateFit {
    /// The path prefix under which the template's structure sits (`""` at the
    /// repository root, `"src/"`, `"apps/web/src/"` in a monorepo). Rebind the
    /// template's `paths` under this to bind it to the real tree.
    pub root: String,
    /// Fraction of the source files under `root` a component claims.
    pub coverage: f64,
    /// Fraction of the internal edges among claimed files the template allows.
    pub conformance: f64,
    pub assigned_files: usize,
    pub source_files: usize,
    pub allowed_edges: usize,
    pub internal_edges: usize,
    /// Components that claimed at least one file — the layers actually present.
    pub matched_components: usize,
}

impl TemplateFit {
    /// The headline number: coverage x conformance.
    pub fn score(&self) -> f64 {
        self.coverage * self.conformance
    }
}

fn is_js_ts(path: &str) -> bool {
    matches!(
        path.rsplit('.').next(),
        Some("ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "mts" | "cts")
    )
}

/// The literal directory a glob fixes before its first wildcard: `src/app/**`
/// -> `src/app/`, `libs/**/feature/**` -> `libs/`.
fn glob_literal_dir(glob: &str) -> &str {
    let literal = &glob[..literal_prefix_len(glob)];
    match literal.rfind('/') {
        Some(position) => &literal[..=position],
        None => "",
    }
}

/// The longest directory prefix shared by every component glob: the template's
/// own root (`"src/"` for FSD, `""` for an Nx workspace whose globs start at
/// `apps/` and `libs/`). What the detector rebinds onto the real tree.
fn canonical_root(contract: &ArchitectureContract) -> String {
    let dirs: Vec<&str> = contract
        .components
        .iter()
        .flat_map(|component| component.paths.iter())
        .map(|glob| glob_literal_dir(glob))
        .collect();
    let Some((first, rest)) = dirs.split_first() else {
        return String::new();
    };
    let mut prefix = *first;
    for dir in rest {
        while !dir.starts_with(prefix) {
            prefix = &prefix[..prefix.len() - 1];
        }
    }
    // Trim back to a directory boundary so a partial segment never leaks.
    match prefix.rfind('/') {
        Some(position) => prefix[..=position].to_string(),
        None => String::new(),
    }
}

/// The distinctive first segment each component expects under the canonical
/// root (`app`, `features`, `domain`, ...): the directory names that, found in
/// the tree, mark where the template lives.
fn anchor_segments(contract: &ArchitectureContract, canonical: &str) -> BTreeSet<String> {
    let mut anchors = BTreeSet::new();
    for component in &contract.components {
        let Some(glob) = component.paths.first() else {
            continue;
        };
        let dir = glob_literal_dir(glob);
        let rest = dir.strip_prefix(canonical).unwrap_or(dir);
        if let Some(segment) = rest.split('/').find(|segment| !segment.is_empty()) {
            anchors.insert(segment.to_string());
        }
    }
    anchors
}

/// Every root prefix under which an anchor directory sits, so a monorepo layout
/// (`apps/web/src/features/...`) is found as readily as a flat `src/`. Always
/// includes the repository root.
fn candidate_roots(files: &[String], anchors: &BTreeSet<String>) -> BTreeSet<String> {
    let mut roots = BTreeSet::from([String::new()]);
    for file in files {
        let path = file.replace('\\', "/");
        let segments: Vec<&str> = path.split('/').collect();
        for (index, segment) in segments.iter().enumerate() {
            if anchors.contains(*segment) {
                let root = if index == 0 {
                    String::new()
                } else {
                    format!("{}/", segments[..index].join("/"))
                };
                roots.insert(root);
            }
        }
    }
    roots
}

/// The template with every `paths` glob rebound from its canonical root onto
/// `root`. Component names, deps, and every other field are untouched, so the
/// conformance check reads the original allow-list.
fn rebind(contract: &ArchitectureContract, canonical: &str, root: &str) -> ArchitectureContract {
    let mut rebound = contract.clone();
    for component in &mut rebound.components {
        for glob in &mut component.paths {
            if let Some(rest) = glob.strip_prefix(canonical) {
                *glob = format!("{root}{rest}");
            }
        }
    }
    rebound
}

/// Scores one template at one root: coverage (claimed share of the source
/// files under the root) times conformance (allowed share of the internal
/// edges among claimed files). `internal_edges` are `(source, target)` file
/// paths, both internal to the repo.
fn evaluate_fit(
    contract: &ArchitectureContract,
    canonical: &str,
    root: &str,
    files: &[String],
    internal_edges: &[(String, String)],
) -> Option<TemplateFit> {
    let rebound = rebind(contract, canonical, root);
    // A rebinding that makes two globs contest a file is not a fit signal;
    // skip it rather than surface the contract error to the user.
    let component_of = assign_components(&rebound, files).ok()?;

    let assigned: BTreeSet<&String> = component_of.keys().filter(|file| is_js_ts(file)).collect();
    // Coverage is the share of the whole repository the template explains, not
    // of the subtree under `root`: measured locally, a deep corner that
    // happens to match one component would score a perfect 1.0. A real
    // architecture root claims the bulk of the code.
    let source_files = files.iter().filter(|file| is_js_ts(file)).count();
    let matched_components: BTreeSet<&str> = component_of
        .iter()
        .filter(|(file, _)| is_js_ts(file))
        .map(|(_, component)| component.as_str())
        .collect();
    // Recognizing an architecture means seeing its layers: a single matched
    // component is a coincidence, not a shape.
    if assigned.len() < 2 || matched_components.len() < 2 || source_files == 0 {
        return None;
    }

    let mut internal = 0usize;
    let mut allowed = 0usize;
    for (source_file, target_file) in internal_edges {
        let (Some(source), Some(target)) =
            (component_of.get(source_file), component_of.get(target_file))
        else {
            continue;
        };
        internal += 1;
        let ok = source == target
            || contract
                .component(source)
                .is_some_and(|spec| spec.depends_on.iter().any(|d| d.component() == target));
        if ok {
            allowed += 1;
        }
    }
    if internal == 0 {
        return None;
    }

    Some(TemplateFit {
        root: root.to_string(),
        coverage: assigned.len() as f64 / source_files as f64,
        conformance: allowed as f64 / internal as f64,
        assigned_files: assigned.len(),
        source_files,
        allowed_edges: allowed,
        internal_edges: internal,
        matched_components: matched_components.len(),
    })
}

/// The best fit of one template against a repository, over every candidate
/// root. `None` when no root binds at least two components with at least one
/// internal edge — the template is not a plausible description. Ties break
/// toward the shallower root, then the lexicographically smaller, so the
/// answer is deterministic.
pub fn recognize(
    contract: &ArchitectureContract,
    files: &[String],
    internal_edges: &[(String, String)],
) -> Option<TemplateFit> {
    let canonical = canonical_root(contract);
    let anchors = anchor_segments(contract, &canonical);
    candidate_roots(files, &anchors)
        .iter()
        .filter_map(|root| evaluate_fit(contract, &canonical, root, files, internal_edges))
        .max_by(|a, b| {
            a.score()
                .total_cmp(&b.score())
                .then_with(|| b.root.len().cmp(&a.root.len()))
                .then_with(|| b.root.cmp(&a.root))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(toml_text: &str) -> ArchitectureContract {
        toml::from_str(toml_text).expect("contract parses")
    }

    const MINIMAL: &str = r#"
        schema = 1

        [[component]]
        name = "api"
        paths = ["src/api/**"]
        depends_on = ["core"]
        interface = ["src/api/index.ts"]

        [[component]]
        name = "core"
        paths = ["src/core/**"]
        external_deny = ["pg*"]
    "#;

    #[test]
    fn parses_and_validates_the_minimal_contract() {
        let contract = contract(MINIMAL);
        contract.validate().expect("valid");
        assert_eq!(contract.mode, EnforcementMode::NewViolations);
        assert_eq!(contract.unassigned, UnassignedPolicy::Warn);
        let api = contract.component("api").expect("api exists");
        assert_eq!(api.depends_on.len(), 1);
        assert_eq!(api.depends_on[0].component(), "core");
        assert!(!api.depends_on[0].deprecated());
    }

    #[test]
    fn parses_a_deprecated_dependency_entry() {
        let contract = contract(
            r#"
            schema = 1

            [[component]]
            name = "api"
            paths = ["src/api/**"]
            depends_on = [{ component = "legacy", deprecated = true }]

            [[component]]
            name = "legacy"
            paths = ["src/legacy/**"]
        "#,
        );
        contract.validate().expect("valid");
        let entry = &contract.component("api").unwrap().depends_on[0];
        assert_eq!(entry.component(), "legacy");
        assert!(entry.deprecated());
    }

    #[test]
    fn rejects_unknown_schema_unknown_targets_and_duplicates() {
        let wrong_schema = contract(&MINIMAL.replace("schema = 1", "schema = 9"));
        assert!(wrong_schema.validate().is_err(), "unsupported schema");

        let unknown_target = contract(
            r#"
            schema = 1
            [[component]]
            name = "api"
            paths = ["src/api/**"]
            depends_on = ["ghost"]
        "#,
        );
        assert!(unknown_target.validate().is_err(), "unknown depends_on");

        let duplicate = contract(
            r#"
            schema = 1
            [[component]]
            name = "api"
            paths = ["a/**"]
            [[component]]
            name = "api"
            paths = ["b/**"]
        "#,
        );
        assert!(duplicate.validate().is_err(), "duplicate name");

        let self_dependency = contract(
            r#"
            schema = 1
            [[component]]
            name = "api"
            paths = ["src/api/**"]
            depends_on = ["api"]
        "#,
        );
        assert!(self_dependency.validate().is_err(), "self dependency");
    }

    #[test]
    fn rejects_unknown_fields() {
        let result: std::result::Result<ArchitectureContract, _> = toml::from_str(
            r#"
            schema = 1
            [[component]]
            name = "api"
            paths = ["src/api/**"]
            interfaces = ["typo.ts"]
        "#,
        );
        assert!(result.is_err(), "'interfaces' is not a field");
    }

    #[test]
    fn assigns_files_with_the_most_specific_glob_winning() {
        let contract = contract(
            r#"
            schema = 1
            [[component]]
            name = "app"
            paths = ["src/**"]
            [[component]]
            name = "api"
            paths = ["src/api/**"]
        "#,
        );
        let files = vec![
            "src/api/routes.ts".to_string(),
            "src/main.ts".to_string(),
            "docs/readme.md".to_string(),
        ];
        let assignment = assign_components(&contract, &files).expect("assigns");
        assert_eq!(assignment.get("src/api/routes.ts").unwrap(), "api");
        assert_eq!(assignment.get("src/main.ts").unwrap(), "app");
        assert!(!assignment.contains_key("docs/readme.md"), "unclaimed");
    }

    #[test]
    fn reports_an_equally_specific_contest_instead_of_picking_one() {
        let contract = contract(
            r#"
            schema = 1
            [[component]]
            name = "a"
            paths = ["src/shared/**"]
            [[component]]
            name = "b"
            paths = ["src/shared/**"]
        "#,
        );
        let files = vec!["src/shared/x.ts".to_string()];
        let error = assign_components(&contract, &files).expect_err("contested");
        let message = error.to_string();
        assert!(message.contains("src/shared/x.ts"), "{message}");
        assert!(
            message.contains("'a'") && message.contains("'b'"),
            "{message}"
        );
    }

    #[test]
    fn load_returns_none_without_a_contract_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            ArchitectureContract::load(dir.path())
                .expect("load")
                .is_none()
        );
    }

    #[test]
    fn load_reads_and_validates_a_contract_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".ovecc")).expect("mkdir");
        std::fs::write(dir.path().join(".ovecc/architecture.toml"), MINIMAL).expect("write");
        let contract = ArchitectureContract::load(dir.path())
            .expect("load")
            .expect("present");
        assert_eq!(contract.components.len(), 2);
    }

    #[test]
    fn baseline_round_trips_per_component_and_prunes_stale_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        assert!(load_baseline(root).expect("empty store").is_empty());

        let mut entries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        entries.entry("api".to_string()).or_default().extend([
            baseline_entry("divergence", "src/api/a.ts", "../db/pool"),
            baseline_entry("divergence", "src/api/b.ts", "../db/pool"),
        ]);
        entries
            .entry("web/ui".to_string())
            .or_default()
            .insert(baseline_entry("external-deny", "src/ui/c.ts", "pg-pool"));
        save_baseline(root, &entries).expect("save");

        assert!(baseline_dir(root).join("api.txt").is_file());
        assert!(
            baseline_dir(root).join("web-ui.txt").is_file(),
            "path separators sanitize to dashes"
        );
        assert_eq!(load_baseline(root).expect("load").len(), 3);

        entries.remove("web/ui");
        save_baseline(root, &entries).expect("shrink");
        assert!(!baseline_dir(root).join("web-ui.txt").exists());
        assert_eq!(load_baseline(root).expect("reload").len(), 2);

        entries.clear();
        save_baseline(root, &entries).expect("clear");
        assert!(!baseline_dir(root).exists(), "an empty store leaves no dir");
    }

    #[test]
    fn baseline_entries_have_no_line_number_and_normalized_slashes() {
        assert_eq!(
            baseline_entry("divergence", "src\\api\\a.ts", "../db/pool"),
            "divergence\tsrc/api/a.ts\t../db/pool"
        );
    }

    #[test]
    fn parses_slices_capabilities_and_budgets() {
        let contract = contract(
            r#"
            schema = 1

            [[component]]
            name = "features"
            paths = ["src/features/**"]
            slices = true

            [[component]]
            name = "domain"
            paths = ["src/domain/**"]
            deny_capabilities = ["network", "time", "random"]
            max_cyclomatic = 10
            max_cognitive = 15
        "#,
        );
        contract.validate().expect("valid");
        assert!(contract.component("features").unwrap().slices);
        let domain = contract.component("domain").unwrap();
        assert_eq!(domain.deny_capabilities.len(), 3);
        assert!(
            domain
                .deny_capabilities
                .contains(&crate::facts::CapabilityKind::Time)
        );
        assert_eq!(domain.max_cyclomatic, Some(10));
        assert_eq!(domain.max_cognitive, Some(15));
    }

    #[test]
    fn rejects_unknown_capability_names_and_a_zero_cyclomatic_budget() {
        let unknown: std::result::Result<ArchitectureContract, _> = toml::from_str(
            r#"
            schema = 1
            [[component]]
            name = "domain"
            paths = ["src/domain/**"]
            deny_capabilities = ["telepathy"]
        "#,
        );
        assert!(unknown.is_err(), "'telepathy' is not a capability");

        let zero = contract(
            r#"
            schema = 1
            [[component]]
            name = "domain"
            paths = ["src/domain/**"]
            max_cyclomatic = 0
        "#,
        );
        assert!(zero.validate().is_err(), "cyclomatic is never below 1");
    }

    #[test]
    fn assigns_slices_by_first_segment_after_the_glob_prefix() {
        let contract = contract(
            r#"
            schema = 1
            [[component]]
            name = "features"
            paths = ["src/features/**"]
            slices = true
            [[component]]
            name = "shared"
            paths = ["src/shared/**"]
        "#,
        );
        let component_of = BTreeMap::from([
            (
                "src/features/auth/login.ts".to_string(),
                "features".to_string(),
            ),
            (
                "src/features/cart/model/store.ts".to_string(),
                "features".to_string(),
            ),
            ("src/features/index.ts".to_string(), "features".to_string()),
            ("src/shared/ui/button.ts".to_string(), "shared".to_string()),
        ]);
        let slices = assign_slices(&contract, &component_of);
        assert_eq!(
            slices.get("src/features/auth/login.ts").unwrap(),
            "features/auth"
        );
        assert_eq!(
            slices.get("src/features/cart/model/store.ts").unwrap(),
            "features/cart"
        );
        assert!(
            !slices.contains_key("src/features/index.ts"),
            "a root file belongs to no slice"
        );
        assert!(
            !slices.contains_key("src/shared/ui/button.ts"),
            "unsliced components stay out"
        );
    }

    #[test]
    fn x_notation_opens_a_slice_only_to_the_named_consumer() {
        assert!(x_notation_allows(
            "entities/artist",
            "src/entities/song/@x/artist.ts"
        ));
        assert!(x_notation_allows(
            "entities/artist",
            "src/entities/song/@x/artist/index.ts"
        ));
        assert!(!x_notation_allows(
            "entities/playlist",
            "src/entities/song/@x/artist.ts"
        ));
        assert!(!x_notation_allows(
            "entities/artist",
            "src/entities/song/model/artist.ts"
        ));
    }

    // ---- recognition ----

    fn layered() -> ArchitectureContract {
        let mut app = component("app", &["src/app/**"]);
        app.depends_on = vec![DependsOn::Name("shared".to_string())];
        let mut features = component("features", &["src/features/**"]);
        features.depends_on = vec![DependsOn::Name("shared".to_string())];
        contract_of(vec![app, features, component("shared", &["src/shared/**"])])
    }

    fn component(name: &str, paths: &[&str]) -> ComponentSpec {
        ComponentSpec {
            name: name.to_string(),
            role: None,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            depends_on: Vec::new(),
            interface: Vec::new(),
            external_deny: Vec::new(),
            slices: false,
            deny_capabilities: Vec::new(),
            max_cyclomatic: None,
            max_cognitive: None,
        }
    }

    fn contract_of(components: Vec<ComponentSpec>) -> ArchitectureContract {
        ArchitectureContract {
            schema: 1,
            mode: EnforcementMode::Warn,
            unassigned: UnassignedPolicy::Warn,
            components,
        }
    }

    #[test]
    fn canonical_root_is_the_shared_glob_prefix() {
        assert_eq!(canonical_root(&layered()), "src/");
        let nx = contract_of(vec![
            component("app", &["apps/**"]),
            component("feature", &["libs/**/feature/**"]),
        ]);
        assert_eq!(canonical_root(&nx), "", "no shared prefix falls to root");
    }

    #[test]
    fn recognize_scores_a_matching_repo_high_and_finds_the_root() {
        let files = vec![
            "src/app/main.ts".to_string(),
            "src/features/auth.ts".to_string(),
            "src/shared/api.ts".to_string(),
        ];
        // app -> shared and features -> shared are allowed; nothing diverges.
        let edges = vec![
            (
                "src/app/main.ts".to_string(),
                "src/shared/api.ts".to_string(),
            ),
            (
                "src/features/auth.ts".to_string(),
                "src/shared/api.ts".to_string(),
            ),
        ];
        let fit = recognize(&layered(), &files, &edges).expect("a fit");
        assert_eq!(fit.root, "src/");
        assert_eq!(fit.coverage, 1.0, "every source file is claimed");
        assert_eq!(fit.conformance, 1.0, "every edge is allowed");
        assert_eq!(fit.matched_components, 3);
        assert_eq!(fit.score(), 1.0);
    }

    #[test]
    fn recognize_detects_a_monorepo_root() {
        let files = vec![
            "apps/web/src/app/main.ts".to_string(),
            "apps/web/src/features/auth.ts".to_string(),
            "apps/web/src/shared/api.ts".to_string(),
            "README.md".to_string(),
        ];
        let edges = vec![(
            "apps/web/src/features/auth.ts".to_string(),
            "apps/web/src/shared/api.ts".to_string(),
        )];
        let fit = recognize(&layered(), &files, &edges).expect("a fit under the app root");
        assert_eq!(fit.root, "apps/web/src/");
        assert_eq!(fit.assigned_files, 3, "the markdown file is not source");
    }

    #[test]
    fn conformance_drops_when_edges_diverge() {
        // shared imports up into features: a divergence against the lattice.
        let files = vec![
            "src/features/auth.ts".to_string(),
            "src/shared/api.ts".to_string(),
        ];
        let edges = vec![(
            "src/shared/api.ts".to_string(),
            "src/features/auth.ts".to_string(),
        )];
        let fit = recognize(&layered(), &files, &edges).expect("still a partial fit");
        assert_eq!(fit.conformance, 0.0, "the only edge is illegal");
        assert_eq!(fit.score(), 0.0);
    }

    #[test]
    fn an_unrelated_repo_does_not_match() {
        let files = vec![
            "lib/parser/lexer.ts".to_string(),
            "lib/parser/token.ts".to_string(),
        ];
        let edges = vec![(
            "lib/parser/lexer.ts".to_string(),
            "lib/parser/token.ts".to_string(),
        )];
        // No app/features/shared directory anywhere, so no component binds.
        assert!(recognize(&layered(), &files, &edges).is_none());
    }
}
