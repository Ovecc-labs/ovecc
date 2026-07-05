//! Deterministic security pattern detection over the JS/TS AST.
//!
//! Two complementary techniques, both dependency-free (no `regex` crate):
//!
//! - **Provider-pattern secrets**: exact prefix + charset +
//!   length scanners for well-known credential formats (AWS, GitHub, Slack,
//!   Stripe, Google, PEM private keys). Near-zero false positives → high
//!   severity, no entropy needed.
//! - **High-entropy secrets**: a string literal
//!   bound to a secret-shaped name (`apiKey`, `token`, `password`, ...) whose
//!   value clears a Shannon-entropy threshold and length floor, excluding env
//!   references and placeholders.
//!
//! Plus AST checks for dynamic `eval`/`new Function`, weak hashes
//! (`createHash("md5"|"sha1")`), and permissive CORS (`origin: "*"`).

use ovecc_core::facts::{SecurityPatternFact, SecurityPatternKind};

/// Base64 high-entropy limit.
const BASE64_ENTROPY_THRESHOLD: f64 = 4.5;
/// Hex high-entropy limit (a hex alphabet caps Shannon
/// entropy near 4.0, so it needs a lower bar than base64).
const HEX_ENTROPY_THRESHOLD: f64 = 3.0;
/// Minimum length before a high-entropy string is considered a candidate.
const MIN_SECRET_LEN: usize = 20;

/// Scans a string-literal value for a provider-pattern secret, returning the
/// provider label when one matches.
pub fn provider_secret(value: &str) -> Option<&'static str> {
    if contains_token(
        value,
        &["AKIA", "ASIA", "ABIA", "ACCA", "A3TA"],
        16,
        is_aws_tail,
    ) {
        // AWS's own documented example keys appear in docs, tests, and SDK
        // samples everywhere; by definition they are not credentials.
        const AWS_DOC_KEYS: [&str; 2] = ["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"];
        if !AWS_DOC_KEYS.iter().any(|key| value.contains(key)) {
            return Some("AWS access key");
        }
    }
    if contains_token(
        value,
        &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        36,
        is_alnum,
    ) {
        return Some("GitHub token");
    }
    if contains_token(value, &["github_pat_"], 82, is_word) {
        return Some("GitHub fine-grained token");
    }
    if contains_token(value, &["AIza"], 35, is_google_tail) {
        return Some("Google API key");
    }
    // A Slack token is a `xox[bparse]-` prefix followed by a real token body
    // (10+ chars of `[0-9a-zA-Z-]`); require the body so the bare prefix string
    // does not self-match.
    if contains_prefix_min(
        value,
        &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-"],
        10,
        is_slack_tail,
    ) {
        return Some("Slack token");
    }
    if contains_prefix_min(value, &["sk_live_", "rk_live_", "sk_prod_"], 10, is_alnum) {
        return Some("Stripe secret key");
    }
    if value.contains("-----BEGIN") && value.contains("PRIVATE KEY") {
        return Some("private key");
    }
    None
}

/// True when `name` looks like it binds a secret (common credential keywords).
pub fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "secret",
        "passwd",
        "password",
        "pwd",
        "token",
        "apikey",
        "api_key",
        "access_key",
        "accesskey",
        "auth",
        "credential",
        "private_key",
        "privatekey",
        "client_secret",
    ];
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

/// True when a value bound to a secret-shaped name should be flagged: long
/// enough, high entropy, and not an obvious non-secret (placeholder, env
/// reference, URL, or path).
pub fn looks_like_high_entropy_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < MIN_SECRET_LEN {
        return false;
    }
    if is_excluded_value(trimmed) {
        return false;
    }
    // A secret token has no spaces and is mostly an identifier/base64 charset.
    if trimmed.contains(char::is_whitespace) {
        return false;
    }
    // Charset-aware threshold: a hex alphabet caps entropy
    // near 4.0, so hex strings use the lower hex bar.
    let threshold = if trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        HEX_ENTROPY_THRESHOLD
    } else {
        BASE64_ENTROPY_THRESHOLD
    };
    shannon_entropy(trimmed) >= threshold
}

/// Detects an obsolete hash algorithm literal (`md5`, `sha1`, `sha-1`).
pub fn weak_hash(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "md5" => Some("MD5"),
        "sha1" | "sha-1" => Some("SHA-1"),
        _ => None,
    }
}

/// Shannon entropy (bits per symbol) of a string.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, usize>::new();
    for ch in value.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let len = value.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Excludes obvious non-secrets: env references, placeholders, URLs, paths.
fn is_excluded_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if value.starts_with("process.env") || value.starts_with("${") || value.starts_with("$") {
        return true;
    }
    if lower.contains("://") || value.starts_with('/') || value.starts_with("./") {
        return true;
    }
    const PLACEHEADERS: &[&str] = &[
        "xxx",
        "change",
        "example",
        "placeholder",
        "your-",
        "your_",
        "todo",
        "dummy",
        "test",
        "sample",
        "redacted",
        "<",
    ];
    PLACEHEADERS.iter().any(|needle| lower.contains(needle))
}

fn convert(
    kind: SecurityPatternKind,
    line: u32,
    detail: &str,
    caller: Option<String>,
) -> SecurityPatternFact {
    SecurityPatternFact {
        kind,
        line,
        detail: Some(detail.to_string()),
        caller_qualified_name: caller,
        in_test_code: false,
    }
}

/// Builds a hardcoded-secret fact (provider label or generic).
pub fn secret_fact(line: u32, label: &str) -> SecurityPatternFact {
    convert(SecurityPatternKind::HardcodedSecret, line, label, None)
}
/// Dynamic code execution sink (`eval`, `new Function`), attributed to its
/// enclosing symbol so taint can reach it.
pub fn eval_fact(line: u32, detail: &str, caller: Option<String>) -> SecurityPatternFact {
    convert(SecurityPatternKind::DynamicEval, line, detail, caller)
}
/// OS command execution sink (`child_process.exec`, ...).
pub fn command_exec_fact(line: u32, detail: &str, caller: Option<String>) -> SecurityPatternFact {
    convert(SecurityPatternKind::CommandExec, line, detail, caller)
}
pub fn weak_hash_fact(line: u32, algo: &str) -> SecurityPatternFact {
    convert(SecurityPatternKind::WeakHash, line, algo, None)
}
pub fn cors_fact(line: u32, detail: &str) -> SecurityPatternFact {
    convert(SecurityPatternKind::PermissiveCors, line, detail, None)
}

/// `child_process` methods that execute OS commands.
pub const COMMAND_EXEC_METHODS: &[&str] = &[
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
];

/// Receiver identifiers that denote the `child_process` module — used to keep
/// `exec` from matching unrelated APIs (e.g. `regex.exec`).
pub const COMMAND_EXEC_OBJECTS: &[&str] = &["child_process", "childProcess", "cp"];

// ---- low-level scanners (avoid pulling in the `regex` crate) ----

fn is_alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}
fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn is_aws_tail(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}
fn is_google_tail(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}
fn is_slack_tail(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// True when `value` contains one of `prefixes` followed by exactly `tail_len`
/// characters all satisfying `tail`.
fn contains_token(value: &str, prefixes: &[&str], tail_len: usize, tail: fn(char) -> bool) -> bool {
    for prefix in prefixes {
        let mut search = value;
        while let Some(pos) = search.find(prefix) {
            let after = &search[pos + prefix.len()..];
            let run = after.chars().take_while(|&c| tail(c)).count();
            // Exact-length token: the run is at least tail_len, and the char
            // right after the token is not part of the charset (boundary).
            if run >= tail_len {
                let boundary_ok = after
                    .chars()
                    .nth(tail_len)
                    .map(|c| !tail(c))
                    .unwrap_or(true);
                if boundary_ok {
                    return true;
                }
            }
            search = &search[pos + prefix.len()..];
        }
    }
    false
}

/// True when `value` contains one of `prefixes` followed by at least `min_len`
/// characters satisfying `tail`.
fn contains_prefix_min(
    value: &str,
    prefixes: &[&str],
    min_len: usize,
    tail: fn(char) -> bool,
) -> bool {
    for prefix in prefixes {
        if let Some(pos) = value.find(prefix) {
            let after = &value[pos + prefix.len()..];
            if after.chars().take_while(|&c| tail(c)).count() >= min_len {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_provider_patterns() {
        assert_eq!(
            provider_secret("AKIAIOSFODNN7EXAMPLB"),
            Some("AWS access key")
        );
        // AWS's own documented example key is allowlisted, never a finding.
        assert_eq!(provider_secret("AKIAIOSFODNN7EXAMPLE"), None);
        assert_eq!(
            provider_secret("ghp_1234567890abcdef1234567890abcdef1234"),
            Some("GitHub token")
        );
        assert_eq!(
            provider_secret("xoxb-123456789012-abcdefghijkl"),
            Some("Slack token")
        );
        // The bare prefix (as it appears in this very file's source) must not
        // self-match — it has no token body.
        assert_eq!(provider_secret("xoxb-"), None);
        assert_eq!(
            provider_secret("-----BEGIN RSA PRIVATE KEY-----"),
            Some("private key")
        );
        assert_eq!(provider_secret("just a normal string"), None);
        // Too short / wrong charset must not match.
        assert_eq!(provider_secret("ghp_short"), None);
    }

    #[test]
    fn high_entropy_secret_heuristic() {
        assert!(is_secret_name("apiKey"));
        assert!(is_secret_name("DB_PASSWORD"));
        assert!(!is_secret_name("userName"));

        assert!(looks_like_high_entropy_secret(
            "8f3a9c2e7b1d4f6a0c5e9d2b7a4f1c8e"
        ));
        // Placeholder / env reference / short are excluded.
        assert!(!looks_like_high_entropy_secret("your-api-key-here"));
        assert!(!looks_like_high_entropy_secret("process.env.API_KEY"));
        assert!(!looks_like_high_entropy_secret("short"));
    }

    #[test]
    fn entropy_is_higher_for_random_strings() {
        assert!(shannon_entropy("aaaaaaaa") < 1.0);
        assert!(shannon_entropy("8f3a9c2e7b1d4f6a") > 3.0);
    }

    #[test]
    fn weak_hash_detection() {
        assert_eq!(weak_hash("md5"), Some("MD5"));
        assert_eq!(weak_hash("SHA1"), Some("SHA-1"));
        assert_eq!(weak_hash("sha256"), None);
    }
}
