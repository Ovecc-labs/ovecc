//! Source languages supported by the indexing pipeline.

use serde::{Deserialize, Serialize};

/// Initial priority: TypeScript/JavaScript, Python, Rust, Go.
/// Later: Java, Kotlin, C#, PHP, Ruby, SQL, Terraform, YAML/OpenAPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceLanguage {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Python,
    Rust,
    Go,
    Cpp,
    Sql,
}

impl SourceLanguage {
    /// Detects the language from a file extension (content heuristics are the
    /// job of `LanguageAdapter::detect`).
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "py" | "pyi" => Some(Self::Python),
            "rs" => Some(Self::Rust),
            "go" => Some(Self::Go),
            // C++ sources and headers. Plain `.h` is treated as C++ because the
            // C++ grammar is a superset of C for declaration extraction.
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "hh" | "hxx" | "h++" | "h" | "c" | "cu"
            | "cuh" => Some(Self::Cpp),
            "sql" => Some(Self::Sql),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Cpp => "cpp",
            Self::Sql => "sql",
        }
    }

    /// True for the JavaScript/TypeScript family handled by one adapter.
    pub fn is_js_family(self) -> bool {
        matches!(
            self,
            Self::JavaScript | Self::Jsx | Self::TypeScript | Self::Tsx
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_languages_by_extension_case_insensitively() {
        use SourceLanguage::*;
        assert_eq!(SourceLanguage::from_extension("ts"), Some(TypeScript));
        assert_eq!(SourceLanguage::from_extension("TSX"), Some(Tsx));
        assert_eq!(SourceLanguage::from_extension("mjs"), Some(JavaScript));
        assert_eq!(SourceLanguage::from_extension("cjs"), Some(JavaScript));
        assert_eq!(SourceLanguage::from_extension("py"), Some(Python));
        assert_eq!(SourceLanguage::from_extension("rs"), Some(Rust));
        assert_eq!(SourceLanguage::from_extension("go"), Some(Go));
        // C and headers fold into the C++ adapter (C++ grammar is a superset).
        assert_eq!(SourceLanguage::from_extension("c"), Some(Cpp));
        assert_eq!(SourceLanguage::from_extension("hpp"), Some(Cpp));
        assert_eq!(SourceLanguage::from_extension("sql"), Some(Sql));
        assert_eq!(SourceLanguage::from_extension("md"), None);
        assert_eq!(SourceLanguage::from_extension(""), None);
    }

    #[test]
    fn as_str_agrees_with_serde_lowercase_naming() {
        assert_eq!(SourceLanguage::TypeScript.as_str(), "typescript");
        assert_eq!(SourceLanguage::Cpp.as_str(), "cpp");
        let json = serde_json::to_string(&SourceLanguage::JavaScript).unwrap();
        assert_eq!(json, "\"javascript\"");
    }

    #[test]
    fn js_family_membership() {
        use SourceLanguage::*;
        for lang in [JavaScript, Jsx, TypeScript, Tsx] {
            assert!(lang.is_js_family(), "{lang:?} should be js family");
        }
        for lang in [Python, Rust, Go, Cpp, Sql] {
            assert!(!lang.is_js_family(), "{lang:?} should not be js family");
        }
    }
}
