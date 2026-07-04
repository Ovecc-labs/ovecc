use std::env;
use std::fs;
use std::path::Path;
use tree_sitter::{Node, Parser};

/// Developer tool: shows how tree-sitter sees a file, so adapter code
/// (`generic.rs`, `typescript.rs`) can be written against real node kinds and
/// field names instead of guesses.
///
/// Usage: cargo run -p ovecc-parser --bin ast_dumper -- <file> [--sexp]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ast_dumper <path_to_file> [--sexp]");
        std::process::exit(1);
    }
    let path = Path::new(&args[1]);
    let want_sexp = args.iter().any(|arg| arg == "--sexp");
    let contents = fs::read_to_string(path)?;

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let language: tree_sitter::Language = match ext {
        "js" | "jsx" | "mjs" | "cjs" => tree_sitter_javascript::LANGUAGE.into(),
        "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "py" => tree_sitter_python::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "rs" => tree_sitter_rust::LANGUAGE.into(),
        "cpp" | "cc" | "cxx" | "h" | "hpp" => tree_sitter_cpp::LANGUAGE.into(),
        _ => {
            eprintln!("Unsupported file type: .{ext}");
            std::process::exit(1);
        }
    };

    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser.parse(&contents, None).ok_or("Failed to parse")?;

    if want_sexp {
        println!("{}", tree.root_node().to_sexp());
        return Ok(());
    }

    print_tree(tree.root_node(), contents.as_bytes(), 0, None);

    let mut errors = Vec::new();
    collect_errors(tree.root_node(), &mut errors);
    if errors.is_empty() {
        println!("\nAST is syntactically clean (no ERROR nodes).");
    } else {
        println!("\n{} syntax problem(s):", errors.len());
        for (kind, line, col) in errors.iter().take(10) {
            println!("  {kind} at {line}:{col}");
        }
        if errors.len() > 10 {
            println!("  ... and {} more", errors.len() - 10);
        }
    }
    Ok(())
}

/// One line per *named* node: indentation = depth, then `field: kind [line:col]`,
/// plus the source text for leaves — exactly what `match node.kind()` arms and
/// `child_by_field_name` calls in the adapters are written against.
fn print_tree(node: Node, source: &[u8], depth: usize, field: Option<&str>) {
    if node.is_named() {
        let indent = "  ".repeat(depth);
        let start = node.start_position();
        let field_prefix = field.map(|name| format!("{name}: ")).unwrap_or_default();
        let mut line = format!(
            "{indent}{field_prefix}{} [{}:{}]",
            node.kind(),
            start.row + 1,
            start.column + 1
        );
        if node.named_child_count() == 0
            && let Ok(text) = node.utf8_text(source)
        {
            line.push_str(&format!("  {:?}", truncate(text, 48)));
        }
        println!("{line}");
    }
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    drop(cursor);
    for (index, child) in children.into_iter().enumerate() {
        let child_field = node.field_name_for_child(index as u32);
        print_tree(
            child,
            source,
            depth + usize::from(node.is_named()),
            child_field,
        );
    }
}

fn truncate(text: &str, max: usize) -> String {
    let flat = text.replace('\n', "\\n");
    if flat.chars().count() > max {
        let cut: String = flat.chars().take(max).collect();
        format!("{cut}...")
    } else {
        flat
    }
}

/// ERROR nodes (unparseable stretch) and MISSING nodes (token the parser had
/// to invent to recover) with their positions. Does not descend into an ERROR
/// node: its children are wreckage, one report per stretch is enough.
fn collect_errors(node: Node, errors: &mut Vec<(&'static str, usize, usize)>) {
    let start = node.start_position();
    if node.is_error() {
        errors.push(("ERROR", start.row + 1, start.column + 1));
        return;
    }
    if node.is_missing() {
        errors.push(("MISSING", start.row + 1, start.column + 1));
    }
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    drop(cursor);
    for child in children {
        collect_errors(child, errors);
    }
}
