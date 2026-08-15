pub const PARAMETER: &str = "{}";
pub const WILDCARD: &str = "{*}";

pub fn canonical(path: &str) -> String {
    let trimmed = path.trim();
    let without_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let segments: Vec<String> = without_query
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(canonical_segment)
        .collect();
    if segments.is_empty() {
        return "/".to_string();
    }
    format!("/{}", segments.join("/"))
}

fn canonical_segment(segment: &str) -> String {
    if is_wildcard(segment) {
        return WILDCARD.to_string();
    }
    if is_parameter(segment) {
        return PARAMETER.to_string();
    }
    segment.to_string()
}

fn is_wildcard(segment: &str) -> bool {
    segment == "*"
        || segment == "**"
        || segment == "..."
        || segment.starts_with("*")
        || segment.starts_with("[...")
        || segment.starts_with("{*")
        || (segment.starts_with(':') && segment.ends_with('+'))
}

fn is_parameter(segment: &str) -> bool {
    segment.starts_with(':')
        || (segment.starts_with('{') && segment.ends_with('}'))
        || (segment.starts_with('<') && segment.ends_with('>'))
        || (segment.starts_with('[') && segment.ends_with(']'))
        || segment.starts_with('$')
}

pub fn normalize_method(method: &str) -> String {
    method.trim().to_ascii_uppercase()
}

pub fn method_matches(indexed: Option<&str>, observed: Option<&str>) -> bool {
    match (indexed, observed) {
        (Some(indexed), Some(observed)) => normalize_method(indexed) == normalize_method(observed),
        _ => true,
    }
}

pub fn is_mount_suffix(observed: &str, indexed: &str) -> bool {
    observed.len() > indexed.len() && observed.ends_with(indexed) && indexed.starts_with('/')
}

pub fn last_segment(canonical_path: &str) -> &str {
    canonical_path.rsplit('/').next().unwrap_or(canonical_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frameworks_parameter_syntax_collapses_to_one_placeholder() {
        for path in [
            "/orders/:id",
            "/orders/{id}",
            "/orders/{id:int}",
            "/orders/<int:id>",
            "/orders/[id]",
            "/orders/$id",
        ] {
            assert_eq!(canonical(path), "/orders/{}", "{path} did not canonicalize");
        }
    }

    #[test]
    fn catch_all_segments_stay_distinct_from_a_single_parameter() {
        for path in [
            "/assets/*",
            "/assets/*path",
            "/assets/[...slug]",
            "/assets/**",
        ] {
            assert_eq!(
                canonical(path),
                "/assets/{*}",
                "{path} did not canonicalize"
            );
        }
        assert_ne!(canonical("/assets/*"), canonical("/assets/:name"));
    }

    #[test]
    fn trailing_and_duplicated_slashes_never_change_the_route_identity() {
        assert_eq!(canonical("/orders/"), "/orders");
        assert_eq!(canonical("orders"), "/orders");
        assert_eq!(canonical("//orders//:id//"), "/orders/{}");
        assert_eq!(canonical("/"), "/");
        assert_eq!(canonical(""), "/");
    }

    #[test]
    fn a_query_string_is_not_part_of_the_route() {
        assert_eq!(canonical("/orders?page=2"), "/orders");
    }

    #[test]
    fn a_mount_prefix_is_a_suffix_match_and_a_shared_word_ending_is_not() {
        assert!(is_mount_suffix("/api/orders/{}", "/orders/{}"));
        assert!(is_mount_suffix("/v1/api/orders", "/orders"));
        assert!(!is_mount_suffix("/reorders", "/orders"));
        assert!(!is_mount_suffix("/orders", "/orders"));
        assert!(!is_mount_suffix("/api/orders", "/api/orders/{}"));
    }

    #[test]
    fn a_method_the_index_does_not_record_matches_anything_observed() {
        assert!(method_matches(Some("get"), Some("GET")));
        assert!(!method_matches(Some("GET"), Some("POST")));
        assert!(method_matches(None, Some("DELETE")));
        assert!(method_matches(Some("GET"), None));
    }

    #[test]
    fn the_last_segment_keys_the_suffix_candidates() {
        assert_eq!(last_segment("/api/orders/{}"), "{}");
        assert_eq!(last_segment("/orders"), "orders");
        assert_eq!(last_segment("/"), "");
    }
}
