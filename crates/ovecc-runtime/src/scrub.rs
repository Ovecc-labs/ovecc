use ovecc_core::util::short_hash;

pub const WITNESS_HASH_CHARS: usize = 16;

pub const ALLOWED_ATTRIBUTES: &[&str] = &[
    "code.file.path",
    "code.filepath",
    "code.function",
    "code.function.name",
    "code.line.number",
    "code.lineno",
    "code.namespace",
    "db.collection.name",
    "db.namespace",
    "db.operation",
    "db.operation.name",
    "db.sql.table",
    "db.system",
    "db.system.name",
    "http.method",
    "http.request.method",
    "http.response.status_code",
    "http.route",
    "http.status_code",
    "messaging.destination.name",
    "messaging.system",
    "net.peer.name",
    "peer.service",
    "rpc.method",
    "rpc.service",
    "rpc.system",
    "server.address",
    "service.name",
    "service.namespace",
];

pub fn is_allowed(key: &str) -> bool {
    ALLOWED_ATTRIBUTES.binary_search(&key).is_ok()
}

pub fn witness(trace_id: &str, keep_trace_ids: bool) -> String {
    let trace_id = trace_id.to_ascii_lowercase();
    if keep_trace_ids {
        trace_id
    } else {
        short_hash(&trace_id, WITNESS_HASH_CHARS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allow_list_is_sorted_so_the_lookup_is_a_binary_search() {
        let mut sorted = ALLOWED_ATTRIBUTES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, ALLOWED_ATTRIBUTES);
    }

    #[test]
    fn the_join_keys_the_attributors_need_are_all_admitted() {
        for key in [
            "http.route",
            "http.request.method",
            "db.collection.name",
            "db.sql.table",
            "code.file.path",
            "code.filepath",
            "code.line.number",
            "code.lineno",
            "service.name",
        ] {
            assert!(is_allowed(key), "{key} is a join key and must be admitted");
        }
    }

    #[test]
    fn free_text_attributes_that_can_carry_user_data_are_refused() {
        for key in [
            "db.query.text",
            "db.statement",
            "http.request.header.authorization",
            "http.url",
            "url.full",
            "url.query",
            "user.id",
            "enduser.id",
            "exception.message",
            "exception.stacktrace",
        ] {
            assert!(!is_allowed(key), "{key} must never reach a stored fact");
        }
    }

    #[test]
    fn an_unknown_attribute_is_refused_rather_than_admitted_by_default() {
        assert!(!is_allowed("vendor.custom.payload"));
        assert!(!is_allowed(""));
    }

    #[test]
    fn a_witness_is_hashed_unless_raw_trace_ids_were_asked_for() {
        let raw = "4BF92F3577B34DA6A3CE929D0E0E4736";
        let hashed = witness(raw, false);
        assert_eq!(hashed.len(), WITNESS_HASH_CHARS);
        assert_ne!(hashed, raw.to_ascii_lowercase());
        assert_eq!(hashed, witness(&raw.to_ascii_lowercase(), false));
        assert_eq!(witness(raw, true), raw.to_ascii_lowercase());
    }
}
