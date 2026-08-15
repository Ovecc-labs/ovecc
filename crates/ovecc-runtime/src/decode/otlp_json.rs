use super::{RawObservation, SpanKind, TelemetryDecoder};
use crate::sampling::SamplingThreshold;
use crate::scrub;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const OTLP_JSON: &str = "otlp-json";

const SERVICE_NAME: &str = "service.name";
const STATUS_CODE_ERROR: u64 = 2;
const SERVER_ERROR_STATUS: u64 = 500;

pub struct OtlpJsonDecoder;

impl TelemetryDecoder for OtlpJsonDecoder {
    fn id(&self) -> &'static str {
        OTLP_JSON
    }

    fn sniff(&self, head: &[u8]) -> bool {
        let text = String::from_utf8_lossy(head);
        text.contains("\"resourceSpans\"") || text.contains("\"resource_spans\"")
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<RawObservation>> {
        if !self.sniff(input) {
            anyhow::bail!(
                "the input carries no resourceSpans, so it is not an OTLP/JSON trace export"
            );
        }
        let payloads = parse_payloads(input)?;
        let mut observations = Vec::new();
        for payload in &payloads {
            for resource_spans in &payload.resource_spans {
                let service = resource_spans.service_name();
                for scope_spans in &resource_spans.scope_spans {
                    for span in &scope_spans.spans {
                        observations.push(span.to_observation(service.as_deref()));
                    }
                }
            }
        }
        Ok(observations)
    }
}

fn parse_payloads(input: &[u8]) -> Result<Vec<TracesData>> {
    if let Ok(single) = serde_json::from_slice::<TracesData>(input) {
        return Ok(vec![single]);
    }
    if let Ok(batch) = serde_json::from_slice::<Vec<TracesData>>(input) {
        return Ok(batch);
    }
    parse_json_lines(input)
}

fn parse_json_lines(input: &[u8]) -> Result<Vec<TracesData>> {
    let text = std::str::from_utf8(input).context("telemetry input is not valid UTF-8")?;
    let mut payloads = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let payload: TracesData = serde_json::from_str(line)
            .with_context(|| format!("line {} is not an OTLP/JSON trace payload", index + 1))?;
        payloads.push(payload);
    }
    if payloads.is_empty() {
        anyhow::bail!("no OTLP/JSON trace payload found in the input");
    }
    Ok(payloads)
}

#[derive(Debug, Deserialize)]
struct TracesData {
    #[serde(rename = "resourceSpans", alias = "resource_spans", default)]
    resource_spans: Vec<ResourceSpans>,
}

#[derive(Debug, Deserialize)]
struct ResourceSpans {
    #[serde(default)]
    resource: Option<Resource>,
    #[serde(rename = "scopeSpans", alias = "scope_spans", default)]
    scope_spans: Vec<ScopeSpans>,
}

impl ResourceSpans {
    fn service_name(&self) -> Option<String> {
        self.resource
            .as_ref()?
            .attributes
            .iter()
            .find(|entry| entry.key == SERVICE_NAME)
            .and_then(KeyValue::text)
    }
}

#[derive(Debug, Deserialize)]
struct Resource {
    #[serde(default)]
    attributes: Vec<KeyValue>,
}

#[derive(Debug, Deserialize)]
struct ScopeSpans {
    #[serde(default)]
    spans: Vec<Span>,
}

#[derive(Debug, Deserialize)]
struct Span {
    #[serde(rename = "traceId", alias = "trace_id", default)]
    trace_id: String,
    #[serde(rename = "spanId", alias = "span_id", default)]
    span_id: String,
    #[serde(rename = "parentSpanId", alias = "parent_span_id", default)]
    parent_span_id: String,
    #[serde(rename = "traceState", alias = "trace_state", default)]
    trace_state: String,
    #[serde(default)]
    kind: Option<SpanKindValue>,
    #[serde(rename = "startTimeUnixNano", alias = "start_time_unix_nano", default)]
    start_time: Option<Scalar>,
    #[serde(rename = "endTimeUnixNano", alias = "end_time_unix_nano", default)]
    end_time: Option<Scalar>,
    #[serde(default)]
    status: Option<Status>,
    #[serde(default)]
    attributes: Vec<KeyValue>,
}

impl Span {
    fn to_observation(&self, resource_service: Option<&str>) -> RawObservation {
        let attributes = self.allowed_attributes();
        let start = self
            .start_time
            .as_ref()
            .and_then(Scalar::as_u64)
            .unwrap_or(0);
        let end = self
            .end_time
            .as_ref()
            .and_then(Scalar::as_u64)
            .unwrap_or(start);
        let service = resource_service
            .map(str::to_string)
            .or_else(|| attributes.get(SERVICE_NAME).cloned());
        RawObservation {
            error: self.is_error(&attributes),
            trace_id: normalize_id(&self.trace_id),
            span_id: normalize_id(&self.span_id),
            parent_span_id: Some(normalize_id(&self.parent_span_id)).filter(|id| !id.is_empty()),
            kind: self
                .kind
                .as_ref()
                .map_or(SpanKind::Unspecified, SpanKindValue::kind),
            service,
            start_unix_nano: start,
            end_unix_nano: end.max(start),
            sampling: SamplingThreshold::parse_tracestate(&self.trace_state),
            attributes,
        }
    }

    fn allowed_attributes(&self) -> BTreeMap<String, String> {
        self.attributes
            .iter()
            .filter(|entry| scrub::is_allowed(&entry.key))
            .filter_map(|entry| entry.text().map(|value| (entry.key.clone(), value)))
            .collect()
    }

    fn is_error(&self, attributes: &BTreeMap<String, String>) -> bool {
        let declared = self
            .status
            .as_ref()
            .and_then(|status| status.code.as_ref())
            .and_then(Scalar::as_u64)
            == Some(STATUS_CODE_ERROR);
        declared || http_status(attributes).is_some_and(|code| code >= SERVER_ERROR_STATUS)
    }
}

fn http_status(attributes: &BTreeMap<String, String>) -> Option<u64> {
    attributes
        .get("http.response.status_code")
        .or_else(|| attributes.get("http.status_code"))
        .and_then(|value| value.parse().ok())
}

fn normalize_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(default)]
    code: Option<Scalar>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SpanKindValue {
    Code(u64),
    Name(String),
}

impl SpanKindValue {
    fn kind(&self) -> SpanKind {
        match self {
            SpanKindValue::Code(code) => SpanKind::from_code(*code),
            SpanKindValue::Name(name) => SpanKind::from_name(name),
        }
    }
}

#[derive(Debug, Deserialize)]
struct KeyValue {
    key: String,
    #[serde(default)]
    value: Option<AnyValue>,
}

impl KeyValue {
    fn text(&self) -> Option<String> {
        self.value.as_ref().and_then(AnyValue::text)
    }
}

#[derive(Debug, Deserialize)]
struct AnyValue {
    #[serde(rename = "stringValue", alias = "string_value", default)]
    string_value: Option<String>,
    #[serde(rename = "intValue", alias = "int_value", default)]
    int_value: Option<Scalar>,
    #[serde(rename = "boolValue", alias = "bool_value", default)]
    bool_value: Option<bool>,
    #[serde(rename = "doubleValue", alias = "double_value", default)]
    double_value: Option<f64>,
}

impl AnyValue {
    fn text(&self) -> Option<String> {
        if let Some(value) = &self.string_value {
            return Some(value.clone());
        }
        if let Some(value) = &self.int_value {
            return Some(value.as_text());
        }
        if let Some(value) = self.bool_value {
            return Some(value.to_string());
        }
        self.double_value.map(|value| value.to_string())
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Scalar {
    Int(u64),
    Text(String),
    Float(f64),
    Bool(bool),
}

impl Scalar {
    fn as_u64(&self) -> Option<u64> {
        match self {
            Scalar::Int(value) => Some(*value),
            Scalar::Text(value) => value.trim().parse().ok(),
            Scalar::Float(_) | Scalar::Bool(_) => None,
        }
    }

    fn as_text(&self) -> String {
        match self {
            Scalar::Int(value) => value.to_string(),
            Scalar::Text(value) => value.clone(),
            Scalar::Float(value) => value.to_string(),
            Scalar::Bool(value) => value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(payload: &str) -> Vec<RawObservation> {
        OtlpJsonDecoder
            .decode(payload.as_bytes())
            .expect("payload decodes")
    }

    fn server_span(extra: &str) -> String {
        format!(
            r#"{{"resourceSpans":[{{"resource":{{"attributes":[
                {{"key":"service.name","value":{{"stringValue":"billing"}}}}]}},
              "scopeSpans":[{{"spans":[{{
                "traceId":"4bf92f3577b34da6a3ce929d0e0e4736",
                "spanId":"00f067aa0ba902b7",
                "kind":2,
                "startTimeUnixNano":"1544712660000000000",
                "endTimeUnixNano":"1544712660300000000",
                "attributes":[{{"key":"http.route","value":{{"stringValue":"/orders/{{id}}"}}}}]
                {extra}}}]}}]}}]}}"#
        )
    }

    #[test]
    fn a_minimal_server_span_decodes_into_one_observation() {
        let spans = decode(&server_span(""));

        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.service.as_deref(), Some("billing"));
        assert_eq!(span.kind, SpanKind::Server);
        assert_eq!(span.attribute("http.route"), Some("/orders/{id}"));
        assert_eq!(span.duration_ns(), 300_000_000);
        assert!(!span.error);
        assert_eq!(span.parent_span_id, None);
    }

    #[test]
    fn sixty_four_bit_fields_decode_from_a_number_as_well_as_a_string() {
        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"aa","spanId":"bb","kind":2,
            "startTimeUnixNano":1544712660000000000,
            "endTimeUnixNano":1544712660300000000}]}]}]}"#;

        let spans = decode(payload);

        assert_eq!(spans[0].start_unix_nano, 1_544_712_660_000_000_000);
        assert_eq!(spans[0].duration_ns(), 300_000_000);
    }

    #[test]
    fn snake_case_keys_decode_the_same_as_the_specified_camel_case() {
        let payload = r#"{"resource_spans":[{"resource":{"attributes":[
            {"key":"service.name","value":{"string_value":"billing"}}]},
          "scope_spans":[{"spans":[{
            "trace_id":"AA","span_id":"BB","parent_span_id":"CC","kind":3,
            "trace_state":"ot=th:c",
            "start_time_unix_nano":"10","end_time_unix_nano":"20",
            "attributes":[{"key":"db.collection.name","value":{"string_value":"orders"}}]
          }]}]}]}"#;

        let spans = decode(payload);

        assert_eq!(spans[0].service.as_deref(), Some("billing"));
        assert_eq!(spans[0].kind, SpanKind::Client);
        assert_eq!(spans[0].attribute("db.collection.name"), Some("orders"));
        assert_eq!(spans[0].parent_span_id.as_deref(), Some("cc"));
        assert_eq!(spans[0].sampling, SamplingThreshold::from_hex("c"));
    }

    #[test]
    fn trace_and_span_ids_are_hex_and_case_insensitive() {
        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"4BF92F3577B34DA6A3CE929D0E0E4736","spanId":"00F067AA0BA902B7"}]}]}]}"#;

        let spans = decode(payload);

        assert_eq!(spans[0].trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(spans[0].span_id, "00f067aa0ba902b7");
    }

    #[test]
    fn unknown_fields_at_every_nesting_level_are_ignored() {
        let payload = r#"{"resourceSpans":[{"schemaUrl":"x","future":1,
            "resource":{"droppedAttributesCount":0,"attributes":[]},
            "scopeSpans":[{"scope":{"name":"lib"},"schemaUrl":"y","spans":[{
              "traceId":"aa","spanId":"bb","kind":2,"name":"GET /orders",
              "events":[],"links":[],"flags":256,"droppedEventsCount":0}]}]}]}"#;

        assert_eq!(decode(payload).len(), 1);
    }

    #[test]
    fn a_span_kind_given_as_its_enum_name_still_decodes() {
        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"aa","spanId":"bb","kind":"SPAN_KIND_SERVER"}]}]}]}"#;

        assert_eq!(decode(payload)[0].kind, SpanKind::Server);
    }

    #[test]
    fn an_error_is_read_from_the_status_or_from_a_server_status_code() {
        assert!(decode(&server_span(r#","status":{"code":2,"message":"boom"}"#))[0].error);
        assert!(!decode(&server_span(r#","status":{"code":1}"#))[0].error);

        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"aa","spanId":"bb","kind":2,
            "attributes":[{"key":"http.response.status_code","value":{"intValue":"503"}}]}]}]}]}"#;
        assert!(decode(payload)[0].error);

        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"aa","spanId":"bb","kind":2,
            "attributes":[{"key":"http.response.status_code","value":{"intValue":"404"}}]}]}]}]}"#;
        assert!(
            !decode(payload)[0].error,
            "a client error is not the server's failure"
        );
    }

    #[test]
    fn attributes_outside_the_allow_list_never_reach_an_observation() {
        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"aa","spanId":"bb","kind":3,"attributes":[
              {"key":"db.collection.name","value":{"stringValue":"orders"}},
              {"key":"db.query.text","value":{"stringValue":"SELECT * FROM orders WHERE email='a@b.c'"}},
              {"key":"enduser.id","value":{"stringValue":"user-42"}}]}]}]}]}"#;

        let spans = decode(payload);

        assert_eq!(spans[0].attribute("db.collection.name"), Some("orders"));
        assert_eq!(spans[0].attribute("db.query.text"), None);
        assert_eq!(spans[0].attribute("enduser.id"), None);
        assert_eq!(spans[0].attribute_keys(), ["db.collection.name"]);
    }

    #[test]
    fn a_json_lines_export_decodes_every_line() {
        let line =
            r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aa","spanId":"bb"}]}]}]}"#;
        let payload = format!("{line}\n\n{line}\n");

        assert_eq!(decode(&payload).len(), 2);
    }

    #[test]
    fn a_json_array_of_payloads_decodes_as_one_batch() {
        let line =
            r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aa","spanId":"bb"}]}]}]}"#;

        assert_eq!(decode(&format!("[{line},{line}]")).len(), 2);
    }

    #[test]
    fn a_broken_line_in_a_json_lines_export_names_the_line() {
        let good =
            r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aa","spanId":"bb"}]}]}]}"#;
        let error = OtlpJsonDecoder
            .decode(format!("{good}\n{{\"resourceSpans\": oops}}\n").as_bytes())
            .unwrap_err()
            .to_string();

        assert!(error.contains("line 2"), "{error}");
    }

    #[test]
    fn a_payload_carrying_another_signal_is_refused_rather_than_read_as_empty() {
        let error = OtlpJsonDecoder
            .decode(br#"{"resourceMetrics":[{"scopeMetrics":[]}]}"#)
            .unwrap_err()
            .to_string();

        assert!(error.contains("resourceSpans"), "{error}");
    }

    #[test]
    fn sniffing_reads_content_rather_than_a_file_extension() {
        assert!(OtlpJsonDecoder.sniff(br#"{"resourceSpans":[]}"#));
        assert!(OtlpJsonDecoder.sniff(br#"{"resource_spans":[]}"#));
        assert!(!OtlpJsonDecoder.sniff(br#"{"resourceMetrics":[]}"#));
        assert!(!OtlpJsonDecoder.sniff(b""));
    }

    #[test]
    fn an_end_before_its_start_yields_a_zero_duration_rather_than_an_underflow() {
        let payload = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"aa","spanId":"bb",
            "startTimeUnixNano":"100","endTimeUnixNano":"50"}]}]}]}"#;

        assert_eq!(decode(payload)[0].duration_ns(), 0);
    }
}
