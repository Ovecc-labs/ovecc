mod otlp_json;

pub use otlp_json::{OTLP_JSON, OtlpJsonDecoder};

use crate::sampling::SamplingThreshold;
use anyhow::{Result, anyhow};
use std::collections::BTreeMap;

const SNIFF_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpanKind {
    Unspecified,
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

impl SpanKind {
    pub fn from_code(code: u64) -> Self {
        match code {
            1 => SpanKind::Internal,
            2 => SpanKind::Server,
            3 => SpanKind::Client,
            4 => SpanKind::Producer,
            5 => SpanKind::Consumer,
            _ => SpanKind::Unspecified,
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_uppercase().as_str() {
            "SPAN_KIND_INTERNAL" | "INTERNAL" => SpanKind::Internal,
            "SPAN_KIND_SERVER" | "SERVER" => SpanKind::Server,
            "SPAN_KIND_CLIENT" | "CLIENT" => SpanKind::Client,
            "SPAN_KIND_PRODUCER" | "PRODUCER" => SpanKind::Producer,
            "SPAN_KIND_CONSUMER" | "CONSUMER" => SpanKind::Consumer,
            _ => SpanKind::Unspecified,
        }
    }

    pub fn is_outbound(self) -> bool {
        matches!(self, SpanKind::Client | SpanKind::Producer)
    }

    pub fn is_inbound(self) -> bool {
        matches!(self, SpanKind::Server | SpanKind::Consumer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObservation {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub kind: SpanKind,
    pub service: Option<String>,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
    pub error: bool,
    pub sampling: Option<SamplingThreshold>,
    pub attributes: BTreeMap<String, String>,
}

impl RawObservation {
    pub fn duration_ns(&self) -> u64 {
        self.end_unix_nano.saturating_sub(self.start_unix_nano)
    }

    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }

    pub fn first_attribute(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|key| self.attribute(key))
    }

    pub fn attribute_keys(&self) -> Vec<String> {
        self.attributes.keys().cloned().collect()
    }
}

pub trait TelemetryDecoder: Sync {
    fn id(&self) -> &'static str;
    fn sniff(&self, head: &[u8]) -> bool;
    fn decode(&self, input: &[u8]) -> Result<Vec<RawObservation>>;
}

pub const DECODERS: &[&dyn TelemetryDecoder] = &[&OtlpJsonDecoder];

pub fn decoder_ids() -> Vec<&'static str> {
    DECODERS.iter().map(|decoder| decoder.id()).collect()
}

pub fn by_id(id: &str) -> Option<&'static dyn TelemetryDecoder> {
    DECODERS.iter().copied().find(|decoder| decoder.id() == id)
}

pub fn sniff(input: &[u8]) -> Option<&'static dyn TelemetryDecoder> {
    let head = &input[..input.len().min(SNIFF_BYTES)];
    DECODERS.iter().copied().find(|decoder| decoder.sniff(head))
}

pub fn select(input: &[u8], requested: Option<&str>) -> Result<&'static dyn TelemetryDecoder> {
    match requested {
        Some(id) => by_id(id).ok_or_else(|| {
            anyhow!(
                "unknown telemetry format '{id}' (known formats: {})",
                decoder_ids().join(", ")
            )
        }),
        None => sniff(input).ok_or_else(|| {
            anyhow!(
                "could not recognize the telemetry format from its content; pass --format \
                 with one of: {}",
                decoder_ids().join(", ")
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_id(
        selected: Result<&'static dyn TelemetryDecoder>,
    ) -> std::result::Result<&'static str, String> {
        selected
            .map(TelemetryDecoder::id)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn span_kinds_decode_from_both_the_integer_and_the_name_forms() {
        assert_eq!(SpanKind::from_code(2), SpanKind::Server);
        assert_eq!(SpanKind::from_name("SPAN_KIND_SERVER"), SpanKind::Server);
        assert_eq!(SpanKind::from_name("client"), SpanKind::Client);
        assert_eq!(SpanKind::from_code(99), SpanKind::Unspecified);
        assert_eq!(SpanKind::from_name("nonsense"), SpanKind::Unspecified);
    }

    #[test]
    fn only_client_and_producer_spans_leave_the_process() {
        assert!(SpanKind::Client.is_outbound());
        assert!(SpanKind::Producer.is_outbound());
        assert!(SpanKind::Server.is_inbound());
        assert!(SpanKind::Consumer.is_inbound());
        assert!(!SpanKind::Internal.is_outbound());
        assert!(!SpanKind::Internal.is_inbound());
    }

    #[test]
    fn an_unrecognized_payload_names_the_formats_it_could_have_been() {
        let error = format_id(select(b"not telemetry", None)).unwrap_err();
        assert!(error.contains("otlp-json"), "{error}");

        let error = format_id(select(b"{}", Some("otlp-protobuf"))).unwrap_err();
        assert!(error.contains("unknown telemetry format"), "{error}");
    }

    #[test]
    fn a_requested_format_is_used_even_when_sniffing_would_have_failed() {
        assert_eq!(format_id(select(b"", Some(OTLP_JSON))), Ok(OTLP_JSON));
    }
}
