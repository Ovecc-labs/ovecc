pub const SAMPLING_DENOMINATOR: u64 = 1 << 56;

const MAX_THRESHOLD_DIGITS: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SamplingThreshold(u64);

impl SamplingThreshold {
    pub const ALWAYS: Self = Self(0);

    pub fn from_hex(digits: &str) -> Option<Self> {
        if digits.is_empty() || digits.len() > MAX_THRESHOLD_DIGITS {
            return None;
        }
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut padded = digits.to_ascii_lowercase();
        padded.extend(std::iter::repeat_n(
            '0',
            MAX_THRESHOLD_DIGITS - digits.len(),
        ));
        let raw = u64::from_str_radix(&padded, 16).ok()?;
        (raw < SAMPLING_DENOMINATOR).then_some(Self(raw))
    }

    pub fn parse_tracestate(tracestate: &str) -> Option<Self> {
        let otel = tracestate
            .split(',')
            .filter_map(|member| member.split_once('='))
            .find(|(key, _)| key.trim() == "ot")
            .map(|(_, value)| value.trim())?;
        let digits = otel
            .split(';')
            .filter_map(|field| field.split_once(':'))
            .find(|(key, _)| key.trim() == "th")
            .map(|(_, value)| value.trim())?;
        Self::from_hex(digits)
    }

    pub fn adjusted_count(self) -> u64 {
        let remaining = SAMPLING_DENOMINATOR - self.0;
        (SAMPLING_DENOMINATOR + remaining / 2) / remaining
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimatedCalls {
    Known(u64),
    Unknown,
}

impl EstimatedCalls {
    pub fn value(self) -> Option<u64> {
        match self {
            EstimatedCalls::Known(count) => Some(count),
            EstimatedCalls::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SamplingAccumulator {
    total: u64,
    unknown: bool,
}

impl SamplingAccumulator {
    pub fn observe(&mut self, threshold: Option<SamplingThreshold>) {
        match threshold {
            Some(threshold) => self.total = self.total.saturating_add(threshold.adjusted_count()),
            None => self.unknown = true,
        }
    }

    pub fn estimate(self) -> EstimatedCalls {
        if self.unknown {
            EstimatedCalls::Unknown
        } else {
            EstimatedCalls::Known(self.total)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_threshold_is_full_sampling_and_needs_no_extrapolation() {
        let threshold = SamplingThreshold::from_hex("0").unwrap();
        assert_eq!(threshold.adjusted_count(), 1);
        assert_eq!(SamplingThreshold::ALWAYS.adjusted_count(), 1);
    }

    #[test]
    fn a_single_hex_digit_is_right_padded_to_fourteen() {
        let short = SamplingThreshold::from_hex("c").unwrap();
        let full = SamplingThreshold::from_hex("c0000000000000").unwrap();
        assert_eq!(short, full);
        assert_eq!(short.adjusted_count(), 4);
    }

    #[test]
    fn half_and_eighth_sampling_decode_to_their_multipliers() {
        assert_eq!(
            SamplingThreshold::from_hex("8").unwrap().adjusted_count(),
            2
        );
        assert_eq!(
            SamplingThreshold::from_hex("e").unwrap().adjusted_count(),
            8
        );
    }

    #[test]
    fn the_threshold_is_read_out_of_a_multi_member_tracestate() {
        let state = "congo=t61rcWkgMzE,ot=p:8;th:c,vendor=x";
        assert_eq!(
            SamplingThreshold::parse_tracestate(state),
            SamplingThreshold::from_hex("c")
        );
    }

    #[test]
    fn a_tracestate_without_a_threshold_leaves_the_rate_unknown() {
        assert_eq!(SamplingThreshold::parse_tracestate(""), None);
        assert_eq!(SamplingThreshold::parse_tracestate("congo=x"), None);
        assert_eq!(SamplingThreshold::parse_tracestate("ot=p:8"), None);
        assert_eq!(SamplingThreshold::parse_tracestate("ot=th:"), None);
    }

    #[test]
    fn a_malformed_threshold_is_rejected_rather_than_guessed_at() {
        assert_eq!(SamplingThreshold::from_hex("zz"), None);
        assert_eq!(SamplingThreshold::from_hex(""), None);
        assert_eq!(SamplingThreshold::from_hex("000000000000000"), None);
    }

    #[test]
    fn the_widest_threshold_extrapolates_without_dividing_by_zero() {
        let widest = SamplingThreshold::from_hex("ffffffffffffff").unwrap();
        assert_eq!(widest.raw(), SAMPLING_DENOMINATOR - 1);
        assert_eq!(widest.adjusted_count(), SAMPLING_DENOMINATOR);
    }

    #[test]
    fn uppercase_digits_decode_to_the_same_threshold() {
        assert_eq!(
            SamplingThreshold::from_hex("C"),
            SamplingThreshold::from_hex("c")
        );
    }

    #[test]
    fn one_unknown_rate_makes_the_whole_estimate_unknown() {
        let mut accumulator = SamplingAccumulator::default();
        accumulator.observe(SamplingThreshold::from_hex("c"));
        accumulator.observe(SamplingThreshold::from_hex("c"));
        assert_eq!(accumulator.estimate(), EstimatedCalls::Known(8));

        accumulator.observe(None);
        assert_eq!(accumulator.estimate(), EstimatedCalls::Unknown);
        assert_eq!(accumulator.estimate().value(), None);
    }

    #[test]
    fn mixed_known_rates_add_up_per_observation() {
        let mut accumulator = SamplingAccumulator::default();
        accumulator.observe(SamplingThreshold::from_hex("0"));
        accumulator.observe(SamplingThreshold::from_hex("8"));
        accumulator.observe(SamplingThreshold::from_hex("c"));
        assert_eq!(accumulator.estimate(), EstimatedCalls::Known(7));
    }
}
