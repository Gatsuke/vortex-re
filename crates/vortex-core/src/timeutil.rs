//! RFC 3339 timestamps used across evidence records.
//!
//! All timestamps are stored as UTC RFC 3339 strings with second precision
//! (`YYYY-MM-DDTHH:MM:SSZ`) so they sort lexicographically and are trivially
//! portable. Parsing is strict; malformed timestamps are surfaced as errors
//! rather than guessed.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Current UTC time formatted as RFC 3339 with second precision.
pub fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    // Truncate sub-second precision for stable, comparable strings.
    let truncated = now.replace_nanosecond(0).unwrap_or(now);
    truncated
        .format(&Rfc3339)
        .expect("RFC 3339 formatting of a UTC timestamp cannot fail")
}

/// Parse an RFC 3339 timestamp string.
pub fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

/// Decide whether a run that started at `started_at` should be considered
/// stale (older than `older_than`). Unparseable timestamps return `None`
/// so callers can flag them without guessing.
pub fn is_stale(started_at: &str, older_than: std::time::Duration) -> Option<bool> {
    let started = parse_rfc3339(started_at)?;
    let age = OffsetDateTime::now_utc() - started;
    Some(age > older_than)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_round_trips() {
        let stamp = now_rfc3339();
        assert!(stamp.ends_with('Z'), "timestamp must be UTC: {stamp}");
        assert_eq!(stamp.len(), 20, "expected second precision: {stamp}");
        assert!(parse_rfc3339(&stamp).is_some());
    }

    #[test]
    fn lexicographic_ordering_matches_chronological_order() {
        let a = "2026-01-01T00:00:01Z";
        let b = "2026-01-01T00:00:02Z";
        assert!(a < b);
        assert!(parse_rfc3339(a).unwrap() < parse_rfc3339(b).unwrap());
    }

    #[test]
    fn staleness_detection() {
        let fresh = now_rfc3339();
        assert_eq!(
            is_stale(&fresh, std::time::Duration::from_secs(3600)),
            Some(false)
        );
        let old = "2020-01-01T00:00:00Z";
        assert_eq!(
            is_stale(old, std::time::Duration::from_secs(3600)),
            Some(true)
        );
        assert_eq!(
            is_stale("not-a-timestamp", std::time::Duration::from_secs(1)),
            None
        );
    }
}
