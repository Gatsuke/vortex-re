//! Printable string extraction (a `strings(1)` equivalent).
//!
//! Only ASCII printable runs are extracted; multi-byte encodings are not
//! interpreted. Results are bounded by count and length, and callers are
//! expected to redact them before showing them to agents.

/// One extracted string with its byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    /// The extracted ASCII string.
    pub value: String,
    /// 0-based byte offset of the first character.
    pub byte_offset: u64,
}

/// Extract printable ASCII runs from `bytes`.
///
/// Returns the strings plus whether extraction stopped early at `max_count`.
pub fn extract_printable_strings(
    bytes: &[u8],
    min_len: usize,
    max_len: usize,
    max_count: usize,
) -> (Vec<ExtractedString>, bool) {
    let mut results = Vec::new();
    let mut truncated = false;
    let mut current = String::new();
    let mut start: u64 = 0;

    for (index, byte) in bytes.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(byte);
        if printable {
            if current.is_empty() {
                start = index as u64;
            }
            if current.len() < max_len {
                current.push(*byte as char);
            }
        } else if !current.is_empty() {
            if current.len() >= min_len {
                if results.len() >= max_count {
                    truncated = true;
                    // Consume the rest of this run then stop scanning.
                    current.clear();
                    break;
                }
                results.push(ExtractedString {
                    value: std::mem::take(&mut current),
                    byte_offset: start,
                });
            } else {
                current.clear();
            }
        }
    }
    // Tail run.
    if current.len() >= min_len && results.len() < max_count {
        results.push(ExtractedString {
            value: current,
            byte_offset: start,
        });
    } else if current.len() >= min_len && results.len() >= max_count {
        truncated = true;
    }

    (results, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_runs_between_non_printables() {
        let bytes = b"\x00\x00hello\x01world!\x00\x00trailing";
        let (strings, truncated) = extract_printable_strings(bytes, 5, 256, 100);
        assert!(!truncated);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(values, vec!["hello", "world!", "trailing"]);
        assert_eq!(strings[0].byte_offset, 2);
        assert_eq!(strings[1].byte_offset, 8);
    }

    #[test]
    fn min_length_filters_short_runs() {
        let bytes = b"ab\x00abcdef\x00abc";
        let (strings, _) = extract_printable_strings(bytes, 5, 256, 100);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(values, vec!["abcdef"]);
    }

    #[test]
    fn max_length_truncates_long_runs() {
        let bytes = vec![b'A'; 100];
        let (strings, _) = extract_printable_strings(&bytes, 5, 10, 100);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value.len(), 10);
    }

    #[test]
    fn max_count_stops_with_truncated_flag() {
        let bytes = b"aaaa\x00bbbb\x00cccc\x00dddd";
        let (strings, truncated) = extract_printable_strings(bytes, 4, 256, 2);
        assert_eq!(strings.len(), 2);
        assert!(truncated);
    }

    #[test]
    fn ascii_range_is_strict() {
        // Tab (0x09) is a separator, not printable, per the documented rule.
        let (strings, _) = extract_printable_strings(b"aa\tbbbbb", 5, 256, 100);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "bbbbb");
    }
}
