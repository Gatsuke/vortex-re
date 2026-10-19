//! Source Map v3 structural parsing.
//!
//! The parser reads the JSON document, decodes the `mappings` field per the
//! source map specification (revision 3), and keeps an honest accounting of
//! everything it could not use. Reconstruction results are declarative data
//! from the artifact: every mapping carries provenance (the segment ordinal
//! inside the `mappings` string and the source index), and every dropped or
//! unusable segment is counted by reason — never silently discarded and
//! never fabricated.
//!
//! What this parser does NOT do: verify that a map actually describes the
//! bundle it sits next to (the format has no checksum linkage; the `file`
//! field is the only hint and callers check it textually), echo
//! `sourcesContent` (presence and byte length are recorded, contents are
//! never reproduced), or guess positions the map does not contain (a lookup
//! that falls between mappings reports `unmapped`; it never extrapolates).

use std::collections::BTreeMap;

/// Hard ceiling on per-entry problem lines recorded per document, so a
/// pathological `sources` array cannot flood the report. Entry counts are
/// always exact in [`SourceMapStats`]; only the per-entry prose is capped.
const MAX_PROBLEM_LINES: usize = 100;

/// A source map that could not be read as JSON at all.
///
/// Everything else — wrong field types, out-of-range indices, invalid VLQ
/// mid-string — degrades per item and is reported inside
/// [`SourceMapDoc::problems`] / [`SourceMapDoc::stats`] instead of failing
/// the whole document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapParseError(pub String);

/// One entry of the `sources` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceName {
    /// A string source path.
    Named(String),
    /// An explicit `null` (legal: "source not available").
    Null,
    /// Neither a string nor null (for example a number). Counted, unusable.
    Unusable,
}

impl SourceName {
    /// Display form used in findings; never fabricated.
    pub fn display(&self) -> String {
        match self {
            SourceName::Named(name) => name.clone(),
            SourceName::Null => "<null: source not available>".to_string(),
            SourceName::Unusable => "<unusable source entry>".to_string(),
        }
    }

    /// The path when named; `None` otherwise (never guessed).
    pub fn as_path(&self) -> Option<&str> {
        match self {
            SourceName::Named(name) => Some(name.as_str()),
            _ => None,
        }
    }
}

/// What one `mappings` segment says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentMapping {
    /// The segment declares a source position.
    /// `source_line` is 1-based here (the format stores 0-based).
    Source {
        source_index: usize,
        source_line: u32,
        source_col: u32,
        name_index: Option<usize>,
    },
    /// Column-only segment (1 field): it terminates the previous mapping's
    /// span and maps nothing.
    ColumnOnly,
    /// The segment declared a source position but the declaration is not
    /// usable; `reason` says why, exactly.
    Broken {
        reason: &'static str,
        detail: String,
    },
}

/// Why a segment is [`SegmentMapping::Broken`].
pub mod segment_reasons {
    /// `sources[index]` does not exist.
    pub const OUT_OF_RANGE_SOURCE: &str = "out_of_range_source_index";
    /// `names[index]` does not exist (only for 5-field segments).
    pub const OUT_OF_RANGE_NAME: &str = "out_of_range_name_index";
    /// A decoded value is negative where the format requires non-negative.
    pub const NEGATIVE_VALUE: &str = "negative_value";
    /// Generated columns decrease within a line (data defect; kept honest).
    pub const OUT_OF_ORDER: &str = "out_of_order_generated_column";
    /// A decoded coordinate exceeds the 32-bit range this implementation
    /// reports (real maps never encode this; garbage input does).
    pub const OVERSIZED_VALUE: &str = "value_exceeds_32bit_coordinate_range";
}

/// One decoded segment on one generated line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// 0-based generated column where the mapping starts.
    pub gen_col: u32,
    /// What the segment maps to.
    pub mapping: SegmentMapping,
    /// 0-based generated column where the mapping's span ends (the next
    /// segment's `gen_col`), when a later segment on the line starts
    /// further right. `None` means "until the end of the generated line" —
    /// the format does not record line lengths, so the span is open-ended.
    pub span_end: Option<u32>,
    /// Global ordinal of this segment within the whole `mappings` string
    /// (0-based). This is the per-mapping provenance key.
    pub ordinal: usize,
}

/// Segments of one generated line (1-based `line`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineMappings {
    pub line: u32,
    pub segments: Vec<Segment>,
}

/// Exact accounting of what the parser saw. Counts are never estimates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMapStats {
    /// Segments decoded (mapped + column-only + broken), before any stop.
    pub segments_total: usize,
    /// Segments that map to a source position.
    pub mapped: usize,
    /// Column-only segments.
    pub column_only: usize,
    /// Broken segments, by exact reason string.
    pub broken_by_reason: BTreeMap<&'static str, usize>,
    /// Generated lines spanned by the `mappings` string (semicolons + 1).
    pub lines_spanned: u32,
    /// Generated lines carrying at least one segment.
    pub lines_with_segments: u32,
    /// `sources` array length.
    pub sources_total: usize,
    /// Sources that are strings.
    pub sources_named: usize,
    /// Sources that are explicit nulls.
    pub sources_null: usize,
    /// Sources that are neither strings nor nulls.
    pub sources_unusable: usize,
    /// Source indexes with embedded content in `sourcesContent`.
    pub sources_with_content: usize,
    /// Total bytes of embedded `sourcesContent` (lengths only; never echoed).
    pub sources_content_bytes: u64,
    /// `names` array length.
    pub names_total: usize,
    /// `names` entries that are not strings.
    pub names_unusable: usize,
}

/// A parsed source map document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapDoc {
    /// `version` as declared (reported even when it is not 3).
    pub version: Option<u64>,
    /// Why the declared version deserves caution, when it does.
    pub version_note: Option<String>,
    /// `file` field, when a string.
    pub file: Option<String>,
    /// `sourceRoot` field, when a string.
    pub source_root: Option<String>,
    /// `sources` entries.
    pub sources: Vec<SourceName>,
    /// `names` entries (`None` = the slot is not a string).
    pub names: Vec<Option<String>>,
    /// Embedded-content byte length per source index (`None` = no content).
    pub sources_content_lengths: Vec<Option<u64>>,
    /// Decoded segments, grouped per generated line.
    pub lines: Vec<LineMappings>,
    /// Exact accounting.
    pub stats: SourceMapStats,
    /// Document-level problems (wrong types, missing arrays, ...).
    pub problems: Vec<String>,
    /// Why segment decoding stopped early, when it did. Segments decoded
    /// before the stop are kept and reported; the remainder was not parsed.
    pub mappings_stop: Option<String>,
}

/// Result of looking up one generated position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// The position is covered by a mapping.
    Mapped {
        /// Global segment ordinal (provenance).
        ordinal: usize,
        /// Coverage span on the generated line, columns `[start, end)`.
        /// `end` is `None` when the span runs to the end of the line.
        span_start: u32,
        span_end: Option<u32>,
        source_index: usize,
        source_line: u32,
        source_col: u32,
        name_index: Option<usize>,
    },
    /// The position is not covered; `reason` says which case applies.
    /// Never extrapolated.
    Unmapped { reason: &'static str },
}

pub mod lookup_reasons {
    /// The generated line carries no segments (or only unusable ones).
    pub const NO_SEGMENTS_ON_LINE: &str = "no_usable_segment_on_generated_line";
    /// The line has segments, but the position precedes the first one.
    pub const BEFORE_FIRST_SEGMENT: &str = "precedes_first_mapping_on_line";
    /// The line is beyond the range the `mappings` string spans.
    pub const BEYOND_LINES: &str = "beyond_mapped_lines";
    /// The line number is 0 (generated lines are 1-based).
    pub const ZERO_LINE: &str = "generated_lines_are_1_based";
}

impl SourceMapDoc {
    /// Look up a generated position (1-based line, 0-based column).
    ///
    /// A segment covers the half-open column span
    /// `[segment.gen_col, next_segment.gen_col)` on its line; the last
    /// segment of a line covers until the end of that line (the format
    /// does not record generated line lengths, so that span is open-ended
    /// and is reported as `None`). Positions inside a gap report
    /// `Unmapped` — they are never attributed to a neighboring segment.
    pub fn lookup(&self, gen_line: u32, gen_col: u32) -> LookupResult {
        if gen_line == 0 {
            return LookupResult::Unmapped {
                reason: lookup_reasons::ZERO_LINE,
            };
        }
        let Some(line) = self.lines.iter().find(|l| l.line == gen_line) else {
            return LookupResult::Unmapped {
                reason: if gen_line > self.stats.lines_spanned {
                    lookup_reasons::BEYOND_LINES
                } else {
                    lookup_reasons::NO_SEGMENTS_ON_LINE
                },
            };
        };
        if line.segments.is_empty() {
            return LookupResult::Unmapped {
                reason: lookup_reasons::NO_SEGMENTS_ON_LINE,
            };
        }
        // The segment with the greatest column at or before the query
        // (ties broken by later ordinal). Out-of-order lines are walked in
        // full: on healthy lines this is exactly the last segment in file
        // order; on broken lines the right-most started mapping wins, and
        // broken segments still map nothing.
        let mut covering: Option<&Segment> = None;
        for segment in &line.segments {
            if segment.gen_col <= gen_col
                && covering.is_none_or(|best| segment.gen_col >= best.gen_col)
            {
                covering = Some(segment);
            }
        }
        match covering {
            None => LookupResult::Unmapped {
                reason: lookup_reasons::BEFORE_FIRST_SEGMENT,
            },
            Some(segment) => match &segment.mapping {
                SegmentMapping::Source {
                    source_index,
                    source_line,
                    source_col,
                    name_index,
                } => LookupResult::Mapped {
                    ordinal: segment.ordinal,
                    span_start: segment.gen_col,
                    span_end: segment.span_end,
                    source_index: *source_index,
                    source_line: *source_line,
                    source_col: *source_col,
                    name_index: *name_index,
                },
                // Column-only and broken segments deliberately map nothing:
                // a position covered by them is unmapped, not guessed.
                SegmentMapping::ColumnOnly | SegmentMapping::Broken { .. } => {
                    LookupResult::Unmapped {
                        reason: lookup_reasons::NO_SEGMENTS_ON_LINE,
                    }
                }
            },
        }
    }

    /// The name for a `names` index, when the slot holds a string.
    pub fn name_at(&self, index: Option<usize>) -> Option<&str> {
        index
            .and_then(|i| self.names.get(i))
            .and_then(|n| n.as_deref())
    }

    /// The source entry for an index, when in range.
    pub fn source_at(&self, index: usize) -> Option<&SourceName> {
        self.sources.get(index)
    }

    /// Per-source aggregates for reconstruction findings: how many segments
    /// point at each source, and the first/last mapping (generated position
    /// to source position) with full provenance. Sources with no mappings
    /// are included with zero counts — absence is reported, not skipped.
    pub fn per_source_aggregates(&self) -> Vec<SourceAggregate> {
        let mut aggregates: Vec<SourceAggregate> = (0..self.sources.len())
            .map(|index| SourceAggregate {
                source_index: index,
                segment_count: 0,
                first: None,
                last: None,
            })
            .collect();
        for line in &self.lines {
            for segment in &line.segments {
                if let SegmentMapping::Source { source_index, .. } = &segment.mapping {
                    if let Some(aggregate) = aggregates.get_mut(*source_index) {
                        let (source_line, source_col) = match &segment.mapping {
                            SegmentMapping::Source {
                                source_line,
                                source_col,
                                ..
                            } => (*source_line, *source_col),
                            _ => unreachable!("guarded by the outer if-let"),
                        };
                        aggregate.segment_count += 1;
                        let mapping = AggMapping {
                            gen_line: line.line,
                            gen_col: segment.gen_col,
                            ordinal: segment.ordinal,
                            source_line,
                            source_col,
                        };
                        if aggregate.first.is_none() {
                            aggregate.first = Some(mapping.clone());
                        }
                        aggregate.last = Some(mapping);
                    }
                }
            }
        }
        aggregates
    }
}

/// One first/last mapping of a per-source aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggMapping {
    /// 1-based generated line.
    pub gen_line: u32,
    /// 0-based generated column.
    pub gen_col: u32,
    /// Global segment ordinal (provenance).
    pub ordinal: usize,
    /// 1-based source line.
    pub source_line: u32,
    /// 0-based source column.
    pub source_col: u32,
}

/// Aggregates for one source across the whole map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAggregate {
    pub source_index: usize,
    /// Segments mapping to this source (exact count).
    pub segment_count: usize,
    /// The earliest mapping observed for this source (file order).
    pub first: Option<AggMapping>,
    /// The latest mapping observed for this source (file order).
    pub last: Option<AggMapping>,
}

// ---------------------------------------------------------------------------
// VLQ
// ---------------------------------------------------------------------------

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug, Clone, PartialEq, Eq)]
enum VlqError {
    /// A field with no characters.
    Empty,
    /// A character outside the base64 alphabet.
    InvalidChar(char),
    /// The assembled value needs more bits than the format can express;
    /// real maps never encode this, so treat it as garbage, not data.
    TooLarge,
    /// The field ends with a continuation flag set (truncated mid-field).
    Truncated,
}

impl VlqError {
    fn message(&self) -> String {
        match self {
            VlqError::Empty => "empty field".to_string(),
            VlqError::InvalidChar(c) => format!("invalid base64 character {c:?}"),
            VlqError::TooLarge => {
                "value exceeds what VLQ can express (over 2^51); treated as garbage".to_string()
            }
            VlqError::Truncated => "field ends inside a continuation (truncated VLQ)".to_string(),
        }
    }
}

/// Decode one VLQ field (a run of base64 characters with no separators).
///
/// The format: base64 characters, 5 payload bits each, the continuation
/// flag in bit 0x20; the assembled value's bit 0 is the sign.
fn decode_vlq(field: &str) -> Result<i64, VlqError> {
    let mut value: i64 = 0;
    let mut shift: u32 = 0;
    let mut seen_any = false;
    for ch in field.chars() {
        let Some(digit) = BASE64_CHARS.iter().position(|&c| c == ch as u8) else {
            return Err(VlqError::InvalidChar(ch));
        };
        seen_any = true;
        const MAX_SHIFT: u32 = 45;
        if shift > MAX_SHIFT {
            return Err(VlqError::TooLarge);
        }
        value |= ((digit & 0x1f) as i64) << shift;
        if digit & 0x20 == 0 {
            let sign = value & 1;
            let magnitude = value >> 1;
            return Ok(if sign == 1 { -magnitude } else { magnitude });
        }
        shift += 5;
    }
    if !seen_any {
        return Err(VlqError::Empty);
    }
    // The last character carried a continuation flag: truncated field.
    Err(VlqError::Truncated)
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

/// Parse a source map document.
///
/// `Err` is reserved for "not JSON at all" — every other defect degrades
/// per item and is reported through `problems`, `stats`, and
/// `mappings_stop`, so partial maps stay usable and honestly labeled.
pub fn parse_source_map(
    bytes: &[u8],
    max_segments: usize,
) -> Result<SourceMapDoc, SourceMapParseError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|err| SourceMapParseError(format!("not valid JSON: {err}")))?;
    let Some(object) = value.as_object() else {
        return Ok(SourceMapDoc {
            version: None,
            version_note: None,
            file: None,
            source_root: None,
            sources: Vec::new(),
            names: Vec::new(),
            sources_content_lengths: Vec::new(),
            lines: Vec::new(),
            stats: SourceMapStats::default(),
            problems: vec!["top-level JSON value is not an object".to_string()],
            mappings_stop: None,
        });
    };
    let mut doc = SourceMapDoc {
        version: None,
        version_note: None,
        file: None,
        source_root: None,
        sources: Vec::new(),
        names: Vec::new(),
        sources_content_lengths: Vec::new(),
        lines: Vec::new(),
        stats: SourceMapStats::default(),
        problems: Vec::new(),
        mappings_stop: None,
    };

    // version
    match object.get("version") {
        None | Some(serde_json::Value::Null) => {
            doc.problems.push("'version' is missing".to_string());
        }
        Some(serde_json::Value::Number(n)) => {
            if let Some(v) = n.as_u64() {
                doc.version = Some(v);
                if v != 3 {
                    doc.version_note = Some(format!(
                        "declared version is {v}; this parser targets version 3; \
                         results below are structural and may not be meaningful"
                    ));
                }
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f >= 0.0 && f <= u32::MAX as f64 {
                    doc.version = Some(f as u64);
                    doc.problems.push(format!(
                        "'version' is the non-integer JSON number {f}; read as {}",
                        f as u64
                    ));
                } else {
                    doc.problems
                        .push(format!("'version' is not an integer: {f}"));
                }
            } else {
                doc.problems
                    .push("'version' is a number but not usable".to_string());
            }
        }
        Some(other) => {
            doc.problems.push(format!(
                "'version' is present but is not a number (found {})",
                json_type_name(other)
            ));
        }
    }

    // file / sourceRoot
    doc.file = optional_string(object, "file", &mut doc.problems);
    doc.source_root = optional_string(object, "sourceRoot", &mut doc.problems);

    // sources
    let mut sources_unusable = 0usize;
    match object.get("sources") {
        None | Some(serde_json::Value::Null) => {
            doc.problems.push("'sources' is missing".to_string());
        }
        Some(serde_json::Value::Array(entries)) => {
            for entry in entries {
                let name = match entry {
                    serde_json::Value::String(s) => SourceName::Named(s.clone()),
                    serde_json::Value::Null => SourceName::Null,
                    other => {
                        sources_unusable += 1;
                        if doc.problems.len() < MAX_PROBLEM_LINES {
                            doc.problems.push(format!(
                                "'sources' entry is neither a string nor null (found {})",
                                json_type_name(other)
                            ));
                        }
                        SourceName::Unusable
                    }
                };
                doc.sources.push(name);
            }
        }
        Some(other) => {
            doc.problems.push(format!(
                "'sources' is present but is not an array (found {})",
                json_type_name(other)
            ));
        }
    }

    // names
    match object.get("names") {
        None | Some(serde_json::Value::Null) => {
            doc.problems.push("'names' is missing".to_string());
        }
        Some(serde_json::Value::Array(entries)) => {
            for entry in entries {
                match entry {
                    serde_json::Value::String(s) => doc.names.push(Some(s.clone())),
                    _ => {
                        doc.names.push(None);
                        doc.stats.names_unusable += 1;
                        if doc.problems.len() < MAX_PROBLEM_LINES {
                            doc.problems
                                .push("'names' entry is not a string".to_string());
                        }
                    }
                }
            }
        }
        Some(other) => {
            doc.problems.push(format!(
                "'names' is present but is not an array (found {})",
                json_type_name(other)
            ));
        }
    }

    // sourcesContent: presence and lengths only; contents never echoed.
    match object.get("sourcesContent") {
        None | Some(serde_json::Value::Null) => {
            // Absent sourcesContent is common and legal.
        }
        Some(serde_json::Value::Array(entries)) => {
            doc.sources_content_lengths = vec![None; doc.sources.len().max(entries.len())];
            for (index, entry) in entries.iter().enumerate() {
                match entry {
                    serde_json::Value::String(s) => {
                        if index < doc.sources_content_lengths.len() {
                            doc.sources_content_lengths[index] = Some(s.len() as u64);
                            doc.stats.sources_with_content += 1;
                            doc.stats.sources_content_bytes += s.len() as u64;
                        }
                    }
                    serde_json::Value::Null => {}
                    other => {
                        if doc.problems.len() < MAX_PROBLEM_LINES {
                            doc.problems.push(format!(
                                "'sourcesContent' entry is neither a string nor null (found {})",
                                json_type_name(other)
                            ));
                        }
                    }
                }
            }
            if entries.len() > doc.sources.len() {
                doc.problems.push(format!(
                    "'sourcesContent' has {} entries for {} sources; extra entries \
                     were counted for totals only",
                    entries.len(),
                    doc.sources.len()
                ));
            }
        }
        Some(other) => {
            doc.problems.push(format!(
                "'sourcesContent' is present but is not an array (found {})",
                json_type_name(other)
            ));
        }
    }

    // stats for the arrays
    doc.stats.sources_total = doc.sources.len();
    doc.stats.sources_named = doc
        .sources
        .iter()
        .filter(|s| matches!(s, SourceName::Named(_)))
        .count();
    doc.stats.sources_null = doc
        .sources
        .iter()
        .filter(|s| matches!(s, SourceName::Null))
        .count();
    doc.stats.sources_unusable = sources_unusable;
    doc.stats.names_total = doc.names.len();
    if doc.sources_content_lengths.len() < doc.sources.len() {
        doc.sources_content_lengths.resize(doc.sources.len(), None);
    }

    // mappings
    let mappings: String = match object.get("mappings") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Null) | None => {
            doc.problems.push("'mappings' is missing".to_string());
            String::new()
        }
        Some(other) => {
            doc.problems.push(format!(
                "'mappings' is present but is not a string (found {})",
                json_type_name(other)
            ));
            String::new()
        }
    };

    decode_mappings(&mappings, max_segments, &mut doc);

    Ok(doc)
}

fn optional_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    problems: &mut Vec<String>,
) -> Option<String> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(other) => {
            problems.push(format!(
                "'{key}' is present but is not a string (found {})",
                json_type_name(other)
            ));
            None
        }
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Running delta state for segment decoding.
///
/// Per the specification: the generated column is relative to the previous
/// segment *on the same line* and resets at each new line; source index,
/// source line, source column, and name index are each relative to the
/// previous segment that carried that field — across lines.
struct SegmentState {
    prev_source: i64,
    prev_source_line: i64,
    prev_source_col: i64,
    prev_name: i64,
}

/// Decode the `mappings` string into per-line segments with honest stops.
fn decode_mappings(mappings: &str, max_segments: usize, doc: &mut SourceMapDoc) {
    if mappings.is_empty() {
        // An empty mappings field is legal: the map declares nothing.
        doc.stats.lines_spanned = 0;
        return;
    }
    let mut state = SegmentState {
        prev_source: 0,
        prev_source_line: 0,
        prev_source_col: 0,
        prev_name: 0,
    };
    let mut ordinal = 0usize;

    for (line_index, line_field) in mappings.split(';').enumerate() {
        let line_no = line_index as u32 + 1;
        doc.stats.lines_spanned = line_no;
        // Generated columns restart at each line; deltas never carry over.
        let mut prev_gen_col: i64 = 0;
        let mut segments: Vec<Segment> = Vec::new();
        if !line_field.is_empty() {
            for (segment_index, segment_field) in line_field.split(',').enumerate() {
                if ordinal >= max_segments {
                    doc.mappings_stop = Some(format!(
                        "segment cap ({max_segments}) reached at line {line_no}; remaining \
                         mappings were not parsed, so the true segment count is at least \
                         {ordinal}"
                    ));
                    break;
                }
                if segment_field.is_empty() {
                    doc.mappings_stop = Some(format!(
                        "empty segment at line {line_no} field {segment_index}; parsing \
                         stopped there, earlier segments are kept"
                    ));
                    break;
                }
                let values = match decode_segment_fields(segment_field) {
                    Ok(values) => values,
                    Err(reason) => {
                        doc.mappings_stop = Some(format!(
                            "segment {ordinal} (line {line_no} field {segment_index}) could \
                             not be decoded: {reason}; parsing stopped there, earlier \
                             segments are kept"
                        ));
                        break;
                    }
                };
                let field_count = values.len();
                if field_count != 1 && field_count != 4 && field_count != 5 {
                    doc.mappings_stop = Some(format!(
                        "segment {ordinal} (line {line_no} field {segment_index}) has \
                         {field_count} VLQ fields; the format allows 1, 4, or 5; parsing \
                         stopped there, earlier segments are kept"
                    ));
                    break;
                }

                let gen_col_delta = values[0];
                let candidate = prev_gen_col + gen_col_delta;
                if candidate < 0 {
                    // Keep the running state sane: this delta is not applied.
                    count_broken(doc, segment_reasons::NEGATIVE_VALUE);
                    push_segment(
                        &mut segments,
                        ordinal,
                        0,
                        SegmentMapping::Broken {
                            reason: segment_reasons::NEGATIVE_VALUE,
                            detail: format!(
                                "generated column decoded to {candidate} (negative); the \
                                 segment is recorded at column 0 for structure only"
                            ),
                        },
                    );
                    ordinal += 1;
                    continue;
                }
                if candidate > u32::MAX as i64 {
                    count_broken(doc, segment_reasons::OVERSIZED_VALUE);
                    push_segment(
                        &mut segments,
                        ordinal,
                        0,
                        SegmentMapping::Broken {
                            reason: segment_reasons::OVERSIZED_VALUE,
                            detail: format!(
                                "generated column decoded to {candidate}, beyond the \
                                 32-bit coordinate range; recorded at column 0 for \
                                 structure only"
                            ),
                        },
                    );
                    ordinal += 1;
                    continue;
                }
                prev_gen_col = candidate;
                let gen_col = prev_gen_col;

                let mapping: SegmentMapping = if field_count == 1 {
                    SegmentMapping::ColumnOnly
                } else {
                    state.prev_source += values[1];
                    state.prev_source_line += values[2];
                    state.prev_source_col += values[3];
                    if field_count == 5 {
                        state.prev_name += values[4];
                    }
                    let source_index = state.prev_source;
                    let source_line = state.prev_source_line;
                    let source_col = state.prev_source_col;
                    let name_index = state.prev_name;

                    let mut broken: Option<(&'static str, String)> = None;
                    if source_line > (u32::MAX as i64) - 1
                        || source_col > u32::MAX as i64
                        || source_index > (i32::MAX as i64)
                    {
                        broken = Some((
                            segment_reasons::OVERSIZED_VALUE,
                            format!(
                                "decoded source coordinates exceed the 32-bit range \
                                 (source index {source_index}, line {source_line}, \
                                 column {source_col})"
                            ),
                        ));
                    } else if source_index < 0
                        || source_line < 0
                        || source_col < 0
                        || name_index < 0
                    {
                        broken = Some((
                            segment_reasons::NEGATIVE_VALUE,
                            format!(
                                "decoded source coordinates are negative (source index \
                                 {source_index}, line {source_line}, column {source_col}, \
                                 name index {name_index})"
                            ),
                        ));
                    } else if source_index as usize >= doc.sources.len() {
                        broken = Some((
                            segment_reasons::OUT_OF_RANGE_SOURCE,
                            format!(
                                "source index {source_index} is outside the 'sources' \
                                 array ({} entries)",
                                doc.sources.len()
                            ),
                        ));
                    } else if field_count == 5 && name_index as usize >= doc.names.len() {
                        broken = Some((
                            segment_reasons::OUT_OF_RANGE_NAME,
                            format!(
                                "name index {name_index} is outside the 'names' array \
                                 ({} entries)",
                                doc.names.len()
                            ),
                        ));
                    }
                    match broken {
                        Some((reason, detail)) => SegmentMapping::Broken { reason, detail },
                        None => SegmentMapping::Source {
                            source_index: source_index as usize,
                            source_line: source_line as u32 + 1,
                            source_col: source_col as u32,
                            name_index: if field_count == 5 {
                                Some(name_index as usize)
                            } else {
                                None
                            },
                        },
                    }
                };

                // Final classification. A segment is counted exactly once:
                // when multiple defects coexist (for example broken source
                // coordinates on an out-of-order column), the primary reason
                // owns the count and the detail names every defect.
                let last_col = segments.last().map(|s| s.gen_col as i64).unwrap_or(-1);
                let out_of_order = gen_col < last_col;
                let final_mapping = if out_of_order {
                    let order_detail = format!(
                        "generated column {gen_col} follows an earlier segment at \
                         column {last_col} on line {line_no}"
                    );
                    match mapping {
                        SegmentMapping::Broken { reason, detail } => SegmentMapping::Broken {
                            reason,
                            detail: format!("{detail}; {order_detail}"),
                        },
                        _ => SegmentMapping::Broken {
                            reason: segment_reasons::OUT_OF_ORDER,
                            detail: order_detail,
                        },
                    }
                } else {
                    mapping
                };
                if let SegmentMapping::Broken { reason, .. } = &final_mapping {
                    count_broken(doc, reason);
                }
                push_segment(&mut segments, ordinal, gen_col as u32, final_mapping);
                ordinal += 1;
            }
        }
        // Early-stop fallout: keep what was decoded so far.
        if doc.mappings_stop.is_some() {
            doc.stats.segments_total = ordinal;
            push_line(doc, line_no, segments);
            return;
        }
        push_line(doc, line_no, segments);
    }
    doc.stats.segments_total = ordinal;
}

/// Decode the concatenated VLQ fields of one segment.
///
/// Fields have no separator in the mappings string; the decoder walks the
/// characters, splitting after each character whose continuation flag
/// (0x20) is clear.
fn decode_segment_fields(segment: &str) -> Result<Vec<i64>, String> {
    let mut values = Vec::new();
    let mut start = 0usize;
    let bytes = segment.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        let Some(digit) = BASE64_CHARS.iter().position(|&c| c == ch as u8) else {
            return Err(VlqError::InvalidChar(ch).message());
        };
        if digit & 0x20 == 0 {
            match decode_vlq(&segment[start..=index]) {
                Ok(value) => values.push(value),
                Err(err) => return Err(err.message()),
            }
            index += 1;
            start = index;
        } else {
            index += 1;
        }
    }
    if !bytes.is_empty() && start < bytes.len() {
        // The segment ended while a field was still continuing.
        return Err(VlqError::Truncated.message());
    }
    if bytes.is_empty() {
        return Err(VlqError::Empty.message());
    }
    Ok(values)
}

fn count_broken(doc: &mut SourceMapDoc, reason: &'static str) {
    *doc.stats.broken_by_reason.entry(reason).or_insert(0) += 1;
}

fn push_segment(
    segments: &mut Vec<Segment>,
    ordinal: usize,
    gen_col: u32,
    mapping: SegmentMapping,
) {
    // span_end is chained when the line is closed (push_line).
    segments.push(Segment {
        gen_col,
        mapping,
        span_end: None,
        ordinal,
    });
}

fn push_line(doc: &mut SourceMapDoc, line_no: u32, mut segments: Vec<Segment>) {
    // Chain span_end: each segment covers until the next segment's column.
    for index in 0..segments.len() {
        if index + 1 < segments.len() {
            let next_col = segments[index + 1].gen_col;
            // Only a *greater* column ends the span; equal or lower columns
            // (out-of-order data) leave the span open-ended rather than
            // fabricating an empty one.
            if next_col > segments[index].gen_col {
                segments[index].span_end = Some(next_col);
            }
        }
    }
    // Count kinds once, when the line is final.
    for segment in &segments {
        match &segment.mapping {
            SegmentMapping::Source { .. } => doc.stats.mapped += 1,
            SegmentMapping::ColumnOnly => doc.stats.column_only += 1,
            SegmentMapping::Broken { .. } => {
                // Counted at parse time via count_broken.
            }
        }
    }
    if !segments.is_empty() {
        doc.stats.lines_with_segments += 1;
    }
    doc.lines.push(LineMappings {
        line: line_no,
        segments,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode one value as a VLQ field (test helper; the parser only decodes).
    fn vlq(value: i64) -> String {
        let sign = if value < 0 { 1i64 } else { 0 };
        let mut encoded = (value.abs() << 1) | sign;
        let mut out = String::new();
        loop {
            let digit = encoded & 0x1f;
            encoded >>= 5;
            let cont = if encoded == 0 { 0u8 } else { 0x20 };
            out.push(BASE64_CHARS[(digit | cont as i64) as usize] as char);
            if encoded == 0 {
                break;
            }
        }
        out
    }

    /// Build a v3 map document JSON with the given pieces.
    fn map_json(sources: &str, names: &str, mappings: &str) -> String {
        format!(
            "{{\"version\":3,\"file\":\"bundle.js\",\"sourceRoot\":\"\",\"sources\":{sources},\
             \"sourcesContent\":[],\"names\":{names},\"mappings\":\"{mappings}\"}}"
        )
    }

    fn parse(text: &str) -> SourceMapDoc {
        let doc = parse_source_map(text.as_bytes(), 1000).expect("valid JSON map");
        assert!(
            doc.problems.is_empty(),
            "unexpected problems: {:?}",
            doc.problems
        );
        doc
    }

    #[test]
    fn vlq_encoder_covers_the_reference_pairs() {
        // Cross-check the helper against hand-computed reference pairs so
        // the fixtures built with it stay trustworthy.
        assert_eq!(vlq(0), "A");
        assert_eq!(vlq(1), "C");
        assert_eq!(vlq(2), "E");
        assert_eq!(vlq(3), "G");
        assert_eq!(vlq(4), "I");
        assert_eq!(vlq(5), "K");
        assert_eq!(vlq(10), "U");
        assert_eq!(vlq(-2), "F");
        assert_eq!(vlq(-5), "L");
        // A 16 needs two characters: value 32 -> 'g' (continuation) + 'B'.
        assert_eq!(vlq(16), "gB");
    }

    #[test]
    fn single_segment_map_decodes_and_lookups() {
        // mappings "AAAA": one segment, line 1 column 0 -> source 0 at 1:0.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAA"));
        assert_eq!(doc.stats.segments_total, 1);
        assert_eq!(doc.stats.mapped, 1);
        assert_eq!(doc.stats.lines_spanned, 1);
        assert_eq!(doc.stats.lines_with_segments, 1);
        match doc.lookup(1, 0) {
            LookupResult::Mapped {
                ordinal,
                span_start,
                span_end,
                source_index,
                source_line,
                source_col,
                name_index,
            } => {
                assert_eq!(ordinal, 0);
                assert_eq!(span_start, 0);
                assert_eq!(span_end, None, "last segment of a line is open-ended");
                assert_eq!(source_index, 0);
                assert_eq!(source_line, 1);
                assert_eq!(source_col, 0);
                assert_eq!(name_index, None);
            }
            other => panic!("expected a mapping, got {other:?}"),
        }
    }

    #[test]
    fn continuation_semantics_across_lines_and_fields() {
        // Line 1: seg0 (1:0 -> a.js 1:0), seg1 (1:4 -> b.js 2:1).
        // Line 2: seg2 (2:2 -> b.js 3:1): generated column resets at the
        // new line; source-family deltas continue from line 1's last value.
        let doc = parse(&map_json("[\"a.js\",\"b.js\"]", "[]", "AAAA,ICCC;EACA"));
        assert_eq!(doc.stats.segments_total, 3);
        assert_eq!(doc.stats.mapped, 3);
        assert_eq!(doc.stats.lines_spanned, 2);

        // (1:0) and its span runs to the next segment at column 4.
        match doc.lookup(1, 0) {
            LookupResult::Mapped {
                ordinal, span_end, ..
            } => {
                assert_eq!(ordinal, 0);
                assert_eq!(span_end, Some(4));
            }
            other => panic!("1:0 should map, got {other:?}"),
        }
        // (1:3) sits inside seg0's span -> same mapping.
        match doc.lookup(1, 3) {
            LookupResult::Mapped { ordinal, .. } => assert_eq!(ordinal, 0),
            other => panic!("1:3 should map via seg0's span, got {other:?}"),
        }
        // (1:4) is seg1: b.js line 2 col 1.
        match doc.lookup(1, 4) {
            LookupResult::Mapped {
                ordinal,
                source_index,
                source_line,
                source_col,
                ..
            } => {
                assert_eq!(ordinal, 1);
                assert_eq!(source_index, 1);
                assert_eq!(source_line, 2);
                assert_eq!(source_col, 1);
            }
            other => panic!("1:4 should map, got {other:?}"),
        }
        // (1:9): still seg1 (open-ended until the end of the line).
        match doc.lookup(1, 9) {
            LookupResult::Mapped { ordinal, .. } => assert_eq!(ordinal, 1),
            other => panic!("1:9 should map via the open span, got {other:?}"),
        }
        // (2:2): source-family deltas continued across the line boundary.
        match doc.lookup(2, 2) {
            LookupResult::Mapped {
                ordinal,
                source_index,
                source_line,
                source_col,
                ..
            } => {
                assert_eq!(ordinal, 2);
                assert_eq!(source_index, 1, "delta 0 keeps the previous source");
                assert_eq!(source_line, 3, "line delta +1 from line 1's last value");
                assert_eq!(source_col, 1, "col delta 0 from line 1's last value");
            }
            other => panic!("2:2 should map, got {other:?}"),
        }
        // Aggregates: a.js 1 mapping, b.js 2 with first/last provenance.
        let aggregates = doc.per_source_aggregates();
        assert_eq!(aggregates.len(), 2);
        assert_eq!(aggregates[0].segment_count, 1);
        assert_eq!(aggregates[1].segment_count, 2);
        let first = aggregates[1].first.as_ref().unwrap();
        assert_eq!((first.gen_line, first.gen_col, first.ordinal), (1, 4, 1));
        assert_eq!((first.source_line, first.source_col), (2, 1));
        let last = aggregates[1].last.as_ref().unwrap();
        assert_eq!((last.gen_line, last.gen_col, last.ordinal), (2, 2, 2));
    }

    #[test]
    fn column_only_segment_maps_nothing() {
        // "AAAA,K": seg0 maps (1:0)->a.js; seg1 at column 5 has one field
        // and terminates seg0's span without mapping anything.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAA,K"));
        assert_eq!(doc.stats.segments_total, 2);
        assert_eq!(doc.stats.mapped, 1);
        assert_eq!(doc.stats.column_only, 1);
        match doc.lookup(1, 4) {
            LookupResult::Mapped { span_end, .. } => assert_eq!(span_end, Some(5)),
            other => panic!("1:4 should map via seg0, got {other:?}"),
        }
        match doc.lookup(1, 5) {
            LookupResult::Unmapped { reason } => {
                assert_eq!(reason, lookup_reasons::NO_SEGMENTS_ON_LINE);
            }
            other => panic!("1:5 is covered only by a column-only segment, got {other:?}"),
        }
        // The zero-mapping source is included, not skipped.
        let single = parse(&map_json("[\"a.js\",\"b.js\"]", "[]", "AAAA,K"));
        assert_eq!(single.per_source_aggregates()[1].segment_count, 0);
    }

    #[test]
    fn gaps_and_boundaries_report_unmapped() {
        // Line 2 starts its first mapping at column 5; line 3 is empty.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAA;KAAA;"));
        assert_eq!(doc.stats.lines_spanned, 3);
        assert_eq!(doc.stats.lines_with_segments, 2);
        match doc.lookup(2, 4) {
            LookupResult::Unmapped { reason } => {
                assert_eq!(reason, lookup_reasons::BEFORE_FIRST_SEGMENT);
            }
            other => panic!("2:4 precedes the first mapping, got {other:?}"),
        }
        match doc.lookup(2, 5) {
            LookupResult::Mapped { .. } => {}
            other => panic!("2:5 should map, got {other:?}"),
        }
        match doc.lookup(3, 0) {
            LookupResult::Unmapped { reason } => {
                assert_eq!(reason, lookup_reasons::NO_SEGMENTS_ON_LINE);
            }
            other => panic!("line 3 has no segments, got {other:?}"),
        }
        match doc.lookup(4, 0) {
            LookupResult::Unmapped { reason } => {
                assert_eq!(reason, lookup_reasons::BEYOND_LINES);
            }
            other => panic!("line 4 is beyond the map, got {other:?}"),
        }
        match doc.lookup(0, 0) {
            LookupResult::Unmapped { reason } => {
                assert_eq!(reason, lookup_reasons::ZERO_LINE);
            }
            other => panic!("generated lines are 1-based, got {other:?}"),
        }
    }

    #[test]
    fn out_of_range_source_index_is_counted_not_dropped() {
        // seg1 points at source index 1 with only one source declared.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAA,ICCC"));
        assert_eq!(doc.stats.segments_total, 2);
        assert_eq!(doc.stats.mapped, 1);
        assert_eq!(
            doc.stats
                .broken_by_reason
                .get(segment_reasons::OUT_OF_RANGE_SOURCE),
            Some(&1)
        );
        match doc.lookup(1, 4) {
            LookupResult::Unmapped { .. } => {}
            other => panic!("the broken segment maps nothing, got {other:?}"),
        }
        assert_eq!(doc.per_source_aggregates()[0].segment_count, 1);
    }

    #[test]
    fn out_of_range_name_index_is_counted() {
        // 5 fields with name index 3 against an empty names array.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAAG"));
        assert_eq!(doc.stats.segments_total, 1);
        assert_eq!(doc.stats.mapped, 0);
        assert_eq!(
            doc.stats
                .broken_by_reason
                .get(segment_reasons::OUT_OF_RANGE_NAME),
            Some(&1)
        );
    }

    #[test]
    fn negative_source_coordinates_are_counted() {
        // [0, 0, -2, 0]: source line decodes to -2.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAFA"));
        assert_eq!(doc.stats.mapped, 0);
        assert_eq!(
            doc.stats
                .broken_by_reason
                .get(segment_reasons::NEGATIVE_VALUE),
            Some(&1)
        );
    }

    #[test]
    fn invalid_base64_stops_the_walk_and_keeps_prefix() {
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAA,="));
        assert_eq!(doc.stats.segments_total, 1);
        assert_eq!(doc.stats.mapped, 1);
        let stop = doc.mappings_stop.as_deref().unwrap();
        assert!(stop.contains("invalid base64"), "stop was: {stop}");
        assert!(stop.contains("earlier segments are kept"));
    }

    #[test]
    fn wrong_field_count_stops_the_walk() {
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AA"));
        assert_eq!(doc.stats.segments_total, 0);
        let stop = doc.mappings_stop.as_deref().unwrap();
        assert!(stop.contains("has 2 VLQ fields"), "stop was: {stop}");
    }

    #[test]
    fn truncated_vlq_field_stops_the_walk() {
        // "AAg": two closed fields then a continuation that never ends.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAg"));
        assert_eq!(doc.stats.segments_total, 0);
        let stop = doc.mappings_stop.as_deref().unwrap();
        assert!(stop.contains("truncated"), "stop was: {stop}");
    }

    #[test]
    fn segment_cap_stops_and_discloses_the_floor() {
        let doc = parse_source_map(
            map_json("[\"a.js\"]", "[]", "AAAA,AAAA,AAAA,AAAA,AAAA").as_bytes(),
            4,
        )
        .expect("valid JSON");
        assert!(doc.problems.is_empty());
        assert_eq!(doc.stats.segments_total, 4);
        assert_eq!(doc.stats.mapped, 4);
        let stop = doc.mappings_stop.as_deref().unwrap();
        assert!(stop.contains("segment cap (4)"), "stop was: {stop}");
        assert!(stop.contains("at least 4"));
    }

    #[test]
    fn out_of_order_columns_are_counted_and_never_resurrected() {
        // Columns 10 then 5 on the same line: the second is out of order.
        let doc = parse(&map_json("[\"a.js\"]", "[]", "UAAA,LAAA"));
        assert_eq!(doc.stats.mapped, 1);
        assert_eq!(
            doc.stats
                .broken_by_reason
                .get(segment_reasons::OUT_OF_ORDER),
            Some(&1)
        );
        // A position covered only by the broken segment maps nothing.
        match doc.lookup(1, 7) {
            LookupResult::Unmapped { .. } => {}
            other => panic!("the out-of-order segment maps nothing, got {other:?}"),
        }
        // The healthy segment still answers for its own span.
        match doc.lookup(1, 10) {
            LookupResult::Mapped { ordinal, .. } => assert_eq!(ordinal, 0),
            other => panic!("1:10 should map, got {other:?}"),
        }
    }

    #[test]
    fn versions_other_than_three_are_parsed_with_a_note() {
        let doc = parse_source_map(
            b"{\"version\":2,\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}",
            1000,
        )
        .expect("valid JSON");
        assert_eq!(doc.version, Some(2));
        let note = doc.version_note.as_deref().unwrap();
        assert!(note.contains("targets version 3"), "note was: {note}");
        // The mappings still decode.
        assert_eq!(doc.stats.mapped, 1);
    }

    #[test]
    fn malformed_version_is_a_problem_not_a_crash() {
        for body in [
            "{\"version\":\"3\",\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}".to_string(),
            "{\"version\":3.5,\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}".to_string(),
            "{\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}".to_string(),
        ] {
            let doc = parse_source_map(body.as_bytes(), 1000).expect("valid JSON");
            assert!(
                doc.problems.iter().any(|p| p.contains("'version'")),
                "expected a version problem, got {:?}",
                doc.problems
            );
        }
        // 3.0 is an integral float literal: read as the integer 3, with a
        // problem that notes the JSON literal was not an integer (Rust
        // renders the float 3.0 as "3").
        let doc = parse_source_map(
            b"{\"version\":3.0,\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}",
            1000,
        )
        .expect("valid JSON");
        assert_eq!(doc.version, Some(3));
        assert!(doc
            .problems
            .iter()
            .any(|p| p.contains("'version' is the non-integer JSON number")));
    }

    #[test]
    fn null_and_unusable_source_entries_are_counted() {
        // This fixture intentionally carries an unusable entry; parse
        // directly instead of through the no-problems helper.
        let doc = parse_source_map(map_json("[null,\"a.js\",7]", "[]", "AAAA").as_bytes(), 1000)
            .expect("valid JSON");
        assert_eq!(doc.stats.sources_total, 3);
        assert_eq!(doc.stats.sources_named, 1);
        assert_eq!(doc.stats.sources_null, 1);
        assert_eq!(doc.stats.sources_unusable, 1);
        assert!(doc
            .problems
            .iter()
            .any(|p| p.contains("neither a string nor null")));
        assert_eq!(doc.source_at(0), Some(&SourceName::Null));
        assert_eq!(doc.source_at(2), Some(&SourceName::Unusable));
        // The mapping points at index 0, which is a null: it is reported
        // with that name, never fabricated into a path.
        match doc.lookup(1, 0) {
            LookupResult::Mapped { source_index, .. } => assert_eq!(source_index, 0),
            other => panic!("1:0 should map, got {other:?}"),
        }
        assert_eq!(
            doc.source_at(0).unwrap().display(),
            "<null: source not available>"
        );
    }

    #[test]
    fn sources_content_is_measured_not_echoed() {
        let body = "{\"version\":3,\"sources\":[\"a.js\",\"b.js\"],\
              \"sourcesContent\":[\"\",\"0123456789\"],\"names\":[],\"mappings\":\"AAAA\"}";
        let doc = parse(body);
        assert_eq!(doc.stats.sources_with_content, 2);
        assert_eq!(doc.stats.sources_content_bytes, 10);
        assert_eq!(doc.sources_content_lengths, vec![Some(0), Some(10)]);

        // More content entries than sources: counted, disclosed.
        let doc = parse_source_map(
            "{\"version\":3,\"sources\":[\"a.js\"],\"sourcesContent\":[\"x\",\"y\",\"z\"],\"names\":[],\"mappings\":\"AAAA\"}".as_bytes(),
            1000,
        )
        .expect("valid JSON");
        assert!(doc.problems.iter().any(|p| p.contains("extra entries")));
    }

    #[test]
    fn empty_mappings_field_is_legal_and_maps_nothing() {
        let doc = parse(&map_json("[\"a.js\"]", "[]", ""));
        assert_eq!(doc.stats.lines_spanned, 0);
        assert_eq!(doc.stats.segments_total, 0);
        assert!(doc.problems.is_empty());
        match doc.lookup(1, 0) {
            LookupResult::Unmapped {
                reason: lookup_reasons::BEYOND_LINES,
            } => {}
            other => panic!("an empty map maps nothing, got {other:?}"),
        }
    }

    #[test]
    fn file_and_source_root_fields_are_recorded() {
        let doc = parse(&map_json("[\"a.js\"]", "[]", "AAAA"));
        assert_eq!(doc.file.as_deref(), Some("bundle.js"));
        assert_eq!(doc.source_root.as_deref(), Some(""));

        let doc = parse_source_map(
            b"{\"version\":3,\"file\":42,\"sources\":[\"a.js\"],\"mappings\":\"AAAA\"}",
            1000,
        )
        .expect("valid JSON");
        assert!(doc.file.is_none());
        assert!(doc
            .problems
            .iter()
            .any(|p| p.contains("'file' is present but is not a string")));
    }

    #[test]
    fn not_json_at_all_is_an_error() {
        let err = parse_source_map(b"{ not json", 1000).unwrap_err();
        assert!(err.0.contains("not valid JSON"));
    }

    #[test]
    fn top_level_non_object_is_a_problem() {
        let doc = parse_source_map(b"[1,2]", 1000).expect("valid JSON");
        assert!(doc
            .problems
            .iter()
            .any(|p| p == "top-level JSON value is not an object"));
    }

    #[test]
    fn stats_invariant_mapped_plus_column_only_plus_broken_equals_total() {
        // Across a mixed document: every parsed segment is accounted exactly
        // once, by exactly one bucket.
        let doc = parse(&map_json(
            "[\"a.js\",\"b.js\",null]",
            "[\"n0\"]",
            "AAAA,ICCC,K,AAFA,UAAA,LAAA,AAAAG,EACA;KAAA",
        ));
        let broken: usize = doc.stats.broken_by_reason.values().sum();
        assert_eq!(
            doc.stats.segments_total,
            doc.stats.mapped + doc.stats.column_only + broken,
            "accounting must be exact: {:?}",
            doc.stats
        );
    }
}
