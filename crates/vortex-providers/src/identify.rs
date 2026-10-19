//! Binary format identification from magic bytes and extensions.
//!
//! Identification is honest about its basis: `magic_bytes` results come from
//! well-known signatures, `extension` results are name-based hints, and
//! `content` results come from decoding checks. A format identification is
//! a *derived* finding backed by observed bytes — it never claims a full
//! structural parse of the format.

use std::path::Path;

/// Formats identified by fixed magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicFormat {
    /// ELF executable or object (`7f 45 4c 46`).
    Elf,
    /// 32-bit Mach-O.
    MachO32,
    /// 64-bit Mach-O.
    MachO64,
    /// FAT Mach-O binary.
    MachOFat,
    /// PE executable (`MZ` header).
    PE,
    /// ZIP archive (also JAR, APK, docx, asar-like containers).
    Zip,
    /// Gzip stream.
    Gzip,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF image.
    Gif,
    /// PDF document.
    Pdf,
    /// WebAssembly module.
    Wasm,
    /// Android DEX.
    Dex,
    /// SQLite 3 database.
    Sqlite,
    /// POSIX tar archive.
    Tar,
}

impl MagicFormat {
    /// Canonical lowercase identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            MagicFormat::Elf => "elf",
            MagicFormat::MachO32 => "mach-o-32",
            MagicFormat::MachO64 => "mach-o-64",
            MagicFormat::MachOFat => "mach-o-fat",
            MagicFormat::PE => "pe",
            MagicFormat::Zip => "zip",
            MagicFormat::Gzip => "gzip",
            MagicFormat::Png => "png",
            MagicFormat::Jpeg => "jpeg",
            MagicFormat::Gif => "gif",
            MagicFormat::Pdf => "pdf",
            MagicFormat::Wasm => "wasm",
            MagicFormat::Dex => "dex",
            MagicFormat::Sqlite => "sqlite",
            MagicFormat::Tar => "tar",
        }
    }

    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            MagicFormat::Elf => "ELF executable/object",
            MagicFormat::MachO32 => "Mach-O 32-bit binary",
            MagicFormat::MachO64 => "Mach-O 64-bit binary",
            MagicFormat::MachOFat => "Mach-O universal (fat) binary",
            MagicFormat::PE => "PE executable (Windows)",
            MagicFormat::Zip => "ZIP archive (also used by JAR/APK/asar-style containers)",
            MagicFormat::Gzip => "gzip compressed stream",
            MagicFormat::Png => "PNG image",
            MagicFormat::Jpeg => "JPEG image",
            MagicFormat::Gif => "GIF image",
            MagicFormat::Pdf => "PDF document",
            MagicFormat::Wasm => "WebAssembly module",
            MagicFormat::Dex => "Android DEX",
            MagicFormat::Sqlite => "SQLite 3 database",
            MagicFormat::Tar => "tar archive",
        }
    }
}

/// The result of identifying one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatIdentification {
    /// Canonical lowercase format name (`elf`, `javascript`, `text`, ...).
    pub format: String,
    /// Human-readable label.
    pub label: String,
    /// How the identification was made: `magic_bytes`, `extension`, or `content`.
    pub basis: &'static str,
    /// Hex dump of the observed magic bytes, when identification used them.
    pub magic_hex: Option<String>,
}

/// Sniff well-known magic bytes.
pub fn sniff_magic(bytes: &[u8]) -> Option<MagicFormat> {
    if bytes.len() < 4 {
        return None;
    }
    match bytes {
        [0x7f, b'E', b'L', b'F', ..] => Some(MagicFormat::Elf),
        [0xfe, 0xed, 0xfa, 0xce, ..] | [0xce, 0xfa, 0xed, 0xfe, ..] => Some(MagicFormat::MachO32),
        [0xfe, 0xed, 0xfa, 0xcf, ..] | [0xcf, 0xfa, 0xed, 0xfe, ..] => Some(MagicFormat::MachO64),
        [b'P', b'K', 0x03, 0x04, ..] | [0xca, 0xfe, 0xba, 0xbe, ..] => {
            // NOTE: 0xcafebabe is shared by FAT Mach-O binaries and JVM class
            // files; we report the Mach-O FAT label and document the ambiguity
            // instead of guessing between the two.
            if bytes.starts_with(b"PK") {
                Some(MagicFormat::Zip)
            } else {
                Some(MagicFormat::MachOFat)
            }
        }
        [0x4d, 0x5a, ..] => Some(MagicFormat::PE),
        [0x1f, 0x8b, ..] => Some(MagicFormat::Gzip),
        [0x89, b'P', b'N', b'G', ..] => Some(MagicFormat::Png),
        [0xff, 0xd8, 0xff, ..] => Some(MagicFormat::Jpeg),
        [b'G', b'I', b'F', b'8', ..] => Some(MagicFormat::Gif),
        [b'%', b'P', b'D', b'F', ..] => Some(MagicFormat::Pdf),
        [0x00, b'a', b's', b'm', ..] => Some(MagicFormat::Wasm),
        [b'd', b'e', b'x', 0x0a, ..] => Some(MagicFormat::Dex),
        _ => {
            if bytes.starts_with(b"SQLite format 3\0") {
                Some(MagicFormat::Sqlite)
            } else if bytes.starts_with(b"ustar") {
                Some(MagicFormat::Tar)
            } else {
                None
            }
        }
    }
}

/// Sniff an Electron asar archive structurally. There is no fixed magic;
/// the format opens with a Chromium pickle whose shape is checkable:
/// payload length 4, a sane header-pickle length, a consistent payload
/// size, and a JSON object starting right after.
fn sniff_asar(bytes: &[u8]) -> bool {
    if bytes.len() < 17 {
        return false;
    }
    let le = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    if le(0) != 4 {
        return false;
    }
    let header_pickle_len = le(4);
    if !(8..=64 * 1024 * 1024).contains(&header_pickle_len) {
        return false;
    }
    if le(8) + 4 != header_pickle_len {
        return false;
    }
    bytes[16] == b'{'
}

/// Extension-based format hints for text-ish files.
pub fn extension_format(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    let format = match extension.as_str() {
        "js" | "mjs" | "cjs" => "javascript",
        "jsx" | "ts" | "tsx" | "mts" | "cts" => "javascript-dialect",
        "json" => "json",
        "map" => "sourcemap-json",
        "html" | "htm" => "html",
        "css" => "css",
        "md" | "markdown" => "markdown",
        "txt" => "text",
        "csv" => "csv",
        "xml" => "xml",
        "yml" | "yaml" => "yaml",
        "toml" => "toml",
        "sh" | "bash" => "shell",
        "py" => "python",
        "rs" => "rust",
        "wasm" => "wasm",
        "node" => "native-addon",
        "asar" => "asar-archive",
        _ => return None,
    };
    Some(format)
}

/// Heuristic text detection: valid UTF-8, no NUL bytes, and a low ratio of
/// control characters in the sample.
pub fn looks_like_text(sample: &[u8]) -> bool {
    if sample.contains(&0) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(sample) else {
        return false;
    };
    if text.is_empty() {
        return true;
    }
    let control = text
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
        .count();
    control * 100 < text.chars().count()
}

/// Identify a file from its path and a content prefix.
///
/// Magic bytes take priority; extensions refine text formats; anything else
/// is reported as `binary` or `text` with the appropriate basis.
pub fn identify(path: &Path, content_prefix: &[u8]) -> FormatIdentification {
    if let Some(magic) = sniff_magic(content_prefix) {
        return FormatIdentification {
            format: magic.as_str().to_string(),
            label: magic.label().to_string(),
            basis: "magic_bytes",
            magic_hex: Some(hex_prefix(content_prefix, 8)),
        };
    }
    if sniff_asar(content_prefix) {
        return FormatIdentification {
            format: "asar-archive".to_string(),
            label: "Electron asar archive (structural check)".to_string(),
            basis: "content",
            magic_hex: Some(hex_prefix(content_prefix, 8)),
        };
    }
    if looks_like_text(content_prefix) {
        if let Some(format) = extension_format(path) {
            let label = match format {
                "javascript" => "JavaScript source",
                "javascript-dialect" => "JavaScript dialect source (JSX/TS)",
                "json" => "JSON document",
                "sourcemap-json" => "source map (JSON)",
                "html" => "HTML document",
                "css" => "CSS stylesheet",
                "markdown" => "Markdown document",
                "text" => "plain text",
                "csv" => "CSV data",
                "xml" => "XML document",
                "yaml" => "YAML document",
                "toml" => "TOML document",
                "shell" => "shell script",
                "python" => "Python source",
                "rust" => "Rust source",
                "native-addon" => "native addon (binary expected)",
                "asar-archive" => "Electron asar archive (identification only)",
                _ => "text",
            };
            return FormatIdentification {
                format: format.to_string(),
                label: label.to_string(),
                basis: "extension",
                magic_hex: None,
            };
        }
        return FormatIdentification {
            format: "text".to_string(),
            label: "plain text (no known extension)".to_string(),
            basis: "content",
            magic_hex: None,
        };
    }
    // Binary content: an .asar extension is a weak hint the structural
    // check above could not confirm; say so honestly and let the asar
    // reader try (and report failure honestly if it is not one).
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("asar"))
        == Some(true)
    {
        return FormatIdentification {
            format: "asar-archive".to_string(),
            label: "Electron asar archive (extension only; structure unconfirmed)".to_string(),
            basis: "extension",
            magic_hex: Some(hex_prefix(content_prefix, 8)),
        };
    }
    FormatIdentification {
        format: "binary".to_string(),
        label: "unidentified binary data".to_string(),
        basis: "content",
        magic_hex: Some(hex_prefix(content_prefix, 8)),
    }
}

fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identify_bytes(path: &str, bytes: &[u8]) -> FormatIdentification {
        identify(Path::new(path), bytes)
    }

    #[test]
    fn elf_magic_is_identified() {
        let id = identify_bytes("program", &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        assert_eq!(id.format, "elf");
        assert_eq!(id.basis, "magic_bytes");
        assert!(id.magic_hex.as_deref().unwrap().starts_with("7f 45 4c 46"));
    }

    #[test]
    fn pe_mach_o_zip_wasm_dex_are_identified() {
        assert_eq!(
            identify_bytes("a.exe", &[0x4d, 0x5a, 0x90, 0x00]).format,
            "pe"
        );
        assert_eq!(
            identify_bytes("bin", &[0xcf, 0xfa, 0xed, 0xfe, 0x07]).format,
            "mach-o-64"
        );
        assert_eq!(
            identify_bytes("pkg", &[b'P', b'K', 0x03, 0x04, 0x14]).format,
            "zip"
        );
        assert_eq!(
            identify_bytes("m.wasm", [0x00, b'a', b's', b'm', 1].as_slice()).format,
            "wasm"
        );
        assert_eq!(
            identify_bytes("classes", &[b'd', b'e', b'x', 0x0a, 0x00]).format,
            "dex"
        );
    }

    #[test]
    fn java_class_cafebabe_is_reported_as_mach_o_fat_with_ambiguity() {
        let id = identify_bytes("Main.class", &[0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00]);
        // cafebabe is shared by FAT Mach-O and JVM class files; the tool
        // reports the Mach-O FAT label (documented ambiguity) rather than
        // guessing between the two.
        assert_eq!(id.format, "mach-o-fat");
    }

    #[test]
    fn asar_is_identified_structurally_and_by_extension() {
        // Minimal structural shape: pickle payload 4, header pickle 8,
        // payload 4, JSON length 4, then '{'.
        let bytes = [
            4u8, 0, 0, 0, // size-pickle payload length
            8, 0, 0, 0, // header pickle length
            4, 0, 0, 0, // header payload
            4, 0, 0, 0, // JSON length
            b'{', b'}', 0, 0,
        ];
        let id = identify_bytes("app.asar", &bytes);
        assert_eq!(id.format, "asar-archive");
        assert_eq!(id.basis, "content");

        // Same pickle shape but not JSON: falls through to the extension
        // hint for .asar files, honestly marked as unconfirmed.
        let mut not_json = bytes;
        not_json[16] = b'x';
        let id = identify_bytes("app.asar", &not_json);
        assert_eq!(id.format, "asar-archive");
        assert_eq!(id.basis, "extension");

        // Arbitrary binary with a different name: not an asar claim.
        let id = identify_bytes("blob.bin", &not_json);
        assert_eq!(id.format, "binary");
    }

    #[test]
    fn sqlite_and_tar_are_identified() {
        assert_eq!(
            identify_bytes("db.sqlite", b"SQLite format 3\0\x10\x00\x01\x01").format,
            "sqlite"
        );
        assert_eq!(identify_bytes("a.tar", b"ustar  \0root").format, "tar");
    }

    #[test]
    fn javascript_by_extension_when_text() {
        let id = identify_bytes("src/main.js", b"const x = require('y');\n");
        assert_eq!(id.format, "javascript");
        assert_eq!(id.basis, "extension");
    }

    #[test]
    fn javascript_extension_with_binary_content_is_not_javascript() {
        let id = identify_bytes("main.js", &[0x7f, b'E', b'L', b'F', 2, 2]);
        assert_eq!(id.format, "elf");
    }

    #[test]
    fn plain_text_without_extension() {
        let id = identify_bytes("LICENSE", b"MIT License\n\nPermission is hereby granted");
        assert_eq!(id.format, "text");
        assert_eq!(id.basis, "content");
    }

    #[test]
    fn text_detection_rejects_nul_and_invalid_utf8() {
        assert!(!looks_like_text(b"hello\x00world"));
        assert!(!looks_like_text(&[0xff, 0xfe, 0xfd]));
        assert!(looks_like_text(b"just text\nwith lines\r\n"));
        assert!(looks_like_text(b""));
    }
}
