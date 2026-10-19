//! PE/COFF structural parsing (PE32 and PE32+), plus a .NET PE/CLI
//! metadata inventory.
//!
//! Reads the DOS header, PE signature, COFF header, optional header
//! (PE32/PE32+), section table, the import table (DLLs and function
//! names), the export table (names), and — when data directory 14 points
//! at a CLR header — the PE/CLI header and the BSJB metadata root with its
//! stream inventory. Structural only; no disassembly, no CIL decoding,
//! no type-system reconstruction.

use super::reader::{Reader, MAX_NAME_BYTES};

/// Hard caps (bounds checks against the buffer are the primary defense;
/// these bound work on headers whose tables are present but huge).
pub const MAX_SECTIONS: usize = 4096;
pub const MAX_IMPORT_DLLS: usize = 1024;
pub const MAX_EXPORT_NAMES: usize = 10_000;

/// One section-table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    /// Section name (up to 8 bytes, NUL-padded, as-is).
    pub name: String,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `VirtualAddress` (RVA).
    pub virtual_address: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
    /// `PointerToRawData` (file offset).
    pub raw_pointer: u32,
}

/// One imported DLL with its function names (bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImportDll {
    /// DLL name from the import descriptor.
    pub dll: String,
    /// Imported function names (hint/name entries; ordinals are counted,
    /// not listed).
    pub functions: Vec<String>,
    /// Imports by ordinal (no name available).
    pub ordinal_count: usize,
}

/// The .NET PE/CLI metadata inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetMetadata {
    /// Runtime version from the CLI header (`Major.Minor`).
    pub runtime_version: (u16, u16),
    /// Version string from the BSJB root (for example `v4.0.30319`).
    pub version_string: String,
    /// Streams found in the metadata root (`#~`, `#Strings`, ...).
    pub streams: Vec<DotnetStream>,
    /// Entry-point token from the CLI header, when non-zero.
    pub entry_point_token: u32,
    /// Flags from the CLI header (raw).
    pub flags: u32,
}

/// One metadata stream header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetStream {
    /// Stream name (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`, ...).
    pub name: String,
    /// Offset relative to the metadata root.
    pub offset: u32,
    /// Stream size in bytes.
    pub size: u32,
}

/// A parsed PE file's structural view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile {
    /// COFF machine type, raw.
    pub machine: u16,
    /// COFF `TimeDateStamp` (raw; fixtures and reproducible builds use 0).
    pub timestamp: u32,
    /// Optional-header magic: `0x10b` (PE32) or `0x20b` (PE32+).
    pub magic: u16,
    /// `AddressOfEntryPoint` (RVA).
    pub entry_point: u32,
    /// `Subsystem` raw value.
    pub subsystem: u16,
    /// Number of RVAs and sizes in the optional header.
    pub rva_and_sizes: u32,
    /// Sections from the section table (bounded by [`MAX_SECTIONS`]).
    pub sections: Vec<PeSection>,
    /// Why the section table is missing/partial, when it is.
    pub sections_reason: Option<String>,
    /// Import table entries (bounded by [`MAX_IMPORT_DLLS`] DLLs).
    pub imports: Vec<PeImportDll>,
    /// Why imports are missing, when they are.
    pub imports_reason: Option<String>,
    /// Exported names (bounded by [`MAX_EXPORT_NAMES`]).
    pub exports: Vec<String>,
    /// Why exports are missing, when they are (absent exports are normal
    /// for executables and are not a reason).
    pub exports_reason: Option<String>,
    /// .NET metadata inventory, present only when data directory 14 is set.
    pub dotnet: Option<DotnetMetadata>,
    /// Why .NET inventory failed, when the CLR directory was present but
    /// could not be read.
    pub dotnet_reason: Option<String>,
}

/// Human name for common COFF machine values.
pub fn machine_name(value: u16) -> &'static str {
    match value {
        0x014C => "Intel 386 (x86)",
        0x8664 => "AMD64 (x86-64)",
        0x01C0 => "ARM",
        0xAA64 => "ARM64",
        0x01F0 => "PowerPC",
        _ => "other",
    }
}

/// Human name for subsystem values.
pub fn subsystem_name(value: u16) -> &'static str {
    match value {
        1 => "native",
        2 => "Windows GUI",
        3 => "Windows console (CUI)",
        7 => "POSIX CUI",
        9 => "Windows CE GUI",
        14 => "EFI application",
        _ => "other",
    }
}

/// Section characteristics flags worth naming in output.
pub fn section_flags_summary(characteristics: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if characteristics & 0x00000020 != 0 {
        out.push("code");
    }
    if characteristics & 0x00000040 != 0 {
        out.push("initialized data");
    }
    if characteristics & 0x40000040 != 0 {
        out.push("readable");
    }
    if characteristics & 0x80000000 != 0 {
        out.push("writable");
    }
    if characteristics & 0x20000000 != 0 {
        out.push("executable");
    }
    if characteristics & 0x02000000 != 0 {
        out.push("discardable");
    }
    out
}

/// Parse the PE structure from `bytes` (the prefix that was read).
pub fn parse(bytes: &[u8]) -> Result<PeFile, String> {
    let r = Reader::with_endian(bytes, false);
    if bytes.len() < 2 || &bytes[0..2] != b"MZ" {
        return Err("not a PE file (no MZ DOS signature)".to_string());
    }
    let e_lfanew = r
        .read_u32(0x3C)
        .filter(|v| *v > 0 && (*v as usize) < bytes.len())
        .ok_or("bad DOS e_lfanew pointer")? as usize;
    if r.slice(e_lfanew, 4) != Some(b"PE\0\0") {
        return Err("PE signature not found at e_lfanew".to_string());
    }

    // COFF header (20 bytes right after the signature).
    let coff = e_lfanew + 4;
    let machine = r.read_u16(coff).ok_or("truncated COFF header")?;
    let section_count = r.read_u16(coff + 2).ok_or("truncated COFF header")? as usize;
    let timestamp = r.read_u32(coff + 4).ok_or("truncated COFF header")?;
    let optional_size = r.read_u16(coff + 16).ok_or("truncated COFF header")? as usize;
    let characteristics = r.read_u16(coff + 18).ok_or("truncated COFF header")?;

    let opt = coff + 20;
    let magic = r.read_u16(opt).ok_or("truncated optional header")?;
    let (is_pe32_plus, expected_size) = match magic {
        0x10B => (false, 224usize),
        0x20B => (true, 240usize),
        other => return Err(format!("unknown optional-header magic 0x{other:x}")),
    };
    if optional_size < expected_size {
        return Err(format!(
            "optional header size {optional_size} is smaller than the {} layout",
            if is_pe32_plus { "PE32+" } else { "PE32" }
        ));
    }

    // Fixed optional-header fields at magic-relative offsets.
    let entry_point = r.read_u32(opt + 16).ok_or("truncated optional header")?;
    let subsystem = r.read_u16(opt + 68).ok_or("truncated optional header")?;
    // NumberOfRvaAndSizes sits at 92 (PE32) / 108 (PE32+); clamp to 16.
    let dir_count_offset = if is_pe32_plus { 108 } else { 92 };
    let rva_and_sizes = r
        .read_u32(opt + dir_count_offset)
        .ok_or("truncated optional header")?
        .min(16);
    let dirs = opt + dir_count_offset + 4;

    let mut file = PeFile {
        machine,
        timestamp,
        magic,
        entry_point,
        subsystem,
        rva_and_sizes,
        sections: Vec::new(),
        sections_reason: None,
        imports: Vec::new(),
        imports_reason: None,
        exports: Vec::new(),
        exports_reason: None,
        dotnet: None,
        dotnet_reason: None,
    };
    let _ = characteristics; // reported via the header finding in builtin.rs

    // --- section table ------------------------------------------------------
    let table = dirs + 16 * 8;
    let capped = section_count.min(MAX_SECTIONS);
    if section_count > 0 {
        if let Some(rows) = read_section_table(&r, table, capped) {
            file.sections = rows;
            if section_count > capped {
                file.sections_reason = Some(format!(
                    "section table has {section_count} entries; parsing stopped at {MAX_SECTIONS}"
                ));
            }
        } else {
            file.sections_reason = Some(format!(
                "section table at offset {table} does not fit in the {} bytes read",
                bytes.len()
            ));
        }
    } else {
        file.sections_reason = Some("file has no sections (e_shnum-style zero count)".to_string());
    }

    // RVA→file-offset mapping via the section table. The result is not
    // filtered against EOF here: every subsequent read is bounds-checked,
    // so a pointer past the end fails honestly instead of being clamped.
    let rva_to_offset = |rva: u32| -> Option<usize> {
        let rva = rva as usize;
        for s in &file.sections {
            let va = s.virtual_address as usize;
            let span = s.virtual_size.max(s.raw_size) as usize;
            if va != 0 && rva >= va && rva < va + span {
                return Some(rva - va + s.raw_pointer as usize);
            }
        }
        // Not covered by any section: treat as a header RVA.
        Some(rva)
    };

    // Helper reading a NUL-terminated string at an RVA.
    let cstr_at_rva = |rva: u32| -> Option<String> {
        let off = rva_to_offset(rva)?;
        r.cstr(off, MAX_NAME_BYTES)
    };

    // --- data directories ----------------------------------------------------
    let dir = |index: usize| -> Option<(u32, u32)> {
        if index >= rva_and_sizes as usize {
            return None;
        }
        let rva = r.read_u32(dirs + index * 8)?;
        let size = r.read_u32(dirs + index * 8 + 4)?;
        Some((rva, size))
    };

    // --- imports (data directory 1) -------------------------------------------
    match dir(1) {
        Some((rva, size)) if rva != 0 && size >= 20 => {
            let mut at = rva_to_offset(rva).filter(|off| *off < bytes.len());
            let mut dll_index = 0;
            while let Some(desc) = at {
                if dll_index >= MAX_IMPORT_DLLS {
                    file.imports_reason =
                        Some(format!("import table has more than {MAX_IMPORT_DLLS} DLLs"));
                    break;
                }
                let Some(ilt_rva) = r.read_u32(desc) else {
                    break;
                };
                let name_rva = r.read_u32(desc + 12).unwrap_or(0);
                let iat_rva = r.read_u32(desc + 16).unwrap_or(0);
                if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                    break; // null terminator descriptor
                }
                let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
                let mut functions = Vec::new();
                let mut ordinal_count = 0usize;
                if let Some(mut thunk_off) = rva_to_offset(thunk_rva).filter(|o| *o < bytes.len()) {
                    for _ in 0..10_000 {
                        let entry = if is_pe32_plus {
                            r.read_u64(thunk_off)
                        } else {
                            r.read_u32(thunk_off).map(u64::from)
                        };
                        let Some(entry) = entry else {
                            break; // thunk array truncated: stop here, honestly
                        };
                        if entry == 0 {
                            break;
                        }
                        const ORDINAL_FLAG: u64 = 0x8000000000000000;
                        if entry & ORDINAL_FLAG != 0 {
                            ordinal_count += 1;
                        } else {
                            // IMAGE_IMPORT_BY_NAME: u16 hint, then the name.
                            let name_rva = (entry & 0xFFFF_FFFF)
                                .checked_add(2)
                                .expect("rva + 2 cannot overflow")
                                as u32;
                            if let Some(name) = cstr_at_rva(name_rva) {
                                if !name.is_empty() {
                                    functions.push(name);
                                } else {
                                    ordinal_count += 1; // empty name; count honestly
                                }
                            } else {
                                ordinal_count += 1; // name unreadable; count honestly
                            }
                        }
                        thunk_off += if is_pe32_plus { 8 } else { 4 };
                    }
                }
                let dll = cstr_at_rva(name_rva).unwrap_or_else(|| "<unreadable>".to_string());
                file.imports.push(PeImportDll {
                    dll,
                    functions,
                    ordinal_count,
                });
                dll_index += 1;
                at = desc.checked_add(20).filter(|next| *next < bytes.len());
            }
            if file.imports.is_empty() && file.imports_reason.is_none() {
                file.imports_reason = Some("import directory points outside the bytes read".into());
            }
        }
        _ => {
            file.imports_reason =
                Some("no import directory (statically resolved or table absent)".into());
        }
    }

    // --- exports (data directory 0) -------------------------------------------
    if let Some((rva, _size)) = dir(0).filter(|(rva, size)| *rva != 0 && *size >= 24) {
        match rva_to_offset(rva).filter(|o| *o < bytes.len()) {
            None => {
                file.exports_reason = Some("export directory points outside the bytes read".into());
            }
            Some(off) => {
                let count = r
                    .read_u32(off + 20)
                    .unwrap_or(0)
                    .min(MAX_EXPORT_NAMES as u32);
                let names_rva = r.read_u32(off + 24).unwrap_or(0);
                match rva_to_offset(names_rva).filter(|o| *o < bytes.len()) {
                    Some(names_off) => {
                        for i in 0..count {
                            let Some(entry_rva) = r.read_u32(names_off + i as usize * 4) else {
                                break;
                            };
                            if let Some(name) = cstr_at_rva(entry_rva) {
                                if !name.is_empty() {
                                    file.exports.push(name);
                                }
                            }
                        }
                        if file.exports.is_empty() {
                            file.exports_reason =
                                Some("export directory present but no readable names".into());
                        }
                    }
                    None => {
                        file.exports_reason =
                            Some("export name table points outside the bytes read".into());
                    }
                }
            }
        }
    }

    // --- .NET CLI metadata (data directory 14) ---------------------------------
    if let Some((clr_rva, _size)) = dir(14).filter(|(rva, _)| *rva != 0) {
        match read_dotnet(&r, &rva_to_offset, clr_rva, is_pe32_plus) {
            Ok(meta) => file.dotnet = Some(meta),
            Err(reason) => file.dotnet_reason = Some(reason),
        }
    }

    Ok(file)
}

fn read_section_table(r: &Reader, at: usize, count: usize) -> Option<Vec<PeSection>> {
    let end = at.checked_add(count.checked_mul(40)?)?;
    if end > r.bytes.len() {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let row = at + i * 40;
        let name_bytes = r.slice(row, 8)?;
        let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
        out.push(PeSection {
            name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
            virtual_size: r.read_u32(row + 8)?,
            virtual_address: r.read_u32(row + 12)?,
            raw_size: r.read_u32(row + 16)?,
            raw_pointer: r.read_u32(row + 20)?,
        });
    }
    Some(out)
}

/// Read the CLI header and BSJB metadata root at `clr_rva`.
fn read_dotnet(
    r: &Reader,
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
    clr_rva: u32,
    _is_pe32_plus: bool,
) -> Result<DotnetMetadata, String> {
    let cli_off = rva_to_offset(clr_rva)
        .filter(|o| *o < r.bytes.len())
        .ok_or("CLR header RVA does not resolve inside the bytes read".to_string())?;
    let _cb = r.read_u32(cli_off).ok_or("truncated CLR header")?;
    let major = r.read_u16(cli_off + 4).ok_or("truncated CLR header")?;
    let minor = r.read_u16(cli_off + 6).ok_or("truncated CLR header")?;
    let md_rva = r.read_u32(cli_off + 8).ok_or("truncated CLR header")?;
    let md_size = r.read_u32(cli_off + 12).ok_or("truncated CLR header")?;
    let flags = r.read_u32(cli_off + 16).ok_or("truncated CLR header")?;
    let entry_point_token = r.read_u32(cli_off + 20).ok_or("truncated CLR header")?;

    let md_off = rva_to_offset(md_rva)
        .filter(|o| *o < r.bytes.len())
        .ok_or("metadata RVA does not resolve inside the bytes read".to_string())?;
    if r.read_u32(md_off) != Some(0x424A_5342) {
        return Err("metadata root does not carry the BSJB signature".to_string());
    }
    // BSJB root: sig(4) major(2) minor(2) reserved(4) versionLen(4) version.
    // ECMA-335 says versionLen is the *allocated* size (multiple of 4), but
    // some producers store the raw string length; accept either and always
    // advance by the rounded-up size, which keeps the walk aligned in both
    // conventions.
    let version_len = r.read_u32(md_off + 12).ok_or("truncated metadata root")? as usize;
    if version_len == 0 || version_len > 1024 {
        return Err(format!("implausible metadata version length {version_len}"));
    }
    let padded_version_len = version_len.div_ceil(4) * 4;
    let version_bytes = r
        .slice(md_off + 16, padded_version_len)
        .ok_or("version string beyond the bytes read")?;
    let version_string = String::from_utf8_lossy(
        &version_bytes[..version_bytes
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(version_bytes.len())],
    )
    .into_owned();
    let streams_at = md_off + 16 + padded_version_len + 4; // skip flags(2)+streamCount(2)
    let stream_count = r
        .read_u16(md_off + 16 + padded_version_len + 2)
        .ok_or("truncated metadata stream header")? as usize;
    if stream_count > 32 {
        return Err(format!("implausible stream count {stream_count}"));
    }
    let mut streams = Vec::with_capacity(stream_count);
    let mut at = streams_at;
    for _ in 0..stream_count {
        let offset = r.read_u32(at).ok_or("truncated stream header")?;
        let size = r.read_u32(at + 4).ok_or("truncated stream header")?;
        // The name field is NUL-terminated and padded to a 4-byte boundary;
        // padding is computed from the raw NUL position, not the decoded
        // string, so non-ASCII bytes cannot skew the walk.
        let name_start = at + 8;
        let raw = r.bytes.get(name_start..).ok_or("truncated stream name")?;
        let nul = raw
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated stream name")?;
        let name = String::from_utf8_lossy(&raw[..nul.min(MAX_NAME_BYTES)]).into_owned();
        at = name_start + ((nul + 1 + 3) & !3);
        streams.push(DotnetStream { name, offset, size });
    }
    // md_size is informational; keep it out of the inventory unless sane.
    if md_size > 0 && (md_size as usize) < streams.iter().map(|s| s.size as usize).sum::<usize>() {
        // Sizes claim less than the streams themselves; do not fail — the
        // inventory reports what was read.
    }
    Ok(DotnetMetadata {
        runtime_version: (major, minor),
        version_string,
        streams,
        entry_point_token,
        flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/native")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    fn pe64_fixture_parses_headers_sections_and_imports() {
        let file = parse(&fixture("pe64-demo.exe")).expect("parses");
        assert_eq!(file.magic, 0x20B);
        assert_eq!(machine_name(file.machine), "AMD64 (x86-64)");
        assert_eq!(subsystem_name(file.subsystem), "Windows console (CUI)");
        let names: Vec<&str> = file.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec![".text", ".rdata"]);
        assert_eq!(file.imports.len(), 2);
        assert_eq!(file.imports[0].dll, "KERNEL32.dll");
        assert_eq!(file.imports[0].functions, vec!["CreateFileW"]);
        assert_eq!(file.imports[1].dll, "USER32.dll");
        assert_eq!(file.imports[1].functions, vec!["MessageBoxW"]);
        assert!(file.dotnet.is_none());
        assert!(file.exports.is_empty()); // no export directory in the fixture
    }

    #[test]
    fn pe32_fixture_parses() {
        let file = parse(&fixture("pe32-demo.exe")).expect("parses");
        assert_eq!(file.magic, 0x10B);
        assert_eq!(machine_name(file.machine), "Intel 386 (x86)");
        assert_eq!(file.imports.len(), 1);
        assert_eq!(file.imports[0].dll, "msvcrt.dll");
        assert_eq!(file.imports[0].functions, vec!["printf"]);
    }

    #[test]
    fn dotnet_fixture_inventories_cli_metadata() {
        let file = parse(&fixture("dotnet-demo.exe")).expect("parses");
        let dotnet = file
            .dotnet
            .as_ref()
            .unwrap_or_else(|| panic!("CLR metadata missing: {:?}", file.dotnet_reason));
        assert_eq!(dotnet.runtime_version, (2, 5));
        assert_eq!(dotnet.version_string, "v4.0.30319");
        assert_eq!(dotnet.entry_point_token, 0x0600_0001);
        let names: Vec<&str> = dotnet.streams.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["#~", "#Strings", "#US", "#GUID", "#Blob"]);
        // Offsets are strictly increasing past the header area.
        let offsets: Vec<u32> = dotnet.streams.iter().map(|s| s.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "{offsets:?}");
    }

    #[test]
    fn truncated_dos_header_is_an_error() {
        assert!(parse(b"M").is_err());
        assert!(parse(b"MZ").is_err()); // e_lfanew beyond buffer
    }

    #[test]
    fn non_pe_magic_is_an_error() {
        assert!(parse(&[0u8; 512]).is_err());
    }

    #[test]
    fn section_table_beyond_read_prefix_is_reported() {
        let full = fixture("pe64-demo.exe");
        // Section table lives at 0x174; cut before it.
        let cut = parse(&full[..0x170]).expect("headers parse");
        assert!(cut.sections.is_empty());
        assert!(cut.sections_reason.is_some());
        // The import directory RVA cannot map without sections.
        assert!(cut.imports.is_empty());
        assert!(cut.imports_reason.is_some());
    }

    #[test]
    fn lying_section_count_is_rejected_by_bounds() {
        let mut full = fixture("pe64-demo.exe");
        // NumberOfSections at COFF+2; claim 4096.
        let e_lfanew = u32::from_le_bytes(full[0x3C..0x40].try_into().unwrap()) as usize;
        let coff = e_lfanew + 4;
        full[coff + 2..coff + 4].copy_from_slice(&4096u16.to_le_bytes());
        let file = parse(&full).expect("parses");
        assert!(file.sections.is_empty());
        assert!(file.sections_reason.is_some());
    }
}
