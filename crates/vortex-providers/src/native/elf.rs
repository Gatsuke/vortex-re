//! ELF structural parsing (32- and 64-bit, little- and big-endian).
//!
//! Reads the ELF header, the section table (with the extended-numbering
//! escape hatches `e_shnum == 0` / `e_shstrndx == SHN_XINDEX`), and the
//! undefined dynamic symbols from `.dynsym` — the closest thing ELF has to
//! an "import list". Everything is bounds-checked against the bytes that
//! were actually read; tables beyond the read prefix are reported as
//! unavailable with a reason instead of being dropped silently.

use super::reader::{Reader, MAX_NAME_BYTES};

/// `e_ident` layout offsets.
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_OSABI: usize = 7;

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2MSB: u8 = 2;

const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;
const SHN_XINDEX: u16 = 0xffff;

/// One parsed section header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    /// Section name from `.shstrtab`.
    pub name: String,
    /// `sh_type` raw value.
    pub sh_type: u32,
    /// `sh_size`.
    pub size: u64,
    /// `sh_offset` (0 for `SHT_NOBITS`).
    pub offset: u64,
}

/// A parsed ELF file's structural view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFile {
    /// 1 or 2 (32/64-bit).
    pub class: u8,
    /// True when big-endian (`EI_DATA == 2`).
    pub big_endian: bool,
    /// OS/ABI byte from `e_ident`.
    pub os_abi: u8,
    /// `e_type` raw value.
    pub elf_type: u16,
    /// `e_machine` raw value.
    pub machine: u16,
    /// `e_entry`.
    pub entry: u64,
    /// `e_phnum`.
    pub phnum: u16,
    /// Sections listed from the table (bounded by [`MAX_SECTIONS`]).
    pub sections: Vec<ElfSection>,
    /// Why the section table (or part of it) is missing, when it is.
    pub sections_reason: Option<String>,
    /// Total section count from the header (may exceed `sections.len()`).
    pub section_total: usize,
    /// Undefined dynamic symbols with names (bounded by [`MAX_SYMBOLS`]).
    pub imports: Vec<String>,
    /// Why `.dynsym` could not be read, when it could not.
    pub imports_reason: Option<String>,
}

/// Hard cap on sections parsed (listing is bounded further by limits; this
/// bounds parser work on headers that lie about counts).
pub const MAX_SECTIONS: usize = 4096;
/// Hard cap on dynamic symbols enumerated per `.dynsym`.
pub const MAX_SYMBOLS: usize = 10_000;

/// Human name for an `e_type` value.
pub fn elf_type_name(value: u16) -> &'static str {
    match value {
        1 => "relocatable",
        2 => "executable",
        3 => "shared object",
        4 => "core dump",
        _ => "unknown",
    }
}

/// Human name for common `e_machine` values.
pub fn machine_name(value: u16) -> &'static str {
    match value {
        0 => "unspecified",
        3 => "Intel 80386 (x86)",
        8 => "MIPS",
        0x28 => "ARM",
        0x3E => "AMD x86-64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        _ => "other",
    }
}

/// OS/ABI name for the `EI_OSABI` byte.
pub fn osabi_name(value: u8) -> &'static str {
    match value {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "GNU/Linux",
        6 => "SunOS/Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "other",
    }
}

/// Section-type name for common `sh_type` values.
pub fn section_type_name(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        _ => "other",
    }
}

/// One section header's raw fields (width differences resolved by class).
#[derive(Debug, Clone, Copy)]
struct RawSection {
    name_off: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// Parse the ELF structure from `bytes` (the prefix that was read).
///
/// `Err` means "not an ELF we can parse at all" (bad magic or a header that
/// does not fit); partial availability is expressed inside [`ElfFile`].
pub fn parse(bytes: &[u8]) -> Result<ElfFile, String> {
    if bytes.len() < 16 || !bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Err("not an ELF file (magic mismatch)".to_string());
    }
    let class = bytes[EI_CLASS];
    if class != ELFCLASS32 && class != ELFCLASS64 {
        return Err(format!("unknown ELF class {class}"));
    }
    let data = bytes[EI_DATA];
    if data != 1 && data != ELFDATA2MSB {
        return Err(format!("unknown ELF data encoding {data}"));
    }
    let reader = Reader::with_endian(bytes, data == ELFDATA2MSB);
    let is64 = class == ELFCLASS64;

    // Fixed fields after e_ident: 32-bit at 16, 64-bit at 16 (same order,
    // different widths for entry/phoff/shoff).
    let (elf_type, machine, entry, phnum, shoff, shnum, shstrndx) = if is64 {
        let elf_type = reader.read_u16(16).ok_or("truncated ELF64 header")?;
        let machine = reader.read_u16(18).ok_or("truncated ELF64 header")?;
        let shoff = reader.read_u64(40).ok_or("truncated ELF64 header")? as usize;
        let phnum = reader.read_u16(56).ok_or("truncated ELF64 header")?;
        let shentsize = reader.read_u16(58).ok_or("truncated ELF64 header")?;
        let shnum = reader.read_u16(60).ok_or("truncated ELF64 header")?;
        let shstrndx = reader.read_u16(62).ok_or("truncated ELF64 header")?;
        if shentsize != 64 {
            return Err(format!("unexpected e_shentsize {shentsize} for ELF64"));
        }
        let entry = reader.read_u64(24).ok_or("truncated ELF64 header")?;
        (elf_type, machine, entry, phnum, shoff, shnum, shstrndx)
    } else {
        let elf_type = reader.read_u16(16).ok_or("truncated ELF32 header")?;
        let machine = reader.read_u16(18).ok_or("truncated ELF32 header")?;
        let entry = reader.read_u32(24).ok_or("truncated ELF32 header")? as u64;
        let shoff = reader.read_u32(32).ok_or("truncated ELF32 header")? as usize;
        let phnum = reader.read_u16(44).ok_or("truncated ELF32 header")?;
        let shentsize = reader.read_u16(46).ok_or("truncated ELF32 header")?;
        let shnum = reader.read_u16(48).ok_or("truncated ELF32 header")?;
        let shstrndx = reader.read_u16(50).ok_or("truncated ELF32 header")?;
        if shentsize != 40 {
            return Err(format!("unexpected e_shentsize {shentsize} for ELF32"));
        }
        (elf_type, machine, entry, phnum, shoff, shnum, shstrndx)
    };

    let mut file = ElfFile {
        class,
        big_endian: data == ELFDATA2MSB,
        os_abi: bytes[EI_OSABI],
        elf_type,
        machine,
        entry,
        phnum,
        sections: Vec::new(),
        sections_reason: None,
        section_total: shnum as usize,
        imports: Vec::new(),
        imports_reason: None,
    };

    // Section table. shoff == 0 means "no section table" (stripped or
    // core-dump style); that is a normal state, not an error.
    if shoff == 0 {
        file.sections_reason = Some("file has no section table (e_shoff is 0)".to_string());
        file.imports_reason = Some("no section table; .dynsym cannot be located".to_string());
        return Ok(file);
    }

    let entsize = if is64 { 64 } else { 40 };
    let table_len = shnum as usize;
    let read_sections = |count: usize| -> Option<Vec<RawSection>> {
        if count > MAX_SECTIONS {
            return None;
        }
        let end = shoff.checked_add(count.checked_mul(entsize)?)?;
        if end > bytes.len() {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let at = shoff + i * entsize;
            let raw = if is64 {
                RawSection {
                    name_off: reader.read_u32(at)?,
                    sh_type: reader.read_u32(at + 4)?,
                    offset: reader.read_u64(at + 24)?,
                    size: reader.read_u64(at + 32)?,
                    link: reader.read_u32(at + 40)?,
                    entsize: reader.read_u64(at + 56)?,
                }
            } else {
                RawSection {
                    name_off: reader.read_u32(at)?,
                    sh_type: reader.read_u32(at + 4)?,
                    offset: reader.read_u32(at + 16)? as u64,
                    size: reader.read_u32(at + 20)? as u64,
                    link: reader.read_u32(at + 24)?,
                    entsize: reader.read_u32(at + 36)? as u64,
                }
            };
            out.push(raw);
        }
        Some(out)
    };

    // Extended numbering: e_shnum == 0 with a table means the real count is
    // sh[0].sh_size; e_shstrndx == SHN_XINDEX means the real index is
    // sh[0].sh_link.
    let mut raw_sections = read_sections(table_len.max(1));
    if raw_sections.is_some() && table_len == 0 {
        let first = raw_sections.as_ref().and_then(|v| v.first()).copied();
        let real = first.map(|f| f.size as usize).unwrap_or(0);
        file.section_total = real;
        raw_sections = if real == 0 {
            None
        } else {
            read_sections(real)
        };
    }

    let Some(raw_sections) = raw_sections else {
        file.sections_reason = Some(format!(
            "section table at offset {shoff} ({} entries) lies beyond the {} bytes read",
            file.section_total,
            bytes.len()
        ));
        file.imports_reason = Some("section table unavailable; .dynsym cannot be located".into());
        return Ok(file);
    };
    if raw_sections.len() > MAX_SECTIONS || file.section_total > raw_sections.len() {
        file.sections_reason = Some(format!(
            "section table has {} entries; parsing stopped at {}",
            file.section_total,
            raw_sections.len()
        ));
    }

    // Section names come from the section-header string table.
    let shstrndx_resolved = if shstrndx == SHN_XINDEX {
        raw_sections.first().map(|f| f.link as usize)
    } else {
        Some(shstrndx as usize)
    };
    let name_reader = shstrndx_resolved.and_then(|idx| raw_sections.get(idx)).map(|sh| {
        (
            Reader::with_endian(
                reader.slice(sh.offset as usize, sh.size.min(MAX_NAME_BYTES as u64 * 64) as usize)
                    .unwrap_or(&[]),
                data == ELFDATA2MSB,
            ),
            sh.size,
        )
    });

    for raw in &raw_sections {
        let name = name_reader
            .as_ref()
            .and_then(|(r, _)| r.cstr(raw.name_off as usize, MAX_NAME_BYTES))
            .unwrap_or_default();
        file.sections.push(ElfSection {
            name,
            sh_type: raw.sh_type,
            size: raw.size,
            offset: raw.offset,
        });
    }

    // Imports: undefined symbols with names from every .dynsym section.
    let dynsym_indexes: Vec<usize> = raw_sections
        .iter()
        .enumerate()
        .filter(|(_, s)| s.sh_type == SHT_DYNSYM)
        .map(|(i, _)| i)
        .collect();
    if dynsym_indexes.is_empty() {
        file.imports_reason =
            Some("no .dynsym section (statically linked or stripped)".to_string());
        return Ok(file);
    }
    for dynsym_idx in dynsym_indexes {
        let sym = &raw_sections[dynsym_idx];
        let strtab = raw_sections
            .get(sym.link as usize)
            .ok_or("bad .dynsym sh_link (strtab index out of range)")?;
        let Some(str_bytes) =
            reader.slice(strtab.offset as usize, strtab.size.min(1 << 20) as usize)
        else {
            file.imports_reason =
                Some(".dynstr lies beyond the bytes read; imports unavailable".into());
            continue;
        };
        let str_reader = Reader::with_endian(str_bytes, data == ELFDATA2MSB);
        let entsize = if sym.entsize == 0 {
            if is64 { 24u64 } else { 16u64 }
        } else {
            sym.entsize
        };
        if entsize == 0 {
            continue;
        }
        let count = (sym.size / entsize).min(MAX_SYMBOLS as u64) as usize;
        let truncated_by_cap = sym.size / entsize > MAX_SYMBOLS as u64;
        for i in 0..count {
            let at = sym.offset as usize + i * entsize as usize;
            let (name_off, shndx) = if is64 {
                (
                    reader.read_u32(at).unwrap_or(0),
                    reader.read_u16(at + 6).unwrap_or(1),
                )
            } else {
                (
                    reader.read_u32(at).unwrap_or(0),
                    reader.read_u16(at + 14).unwrap_or(1),
                )
            };
            if shndx != SHN_UNDEF || name_off == 0 {
                continue;
            }
            if let Some(name) = str_reader.cstr(name_off as usize, MAX_NAME_BYTES) {
                if !name.is_empty() {
                    file.imports.push(name);
                }
            }
        }
        if truncated_by_cap {
            file.imports_reason = Some(format!(
                ".dynsym has more than {MAX_SYMBOLS} entries; enumeration stopped there"
            ));
        }
    }
    if file.imports.is_empty() && file.imports_reason.is_none() {
        file.imports_reason =
            Some("no undefined dynamic symbols with names found".to_string());
    }
    Ok(file)
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
    fn elf64_fixture_parses_header_sections_and_imports() {
        let file = parse(&fixture("elf64-demo")).expect("parses");
        assert_eq!(file.class, 2);
        assert!(!file.big_endian);
        assert_eq!(file.elf_type, 2);
        assert_eq!(elf_type_name(file.elf_type), "executable");
        assert_eq!(file.machine, 0x3E);
        assert_eq!(machine_name(file.machine), "AMD x86-64");
        assert_eq!(file.entry, 0x1000);
        assert_eq!(file.section_total, 5);
        let names: Vec<&str> = file.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["", ".text", ".dynsym", ".dynstr", ".shstrtab"]
        );
        assert!(file.sections_reason.is_none());
        assert_eq!(file.imports, vec!["puts", "malloc"]);
    }

    #[test]
    fn elf32_fixture_parses() {
        let file = parse(&fixture("elf32-demo")).expect("parses");
        assert_eq!(file.class, 1);
        assert_eq!(file.elf_type, 3);
        assert_eq!(elf_type_name(file.elf_type), "shared object");
        assert_eq!(machine_name(file.machine), "Intel 80386 (x86)");
        assert_eq!(file.imports, vec!["printf"]);
        let dynsym = file.sections.iter().find(|s| s.name == ".dynsym").unwrap();
        assert_eq!(section_type_name(dynsym.sh_type), "DYNSYM");
    }

    #[test]
    fn truncated_header_is_an_error() {
        let full = fixture("elf64-demo");
        let err = parse(&full[..40]).unwrap_err();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn bad_magic_is_an_error() {
        let mut bytes = vec![0x7f, b'E', b'L', b'G', 2, 1, 1, 0];
        bytes.resize(72, 0);
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn section_table_beyond_read_prefix_is_reported_not_guessed() {
        let full = fixture("elf64-demo");
        // Cut just before the section table (shoff = 192 for this fixture).
        let cut = parse(&full[..188]).expect("header still parses");
        assert!(cut.sections.is_empty());
        assert!(cut
            .sections_reason
            .as_deref()
            .unwrap()
            .contains("beyond"));
        assert!(cut.imports.is_empty());
        assert!(cut.imports_reason.is_some());
    }

    #[test]
    fn big_endian_header_is_recognized() {
        // Minimal ELF32 BE header: magic, class 1, data 2, then fields at
        // their fixed offsets. No section table.
        let mut bytes = vec![0u8; 52];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[EI_CLASS] = 1;
        bytes[EI_DATA] = ELFDATA2MSB;
        bytes[EI_OSABI] = 0;
        // e_type = 2 (EXEC) big-endian at 16.
        bytes[16..18].copy_from_slice(&0x0002u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&0x0003u16.to_be_bytes()); // e_machine i386
        // e_shentsize 40 at 46, everything else zero (no table, no phdrs).
        bytes[46..48].copy_from_slice(&40u16.to_be_bytes());
        let file = parse(&bytes).expect("parses");
        assert!(file.big_endian);
        assert_eq!(file.elf_type, 2);
        assert_eq!(file.machine, 3);
        assert!(file
            .sections_reason
            .as_deref()
            .unwrap()
            .contains("no section table"));
    }

    #[test]
    fn lying_section_count_is_rejected_by_bounds() {
        let mut full = fixture("elf64-demo");
        // Claim 4096 sections while the file holds 5.
        full[60..62].copy_from_slice(&4096u16.to_le_bytes());
        let file = parse(&full).expect("header parses");
        assert!(file.sections.is_empty());
        assert!(file.sections_reason.is_some());
    }
}
