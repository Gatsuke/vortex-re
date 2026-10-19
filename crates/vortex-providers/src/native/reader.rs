//! Bounds-checked little/big-endian reader over a byte slice, shared by the
//! native-format parsers. Kept deliberately small: every accessor returns
//! `Option` and every caller must handle `None` honestly.

#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    pub bytes: &'a [u8],
    pub big_endian: bool,
}

impl<'a> Reader<'a> {
    /// A reader with explicit endianness (ELF EI_DATA).
    pub(crate) fn with_endian(bytes: &'a [u8], big_endian: bool) -> Self {
        Self { bytes, big_endian }
    }

    /// (Used by the DEX reader; kept on the shared reader so every parser
    /// reads bytes through the same bounds-checked path.)
    #[allow(dead_code)]
    pub(crate) fn read_u8(&self, at: usize) -> Option<u8> {
        self.bytes.get(at).copied()
    }

    pub(crate) fn read_u16(&self, at: usize) -> Option<u16> {
        let b = self.bytes.get(at..at.checked_add(2)?)?;
        if self.big_endian {
            Some(u16::from_be_bytes([b[0], b[1]]))
        } else {
            Some(u16::from_le_bytes([b[0], b[1]]))
        }
    }

    pub(crate) fn read_u32(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
        if self.big_endian {
            Some(u32::from_be_bytes(b))
        } else {
            Some(u32::from_le_bytes(b))
        }
    }

    pub(crate) fn read_u64(&self, at: usize) -> Option<u64> {
        let b: [u8; 8] = self.bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
        if self.big_endian {
            Some(u64::from_be_bytes(b))
        } else {
            Some(u64::from_le_bytes(b))
        }
    }

    /// A NUL-terminated string starting at `at`, bounded to `max_len` bytes.
    /// Returns `None` when `at` is outside the buffer; the (possibly empty)
    /// string otherwise. Invalid UTF-8 is replaced lossily and the caller is
    /// expected to say so when the name matters.
    pub(crate) fn cstr(&self, at: usize, max_len: usize) -> Option<String> {
        let window = self.bytes.get(at..)?;
        let end = window.iter().position(|b| *b == 0).unwrap_or(window.len());
        let taken = end.min(max_len);
        Some(String::from_utf8_lossy(&window[..taken]).into_owned())
    }

    /// Raw bytes at `at..at+len` when they are fully present.
    pub(crate) fn slice(&self, at: usize, len: usize) -> Option<&'a [u8]> {
        self.bytes.get(at..at.checked_add(len)?)
    }
}

/// Fixed cap on name lengths read out of string tables (bytes).
pub(crate) const MAX_NAME_BYTES: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_respects_bounds_and_endianness() {
        let le = Reader::with_endian(&[0x34, 0x12, 0x78, 0x56, 0x00, 0xef], false);
        assert_eq!(le.read_u16(0), Some(0x1234));
        assert_eq!(le.read_u32(0), Some(0x56781234));
        assert_eq!(le.read_u16(2), Some(0x5678));
        assert_eq!(le.read_u16(5), None);
        assert_eq!(le.read_u32(3), None);

        let be = Reader::with_endian(&[0x12, 0x34], true);
        assert_eq!(be.read_u16(0), Some(0x1234));
    }

    #[test]
    fn cstr_is_bounded_and_lossy() {
        let r = Reader::with_endian(b"hello\0world\xff\xfe", false);
        assert_eq!(r.cstr(0, MAX_NAME_BYTES).as_deref(), Some("hello"));
        assert_eq!(
            r.cstr(6, MAX_NAME_BYTES).as_deref(),
            Some("world\u{fffd}\u{fffd}")
        );
        assert_eq!(r.cstr(0, 3).as_deref(), Some("hel"));
        assert_eq!(r.cstr(20, MAX_NAME_BYTES), None);
    }
}
