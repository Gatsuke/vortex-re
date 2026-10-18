//! SHA-256 digests for artifacts.
//!
//! File digests are streamed so large artifacts never need to fit in memory.
//! Directory digests hash an ordered manifest of `(relative path, file digest)`
//! pairs, which keeps them deterministic across filesystems.

use crate::error::{ErrorCode, VortexError, VortexResult};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Hash arbitrary bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

/// Stream a reader through SHA-256, reading in bounded chunks.
pub fn sha256_reader(reader: &mut dyn Read) -> VortexResult<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(to_hex(&hasher.finalize()))
}

/// Hash a file on disk by streaming its contents.
pub fn sha256_file(path: &Path) -> VortexResult<String> {
    let file = std::fs::File::open(path).map_err(|err| {
        VortexError::new(
            ErrorCode::Io,
            format!("cannot open {}: {err}", path.display()),
        )
    })?;
    let mut reader = std::io::BufReader::new(file);
    sha256_reader(&mut reader)
}

/// Deterministic digest over a directory manifest.
///
/// The manifest is the sorted concatenation of `"{relative_path}\0{sha256}\n"`
/// for every regular file. Symlinks and special files are never included;
/// callers must report them separately so the digest's scope is clear.
pub fn directory_manifest_digest(entries: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (path, digest) in sorted {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vectors() {
        // Standard NIST/SHA-256 test vectors.
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn file_hash_matches_bytes_hash() {
        let dir = std::env::temp_dir().join(format!("vortex-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("sample.txt");
        std::fs::write(&file, b"hello vortex").expect("write sample");
        assert_eq!(sha256_file(&file).unwrap(), sha256_bytes(b"hello vortex"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_digest_is_order_independent_and_deterministic() {
        let a = vec![
            ("src/a.js".to_string(), "aa".to_string()),
            ("src/b.js".to_string(), "bb".to_string()),
        ];
        let b = vec![
            ("src/b.js".to_string(), "bb".to_string()),
            ("src/a.js".to_string(), "aa".to_string()),
        ];
        assert_eq!(directory_manifest_digest(&a), directory_manifest_digest(&b));
        assert_ne!(
            directory_manifest_digest(&a),
            directory_manifest_digest(&[a[0].clone()])
        );
    }
}
