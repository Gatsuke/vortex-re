//! Ed25519 signing for tamper-evident evidence exports.
//!
//! Design notes:
//! * the keypair is generated on first use of `--signed`, stored under
//!   `<data_dir>/keys/` with owner-only permissions, and announced by the
//!   doctor — never silently;
//! * the private half never leaves the machine; the public half is written
//!   next to it so exports can be verified by third parties;
//! * signatures are deterministic (Ed25519), so re-signing identical bytes
//!   produces identical signatures — no hidden state.

use ed25519_dalek::Signer;
use std::path::{Path, PathBuf};

/// Errors from the signing module.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// The key directory could not be created or used.
    #[error("key directory {0} is unusable: {1}")]
    UnusableDir(PathBuf, String),
    /// The stored key could not be read or parsed.
    #[error("signing key at {0} is unreadable: {1}")]
    UnreadableKey(PathBuf, String),
    /// Key material has the wrong length.
    #[error("signing key at {0} is malformed: expected 32 bytes of hex, got {1} bytes")]
    MalformedKey(PathBuf, usize),
    /// A public key could not be parsed.
    #[error("public key '{0}' is malformed")]
    MalformedPublicKey(String),
    /// The signature does not verify against the given public key.
    #[error("signature does not verify against this public key")]
    VerificationFailed,
    /// Writing a file failed.
    #[error("cannot write {0}: {1}")]
    WriteFailed(PathBuf, String),
}

/// File name of the private half inside the keys directory.
pub const PRIVATE_KEY_FILE: &str = "signing.key";

/// File name of the public half inside the keys directory.
pub const PUBLIC_KEY_FILE: &str = "signing.pub";

/// An Ed25519 keypair for signing exports.
pub struct SigningKeypair {
    signing: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private half; the public half is shareable.
        f.debug_struct("SigningKeypair")
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl SigningKeypair {
    /// Load the keypair from `keys_dir`, generating and persisting a fresh
    /// one (announced by the returned `generated` flag) when absent.
    pub fn load_or_generate(keys_dir: &Path) -> Result<(Self, bool), SigningError> {
        std::fs::create_dir_all(keys_dir)
            .map_err(|err| SigningError::UnusableDir(keys_dir.to_path_buf(), err.to_string()))?;
        let private_path = keys_dir.join(PRIVATE_KEY_FILE);
        let public_path = keys_dir.join(PUBLIC_KEY_FILE);

        if private_path.exists() {
            let hex = std::fs::read_to_string(&private_path).map_err(|err| {
                SigningError::UnreadableKey(private_path.clone(), err.to_string())
            })?;
            let hex = hex.trim();
            let bytes: [u8; 32] = decode_hex(hex)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| SigningError::MalformedKey(private_path.clone(), hex.len() / 2))?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&bytes);
            let pair = Self { signing };
            // Refresh the public half if it is missing (recoverable state).
            if !public_path.exists() {
                pair.write_public(&public_path)?;
            }
            Ok((pair, false))
        } else {
            // Fresh key from the OS RNG.
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|err| {
                SigningError::UnusableDir(keys_dir.to_path_buf(), err.to_string())
            })?;
            let pair = Self {
                signing: ed25519_dalek::SigningKey::from_bytes(&seed),
            };
            pair.write_private(&private_path)?;
            pair.write_public(&public_path)?;
            Ok((pair, true))
        }
    }

    fn write_private(&self, path: &Path) -> Result<(), SigningError> {
        use std::io::Write;
        let mut bytes = self.signing.to_bytes();
        let hex = encode_hex(&bytes);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| SigningError::WriteFailed(path.to_path_buf(), err.to_string()))?;
        file.write_all(hex.as_bytes())
            .and_then(|_| file.flush())
            .map_err(|err| SigningError::WriteFailed(path.to_path_buf(), err.to_string()))?;
        // Owner-only, per the threat model.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)
                .map_err(|err| SigningError::WriteFailed(path.to_path_buf(), err.to_string()))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)
                .map_err(|err| SigningError::WriteFailed(path.to_path_buf(), err.to_string()))?;
        }
        bytes.fill(0);
        Ok(())
    }

    fn write_public(&self, path: &Path) -> Result<(), SigningError> {
        std::fs::write(path, self.public_key_hex())
            .map_err(|err| SigningError::WriteFailed(path.to_path_buf(), err.to_string()))?;
        Ok(())
    }

    /// The shareable public half as lower-case hex.
    pub fn public_key_hex(&self) -> String {
        encode_hex(self.signing.verifying_key().as_bytes())
    }

    /// Sign a message, returning the raw 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Verify a signature with an explicit public key (hex) — usable without
/// the private key, e.g. by a pipeline or a third party.
pub fn verify(
    public_key_hex: &str,
    signature: &[u8; 64],
    message: &[u8],
) -> Result<(), SigningError> {
    use ed25519_dalek::Verifier;
    let public: [u8; 32] = decode_hex(public_key_hex.trim())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| SigningError::MalformedPublicKey(public_key_hex.to_string()))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public)
        .map_err(|_| SigningError::MalformedPublicKey(public_key_hex.to_string()))?;
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    verifying
        .verify(message, &signature)
        .map_err(|_| SigningError::VerificationFailed)
        .map(|_| ())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode a hex string into bytes; `None` on non-hex input.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for pair in chars.chunks(2) {
        let high = pair[0].to_digit(16)?;
        let low = pair[1].to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (pair, generated) = SigningKeypair::load_or_generate(dir.path()).expect("keypair");
        assert!(generated, "first load generates");
        let public = pair.public_key_hex();
        assert_eq!(public.len(), 64);
        assert!(!public.contains(|c: char| !c.is_ascii_hexdigit()));

        let message = b"the exported evidence bytes";
        let signature = pair.sign(message);
        assert!(
            verify(&public, &signature, message).is_ok(),
            "signature verifies"
        );
        verify(&public, &signature, b"tampered").expect_err("must not verify");
        let mut bad = signature;
        bad[0] ^= 0x01;
        verify(&public, &bad, message).expect_err("broken signature must fail");

        // Reload is stable (no regeneration, same public key).
        let (again, regenerated) = SigningKeypair::load_or_generate(dir.path()).expect("reload");
        assert!(!regenerated);
        assert_eq!(again.public_key_hex(), public);
        let same_again = again.sign(message);
        assert_eq!(same_again.to_vec(), signature.to_vec(), "deterministic");
    }

    #[test]
    fn private_key_permissions_are_owner_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (_pair, _) = SigningKeypair::load_or_generate(dir.path()).expect("keypair");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(PRIVATE_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "owner-only private key");
        }
    }

    #[test]
    fn tampered_public_key_is_rejected() {
        let err = verify("zzzz", &[0u8; 64], b"msg").expect_err("non-hex key");
        assert!(matches!(err, SigningError::MalformedPublicKey(_)));
    }
}
