use crate::base64::{Base64, Decoder, Encoder};
use crate::constants::*;
use crate::crypto::util::fixed_time_eq;
use crate::errors::*;
use crate::helpers::*;
use crate::keynum::*;
use std::cmp;
use std::fmt::Write as fmtWrite;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

/// A public key and its metadata.
///
/// A `PublicKeyBox` represents a raw public key, along with a key
/// identifier and an untrusted description.
///
/// This is what usually gets exported to disk.
///
/// A `PublicKeyBox` can be directly converted to/from a single-line string.
#[derive(Clone, Debug)]
pub struct PublicKeyBox(String);

impl Into<String> for PublicKeyBox {
    fn into(self) -> String {
        self.0
    }
}

impl Into<PublicKeyBox> for String {
    fn into(self) -> PublicKeyBox {
        PublicKeyBox(self)
    }
}

impl ToString for PublicKeyBox {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl Into<PublicKey> for PublicKeyBox {
    fn into(self) -> PublicKey {
        self.into_public_key().unwrap()
    }
}

impl PublicKeyBox {
    /// Create a new `PublicKeyBox` from a string.
    pub fn from_string(s: &str) -> Result<PublicKeyBox> {
        Ok(s.to_string().into())
    }

    /// Return a `PublicKeyBox` for a string, for storage.
    pub fn into_string(self) -> String {
        self.into()
    }

    /// Convert a `PublicKeyBox` to a string, for storage.
    pub fn into_public_key(self) -> Result<PublicKey> {
        PublicKey::from_box(self)
    }

    /// Return a byte representation of the public key, for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_string().as_bytes().to_vec()
    }
}

/// A `PublicKey` is used to verify signatures.
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) sig_alg: [u8; TWOBYTES],
    pub(crate) keynum_pk: KeynumPK,
}

impl PublicKey {
    /// The key identifier of this public key.
    pub fn keynum(&self) -> &[u8] {
        &self.keynum_pk.keynum[..]
    }

    /// Deserialize a `PublicKey`.
    ///
    /// For storage, a `PublicKeyBox` is usually what you need instead.
    pub fn from_bytes(buf: &[u8]) -> Result<PublicKey> {
        let mut buf = Cursor::new(buf);
        let mut sig_alg = [0u8; TWOBYTES];
        let mut keynum = [0u8; KEYNUM_BYTES];
        let mut pk = [0u8; PUBLICKEY_BYTES];
        buf.read_exact(&mut sig_alg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut pk)?;
        Ok(PublicKey {
            sig_alg,
            keynum_pk: KeynumPK { keynum, pk },
        })
    }

    /// Serialize a `PublicKey`.
    ///
    /// For storage, a `PublicKeyBox` is usually what you want to use instead.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut iters = Vec::new();
        iters.push(self.sig_alg.iter());
        iters.push(self.keynum_pk.keynum.iter());
        iters.push(self.keynum_pk.pk.iter());
        let v: Vec<u8> = iters
            .iter()
            .flat_map(|b| {
                let b = b.clone();
                b.cloned()
            })
            .collect();
        v
    }

    /// Convert a `PublicKeyBox` to a `PublicKey`.
    pub fn from_box(pk_box: PublicKeyBox) -> Result<PublicKey> {
        let s = pk_box.0;
        let mut lines = s.lines();
        lines.next().ok_or_else(|| {
            PError::new(ErrorKind::Io, "Missing comment in public key".to_string())
        })?;
        let encoded_pk = lines.next().ok_or_else(|| {
            PError::new(
                ErrorKind::Io,
                "Missing encoded key in public key".to_string(),
            )
        })?;
        if encoded_pk.len() != PK_B64_ENCODED_LEN {
            return Err(PError::new(
                ErrorKind::Io,
                "Base64 conversion failed - was an actual public key given?".to_string(),
            ));
        }
        let decoded_buf = Base64::decode_to_vec(encoded_pk.trim()).map_err(|e| {
            PError::new(
                ErrorKind::Io,
                format!(
                    "Base64 conversion failed - was an actual public key given?: {}",
                    e
                ),
            )
        })?;
        Ok(PublicKey::from_bytes(&decoded_buf)?)
    }

    /// Convert a `PublicKey` to a `PublicKeyBox`.
    pub fn to_box(&self) -> Result<PublicKeyBox> {
        let mut s = String::new();
        write!(s, "{}minisign public key: ", COMMENT_PREFIX)?;
        writeln!(s, "{:X}", load_u64_le(&self.keynum_pk.keynum[..]))?;
        writeln!(s, "{}", self.to_base64())?;
        Ok(s.into())
    }

    /// Create a minimal public key from a base64-encoded string.
    pub fn from_base64(pk_string: &str) -> Result<PublicKey> {
        let encoded_string = pk_string.to_string();
        if encoded_string.trim().len() != PK_B64_ENCODED_LEN {
            return Err(PError::new(
                ErrorKind::Io,
                "base64 conversion failed - was an actual public key given?".to_string(),
            ));
        }
        let decoded_string = Base64::decode_to_vec(encoded_string.as_bytes()).map_err(|e| {
            PError::new(
                ErrorKind::Io,
                format!(
                    "base64 conversion failed - was an actual public key given?: {}",
                    e
                ),
            )
        })?;
        PublicKey::from_bytes(&decoded_string)
    }

    /// Encode a public key as a base64-encoded string.
    pub fn to_base64(&self) -> String {
        Base64::encode_to_string(self.to_bytes().as_slice()).unwrap()
    }

    /// Load a `PublicKeyBox` from a file, and returns a `PublicKey` from it.
    pub fn from_file<P>(pk_path: P) -> Result<PublicKey>
    where
        P: AsRef<Path>,
    {
        let s = fs::read_to_string(pk_path)?;
        PublicKey::from_box(s.into())
    }
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        fixed_time_eq(&self.keynum_pk.pk, &other.keynum_pk.pk)
    }
}

impl cmp::Eq for PublicKey {}
