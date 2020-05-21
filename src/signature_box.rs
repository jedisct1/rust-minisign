use crate::base64::{Base64, Decoder, Encoder};
use crate::constants::*;
use crate::errors::*;
use crate::signature::*;
use std::fmt::Write as fmtWrite;
use std::fs;
use std::path::Path;

/// A signature, as well as the metadata required to verify it.
#[derive(Clone)]
pub struct SignatureBox {
    pub(crate) untrusted_comment: String,
    pub(crate) signature: Signature,
    pub(crate) sig_and_trusted_comment: Option<Vec<u8>>,
    pub(crate) global_sig: Option<Vec<u8>>,
    pub(crate) is_prehashed: bool,
}

impl Into<String> for SignatureBox {
    fn into(self) -> String {
        self.into_string()
    }
}

impl Into<SignatureBox> for String {
    fn into(self) -> SignatureBox {
        SignatureBox::from_string(&self).unwrap()
    }
}

impl SignatureBox {
    /// Returns `true` if the signed data was pre-hashed.
    pub fn is_prehashed(&self) -> bool {
        self.is_prehashed
    }

    /// The untrusted comment present in the signature.
    pub fn untrusted_comment(&self) -> Result<String> {
        Ok(self.untrusted_comment.clone())
    }

    /// The trusted comment present in the signature.
    pub fn trusted_comment(&self) -> Result<String> {
        let sig_and_trusted_comment = match &self.sig_and_trusted_comment {
            None => {
                return Err(PError::new(
                    ErrorKind::Misc,
                    "trusted comment is not present",
                ))
            }
            Some(sig_and_trusted_comment) => sig_and_trusted_comment,
        };
        if sig_and_trusted_comment.len() < SIGNATURE_BYTES {
            return Err(PError::new(
                ErrorKind::Encoding,
                "invalid trusted comment encoding",
            ));
        }
        let just_comment = String::from_utf8(sig_and_trusted_comment[SIGNATURE_BYTES..].to_vec())?;
        Ok(just_comment)
    }

    /// The key identifier used to create the signature.
    pub fn keynum(&self) -> &[u8] {
        &self.signature.keynum[..]
    }

    /// Create a new `SignatureBox` from a string.
    pub fn from_string(s: &str) -> Result<SignatureBox> {
        let mut lines = s.lines();
        let untrusted_comment = lines
            .next()
            .ok_or_else(|| PError::new(ErrorKind::Io, "Missing untrusted comment"))?
            .to_string();
        let signature_str = lines
            .next()
            .ok_or_else(|| PError::new(ErrorKind::Io, "Missing signature"))?
            .to_string();
        let mut trusted_comment_str = lines
            .next()
            .ok_or_else(|| PError::new(ErrorKind::Io, "Missing trusted comment"))?
            .to_string();
        let global_sig = lines
            .next()
            .ok_or_else(|| PError::new(ErrorKind::Io, "Missing global signature"))?
            .to_string();
        if !untrusted_comment.starts_with(COMMENT_PREFIX) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!("Untrusted comment must start with: {}", COMMENT_PREFIX),
            ));
        }
        let untrusted_comment = untrusted_comment[COMMENT_PREFIX.len()..].to_string();
        let sig_bytes = Base64::decode_to_vec(signature_str.trim().as_bytes())
            .map_err(|e| PError::new(ErrorKind::Io, e))?;
        let signature = Signature::from_bytes(&sig_bytes)?;
        if !trusted_comment_str.starts_with(TRUSTED_COMMENT_PREFIX) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!(
                    "Trusted comment should start with: {}",
                    TRUSTED_COMMENT_PREFIX
                ),
            ));
        }
        let is_prehashed = match signature.sig_alg {
            SIGALG => false,
            SIGALG_PREHASHED => true,
            _ => {
                return Err(PError::new(
                    ErrorKind::Verify,
                    "Unsupported signature algorithm".to_string(),
                ))
            }
        };
        let _ = trusted_comment_str
            .drain(..TRUSTED_COMMENT_PREFIX_LEN)
            .count();
        let mut sig_and_trusted_comment = signature.sig.to_vec();
        sig_and_trusted_comment.extend_from_slice(trusted_comment_str.trim().as_bytes());
        let global_sig = Base64::decode_to_vec(global_sig.trim().as_bytes())
            .map_err(|e| PError::new(ErrorKind::Io, e))?;
        Ok(SignatureBox {
            untrusted_comment,
            signature,
            sig_and_trusted_comment: Some(sig_and_trusted_comment),
            global_sig: Some(global_sig),
            is_prehashed,
        })
    }

    /// Return a `SignatureBox` for a string, for storage.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let mut signature_box = String::new();
        writeln!(
            signature_box,
            "{}{}",
            COMMENT_PREFIX, self.untrusted_comment
        )
        .unwrap();
        writeln!(signature_box, "{}", self.signature.to_string()).unwrap();
        writeln!(
            signature_box,
            "{}{}",
            TRUSTED_COMMENT_PREFIX,
            self.trusted_comment()
                .expect("Incomplete SignatureBox: trusted comment is missing")
        )
        .unwrap();
        let global_sig = self
            .global_sig
            .as_ref()
            .expect("Incomplete SignatureBox: global signature is missing");
        writeln!(
            signature_box,
            "{}",
            Base64::encode_to_string(&global_sig[..]).unwrap()
        )
        .unwrap();
        signature_box
    }

    /// Convert a `SignatureBox` to a string, for storage.
    pub fn into_string(self) -> String {
        self.to_string()
    }

    /// Return a byte representation of the signature, for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_string().as_bytes().to_vec()
    }

    /// Load a `SignatureBox` from a file.
    pub fn from_file<P>(sig_path: P) -> Result<SignatureBox>
    where
        P: AsRef<Path>,
    {
        let s = fs::read_to_string(sig_path)?;
        SignatureBox::from_string(&s)
    }
}
