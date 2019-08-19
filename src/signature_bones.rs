use crate::constants::*;
use crate::errors::*;
use crate::signature::*;
use crate::signature_box::*;

/// A trimmed-down signature, without any comments section, with binary serialization only
#[derive(Clone)]
pub struct SignatureBones {
    pub(crate) signature: Signature,
    pub(crate) is_prehashed: bool,
}

impl SignatureBones {
    /// Returns `true` if the signed data was pre-hashed.
    pub fn is_prehashed(&self) -> bool {
        self.is_prehashed
    }

    /// Create a new `SignatureBones` from a &[u8].
    pub fn from_bytes(bytes: &[u8]) -> Result<SignatureBones> {
        let signature = Signature::from_bytes(&bytes)?;
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
        Ok(SignatureBones {
            signature,
            is_prehashed,
        })
    }

    /// Return a `SignatureBones` as bytes, for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature.to_bytes()
    }

    /// Size of a minimal signature in bytes
    pub const BYTES: usize = Signature::BYTES;
}

impl Into<SignatureBox> for SignatureBones {
    fn into(self) -> SignatureBox {
        let is_prehashed = self.is_prehashed();
        SignatureBox {
            untrusted_comment: String::new(),
            signature: self.signature,
            sig_and_trusted_comment: None,
            global_sig: None,
            is_prehashed,
        }
    }
}

impl Into<SignatureBones> for SignatureBox {
    fn into(self) -> SignatureBones {
        let is_prehashed = self.is_prehashed();
        SignatureBones {
            signature: self.signature,
            is_prehashed,
        }
    }
}
