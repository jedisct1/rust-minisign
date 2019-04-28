use crate::constants::*;
use crate::errors::*;
use crate::signature::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone)]
pub struct SignatureBox {
    pub(crate) global_sig: Vec<u8>,
    pub(crate) sig_and_trusted_comment: Vec<u8>,
    pub(crate) signature: Signature,
    is_hashed: bool,
}

impl SignatureBox {
    pub fn is_hashed(&self) -> bool {
        self.is_hashed
    }

    pub fn trusted_comment(&self) -> Result<String> {
        if self.sig_and_trusted_comment.len() < SIGNATURE_BYTES {
            Err(PError::new(
                ErrorKind::Encoding,
                "invalid trusted comment encoding",
            ))?
        }
        let just_comment =
            String::from_utf8(self.sig_and_trusted_comment[SIGNATURE_BYTES..].to_vec())?;
        Ok(just_comment)
    }

    pub fn from_string(s: &str) -> Result<SignatureBox> {
        let mut lines = s.lines();
        let untrusted_comment = lines
            .next()
            .ok_or_else(|| PError::new(ErrorKind::Io, "Missing untrusted comment"))?
            .to_string();
        let signatureing = lines
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
        let sig_bytes = base64::decode(signatureing.trim().as_bytes())
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
        let is_hashed = match signature.sig_alg {
            SIGALG => false,
            SIGALG_HASHED => true,
            _ => Err(PError::new(
                ErrorKind::Verify,
                "Unsupported signature algorithm".to_string(),
            ))?,
        };
        let _ = trusted_comment_str
            .drain(..TRUSTED_COMMENT_PREFIX_LEN)
            .count();
        let mut sig_and_trusted_comment = signature.sig.to_vec();
        sig_and_trusted_comment.extend_from_slice(trusted_comment_str.trim().as_bytes());
        let global_sig = base64::decode(global_sig.trim().as_bytes())
            .map_err(|e| PError::new(ErrorKind::Io, e))?;
        Ok(SignatureBox {
            global_sig,
            sig_and_trusted_comment,
            signature,
            is_hashed,
        })
    }

    pub fn from_file<P>(sig_path: P) -> Result<SignatureBox>
    where
        P: AsRef<Path>,
    {
        let sig_path = sig_path.as_ref();
        let mut file = File::open(sig_path)
            .map_err(|e| PError::new(ErrorKind::Io, format!("{} {}", e, sig_path.display())))?;
        let mut s = String::new();
        file.read_to_string(&mut s)?;
        SignatureBox::from_string(&s)
    }
}
