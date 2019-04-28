use crate::constants::*;
use crate::errors::*;
use crate::signature::*;
use std::fmt::Write as fmtWrite;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone)]
pub struct SignatureBox {
    pub(crate) untrusted_comment: String,
    pub(crate) signature: Signature,
    pub(crate) sig_and_trusted_comment: Vec<u8>,
    pub(crate) global_sig: Vec<u8>,
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
    pub fn is_prehashed(&self) -> bool {
        self.is_prehashed
    }

    pub fn untrusted_comment(&self) -> Result<String> {
        Ok(self.untrusted_comment.clone())
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
        let untrusted_comment = untrusted_comment[COMMENT_PREFIX.len()..].to_string();
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
        let is_prehashed = match signature.sig_alg {
            SIGALG => false,
            SIGALG_PREHASHED => true,
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
            untrusted_comment,
            signature,
            sig_and_trusted_comment,
            global_sig,
            is_prehashed,
        })
    }

    pub fn to_string(&self) -> String {
        let mut signature_box = String::new();
        writeln!(signature_box, "{}", self.untrusted_comment).unwrap();
        writeln!(signature_box, "{}", self.signature.to_string()).unwrap();
        writeln!(
            signature_box,
            "{}{}",
            TRUSTED_COMMENT_PREFIX,
            self.trusted_comment().unwrap()
        )
        .unwrap();
        writeln!(signature_box, "{}", base64::encode(&self.global_sig[..])).unwrap();
        signature_box
    }

    pub fn into_string(self) -> String {
        self.to_string()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.to_string().as_bytes().to_vec()
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
