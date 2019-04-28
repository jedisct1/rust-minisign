use crate::constants::*;
use crate::errors::*;
use crate::signature::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Clone)]
pub struct SignatureBox {
    pub(crate) global_sig: Vec<u8>,
    pub trusted_comment: Vec<u8>,
    pub(crate) signature: Signature,
    pub hashed: bool,
}

impl SignatureBox {
    pub fn from_file<P>(sig_path: P) -> Result<SignatureBox>
    where
        P: AsRef<Path>,
    {
        let sig_path = sig_path.as_ref();
        let file = File::open(sig_path)
            .map_err(|e| PError::new(ErrorKind::Io, format!("{} {}", e, sig_path.display())))?;

        let mut buf = BufReader::new(file);
        let mut untrusted_comment = String::with_capacity(COMMENTBYTES);
        buf.read_line(&mut untrusted_comment)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        let mut signatureing = String::with_capacity(Signature::len());
        buf.read_line(&mut signatureing)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
        buf.read_line(&mut t_comment)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        let mut g_sig = String::with_capacity(SIGNATUREBYTES);
        buf.read_line(&mut g_sig)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        if !untrusted_comment.starts_with(COMMENT_PREFIX) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!("Untrusted comment must start with: {}", COMMENT_PREFIX),
            ));
        }

        let sig_bytes = base64::decode(signatureing.trim().as_bytes())
            .map_err(|e| PError::new(ErrorKind::Io, e))?;
        let signature = Signature::from_bytes(&sig_bytes)?;
        if !t_comment.starts_with(TRUSTED_COMMENT_PREFIX) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!(
                    "trusted comment should start with: {}",
                    TRUSTED_COMMENT_PREFIX
                ),
            ));
        }
        let hashed = match signature.sig_alg {
            SIGALG => false,
            SIGALG_HASHED => true,
            _ => Err(PError::new(
                ErrorKind::Verify,
                "Unsupported signature algorithm".to_string(),
            ))?,
        };
        let _ = t_comment.drain(..TR_COMMENT_PREFIX_LEN).count();
        let mut trusted_comment = signature.sig.to_vec();
        trusted_comment.extend_from_slice(t_comment.trim().as_bytes());
        let global_sig =
            base64::decode(g_sig.trim().as_bytes()).map_err(|e| PError::new(ErrorKind::Io, e))?;
        Ok(SignatureBox {
            global_sig,
            trusted_comment,
            signature,
            hashed,
        })
    }
}
