use crate::constants::*;
use crate::Result;
use std::io::{Cursor, Read};

#[derive(Clone)]
pub(crate) struct Signature {
    pub sig_alg: [u8; TWOBYTES],
    pub keynum: [u8; KEYNUM_BYTES],
    pub sig: [u8; SIGNATURE_BYTES],
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut iters = Vec::new();
        iters.push(self.sig_alg.iter());
        iters.push(self.keynum.iter());
        iters.push(self.sig.iter());
        let v: Vec<u8> = iters
            .iter()
            .flat_map(|b| {
                let b = b.clone();
                b.cloned()
            })
            .collect();
        v
    }

    pub fn from_bytes(bytes_buf: &[u8]) -> Result<Signature> {
        let mut buf = Cursor::new(bytes_buf);
        let mut sig_alg = [0u8; 2];
        let mut keynum = [0u8; KEYNUM_BYTES];
        let mut sig = [0u8; SIGNATURE_BYTES];
        buf.read_exact(&mut sig_alg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut sig)?;
        Ok(Signature {
            sig_alg,
            keynum,
            sig,
        })
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            sig_alg: [0u8; TWOBYTES],
            keynum: [0u8; KEYNUM_BYTES],
            sig: [0u8; SIGNATURE_BYTES],
        }
    }
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        base64::encode(self.to_bytes().as_slice())
    }
}
