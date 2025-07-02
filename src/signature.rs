use std::io::{Cursor, Read};

use ct_codecs::{Base64, Encoder};

use crate::constants::*;
use crate::Result;

#[derive(Clone)]
pub(crate) struct Signature {
    pub sig_alg: [u8; TWOBYTES],
    pub keynum: [u8; KEYNUM_BYTES],
    pub sig: [u8; SIGNATURE_BYTES],
}

impl Signature {
    pub const BYTES: usize = 2 + KEYNUM_BYTES + SIGNATURE_BYTES;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(Self::BYTES);
        v.extend(self.sig_alg);
        v.extend(self.keynum);
        v.extend(&self.sig[..]);
        debug_assert_eq!(v.len(), Self::BYTES);
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
        debug_assert_eq!(buf.position() as usize, Self::BYTES);
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

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = Base64::encode_to_string(self.to_bytes().as_slice()).unwrap();
        write!(f, "{}", encoded)
    }
}
