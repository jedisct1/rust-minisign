use crate::constants::*;
use crate::crypto::util::fixed_time_eq;
use crate::errors::*;
use crate::keynum::*;
use std::cmp;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) sig_alg: [u8; TWOBYTES],
    pub(crate) keynum_pk: KeynumPK,
}

impl PublicKey {
    pub fn len() -> usize {
        use std::mem;
        mem::size_of::<PublicKey>()
    }

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

    pub fn from_file<P>(pk_path: P) -> Result<PublicKey>
    where
        P: AsRef<Path>,
    {
        let pk_path = pk_path.as_ref();
        let file = OpenOptions::new().read(true).open(pk_path).map_err(|e| {
            PError::new(
                ErrorKind::Io,
                format!(
                    "couldn't retrieve public key from {}: {}",
                    pk_path.display(),
                    e
                ),
            )
        })?;
        let mut pk_buf = BufReader::new(file);
        let mut _comment = String::new();
        pk_buf.read_line(&mut _comment)?;
        let mut encoded_buf = String::new();
        pk_buf.read_line(&mut encoded_buf)?;
        if encoded_buf.trim().len() != PK_B64_ENCODED_LEN {
            return Err(PError::new(
                ErrorKind::Io,
                "base64 conversion failed - was an actual public key given?".to_string(),
            ));
        }
        let decoded_buf = base64::decode(encoded_buf.trim()).map_err(|e| {
            PError::new(
                ErrorKind::Io,
                format!(
                    "base64 conversion failed - was an actual public key given?: {}",
                    e
                ),
            )
        })?;
        Ok(PublicKey::from_bytes(&decoded_buf)?)
    }

    pub fn from_string(pk_string: &str) -> Result<PublicKey> {
        let encoded_string = pk_string.to_string();
        if encoded_string.trim().len() != PK_B64_ENCODED_LEN {
            return Err(PError::new(
                ErrorKind::Io,
                "base64 conversion failed - was an actual public key given?".to_string(),
            ));
        }
        let decoded_string = base64::decode(encoded_string.as_bytes()).map_err(|e| {
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
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        fixed_time_eq(&self.keynum_pk.pk, &other.keynum_pk.pk)
    }
}

impl cmp::Eq for PublicKey {}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        base64::encode(self.to_bytes().as_slice())
    }
}
