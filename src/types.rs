use crate::crypto::blake2b::Blake2b;
use crate::crypto::digest::Digest;
use crate::crypto::util::fixed_time_eq;
use crate::Result;
use std::cmp;
use std::fmt::{self, Formatter};
use std::io::{Cursor, Read};

pub const COMMENTBYTES: usize = 1024;
pub const DEFAULT_COMMENT: &str = "signature from rsign secret key";
pub const SIG_DEFAULT_CONFIG_DIR_ENV_VAR: &str = "RSIGN_CONFIG_DIR";
pub const SIG_DEFAULT_CONFIG_DIR: &str = ".rsign";
pub const SIG_DEFAULT_PKFILE: &str = "rsign.pub";
pub const SIG_DEFAULT_SKFILE: &str = "rsign.key";
pub const SIG_SUFFIX: &str = ".minisig";
pub const TRUSTED_COMMENT_PREFIX: &str = "trusted comment: ";
pub const TRUSTEDCOMMENTMAXBYTES: usize = 8192;
pub(crate) const CHK_BYTES: usize = 32;
pub(crate) const CHKALG: [u8; 2] = *b"B2";
pub(crate) const COMMENT_PREFIX: &str = "untrusted comment: ";
pub(crate) const KDF_SALTBYTES: usize = 32;
pub(crate) const KDFALG: [u8; 2] = *b"Sc";
pub(crate) const KEYNUMBYTES: usize = 8;
pub(crate) const MEMLIMIT: usize = 33_554_432;
pub(crate) const OPSLIMIT: u64 = 1_048_576;
pub(crate) const PASSWORDMAXBYTES: usize = 1024;
pub(crate) const PK_B64_ENCODED_LEN: usize = 56;
pub(crate) const PREHASH_BYTES: usize = 64;
pub(crate) const PUBLICKEYBYTES: usize = 32;
pub(crate) const SECRETKEY_DEFAULT_COMMENT: &str = "rsign encrypted secret key";
pub(crate) const SECRETKEYBYTES: usize = 64;
pub(crate) const SIGALG_HASHED: [u8; 2] = *b"ED";
pub(crate) const SIGALG: [u8; 2] = *b"Ed";
pub(crate) const SIGNATUREBYTES: usize = 64;
pub(crate) const TR_COMMENT_PREFIX_LEN: usize = 17;
pub(crate) const TWOBYTES: usize = 2;

pub(crate) struct KeynumSK {
    pub keynum: [u8; KEYNUMBYTES],
    pub sk: [u8; SECRETKEYBYTES],
    pub chk: [u8; CHK_BYTES],
}

impl Clone for KeynumSK {
    fn clone(&self) -> KeynumSK {
        KeynumSK {
            keynum: self.keynum,
            sk: self.sk,
            chk: self.chk,
        }
    }
}

#[allow(clippy::len_without_is_empty, dead_code)]
impl KeynumSK {
    pub fn len(&self) -> usize {
        std::mem::size_of::<KeynumSK>()
    }
}

impl fmt::Debug for KeynumSK {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in self.sk.iter() {
            write!(f, "{:x}", byte)?
        }
        Ok(())
    }
}

impl cmp::PartialEq for KeynumSK {
    fn eq(&self, other: &KeynumSK) -> bool {
        fixed_time_eq(&self.sk, &other.sk)
    }
}
impl cmp::Eq for KeynumSK {}

pub struct SecretKey {
    pub(crate) sig_alg: [u8; TWOBYTES],
    pub(crate) kdf_alg: [u8; TWOBYTES],
    pub(crate) chk_alg: [u8; TWOBYTES],
    pub(crate) kdf_salt: [u8; KDF_SALTBYTES],
    pub(crate) kdf_opslimit_le: [u8; KEYNUMBYTES],
    pub(crate) kdf_memlimit_le: [u8; KEYNUMBYTES],
    pub(crate) keynum_sk: KeynumSK,
}

impl SecretKey {
    pub fn from_bytes(bytes_buf: &[u8]) -> Result<SecretKey> {
        let mut buf = Cursor::new(bytes_buf);
        let mut sig_alg = [0u8; TWOBYTES];
        let mut kdf_alg = [0u8; TWOBYTES];
        let mut chk_alg = [0u8; TWOBYTES];
        let mut kdf_salt = [0u8; KDF_SALTBYTES];
        let mut ops_limit = [0u8; KEYNUMBYTES];
        let mut mem_limit = [0u8; KEYNUMBYTES];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        let mut chk = [0u8; CHK_BYTES];
        buf.read_exact(&mut sig_alg)?;
        buf.read_exact(&mut kdf_alg)?;
        buf.read_exact(&mut chk_alg)?;
        buf.read_exact(&mut kdf_salt)?;
        buf.read_exact(&mut ops_limit)?;
        buf.read_exact(&mut mem_limit)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut sk)?;
        buf.read_exact(&mut chk)?;

        Ok(SecretKey {
            sig_alg,
            kdf_alg,
            chk_alg,
            kdf_salt,
            kdf_opslimit_le: ops_limit,
            kdf_memlimit_le: mem_limit,
            keynum_sk: KeynumSK { keynum, sk, chk },
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut iters = Vec::new();
        iters.push(self.sig_alg.iter());
        iters.push(self.kdf_alg.iter());
        iters.push(self.chk_alg.iter());
        iters.push(self.kdf_salt.iter());
        iters.push(self.kdf_opslimit_le.iter());
        iters.push(self.kdf_memlimit_le.iter());
        iters.push(self.keynum_sk.keynum.iter());
        iters.push(self.keynum_sk.sk.iter());
        iters.push(self.keynum_sk.chk.iter());
        let v: Vec<u8> = iters
            .iter()
            .flat_map(|b| {
                let b = b.clone();
                b.cloned()
            })
            .collect();
        v
    }
    pub(crate) fn write_checksum(&mut self) -> Result<()> {
        let h = self.read_checksum()?;
        self.keynum_sk.chk.copy_from_slice(&h[..]);
        Ok(())
    }

    pub(crate) fn read_checksum(&self) -> Result<Vec<u8>> {
        let mut state = Blake2b::new(CHK_BYTES);
        state.input(&self.sig_alg);
        state.input(&self.keynum_sk.keynum);
        state.input(&self.keynum_sk.sk);
        let mut h = vec![0u8; CHK_BYTES];
        state.result(&mut h);
        Ok(h)
    }

    pub(crate) fn xor_keynum(&mut self, stream: &[u8]) {
        let b8 = self
            .keynum_sk
            .keynum
            .iter_mut()
            .zip(stream.iter())
            .map(|(byte, stream)| *byte ^= *stream)
            .count();

        let b64 = self
            .keynum_sk
            .sk
            .iter_mut()
            .zip(stream[b8..].iter())
            .map(|(byte, stream)| *byte ^= *stream)
            .count();

        let _b32 = self
            .keynum_sk
            .chk
            .iter_mut()
            .zip(stream[b8 + b64..].iter())
            .map(|(byte, stream)| *byte ^= *stream)
            .count();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in self.keynum_sk.sk.iter() {
            write!(f, "{:x}", byte)?
        }
        Ok(())
    }
}

impl cmp::PartialEq for SecretKey {
    fn eq(&self, other: &SecretKey) -> bool {
        fixed_time_eq(&self.keynum_sk.sk, &other.keynum_sk.sk)
    }
}
impl cmp::Eq for SecretKey {}

impl ToString for SecretKey {
    fn to_string(&self) -> String {
        base64::encode(self.to_bytes().as_slice())
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub(crate) sig_alg: [u8; TWOBYTES],
    pub(crate) keynum_pk: KeynumPK,
}

#[derive(Debug, Clone)]
pub(crate) struct KeynumPK {
    pub(crate) keynum: [u8; KEYNUMBYTES],
    pub(crate) pk: [u8; PUBLICKEYBYTES],
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        fixed_time_eq(&self.keynum_pk.pk, &other.keynum_pk.pk)
    }
}

impl cmp::Eq for PublicKey {}

impl PublicKey {
    pub fn len() -> usize {
        use std::mem;
        mem::size_of::<PublicKey>()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<PublicKey> {
        let mut buf = Cursor::new(buf);
        let mut sig_alg = [0u8; TWOBYTES];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut pk = [0u8; PUBLICKEYBYTES];
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
}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        base64::encode(self.to_bytes().as_slice())
    }
}

#[derive(Clone)]
pub(crate) struct Signature {
    pub sig_alg: [u8; TWOBYTES],
    pub keynum: [u8; KEYNUMBYTES],
    pub sig: [u8; SIGNATUREBYTES],
}

impl Signature {
    pub fn len() -> usize {
        use std::mem;
        mem::size_of::<Signature>()
    }

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
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut sig = [0u8; SIGNATUREBYTES];
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
            keynum: [0u8; KEYNUMBYTES],
            sig: [0u8; SIGNATUREBYTES],
        }
    }
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        base64::encode(self.to_bytes().as_slice())
    }
}
