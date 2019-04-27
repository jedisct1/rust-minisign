extern crate libsodium_sys as ffi;

use crate::Result;
use sodiumoxide::crypto::generichash;
use sodiumoxide::crypto::sign::*;
use std::cmp;
use std::fmt::{self, Formatter};
use std::io::{Cursor, Read};

pub const KEYNUMBYTES: usize = 8;
pub const TWOBYTES: usize = 2;
pub const TR_COMMENT_PREFIX_LEN: usize = 17;
pub const PK_B64_ENCODED_LEN: usize = 56;
pub const PASSWORDMAXBYTES: usize = 1024;
pub const COMMENTBYTES: usize = 1024;
pub const TRUSTEDCOMMENTMAXBYTES: usize = 8192;
pub const SIGALG: [u8; 2] = *b"Ed";
pub const SIGALG_HASHED: [u8; 2] = *b"ED";
pub const KDFALG: [u8; 2] = *b"Sc";
pub const CHKALG: [u8; 2] = *b"B2";
pub const COMMENT_PREFIX: &str = "untrusted comment: ";
pub const DEFAULT_COMMENT: &str = "signature from rsign secret key";
pub const SECRETKEY_DEFAULT_COMMENT: &str = "rsign encrypted secret key";
pub const TRUSTED_COMMENT_PREFIX: &str = "trusted comment: ";
pub const SIG_DEFAULT_CONFIG_DIR: &str = ".rsign";
pub const SIG_DEFAULT_CONFIG_DIR_ENV_VAR: &str = "RSIGN_CONFIG_DIR";
pub const SIG_DEFAULT_PKFILE: &str = "rsign.pub";
pub const SIG_DEFAULT_SKFILE: &str = "rsign.key";
pub const SIG_SUFFIX: &str = ".minisig";
pub const CHK_BYTES: usize = 32;
pub const PREHASH_BYTES: usize = 64;
pub const KDF_SALTBYTES: usize = 32;
pub const OPSLIMIT: u64 = 1_048_576;
pub const MEMLIMIT: usize = 33_554_432;

pub struct KeynumSK {
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

#[allow(clippy::len_without_is_empty)]
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
        use sodiumoxide::utils::memcmp;
        memcmp(&self.sk, &other.sk)
    }
}
impl cmp::Eq for KeynumSK {}

pub struct SeckeyStruct {
    pub sig_alg: [u8; TWOBYTES],
    pub kdf_alg: [u8; TWOBYTES],
    pub chk_alg: [u8; TWOBYTES],
    pub kdf_salt: [u8; KDF_SALTBYTES],
    pub kdf_opslimit_le: [u8; KEYNUMBYTES],
    pub kdf_memlimit_le: [u8; KEYNUMBYTES],
    pub keynum_sk: KeynumSK,
}

impl SeckeyStruct {
    pub fn from(bytes_buf: &[u8]) -> Result<SeckeyStruct> {
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

        Ok(SeckeyStruct {
            sig_alg,
            kdf_alg,
            chk_alg,
            kdf_salt,
            kdf_opslimit_le: ops_limit,
            kdf_memlimit_le: mem_limit,
            keynum_sk: KeynumSK { keynum, sk, chk },
        })
    }
    pub fn bytes(&self) -> Vec<u8> {
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
    pub fn write_checksum(&mut self) -> Result<()> {
        let h = self.read_checksum()?;
        self.keynum_sk.chk.copy_from_slice(&h[..]);
        Ok(())
    }

    pub fn read_checksum(&self) -> Result<Vec<u8>> {
        let mut state = generichash::State::new(CHK_BYTES, None).unwrap();
        state.update(&self.sig_alg).unwrap();
        state.update(&self.keynum_sk.keynum).unwrap();
        state.update(&self.keynum_sk.sk).unwrap();
        let h = state.finalize().unwrap();
        Ok(Vec::from(&h[..]))
    }

    pub fn xor_keynum(&mut self, stream: &[u8]) {
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

impl fmt::Debug for SeckeyStruct {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in self.keynum_sk.sk.iter() {
            write!(f, "{:x}", byte)?
        }
        Ok(())
    }
}

impl cmp::PartialEq for SeckeyStruct {
    fn eq(&self, other: &SeckeyStruct) -> bool {
        use sodiumoxide::utils::memcmp;
        memcmp(&self.keynum_sk.sk, &other.keynum_sk.sk)
    }
}
impl cmp::Eq for SeckeyStruct {}

#[derive(Debug)]
pub struct PubkeyStruct {
    pub sig_alg: [u8; TWOBYTES],
    pub keynum_pk: KeynumPK,
}
#[derive(Debug, Clone)]
pub struct KeynumPK {
    pub keynum: [u8; KEYNUMBYTES],
    pub pk: [u8; PUBLICKEYBYTES],
}

impl cmp::PartialEq for PubkeyStruct {
    fn eq(&self, other: &PubkeyStruct) -> bool {
        use sodiumoxide::utils::memcmp;
        memcmp(&self.keynum_pk.pk, &other.keynum_pk.pk)
    }
}
impl cmp::Eq for PubkeyStruct {}

impl PubkeyStruct {
    pub fn len() -> usize {
        use std::mem;
        mem::size_of::<PubkeyStruct>()
    }

    pub fn from(buf: &[u8]) -> Result<PubkeyStruct> {
        let mut buf = Cursor::new(buf);
        let mut sig_alg = [0u8; TWOBYTES];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut pk = [0u8; PUBLICKEYBYTES];
        buf.read_exact(&mut sig_alg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut pk)?;
        Ok(PubkeyStruct {
            sig_alg,
            keynum_pk: KeynumPK { keynum, pk },
        })
    }

    pub fn bytes(&self) -> Vec<u8> {
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

pub struct SigStruct {
    pub sig_alg: [u8; TWOBYTES],
    pub keynum: [u8; KEYNUMBYTES],
    pub sig: [u8; SIGNATUREBYTES],
}
impl SigStruct {
    pub fn len() -> usize {
        use std::mem;
        mem::size_of::<SigStruct>()
    }
    pub fn bytes(&self) -> Vec<u8> {
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
    pub fn from(bytes_buf: &[u8]) -> Result<SigStruct> {
        let mut buf = Cursor::new(bytes_buf);
        let mut sig_alg = [0u8; 2];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut sig = [0u8; SIGNATUREBYTES];
        buf.read_exact(&mut sig_alg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut sig)?;
        Ok(SigStruct {
            sig_alg,
            keynum,
            sig,
        })
    }
}

impl Default for SigStruct {
    fn default() -> Self {
        SigStruct {
            sig_alg: [0u8; TWOBYTES],
            keynum: [0u8; KEYNUMBYTES],
            sig: [0u8; SIGNATUREBYTES],
        }
    }
}
