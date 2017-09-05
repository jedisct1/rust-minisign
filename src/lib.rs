extern crate sodiumoxide;
extern crate libc;
extern crate libsodium_sys as ffi;

use sodiumoxide::crypto::pwhash::*;
use sodiumoxide::randombytes::*;
use sodiumoxide::crypto::sign::{SecretKey, PublicKey, SIGNATUREBYTES, SECRETKEYBYTES, PUBLICKEYBYTES, gen_keypair};

use std::io::{Cursor, Read};

#[macro_use]
mod macros;
pub mod parse_args;
pub mod generichash;
pub mod perror;

pub use generichash::*;
pub use perror::*;
pub use parse_args::*;

pub const KEYNUMBYTES: usize = 8;
pub const TWOBYTES: usize = 2;
pub const TR_COMMENT_PREFIX_LEN: usize = 17;
pub const PASSWORDMAXBYTES: usize = 1024;
pub const COMMENTBYTES: usize = 1024;
pub const TRUSTEDCOMMENTMAXBYTES: usize = 8192;
pub const SIGALG: [u8; 2] = *b"Ed";
pub const SIGALG_HASHED: [u8; 2] = *b"ED";
pub const KDFALG: [u8; 2] = *b"Sc";
pub const CHKALG: [u8; 2] = *b"B2";
pub const COMMENT_PREFIX: &'static str = "untrusted comment: ";
pub const DEFAULT_COMMENT: &'static str = "signature from rsign secret key";
pub const SECRETKEY_DEFAULT_COMMENT: &'static str = "rsign encrypted secret key";
pub const TRUSTED_COMMENT_PREFIX: &'static str = "trusted comment: ";
pub const SIG_DEFAULT_CONFIG_DIR: &'static str = ".rsign/";
pub const SIG_DEFAULT_CONFIG_DIR_ENV_VAR: &'static str = "MINISIGN_CONFIG_DIR";
pub const SIG_DEFAULT_PKFILE: &'static str = "rsign.pub";
pub const SIG_DEFAULT_SKFILE: &'static str = "rsign.key";
pub const SIG_SUFFIX: &'static str = ".rsign";


pub struct KeynumSK {
    pub keynum: [u8; KEYNUMBYTES],
    pub sk: [u8; SECRETKEYBYTES],
    pub chk: [u8; BYTES],
}
impl KeynumSK {
    pub fn len(&self) -> usize {
        self.keynum.len() + self.sk.len() + self.chk.len()
    }
}

pub struct SeckeyStruct {
    pub sig_alg: [u8; 2],
    pub kdf_alg: [u8; 2],
    pub chk_alg: [u8; 2],
    pub kdf_salt: [u8; SALTBYTES],
    pub kdf_opslimit_le: [u8; 8],
    pub kdf_memlimit_le: [u8; 8],
    pub keynum_sk: KeynumSK,
}

impl SeckeyStruct {
    pub fn from(bytes_buf: &[u8]) -> Result<SeckeyStruct> {
        let mut buf = Cursor::new(bytes_buf);
        let mut sig_alg = [0u8; 2];
        let mut kdf_alg = [0u8; 2];
        let mut chk_alg = [0u8; 2];
        let mut kdf_salt = [0u8; SALTBYTES];
        let mut ops_limit = [0u8; 8];
        let mut mem_limit = [0u8; 8];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut sk = [0u8; SECRETKEYBYTES];
        let mut chk = [0u8; BYTES];
        buf.read(&mut sig_alg)?;
        buf.read(&mut kdf_alg)?;
        buf.read(&mut chk_alg)?;
        buf.read(&mut kdf_salt)?;
        buf.read(&mut ops_limit)?;
        buf.read(&mut mem_limit)?;
        buf.read(&mut keynum)?;
        buf.read(&mut sk)?;
        buf.read(&mut chk)?;
        
        Ok (SeckeyStruct {
            sig_alg: sig_alg,
            kdf_alg: kdf_alg,
            chk_alg: chk_alg,
            kdf_salt: kdf_salt,
            kdf_opslimit_le: ops_limit,
            kdf_memlimit_le: mem_limit,
            keynum_sk: KeynumSK {
                keynum: keynum,
                sk: sk,
                chk: chk,
            },
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
                          b.into_iter().cloned()
                      })
            .collect();
        v
    }
    pub fn checksum(&mut self) -> Result<()> {
        let state_sz = unsafe { ffi::crypto_generichash_statebytes() };
        let mut state: Vec<u8> = vec![0;state_sz];
        let ptr_state = state.as_mut_ptr() as *mut ffi::crypto_generichash_state;
        generichash::init(ptr_state)?;
        generichash::update(ptr_state, &self.sig_alg)?;
        generichash::update(ptr_state, &self.keynum_sk.keynum)?;
        generichash::update(ptr_state, &self.keynum_sk.sk)?;
        let h = generichash::finalize(ptr_state)?;
        self.keynum_sk.chk.copy_from_slice(&h[..]);
        Ok(())
    }
    
    pub fn xor_keynum(&mut self, stream: &[u8]) {

        let b8 = self.keynum_sk
            .keynum
            .iter_mut()
            .zip(stream.iter())
            .map(|(byte, stream)| *byte = *byte ^ *stream)
            .count();

        let b64 = self.keynum_sk
            .sk
            .iter_mut()
            .zip(stream[b8..].iter())
            .map(|(byte, stream)| *byte = *byte ^ *stream)
            .count();

        let _b32 = self.keynum_sk
            .chk
            .iter_mut()
            .zip(stream[b8 + b64..].iter())
            .map(|(byte, stream)| *byte = *byte ^ *stream)
            .count();
    }
}

#[derive(Debug)]
pub struct PubkeyStruct {
    pub sig_alg: [u8; 2],
    pub keynum_pk: KeynumPK,
}
#[derive(Debug, Clone)]
pub struct KeynumPK {
    pub keynum: [u8; KEYNUMBYTES],
    pub pk: [u8; PUBLICKEYBYTES],
}
impl PubkeyStruct {
    pub fn from(buf: &[u8]) -> Result<PubkeyStruct> {
        let mut buf = Cursor::new(buf);
        let mut sig_alg = [0u8; 2];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut pk = [0u8; PUBLICKEYBYTES];
        buf.read(&mut sig_alg)?;
        buf.read(&mut keynum)?;
        buf.read(&mut pk)?;
        Ok(PubkeyStruct {
               sig_alg: sig_alg,
               keynum_pk: KeynumPK {
                   keynum: keynum,
                   pk: pk,
               },
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
                          b.into_iter().cloned()
                      })
            .collect();
        v
    }
}

pub struct SigStruct {
    pub sig_alg: [u8; 2],
    pub keynum: [u8; KEYNUMBYTES],
    pub sig: [u8; SIGNATUREBYTES],
}
impl SigStruct {
    pub fn len() -> usize {
        KEYNUMBYTES + SIGNATUREBYTES + TWOBYTES
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
                          b.into_iter().cloned()
                      })
            .collect();
        v
    }
    pub fn from(bytes_buf: &[u8]) -> Result<SigStruct> {
        let mut buf = Cursor::new(bytes_buf);
        let mut sig_alg = [0u8; 2];
        let mut keynum = [0u8; KEYNUMBYTES];
        let mut sig = [0u8; SIGNATUREBYTES];
        buf.read(&mut sig_alg)?;
        buf.read(&mut keynum)?;
        buf.read(&mut sig)?;
        Ok(SigStruct {
               sig_alg: sig_alg,
               keynum: keynum,
               sig: sig,
           })
    }
}

impl Default for SigStruct {
    fn default() -> Self {
        SigStruct {
            sig_alg: [0; 2],
            keynum: [0; KEYNUMBYTES],
            sig: [0; SIGNATUREBYTES],
        }
    }
}

pub fn gen_keystruct() -> (PubkeyStruct, SeckeyStruct) {
    let (pk, sk) = gen_keypair();
    let SecretKey(sk) = sk;
    let PublicKey(pk) = pk;

    let keynum_vec = randombytes(KEYNUMBYTES);
    let mut keynum = [0u8; KEYNUMBYTES];
    keynum.copy_from_slice(keynum_vec.as_slice());

    let kdf_salt_vec = randombytes(SALTBYTES);
    let mut kdf_salt = [0u8; SALTBYTES];
    kdf_salt.copy_from_slice(kdf_salt_vec.as_slice());

    let OpsLimit(ops_limit) = OPSLIMIT_SENSITIVE;
    let MemLimit(mem_limit) = MEMLIMIT_SENSITIVE;

    let p_struct = PubkeyStruct {
        sig_alg: SIGALG,
        keynum_pk: KeynumPK {
            keynum: keynum,
            pk: pk,
        },
    };
    let s_struct = SeckeyStruct {
        sig_alg: SIGALG,
        kdf_alg: KDFALG,
        chk_alg: CHKALG,
        kdf_salt: kdf_salt,
        kdf_opslimit_le: store_usize_le(ops_limit),
        kdf_memlimit_le: store_usize_le(mem_limit),
        keynum_sk: KeynumSK {
            keynum: keynum.clone(),
            sk: sk,
            chk: [0; BYTES],
        },
    };
    (p_struct, s_struct)
}

pub fn store_usize_le(x: usize) -> [u8; 8] {
    let b1: u8 = (x & 0xff) as u8;
    let b2: u8 = ((x >> 8) & 0xff) as u8;
    let b3: u8 = ((x >> 16) & 0xff) as u8;
    let b4: u8 = ((x >> 24) & 0xff) as u8;
    let b5: u8 = ((x >> 32) & 0xff) as u8;
    let b6: u8 = ((x >> 40) & 0xff) as u8;
    let b7: u8 = ((x >> 48) & 0xff) as u8;
    let b8: u8 = ((x >> 56) & 0xff) as u8;
    return [b1, b2, b3, b4, b5, b6, b7, b8];
}

pub fn load_usize_le(x: &[u8]) -> usize {
    (x[0] as usize) | (x[1] as usize) << 8 | (x[2] as usize) << 16 | (x[3] as usize) << 24 |
    (x[4] as usize) << 32 | (x[5] as usize) << 40 |
    (x[6] as usize) << 48 | (x[7] as usize) << 56
}
