use crate::constants::*;
use crate::crypto::blake2b::Blake2b;
use crate::crypto::digest::Digest;
use crate::crypto::util::fixed_time_eq;
use crate::errors::*;
use crate::helpers::*;
use crate::keynum::*;
use crate::Result;
use std::cmp;
use std::fmt::{self, Formatter};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::io::{Cursor, Read};
use std::path::Path;

#[derive(Clone)]
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

    pub fn from_file<P: AsRef<Path>>(sk_path: P, password: Option<String>) -> Result<SecretKey> {
        let file = OpenOptions::new()
            .read(true)
            .open(sk_path)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;
        let sk = {
            let mut sk_buf = BufReader::new(file);
            let mut _comment = String::new();
            sk_buf.read_line(&mut _comment)?;
            let mut encoded_buf = String::new();
            sk_buf.read_line(&mut encoded_buf)?;
            let decoded_buf =
                base64::decode(encoded_buf.trim()).map_err(|e| PError::new(ErrorKind::Io, e))?;
            SecretKey::from_bytes(&decoded_buf[..])
        }?;
        let interactive = password.is_none();
        let password = match password {
            Some(password) => password,
            None => {
                let password = get_password("Password: ")?;
                write!(
                    io::stdout(),
                    "Deriving a key from the password and decrypting the secret key... "
                )
                .map_err(|e| PError::new(ErrorKind::Io, e))?;
                io::stdout().flush()?;
                password
            }
        };
        let sk = sk.encrypt(password)?;
        if interactive {
            writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e))?
        }
        let checksum_vec = sk.read_checksum().map_err(|e| e)?;
        let mut chk = [0u8; CHK_BYTES];
        chk.copy_from_slice(&checksum_vec[..]);
        if chk != sk.keynum_sk.chk {
            Err(PError::new(
                ErrorKind::Verify,
                "Wrong password for that key",
            ))
        } else {
            Ok(sk)
        }
    }

    pub fn encrypt(mut self, password: String) -> Result<SecretKey> {
        let mut stream = [0u8; CHK_BYTES + SECRETKEYBYTES + KEYNUMBYTES];
        let opslimit = load_u64_le(&self.kdf_opslimit_le);
        let memlimit = load_u64_le(&self.kdf_memlimit_le) as usize;
        let params = raw_scrypt_params(memlimit, opslimit)?;
        scrypt::scrypt(&password.as_bytes(), &self.kdf_salt, &params, &mut stream)?;
        self.xor_keynum(&stream);
        Ok(self)
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
