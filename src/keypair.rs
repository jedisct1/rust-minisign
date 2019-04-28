use crate::constants::*;
use crate::crypto::ed25519;
use crate::errors::*;
use crate::helpers::*;
use crate::keynum::*;
use crate::public_key::*;
use crate::secret_key::*;
use rand::{thread_rng, RngCore};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::u64;

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    pub fn generate_unencrypted_keypair() -> Result<Self> {
        let mut seed = vec![0u8; 32];
        let mut rng = thread_rng();
        rng.try_fill_bytes(&mut seed)?;
        let (sk, pk) = ed25519::keypair(&seed);
        let mut keynum = [0u8; KEYNUM_BYTES];
        rng.try_fill_bytes(&mut keynum)?;
        let mut kdf_salt = [0u8; KDF_SALTBYTES];
        rng.try_fill_bytes(&mut kdf_salt)?;

        let opslimit = OPSLIMIT;
        let memlimit = MEMLIMIT;
        let pk = PublicKey {
            sig_alg: SIGALG,
            keynum_pk: KeynumPK { keynum, pk },
        };
        let sk = SecretKey {
            sig_alg: SIGALG,
            kdf_alg: KDF_ALG,
            chk_alg: CHK_ALG,
            kdf_salt,
            kdf_opslimit_le: store_u64_le(opslimit),
            kdf_memlimit_le: store_u64_le(memlimit as u64),
            keynum_sk: KeynumSK {
                keynum,
                sk,
                chk: [0; CHK_BYTES],
            },
        };
        Ok(KeyPair { pk, sk })
    }

    pub fn generate_encrypted_keypair(password: Option<String>) -> Result<Self> {
        let KeyPair { pk, mut sk } = Self::generate_unencrypted_keypair()?;
        let interactive = password.is_none();
        sk.write_checksum()
            .map_err(|_| PError::new(ErrorKind::Generate, "failed to hash and write checksum!"))?;
        let password = match password {
            Some(password) => password,
            None => {
                writeln!(
                    io::stdout(),
                    "Please enter a password to protect the secret key."
                )?;
                let password = get_password("Password: ")?;
                let password2 = get_password("Password (one more time): ")?;
                if password != password2 {
                    return Err(PError::new(ErrorKind::Generate, "passwords don't match!"));
                }
                write!(
                    io::stdout(),
                    "Deriving a key from the password in order to encrypt the secret key... "
                )
                .map_err(|e| PError::new(ErrorKind::Io, e))?;
                io::stdout().flush()?;
                password
            }
        };
        let sk = sk.encrypt(password)?;
        if interactive {
            writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e))?;
        }
        Ok(KeyPair { pk, sk })
    }

    pub fn generate_and_write_encrypted_keypair(
        mut pk_writer: BufWriter<File>,
        mut sk_writer: BufWriter<File>,
        comment: Option<&str>,
        password: Option<String>,
    ) -> Result<Self> {
        let KeyPair { pk, sk } = Self::generate_encrypted_keypair(password)?;
        write!(pk_writer, "{}minisign public key: ", COMMENT_PREFIX)?;
        writeln!(pk_writer, "{:X}", load_u64_le(&pk.keynum_pk.keynum[..]))?;
        writeln!(pk_writer, "{}", pk.to_string())?;
        pk_writer.flush()?;

        write!(sk_writer, "{}", COMMENT_PREFIX)?;
        if let Some(comment) = comment {
            writeln!(sk_writer, "{}", comment)?;
        } else {
            writeln!(sk_writer, "{}", SECRETKEY_DEFAULT_COMMENT)?;
        }
        writeln!(sk_writer, "{}", sk.to_string())?;
        sk_writer.flush()?;
        Ok(KeyPair { pk, sk })
    }
}
