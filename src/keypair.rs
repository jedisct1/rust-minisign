use crate::constants::*;
use crate::crypto::ed25519;
use crate::errors::*;
use crate::helpers::*;
use crate::keynum::*;
use crate::public_key::*;
use crate::secret_key::*;
use getrandom::getrandom;
use std::io::{self, Write};
use std::u64;

/// A key pair (`PublicKey` and `SecretKey`).
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl KeyPair {
    /// Create an unencrypted key pair.
    ///
    /// The secret key will not be protected by a password.
    ///
    /// This is not recommended and incompatible with other implementations,
    /// but can be necessary if using a password is really not an option
    /// for your application.
    ///
    /// You generally want to use `generated_encrypted_keypair()` instead.
    pub fn generate_unencrypted_keypair() -> Result<Self> {
        let mut seed = vec![0u8; 32];
        getrandom(&mut seed)?;
        let (sk, pk) = ed25519::keypair(&seed);
        let mut keynum = [0u8; KEYNUM_BYTES];
        getrandom(&mut keynum)?;
        let mut kdf_salt = [0u8; KDF_SALTBYTES];
        getrandom(&mut kdf_salt)?;

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

    /// Create and encrypt a new key pair.
    ///
    /// If `password` is `None`, a password will be interactively asked for.
    ///
    /// A key can be converted to a box in order to be serialized and saved.
    /// Ex: `pk.to_box()?.to_bytes()`
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

    /// Create, encrypt and save a new key pair.
    ///
    /// # Arguments
    ///
    /// * `pk_writer` - Where to store the public key box.
    /// * `sk_writer` - Where to store the secret key box.
    /// * `comment` - An optional untrusted comment to replace the default one.
    /// * `password` - If `None`, a password will be interactively asked for.
    pub fn generate_and_write_encrypted_keypair<W, X>(
        mut pk_writer: W,
        mut sk_writer: X,
        comment: Option<&str>,
        password: Option<String>,
    ) -> Result<Self>
    where
        W: Write,
        X: Write,
    {
        let KeyPair { pk, sk } = Self::generate_encrypted_keypair(password)?;

        pk_writer.write_all(&pk.to_box()?.to_bytes())?;
        pk_writer.flush()?;

        sk_writer.write_all(&sk.to_box(comment)?.to_bytes())?;
        sk_writer.flush()?;

        Ok(KeyPair { pk, sk })
    }

    /// Create and save an unencrypted key pair.
    ///
    /// The secret key will not be protected by a password,
    /// and keys will be stored as raw bytes, not as a box.
    ///
    /// This is not recommended and incompatible with other implementations,
    /// but can be necessary if using a password is not an option
    /// for your application.
    ///
    /// You generally want to use `generated_encrypted_keypair()` instead.
    ///
    /// # Arguments
    ///
    /// * `pk_writer` - Where to store the public key box.
    /// * `sk_writer` - Where to store the secret key box.
    pub fn generate_and_write_unencrypted_keypair<W, X>(
        mut pk_writer: W,
        mut sk_writer: X,
    ) -> Result<Self>
    where
        W: Write,
        X: Write,
    {
        let KeyPair { pk, sk } = Self::generate_unencrypted_keypair()?;

        pk_writer.write_all(&pk.to_bytes())?;
        pk_writer.flush()?;

        sk_writer.write_all(&sk.to_bytes())?;
        sk_writer.flush()?;

        Ok(KeyPair { pk, sk })
    }
}
