extern crate base64;
extern crate rand;
extern crate rpassword;
extern crate scrypt;

mod helpers;
mod perror;
mod signature_box;
mod types;

pub mod crypto;

use crate::crypto::ed25519;
use helpers::*;
use rand::{thread_rng, RngCore};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::u64;

pub use crate::perror::*;
pub use crate::signature_box::*;
pub use crate::types::*;

pub fn generate_unencrypted_keypair() -> Result<(PublicKey, SecretKey)> {
    let mut seed = vec![0u8; 32];
    let mut rng = thread_rng();
    rng.try_fill_bytes(&mut seed)?;
    let (sk, pk) = ed25519::keypair(&seed);
    let mut keynum = [0u8; KEYNUMBYTES];
    rng.try_fill_bytes(&mut keynum)?;
    let mut kdf_salt = [0u8; KDF_SALTBYTES];
    rng.try_fill_bytes(&mut kdf_salt)?;

    let opslimit = OPSLIMIT;
    let memlimit = MEMLIMIT;
    let p_struct = PublicKey {
        sig_alg: SIGALG,
        keynum_pk: KeynumPK { keynum, pk },
    };
    let s_struct = SecretKey {
        sig_alg: SIGALG,
        kdf_alg: KDFALG,
        chk_alg: CHKALG,
        kdf_salt,
        kdf_opslimit_le: store_u64_le(opslimit),
        kdf_memlimit_le: store_u64_le(memlimit as u64),
        keynum_sk: KeynumSK {
            keynum,
            sk,
            chk: [0; CHK_BYTES],
        },
    };
    Ok((p_struct, s_struct))
}

fn derive_and_crypt(sk: &mut SecretKey, pwd: &[u8]) -> Result<()> {
    let mut stream = [0u8; CHK_BYTES + SECRETKEYBYTES + KEYNUMBYTES];
    let opslimit = load_u64_le(&sk.kdf_opslimit_le);
    let memlimit = load_u64_le(&sk.kdf_memlimit_le) as usize;
    let params = raw_scrypt_params(memlimit, opslimit)?;
    scrypt::scrypt(&pwd, &sk.kdf_salt, &params, &mut stream)?;
    sk.xor_keynum(&stream);
    Ok(())
}

pub fn generate_encrypted_keypair(password: Option<String>) -> Result<(PublicKey, SecretKey)> {
    let (pk, mut sk) = generate_unencrypted_keypair()?;
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
    derive_and_crypt(&mut sk, &password.as_bytes())?;
    if interactive {
        writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e))?;
    }
    Ok((pk, sk))
}

pub fn generate_and_write_encrypted_keypair(
    mut pk_writer: BufWriter<File>,
    mut sk_writer: BufWriter<File>,
    comment: Option<&str>,
    password: Option<String>,
) -> Result<(PublicKey, SecretKey)> {
    let (pk, sk) = generate_encrypted_keypair(password)?;
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
    Ok((pk, sk))
}

pub fn sign<W>(
    mut signature_box_writer: W,
    pk: Option<&PublicKey>,
    sk: &SecretKey,
    message: &[u8],
    hashed: bool,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<()>
where
    W: Write,
{
    let trusted_comment = match trusted_comment {
        Some(trusted_comment) => trusted_comment.to_string(),
        None => format!("timestamp:{}", unix_timestamp()),
    };
    let untrusted_comment = match untrusted_comment {
        Some(untrusted_comment) => format!("{}{}", COMMENT_PREFIX, untrusted_comment),
        None => format!("{}{}", COMMENT_PREFIX, DEFAULT_COMMENT),
    };
    let mut signature = Signature::default();
    if !hashed {
        signature.sig_alg = sk.sig_alg;
    } else {
        signature.sig_alg = SIGALG_HASHED;
    }
    signature.keynum.copy_from_slice(&sk.keynum_sk.keynum[..]);
    let mut rng = thread_rng();
    let mut z = vec![0; 64];
    rng.try_fill_bytes(&mut z)?;
    let signature_raw = ed25519::signature(message, &sk.keynum_sk.sk, Some(&z));
    signature.sig.copy_from_slice(&signature_raw[..]);

    let mut sig_and_trust_comment: Vec<u8> = vec![];
    sig_and_trust_comment.extend(signature.sig.iter());
    sig_and_trust_comment.extend(trusted_comment.as_bytes().iter());

    rng.try_fill_bytes(&mut z)?;
    let global_sig = ed25519::signature(&sig_and_trust_comment, &sk.keynum_sk.sk, Some(&z));
    if let Some(pk) = pk {
        if !ed25519::verify(&sig_and_trust_comment, &pk.keynum_pk.pk[..], &global_sig) {
            Err(PError::new(
                ErrorKind::Verify,
                format!(
                    "Could not verify signature with the \
                     provided public key ID: {:X}",
                    load_u64_le(&pk.keynum_pk.keynum[..])
                ),
            ))?
        }
    }
    writeln!(signature_box_writer, "{}", untrusted_comment)?;
    writeln!(signature_box_writer, "{}", signature.to_string())?;
    writeln!(
        signature_box_writer,
        "{}{}",
        TRUSTED_COMMENT_PREFIX, trusted_comment
    )?;
    writeln!(signature_box_writer, "{}", base64::encode(&global_sig[..]))?;
    signature_box_writer.flush()?;
    Ok(())
}

pub fn verify(
    pk_key: &PublicKey,
    signature_box: &SignatureBox,
    message: &[u8],
    quiet: bool,
    output: bool,
) -> Result<()> {
    let sig = &signature_box.signature;
    let global_sig = &signature_box.global_sig[..];
    let trusted_comment = &signature_box.trusted_comment;
    if sig.keynum != pk_key.keynum_pk.keynum {
        return Err(PError::new(
            ErrorKind::Verify,
            format!(
                "Signature key id: {:X} is different from public key: {:X}",
                load_u64_le(&sig.keynum[..]),
                load_u64_le(&pk_key.keynum_pk.keynum[..])
            ),
        ));
    }
    if !ed25519::verify(&message, &pk_key.keynum_pk.pk, &sig.sig) {
        Err(PError::new(
            ErrorKind::Verify,
            "Signature verification failed",
        ))?
    }
    if !ed25519::verify(&trusted_comment, &pk_key.keynum_pk.pk, &global_sig) {
        Err(PError::new(
            ErrorKind::Verify,
            "Comment signature verification failed",
        ))?
    }
    if !quiet {
        let just_comment = String::from_utf8(trusted_comment[SIGNATUREBYTES..].to_vec())?;
        eprintln!("Signature and comment signature verified");
        eprintln!("Trusted comment: {}", just_comment);
    }
    if output {
        io::stdout().write_all(message)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn byte_array_store() {
        use crate::store_u64_le;

        assert_eq!([0xFF, 0, 0, 0, 0, 0, 0, 0], store_u64_le(0xFF));
    }
    #[test]
    fn byte_array_load() {
        use crate::load_u64_le;

        assert_eq!(255, load_u64_le(&[0xFF, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn pk_key_struct_conversion() {
        use crate::generate_unencrypted_keypair;
        use crate::PublicKey;

        let (pk, _) = generate_unencrypted_keypair().unwrap();
        assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
    }
    #[test]
    fn sk_key_struct_conversion() {
        use crate::generate_unencrypted_keypair;
        use crate::SecretKey;

        let (_, sk) = generate_unencrypted_keypair().unwrap();
        assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
    }

    #[test]
    fn xor_keynum() {
        use crate::generate_unencrypted_keypair;
        use rand::{thread_rng, RngCore};

        let (_, mut sk) = generate_unencrypted_keypair().unwrap();
        let mut rng = thread_rng();
        let mut key = vec![0u8; sk.keynum_sk.len()];
        rng.fill_bytes(&mut key);
        let original_keynum = sk.keynum_sk.clone();
        sk.xor_keynum(&key);
        assert_ne!(original_keynum, sk.keynum_sk);
        sk.xor_keynum(&key);
        assert_eq!(original_keynum, sk.keynum_sk);
    }
    #[test]
    fn sk_checksum() {
        use crate::generate_unencrypted_keypair;

        let (_, mut sk) = generate_unencrypted_keypair().unwrap();
        assert!(sk.write_checksum().is_ok());
        assert_eq!(sk.keynum_sk.chk.to_vec(), sk.read_checksum().unwrap());
    }
}

pub fn sk_load<P: AsRef<Path>>(sk_path: P) -> Result<SecretKey> {
    let file = OpenOptions::new()
        .read(true)
        .open(sk_path)
        .map_err(|e| PError::new(ErrorKind::Io, e))?;
    let mut sk_str = {
        let mut sk_buf = BufReader::new(file);
        let mut _comment = String::new();
        sk_buf.read_line(&mut _comment)?;
        let mut encoded_buf = String::new();
        sk_buf.read_line(&mut encoded_buf)?;
        let decoded_buf =
            base64::decode(encoded_buf.trim()).map_err(|e| PError::new(ErrorKind::Io, e))?;
        SecretKey::from_bytes(&decoded_buf[..])
    }?;

    let pwd = get_password("Password: ")?;
    write!(
        io::stdout(),
        "Deriving a key from the password and decrypting the secret key... "
    )
    .map_err(|e| PError::new(ErrorKind::Io, e))
    .and_then(|_| {
        io::stdout().flush()?;
        derive_and_crypt(&mut sk_str, &pwd.as_bytes())
    })
    .and(writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e)))?;
    let checksum_vec = sk_str.read_checksum().map_err(|e| e)?;
    let mut chk = [0u8; CHK_BYTES];
    chk.copy_from_slice(&checksum_vec[..]);
    if chk != sk_str.keynum_sk.chk {
        Err(PError::new(
            ErrorKind::Verify,
            "Wrong password for that key",
        ))
    } else {
        Ok(sk_str)
    }
}

pub fn pk_load<P>(pk_path: P) -> Result<PublicKey>
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

pub fn pk_load_string(pk_string: &str) -> Result<PublicKey> {
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
