extern crate base64;
extern crate rand;
extern crate rpassword;
extern crate scrypt;

pub mod crypto;
pub mod parse_args;
pub mod perror;
pub mod types;

use crate::crypto::ed25519;
use rand::{thread_rng, RngCore};
use scrypt::ScryptParams;
use std::cmp;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::u64;

pub use crate::parse_args::*;
pub use crate::perror::*;
pub use crate::types::*;

fn store_u64_le(x: u64) -> [u8; 8] {
    let b1: u8 = (x & 0xff) as u8;
    let b2: u8 = ((x >> 8) & 0xff) as u8;
    let b3: u8 = ((x >> 16) & 0xff) as u8;
    let b4: u8 = ((x >> 24) & 0xff) as u8;
    let b5: u8 = ((x >> 32) & 0xff) as u8;
    let b6: u8 = ((x >> 40) & 0xff) as u8;
    let b7: u8 = ((x >> 48) & 0xff) as u8;
    let b8: u8 = ((x >> 56) & 0xff) as u8;
    [b1, b2, b3, b4, b5, b6, b7, b8]
}

#[allow(clippy::cast_lossless)]
fn load_u64_le(x: &[u8]) -> u64 {
    (x[0] as u64)
        | (x[1] as u64) << 8
        | (x[2] as u64) << 16
        | (x[3] as u64) << 24
        | (x[4] as u64) << 32
        | (x[5] as u64) << 40
        | (x[6] as u64) << 48
        | (x[7] as u64) << 56
}

fn raw_scrypt_params(memlimit: usize, opslimit: u64) -> Result<ScryptParams> {
    let opslimit = cmp::max(32768, opslimit);
    let mut n_log2 = 1u8;
    let r = 8u32;
    let p;
    if opslimit < (memlimit / 32) as u64 {
        p = 1;
        let maxn = opslimit / (u64::from(r) * 4);
        while n_log2 < 63 {
            if 1u64 << n_log2 > maxn / 2 {
                break;
            }
            n_log2 += 1;
        }
    } else {
        let maxn = memlimit as u64 / (u64::from(r) * 128);
        while n_log2 < 63 {
            if 1u64 << n_log2 > maxn / 2 {
                break;
            }
            n_log2 += 1;
        }
        let maxrp = cmp::min(
            0x3fff_ffff as u32,
            ((opslimit / 4) / (1u64 << n_log2)) as u32,
        );
        p = maxrp / r;
    }
    ScryptParams::new(n_log2, r, p).map_err(Into::into)
}

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

fn derive_and_crypt(sk_str: &mut SecretKey, pwd: &[u8]) -> Result<()> {
    let mut stream = [0u8; CHK_BYTES + SECRETKEYBYTES + KEYNUMBYTES];
    let opslimit = load_u64_le(&sk_str.kdf_opslimit_le);
    let memlimit = load_u64_le(&sk_str.kdf_memlimit_le) as usize;
    let params = raw_scrypt_params(memlimit, opslimit)?;
    scrypt::scrypt(&pwd, &sk_str.kdf_salt, &params, &mut stream)?;
    sk_str.xor_keynum(&stream);
    Ok(())
}

fn get_password(prompt: &str) -> Result<String> {
    let pwd = rpassword::prompt_password_stdout(prompt)?;
    if pwd.is_empty() {
        println!("<empty>");
        Ok(pwd)
    } else if pwd.len() > PASSWORDMAXBYTES {
        Err(PError::new(
            ErrorKind::Misc,
            "passphrase can't exceed 1024 bytes length",
        ))
    } else {
        Ok(pwd)
    }
}

fn unix_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("system clock is incorrect");
    since_the_epoch.as_secs()
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

#[derive(Clone)]
pub struct SignatureBox {
    pub global_sig: Vec<u8>,
    pub trusted_comment: Vec<u8>,
    pub signature: Signature,
    pub hashed: bool,
}

impl SignatureBox {
    pub fn from_file<P>(sig_path: P) -> Result<SignatureBox>
    where
        P: AsRef<Path>,
    {
        let sig_path = sig_path.as_ref();
        let file = File::open(sig_path)
            .map_err(|e| PError::new(ErrorKind::Io, format!("{} {}", e, sig_path.display())))?;

        let mut buf = BufReader::new(file);
        let mut untrusted_comment = String::with_capacity(COMMENTBYTES);
        buf.read_line(&mut untrusted_comment)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        let mut signatureing = String::with_capacity(Signature::len());
        buf.read_line(&mut signatureing)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        let mut t_comment = String::with_capacity(TRUSTEDCOMMENTMAXBYTES);
        buf.read_line(&mut t_comment)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        let mut g_sig = String::with_capacity(SIGNATUREBYTES);
        buf.read_line(&mut g_sig)
            .map_err(|e| PError::new(ErrorKind::Io, e))?;

        if !untrusted_comment.starts_with(COMMENT_PREFIX) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!("Untrusted comment must start with: {}", COMMENT_PREFIX),
            ));
        }

        let sig_bytes = base64::decode(signatureing.trim().as_bytes())
            .map_err(|e| PError::new(ErrorKind::Io, e))?;
        let signature = Signature::from_bytes(&sig_bytes)?;
        if !t_comment.starts_with(TRUSTED_COMMENT_PREFIX) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!(
                    "trusted comment should start with: {}",
                    TRUSTED_COMMENT_PREFIX
                ),
            ));
        }
        let hashed = match signature.sig_alg {
            SIGALG => false,
            SIGALG_HASHED => true,
            _ => Err(PError::new(
                ErrorKind::Verify,
                "Unsupported signature algorithm".to_string(),
            ))?,
        };
        let _ = t_comment.drain(..TR_COMMENT_PREFIX_LEN).count();
        let mut trusted_comment = signature.sig.to_vec();
        trusted_comment.extend_from_slice(t_comment.trim().as_bytes());
        let global_sig =
            base64::decode(g_sig.trim().as_bytes()).map_err(|e| PError::new(ErrorKind::Io, e))?;
        Ok(SignatureBox {
            global_sig,
            trusted_comment,
            signature,
            hashed,
        })
    }
}
