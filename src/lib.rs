extern crate libc;
extern crate sodiumoxide;

extern crate base64;
extern crate rpassword;

use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::*;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::*;
use sodiumoxide::randombytes::randombytes;

use std::fs::File;
use std::io::{self, BufWriter, Write};

pub mod parse_args;
pub mod perror;
pub mod types;

pub use crate::parse_args::*;
pub use crate::perror::*;
pub use crate::types::*;

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
        keynum_pk: KeynumPK { keynum, pk },
    };
    let s_struct = SeckeyStruct {
        sig_alg: SIGALG,
        kdf_alg: KDFALG,
        chk_alg: CHKALG,
        kdf_salt,
        kdf_opslimit_le: store_usize_le(ops_limit),
        kdf_memlimit_le: store_usize_le(mem_limit),
        keynum_sk: KeynumSK {
            keynum,
            sk,
            chk: [0; CHK_BYTES],
        },
    };
    (p_struct, s_struct)
}

pub fn get_password(prompt: &str) -> Result<String> {
    let pwd = rpassword::prompt_password_stdout(prompt)?;
    if pwd.is_empty() {
        println!("<empty>");
        Ok(pwd)
    } else if pwd.len() > PASSWORDMAXBYTES {
        Err(PError::new(
            ErrorKind::Misc,
            "passphrase can't exceed 1024 bytes lenght",
        ))
    } else {
        Ok(pwd)
    }
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
    [b1, b2, b3, b4, b5, b6, b7, b8]
}

pub fn load_usize_le(x: &[u8]) -> usize {
    (x[0] as usize)
        | (x[1] as usize) << 8
        | (x[2] as usize) << 16
        | (x[3] as usize) << 24
        | (x[4] as usize) << 32
        | (x[5] as usize) << 40
        | (x[6] as usize) << 48
        | (x[7] as usize) << 56
}
pub fn verify(
    pk_key: PubkeyStruct,
    sig: SigStruct,
    global_sig: &[u8],
    trusted_comment: &[u8],
    message: &[u8],
    quiet: bool,
    output: bool,
) -> Result<()> {
    if sig.keynum != pk_key.keynum_pk.keynum {
        return Err(PError::new(
            ErrorKind::Verify,
            format!(
                "Signature key id: {:X} is different from public key: {:X}",
                load_usize_le(&sig.keynum[..]),
                load_usize_le(&pk_key.keynum_pk.keynum[..])
            ),
        ));
    }
    Signature::from_slice(&sig.sig)
        .ok_or_else(|| {
            PError::new(
                ErrorKind::Verify,
                "Couldn't compose message file signature from bytes",
            )
        })
        .and_then(|signature| {
            PublicKey::from_slice(&pk_key.keynum_pk.pk)
                .ok_or_else(|| {
                    PError::new(
                        ErrorKind::Verify,
                        "Couldn't compose a public key from bytes",
                    )
                })
                .and_then(|pk| {
                    if sign::verify_detached(&signature, &message, &pk) {
                        Ok(pk)
                    } else {
                        Err(PError::new(
                            ErrorKind::Verify,
                            "Signature verification failed",
                        ))
                    }
                })
                .and_then(|pk| {
                    Signature::from_slice(&global_sig[..])
                        .ok_or_else(|| {
                            PError::new(
                                ErrorKind::Verify,
                                "Couldn't compose trusted comment signature from bytes",
                            )
                        })
                        .and_then(|global_sig| {
                            if sign::verify_detached(&global_sig, &trusted_comment, &pk) {
                                let just_comment =
                                    String::from_utf8(trusted_comment[SIGNATUREBYTES..].to_vec())?;
                                if !quiet {
                                    println!("Signature and comment signature verified");
                                    println!("Trusted comment: {}", just_comment);
                                }
                                if output {
                                    print!("{}", String::from_utf8_lossy(&message[..]));
                                }
                                Ok(())
                            } else {
                                Err(PError::new(
                                    ErrorKind::Verify,
                                    "Comment signature verification \
                                     failed",
                                ))
                            }
                        })
                })
        })
}

pub fn sign<W>(
    sk_key: SeckeyStruct,
    pk_key: Option<PubkeyStruct>,
    mut sig_buf: W,
    message: &[u8],
    hashed: bool,
    trusted_comment: &str,
    untrusted_comment: &str,
) -> Result<()>
where
    W: Write,
{
    let mut sig_str = SigStruct::default();
    if !hashed {
        sig_str.sig_alg = sk_key.sig_alg;
    } else {
        sig_str.sig_alg = SIGALG_HASHED;
    }
    sig_str.keynum.copy_from_slice(&sk_key.keynum_sk.keynum[..]);

    let sk = SecretKey::from_slice(&sk_key.keynum_sk.sk)
        .ok_or_else(|| PError::new(ErrorKind::Sign, "Couldn't generate secret key from bytes"))?;

    let signature = sodiumoxide::crypto::sign::sign_detached(message, &sk);

    sig_str.sig.copy_from_slice(&signature[..]);

    let mut sig_and_trust_comment: Vec<u8> = vec![];
    sig_and_trust_comment.extend(sig_str.sig.iter());
    sig_and_trust_comment.extend(trusted_comment.as_bytes().iter());

    let global_sig = sodiumoxide::crypto::sign::sign_detached(&sig_and_trust_comment, &sk);

    if let Some(pk_str) = pk_key {
        PublicKey::from_slice(&pk_str.keynum_pk.pk[..])
            .ok_or_else(|| PError::new(ErrorKind::Sign, "failed to obtain public key from bytes"))
            .and_then(|pk| {
                if !sodiumoxide::crypto::sign::verify_detached(
                    &global_sig,
                    &sig_and_trust_comment,
                    &pk,
                ) {
                    Err(PError::new(
                        ErrorKind::Verify,
                        format!(
                            "Could not verify signature with the \
                             provided public key ID: {:X}",
                            load_usize_le(&pk_str.keynum_pk.keynum[..])
                        ),
                    ))
                } else {
                    println!(
                        "\nSignature checked with the public key ID: {:X}",
                        load_usize_le(&pk_str.keynum_pk.keynum[..])
                    );
                    Ok(())
                }
            })?;
    }

    writeln!(sig_buf, "{}", untrusted_comment)?;
    writeln!(sig_buf, "{}", base64::encode(&sig_str.bytes()))?;
    writeln!(sig_buf, "{}{}", TRUSTED_COMMENT_PREFIX, trusted_comment)?;
    writeln!(sig_buf, "{}", base64::encode(&global_sig[..]))?;
    sig_buf.flush()?;
    Ok(())
}

pub fn generate(
    mut pk_file: BufWriter<File>,
    mut sk_file: BufWriter<File>,
    comment: Option<&str>,
) -> Result<(PubkeyStruct, SeckeyStruct)> {
    let (pk_str, mut sk_str) = gen_keystruct();
    sk_str
        .write_checksum()
        .map_err(|_| PError::new(ErrorKind::Generate, "failed to hash and write checksum!"))?;
    writeln!(
        io::stdout(),
        "Please enter a password to protect the secret key."
    )?;
    let pwd = get_password("Password: ")?;
    let pwd2 = get_password("Password (one more time): ")?;
    if pwd != pwd2 {
        return Err(PError::new(ErrorKind::Generate, "passwords don't match!"));
    }

    write!(
        io::stdout(),
        "Deriving a key from the password in order to encrypt the secret key... "
    )
    .map_err(|e| PError::new(ErrorKind::Io, e))
    .and_then(|_| {
        io::stdout().flush()?;
        derive_and_crypt(&mut sk_str, &pwd.as_bytes())
    })
    .and(writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e)))?;

    write!(pk_file, "{}rsign2 public key: ", COMMENT_PREFIX)?;
    writeln!(pk_file, "{:X}", load_usize_le(&pk_str.keynum_pk.keynum[..]))?;
    writeln!(pk_file, "{}", base64::encode(&pk_str.bytes()))?;
    pk_file.flush()?;

    write!(sk_file, "{}", COMMENT_PREFIX)?;
    if let Some(comment) = comment {
        writeln!(sk_file, "{}", comment)?;
    } else {
        writeln!(sk_file, "{}", SECRETKEY_DEFAULT_COMMENT)?;
    }
    writeln!(sk_file, "{}", base64::encode(&sk_str.bytes()))?;
    sk_file.flush()?;

    Ok((pk_str, sk_str))
}

pub fn derive_and_crypt(sk_str: &mut SeckeyStruct, pwd: &[u8]) -> Result<()> {
    let mut stream = [0u8; CHK_BYTES + SECRETKEYBYTES + KEYNUMBYTES];
    pwhash::Salt::from_slice(&sk_str.kdf_salt)
        .ok_or_else(|| PError::new(ErrorKind::Misc, "failed to generate Salt from random bytes"))
        .and_then(|salt| {
            pwhash::derive_key(
                &mut stream,
                &pwd,
                &salt,
                OpsLimit(load_usize_le(&sk_str.kdf_opslimit_le)),
                MemLimit(load_usize_le(&sk_str.kdf_memlimit_le)),
            )
            .map_err(|_| PError::new(ErrorKind::Misc, "failed to derive key from password"))
        })?;
    sk_str.xor_keynum(&stream);
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn byte_array_store() {
        use crate::store_usize_le;
        assert_eq!([0xFF, 0, 0, 0, 0, 0, 0, 0], store_usize_le(0xFF));
    }
    #[test]
    fn byte_array_load() {
        use crate::load_usize_le;
        assert_eq!(255, load_usize_le(&[0xFF, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn pk_key_struct_conversion() {
        use crate::gen_keystruct;
        use crate::PubkeyStruct;
        let (pk, _) = gen_keystruct();
        assert_eq!(pk, PubkeyStruct::from(&pk.bytes()).unwrap());
    }
    #[test]
    fn sk_key_struct_conversion() {
        use crate::gen_keystruct;
        use crate::SeckeyStruct;
        let (_, sk) = gen_keystruct();
        assert_eq!(sk, SeckeyStruct::from(&sk.bytes()).unwrap());
    }

    #[test]
    fn xor_keynum() {
        use crate::gen_keystruct;
        use crate::randombytes;
        let (_, mut sk) = gen_keystruct();
        let key = randombytes(sk.keynum_sk.len());
        let original_keynum = sk.keynum_sk.clone();
        sk.xor_keynum(&key);
        assert_ne!(original_keynum, sk.keynum_sk);
        sk.xor_keynum(&key);
        assert_eq!(original_keynum, sk.keynum_sk);
    }
    #[test]
    fn sk_checksum() {
        use crate::gen_keystruct;
        let (_, mut sk) = gen_keystruct();
        assert!(sk.write_checksum().is_ok());
        assert_eq!(sk.keynum_sk.chk.to_vec(), sk.read_checksum().unwrap());
    }
}
