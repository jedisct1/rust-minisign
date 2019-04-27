extern crate base64;
extern crate libc;
extern crate rand;
extern crate rpassword;
extern crate scrypt;
extern crate sodiumoxide;

use rand::{thread_rng, RngCore};
use scrypt::ScryptParams;
use sodiumoxide::crypto::sign::{self, gen_keypair, PublicKey, SecretKey, Signature};
use std::cmp;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::u64;

pub mod crypto;
pub mod parse_args;
pub mod perror;
pub mod types;

pub use crate::parse_args::*;
pub use crate::perror::*;
pub use crate::types::*;

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

pub fn gen_keystruct() -> (PubkeyStruct, SeckeyStruct) {
    let (pk, sk) = gen_keypair();
    let SecretKey(sk) = sk;
    let PublicKey(pk) = pk;

    let mut rng = thread_rng();
    let mut keynum = [0u8; KEYNUMBYTES];
    rng.fill_bytes(&mut keynum);
    let mut kdf_salt = [0u8; KDF_SALTBYTES];
    rng.fill_bytes(&mut kdf_salt);

    let opslimit = OPSLIMIT;
    let memlimit = MEMLIMIT;

    let p_struct = PubkeyStruct {
        sig_alg: SIGALG,
        keynum_pk: KeynumPK { keynum, pk },
    };
    let s_struct = SeckeyStruct {
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

pub fn store_u64_le(x: u64) -> [u8; 8] {
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
pub fn load_u64_le(x: &[u8]) -> u64 {
    (x[0] as u64)
        | (x[1] as u64) << 8
        | (x[2] as u64) << 16
        | (x[3] as u64) << 24
        | (x[4] as u64) << 32
        | (x[5] as u64) << 40
        | (x[6] as u64) << 48
        | (x[7] as u64) << 56
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
                load_u64_le(&sig.keynum[..]),
                load_u64_le(&pk_key.keynum_pk.keynum[..])
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
                            load_u64_le(&pk_str.keynum_pk.keynum[..])
                        ),
                    ))
                } else {
                    println!(
                        "\nSignature checked with the public key ID: {:X}",
                        load_u64_le(&pk_str.keynum_pk.keynum[..])
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
    writeln!(pk_file, "{:X}", load_u64_le(&pk_str.keynum_pk.keynum[..]))?;
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
    let opslimit = load_u64_le(&sk_str.kdf_opslimit_le);
    let memlimit = load_u64_le(&sk_str.kdf_memlimit_le) as usize;
    let params = raw_scrypt_params(memlimit, opslimit)?;
    scrypt::scrypt(&pwd, &sk_str.kdf_salt, &params, &mut stream)?;
    sk_str.xor_keynum(&stream);
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
        use rand::{thread_rng, RngCore};

        let (_, mut sk) = gen_keystruct();
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
        use crate::gen_keystruct;

        let (_, mut sk) = gen_keystruct();
        assert!(sk.write_checksum().is_ok());
        assert_eq!(sk.keynum_sk.chk.to_vec(), sk.read_checksum().unwrap());
    }
}
