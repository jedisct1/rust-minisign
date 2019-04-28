extern crate base64;
extern crate rand;
extern crate rpassword;
extern crate scrypt;

mod constants;
mod crypto;
mod errors;
mod helpers;
mod keynum;
mod keypair;
mod public_key;
mod secret_key;
mod signature;
mod signature_box;

#[cfg(test)]
mod tests;

use crate::crypto::blake2b::Blake2b;
use crate::crypto::digest::Digest;
use crate::crypto::ed25519;
use crate::helpers::*;
use crate::signature::*;
use rand::{thread_rng, RngCore};
use std::io::{self, Read, Seek, SeekFrom, Write};

pub use crate::constants::*;
pub use crate::errors::*;
pub use crate::keypair::*;
pub use crate::public_key::*;
pub use crate::secret_key::*;
pub use crate::signature_box::*;

fn prehash<R>(data_reader: &mut R) -> Result<Vec<u8>>
where
    R: Read,
{
    let mut h = vec![0u8; PREHASH_BYTES];
    let mut buf = vec![0u8; 65536];
    let mut state = Blake2b::new(PREHASH_BYTES);
    loop {
        let len = data_reader.read(&mut buf)?;
        if len == 0 {
            break;
        }
        state.input(&buf);
    }
    state.result(&mut h);
    Ok(h)
}

pub fn sign<W, R>(
    mut signature_box_writer: W,
    pk: Option<&PublicKey>,
    sk: &SecretKey,
    mut data_reader: R,
    hashed: bool,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<()>
where
    W: Write,
    R: Read,
{
    let data = if hashed {
        prehash(&mut data_reader)?
    } else {
        let mut data = vec![];
        data_reader.read_to_end(&mut data)?;
        data
    };
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
    let signature_raw = ed25519::signature(&data, &sk.keynum_sk.sk, Some(&z));
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

pub fn verify<R>(
    pk: &PublicKey,
    signature_box: &SignatureBox,
    mut data_reader: R,
    quiet: bool,
    output: bool,
) -> Result<()>
where
    R: Read + Seek,
{
    let data = if signature_box.is_hashed() {
        prehash(&mut data_reader)?
    } else {
        let mut data = vec![];
        data_reader.read_to_end(&mut data)?;
        data
    };
    let sig = &signature_box.signature;
    let global_sig = &signature_box.global_sig[..];
    let sig_and_trusted_comment = &signature_box.sig_and_trusted_comment;
    if sig.keynum != pk.keynum_pk.keynum {
        return Err(PError::new(
            ErrorKind::Verify,
            format!(
                "Signature key id: {:X} is different from public key: {:X}",
                load_u64_le(&sig.keynum[..]),
                load_u64_le(&pk.keynum_pk.keynum[..])
            ),
        ));
    }
    if !ed25519::verify(&data, &pk.keynum_pk.pk, &sig.sig) {
        Err(PError::new(
            ErrorKind::Verify,
            "Signature verification failed",
        ))?
    }
    if !ed25519::verify(&sig_and_trusted_comment, &pk.keynum_pk.pk, &global_sig) {
        Err(PError::new(
            ErrorKind::Verify,
            "Comment signature verification failed",
        ))?
    }
    if !quiet {
        eprintln!("Signature and comment signature verified");
        eprintln!("Trusted comment: {}", signature_box.trusted_comment()?);
    }
    if output {
        data_reader.seek(SeekFrom::Start(0))?;
        let mut buf = vec![0; 65536];
        loop {
            let len = data_reader.read(&mut buf)?;
            if len == 0 {
                break;
            }
            io::stdout().write_all(&buf[..len])?;
        }
    }
    Ok(())
}
