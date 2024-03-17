#![doc = include_str!("../README.md")]
#![allow(
    clippy::inherent_to_string,
    clippy::wrong_self_convention,
    clippy::derivable_impls,
    clippy::field_reassign_with_default,
    clippy::vec_init_then_push
)]

mod base64;
mod constants;
mod crypto;
mod errors;
mod helpers;
mod keynum;
mod keypair;
mod public_key;
mod secret_key;
mod signature;
mod signature_bones;
mod signature_box;

#[cfg(test)]
mod tests;

use std::io::{self, Read, Seek, Write};

use getrandom::getrandom;

pub use crate::constants::*;
use crate::crypto::blake2b::Blake2b;
use crate::crypto::ed25519;
pub use crate::errors::*;
use crate::helpers::*;
pub use crate::keypair::*;
pub use crate::public_key::*;
pub use crate::secret_key::*;
use crate::signature::*;
pub use crate::signature_bones::*;
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
        state.update(&buf[..len]);
    }
    state.finalize(&mut h);
    Ok(h)
}

/// Compute a signature.
///
/// # Arguments
///
/// * `pk` - an optional public key. If provided, it must be the public key from
///   the original key pair.
/// * `sk` - the secret key
/// * `data_reader` - the source of the data to be signed
/// * `trusted_comment` - overrides the default trusted comment
/// * `untrusted_comment` - overrides the default untrusted comment
pub fn sign<R>(
    pk: Option<&PublicKey>,
    sk: &SecretKey,
    mut data_reader: R,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<SignatureBox>
where
    R: Read,
{
    let data = prehash(&mut data_reader)?;
    let trusted_comment = match trusted_comment {
        Some(trusted_comment) => trusted_comment.to_string(),
        None => format!("timestamp:{}", unix_timestamp()),
    };
    let untrusted_comment = match untrusted_comment {
        Some(untrusted_comment) => untrusted_comment.to_string(),
        None => DEFAULT_COMMENT.to_string(),
    };
    let mut signature = Signature::default();
    signature.sig_alg = SIGALG_PREHASHED;

    signature.keynum.copy_from_slice(&sk.keynum_sk.keynum[..]);
    let mut z = vec![0; 64];
    getrandom(&mut z)?;
    let signature_raw = ed25519::signature(&data, &sk.keynum_sk.sk, Some(&z));
    signature.sig.copy_from_slice(&signature_raw[..]);

    let mut sig_and_trusted_comment: Vec<u8> = vec![];
    sig_and_trusted_comment.extend(signature.sig.iter());
    sig_and_trusted_comment.extend(trusted_comment.as_bytes().iter());

    getrandom(&mut z)?;
    let global_sig = ed25519::signature(&sig_and_trusted_comment, &sk.keynum_sk.sk, Some(&z));
    if let Some(pk) = pk {
        if !ed25519::verify(&sig_and_trusted_comment, &pk.keynum_pk.pk[..], &global_sig) {
            return Err(PError::new(
                ErrorKind::Verify,
                format!(
                    "Could not verify signature with the provided public key ID: {:016X}",
                    load_u64_le(&pk.keynum_pk.keynum[..])
                ),
            ));
        }
    }
    let signature_box = SignatureBox {
        untrusted_comment,
        signature,
        sig_and_trusted_comment: Some(sig_and_trusted_comment),
        global_sig: Some(global_sig.to_vec()),
        is_prehashed: true,
    };
    Ok(signature_box)
}

/// Verify a signature using a public key.
///
/// # Arguments
///
/// * `pk` - the public key
/// * `signature_box` - the signature and its metadata
/// * `data_reader` - the data source
/// * `quiet` - use `false` to output status information to `stderr`
/// * `output` - use `true` to output a copy of the data to `stdout`
/// * `allow_legacy` - accept signatures from legacy versions of minisign
pub fn verify<R>(
    pk: &PublicKey,
    signature_box: &SignatureBox,
    mut data_reader: R,
    quiet: bool,
    output: bool,
    allow_legacy: bool,
) -> Result<()>
where
    R: Read + Seek,
{
    let data = if signature_box.is_prehashed() {
        prehash(&mut data_reader)?
    } else {
        let mut data = vec![];
        data_reader.read_to_end(&mut data)?;
        data
    };
    let sig = &signature_box.signature;
    if sig.keynum != pk.keynum_pk.keynum {
        return Err(PError::new(
            ErrorKind::Verify,
            format!(
                "Signature key id: {:016X} is different from public key: {:016X}",
                load_u64_le(&sig.keynum[..]),
                load_u64_le(&pk.keynum_pk.keynum[..])
            ),
        ));
    }
    if !allow_legacy && !signature_box.is_prehashed() {
        return Err(PError::new(
            ErrorKind::Verify,
            "Legacy signatures are not accepted",
        ));
    }
    if !ed25519::verify(&data, &pk.keynum_pk.pk, &sig.sig) {
        return Err(PError::new(
            ErrorKind::Verify,
            "Signature verification failed",
        ));
    }
    match (
        &signature_box.sig_and_trusted_comment,
        &signature_box.global_sig,
    ) {
        (Some(sig_and_trusted_comment), Some(global_sig)) => {
            if !ed25519::verify(sig_and_trusted_comment, &pk.keynum_pk.pk, &global_sig[..]) {
                return Err(PError::new(
                    ErrorKind::Verify,
                    "Comment signature verification failed",
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(PError::new(
                ErrorKind::Verify,
                "Inconsistent signature presence for trusted comment presence",
            ))
        }
    };
    if !quiet {
        eprintln!("Signature and comment signature verified");
        if signature_box.global_sig.is_some() {
            eprintln!("Trusted comment: {}", signature_box.trusted_comment()?);
        }
    }
    if output {
        data_reader.rewind()?;
        let mut buf = vec![0; 65536];
        loop {
            let len = data_reader.read(&mut buf)?;
            if len == 0 {
                break;
            }
            io::stdout().write_all(&buf[..len])?;
        }
        io::stdout().flush()?;
    }
    Ok(())
}
