//! Minisign is a public key signature system for arbitrary large files.
//!
//! This implementation is fully compatible with the reference implementation.
//!
//! # Example
//!
//! ```rust
//!     extern crate minisign;
//!     use minisign::{KeyPair, PublicKeyBox, SecretKeyBox, SignatureBox};
//!     use std::io::Cursor;
//!
//!     // -------------------- KEY GENERATION --------------------
//!
//!     // Generate and return a new key pair
//!     // The key is encrypted using a password.
//!     // If `None` is given, the password will be asked for interactively.
//!     let KeyPair { pk, sk } =
//!         KeyPair::generate_encrypted_keypair(Some("key password".to_string())).unwrap();
//!
//!     // In order to be stored to disk, keys have to be converted to "boxes".
//!     // A box is just a container, with some metadata about its content.
//!     // Boxes can be converted to/from strings, making them convenient to use for storage.
//!     let pk_box_str = pk.to_box().unwrap().to_string();
//!     let sk_box_str = sk
//!         .to_box(None) // Optional comment about the key
//!         .unwrap()
//!         .to_string();
//!
//!     // `pk_box_str` and sk_box_str` can now be saved to disk.
//!     // This is a long-term key pair, that can be used to sign as many files as needed.
//!     // For conveniency, the `KeyPair::generate_and_write_encrypted_keypair()` function
//!     // is available: it generates a new key pair, and saves it to disk (or any `Writer`)
//!     // before returning it.
//!
//!     // -------------------- SIGNING DATA WITH AN EXISTING SECRET KEY --------------------
//!
//!     // Assuming that `sk_box_str` is something we previously saved and just reloaded,
//!     // it can be converted back to a secret key box:
//!     let sk_box = SecretKeyBox::from_string(&sk_box_str).unwrap();
//!
//!     // and the box can be opened using the password to reveal the original secret key:
//!     let sk = sk_box
//!         .into_secret_key(Some("key password".to_string()))
//!         .unwrap();
//!
//!     // Now, we can use the secret key to sign anything.
//!     let data = b"lorem ipsum";
//!     let data_reader = Cursor::new(data);
//!     let signature_box = minisign::sign(None, &sk, data_reader, false, None, None).unwrap();
//!
//!     // We have a signature! Let's inspect it a little bit.
//!     println!(
//!         "Untrusted comment: [{}]",
//!         signature_box.untrusted_comment().unwrap()
//!     );
//!     println!(
//!         "Trusted comment: [{}]",
//!         signature_box.trusted_comment().unwrap()
//!     );
//!
//!     // -------------------- SIGNATURE VERIFICATION WITH A PUBLIC KEY --------------------
//!
//!     // Converting the signature box to a string in order to save it is easy.
//!     let signature_box_str = signature_box.into_string();
//!
//!     // Now, let's verify the signature.
//!     // Assuming we just loaded it into `signature_box_str`, get the box back.
//!     let signature_box = SignatureBox::from_string(&signature_box_str).unwrap();
//!
//!     // Load the public key from the string.
//!     let pk_box = PublicKeyBox::from_string(&pk_box_str).unwrap();
//!     let pk = pk_box.into_public_key().unwrap();
//!
//!     // And verify the data.
//!     let data_reader = Cursor::new(data);
//!     let verified = minisign::verify(&pk, &signature_box, data_reader, true, false);
//!     match verified {
//!         Ok(()) => println!("Success!"),
//!         Err(_) => println!("Verification failed"),
//!     };
//!```

#![allow(clippy::inherent_to_string)]

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

use crate::crypto::blake2b::Blake2b;
use crate::crypto::ed25519;
use crate::helpers::*;
use crate::signature::*;
use getrandom::getrandom;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub use crate::constants::*;
pub use crate::errors::*;
pub use crate::keypair::*;
pub use crate::public_key::*;
pub use crate::secret_key::*;
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
/// * `pk` - an optional public key. If provided, it must be the public key from the original key pair.
/// * `sk` - the secret key
/// * `data_reader` - the source of the data to be signed
/// * `prehashed` - use prehashing. Recommended for large files, enabled by default if the data size exceeds 1 GiB.
/// * `trusted_comment` - overrides the default trusted comment
/// * `untrusted_comment` - overrides the default untrusted comment
pub fn sign<R>(
    pk: Option<&PublicKey>,
    sk: &SecretKey,
    mut data_reader: R,
    prehashed: bool,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<SignatureBox>
where
    R: Read,
{
    let data = if prehashed {
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
        Some(untrusted_comment) => untrusted_comment.to_string(),
        None => DEFAULT_COMMENT.to_string(),
    };
    let mut signature = Signature::default();
    if !prehashed {
        signature.sig_alg = sk.sig_alg;
    } else {
        signature.sig_alg = SIGALG_PREHASHED;
    }
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
                    "Could not verify signature with the \
                     provided public key ID: {:X}",
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
        is_prehashed: prehashed,
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
                "Signature key id: {:X} is different from public key: {:X}",
                load_u64_le(&sig.keynum[..]),
                load_u64_le(&pk.keynum_pk.keynum[..])
            ),
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
            if !ed25519::verify(&sig_and_trusted_comment, &pk.keynum_pk.pk, &global_sig[..]) {
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
        data_reader.seek(SeekFrom::Start(0))?;
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
