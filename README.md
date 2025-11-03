![CI status](https://github.com/jedisct1/rust-minisign/workflows/Rust/badge.svg)
[![Last version](https://img.shields.io/crates/v/minisign.svg)](https://crates.io/crates/minisign)
[![Documentation](https://docs.rs/minisign/badge.svg)](https://docs.rs/minisign)

# rust-minisign

A pure Rust implementation of the [Minisign](https://jedisct1.github.io/minisign/) signature system.

This is a crate designed to be used by applications.

For a command-line tool reimplementing the Minisign utility in Rust, and based on this crate, check out [rsign2](https://github.com/jedisct1/rsign2).

For a minimal crate that only verifies signatures, check out [minisign-verify](https://github.com/jedisct1/rust-minisign-verify).

## API documentation

[API documentation on docs.rs](https://docs.rs/minisign)

## Example

```rust
use minisign::{KeyPair, PublicKeyBox, SecretKeyBox, SignatureBox};
use std::io::Cursor;

// Generate and return a new key pair
// The key is encrypted using a password.
// If `None` is given, the password will be asked for interactively.
let KeyPair { pk, sk } =
    KeyPair::generate_encrypted_keypair(Some("key password".to_string())).unwrap();

// In order to be stored to disk, keys have to be converted to "boxes".
// A box is just a container, with some metadata about its content.
// Boxes can be converted to/from strings, making them convenient to use for storage.
let pk_box_str = pk.to_box().unwrap().to_string();
let sk_box_str = sk
    .to_box(None) // Optional comment about the key
    .unwrap()
    .to_string();

// `pk_box_str` and `sk_box_str` can now be saved to disk.
// This is a long-term key pair, that can be used to sign as many files as needed.
// For convenience, the `KeyPair::generate_and_write_encrypted_keypair()` function
// is available: it generates a new key pair, and saves it to disk (or any `Writer`)
// before returning it.

// Assuming that `sk_box_str` is something we previously saved and just reloaded,
// it can be converted back to a secret key box:
let sk_box = SecretKeyBox::from_string(&sk_box_str).unwrap();

// and the box can be opened using the password to reveal the original secret key:
let sk = sk_box
    .into_secret_key(Some("key password".to_string()))
    .unwrap();

// Now, we can use the secret key to sign anything.
let data = b"lorem ipsum";
let data_reader = Cursor::new(data);
let signature_box = minisign::sign(None, &sk, data_reader, None, None).unwrap();

// We have a signature! Let's inspect it a little bit.
println!(
    "Untrusted comment: [{}]",
    signature_box.untrusted_comment().unwrap()
);
println!(
    "Trusted comment: [{}]",
    signature_box.trusted_comment().unwrap()
);

// Converting the signature box to a string in order to save it is easy.
let signature_box_str = signature_box.into_string();

// Now, let's verify the signature.
// Assuming we just loaded it into `signature_box_str`, get the box back.
let signature_box = SignatureBox::from_string(&signature_box_str).unwrap();

// Load the public key from the string.
let pk_box = PublicKeyBox::from_string(&pk_box_str).unwrap();
let pk = pk_box.into_public_key().unwrap();

// And verify the data.
let data_reader = Cursor::new(data);
let verified = minisign::verify(&pk, &signature_box, data_reader, true, false, false);
match verified {
    Ok(()) => println!("Success!"),
    Err(_) => println!("Verification failed"),
};
```
