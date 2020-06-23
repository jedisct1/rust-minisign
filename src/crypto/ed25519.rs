use super::curve25519::{ge_scalarmult_base, is_identity, sc_muladd, sc_reduce, GeP2, GeP3};
use super::sha512;

static L: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

fn check_s_lt_l(s: &[u8]) -> bool {
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
        if i == 0 {
            break;
        } else {
            i -= 1;
        }
    }
    c == 0
}

pub fn verify(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    if check_s_lt_l(&signature[32..64]) || is_identity(public_key) {
        return false;
    }
    let a = match GeP3::from_bytes_negate_vartime(public_key) {
        Some(g) => g,
        None => {
            return false;
        }
    };
    if public_key.iter().fold(0, |acc, x| acc | x) == 0 {
        return false;
    }

    let mut hasher = sha512::Hash::new();
    hasher.update(&signature[0..32]);
    hasher.update(public_key);
    hasher.update(message);
    let mut hash = hasher.finalize();
    sc_reduce(&mut hash);

    let r = GeP2::double_scalarmult_vartime(hash.as_ref(), a, &signature[32..64]);
    r.to_bytes()
        .as_ref()
        .iter()
        .zip(signature.iter())
        .fold(0, |acc, (x, y)| acc | (x ^ y))
        == 0
}

pub fn keypair(seed: &[u8]) -> ([u8; 64], [u8; 32]) {
    let mut secret: [u8; 64] = {
        let mut hash_output = sha512::Hash::hash(seed);
        hash_output[0] &= 248;
        hash_output[31] &= 63;
        hash_output[31] |= 64;
        hash_output
    };
    let a = ge_scalarmult_base(&secret[0..32]);
    let public_key = a.to_bytes();
    for (dest, src) in (&mut secret[32..64]).iter_mut().zip(public_key.iter()) {
        *dest = *src;
    }
    for (dest, src) in (&mut secret[0..32]).iter_mut().zip(seed.iter()) {
        *dest = *src;
    }
    (secret, public_key)
}

pub fn signature(message: &[u8], secret_key: &[u8], z: Option<&[u8]>) -> [u8; 64] {
    let seed = &secret_key[0..32];
    let public_key = &secret_key[32..64];
    let az: [u8; 64] = {
        let mut hash_output = sha512::Hash::hash(seed);
        hash_output[0] &= 248;
        hash_output[31] &= 63;
        hash_output[31] |= 64;
        hash_output
    };
    let nonce = {
        let mut hasher = sha512::Hash::new();
        if let Some(z) = z {
            hasher.update(z);
            hasher.update(&az[..]);
        } else {
            hasher.update(&az[32..64]);
        }
        hasher.update(message);
        let mut hash_output = hasher.finalize();
        sc_reduce(&mut hash_output[0..64]);
        hash_output
    };
    let mut signature: [u8; 64] = [0; 64];
    let r: GeP3 = ge_scalarmult_base(&nonce[0..32]);
    for (result_byte, source_byte) in (&mut signature[0..32]).iter_mut().zip(r.to_bytes().iter()) {
        *result_byte = *source_byte;
    }
    for (result_byte, source_byte) in (&mut signature[32..64]).iter_mut().zip(public_key.iter()) {
        *result_byte = *source_byte;
    }
    {
        let mut hasher = sha512::Hash::new();
        hasher.update(signature.as_ref());
        hasher.update(message);
        let mut hram = hasher.finalize();
        sc_reduce(&mut hram);
        sc_muladd(
            &mut signature[32..64],
            &hram[0..32],
            &az[0..32],
            &nonce[0..32],
        );
    }
    signature
}
