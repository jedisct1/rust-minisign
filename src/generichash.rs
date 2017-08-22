extern crate libsodium_sys as ffi;

use sodiumoxide::randombytes::randombytes_into;
use libc::c_ulonglong;
use std::ptr::null;

pub const BYTES_MIN: usize = ffi::crypto_generichash_blake2b_BYTES_MIN;
pub const BYTES_MAX: usize = ffi::crypto_generichash_blake2b_BYTES_MAX;
pub const BYTES: usize = ffi::crypto_generichash_blake2b_BYTES;
pub const KEYBYTES_MIN: usize = ffi::crypto_generichash_blake2b_KEYBYTES_MIN;
pub const KEYBYTES_MAX: usize = ffi::crypto_generichash_blake2b_KEYBYTES_MAX;
pub const KEYBYTES: usize = ffi::crypto_generichash_blake2b_KEYBYTES;
pub const HASH_SALTBYTES: usize = ffi::crypto_generichash_blake2b_SALTBYTES;
pub const PERSONALBYTES: usize = ffi::crypto_generichash_blake2b_PERSONALBYTES;

new_type! {
    /// `GenericHash` result produced by generichash()  
    public GenericHash(BYTES);
}


new_type! {
     public Key(KEYBYTES);
 }

pub fn hash(message: &[u8], Key(ref key): Key) -> Result<GenericHash, ()> {
    let mut out = GenericHash([0; BYTES]);
    if unsafe {
           let GenericHash(ref mut hash_) = out;
           ffi::crypto_generichash(hash_.as_mut_ptr(),
                                   BYTES,
                                   message.as_ptr(),
                                   message.len() as c_ulonglong,
                                   key.as_ptr(),
                                   key.len())

       } == 0 {
        Ok(out)
    } else {
        Err(())
    }
}

pub fn keygen() -> Key {
    let mut key = Key([0; KEYBYTES]);
    {
        let Key(ref mut kb) = key;
        randombytes_into(kb);
    }
    key
}

pub type GenericState = ffi::crypto_generichash_state;

pub fn init(state: *mut GenericState) -> Result<(), ()> {
    if unsafe { ffi::crypto_generichash_init(state, null(), 0, BYTES) } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn update(state: *mut GenericState, chunk: &[u8]) -> Result<(), ()> {
    if unsafe {
           ffi::crypto_generichash_update(state, chunk.as_ptr(), chunk.len() as c_ulonglong)
       } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

pub fn finalize(state: *mut GenericState) -> Result<GenericHash, ()> {
    let mut out = GenericHash([0; BYTES]);
    if unsafe {
           let GenericHash(ref mut hash_) = out;
           ffi::crypto_generichash_final(state, hash_.as_mut_ptr(), hash_.len())
       } == 0 {
        Ok(out)
    } else {
        Err(())
    }
}
