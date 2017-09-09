extern crate libsodium_sys as ffi;

use sodiumoxide::randombytes::randombytes_into;
use libc::c_ulonglong;
use std::ptr::null;
use perror::{PError, ErrorKind, Result};

pub const BYTES: usize = ffi::crypto_generichash_blake2b_BYTES;
pub const KEYBYTES: usize = ffi::crypto_generichash_blake2b_KEYBYTES;

pub struct GenericHash([u8;BYTES]);

impl Clone for GenericHash {
    fn clone(&self) -> GenericHash {
        let &GenericHash(v) = self;
        GenericHash(v)
    }
}

pub fn from_slice(bs: &[u8]) -> Option<GenericHash> {
    if bs.len() != BYTES {
        return None;
    }
    let mut n = GenericHash([0u8; BYTES]);
    {
        let GenericHash(ref mut b) = n;
        for (bi, &bsi) in b.iter_mut().zip(bs.iter()) {
            *bi = bsi
        }
    }
    Some(n)
}

impl AsRef<[u8]> for GenericHash{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}
impl ::std::cmp::PartialEq for GenericHash {
        fn eq(&self, &GenericHash(ref other): &GenericHash) -> bool {
            use sodiumoxide::utils::memcmp;
            let &GenericHash(ref this) = self;
            memcmp(this, other)
        }
    }

impl ::std::cmp::Eq for GenericHash {}

impl ::std::cmp::PartialOrd for GenericHash {
    #[inline]
    fn partial_cmp(&self,
                    other: &GenericHash) -> Option<::std::cmp::Ordering> {
        ::std::cmp::PartialOrd::partial_cmp(self.as_ref(), other.as_ref())
    }
    #[inline]
    fn lt(&self, other: &GenericHash) -> bool {
        ::std::cmp::PartialOrd::lt(self.as_ref(), other.as_ref())
    }
    #[inline]
    fn le(&self, other: &GenericHash) -> bool {
        ::std::cmp::PartialOrd::le(self.as_ref(), other.as_ref())
    }
    #[inline]
    fn ge(&self, other: &GenericHash) -> bool {
        ::std::cmp::PartialOrd::ge(self.as_ref(), other.as_ref())
    }
    #[inline]
    fn gt(&self, other: &GenericHash) -> bool {
        ::std::cmp::PartialOrd::gt(self.as_ref(), other.as_ref())
    }
}

impl ::std::ops::Index<::std::ops::Range<usize>> for GenericHash {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::Range<usize>) -> &[u8] {
        let &GenericHash(ref b) = self;
        b.index(_index)
    }
}
    
impl ::std::ops::Index<::std::ops::RangeTo<usize>> for GenericHash {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeTo<usize>) -> &[u8] {
        let &GenericHash(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for GenericHash {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFrom<usize>) -> &[u8] {
        let &GenericHash(ref b) = self;
        b.index(_index)
    }
}

impl ::std::ops::Index<::std::ops::RangeFull> for GenericHash {
    type Output = [u8];
    fn index(&self, _index: ::std::ops::RangeFull) -> &[u8] {
        let &GenericHash(ref b) = self;
        b.index(_index)
    }
}

impl ::std::cmp::Ord for GenericHash {
    #[inline]
    fn cmp(&self, other: &GenericHash) -> ::std::cmp::Ordering {
        ::std::cmp::Ord::cmp(self.as_ref(), other.as_ref())
    }
}

impl Drop for GenericHash {
    fn drop(&mut self) {
        use sodiumoxide::utils::memzero;
        let &mut GenericHash(ref mut v) = self;
        memzero(v);
    }
}
impl ::std::fmt::Debug for GenericHash {
    fn fmt(&self,
            formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(formatter, "{}(****)", stringify!(GenericHash))
    }
}    

pub struct Key([u8;KEYBYTES]);
pub fn hash(message: &[u8], Key(ref key): Key) -> Result<GenericHash> {
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
        Err(PError::new(ErrorKind::Hash, "failed to hash message"))
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

pub fn init(state: *mut GenericState) -> Result<()> {
    if unsafe { ffi::crypto_generichash_init(state, null(), 0, BYTES) } == 0 {
        Ok(())
    } else {
        Err(PError::new(ErrorKind::Hash,
                        "failed to initialize generichash state pointer"))
    }
}

pub fn update(state: *mut GenericState, chunk: &[u8]) -> Result<()> {
    if unsafe {
           ffi::crypto_generichash_update(state, chunk.as_ptr(), chunk.len() as c_ulonglong)
       } == 0 {
        Ok(())
    } else {
        Err(PError::new(ErrorKind::Hash,
                        "failed to update generichash state pointer"))
    }
}

pub fn finalize(state: *mut GenericState) -> Result<GenericHash> {
    let mut out = GenericHash([0; BYTES]);
    if unsafe {
           let GenericHash(ref mut hash_) = out;
           ffi::crypto_generichash_final(state, hash_.as_mut_ptr(), hash_.len())
       } == 0 {
        Ok(out)
    } else {
        Err(PError::new(ErrorKind::Hash, "failed to finalize hash state pointer"))
    }
}

mod tests {
     
    
    #[test]
    fn hash_with_key() {
        let message = b"Sphinx of black quartz, judge my vow.";
        let key = keygen();
        assert!(hash(&message[..], key).is_ok());
    }
    #[test]
    fn hash_detached() {
        let state_sz = unsafe { ffi::crypto_generichash_statebytes() };
        let message = b"Sphinx of black quartz, judge my vow.";
        let message2 = b"The five boxing wizards jump quickly";
        let mut state = vec![0u8;state_sz];
        let ptr = state.as_mut_ptr() as *mut ffi::crypto_generichash_state;

        assert!(init(ptr).is_ok());
        assert!(update(ptr, &message[..]).is_ok());
        assert!(update(ptr, &message2[..]).is_ok());
        assert!(finalize(ptr).is_ok());

    }
}
