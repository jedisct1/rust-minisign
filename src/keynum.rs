use crate::constants::*;
use crate::crypto::util::fixed_time_eq;
use std::cmp;
use std::fmt::{self, Formatter};

#[derive(Debug, Clone)]
pub(crate) struct KeynumPK {
    pub(crate) keynum: [u8; KEYNUM_BYTES],
    pub(crate) pk: [u8; PUBLICKEY_BYTES],
}

impl cmp::PartialEq for KeynumPK {
    fn eq(&self, other: &KeynumPK) -> bool {
        self.keynum == other.keynum && fixed_time_eq(&self.pk, &other.pk)
    }
}
impl cmp::Eq for KeynumPK {}

#[derive(Clone)]
pub(crate) struct KeynumSK {
    pub keynum: [u8; KEYNUM_BYTES],
    pub sk: [u8; SECRETKEY_BYTES],
    pub chk: [u8; CHK_BYTES],
}

#[allow(clippy::len_without_is_empty, dead_code)]
impl KeynumSK {
    pub fn len(&self) -> usize {
        std::mem::size_of::<KeynumSK>()
    }
}

impl fmt::Debug for KeynumSK {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.sk.iter() {
            write!(f, "{:x}", byte)?
        }
        Ok(())
    }
}

impl cmp::PartialEq for KeynumSK {
    fn eq(&self, other: &KeynumSK) -> bool {
        self.keynum == other.keynum && fixed_time_eq(&self.sk, &other.sk)
    }
}
impl cmp::Eq for KeynumSK {}
