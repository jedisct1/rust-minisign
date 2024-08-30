#![forbid(unsafe_code)]

use core::fmt::{self, Display};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The provided output buffer would be too small.
    Overflow,
    /// The input isn't valid for the given encoding.
    InvalidInput,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Overflow => write!(f, "Overflow"),
            Error::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

pub trait Encoder {
    /// Length of `bin_len` bytes after encoding.
    fn encoded_len(bin_len: usize) -> Result<usize, Error>;

    /// Encode `bin` into `encoded`.
    /// The output buffer can be larger than required; the returned slice is
    /// a view of the buffer with the correct length.
    fn encode<IN: AsRef<[u8]>>(encoded: &mut [u8], bin: IN) -> Result<&[u8], Error>;

    /// Encode `bin` as a `String`.
    fn encode_to_string<IN: AsRef<[u8]>>(bin: IN) -> Result<String, Error> {
        let mut encoded = vec![0u8; Self::encoded_len(bin.as_ref().len())?];
        let encoded_len = Self::encode(&mut encoded, bin)?.len();
        encoded.truncate(encoded_len);
        Ok(String::from_utf8(encoded).unwrap())
    }
}

pub trait Decoder {
    /// Decode `encoded` into `bin`.
    /// The output buffer can be larger than required; the returned slice is
    /// a view of the buffer with the correct length.
    fn decode<IN: AsRef<[u8]>>(bin: &mut [u8], encoded: IN) -> Result<&[u8], Error>;

    /// Decode `encoded` into a `Vec<u8>`.
    fn decode_to_vec<IN: AsRef<[u8]>>(encoded: IN) -> Result<Vec<u8>, Error> {
        let mut bin = vec![0u8; encoded.as_ref().len()];
        let bin_len = Self::decode(&mut bin, encoded)?.len();
        bin.truncate(bin_len);
        Ok(bin)
    }
}

struct Base64Impl;

impl Base64Impl {
    #[inline]
    fn _eq(x: u8, y: u8) -> u8 {
        !(((0u16.wrapping_sub((x as u16) ^ (y as u16))) >> 8) as u8)
    }

    #[inline]
    fn _gt(x: u8, y: u8) -> u8 {
        (((y as u16).wrapping_sub(x as u16)) >> 8) as u8
    }

    #[inline]
    fn _ge(x: u8, y: u8) -> u8 {
        !Self::_gt(y, x)
    }

    #[inline]
    fn _lt(x: u8, y: u8) -> u8 {
        Self::_gt(y, x)
    }

    #[inline]
    fn _le(x: u8, y: u8) -> u8 {
        Self::_ge(y, x)
    }

    #[inline]
    fn b64_byte_to_char(x: u8) -> u8 {
        (Self::_lt(x, 26) & (x.wrapping_add(b'A')))
            | (Self::_ge(x, 26) & Self::_lt(x, 52) & (x.wrapping_add(b'a'.wrapping_sub(26))))
            | (Self::_ge(x, 52) & Self::_lt(x, 62) & (x.wrapping_add(b'0'.wrapping_sub(52))))
            | (Self::_eq(x, 62) & b'+')
            | (Self::_eq(x, 63) & b'/')
    }

    #[inline]
    fn b64_char_to_byte(c: u8) -> u8 {
        let x = (Self::_ge(c, b'A') & Self::_le(c, b'Z') & (c.wrapping_sub(b'A')))
            | (Self::_ge(c, b'a') & Self::_le(c, b'z') & (c.wrapping_sub(b'a'.wrapping_sub(26))))
            | (Self::_ge(c, b'0') & Self::_le(c, b'9') & (c.wrapping_sub(b'0'.wrapping_sub(52))))
            | (Self::_eq(c, b'+') & 62)
            | (Self::_eq(c, b'/') & 63);
        x | (Self::_eq(x, 0) & (Self::_eq(c, b'A') ^ 0xff))
    }

    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        let nibbles = bin_len / 3;
        let rounded = nibbles * 3;
        let pad = bin_len - rounded;
        Ok(nibbles.checked_mul(4).ok_or(Error::Overflow)?
            + ((pad | (pad >> 1)) & 1)
                * (4 - (!(((1_usize & 2) >> 1).wrapping_sub(1)) & (3 - pad)))
            + 1)
    }

    pub fn encode<'t>(b64: &'t mut [u8], bin: &[u8]) -> Result<&'t [u8], Error> {
        let bin_len = bin.len();
        let b64_maxlen = b64.len();
        let mut acc_len = 0usize;
        let mut b64_pos = 0usize;
        let mut acc = 0u16;

        let nibbles = bin_len / 3;
        let remainder = bin_len - 3 * nibbles;
        let mut b64_len = nibbles * 4;
        if remainder != 0 {
            b64_len += 4;
        }
        if b64_maxlen < b64_len {
            return Err(Error::Overflow);
        }
        for &v in bin {
            acc = (acc << 8) + v as u16;
            acc_len += 8;
            while acc_len >= 6 {
                acc_len -= 6;
                b64[b64_pos] = Self::b64_byte_to_char(((acc >> acc_len) & 0x3f) as u8);
                b64_pos += 1;
            }
        }
        if acc_len > 0 {
            b64[b64_pos] = Self::b64_byte_to_char(((acc << (6 - acc_len)) & 0x3f) as u8);
            b64_pos += 1;
        }
        while b64_pos < b64_len {
            b64[b64_pos] = b'=';
            b64_pos += 1
        }
        Ok(&b64[..b64_pos])
    }

    fn skip_padding(b64: &[u8], mut padding_len: usize) -> Result<&[u8], Error> {
        let b64_len = b64.len();
        let mut b64_pos = 0usize;
        while padding_len > 0 {
            if b64_pos >= b64_len {
                return Err(Error::InvalidInput);
            }
            let c = b64[b64_pos];
            if c == b'=' {
                padding_len -= 1
            } else {
                return Err(Error::InvalidInput);
            }
            b64_pos += 1
        }
        Ok(&b64[b64_pos..])
    }

    pub fn decode<'t>(bin: &'t mut [u8], b64: &[u8]) -> Result<&'t [u8], Error> {
        let bin_maxlen = bin.len();
        let mut acc = 0u16;
        let mut acc_len = 0usize;
        let mut bin_pos = 0usize;
        let mut premature_end = None;
        for (b64_pos, &c) in b64.iter().enumerate() {
            let d = Self::b64_char_to_byte(c);
            if d == 0xff {
                premature_end = Some(b64_pos);
                break;
            }
            acc = (acc << 6) + d as u16;
            acc_len += 6;
            if acc_len >= 8 {
                acc_len -= 8;
                if bin_pos >= bin_maxlen {
                    return Err(Error::Overflow);
                }
                bin[bin_pos] = (acc >> acc_len) as u8;
                bin_pos += 1;
            }
        }
        if acc_len > 4 || (acc & ((1u16 << acc_len).wrapping_sub(1))) != 0 {
            return Err(Error::InvalidInput);
        }
        let padding_len = acc_len / 2;
        if let Some(premature_end) = premature_end {
            let remaining = Self::skip_padding(&b64[premature_end..], padding_len)?;
            if !remaining.is_empty() {
                return Err(Error::InvalidInput);
            }
        } else if padding_len != 0 {
            return Err(Error::InvalidInput);
        }
        Ok(&bin[..bin_pos])
    }
}

pub struct Base64;

impl Encoder for Base64 {
    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        Base64Impl::encoded_len(bin_len)
    }

    #[inline]
    fn encode<IN: AsRef<[u8]>>(b64: &mut [u8], bin: IN) -> Result<&[u8], Error> {
        Base64Impl::encode(b64, bin.as_ref())
    }
}

impl Decoder for Base64 {
    #[inline]
    fn decode<IN: AsRef<[u8]>>(bin: &mut [u8], b64: IN) -> Result<&[u8], Error> {
        Base64Impl::decode(bin, b64.as_ref())
    }
}

#[test]
fn test_base64() {
    let bin = [1u8, 5, 11, 15, 19, 131, 122];
    let expected = "AQULDxODeg==";
    let b64 = Base64::encode_to_string(bin).unwrap();
    assert_eq!(b64, expected);
    let bin2 = Base64::decode_to_vec(&b64).unwrap();
    assert_eq!(bin, &bin2[..]);
}

#[test]
fn test_base64_mising_padding() {
    let missing_padding = "AA";
    assert!(Base64::decode_to_vec(missing_padding).is_err());
    let missing_padding = "AAA";
    assert!(Base64::decode_to_vec(missing_padding).is_err());
}

#[test]
fn test_base64_no_std() {
    let bin = [1u8, 5, 11, 15, 19, 131, 122];
    let expected = [65, 81, 85, 76, 68, 120, 79, 68, 101, 103, 61, 61];
    let mut b64 = [0u8; 12];
    let b64 = Base64::encode(&mut b64, bin).unwrap();
    assert_eq!(b64, expected);
    let mut bin2 = [0u8; 7];
    let bin2 = Base64::decode(&mut bin2, b64).unwrap();
    assert_eq!(bin, bin2);
}

#[test]
fn test_base64_invalid_padding() {
    let valid_padding = "AA==";
    assert_eq!(Base64::decode_to_vec(valid_padding), Ok(vec![0u8; 1]));
    let invalid_padding = "AA=";
    assert_eq!(
        Base64::decode_to_vec(invalid_padding),
        Err(Error::InvalidInput)
    );
}
