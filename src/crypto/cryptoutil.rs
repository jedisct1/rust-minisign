// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{convert::TryInto, io};

#[inline(always)]
pub fn write_u64_le(dst: &mut [u8], input: u64) {
    assert!(dst.len() == 8);
    dst.copy_from_slice(&input.to_le_bytes());
}

#[inline(always)]
pub fn write_u64v_le(dst: &mut [u8], input: &[u64]) {
    assert!(dst.len() == 8 * input.len());
    for (chunk, word) in dst.chunks_exact_mut(8).zip(input.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

#[inline(always)]
pub fn write_u32_le(dst: &mut [u8], input: u32) {
    assert!(dst.len() == 4);
    dst.copy_from_slice(&input.to_le_bytes());
}

#[inline(always)]
pub fn read_u64v_le(dst: &mut [u64], input: &[u8]) {
    assert!(dst.len() * 8 == input.len());
    for (word, chunk) in dst.iter_mut().zip(input.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

#[inline(always)]
pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len());
    dst[..src.len()].copy_from_slice(src);
}

pub trait WriteExt {
    fn write_u8(&mut self, val: u8) -> io::Result<()>;
    fn write_u32_le(&mut self, val: u32) -> io::Result<()>;
    fn write_u64_le(&mut self, val: u64) -> io::Result<()>;
}

impl<T> WriteExt for T
where
    T: io::Write,
{
    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        let buff = [val];
        self.write_all(&buff)
    }

    fn write_u32_le(&mut self, val: u32) -> io::Result<()> {
        let mut buff = [0u8; 4];
        write_u32_le(&mut buff, val);
        self.write_all(&buff)
    }

    fn write_u64_le(&mut self, val: u64) -> io::Result<()> {
        let mut buff = [0u8; 8];
        write_u64_le(&mut buff, val);
        self.write_all(&buff)
    }
}
