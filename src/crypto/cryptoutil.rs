// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr;
use std::{io, mem};

pub fn write_u64_be(dst: &mut [u8], mut input: u64) {
    assert!(dst.len() == 8);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 8);
    }
}

pub fn write_u64_le(dst: &mut [u8], mut input: u64) {
    assert!(dst.len() == 8);
    input = input.to_le();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 8);
    }
}

#[allow(dead_code)]
pub fn write_u64v_le(dst: &mut [u8], input: &[u64]) {
    assert!(dst.len() == 8 * input.len());
    unsafe {
        let mut x: *mut u8 = dst.get_unchecked_mut(0);
        let mut y: *const u64 = input.get_unchecked(0);
        for _ in 0..input.len() {
            let tmp = (*y).to_le();
            ptr::copy_nonoverlapping(&tmp as *const _ as *const u8, x, 8);
            x = x.offset(8);
            y = y.offset(1);
        }
    }
}

pub fn write_u32_be(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_be();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

pub fn write_u32_le(dst: &mut [u8], mut input: u32) {
    assert!(dst.len() == 4);
    input = input.to_le();
    unsafe {
        let tmp = &input as *const _ as *const u8;
        ptr::copy_nonoverlapping(tmp, dst.get_unchecked_mut(0), 4);
    }
}

pub fn read_u64v_be(dst: &mut [u64], input: &[u8]) {
    assert!(dst.len() * 8 == input.len());
    unsafe {
        let mut x: *mut u64 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u64 = mem::uninitialized();
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 8);
            *x = u64::from_be(tmp);
            x = x.offset(1);
            y = y.offset(8);
        }
    }
}

#[allow(dead_code)]
pub fn read_u64v_le(dst: &mut [u64], input: &[u8]) {
    assert!(dst.len() * 8 == input.len());
    unsafe {
        let mut x: *mut u64 = dst.get_unchecked_mut(0);
        let mut y: *const u8 = input.get_unchecked(0);
        for _ in 0..dst.len() {
            let mut tmp: u64 = mem::uninitialized();
            ptr::copy_nonoverlapping(y, &mut tmp as *mut _ as *mut u8, 8);
            *x = u64::from_le(tmp);
            x = x.offset(1);
            y = y.offset(8);
        }
    }
}

#[inline]
pub fn copy_memory(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len());
    unsafe {
        let srcp = src.as_ptr();
        let dstp = dst.as_mut_ptr();
        ptr::copy_nonoverlapping(srcp, dstp, src.len());
    }
}

#[inline]
pub fn zero(dst: &mut [u8]) {
    unsafe {
        ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
    }
}

pub trait WriteExt {
    fn write_u8(&mut self, val: u8) -> io::Result<()>;
    fn write_u32_le(&mut self, val: u32) -> io::Result<()>;
    fn write_u32_be(&mut self, val: u32) -> io::Result<()>;
    fn write_u64_le(&mut self, val: u64) -> io::Result<()>;
    fn write_u64_be(&mut self, val: u64) -> io::Result<()>;
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
    fn write_u32_be(&mut self, val: u32) -> io::Result<()> {
        let mut buff = [0u8; 4];
        write_u32_be(&mut buff, val);
        self.write_all(&buff)
    }
    fn write_u64_le(&mut self, val: u64) -> io::Result<()> {
        let mut buff = [0u8; 8];
        write_u64_le(&mut buff, val);
        self.write_all(&buff)
    }
    fn write_u64_be(&mut self, val: u64) -> io::Result<()> {
        let mut buff = [0u8; 8];
        write_u64_be(&mut buff, val);
        self.write_all(&buff)
    }
}

fn to_bits(x: u64) -> (u64, u64) {
    (x >> 61, x << 3)
}

pub fn add_bytes_to_bits_tuple(bits: (u64, u64), bytes: u64) -> (u64, u64) {
    let (new_high_bits, new_low_bits) = to_bits(bytes);
    let (hi, low) = bits;

    match low.checked_add(new_low_bits) {
        Some(x) => {
            if new_high_bits == 0 {
                return (hi, x);
            } else {
                match hi.checked_add(new_high_bits) {
                    Some(y) => return (y, x),
                    None => panic!("Numeric overflow occured."),
                }
            }
        }
        None => {
            let z = match new_high_bits.checked_add(1) {
                Some(w) => w,
                None => panic!("Numeric overflow occured."),
            };
            match hi.checked_add(z) {
                Some(y) => return (y, low.wrapping_add(new_low_bits)),
                None => panic!("Numeric overflow occured."),
            }
        }
    }
}

pub trait FixedBuffer {
    fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], func: F);
    fn reset(&mut self);
    fn zero_until(&mut self, idx: usize);
    fn next<'s>(&'s mut self, len: usize) -> &'s mut [u8];
    fn full_buffer<'s>(&'s mut self) -> &'s [u8];
    fn current_buffer<'s>(&'s mut self) -> &'s [u8];
    fn position(&self) -> usize;
    fn remaining(&self) -> usize;
    fn size(&self) -> usize;
}

macro_rules! impl_fixed_buffer( ($name:ident, $size:expr) => (
    impl FixedBuffer for $name {
        fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
            let mut i = 0;
            let size = $size;

            if self.buffer_idx != 0 {
                let buffer_remaining = size - self.buffer_idx;
                if input.len() >= buffer_remaining {
                        copy_memory(
                            &input[..buffer_remaining],
                            &mut self.buffer[self.buffer_idx..size]);
                    self.buffer_idx = 0;
                    func(&self.buffer);
                    i += buffer_remaining;
                } else {
                    copy_memory(
                        input,
                        &mut self.buffer[self.buffer_idx..self.buffer_idx + input.len()]);
                    self.buffer_idx += input.len();
                    return;
                }
            }


            while input.len() - i >= size {
                func(&input[i..i + size]);
                i += size;
            }

            let input_remaining = input.len() - i;
            copy_memory(
                &input[i..],
                &mut self.buffer[0..input_remaining]);
            self.buffer_idx += input_remaining;
        }

        fn reset(&mut self) {
            self.buffer_idx = 0;
        }

        fn zero_until(&mut self, idx: usize) {
            assert!(idx >= self.buffer_idx);
            zero(&mut self.buffer[self.buffer_idx..idx]);
            self.buffer_idx = idx;
        }

        fn next<'s>(&'s mut self, len: usize) -> &'s mut [u8] {
            self.buffer_idx += len;
            &mut self.buffer[self.buffer_idx - len..self.buffer_idx]
        }

        fn full_buffer<'s>(&'s mut self) -> &'s [u8] {
            assert!(self.buffer_idx == $size);
            self.buffer_idx = 0;
            &self.buffer[..$size]
        }

        fn current_buffer<'s>(&'s mut self) -> &'s [u8] {
            let tmp = self.buffer_idx;
            self.buffer_idx = 0;
            &self.buffer[..tmp]
        }

        fn position(&self) -> usize { self.buffer_idx }

        fn remaining(&self) -> usize { $size - self.buffer_idx }

        fn size(&self) -> usize { $size }
    }
));

#[derive(Copy)]
pub struct FixedBuffer128 {
    buffer: [u8; 128],
    buffer_idx: usize,
}

impl Clone for FixedBuffer128 {
    fn clone(&self) -> FixedBuffer128 {
        *self
    }
}

impl FixedBuffer128 {
    /// Create a new buffer
    pub fn new() -> FixedBuffer128 {
        FixedBuffer128 {
            buffer: [0u8; 128],
            buffer_idx: 0,
        }
    }
}

impl_fixed_buffer!(FixedBuffer128, 128);

pub trait StandardPadding {
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, func: F);
}

impl<T: FixedBuffer> StandardPadding for T {
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, mut func: F) {
        let size = self.size();

        self.next(1)[0] = 128;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }
}
