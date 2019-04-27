// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(
    clippy::needless_range_loop,
    clippy::many_single_char_names,
    clippy::unreadable_literal,
    clippy::let_and_return,
    clippy::needless_lifetimes,
    clippy::cast_lossless,
    clippy::suspicious_arithmetic_impl,
    clippy::identity_op
)]
mod cryptoutil;
mod curve25519;
mod sha2;
mod simd;
mod step_by;

pub mod blake2b;
pub mod digest;
pub mod ed25519;
pub mod util;
